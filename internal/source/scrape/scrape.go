// Package scrape pulls Prometheus/OpenMetrics endpoints. Each scraped target is
// attributed to its own service via service.name=<job> and
// service.instance.id=<address>, so the metrics belong to the scraped app, not
// to wisp. Targets come from static config and/or Prometheus file_sd files,
// re-read every cycle so adding or removing a target file takes effect without a
// restart.
package scrape

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yaop-labs/wisp/internal/httpx"
	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/pipeline"
	"github.com/yaop-labs/wisp/internal/selfobs"
)

// resolver abstracts DNS lookups so tests can inject a fake. *net.Resolver
// satisfies it.
type resolver interface {
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// DNSSD configures DNS-based discovery for a job: resolve each name (SRV gives
// host+port; A/AAAA give hosts combined with Port) into scrape targets.
type DNSSD struct {
	Job   string
	Names []string
	Type  string // "srv" (default when Port==0) | "a" | "aaaa"
	Port  int    // required for A/AAAA
}

// Target is a single scrape endpoint.
type Target struct {
	Job      string
	Instance string // address, e.g. "127.0.0.1:8080"
	URL      string
	Extra    model.Labels // extra resource labels from file_sd
}

// Config configures the scrape source.
type Config struct {
	Interval time.Duration
	Timeout  time.Duration
	Static   map[string][]string // job -> addresses
	FileSD   []string            // file_sd globs
	DNSSD    []DNSSD             // DNS-based discovery
	KubeSD   []KubernetesSD      // Kubernetes pod discovery
}

// Source scrapes static and file-discovered targets on an interval. Its targets
// and interval are hot-reloadable (see Reload); the loop reads them under mu.
type Source struct {
	mu       sync.RWMutex
	interval time.Duration
	static   []Target
	fileSD   []string
	dnsSD    []DNSSD
	kubeSD   []KubernetesSD

	client   *http.Client
	resolver resolver
	kube     *kubeClient // nil when k8s SD is unconfigured or unavailable
	logger   *slog.Logger
	reloadCh chan struct{} // nudges the loop to re-arm its ticker on interval change
}

func New(cfg Config, logger *slog.Logger) *Source {
	interval := cfg.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	timeout := cfg.Timeout
	if timeout <= 0 || timeout > interval {
		timeout = interval
	}
	s := &Source{
		interval: interval,
		static:   staticTargets(cfg.Static),
		fileSD:   cfg.FileSD,
		dnsSD:    cfg.DNSSD,
		kubeSD:   cfg.KubeSD,
		client:   &http.Client{Timeout: timeout},
		resolver: net.DefaultResolver,
		logger:   logger,
		reloadCh: make(chan struct{}, 1),
	}
	if len(cfg.KubeSD) > 0 {
		// Best-effort in-cluster bootstrap; degrade gracefully if unavailable.
		kc, err := inClusterClient()
		if err != nil {
			logger.Warn("kubernetes_sd configured but unavailable; disabling", "err", err)
		} else {
			s.kube = kc
			logger.Info("kubernetes_sd enabled", "configs", len(cfg.KubeSD))
		}
	}
	return s
}

// staticTargets flattens a job->addresses map into Targets.
func staticTargets(static map[string][]string) []Target {
	var out []Target
	for job, addrs := range static {
		for _, addr := range addrs {
			out = append(out, Target{Job: job, Instance: addr, URL: targetURL(addr)})
		}
	}
	return out
}

// Reload swaps the static target set, file_sd globs, and interval without a
// restart. Safe to call concurrently with the scrape loop.
func (s *Source) Reload(cfg Config) {
	s.mu.Lock()
	s.static = staticTargets(cfg.Static)
	s.fileSD = cfg.FileSD
	s.dnsSD = cfg.DNSSD
	s.kubeSD = cfg.KubeSD
	intervalChanged := cfg.Interval > 0 && cfg.Interval != s.interval
	if cfg.Interval > 0 {
		s.interval = cfg.Interval
	}
	s.mu.Unlock()
	if intervalChanged {
		select {
		case s.reloadCh <- struct{}{}: // wake the loop to re-arm its ticker
		default:
		}
	}
}

func (s *Source) currentInterval() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.interval
}

func targetURL(addr string) string {
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		return addr
	}
	return "http://" + addr + "/metrics"
}

// Start scrapes all targets immediately, then every interval until ctx ends.
// A Reload that changes the interval re-arms the ticker via reloadCh.
func (s *Source) Start(ctx context.Context, emit func(context.Context, model.Batch) error) error {
	t := time.NewTicker(s.currentInterval())
	defer t.Stop()
	s.scrapeAll(ctx, emit)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.scrapeAll(ctx, emit)
		case <-s.reloadCh:
			t.Reset(s.currentInterval())
		}
	}
}

func (s *Source) Stop(context.Context) error { return nil }

// currentTargets resolves static, file-discovered, and DNS-discovered targets
// for this cycle, reading the (hot-reloadable) config under the lock.
func (s *Source) currentTargets(ctx context.Context) []Target {
	s.mu.RLock()
	targets := append([]Target(nil), s.static...)
	globs := append([]string(nil), s.fileSD...)
	dnsSD := append([]DNSSD(nil), s.dnsSD...)
	kubeSD := append([]KubernetesSD(nil), s.kubeSD...)
	s.mu.RUnlock()
	targets = append(targets, s.discoverFiles(globs)...)
	targets = append(targets, s.discoverDNS(ctx, dnsSD)...)
	return append(targets, s.discoverKubernetes(ctx, kubeSD)...)
}

// discoverDNS resolves DNS SD configs into targets, attaching __meta_dns_*
// labels (available to relabel, stripped before export by the pipeline).
func (s *Source) discoverDNS(ctx context.Context, configs []DNSSD) []Target {
	var out []Target
	for _, d := range configs {
		job := d.Job
		typ := strings.ToLower(d.Type)
		if typ == "" {
			if d.Port == 0 {
				typ = "srv"
			} else {
				typ = "a"
			}
		}
		for _, name := range d.Names {
			jobName := job
			if jobName == "" {
				jobName = name
			}
			switch typ {
			case "srv":
				_, addrs, err := s.resolver.LookupSRV(ctx, "", "", name)
				if err != nil {
					selfobs.ScrapeErrors.Inc()
					s.logger.Warn("dns_sd: SRV lookup failed", "name", name, "err", err)
					continue
				}
				for _, a := range addrs {
					host := strings.TrimSuffix(a.Target, ".")
					addr := net.JoinHostPort(host, strconv.Itoa(int(a.Port)))
					out = append(out, Target{Job: jobName, Instance: addr, URL: targetURL(addr), Extra: model.Labels{
						{Name: "__meta_dns_name", Value: name},
						{Name: "__meta_dns_srv_record_target", Value: host},
						{Name: "__meta_dns_srv_record_port", Value: strconv.Itoa(int(a.Port))},
					}})
				}
			case "a", "aaaa":
				if d.Port == 0 {
					s.logger.Warn("dns_sd: A/AAAA discovery needs a port", "name", name)
					continue
				}
				ips, err := s.resolver.LookupIPAddr(ctx, name)
				if err != nil {
					selfobs.ScrapeErrors.Inc()
					s.logger.Warn("dns_sd: host lookup failed", "name", name, "err", err)
					continue
				}
				for _, ip := range ips {
					addr := net.JoinHostPort(ip.IP.String(), strconv.Itoa(d.Port))
					out = append(out, Target{Job: jobName, Instance: addr, URL: targetURL(addr), Extra: model.Labels{
						{Name: "__meta_dns_name", Value: name},
					}})
				}
			default:
				s.logger.Warn("dns_sd: unknown type", "type", d.Type, "name", name)
			}
		}
	}
	return out
}

func (s *Source) scrapeAll(ctx context.Context, emit func(context.Context, model.Batch) error) {
	var wg sync.WaitGroup
	for _, tg := range s.currentTargets(ctx) {
		wg.Add(1)
		go func(tg Target) {
			defer wg.Done()
			s.scrapeOne(ctx, tg, emit)
		}(tg)
	}
	wg.Wait()
}

func (s *Source) scrapeOne(ctx context.Context, tg Target, emit func(context.Context, model.Batch) error) {
	series, err := s.fetch(ctx, tg)
	if err != nil {
		selfobs.ScrapeErrors.Inc()
		s.logger.Warn("scrape failed", "job", tg.Job, "instance", tg.Instance, "err", err)
		return
	}
	resource := make(model.Labels, 0, 2+len(tg.Extra))
	resource = append(resource,
		model.Label{Name: "service.name", Value: tg.Job},
		model.Label{Name: "service.instance.id", Value: tg.Instance},
	)
	resource = append(resource, tg.Extra...)
	for i := range series {
		series[i].Resource = resource
	}
	batch := model.Batch{Series: series}
	if err := emit(ctx, batch); pipeline.IsLoggableEmitError(ctx, err) {
		s.logger.Warn("scrape emit failed", "job", tg.Job, "err", err)
	}
}

func (s *Source) fetch(ctx context.Context, tg Target) ([]model.Series, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tg.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, httpx.ErrorFromResponse(resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	return parse(body, uint64(time.Now().UnixNano())), nil
}

// fileSDGroup is the Prometheus file_sd JSON entry.
type fileSDGroup struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

// discoverFiles reads file_sd globs and turns each entry into targets. A "job"
// label names the service; other labels become extra resource labels.
func (s *Source) discoverFiles(globs []string) []Target {
	var out []Target
	for _, glob := range globs {
		matches, err := filepath.Glob(glob)
		if err != nil {
			s.logger.Warn("file_sd: bad glob", "glob", glob, "err", err)
			continue
		}
		for _, path := range matches {
			data, err := os.ReadFile(path)
			if err != nil {
				s.logger.Warn("file_sd: read", "path", path, "err", err)
				continue
			}
			var groups []fileSDGroup
			if err := json.Unmarshal(data, &groups); err != nil {
				s.logger.Warn("file_sd: parse", "path", path, "err", err)
				continue
			}
			for _, g := range groups {
				out = append(out, g.targets()...)
			}
		}
	}
	return out
}

func (g fileSDGroup) targets() []Target {
	job := g.Labels["job"]
	if job == "" {
		job = "unknown"
	}
	var extra model.Labels
	for k, v := range g.Labels {
		if k == "job" {
			continue
		}
		extra = append(extra, model.Label{Name: k, Value: v})
	}
	out := make([]Target, 0, len(g.Targets))
	for _, addr := range g.Targets {
		out = append(out, Target{Job: job, Instance: addr, URL: targetURL(addr), Extra: extra})
	}
	return out
}
