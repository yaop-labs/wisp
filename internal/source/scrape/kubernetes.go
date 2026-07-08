package scrape

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/yaop-labs/wisp/internal/model"
	"github.com/yaop-labs/wisp/internal/selfobs"
)

// Kubernetes pod discovery. To keep the agent stdlib-first (no client-go), wisp
// talks to the API server directly over HTTP using the in-cluster service
// account, periodically listing pods (one list per scrape cycle). Pods opt in
// via the prometheus.io/scrape annotation; discovered targets carry
// __meta_kubernetes_* labels (available to relabel, stripped before export).
//
// NOTE: verified against a fake API server in tests; real-cluster e2e is gated
// (needs a cluster). A watch-based (vs list-per-cycle) refresh is a later
// improvement.

const (
	saTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	saCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// KubernetesSD configures Kubernetes pod discovery for a job.
type KubernetesSD struct {
	Job       string
	Namespace string // empty -> all namespaces
	Port      int    // fallback when a pod has no prometheus.io/port annotation
}

// kubeClient is a minimal Kubernetes API client (list pods only).
type kubeClient struct {
	baseURL string
	token   string
	http    *http.Client
}

// inClusterClient builds a client from the mounted service account. Returns an
// error when not running in a cluster, so the caller can degrade gracefully.
func inClusterClient() (*kubeClient, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("not in a kubernetes cluster (KUBERNETES_SERVICE_HOST unset)")
	}
	token, err := os.ReadFile(saTokenFile)
	if err != nil {
		return nil, fmt.Errorf("read service account token: %w", err)
	}
	caPEM, err := os.ReadFile(saCAFile)
	if err != nil {
		return nil, fmt.Errorf("read service account CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("bad service account CA")
	}
	return &kubeClient{
		baseURL: "https://" + net.JoinHostPort(host, port),
		token:   string(token),
		http: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		}},
	}, nil
}

// pod is the subset of the Kubernetes Pod object wisp needs.
type pod struct {
	Metadata struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
	Status struct {
		Phase string `json:"phase"`
		PodIP string `json:"podIP"`
	} `json:"status"`
}

type podList struct {
	Items []pod `json:"items"`
}

func (c *kubeClient) listPods(ctx context.Context, namespace string) (*podList, error) {
	path := "/api/v1/pods"
	if namespace != "" {
		path = "/api/v1/namespaces/" + namespace + "/pods"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("api server status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	var pl podList
	if err := json.NewDecoder(resp.Body).Decode(&pl); err != nil {
		return nil, fmt.Errorf("decode pod list: %w", err)
	}
	return &pl, nil
}

// discoverKubernetes lists pods per configured KubernetesSD and turns the
// scrape-annotated, running ones into targets with __meta_kubernetes_* labels.
func (s *Source) discoverKubernetes(ctx context.Context, configs []KubernetesSD) []Target {
	if s.kube == nil {
		return nil
	}
	var out []Target
	for _, k := range configs {
		pl, err := s.kube.listPods(ctx, k.Namespace)
		if err != nil {
			selfobs.ScrapeErrors.Inc()
			s.logger.Warn("kubernetes_sd: list pods failed", "namespace", k.Namespace, "err", err)
			continue
		}
		for i := range pl.Items {
			if tg, ok := podTarget(&pl.Items[i], k); ok {
				out = append(out, tg)
			}
		}
	}
	return out
}

// podTarget builds a scrape target from a pod, or ok=false when the pod is not
// scrapeable (not running, no IP, opted out, or no resolvable port).
func podTarget(p *pod, k KubernetesSD) (Target, bool) {
	if p.Status.Phase != "Running" || p.Status.PodIP == "" {
		return Target{}, false
	}
	ann := p.Metadata.Annotations
	if ann["prometheus.io/scrape"] == "false" {
		return Target{}, false
	}
	port := k.Port
	if v := ann["prometheus.io/port"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			port = n
		}
	}
	if port == 0 {
		return Target{}, false
	}
	addr := net.JoinHostPort(p.Status.PodIP, strconv.Itoa(port))
	url := targetURL(addr)
	if path := ann["prometheus.io/path"]; path != "" {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		url = "http://" + addr + path
	}
	job := k.Job
	if job == "" {
		job = p.Metadata.Namespace
	}
	extra := model.Labels{
		{Name: "__meta_kubernetes_namespace", Value: p.Metadata.Namespace},
		{Name: "__meta_kubernetes_pod_name", Value: p.Metadata.Name},
		{Name: "__meta_kubernetes_pod_node_name", Value: p.Spec.NodeName},
		{Name: "__meta_kubernetes_pod_ip", Value: p.Status.PodIP},
	}
	for lk, lv := range p.Metadata.Labels {
		extra = append(extra, model.Label{Name: "__meta_kubernetes_pod_label_" + sanitizeLabelName(lk), Value: lv})
	}
	return Target{Job: job, Instance: addr, URL: url, Extra: extra}, true
}

// sanitizeLabelName maps a Kubernetes label key to a Prometheus-safe name
// ([a-zA-Z0-9_]); other characters become underscores.
func sanitizeLabelName(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
