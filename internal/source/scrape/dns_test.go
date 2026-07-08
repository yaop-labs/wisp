package scrape

import (
	"context"
	"net"
	"sort"
	"testing"
	"time"
)

// fakeResolver returns canned SRV / host results for DNS SD tests.
type fakeResolver struct {
	srv  map[string][]*net.SRV
	host map[string][]net.IPAddr
}

func (f fakeResolver) LookupSRV(_ context.Context, _, _, name string) (string, []*net.SRV, error) {
	if a, ok := f.srv[name]; ok {
		return name, a, nil
	}
	return "", nil, &net.DNSError{Err: "not found", Name: name, IsNotFound: true}
}
func (f fakeResolver) LookupIPAddr(_ context.Context, name string) ([]net.IPAddr, error) {
	if a, ok := f.host[name]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "not found", Name: name, IsNotFound: true}
}

func newWithResolver(cfg Config, r resolver) *Source {
	s := New(cfg, discard())
	s.resolver = r
	return s
}

func TestDNSDiscoverySRV(t *testing.T) {
	r := fakeResolver{srv: map[string][]*net.SRV{
		"_metrics._tcp.svc.local": {
			{Target: "host-a.svc.local.", Port: 9100},
			{Target: "host-b.svc.local.", Port: 9100},
		},
	}}
	s := newWithResolver(Config{
		Interval: time.Minute,
		DNSSD:    []DNSSD{{Job: "node", Names: []string{"_metrics._tcp.svc.local"}, Type: "srv"}},
	}, r)

	tgts := s.discoverDNS(context.Background(), s.dnsSD)
	if len(tgts) != 2 {
		t.Fatalf("got %d targets, want 2", len(tgts))
	}
	addrs := []string{tgts[0].Instance, tgts[1].Instance}
	sort.Strings(addrs)
	if addrs[0] != "host-a.svc.local:9100" || addrs[1] != "host-b.svc.local:9100" {
		t.Fatalf("addrs = %v", addrs)
	}
	// meta labels present (trailing dot stripped from target).
	if labelValue(tgts[0].Extra, "__meta_dns_name") != "_metrics._tcp.svc.local" {
		t.Errorf("missing __meta_dns_name: %v", tgts[0].Extra)
	}
	if labelValue(tgts[0].Extra, "__meta_dns_srv_record_port") != "9100" {
		t.Errorf("missing/srv port meta: %v", tgts[0].Extra)
	}
	if tgts[0].Job != "node" {
		t.Errorf("job = %q, want node", tgts[0].Job)
	}
}

func TestDNSDiscoveryA(t *testing.T) {
	r := fakeResolver{host: map[string][]net.IPAddr{
		"app.svc.local": {{IP: net.ParseIP("10.0.0.1")}, {IP: net.ParseIP("10.0.0.2")}},
	}}
	s := newWithResolver(Config{
		DNSSD: []DNSSD{{Job: "app", Names: []string{"app.svc.local"}, Type: "a", Port: 8080}},
	}, r)

	tgts := s.discoverDNS(context.Background(), s.dnsSD)
	if len(tgts) != 2 {
		t.Fatalf("got %d targets, want 2", len(tgts))
	}
	addrs := []string{tgts[0].Instance, tgts[1].Instance}
	sort.Strings(addrs)
	if addrs[0] != "10.0.0.1:8080" || addrs[1] != "10.0.0.2:8080" {
		t.Fatalf("addrs = %v", addrs)
	}
}

func TestDNSDiscoveryAWithoutPortSkips(t *testing.T) {
	r := fakeResolver{host: map[string][]net.IPAddr{"x": {{IP: net.ParseIP("10.0.0.1")}}}}
	s := newWithResolver(Config{DNSSD: []DNSSD{{Names: []string{"x"}, Type: "a"}}}, r) // no port
	if got := s.discoverDNS(context.Background(), s.dnsSD); len(got) != 0 {
		t.Fatalf("A discovery without a port should yield 0 targets, got %d", len(got))
	}
}
