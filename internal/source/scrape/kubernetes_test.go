package scrape

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
)

const podListJSON = `{
  "items": [
    {"metadata": {"name": "api-1", "namespace": "prod",
       "labels": {"app": "api", "pod-template-hash": "abc"},
       "annotations": {"prometheus.io/scrape": "true", "prometheus.io/port": "9100", "prometheus.io/path": "/m"}},
     "spec": {"nodeName": "node-1"},
     "status": {"phase": "Running", "podIP": "10.0.0.1"}},
    {"metadata": {"name": "api-2", "namespace": "prod", "annotations": {"prometheus.io/scrape": "false"}},
     "spec": {"nodeName": "node-2"},
     "status": {"phase": "Running", "podIP": "10.0.0.2"}},
    {"metadata": {"name": "pending", "namespace": "prod"},
     "status": {"phase": "Pending", "podIP": ""}},
    {"metadata": {"name": "fallback", "namespace": "prod", "annotations": {"prometheus.io/scrape": "true"}},
     "spec": {"nodeName": "node-3"},
     "status": {"phase": "Running", "podIP": "10.0.0.3"}},
    {"metadata": {"name": "noann", "namespace": "prod"},
     "spec": {"nodeName": "node-4"},
     "status": {"phase": "Running", "podIP": "10.0.0.4"}}
  ]
}`

func TestKubernetesDiscovery(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, podListJSON)
	}))
	defer srv.Close()

	s := New(Config{KubeSD: []KubernetesSD{{Job: "k8s", Namespace: "prod", Port: 8080}}}, discard())
	s.kube = &kubeClient{baseURL: srv.URL, token: "tok", http: srv.Client()}

	tgts := s.discoverKubernetes(context.Background(), s.kubeSD)

	// Opt-in: api-1 (scrape=true, port 9100, path /m) + fallback (scrape=true, no
	// port -> config Port 8080). api-2 opted out, pending has no IP, and noann has
	// no scrape annotation -> all three skipped.
	if len(tgts) != 2 {
		t.Fatalf("got %d targets, want 2: %+v", len(tgts), tgts)
	}
	if gotPath != "/api/v1/namespaces/prod/pods" {
		t.Errorf("listed path = %q, want namespaced pods", gotPath)
	}

	byInstance := map[string]Target{}
	for _, tg := range tgts {
		byInstance[tg.Instance] = tg
	}
	api1, ok := byInstance["10.0.0.1:9100"]
	if !ok {
		t.Fatalf("api-1 target missing; have %v", keys(byInstance))
	}
	if api1.URL != "http://10.0.0.1:9100/m" {
		t.Errorf("api-1 url = %q, want .../m from annotation", api1.URL)
	}
	if labelValue(api1.Extra, "__meta_kubernetes_pod_name") != "api-1" ||
		labelValue(api1.Extra, "__meta_kubernetes_namespace") != "prod" ||
		labelValue(api1.Extra, "__meta_kubernetes_pod_node_name") != "node-1" {
		t.Errorf("api-1 meta labels wrong: %v", api1.Extra)
	}
	if labelValue(api1.Extra, "__meta_kubernetes_pod_label_app") != "api" {
		t.Errorf("api-1 pod label not mapped: %v", api1.Extra)
	}
	if _, ok := byInstance["10.0.0.3:8080"]; !ok {
		t.Errorf("fallback target (config port) missing; have %v", keys(byInstance))
	}
	if _, ok := byInstance["10.0.0.4:8080"]; ok {
		t.Error("noann pod (no scrape annotation) must not be scraped under opt-in")
	}
}

func keys(m map[string]Target) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestSanitizeLabelName(t *testing.T) {
	if got := sanitizeLabelName("app.kubernetes.io/name"); got != "app_kubernetes_io_name" {
		t.Errorf("sanitizeLabelName = %q", got)
	}
}
