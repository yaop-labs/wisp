package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/yaop-labs/gyre"

	"github.com/yaop-labs/wisp/internal/config"
)

func TestGyreComponentContract(t *testing.T) {
	a, err := New(config.Config{}, nil)
	if err == nil {
		t.Fatal("expected invalid empty config")
	}
	_ = a
	var _ gyre.Component = (*GyreComponent)(nil)
}

func TestGyreComponentInitialStatus(t *testing.T) {
	c := NewGyreComponent(&App{}, "v0.7.0-test")
	if c.Status().State != gyre.StateStarting {
		t.Fatalf("state=%s", c.Status().State)
	}
	if c.Status().Version != "v0.7.0-test" {
		t.Fatalf("version=%q", c.Status().Version)
	}
	if c.Status().Generation != 1 {
		t.Fatalf("generation=%d", c.Status().Generation)
	}
	if err := c.Ready(context.Background()); err == nil {
		t.Fatal("expected not ready")
	}
}

func TestGyreConformance(t *testing.T) {
	if err := gyre.ConformanceCheck(context.Background(), NewGyreComponent(&App{}, "test")); err != nil {
		t.Fatal(err)
	}
}

func TestGyreOperationalEndpointsInstalled(t *testing.T) {
	a, err := New(fullConfig(t), discardLog())
	if err != nil {
		t.Fatal(err)
	}
	NewGyreComponent(a, "v0.7.0-test")

	for path, want := range map[string]int{
		"/healthz": http.StatusOK,
		"/readyz":  http.StatusServiceUnavailable,
		"/status":  http.StatusOK,
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		a.operational.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("%s status=%d, want %d: %s", path, rec.Code, want, rec.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	rec := httptest.NewRecorder()
	a.operational.ServeHTTP(rec, req)
	var got gyre.Snapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != "v0.7.0-test" || got.Generation != 1 {
		t.Fatalf("status=%+v", got)
	}
}

func TestGyreReloadUsesCanonicalSpecAndPreservesGenerationOnRejection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wisp.yaml")
	write := func(target, endpoint string) {
		t.Helper()
		data := []byte(fmt.Sprintf(`
agent:
  self_metrics:
    endpoint: ""
sources:
  scrape:
    interval: 1s
    targets:
      - job: app
        static: [%q]
processors:
  - type: reset
exporter:
  otlp:
    endpoint: %q
    protocol: grpc
resource:
  attributes:
    service.name: wisp-test
`, target, endpoint))
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write("127.0.0.1:9000", "127.0.0.1:4317")
	cfg, sameSpec, err := config.LoadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg, discardLog())
	if err != nil {
		t.Fatal(err)
	}
	c := NewGyreComponent(a, "test")
	result, err := c.Reload(context.Background(), gyre.Envelope{
		APIVersion: "gyre/v1", Kind: "Wisp", Generation: 2, Spec: sameSpec,
	})
	if err != nil {
		t.Fatalf("same config reload: %v", err)
	}
	if len(result.Changed) != 0 || result.Generation != 2 {
		t.Fatalf("same config result=%+v", result)
	}

	write("127.0.0.1:9001", "127.0.0.1:4317")
	_, changedSpec, err := config.LoadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	result, err = c.Reload(context.Background(), gyre.Envelope{
		APIVersion: "gyre/v1", Kind: "Wisp", Generation: 3, Spec: changedSpec,
	})
	if err != nil || result.Generation != 3 || len(result.Changed) != 1 {
		t.Fatalf("scrape reload result=%+v err=%v", result, err)
	}

	write("127.0.0.1:9001", "127.0.0.1:5317")
	_, rejectedSpec, err := config.LoadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Reload(context.Background(), gyre.Envelope{
		APIVersion: "gyre/v1", Kind: "Wisp", Generation: 4, Spec: rejectedSpec,
	}); err == nil {
		t.Fatal("expected exporter reload rejection")
	}
	if got := c.Status().Generation; got != 3 {
		t.Fatalf("generation advanced after rejected reload: %d", got)
	}
}
