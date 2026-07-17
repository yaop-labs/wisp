package selfobs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func scrapeSelf(t *testing.T) string {
	t.Helper()
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type = %q, want prometheus text", ct)
	}
	return rec.Body.String()
}

func TestHandlerRendersCountersAndGauges(t *testing.T) {
	SamplesEmitted.Add(5)
	body := scrapeSelf(t)

	// A known counter renders with HELP/TYPE/value lines.
	for _, want := range []string{
		"# HELP wisp_samples_emitted_total",
		"# TYPE wisp_samples_emitted_total counter",
		"wisp_samples_emitted_total ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func TestHandlerRendersRegisteredGauge(t *testing.T) {
	RegisterGaugeFunc("wisp_test_gauge", "A test gauge.", func() float64 { return 42 })
	body := scrapeSelf(t)
	for _, want := range []string{
		"# TYPE wisp_test_gauge gauge",
		"wisp_test_gauge 42",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func TestRegisterGaugeFuncIsIdempotentByName(t *testing.T) {
	RegisterGaugeFunc("wisp_dup_gauge", "v1", func() float64 { return 1 })
	RegisterGaugeFunc("wisp_dup_gauge", "v2", func() float64 { return 2 })
	body := scrapeSelf(t)
	if n := strings.Count(body, "\nwisp_dup_gauge "); n != 1 {
		t.Fatalf("gauge rendered %d times, want 1 (re-register replaces)", n)
	}
	if !strings.Contains(body, "wisp_dup_gauge 2") {
		t.Error("re-register should have replaced the value with 2")
	}
}

func TestHandlerRendersSortedGaugeVector(t *testing.T) {
	RegisterGaugeVecFunc("wisp_test_vector", "A test vector.", "signal", func() map[string]float64 {
		return map[string]float64{"metrics": 2, "logs": 1}
	})
	body := scrapeSelf(t)
	for _, want := range []string{
		"# TYPE wisp_test_vector gauge",
		"wisp_test_vector{signal=\"logs\"} 1",
		"wisp_test_vector{signal=\"metrics\"} 2",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	if strings.Index(body, `signal="logs"`) > strings.Index(body, `signal="metrics"`) {
		t.Error("gauge vector label values are not sorted")
	}
}

func TestCounter(t *testing.T) {
	var c Counter
	c.Inc()
	c.Add(4)
	if c.Get() != 5 {
		t.Fatalf("Get = %d, want 5", c.Get())
	}
}
