package scrape

import (
	"fmt"
	"strings"
	"testing"
)

// scrapePayload builds a representative OpenMetrics body with n series across a
// handful of metrics with labels - the scrape hot path.
func scrapePayload(n int) string {
	var b strings.Builder
	b.WriteString("# HELP http_requests_total Total requests.\n# TYPE http_requests_total counter\n")
	methods := []string{"get", "post", "put", "delete"}
	codes := []string{"200", "404", "500"}
	for i := range n {
		fmt.Fprintf(&b, "http_requests_total{method=%q,code=%q,handler=\"/api/v%d\"} %d %d\n",
			methods[i%len(methods)], codes[i%len(codes)], i%8, i*7, 1395066363000+i)
	}
	b.WriteString("# TYPE process_resident_memory_bytes gauge\nprocess_resident_memory_bytes 1.234e8\n")
	return b.String()
}

func BenchmarkParse(b *testing.B) {
	body := scrapePayload(100)
	b.ReportAllocs()
	
	for b.Loop() {
		_ = parse([]byte(body), 1)
	}
}

func BenchmarkParseLabels(b *testing.B) {
	const ls = `{method="get",code="200",handler="/api/v3",region="eu-west-1"}`
	b.ReportAllocs()
	
	for b.Loop() {
		_ = parseLabels([]byte(ls))
	}
}
