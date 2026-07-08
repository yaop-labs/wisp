package scrape

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/yaop-labs/wisp/internal/model"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func targetJobs(ts []Target) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Job)
	}
	sort.Strings(out)
	return out
}

// TestReloadSwapsTargets: Reload replaces the static target set live.
func TestReloadSwapsTargets(t *testing.T) {
	s := New(Config{
		Interval: time.Minute,
		Static:   map[string][]string{"a": {"127.0.0.1:1"}},
	}, discard())

	if got := targetJobs(s.currentTargets(context.Background())); len(got) != 1 || got[0] != "a" {
		t.Fatalf("initial targets = %v, want [a]", got)
	}

	s.Reload(Config{
		Interval: time.Minute,
		Static:   map[string][]string{"b": {"127.0.0.1:2"}, "c": {"127.0.0.1:3"}},
	})
	if got := targetJobs(s.currentTargets(context.Background())); len(got) != 2 || got[0] != "b" || got[1] != "c" {
		t.Fatalf("reloaded targets = %v, want [b c]", got)
	}
}

// TestReloadIntervalReArmsTicker: changing the interval wakes the loop so the
// next scrape happens on the new (shorter) cadence rather than the old one.
func TestReloadIntervalReArmsTicker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "# TYPE up gauge\nup 1\n")
	}))
	defer srv.Close()
	addr := srv.URL // has http:// prefix -> used as-is by targetURL

	var mu sync.Mutex
	scrapes := 0
	s := New(Config{
		Interval: time.Hour, // effectively "never" until reloaded
		Static:   map[string][]string{"a": {addr}},
	}, discard())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = s.Start(ctx, func(_ context.Context, b model.Batch) error {
			if b.Len() > 0 {
				mu.Lock()
				scrapes++
				mu.Unlock()
			}
			return nil
		})
	}()

	time.Sleep(50 * time.Millisecond) // immediate first scrape lands

	// Reload to a tiny interval -> loop re-arms and starts scraping frequently.
	s.Reload(Config{Interval: 20 * time.Millisecond, Static: map[string][]string{"a": {addr}}})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := scrapes
		mu.Unlock()
		if n >= 3 {
			return // ticker re-armed and fired multiple times
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("interval reload did not re-arm the ticker (too few scrape cycles)")
}
