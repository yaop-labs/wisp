package scrape

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yaop-labs/wisp/internal/model"
)

func TestScrapeOneTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "# TYPE up gauge\nup 1\nhttp_requests_total{code=\"200\"} 5\n")
	}))
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	s := New(Config{Interval: time.Hour, Timeout: time.Second, Static: map[string][]string{"app": {addr}}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan model.Batch, 1)
	emit := func(_ context.Context, b model.Batch) error {
		select {
		case got <- b:
		default:
		}
		cancel()
		return nil
	}
	_ = s.Start(ctx, emit)

	select {
	case b := <-got:
		if b.Len() != 2 {
			t.Fatalf("expected 2 points, got %d", b.Len())
		}
		for _, ser := range b.Series {
			if labelValue(ser.Resource, "service.name") != "app" {
				t.Errorf("series %q should be attributed to job 'app'", ser.Name)
			}
			if labelValue(ser.Resource, "service.instance.id") != addr {
				t.Errorf("series %q missing instance %q", ser.Name, addr)
			}
		}
	default:
		t.Fatal("no batch emitted")
	}
}

func TestFileSD(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "# TYPE up gauge\nup 1\n")
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	dir := t.TempDir()
	sd := filepath.Join(dir, "targets.json")
	body := `[{"targets":["` + addr + `"],"labels":{"job":"discovered","env":"prod"}}]`
	if err := os.WriteFile(sd, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	s := New(Config{Interval: time.Hour, Timeout: time.Second, FileSD: []string{filepath.Join(dir, "*.json")}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan model.Batch, 1)
	emit := func(_ context.Context, b model.Batch) error {
		select {
		case got <- b:
		default:
		}
		cancel()
		return nil
	}
	_ = s.Start(ctx, emit)

	select {
	case b := <-got:
		if b.Len() == 0 {
			t.Fatal("discovered target produced no series")
		}
		r := b.Series[0].Resource
		if labelValue(r, "service.name") != "discovered" {
			t.Errorf("job from file_sd not applied: %v", r)
		}
		if labelValue(r, "env") != "prod" {
			t.Errorf("extra file_sd label not applied: %v", r)
		}
		if labelValue(r, "service.instance.id") != addr {
			t.Errorf("instance not set: %v", r)
		}
	default:
		t.Fatal("no batch from file_sd target")
	}
}

func labelValue(ls model.Labels, name string) string {
	for _, l := range ls {
		if l.Name == name {
			return l.Value
		}
	}
	return ""
}
