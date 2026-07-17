package app

import (
	"context"
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
	c := NewGyreComponent(&App{})
	if c.Status().State != gyre.StateStarting {
		t.Fatalf("state=%s", c.Status().State)
	}
	if err := c.Ready(context.Background()); err == nil {
		t.Fatal("expected not ready")
	}
}

func TestGyreConformance(t *testing.T) {
	if err := gyre.ConformanceCheck(context.Background(), NewGyreComponent(&App{})); err != nil {
		t.Fatal(err)
	}
}
