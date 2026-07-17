package app

import (
	"context"
	"sync"
	"time"

	"github.com/yaop-labs/gyre"
	"github.com/yaop-labs/wisp/internal/config"
	"gopkg.in/yaml.v3"
)

// GyreComponent adapts the Wisp application to Gyre's platform lifecycle.
// It deliberately delegates to the existing App methods, preserving Wisp's
// established startup and shutdown semantics.
type GyreComponent struct {
	app        *App
	mu         sync.RWMutex
	state      gyre.State
	since      time.Time
	generation uint64
	// credentials is an optional Reef-backed provider. It is intentionally
	// interface-typed so Wisp does not depend on Reef's concrete package.
	credentials gyre.CredentialSource
}

// SetCredentialSource attaches a Reef (or compatible) credential provider.
// Credential material never enters Wisp status; only redacted status is exposed.
func (c *GyreComponent) SetCredentialSource(src gyre.CredentialSource) {
	c.mu.Lock()
	c.credentials = src
	c.mu.Unlock()
}

// CredentialStatus returns provider-owned, secret-free credential snapshots.
func (c *GyreComponent) CredentialStatus() []gyre.CredentialStatus {
	c.mu.RLock()
	src := c.credentials
	c.mu.RUnlock()
	if src == nil {
		return nil
	}
	return src.CredentialStatus()
}

func NewGyreComponent(a *App) *GyreComponent {
	return &GyreComponent{app: a, state: gyre.StateStarting, since: time.Now()}
}

func (c *GyreComponent) Name() string    { return "wisp" }
func (c *GyreComponent) Version() string { return "dev" }

func (c *GyreComponent) Start(ctx context.Context) error {
	if err := c.app.Start(ctx); err != nil {
		c.mu.Lock()
		c.state = gyre.StateFailed
		c.mu.Unlock()
		return err
	}
	c.mu.Lock()
	c.state = gyre.StateReady
	c.since = time.Now()
	c.mu.Unlock()
	return nil
}

func (c *GyreComponent) Ready(context.Context) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.state != gyre.StateReady && c.state != gyre.StateDegraded {
		return gyre.E(gyre.CodeUnavailable, "wisp", "ready", true, nil)
	}
	return nil
}

func (c *GyreComponent) Status() gyre.Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return gyre.Snapshot{Name: c.Name(), Version: c.Version(), State: c.state, Generation: c.generation, Since: c.since}
}

func (c *GyreComponent) Close(ctx context.Context) error {
	c.mu.Lock()
	c.state = gyre.StateStopping
	c.mu.Unlock()
	var err error
	if c.app != nil && c.app.pipeline != nil {
		err = c.app.Shutdown(ctx)
	}
	c.mu.Lock()
	if err != nil {
		c.state = gyre.StateFailed
	} else {
		c.state = gyre.StateStopped
	}
	c.mu.Unlock()
	return err
}

func (c *GyreComponent) Reload(ctx context.Context, env gyre.Envelope) (gyre.ReloadResult, error) {
	if err := ctx.Err(); err != nil {
		return gyre.ReloadResult{}, err
	}
	if err := env.Validate(); err != nil {
		return gyre.ReloadResult{}, err
	}
	var cfg config.Config
	if err := yaml.Unmarshal(env.Spec, &cfg); err != nil {
		return gyre.ReloadResult{}, gyre.E(gyre.CodeConfigInvalid, c.Name(), "reload", false, err)
	}
	if err := c.app.Reload(cfg); err != nil {
		return gyre.ReloadResult{}, gyre.E(gyre.CodeConfigInvalid, c.Name(), "reload", false, err)
	}
	c.mu.Lock()
	if env.Generation > c.generation {
		c.generation = env.Generation
	}
	c.mu.Unlock()
	return gyre.ReloadResult{Generation: c.generation, Changed: []string{"config"}}, nil
}
