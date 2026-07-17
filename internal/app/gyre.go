package app

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yaop-labs/gyre"
	"gopkg.in/yaml.v3"

	"github.com/yaop-labs/wisp/internal/config"
)

// GyreComponent adapts the Wisp application to Gyre's platform lifecycle.
// It deliberately delegates to the existing App methods, preserving Wisp's
// established startup and shutdown semantics.
type GyreComponent struct {
	app        *App
	mu         sync.RWMutex
	version    string
	state      gyre.State
	since      time.Time
	generation uint64
	readyError string
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

func NewGyreComponent(a *App, version string) *GyreComponent {
	if version == "" {
		version = "dev"
	}
	c := &GyreComponent{
		app:        a,
		version:    version,
		state:      gyre.StateStarting,
		since:      time.Now(),
		generation: 1, // the startup config has already passed validation
	}
	if a != nil {
		a.SetOperationalHandler(gyre.HTTPHandler(c))
	}
	return c
}

func (c *GyreComponent) Name() string    { return "wisp" }
func (c *GyreComponent) Version() string { return c.version }

func (c *GyreComponent) Start(ctx context.Context) error {
	c.mu.RLock()
	state := c.state
	c.mu.RUnlock()
	if state == gyre.StateStopping || state == gyre.StateStopped {
		return gyre.E(gyre.CodeShuttingDown, c.Name(), "start", false, nil)
	}
	if c.app == nil {
		return gyre.E(gyre.CodeInternal, c.Name(), "start", false, nil)
	}
	if err := c.app.Start(ctx); err != nil {
		c.mu.Lock()
		c.state = gyre.StateFailed
		c.since = time.Now()
		c.mu.Unlock()
		return err
	}
	c.mu.Lock()
	c.state = gyre.StateReady
	c.since = time.Now()
	c.readyError = ""
	c.mu.Unlock()
	return nil
}

func (c *GyreComponent) Ready(ctx context.Context) error {
	c.mu.RLock()
	state := c.state
	c.mu.RUnlock()
	if state != gyre.StateReady && state != gyre.StateDegraded {
		return gyre.E(gyre.CodeUnavailable, "wisp", "ready", true, nil)
	}
	if err := c.app.Ready(ctx); err != nil {
		c.setReadiness(gyre.StateDegraded, err.Error())
		return gyre.E(gyre.CodeDependency, c.Name(), "ready", true, err)
	}
	c.setReadiness(gyre.StateReady, "")
	return nil
}

func (c *GyreComponent) Status() gyre.Snapshot {
	// Readiness checks are intentionally cheap, so status can report current
	// degradation even if nobody has polled /readyz yet.
	if c.app != nil {
		if err := c.app.Ready(context.Background()); err != nil {
			c.setReadiness(gyre.StateDegraded, err.Error())
		} else {
			c.setReadiness(gyre.StateReady, "")
		}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	snapshot := gyre.Snapshot{
		Name:       c.Name(),
		Version:    c.Version(),
		State:      c.state,
		Generation: c.generation,
		Since:      c.since,
	}
	if c.state == gyre.StateReady || c.state == gyre.StateDegraded {
		condition := gyre.Condition{
			Type:           "ready",
			Status:         c.state == gyre.StateReady,
			LastTransition: c.since,
		}
		if c.readyError != "" {
			condition.Reason = "dependency_failed"
			condition.Message = c.readyError
		}
		snapshot.Conditions = []gyre.Condition{condition}
	}
	return snapshot
}

func (c *GyreComponent) Close(ctx context.Context) error {
	c.mu.Lock()
	c.state = gyre.StateStopping
	c.since = time.Now()
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
	c.since = time.Now()
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
	c.mu.RLock()
	currentGeneration := c.generation
	c.mu.RUnlock()
	if env.Generation <= currentGeneration {
		return gyre.ReloadResult{}, gyre.E(
			gyre.CodeConfigInvalid,
			c.Name(),
			"reload",
			false,
			fmt.Errorf("generation %d must be greater than active generation %d", env.Generation, currentGeneration),
		)
	}
	var cfg config.Config
	if err := yaml.Unmarshal(env.Spec, &cfg); err != nil {
		return gyre.ReloadResult{}, gyre.E(gyre.CodeConfigInvalid, c.Name(), "reload", false, err)
	}
	if c.app == nil {
		return gyre.ReloadResult{}, gyre.E(gyre.CodeUnavailable, c.Name(), "reload", true, nil)
	}
	outcome, err := c.app.Reload(cfg)
	if err != nil {
		return gyre.ReloadResult{}, gyre.E(gyre.CodeConfigInvalid, c.Name(), "reload", false, err)
	}
	c.mu.Lock()
	c.generation = env.Generation
	c.mu.Unlock()
	return gyre.ReloadResult{Generation: env.Generation, Changed: outcome.Changed}, nil
}

func (c *GyreComponent) setReadiness(state gyre.State, message string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != gyre.StateReady && c.state != gyre.StateDegraded {
		return
	}
	if c.state != state {
		c.state = state
		c.since = time.Now()
	}
	c.readyError = message
}
