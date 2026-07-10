// Package ebpf is the kernel-side RED/L7 probe source: rate/errors/duration for
// HTTP/gRPC/SQL and L4/L7 network metrics, observed from the kernel without
// instrumenting the application. The BPF backend is not compiled into this
// binary (requires CO-RE/clang); Start is a no-op and the source degrades
// gracefully when eBPF is unavailable.
package ebpf

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/yaop-labs/wisp/internal/model"
)

// Config configures the eBPF probe source.
type Config struct {
	Probes []string // requested probes, e.g. http, grpc, sql
}

// Source implements pipeline.Source for the kernel-side probe.
type Source struct {
	probes []string
	logger *slog.Logger
}

// New builds the eBPF source.
func New(cfg Config, logger *slog.Logger) *Source {
	return &Source{probes: cfg.Probes, logger: logger}
}

// Available reports whether the kernel-side probe can run on this host, with a
// human-readable reason when it cannot. It loads nothing - it only inspects the
// OS and the process's effective capabilities.
func Available() (bool, string) {
	if runtime.GOOS != "linux" {
		return false, "eBPF requires Linux (GOOS=" + runtime.GOOS + ")"
	}
	if os.Geteuid() == 0 {
		return true, ""
	}
	if hasBPFCapability() {
		return true, ""
	}
	return false, "missing CAP_BPF/CAP_SYS_ADMIN (grant the capability or run as root)"
}

// Start runs the probe lifecycle. When eBPF is unavailable it logs the reason
// and no-ops until ctx is canceled (graceful degradation). When the host is
// capable but the BPF backend isn't compiled in, it also no-ops - it never
// fabricates metrics.
func (s *Source) Start(ctx context.Context, _ func(context.Context, model.Batch) error) error {
	if ok, reason := Available(); !ok {
		s.logger.Warn("ebpf source disabled (graceful degradation)", "reason", reason)
		<-ctx.Done()
		return nil
	}
	s.logger.Warn("ebpf host is capable but the BPF backend is not built in this binary; probe is a no-op",
		"probes", s.probes)
	<-ctx.Done()
	return nil
}

func (s *Source) Stop(context.Context) error { return nil }

// hasBPFCapability checks the effective capability set for CAP_BPF (39) or
// CAP_SYS_ADMIN (21) via /proc/self/status. Linux-only; callers gate on GOOS.
func hasBPFCapability() bool {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()
	const (
		capSysAdmin = 21
		capBPF      = 39
	)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		mask, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		if err != nil {
			return false
		}
		return mask&(1<<capBPF) != 0 || mask&(1<<capSysAdmin) != 0
	}
	if err := sc.Err(); err != nil {
		// Unreadable /proc/self/status (I/O or overlong line): we can't confirm
		// the capability, so fail closed.
		return false
	}
	// No CapEff line present: capability not granted.
	return false
}
