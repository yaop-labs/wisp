// Command wisp is the entrypoint for the wisp observability agent.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yaop-labs/wisp/internal/app"
	"github.com/yaop-labs/wisp/internal/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "wisp:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "", "path to YAML config (required)")
	flag.Parse()

	if *configPath == "" {
		return fmt.Errorf("--config is required; refusing to start an unconfigured agent")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: parseLevel(cfg.Agent.LogLevel),
	}))
	logger.Info("loaded config", "path", *configPath)
	logger.Info("sources enabled", "sources", strings.Join(cfg.Sources.Enabled(), ","))
	logger.Info("egress", "endpoint", cfg.Exporter.OTLP.Endpoint, "protocol", cfg.Exporter.OTLP.Protocol)

	a, err := app.New(cfg, logger)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := a.Start(ctx); err != nil {
		return err
	}
	logger.Info("wisp started")

	// SIGHUP hot-reloads the config (scrape targets/interval) without a restart.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				newCfg, err := config.Load(*configPath)
				if err != nil {
					logger.Error("reload: failed to load config, keeping current", "err", err)
					continue
				}
				if err := a.Reload(newCfg); err != nil {
					logger.Error("reload failed", "err", err)
					continue
				}
				logger.Info("config reloaded", "path", *configPath)
			}
		}
	}()

	<-ctx.Done()
	logger.Info("shutdown signal received")

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer stopCancel()
	if err := a.Shutdown(stopCtx); err != nil {
		logger.Error("shutdown error", "err", err)
		return err
	}
	logger.Info("wisp stopped")
	return nil
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
