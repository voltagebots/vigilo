package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/voltagebots/vigilo/internal/alerter"
	"github.com/voltagebots/vigilo/internal/buffer"
	"github.com/voltagebots/vigilo/internal/collector"
	"github.com/voltagebots/vigilo/internal/config"
	vigilomcp "github.com/voltagebots/vigilo/internal/mcp"
	"github.com/voltagebots/vigilo/internal/web"
)

// Set by goreleaser via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	configPath  := flag.String("config", "/etc/vigilo/config.yaml", "Path to config file")
	dbPath      := flag.String("db", "/var/lib/vigilo/events.db", "SQLite database path")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("vigilo %s (%s) built %s\n", version, commit, date)
		os.Exit(0)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	// Build suppress matcher from config rules
	var suppressRules []collector.SuppressRule
	for _, r := range cfg.SuppressRules {
		suppressRules = append(suppressRules, collector.SuppressRule{
			Match: r.Match, Source: r.Source, Reason: r.Reason,
		})
	}
	suppress := collector.NewSuppressMatcher(suppressRules)
	if len(suppressRules) > 0 {
		slog.Info("suppression rules loaded", "count", len(suppressRules))
	}

	// Build immediate alerter from config
	dispatch := alerter.New(alerter.Config{
		MinSeverity: cfg.Alerter.MinSeverity,
		Cooldown:    cfg.SignalCooldown,
		Slack:       toAlertSlack(cfg.Alerter.Slack),
		Telegram:    toAlertTelegram(cfg.Alerter.Telegram),
		Email:       toAlertEmail(cfg.Alerter.Email),
		Webhooks:    toAlertWebhooks(cfg.Alerter.Webhooks),
		Syslog:      toAlertSyslog(cfg.Alerter.Syslog),
	})

	// Event bus — buffered to avoid blocking collectors.
	events := make(chan collector.Event, 512)

	// Open SQLite buffer
	store, err := buffer.Open(*dbPath, cfg.BufferRetentionHours)
	if err != nil {
		slog.Error("failed to open event store", "err", err)
		os.Exit(1)
	}

	// Context wired to OS signals — collectors and server shut down on cancel.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Start collectors
	fileWatcher, err := collector.NewFileWatcher(cfg.WatchPaths, cfg.ExcludePaths, events, suppress)
	if err != nil {
		slog.Warn("file watcher unavailable", "err", err)
	} else {
		if err := fileWatcher.Start(); err != nil {
			slog.Warn("file watcher start failed", "err", err)
		} else {
			slog.Info("file watcher started", "paths", cfg.WatchPaths)
		}
		defer fileWatcher.Stop()
	}

	procWatcher := collector.NewProcessWatcher(cfg.PollInterval, events, suppress)
	procWatcher.Start()
	defer procWatcher.Stop()
	slog.Info("process watcher started", "interval", cfg.PollInterval)

	netWatcher := collector.NewNetworkWatcher(cfg.PollInterval, events, suppress)
	netWatcher.Start()
	defer netWatcher.Stop()
	slog.Info("network watcher started", "interval", cfg.PollInterval)

	if cfg.SupplyChainGuard.Enabled {
		ecosystems := buildEcosystems(cfg.SupplyChainGuard)
		if len(ecosystems) == 0 {
			slog.Warn("supply-chain guard enabled but no ecosystems configured")
		} else {
			roots := cfg.SupplyChainGuard.Roots
			if len(roots) == 0 {
				roots = []string{"$HOME"}
			}
			scGuard := collector.NewSupplyChainGuard(
				roots,
				cfg.SupplyChainGuard.ScanInterval,
				ecosystems,
				events,
				suppress,
			)
			scGuard.Start()
			defer scGuard.Stop()
			names := make([]string, len(ecosystems))
			for i, e := range ecosystems {
				names[i] = e.Name()
			}
			slog.Info("supply-chain guard started",
				"roots", roots, "interval", cfg.SupplyChainGuard.ScanInterval, "ecosystems", names)
		}
	}

	if cfg.AuditdLogPath != "" {
		auditWatcher := collector.NewAuditdWatcher(cfg.AuditdLogPath, events, suppress)
		if err := auditWatcher.Start(); err != nil {
			slog.Warn("auditd watcher unavailable", "path", cfg.AuditdLogPath, "err", err)
		} else {
			slog.Info("auditd watcher started", "path", cfg.AuditdLogPath)
			defer auditWatcher.Stop()
		}
	}

	// Web dashboard (optional)
	var webSrv *web.Server
	webEnabled := cfg.WebAddr != ""
	if webEnabled {
		webSrv = web.New(store, web.Config{Token: cfg.WebToken})
		go func() {
			slog.Info("web dashboard listening", "addr", cfg.WebAddr)
			if err := webSrv.Listen(ctx, cfg.WebAddr); err != nil && ctx.Err() == nil {
				slog.Error("web dashboard error", "err", err)
			}
		}()
	}

	// Drain event bus → SQLite + immediate alerter.
	// WaitGroup ensures all events are flushed before store.Close().
	var drainWg sync.WaitGroup
	var eventsDropped uint64
	drainWg.Add(1)
	go func() {
		defer drainWg.Done()
		for e := range events {
			if err := store.Insert(e); err != nil {
				slog.Error("failed to insert event", "err", err)
				continue
			}
			slog.Debug("event stored",
				"source", e.Source,
				"action", e.Action,
				"resource", e.Resource,
				"severity", e.Severity,
			)
			// Broadcast to SSE subscribers if web is enabled.
			if webEnabled {
				webSrv.Broadcast(e)
			}
			// Tier-1: fire immediately for high/critical events.
			if dispatch.ShouldAlert(e) {
				go func(ev collector.Event) {
					dispatch.Fire(ev)
					// Keep expvar metrics in sync with alerter counters.
					if webEnabled {
						s := dispatch.Stats()
						webSrv.SetAlertCounters(s.AlertsSent, s.AlertsDropped)
					}
				}(e)
			}
		}
	}()

	// MCP server
	mcpServer := vigilomcp.New(store)

	slog.Info("vigilo daemon ready",
		"mcp_transport", cfg.MCPTransport,
		"signal_cooldown", cfg.SignalCooldown,
	)

	switch cfg.MCPTransport {
	case "http":
		addr := cfg.MCPAddr
		if addr == "" {
			addr = ":7070"
		}
		slog.Info("MCP server listening", "addr", addr)
		go func() {
			if err := mcpServer.ServeSSE(addr); err != nil {
				slog.Error("MCP HTTP server error", "err", err)
				cancel()
			}
		}()
		<-ctx.Done()
	default: // "stdio"
		if err := mcpServer.ServeStdio(ctx); err != nil {
			slog.Error("MCP stdio server error", "err", err)
			os.Exit(1)
		}
	}

	// Graceful shutdown: close events channel, wait for drain, close store.
	close(events)
	drainWg.Wait()
	if dropped := atomic.LoadUint64(&eventsDropped); dropped > 0 {
		slog.Warn("events dropped during shutdown", "count", dropped)
	}
	if err := store.Close(); err != nil {
		slog.Warn("store close error", "err", err)
	}

	slog.Info("vigilo daemon stopped")
}

// buildEcosystems assembles the enabled supply-chain ecosystem analyzers from
// config. Add a case here (and a config sub-block) to register a new ecosystem.
func buildEcosystems(cfg config.SupplyChainGuardConfig) []collector.Ecosystem {
	var out []collector.Ecosystem
	if tf := cfg.Terraform; tf != nil && tf.Enabled {
		out = append(out, collector.NewTerraformEcosystem(tf.AllowedProviderPrefixes, tf.PinnedHashes))
	}
	if npm := cfg.Npm; npm != nil && npm.Enabled {
		out = append(out, collector.NewNpmEcosystem(npm.AllowedRegistries))
	}
	return out
}

// Conversion helpers — keep config and alerter packages decoupled.

func toAlertSlack(c *config.SlackConfig) *alerter.SlackConfig {
	if c == nil {
		return nil
	}
	return &alerter.SlackConfig{WebhookURL: c.WebhookURL}
}

func toAlertTelegram(c *config.TelegramConfig) *alerter.TelegramConfig {
	if c == nil {
		return nil
	}
	return &alerter.TelegramConfig{BotToken: c.BotToken, ChatID: c.ChatID}
}

func toAlertEmail(c *config.EmailConfig) *alerter.EmailConfig {
	if c == nil {
		return nil
	}
	return &alerter.EmailConfig{
		SMTPHost: c.SMTPHost,
		SMTPPort: c.SMTPPort,
		Username: c.Username,
		Password: c.Password,
		From:     c.From,
		To:       c.To,
	}
}

func toAlertWebhooks(ws []config.WebhookConfig) []alerter.WebhookConfig {
	out := make([]alerter.WebhookConfig, len(ws))
	for i, w := range ws {
		out[i] = alerter.WebhookConfig{Name: w.Name, URL: w.URL, Headers: w.Headers}
	}
	return out
}

func toAlertSyslog(c *config.SyslogConfig) *alerter.SyslogConfig {
	if c == nil {
		return nil
	}
	return &alerter.SyslogConfig{Enabled: c.Enabled}
}
