package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/voltagebots/vigilo/internal/alerter"
	"github.com/voltagebots/vigilo/internal/buffer"
	"github.com/voltagebots/vigilo/internal/collector"
	"github.com/voltagebots/vigilo/internal/config"
	vigilomcp "github.com/voltagebots/vigilo/internal/mcp"
)

func main() {
	configPath := flag.String("config", "/etc/vigilo/config.yaml", "Path to config file")
	dbPath := flag.String("db", "/var/lib/vigilo/events.db", "SQLite database path")
	flag.Parse()

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
		Slack:       toAlertSlack(cfg.Alerter.Slack),
		Telegram:    toAlertTelegram(cfg.Alerter.Telegram),
		Email:       toAlertEmail(cfg.Alerter.Email),
		Webhooks:    toAlertWebhooks(cfg.Alerter.Webhooks),
	})

	// Event bus — buffered to avoid blocking collectors
	events := make(chan collector.Event, 512)

	// Open SQLite buffer
	store, err := buffer.Open(*dbPath, cfg.BufferRetentionHours)
	if err != nil {
		slog.Error("failed to open event store", "err", err)
		os.Exit(1)
	}

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

	if cfg.AuditdLogPath != "" {
		auditWatcher := collector.NewAuditdWatcher(cfg.AuditdLogPath, events, suppress)
		if err := auditWatcher.Start(); err != nil {
			slog.Warn("auditd watcher unavailable", "path", cfg.AuditdLogPath, "err", err)
		} else {
			slog.Info("auditd watcher started", "path", cfg.AuditdLogPath)
			defer auditWatcher.Stop()
		}
	}

	// Drain event bus → SQLite + immediate alerter
	go func() {
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
			// Tier-1: fire immediately for high/critical events
			if dispatch.ShouldAlert(e) {
				go dispatch.Fire(e)
			}
		}
	}()

	// MCP server
	mcpServer := vigilomcp.New(store)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

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

	slog.Info("vigilo daemon stopped")
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
