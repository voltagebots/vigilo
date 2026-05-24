package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

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

	// Event bus — buffered to avoid blocking collectors
	events := make(chan collector.Event, 512)

	// Open SQLite buffer
	store, err := buffer.Open(*dbPath, cfg.BufferRetentionHours)
	if err != nil {
		slog.Error("failed to open event store", "err", err)
		os.Exit(1)
	}

	// Start collectors
	fileWatcher, err := collector.NewFileWatcher(cfg.WatchPaths, cfg.ExcludePaths, events)
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

	procWatcher := collector.NewProcessWatcher(cfg.PollInterval, events)
	procWatcher.Start()
	defer procWatcher.Stop()
	slog.Info("process watcher started", "interval", cfg.PollInterval)

	netWatcher := collector.NewNetworkWatcher(cfg.PollInterval, events)
	netWatcher.Start()
	defer netWatcher.Stop()
	slog.Info("network watcher started", "interval", cfg.PollInterval)

	// Drain event bus → SQLite
	go func() {
		for e := range events {
			if err := store.Insert(e); err != nil {
				slog.Error("failed to insert event", "err", err)
			} else {
				slog.Debug("event stored",
					"source", e.Source,
					"action", e.Action,
					"resource", e.Resource,
					"severity", e.Severity,
				)
			}
		}
	}()

	// MCP server
	mcpServer := vigilomcp.New(store)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	slog.Info("vigilo daemon ready", "mcp_transport", cfg.MCPTransport)

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
