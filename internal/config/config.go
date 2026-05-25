package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// SuppressRule suppresses events whose resource or process contains Match.
// Source is optional — if empty the rule applies to all sources.
type SuppressRule struct {
	Match  string `yaml:"match"`  // substring to match against resource or process name
	Source string `yaml:"source"` // optional: file_access|process|network
	Reason string `yaml:"reason"` // human-readable explanation logged on suppression
}

type Config struct {
	// Paths to watch for sensitive file access
	WatchPaths []string `yaml:"watch_paths"`

	// Paths to exclude from watching (test fixtures, etc.)
	ExcludePaths []string `yaml:"exclude_paths"`

	// How often to poll /proc and network state
	PollInterval time.Duration `yaml:"poll_interval"`

	// SQLite buffer: keep last N hours of events
	BufferRetentionHours int `yaml:"buffer_retention_hours"`

	// MCP server transport: "stdio" or "http"
	MCPTransport string `yaml:"mcp_transport"`
	MCPAddr      string `yaml:"mcp_addr"` // only for http mode, e.g. ":7070"

	// Alert webhook (optional — agent can also pull via MCP)
	AlertWebhookURL string `yaml:"alert_webhook_url"`

	// Anthropic key for local standalone mode
	AnthropicAPIKey string `yaml:"anthropic_api_key"`

	// Signal dedup cooldown — same signal won't re-alert within this window
	SignalCooldown time.Duration `yaml:"signal_cooldown"`

	// Suppress rules — events matching any rule are dropped before buffering
	SuppressRules []SuppressRule `yaml:"suppress_rules"`
}

var Defaults = Config{
	WatchPaths: []string{
		"$HOME/.ethereum",
		"$HOME/.bitcoin",
		"/etc/vigilo/keys",
		"/run/secrets",
	},
	PollInterval:         5 * time.Second,
	BufferRetentionHours: 24,
	MCPTransport:         "stdio",
	SignalCooldown:       time.Hour,
}

func Load(path string) (*Config, error) {
	cfg := Defaults

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &cfg, nil // use defaults
		}
		return nil, err
	}
	defer f.Close()

	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
