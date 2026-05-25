// Package alerter provides immediate (daemon-side) push alerts for high/critical
// events — no LLM involved, fires within seconds of detection.
// The TS analyst agent handles pattern correlation on its own schedule.
package alerter

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/voltagebots/vigilo/internal/collector"
)

// Config holds all alerter configuration loaded from the daemon config file.
type Config struct {
	// Minimum severity to trigger immediate alerts: "high" or "critical"
	MinSeverity string `yaml:"min_severity"`

	Slack    *SlackConfig    `yaml:"slack"`
	Telegram *TelegramConfig `yaml:"telegram"`
	Email    *EmailConfig    `yaml:"email"`
	Webhooks []WebhookConfig `yaml:"webhooks"`
}

// Dispatcher fires all configured alert channels for a given event.
type Dispatcher struct {
	cfg      Config
	channels []channel
}

type channel interface {
	name() string
	send(e collector.Event, msg string) error
}

var severityRank = map[collector.Severity]int{
	collector.SeverityInfo:     0,
	collector.SeverityMedium:   1,
	collector.SeverityHigh:     2,
	collector.SeverityCritical: 3,
}

func New(cfg Config) *Dispatcher {
	d := &Dispatcher{cfg: cfg}

	if cfg.Slack != nil && cfg.Slack.WebhookURL != "" {
		d.channels = append(d.channels, newSlackChannel(cfg.Slack))
	}
	if cfg.Telegram != nil && cfg.Telegram.BotToken != "" && cfg.Telegram.ChatID != "" {
		d.channels = append(d.channels, newTelegramChannel(cfg.Telegram))
	}
	if cfg.Email != nil && cfg.Email.SMTPHost != "" && len(cfg.Email.To) > 0 {
		d.channels = append(d.channels, newEmailChannel(cfg.Email))
	}
	for i := range cfg.Webhooks {
		d.channels = append(d.channels, newWebhookChannel(&cfg.Webhooks[i]))
	}

	if len(d.channels) > 0 {
		names := make([]string, len(d.channels))
		for i, c := range d.channels {
			names[i] = c.name()
		}
		slog.Info("immediate alerter ready", "channels", strings.Join(names, ","))
	}
	return d
}

// ShouldAlert returns true if the event severity meets the configured threshold.
func (d *Dispatcher) ShouldAlert(e collector.Event) bool {
	if len(d.channels) == 0 {
		return false
	}
	minSev := collector.Severity(d.cfg.MinSeverity)
	if minSev == "" {
		minSev = collector.SeverityHigh
	}
	return severityRank[e.Severity] >= severityRank[minSev]
}

// Fire sends an immediate alert to all configured channels.
func (d *Dispatcher) Fire(e collector.Event) {
	msg := formatAlert(e)
	for _, ch := range d.channels {
		if err := ch.send(e, msg); err != nil {
			slog.Error("alert send failed", "channel", ch.name(), "err", err)
		}
	}
}

func formatAlert(e collector.Event) string {
	sev := strings.ToUpper(string(e.Severity))
	ts := e.Timestamp.UTC().Format(time.RFC3339)
	lines := []string{
		fmt.Sprintf("🚨 VIGILO ALERT — %s", sev),
		fmt.Sprintf("Source:   %s", e.Source),
		fmt.Sprintf("Action:   %s", e.Action),
		fmt.Sprintf("Resource: %s", e.Resource),
		fmt.Sprintf("Time:     %s", ts),
	}
	if e.Process != "" {
		lines = append(lines, fmt.Sprintf("Process:  %s (pid %d)", e.Process, e.PID))
	}
	if e.Detail != "" {
		lines = append(lines, fmt.Sprintf("Detail:   %s", e.Detail))
	}
	return strings.Join(lines, "\n")
}
