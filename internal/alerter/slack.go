package alerter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/voltagebots/vigilo/internal/collector"
)

// SlackConfig uses an incoming webhook URL — no bot token required.
// Create one at: https://api.slack.com/apps → Incoming Webhooks
type SlackConfig struct {
	WebhookURL string `yaml:"webhook_url"`
}

type slackChannel struct {
	cfg *SlackConfig
}

func newSlackChannel(cfg *SlackConfig) *slackChannel { return &slackChannel{cfg: cfg} }
func (s *slackChannel) name() string                  { return "slack" }

func (s *slackChannel) send(e collector.Event, _ string) error {
	emoji := severityEmoji(e.Severity)
	payload := map[string]any{
		"text": fmt.Sprintf("%s *[%s]* `%s` → `%s`  (%s)",
			emoji, strings.ToUpper(string(e.Severity)),
			e.Action, e.Resource, e.Source),
		"blocks": []map[string]any{
			{
				"type": "section",
				"text": map[string]any{
					"type": "mrkdwn",
					"text": fmt.Sprintf(
						"%s *Vigilo Immediate Alert — %s*\n*Action:* `%s`\n*Resource:* `%s`\n*Source:* %s%s",
						emoji,
						strings.ToUpper(string(e.Severity)),
						e.Action, e.Resource, e.Source,
						func() string {
							if e.Process != "" {
								return fmt.Sprintf("\n*Process:* `%s` (pid %d)", e.Process, e.PID)
							}
							return ""
						}(),
					),
				},
			},
		},
	}

	b, _ := json.Marshal(payload)
	resp, err := http.Post(s.cfg.WebhookURL, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook: status %d", resp.StatusCode)
	}
	return nil
}

func severityEmoji(sev collector.Severity) string {
	switch sev {
	case collector.SeverityCritical:
		return "🔴"
	case collector.SeverityHigh:
		return "🟠"
	case collector.SeverityMedium:
		return "🟡"
	default:
		return "🔵"
	}
}
