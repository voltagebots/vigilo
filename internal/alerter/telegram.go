package alerter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/voltagebots/vigilo/internal/collector"
)

// TelegramConfig uses the Telegram Bot API.
// Create a bot at https://t.me/BotFather → /newbot → copy the token.
// Get your chat/group ID: add @userinfobot to the group, it will reply with the ID.
type TelegramConfig struct {
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
}

type telegramChannel struct {
	cfg    *TelegramConfig
	client *http.Client
}

func newTelegramChannel(cfg *TelegramConfig, client *http.Client) *telegramChannel {
	return &telegramChannel{cfg: cfg, client: client}
}
func (t *telegramChannel) name() string { return "telegram" }

func (t *telegramChannel) send(e collector.Event, _ string) error {
	sev := strings.ToUpper(string(e.Severity))

	lines := []string{
		fmt.Sprintf("<b>Vigilo Alert -- %s</b>", sev),
		fmt.Sprintf("<b>Source:</b> %s", e.Source),
		fmt.Sprintf("<b>Action:</b> <code>%s</code>", e.Action),
		fmt.Sprintf("<b>Resource:</b> <code>%s</code>", e.Resource),
	}
	if e.Process != "" {
		lines = append(lines, fmt.Sprintf("<b>Process:</b> <code>%s</code> (pid %d)", e.Process, e.PID))
	}
	if e.Detail != "" {
		lines = append(lines, fmt.Sprintf("<b>Detail:</b> %s", e.Detail))
	}
	text := strings.Join(lines, "\n")

	payload := map[string]any{
		"chat_id":    t.cfg.ChatID,
		"text":       text,
		"parse_mode": "HTML",
	}
	b, _ := json.Marshal(payload)

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.cfg.BotToken)
	resp, err := t.client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram api: status %d", resp.StatusCode)
	}
	return nil
}
