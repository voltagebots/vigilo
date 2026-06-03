package e2e_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// webhookSink is a local HTTP server that captures incoming webhook POSTs.
type webhookSink struct {
	server   *httptest.Server
	received chan map[string]any
	calls    atomic.Int64
}

func newWebhookSink(t *testing.T) *webhookSink {
	t.Helper()
	sink := &webhookSink{received: make(chan map[string]any, 32)}
	sink.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sink.calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err == nil {
			select {
			case sink.received <- payload:
			default:
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(sink.server.Close)
	return sink
}

// startDaemonWithWebhook starts a daemon configured to POST alerts to sink.
func startDaemonWithWebhook(t *testing.T, sink *webhookSink, watchDir, minSeverity string, cooldown string) *instance {
	t.Helper()
	return startDaemon(t, daemonOpts{
		watchPaths:  []string{watchDir},
		webhookURL:  sink.server.URL,
		minSeverity: minSeverity,
		cooldown:    cooldown,
	})
}

// TestWebhookFiredForCriticalEvent verifies a critical file write triggers a webhook POST.
func TestWebhookFiredForCriticalEvent(t *testing.T) {
	sink := newWebhookSink(t)
	dir := t.TempDir()
	startDaemonWithWebhook(t, sink, dir, "high", "1s")
	time.Sleep(150 * time.Millisecond)

	os.WriteFile(filepath.Join(dir, "wallet.json"), []byte(`{"key":"secret"}`), 0600) //nolint:errcheck

	select {
	case payload := <-sink.received:
		if payload["severity"] != "critical" {
			t.Errorf("webhook severity = %v, want critical", payload["severity"])
		}
		if !strings.Contains(payload["resource"].(string), "wallet.json") {
			t.Errorf("webhook resource = %v, want wallet.json", payload["resource"])
		}
		if payload["source"] != "file_access" {
			t.Errorf("webhook source = %v, want file_access", payload["source"])
		}
	case <-time.After(8 * time.Second):
		t.Fatal("no webhook received within 8s after wallet.json write")
	}
}

// TestWebhookNotFiredBelowThreshold verifies that events below min_severity are not alerted.
func TestWebhookNotFiredBelowThreshold(t *testing.T) {
	sink := newWebhookSink(t)
	dir := t.TempDir()
	// min_severity=critical — .env (high) must NOT trigger webhook
	startDaemonWithWebhook(t, sink, dir, "critical", "1s")
	time.Sleep(150 * time.Millisecond)

	// .env → SeverityHigh — below the critical threshold
	os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=x"), 0600) //nolint:errcheck

	// Sentinel: wallet.json → critical → should trigger (proves daemon is live)
	time.Sleep(300 * time.Millisecond)
	os.WriteFile(filepath.Join(dir, "wallet.json"), []byte(`{}`), 0600) //nolint:errcheck

	// Wait for sentinel
	select {
	case payload := <-sink.received:
		// Only the wallet.json (critical) should arrive
		if !strings.Contains(payload["resource"].(string), "wallet.json") {
			t.Errorf("unexpected webhook for %v (expected only wallet.json)", payload["resource"])
		}
	case <-time.After(8 * time.Second):
		t.Fatal("sentinel wallet.json webhook never received")
	}

	// Drain any remaining — .env must not appear
	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case payload := <-sink.received:
			if strings.Contains(payload["resource"].(string), ".env") {
				t.Errorf("webhook fired for .env (high) when threshold is critical")
			}
		case <-deadline:
			return
		}
	}
}

// TestWebhookDedupSuppressesRepeat verifies the cooldown prevents duplicate alerts
// for the same resource within the cooldown window.
func TestWebhookDedupSuppressesRepeat(t *testing.T) {
	sink := newWebhookSink(t)
	dir := t.TempDir()
	// Long cooldown so the second write is definitely within the window
	startDaemonWithWebhook(t, sink, dir, "high", "30s")
	time.Sleep(150 * time.Millisecond)

	walletPath := filepath.Join(dir, "wallet.json")
	os.WriteFile(walletPath, []byte(`{"key":"first"}`), 0600) //nolint:errcheck

	// Wait for first alert
	select {
	case <-sink.received:
	case <-time.After(8 * time.Second):
		t.Fatal("first webhook not received")
	}

	// Write again — same resource, within cooldown window
	time.Sleep(200 * time.Millisecond)
	os.WriteFile(walletPath, []byte(`{"key":"second"}`), 0600) //nolint:errcheck

	// No second webhook should arrive within 2 seconds
	select {
	case payload := <-sink.received:
		t.Errorf("dedup failed: second webhook fired for %v", payload["resource"])
	case <-time.After(2 * time.Second):
		// correct — suppressed
	}
}

// TestWebhookPayloadShape verifies the JSON structure of the webhook payload.
func TestWebhookPayloadShape(t *testing.T) {
	sink := newWebhookSink(t)
	dir := t.TempDir()
	startDaemonWithWebhook(t, sink, dir, "high", "1s")
	time.Sleep(150 * time.Millisecond)

	os.WriteFile(filepath.Join(dir, "wallet.json"), []byte(`{}`), 0600) //nolint:errcheck

	select {
	case payload := <-sink.received:
		required := []string{"source", "timestamp", "action", "resource", "severity"}
		for _, field := range required {
			if _, ok := payload[field]; !ok {
				t.Errorf("webhook payload missing field %q", field)
			}
		}
		// Timestamp must be RFC3339
		ts, _ := payload["timestamp"].(string)
		if _, err := time.Parse(time.RFC3339, ts); err != nil {
			t.Errorf("timestamp %q not RFC3339: %v", ts, err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("webhook not received")
	}
}
