package e2e_test

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSSEStreamDeliversEvent connects to /events/stream and verifies that a file
// write triggers an SSE message on the stream.
func TestSSEStreamDeliversEvent(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}})

	// Open SSE connection
	req, err := http.NewRequest(http.MethodGet, "http://"+d.webAddr+"/events/stream", nil)
	if err != nil {
		t.Fatalf("build SSE request: %v", err)
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("connect SSE: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("SSE status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Errorf("Content-Type = %q, want text/event-stream", resp.Header.Get("Content-Type"))
	}

	// Read SSE events in a goroutine
	events := make(chan string, 8)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				events <- strings.TrimPrefix(line, "data: ")
			}
		}
	}()

	// Give SSE connection time to establish, then trigger an event
	time.Sleep(200 * time.Millisecond)
	os.WriteFile(filepath.Join(dir, "wallet.json"), []byte(`{}`), 0600) //nolint:errcheck

	select {
	case raw := <-events:
		var e map[string]any
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			t.Fatalf("SSE data not valid JSON: %v\nraw: %s", err, raw)
		}
		if e["source"] != "file_access" {
			t.Errorf("SSE event source = %v, want file_access", e["source"])
		}
		if !strings.Contains(e["resource"].(string), "wallet.json") {
			t.Errorf("SSE event resource = %v, want wallet.json", e["resource"])
		}
	case <-time.After(8 * time.Second):
		t.Fatal("no SSE event received within 8s")
	}
}

// TestMetricsCounterIncrements verifies vigilo_events_total increases after events.
func TestMetricsCounterIncrements(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}})

	readCounter := func(name string) int64 {
		resp, err := http.Get("http://" + d.webAddr + "/metrics")
		if err != nil {
			return -1
		}
		defer resp.Body.Close()
		var all map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&all); err != nil {
			return -1
		}
		v, ok := all[name]
		if !ok {
			return 0
		}
		// expvar encodes ints as JSON numbers
		if f, ok := v.(float64); ok {
			return int64(f)
		}
		return 0
	}

	before := readCounter("vigilo_events_total")

	// Trigger an event via the SSE path (Broadcast is only called when web is enabled)
	time.Sleep(150 * time.Millisecond)
	os.WriteFile(filepath.Join(dir, "wallet.json"), []byte(`{}`), 0600) //nolint:errcheck

	ok := pollUntil(t, func() bool {
		return readCounter("vigilo_events_total") > before
	})
	if !ok {
		t.Fatalf("vigilo_events_total did not increase from %d", before)
	}
}

// TestMetricsEndpointContainsKnownCounters verifies the /metrics response includes
// all expected expvar keys.
func TestMetricsEndpointContainsKnownCounters(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}})

	resp, err := http.Get("http://" + d.webAddr + "/metrics")
	if err != nil {
		t.Fatalf("metrics request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	for _, key := range []string{
		"vigilo_events_total",
		"vigilo_alerts_sent",
		"vigilo_alerts_dropped",
		"vigilo_web_requests_total",
	} {
		if !strings.Contains(string(body), key) {
			t.Errorf("metrics missing key %q", key)
		}
	}
}

// TestWebRequestsCounterIncrements verifies vigilo_web_requests_total tracks HTTP calls.
func TestWebRequestsCounterIncrements(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}})

	readWebRequests := func() int64 {
		resp, err := http.Get("http://" + d.webAddr + "/metrics")
		if err != nil {
			return -1
		}
		defer resp.Body.Close()
		var all map[string]any
		json.NewDecoder(resp.Body).Decode(&all) //nolint:errcheck
		if f, ok := all["vigilo_web_requests_total"].(float64); ok {
			return int64(f)
		}
		return 0
	}

	before := readWebRequests()

	// Each /api/events call increments the counter
	for i := 0; i < 3; i++ {
		http.Get("http://" + d.webAddr + "/api/events") //nolint:errcheck
	}

	after := readWebRequests()
	if after <= before {
		t.Errorf("web_requests_total did not increase: before=%d after=%d", before, after)
	}
}

// TestNotFoundReturns404 verifies unknown routes return 404 (not 200).
func TestNotFoundReturns404(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}})

	resp, err := http.Get("http://" + d.webAddr + "/api/nonexistent")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("unknown route status = %d, want 404", resp.StatusCode)
	}
}

// TestRateLimitReturns429AfterBurst verifies the web server enforces its burst limit.
func TestRateLimitReturns429AfterBurst(t *testing.T) {
	dir := t.TempDir()
	d := startDaemon(t, daemonOpts{watchPaths: []string{dir}})

	// Fire > 20 requests instantly to exhaust the burst of 20
	got429 := false
	client := &http.Client{Timeout: 2 * time.Second}
	for i := 0; i < 30; i++ {
		resp, err := client.Get("http://" + d.webAddr + "/api/events")
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 429 {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Error("30 rapid requests did not trigger 429 rate limit")
	}
}
