package mcp_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/voltagebots/vigilo/internal/buffer"
	"github.com/voltagebots/vigilo/internal/collector"
	vigilomcp "github.com/voltagebots/vigilo/internal/mcp"
)

func openTestStore(t *testing.T) *buffer.Store {
	t.Helper()
	f, err := os.CreateTemp("", "vigilo-mcp-test-*.db")
	if err != nil {
		t.Fatalf("temp db: %v", err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	store, err := buffer.Open(f.Name(), 24)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return store
}

func insertEvent(t *testing.T, store *buffer.Store, source collector.EventSource, action, resource string, sev collector.Severity) {
	t.Helper()
	if err := store.Insert(collector.Event{
		Source:    source,
		Timestamp: time.Now(),
		Action:    action,
		Resource:  resource,
		Severity:  sev,
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
}

// callTool invokes a tool on the Server by constructing a CallToolRequest directly.
func callTool(t *testing.T, srv *vigilomcp.Server, name string, args map[string]any) []collector.Event {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Name = name
	req.Params.Arguments = args

	result, err := srv.CallTool(context.Background(), req)
	if err != nil {
		t.Fatalf("CallTool %q: %v", name, err)
	}
	if len(result.Content) == 0 {
		t.Fatalf("CallTool %q: empty content", name)
	}
	text, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("CallTool %q: unexpected content type", name)
	}

	var events []collector.Event
	if err := json.Unmarshal([]byte(text.Text), &events); err != nil {
		t.Fatalf("unmarshal result: %v\nraw: %s", err, text.Text)
	}
	return events
}

func TestGetAllEvents(t *testing.T) {
	store := openTestStore(t)
	insertEvent(t, store, collector.SourceFile, "write", "/app/.env", collector.SeverityHigh)
	insertEvent(t, store, collector.SourceProcess, "spawn", "bash", collector.SeverityCritical)

	srv := vigilomcp.New(store)
	since := time.Now().Add(-time.Minute).Format(time.RFC3339)
	events := callTool(t, srv, "get_all_events", map[string]any{"since": since})

	if len(events) != 2 {
		t.Errorf("expected 2 events, got %d", len(events))
	}
}

func TestGetFileEvents(t *testing.T) {
	store := openTestStore(t)
	insertEvent(t, store, collector.SourceFile, "write", "/app/.env", collector.SeverityHigh)
	insertEvent(t, store, collector.SourceProcess, "spawn", "bash", collector.SeverityCritical)

	srv := vigilomcp.New(store)
	since := time.Now().Add(-time.Minute).Format(time.RFC3339)
	events := callTool(t, srv, "get_file_access_events", map[string]any{"since": since})

	if len(events) != 1 {
		t.Errorf("expected 1 file event, got %d", len(events))
	}
	if events[0].Source != collector.SourceFile {
		t.Errorf("wrong source: %q", events[0].Source)
	}
}

func TestGetCriticalEvents(t *testing.T) {
	store := openTestStore(t)
	insertEvent(t, store, collector.SourceFile, "write", "/tmp/readme.txt", collector.SeverityInfo)
	insertEvent(t, store, collector.SourceFile, "write", "/app/.env", collector.SeverityHigh)
	insertEvent(t, store, collector.SourceNetwork, "connect", "1.2.3.4:4444", collector.SeverityCritical)

	srv := vigilomcp.New(store)
	since := time.Now().Add(-time.Minute).Format(time.RFC3339)
	events := callTool(t, srv, "get_critical_events", map[string]any{"since": since})

	if len(events) != 2 {
		t.Errorf("expected 2 high+ events, got %d", len(events))
	}
	for _, e := range events {
		if e.Severity == collector.SeverityInfo || e.Severity == collector.SeverityMedium {
			t.Errorf("low severity event returned: %q", e.Severity)
		}
	}
}

func TestEmptyResultReturnsArray(t *testing.T) {
	store := openTestStore(t)
	srv := vigilomcp.New(store)
	since := time.Now().Add(-time.Minute).Format(time.RFC3339)
	events := callTool(t, srv, "get_all_events", map[string]any{"since": since})
	if events == nil {
		t.Error("expected empty array, got nil")
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}
}
