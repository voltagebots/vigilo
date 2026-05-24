package buffer_test

import (
	"os"
	"testing"
	"time"

	"github.com/voltagebots/vigilo/internal/buffer"
	"github.com/voltagebots/vigilo/internal/collector"
)

func openTestStore(t *testing.T) *buffer.Store {
	t.Helper()
	f, err := os.CreateTemp("", "vigilo-test-*.db")
	if err != nil {
		t.Fatalf("create temp db: %v", err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })

	store, err := buffer.Open(f.Name(), 24)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return store
}

func makeEvent(source collector.EventSource, action, resource string, sev collector.Severity) collector.Event {
	return collector.Event{
		Source:    source,
		Timestamp: time.Now(),
		Action:    action,
		Resource:  resource,
		Severity:  sev,
	}
}

func TestInsertAndGet(t *testing.T) {
	store := openTestStore(t)

	e := makeEvent(collector.SourceFile, "write", "/app/.env", collector.SeverityHigh)
	if err := store.Insert(e); err != nil {
		t.Fatalf("insert: %v", err)
	}

	events, err := store.List(buffer.QueryOptions{Since: time.Now().Add(-time.Minute)})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Resource != "/app/.env" {
		t.Errorf("resource mismatch: got %q", events[0].Resource)
	}
	if events[0].Severity != collector.SeverityHigh {
		t.Errorf("severity mismatch: got %q", events[0].Severity)
	}
}

func TestListFilterBySource(t *testing.T) {
	store := openTestStore(t)

	_ = store.Insert(makeEvent(collector.SourceFile, "write", "/app/.env", collector.SeverityHigh))
	_ = store.Insert(makeEvent(collector.SourceProcess, "spawn", "bash", collector.SeverityCritical))
	_ = store.Insert(makeEvent(collector.SourceNetwork, "connect", "1.2.3.4:4444", collector.SeverityCritical))

	fileEvents, err := store.List(buffer.QueryOptions{
		Since:   time.Now().Add(-time.Minute),
		Sources: []string{string(collector.SourceFile)},
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(fileEvents) != 1 {
		t.Errorf("expected 1 file event, got %d", len(fileEvents))
	}
	if fileEvents[0].Source != collector.SourceFile {
		t.Errorf("wrong source: %q", fileEvents[0].Source)
	}
}

func TestListFilterBySeverity(t *testing.T) {
	store := openTestStore(t)

	_ = store.Insert(makeEvent(collector.SourceFile, "write", "/tmp/readme.txt", collector.SeverityInfo))
	_ = store.Insert(makeEvent(collector.SourceFile, "write", "/app/.env", collector.SeverityHigh))
	_ = store.Insert(makeEvent(collector.SourceNetwork, "connect", "1.2.3.4:4444", collector.SeverityCritical))

	highPlus, err := store.List(buffer.QueryOptions{
		Since:    time.Now().Add(-time.Minute),
		Severity: "high",
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(highPlus) != 2 {
		t.Errorf("expected 2 high+ events, got %d", len(highPlus))
	}
	for _, e := range highPlus {
		if e.Severity == collector.SeverityInfo || e.Severity == collector.SeverityMedium {
			t.Errorf("low-severity event slipped through: %q", e.Severity)
		}
	}
}

func TestListSinceFilter(t *testing.T) {
	store := openTestStore(t)

	// Insert an old event by manipulating timestamp via direct insert
	oldEvent := collector.Event{
		Source:    collector.SourceFile,
		Timestamp: time.Now().Add(-2 * time.Hour),
		Action:    "write",
		Resource:  "/old/path",
		Severity:  collector.SeverityHigh,
	}
	_ = store.Insert(oldEvent)
	_ = store.Insert(makeEvent(collector.SourceFile, "write", "/new/path", collector.SeverityHigh))

	recent, err := store.List(buffer.QueryOptions{Since: time.Now().Add(-time.Minute)})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(recent) != 1 {
		t.Errorf("expected 1 recent event, got %d", len(recent))
	}
	if recent[0].Resource != "/new/path" {
		t.Errorf("wrong event returned: %q", recent[0].Resource)
	}
}

func TestListLimit(t *testing.T) {
	store := openTestStore(t)

	for i := 0; i < 10; i++ {
		_ = store.Insert(makeEvent(collector.SourceFile, "write", "/app/.env", collector.SeverityHigh))
	}

	limited, err := store.List(buffer.QueryOptions{
		Since: time.Now().Add(-time.Minute),
		Limit: 3,
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(limited) != 3 {
		t.Errorf("expected 3 events, got %d", len(limited))
	}
}

func TestEmptyStoreReturnsEmpty(t *testing.T) {
	store := openTestStore(t)
	events, err := store.List(buffer.QueryOptions{Since: time.Now().Add(-time.Minute)})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events from empty store, got %d", len(events))
	}
}

func TestMultipleSourceFilter(t *testing.T) {
	store := openTestStore(t)

	_ = store.Insert(makeEvent(collector.SourceFile, "write", "/app/.env", collector.SeverityHigh))
	_ = store.Insert(makeEvent(collector.SourceProcess, "spawn", "bash", collector.SeverityCritical))
	_ = store.Insert(makeEvent(collector.SourceNetwork, "connect", "1.2.3.4:4444", collector.SeverityCritical))

	both, err := store.List(buffer.QueryOptions{
		Since:   time.Now().Add(-time.Minute),
		Sources: []string{string(collector.SourceFile), string(collector.SourceProcess)},
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(both) != 2 {
		t.Errorf("expected 2 events, got %d", len(both))
	}
}
