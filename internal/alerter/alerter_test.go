package alerter

import (
	"sync"
	"testing"
	"time"

	"github.com/voltagebots/vigilo/internal/collector"
)

// fakeChannel records every send() call for assertions -- avoids a real
// network call while still exercising Fire()'s real dedup/dispatch logic.
type fakeChannel struct {
	mu    sync.Mutex
	sends int
}

func (f *fakeChannel) name() string { return "fake" }
func (f *fakeChannel) send(_ collector.Event, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sends++
	return nil
}
func (f *fakeChannel) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sends
}

func testEvent() collector.Event {
	return collector.Event{
		Source:   collector.SourceFile,
		Action:   "write",
		Resource: "/app/keystore/x",
		Severity: collector.SeverityCritical,
	}
}

// TestZeroCooldownFiresOnEveryRepeat is a regression for a live-reproduced
// bug: New() treated Cooldown == 0 as "unset" and silently substituted 15
// minutes, so an explicit signal_cooldown: 0s in config.yaml (a real, valid
// request for "no cooldown") suppressed every repeat alert on the same
// resource for 15 minutes -- indistinguishable from never having set the
// field at all.
func TestZeroCooldownFiresOnEveryRepeat(t *testing.T) {
	d := New(Config{MinSeverity: "high", Cooldown: 0})
	fake := &fakeChannel{}
	d.channels = []channel{fake}

	d.Fire(testEvent())
	d.Fire(testEvent())
	d.Fire(testEvent())

	if got := fake.count(); got != 3 {
		t.Fatalf("with Cooldown=0, want 3 sends (no suppression), got %d", got)
	}
}

// TestNegativeCooldownUsesPackageDefault confirms the sentinel: a caller
// that wants the package default now passes a negative Duration instead of
// relying on the zero value, which is reserved for "explicitly no cooldown".
func TestNegativeCooldownUsesPackageDefault(t *testing.T) {
	d := New(Config{MinSeverity: "high", Cooldown: -1})
	fake := &fakeChannel{}
	d.channels = []channel{fake}

	d.Fire(testEvent())
	d.Fire(testEvent())

	if got := fake.count(); got != 1 {
		t.Fatalf("with Cooldown=-1 (package default 15m), want 1 send (second suppressed), got %d", got)
	}
	if d.cfg.Cooldown != 15*time.Minute {
		t.Fatalf("Cooldown = %v, want the resolved 15m default", d.cfg.Cooldown)
	}
}
