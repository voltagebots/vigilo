package collector

import (
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// Ecosystem is a pluggable supply-chain analyzer for one package/dependency
// ecosystem (Terraform, npm, pip, cargo, …). New ecosystems are added by
// implementing this interface — the SupplyChainGuard needs no changes.
type Ecosystem interface {
	// Name identifies the ecosystem, e.g. "terraform".
	Name() string
	// Matches reports whether this ecosystem handles a file with the given base name.
	Matches(filename string) bool
	// Inspect parses a matched file and returns any findings as Events
	// (Source SourceSupplyChain, severity/action/detail already set).
	Inspect(path string, content []byte) []Event
}

// ExtraPathProvider is an optional capability: an ecosystem that also needs to
// inspect fixed absolute paths outside the scanned roots (e.g. a global CLI
// config referenced by an env var).
type ExtraPathProvider interface {
	ExtraPaths() []string
}

// SupplyChainGuard walks configured roots on an interval and routes each matched
// dependency-manifest / lockfile / CLI-config file to the ecosystems that handle
// it. It owns the shared machinery — scheduling, walking, dedup, suppress, emit —
// so ecosystems only implement parsing + validation. Tier-0: pure rules, no LLM.
type SupplyChainGuard struct {
	roots      []string
	interval   time.Duration
	ecosystems []Ecosystem
	suppress   *SuppressMatcher
	out        chan<- Event
	seen       map[string]bool // dedup: don't re-emit the same finding every scan
	stop       chan struct{}
}

func NewSupplyChainGuard(roots []string, interval time.Duration, ecosystems []Ecosystem, out chan<- Event, suppress ...*SuppressMatcher) *SupplyChainGuard {
	var sm *SuppressMatcher
	if len(suppress) > 0 {
		sm = suppress[0]
	}
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	expanded := make([]string, 0, len(roots))
	for _, r := range roots {
		expanded = append(expanded, os.ExpandEnv(r))
	}
	return &SupplyChainGuard{
		roots:      expanded,
		interval:   interval,
		ecosystems: ecosystems,
		suppress:   sm,
		out:        out,
		seen:       make(map[string]bool),
		stop:       make(chan struct{}),
	}
}

func (g *SupplyChainGuard) Start() { go g.loop() }
func (g *SupplyChainGuard) Stop()  { close(g.stop) }

func (g *SupplyChainGuard) loop() {
	ticker := time.NewTicker(g.interval)
	defer ticker.Stop()
	g.scan()
	for {
		select {
		case <-g.stop:
			return
		case <-ticker.C:
			g.scan()
		}
	}
}

func (g *SupplyChainGuard) scan() {
	for _, root := range g.roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // skip unreadable
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", "node_modules", "vendor", ".terraform":
					return filepath.SkipDir
				}
				return nil
			}
			g.inspectFile(path, d.Name())
			return nil
		})
	}
	// Ecosystem-declared absolute paths outside the roots.
	for _, e := range g.ecosystems {
		ep, ok := e.(ExtraPathProvider)
		if !ok {
			continue
		}
		for _, p := range ep.ExtraPaths() {
			content, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			for _, ev := range e.Inspect(p, content) {
				g.emit(ev)
			}
		}
	}
}

// inspectFile routes one file to every ecosystem that claims it, reading the
// file at most once.
func (g *SupplyChainGuard) inspectFile(path, name string) {
	var matched []Ecosystem
	for _, e := range g.ecosystems {
		if e.Matches(name) {
			matched = append(matched, e)
		}
	}
	if len(matched) == 0 {
		return
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, e := range matched {
		for _, ev := range e.Inspect(path, content) {
			g.emit(ev)
		}
	}
}

// emit deduplicates and forwards a finding to the event bus.
func (g *SupplyChainGuard) emit(e Event) {
	key := string(e.Source) + "|" + e.Action + "|" + e.Resource + "|" + e.Detail
	if g.seen[key] {
		return
	}
	g.seen[key] = true
	if g.suppress.IsSuppressed(e) {
		return
	}
	slog.Info("supply-chain finding",
		"action", e.Action, "resource", e.Resource, "severity", e.Severity)
	g.out <- e
}
