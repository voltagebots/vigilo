package collector

import "testing"

// This file defines the Ecosystem conformance harness: the invariants every
// supply-chain Ecosystem must satisfy. New ecosystems inherit this whole suite
// by declaring an ecosystemConformance and calling runEcosystemConformance —
// so a broken plugin can't ship, and correctness scales with plugin count.

// expectedFinding is an ecosystem-agnostic assertion about one emitted event.
type expectedFinding struct {
	action   string
	severity Severity
}

// conformanceCase is one input file plus its expected findings.
type conformanceCase struct {
	name    string
	file    string // base name passed to Inspect
	content string
	want    []expectedFinding // empty = expect no findings
}

// ecosystemConformance is the full conformance contract for one ecosystem.
type ecosystemConformance struct {
	ecosystem Ecosystem
	match     []string // filenames Matches() must accept
	nonMatch  []string // filenames Matches() must reject
	cases     []conformanceCase
}

func runEcosystemConformance(t *testing.T, c ecosystemConformance) {
	t.Helper()
	eco := c.ecosystem

	if eco.Name() == "" {
		t.Error("Name() must be non-empty")
	}
	for _, f := range c.match {
		if !eco.Matches(f) {
			t.Errorf("Matches(%q) = false, want true", f)
		}
	}
	for _, f := range c.nonMatch {
		if eco.Matches(f) {
			t.Errorf("Matches(%q) = true, want false", f)
		}
	}

	for _, tc := range c.cases {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte(tc.content)
			snapshot := string(content)

			got := eco.Inspect(tc.file, content)
			again := eco.Inspect(tc.file, []byte(tc.content))

			// Determinism (order-insensitive — ecosystems may iterate maps).
			if !findingsEqual(got, again) {
				t.Errorf("Inspect not deterministic:\n first=%v\n second=%v", got, again)
			}
			// Purity: must not mutate its input.
			if string(content) != snapshot {
				t.Error("Inspect mutated its content argument")
			}
			// Every finding is well-formed.
			for _, e := range got {
				if e.Source != SourceSupplyChain {
					t.Errorf("finding source = %q, want %q", e.Source, SourceSupplyChain)
				}
				if e.Action == "" {
					t.Error("finding has empty action")
				}
				if !validSeverity(e.Severity) {
					t.Errorf("finding has invalid severity %q", e.Severity)
				}
			}
			assertFindings(t, got, tc.want)
		})
	}
}

func validSeverity(s Severity) bool {
	switch s {
	case SeverityInfo, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// findingKey identifies a finding ignoring timestamp (which varies per call).
type findingKey struct {
	action   string
	severity Severity
	resource string
	detail   string
}

func findingsEqual(a, b []Event) bool {
	if len(a) != len(b) {
		return false
	}
	ma := map[findingKey]int{}
	for _, e := range a {
		ma[findingKey{e.Action, e.Severity, e.Resource, e.Detail}]++
	}
	for _, e := range b {
		ma[findingKey{e.Action, e.Severity, e.Resource, e.Detail}]--
	}
	for _, v := range ma {
		if v != 0 {
			return false
		}
	}
	return true
}

// assertFindings checks got contains exactly the want (action, severity) pairs,
// order-insensitive.
func assertFindings(t *testing.T, got []Event, want []expectedFinding) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(got), len(want), got)
	}
	counts := map[expectedFinding]int{}
	for _, e := range got {
		counts[expectedFinding{e.Action, e.Severity}]++
	}
	for _, w := range want {
		counts[w]--
	}
	for k, v := range counts {
		if v != 0 {
			t.Errorf("finding mismatch for %+v (delta %d); got=%+v", k, v, got)
		}
	}
}
