package collector

import "testing"

func TestIOCStoreMatchesIncidentC2(t *testing.T) {
	// The 2026-07 infostealer's C2 IP, over :443 — the case port heuristics miss.
	s := NewIOCStore(KnownC2IPRanges)
	m, ok := s.MatchIP("149.154.166.110")
	if !ok {
		t.Fatal("known incident C2 IP not matched")
	}
	if m.Severity != SeverityCritical {
		t.Errorf("severity = %s, want critical", m.Severity)
	}
}

func TestIOCStoreCleanIP(t *testing.T) {
	s := NewIOCStore(KnownC2IPRanges)
	if _, ok := s.MatchIP("1.1.1.1"); ok {
		t.Error("clean IP matched an indicator")
	}
}

func TestIOCStoreCustomRange(t *testing.T) {
	s := NewIOCStore([]IOCIPRange{
		{CIDR: "203.0.113.0/24", Label: "test-bad", Severity: SeverityHigh},
	})
	m, ok := s.MatchIP("203.0.113.42")
	if !ok || m.Severity != SeverityHigh || m.Label != "test-bad" {
		t.Fatalf("custom range not matched correctly: %+v ok=%v", m, ok)
	}
}

func TestIOCStoreNilSafe(t *testing.T) {
	var s *IOCStore // nil — collectors hold an optional store
	if _, ok := s.MatchIP("149.154.166.110"); ok {
		t.Error("nil store should match nothing")
	}
	if !s.Empty() {
		t.Error("nil store should be Empty")
	}
}

func TestIOCStoreInvalidCIDRSkipped(t *testing.T) {
	s := NewIOCStore([]IOCIPRange{
		{CIDR: "not-a-cidr", Label: "bad", Severity: SeverityHigh},
		{CIDR: "198.51.100.0/24", Label: "good", Severity: SeverityCritical},
	})
	if s.Empty() {
		t.Fatal("valid entry should survive an invalid one")
	}
	if _, ok := s.MatchIP("198.51.100.7"); !ok {
		t.Error("valid range after invalid one not matched")
	}
}

func TestIOCStoreDefaultSeverity(t *testing.T) {
	s := NewIOCStore([]IOCIPRange{
		{CIDR: "192.0.2.0/24", Label: "no-sev"}, // severity omitted
	})
	m, ok := s.MatchIP("192.0.2.1")
	if !ok || m.Severity != SeverityHigh {
		t.Errorf("missing severity should default to high, got %s ok=%v", m.Severity, ok)
	}
}
