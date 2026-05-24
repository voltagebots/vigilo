package collector

import (
	"log/slog"
	"strings"
)

// SuppressRule mirrors config.SuppressRule without creating an import cycle.
type SuppressRule struct {
	Match  string
	Source string
	Reason string
}

// SuppressMatcher checks events against a list of suppression rules.
type SuppressMatcher struct {
	rules []SuppressRule
}

func NewSuppressMatcher(rules []SuppressRule) *SuppressMatcher {
	return &SuppressMatcher{rules: rules}
}

// IsSuppressed returns true if the event matches any rule.
func (sm *SuppressMatcher) IsSuppressed(e Event) bool {
	if sm == nil {
		return false
	}
	lowerResource := strings.ToLower(e.Resource)
	lowerProcess := strings.ToLower(e.Process)
	src := string(e.Source)

	for _, r := range sm.rules {
		if r.Source != "" && r.Source != src {
			continue
		}
		lowerMatch := strings.ToLower(r.Match)
		if strings.Contains(lowerResource, lowerMatch) || strings.Contains(lowerProcess, lowerMatch) {
			slog.Debug("event suppressed", "rule", r.Match, "reason", r.Reason,
				"resource", e.Resource, "source", src)
			return true
		}
	}
	return false
}
