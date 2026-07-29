package collector

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TerraformEcosystem is the Ecosystem implementation for Terraform. It inspects
// provider lockfiles (.terraform.lock.hcl) and CLI config (.terraformrc) for the
// two ways `terraform init` can be made to fetch a trojaned provider that then
// executes on `plan` — the vector behind the "malicious provider via fake
// assessment" (DPRK Contagious Interview) pattern:
//
//  1. Untrusted / typosquatted provider source — a `provider "…"` address not on
//     the allowlist (e.g. registry.terraform.io/hashicorpp/aws, or a non-official
//     registry host).
//  2. Mirror swap — a `network_mirror`/`filesystem_mirror` in .terraformrc that
//     serves a trojaned binary under the real provider name; optionally confirmed
//     by a pinned-hash mismatch in the lockfile.
type TerraformEcosystem struct {
	allowed []string            // allowlisted provider source prefixes
	pinned  map[string][]string // "source@version" -> known-good hashes (optional)
}

// DefaultAllowedProviderPrefixes is the baseline trust set — official HashiCorp
// providers. Operators extend this with their own org namespaces via config.
var DefaultAllowedProviderPrefixes = []string{
	"registry.terraform.io/hashicorp/",
}

func NewTerraformEcosystem(allowed []string, pinned map[string][]string) *TerraformEcosystem {
	if len(allowed) == 0 {
		allowed = DefaultAllowedProviderPrefixes
	}
	return &TerraformEcosystem{allowed: allowed, pinned: pinned}
}

func (t *TerraformEcosystem) Name() string { return "terraform" }

func (t *TerraformEcosystem) Matches(filename string) bool {
	switch filename {
	case ".terraform.lock.hcl", ".terraformrc", "terraform.rc":
		return true
	}
	return false
}

func (t *TerraformEcosystem) Inspect(path string, content []byte) []Event {
	switch filepath.Base(path) {
	case ".terraform.lock.hcl":
		return t.inspectLockfile(path, parseLockfile(string(content)))
	case ".terraformrc", "terraform.rc":
		return t.inspectTerraformrc(path, content)
	}
	return nil
}

// ExtraPaths adds the global CLI config referenced by TF_CLI_CONFIG_FILE, which
// lives outside the scanned roots.
func (t *TerraformEcosystem) ExtraPaths() []string {
	if v := os.Getenv("TF_CLI_CONFIG_FILE"); v != "" {
		return []string{v}
	}
	return nil
}

// inspectLockfile applies the provider-trust rules to parsed locks. Pure (no IO).
func (t *TerraformEcosystem) inspectLockfile(file string, locks []ProviderLock) []Event {
	var out []Event
	for _, p := range locks {
		if !t.sourceAllowed(p.Source) {
			sev := SeverityHigh
			action := "provider_untrusted_source"
			detail := "provider source not on allowlist: " + p.Source + " (in " + file + ")"
			if t.looksLikeTyposquat(p.Source) {
				sev = SeverityCritical
				action = "provider_typosquat"
				detail = "provider source is a likely typosquat of a trusted namespace: " + p.Source + " (in " + file + ")"
			}
			out = append(out, Event{
				Source:    SourceSupplyChain,
				Timestamp: time.Now(),
				Action:    action,
				Resource:  p.Source,
				Detail:    detail,
				Severity:  sev,
			})
			continue
		}
		// Optional hash pinning — confirms a mirror swap even under a trusted name.
		if want, ok := t.pinned[p.Source+"@"+p.Version]; ok && len(p.Hashes) > 0 {
			if !hashesIntersect(want, p.Hashes) {
				out = append(out, Event{
					Source:    SourceSupplyChain,
					Timestamp: time.Now(),
					Action:    "provider_hash_mismatch",
					Resource:  p.Source,
					Detail:    "lockfile hashes for " + p.Source + "@" + p.Version + " do not match pinned known-good hashes — possible mirror swap (in " + file + ")",
					Severity:  SeverityCritical,
				})
			}
		}
	}
	return out
}

// inspectTerraformrc flags a provider mirror, which redirects `init` away from
// the official registry — the setup step for a mirror-swap attack.
func (t *TerraformEcosystem) inspectTerraformrc(file string, content []byte) []Event {
	lower := strings.ToLower(string(content))
	if strings.Contains(lower, "network_mirror") || strings.Contains(lower, "filesystem_mirror") {
		return []Event{{
			Source:    SourceSupplyChain,
			Timestamp: time.Now(),
			Action:    "provider_mirror_config",
			Resource:  file,
			Detail:    "Terraform CLI config defines a provider mirror — init will fetch providers from a non-registry source",
			Severity:  SeverityHigh,
		}}
	}
	return nil
}

func (t *TerraformEcosystem) sourceAllowed(source string) bool {
	for _, prefix := range t.allowed {
		if strings.HasPrefix(source, prefix) {
			return true
		}
	}
	return false
}

// looksLikeTyposquat reports whether source's registry+namespace is a near-miss
// (edit distance 1-2) of an allowlisted namespace — e.g. hashicorpp vs hashicorp.
func (t *TerraformEcosystem) looksLikeTyposquat(source string) bool {
	ns := namespaceOf(source)
	if ns == "" {
		return false
	}
	for _, prefix := range t.allowed {
		allowedNS := strings.TrimSuffix(prefix, "/")
		if d := levenshtein(ns, allowedNS); d > 0 && d <= 2 {
			return true
		}
	}
	return false
}

// namespaceOf returns the registry+namespace portion of a provider source,
// i.e. everything up to (not including) the final "/type" segment.
// "registry.terraform.io/hashicorpp/aws" -> "registry.terraform.io/hashicorpp"
func namespaceOf(source string) string {
	i := strings.LastIndex(source, "/")
	if i < 0 {
		return ""
	}
	return source[:i]
}

func hashesIntersect(a, b []string) bool {
	set := make(map[string]struct{}, len(a))
	for _, x := range a {
		set[x] = struct{}{}
	}
	for _, y := range b {
		if _, ok := set[y]; ok {
			return true
		}
	}
	return false
}

// ProviderLock is one provider block parsed from a .terraform.lock.hcl file.
type ProviderLock struct {
	Source  string
	Version string
	Hashes  []string
}

// parseLockfile does a dependency-free line parse of the (simple, stable)
// .terraform.lock.hcl grammar.
func parseLockfile(content string) []ProviderLock {
	var locks []ProviderLock
	var cur *ProviderLock
	inHashes := false
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if cur == nil {
			if src, ok := parseProviderHeader(line); ok {
				cur = &ProviderLock{Source: src}
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "version"):
			cur.Version = firstQuoted(line)
		case strings.HasPrefix(line, "hashes"):
			inHashes = !strings.Contains(line, "]")
			cur.Hashes = append(cur.Hashes, allQuoted(line)...)
		case inHashes:
			if strings.Contains(line, "]") {
				inHashes = false
			}
			cur.Hashes = append(cur.Hashes, allQuoted(line)...)
		case line == "}":
			locks = append(locks, *cur)
			cur = nil
			inHashes = false
		}
	}
	if cur != nil {
		locks = append(locks, *cur)
	}
	return locks
}

// parseProviderHeader matches lines of the form: provider "<source>" {
func parseProviderHeader(line string) (string, bool) {
	if !strings.HasPrefix(line, "provider") || !strings.HasSuffix(line, "{") {
		return "", false
	}
	src := firstQuoted(line)
	if src == "" {
		return "", false
	}
	return src, true
}

// firstQuoted returns the first double-quoted substring in line, or "".
func firstQuoted(line string) string {
	start := strings.Index(line, `"`)
	if start < 0 {
		return ""
	}
	rest := line[start+1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// allQuoted returns every double-quoted substring in line.
func allQuoted(line string) []string {
	var out []string
	for {
		start := strings.Index(line, `"`)
		if start < 0 {
			break
		}
		rest := line[start+1:]
		end := strings.Index(rest, `"`)
		if end < 0 {
			break
		}
		out = append(out, rest[:end])
		line = rest[end+1:]
	}
	return out
}

// levenshtein is a small edit-distance for typosquat detection.
func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}
