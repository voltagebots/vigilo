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
		locks := parseLockfile(string(content))
		// A non-empty lockfile that yields no provider blocks means the parser
		// was defeated — by malformed HCL, an unhandled form, or deliberate
		// evasion. Silence there is indistinguishable from "clean", so treat
		// the parse failure itself as the finding.
		if len(locks) == 0 && hasNonCommentContent(string(content)) {
			return []Event{{
				Source:    SourceSupplyChain,
				Timestamp: time.Now(),
				Action:    "provider_lockfile_unparseable",
				Resource:  path,
				Detail:    "lockfile is non-empty but no provider blocks were parsed — malformed HCL or evasion attempt (in " + path + ")",
				Severity:  SeverityHigh,
			}}
		}
		return t.inspectLockfile(path, locks)
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

// terraformProviderRedirects are the CLI-config mechanisms that redirect where
// `init` sources a provider binary from. dev_overrides is the most dangerous:
// it points terraform at an arbitrary local directory and skips registry AND
// lockfile checksum verification entirely.
var terraformProviderRedirects = []struct {
	token  string
	detail string
	sev    Severity
}{
	{"dev_overrides", "Terraform CLI config defines dev_overrides — init/plan will load an unverified local provider binary, bypassing both the registry and lockfile checksums", SeverityCritical},
	{"network_mirror", "Terraform CLI config defines a provider mirror — init will fetch providers from a non-registry source", SeverityHigh},
	{"filesystem_mirror", "Terraform CLI config defines a provider mirror — init will fetch providers from a non-registry source", SeverityHigh},
}

// inspectTerraformrc flags provider-source redirection, the setup step for
// serving a trojaned provider under a trusted name.
func (t *TerraformEcosystem) inspectTerraformrc(file string, content []byte) []Event {
	lower := strings.ToLower(string(content))
	var out []Event
	for _, r := range terraformProviderRedirects {
		if strings.Contains(lower, r.token) {
			out = append(out, Event{
				Source:    SourceSupplyChain,
				Timestamp: time.Now(),
				Action:    "provider_mirror_config",
				Resource:  file,
				Detail:    r.detail + " (in " + file + ")",
				Severity:  r.sev,
			})
		}
	}
	return out
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
		// Strip comments BEFORE any structural decision. A `}` inside a trailing
		// comment must not be read as a block close — that silently discarded the
		// provider's version and hashes, which skipped the hash-pin check.
		line := stripComment(raw)
		if line == "" {
			continue
		}
		// A provider header always starts a new block, even if the previous one
		// was never closed — a missing `}` must not make every subsequent
		// provider invisible.
		if src, ok := parseProviderHeader(line); ok {
			if cur != nil {
				locks = append(locks, *cur)
			}
			cur = &ProviderLock{Source: src}
			inHashes = false
			// Single-line block: `provider "x" { ... }` closes immediately.
			if i := strings.Index(line, "{"); i >= 0 && strings.Contains(line[i+1:], "}") {
				locks = append(locks, *cur)
				cur = nil
			}
			continue
		}
		if cur == nil {
			continue
		}
		switch {
		// A closing brace ends the provider block even mid-hashes: an
		// unterminated `hashes = [` must not swallow the next provider header.
		case line == "}":
			locks = append(locks, *cur)
			cur = nil
			inHashes = false
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
		}
	}
	if cur != nil {
		locks = append(locks, *cur)
	}
	return locks
}

// stripComment removes a trailing `#` or `//` comment and surrounding space.
// Quote-aware: hash values are base64-ish and legitimately contain `/`, so a
// naive split would truncate a hash like "zh:aa//bb" into a wrong value.
func stripComment(line string) string {
	inQuote := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\\':
			if inQuote {
				i++ // skip the escaped character
			}
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote {
				return strings.TrimSpace(line[:i])
			}
		case '/':
			if !inQuote && i+1 < len(line) && line[i+1] == '/' {
				return strings.TrimSpace(line[:i])
			}
		}
	}
	return strings.TrimSpace(line)
}

// hasNonCommentContent reports whether content holds anything but comments and
// whitespace. Terraform's auto-generated lockfile header is two comment lines,
// and a lockfile carrying only that header is legitimate (all providers removed
// from the config) — it must not be reported as unparseable.
func hasNonCommentContent(content string) bool {
	for _, raw := range strings.Split(content, "\n") {
		if stripComment(raw) != "" {
			return true
		}
	}
	return false
}

// parseProviderHeader matches lines of the form: provider "<source>" {
// The opening brace need only appear after the quoted source, not at
// end-of-line — `provider "x" { # pinned by ops` is valid HCL that terraform
// honours, and requiring a trailing brace made such a provider invisible.
func parseProviderHeader(line string) (string, bool) {
	if !strings.HasPrefix(line, "provider") {
		return "", false
	}
	src := firstQuoted(line)
	if src == "" {
		return "", false
	}
	// The brace must come after the closing quote of the source, otherwise
	// this is a reference to a provider rather than a block header.
	if i := strings.Index(line, src); i >= 0 {
		if !strings.Contains(line[i+len(src):], "{") {
			return "", false
		}
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
