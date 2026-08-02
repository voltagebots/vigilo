package collector

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// NpmEcosystem is the Ecosystem implementation for npm. It inspects package.json,
// package-lock.json, and .npmrc for the npm delivery vectors of the same
// supply-chain campaigns (DPRK Contagious Interview / BeaverTail ships via
// malicious lifecycle scripts and registry substitution):
//
//  1. Malicious lifecycle scripts — preinstall/install/postinstall/prepare that
//     fetch+exec a payload (curl|sh, node -e, base64 -d, child_process…).
//  2. Non-registry dependency sources — a dep pinned to an http tarball or
//     git+http URL instead of the registry.
//  3. Registry substitution — a package-lock `resolved` host, or an .npmrc
//     `registry=` override, pointing at a non-allowlisted registry.
type NpmEcosystem struct {
	allowedRegistries []string
}

// DefaultAllowedNpmRegistries is the baseline trust set for npm.
var DefaultAllowedNpmRegistries = []string{"registry.npmjs.org"}

// npmInstallHooks are the lifecycle scripts that run automatically on install —
// the ones an attacker plants a payload in.
var npmInstallHooks = []string{"preinstall", "install", "postinstall", "prepare", "prepublish"}

// npmScriptRedFlags mark a lifecycle script as payload-fetching/exec.
var npmScriptRedFlags = []string{
	"curl", "wget", "|sh", "| sh", "|bash", "| bash", "node -e", "node --eval",
	"base64 -d", "base64 --decode", "atob(", "child_process", "eval(", "-fssl",
}

func NewNpmEcosystem(allowedRegistries []string) *NpmEcosystem {
	if len(allowedRegistries) == 0 {
		allowedRegistries = DefaultAllowedNpmRegistries
	}
	return &NpmEcosystem{allowedRegistries: allowedRegistries}
}

func (n *NpmEcosystem) Name() string { return "npm" }

func (n *NpmEcosystem) Matches(filename string) bool {
	switch filename {
	case "package.json", "package-lock.json", ".npmrc":
		return true
	}
	return false
}

func (n *NpmEcosystem) Inspect(path string, content []byte) []Event {
	switch filepath.Base(path) {
	case "package.json":
		return n.inspectPackageJSON(path, content)
	case "package-lock.json":
		return n.inspectPackageLock(path, content)
	case ".npmrc":
		return n.inspectNpmrc(path, content)
	}
	return nil
}

type npmPackageJSON struct {
	Scripts         map[string]string `json:"scripts"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func (n *NpmEcosystem) inspectPackageJSON(file string, content []byte) []Event {
	var pkg npmPackageJSON
	if json.Unmarshal(content, &pkg) != nil {
		return nil
	}
	var out []Event

	for _, hook := range npmInstallHooks {
		cmd, ok := pkg.Scripts[hook]
		if !ok {
			continue
		}
		if tok := scriptRedFlag(cmd); tok != "" {
			out = append(out, Event{
				Source:    SourceSupplyChain,
				Timestamp: time.Now(),
				Action:    "npm_install_script",
				Resource:  file,
				Detail:    "npm lifecycle script '" + hook + "' fetches/executes a payload (matched '" + tok + "'): " + cmd + " (in " + file + ")",
				Severity:  SeverityCritical,
			})
		}
	}

	for _, deps := range []map[string]string{pkg.Dependencies, pkg.DevDependencies} {
		for name, spec := range deps {
			if isNonRegistrySpec(spec) {
				out = append(out, Event{
					Source:    SourceSupplyChain,
					Timestamp: time.Now(),
					Action:    "npm_nonregistry_dependency",
					Resource:  name,
					Detail:    "dependency '" + name + "' resolves from a non-registry source: " + spec + " (in " + file + ")",
					Severity:  SeverityHigh,
				})
			}
		}
	}
	return out
}

type npmLockEntry struct {
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
}

type npmPackageLock struct {
	Packages     map[string]npmLockEntry `json:"packages"`     // v2/v3
	Dependencies map[string]npmLockEntry `json:"dependencies"` // v1
}

func (n *NpmEcosystem) inspectPackageLock(file string, content []byte) []Event {
	var lock npmPackageLock
	if json.Unmarshal(content, &lock) != nil {
		return nil
	}
	var out []Event
	check := func(name string, e npmLockEntry) {
		if e.Resolved == "" {
			return
		}
		host := hostOf(e.Resolved)
		if host == "" || n.registryAllowed(host) {
			return
		}
		label := name
		if label == "" {
			label = e.Resolved
		}
		out = append(out, Event{
			Source:    SourceSupplyChain,
			Timestamp: time.Now(),
			Action:    "npm_untrusted_registry",
			Resource:  host,
			Detail:    "package '" + label + "' resolved from non-allowlisted registry " + host + ": " + e.Resolved + " (in " + file + ")",
			Severity:  SeverityHigh,
		})
	}
	for name, e := range lock.Packages {
		check(name, e)
	}
	for name, e := range lock.Dependencies {
		check(name, e)
	}
	return out
}

func (n *NpmEcosystem) inspectNpmrc(file string, content []byte) []Event {
	var out []Event
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// registry=… or @scope:registry=…
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if !strings.HasSuffix(strings.TrimSpace(key), "registry") {
			continue
		}
		host := hostOf(strings.TrimSpace(val))
		if host == "" || n.registryAllowed(host) {
			continue
		}
		out = append(out, Event{
			Source:    SourceSupplyChain,
			Timestamp: time.Now(),
			Action:    "npm_registry_override",
			Resource:  host,
			Detail:    ".npmrc overrides the registry to a non-allowlisted host " + host + ": " + line + " (in " + file + ")",
			Severity:  SeverityHigh,
		})
	}
	return out
}

func (n *NpmEcosystem) registryAllowed(host string) bool {
	for _, a := range n.allowedRegistries {
		if host == a || strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}

// scriptRedFlag returns the first payload-indicator token found in a script
// command, or "" if none.
func scriptRedFlag(cmd string) string {
	lower := strings.ToLower(cmd)
	for _, flag := range npmScriptRedFlags {
		if strings.Contains(lower, flag) {
			return flag
		}
	}
	return ""
}

// nonRegistrySpecPrefixes are dependency-spec forms that resolve somewhere
// other than the npm registry. npm runs the fetched package's lifecycle
// scripts either way, so any of these is an arbitrary-code-execution path
// under the attacker's control.
// registryAliasPrefixes still resolve from the registry (or the workspace), so
// they are checked before the non-registry forms and the bare-shorthand rule.
var registryAliasPrefixes = []string{"npm:", "workspace:", "catalog:", "jsr:"}

var nonRegistrySpecPrefixes = []string{
	"http://", "https://",
	"git://", "git+http://", "git+https://", "git+ssh://",
	"file:", "link:", "portal:",
	"github:", "gitlab:", "bitbucket:", "gist:",
}

// isNonRegistrySpec reports whether a dependency version spec points somewhere
// other than the npm registry. Note npm accepts a tarball URL with any
// extension, so URL forms are flagged on scheme alone rather than a ".tgz"
// suffix, and the bare "owner/repo" GitHub shorthand counts too.
func isNonRegistrySpec(spec string) bool {
	s := strings.ToLower(strings.TrimSpace(spec))
	if s == "" {
		return false
	}
	// Alias and protocol forms that still resolve from the registry or the
	// workspace. `npm:@scope/pkg@1.0.0` is an ordinary registry install under
	// an alias — common in monorepos — and must not trip the shorthand
	// heuristic below just because it contains a slash.
	for _, p := range registryAliasPrefixes {
		if strings.HasPrefix(s, p) {
			return false
		}
	}
	for _, p := range nonRegistrySpecPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	// Bare GitHub shorthand: "owner/repo" or "owner/repo#ref". Excludes scoped
	// package names ("@scope/pkg") and anything carrying semver range syntax,
	// which are ordinary registry specs.
	if strings.Contains(s, "/") && !strings.HasPrefix(s, "@") &&
		strings.IndexAny(s, "^~<>=* ") == -1 {
		return true
	}
	return false
}

func hostOf(rawurl string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
