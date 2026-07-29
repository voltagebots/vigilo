# Supply-Chain Guard

Tier-0 (rules, no LLM) collector that scans dependency manifests, lockfiles, and
package-manager CLI config for supply-chain tampering — the delivery vector behind
the DPRK "Contagious Interview" campaign, which ships the same infostealer via
Terraform providers, npm lifecycle scripts, pip, cargo, and more.

It is a **software factory**: shared machinery + pluggable per-ecosystem analyzers.
Adding a new ecosystem is a mechanical act — one file, one registration line, one
config block — with no changes to the guard.

## Architecture

```
SupplyChainGuard (internal/collector/supplychain.go)
  owns: walk roots, schedule, read-once, dedup, suppress, emit
  routes each matched file -> Ecosystem analyzers
        |
        Ecosystem interface:
          Name() string
          Matches(filename string) bool
          Inspect(path string, content []byte) []Event
        (optional) ExtraPathProvider: ExtraPaths() []string   # out-of-root files
        |
        +- TerraformEcosystem (terraform.go)  # provider typosquat / mirror / hash-pin
        +- NpmEcosystem       (npm.go)        # install scripts / registry substitution
        +- <your ecosystem>   (…)
```

Findings are emitted as `collector.Event{Source: SourceSupplyChain, …}` and flow
through the normal pipeline (SQLite buffer → immediate alerter on high/critical →
MCP for the analyst).

## Add an ecosystem

1. Create `internal/collector/<eco>.go` implementing `Ecosystem`:

   ```go
   type PipEcosystem struct{ allowed []string }

   func NewPipEcosystem(allowed []string) *PipEcosystem { /* defaults */ }

   func (p *PipEcosystem) Name() string { return "pip" }

   func (p *PipEcosystem) Matches(f string) bool {
       return f == "requirements.txt" || f == "poetry.lock" || f == "Pipfile.lock"
   }

   func (p *PipEcosystem) Inspect(path string, content []byte) []Event {
       // parse; return Events with Source: SourceSupplyChain, an Action,
       // a Severity, and a Detail. Must be pure + deterministic.
   }
   ```

2. Add a conformance test — inherit the whole invariant suite for free:

   ```go
   func TestPipConformance(t *testing.T) {
       runEcosystemConformance(t, ecosystemConformance{
           ecosystem: NewPipEcosystem(nil),
           match:     []string{"requirements.txt", "poetry.lock"},
           nonMatch:  []string{"package.json", ".terraform.lock.hcl"},
           cases: []conformanceCase{
               {name: "clean", file: "requirements.txt", content: "...", want: nil},
               {name: "rogue index", file: "requirements.txt", content: "...",
                   want: []expectedFinding{{"pip_untrusted_index", SeverityHigh}}},
           },
       })
   }
   ```

3. Add a config sub-block in `internal/config/config.go`
   (`SupplyChainGuardConfig.Pip *PipEcosystemConfig`) and register it in
   `cmd/vigilo/main.go` `buildEcosystems`:

   ```go
   if p := cfg.Pip; p != nil && p.Enabled {
       out = append(out, collector.NewPipEcosystem(p.AllowedIndexes))
   }
   ```

That's the entire diff. The guard, walker, dedup, and event pipeline are untouched.

## Conformance contract

Every ecosystem must satisfy (enforced by `runEcosystemConformance`):

- `Name()` is non-empty.
- `Matches` accepts its own files and rejects other ecosystems' files (exclusivity).
- `Inspect` is **deterministic** (same input → same findings, order aside) and
  **pure** (never mutates its `content` argument).
- Every finding has `Source == SourceSupplyChain`, a non-empty `Action`, and a
  valid `Severity`.

## Config

```yaml
supply_chain_guard:
  enabled: true
  roots: ["$HOME/code"]      # defaults to $HOME
  scan_interval: 5m
  terraform:
    enabled: true
    allowed_provider_prefixes:
      - registry.terraform.io/hashicorp/
      - registry.terraform.io/blockopsnetwork/
    pinned_hashes: {}        # optional "source@version" -> [h1:…]
  npm:
    enabled: true
    allowed_registries:
      - registry.npmjs.org
```

## Current detections

| Ecosystem | Finding (action) | Severity |
|---|---|---|
| terraform | `provider_typosquat` (near-miss of trusted namespace) | critical |
| terraform | `provider_untrusted_source` (non-allowlisted registry/namespace) | high |
| terraform | `provider_hash_mismatch` (lockfile hashes miss pinned set) | critical |
| terraform | `provider_mirror_config` (`network_mirror`/`filesystem_mirror` in `.terraformrc`) | high |
| npm | `npm_install_script` (payload-fetching lifecycle hook) | critical |
| npm | `npm_nonregistry_dependency` (http tarball / git+http dep) | high |
| npm | `npm_untrusted_registry` (lockfile `resolved` off-allowlist) | high |
| npm | `npm_registry_override` (`.npmrc` registry to non-allowlisted host) | high |
