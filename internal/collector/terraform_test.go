package collector

import "testing"

const officialLock = `# maintained automatically
provider "registry.terraform.io/hashicorp/aws" {
  version     = "5.31.0"
  constraints = ">= 5.0.0"
  hashes = [
    "h1:goodhashaaa",
    "zh:goodhashbbb",
  ]
}
`

const typosquatLock = `provider "registry.terraform.io/hashicorpp/aws" {
  version = "5.31.0"
  hashes = [
    "h1:evilhash",
  ]
}
`

const unknownRegistryLock = `provider "evil-registry.io/foo/aws" {
  version = "1.0.0"
  hashes  = [ "h1:x" ]
}
`

func TestTerraformConformance(t *testing.T) {
	runEcosystemConformance(t, ecosystemConformance{
		ecosystem: NewTerraformEcosystem(nil, nil),
		match:     []string{".terraform.lock.hcl", ".terraformrc", "terraform.rc"},
		nonMatch:  []string{"package.json", "requirements.txt", "main.tf"},
		cases: []conformanceCase{
			{name: "official provider clean", file: ".terraform.lock.hcl", content: officialLock, want: nil},
			{name: "typosquat", file: ".terraform.lock.hcl", content: typosquatLock,
				want: []expectedFinding{{"provider_typosquat", SeverityCritical}}},
			{name: "unknown registry", file: ".terraform.lock.hcl", content: unknownRegistryLock,
				want: []expectedFinding{{"provider_untrusted_source", SeverityHigh}}},
			{name: "mirror config", file: ".terraformrc",
				content: "provider_installation {\n  network_mirror { url = \"https://m.example/\" }\n}",
				want:    []expectedFinding{{"provider_mirror_config", SeverityHigh}}},
		},
	})
}

func TestParseLockfile(t *testing.T) {
	locks := parseLockfile(officialLock)
	if len(locks) != 1 {
		t.Fatalf("want 1 provider, got %d", len(locks))
	}
	p := locks[0]
	if p.Source != "registry.terraform.io/hashicorp/aws" {
		t.Errorf("source = %q", p.Source)
	}
	if p.Version != "5.31.0" {
		t.Errorf("version = %q", p.Version)
	}
	if len(p.Hashes) != 2 {
		t.Errorf("hashes = %v", p.Hashes)
	}
}

func TestOfficialProviderIsClean(t *testing.T) {
	e := NewTerraformEcosystem(nil, nil)
	if evs := e.inspectLockfile("x", parseLockfile(officialLock)); len(evs) != 0 {
		t.Fatalf("official provider flagged: %+v", evs)
	}
}

func TestTyposquatIsCritical(t *testing.T) {
	e := NewTerraformEcosystem(nil, nil)
	evs := e.inspectLockfile("x", parseLockfile(typosquatLock))
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	if evs[0].Severity != SeverityCritical {
		t.Errorf("severity = %s, want critical", evs[0].Severity)
	}
	if evs[0].Action != "provider_typosquat" {
		t.Errorf("action = %s", evs[0].Action)
	}
}

func TestUnknownRegistryIsHigh(t *testing.T) {
	e := NewTerraformEcosystem(nil, nil)
	evs := e.inspectLockfile("x", parseLockfile(unknownRegistryLock))
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	if evs[0].Severity != SeverityHigh {
		t.Errorf("severity = %s, want high", evs[0].Severity)
	}
	if evs[0].Action != "provider_untrusted_source" {
		t.Errorf("action = %s", evs[0].Action)
	}
}

func TestHashPinMismatchIsCritical(t *testing.T) {
	pinned := map[string][]string{
		"registry.terraform.io/hashicorp/aws@5.31.0": {"h1:realhash", "zh:realhash"},
	}
	e := NewTerraformEcosystem(nil, pinned)
	evs := e.inspectLockfile("x", parseLockfile(officialLock)) // hashes are goodhash*, not realhash
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	if evs[0].Action != "provider_hash_mismatch" || evs[0].Severity != SeverityCritical {
		t.Errorf("got action=%s sev=%s", evs[0].Action, evs[0].Severity)
	}
}

func TestHashPinMatchIsClean(t *testing.T) {
	pinned := map[string][]string{
		"registry.terraform.io/hashicorp/aws@5.31.0": {"h1:goodhashaaa"},
	}
	e := NewTerraformEcosystem(nil, pinned)
	if evs := e.inspectLockfile("x", parseLockfile(officialLock)); len(evs) != 0 {
		t.Fatalf("matching hash flagged: %+v", evs)
	}
}

func TestCustomAllowlist(t *testing.T) {
	e := NewTerraformEcosystem(
		[]string{"registry.terraform.io/hashicorp/", "registry.terraform.io/blockopsnetwork/"},
		nil)
	lock := `provider "registry.terraform.io/blockopsnetwork/internal" {
  version = "1.0.0"
  hashes = [ "h1:x" ]
}
`
	if evs := e.inspectLockfile("x", parseLockfile(lock)); len(evs) != 0 {
		t.Fatalf("allowlisted org namespace flagged: %+v", evs)
	}
}

func TestTerraformMatches(t *testing.T) {
	e := NewTerraformEcosystem(nil, nil)
	for _, name := range []string{".terraform.lock.hcl", ".terraformrc", "terraform.rc"} {
		if !e.Matches(name) {
			t.Errorf("should match %q", name)
		}
	}
	if e.Matches("package-lock.json") {
		t.Error("should not match npm lockfile")
	}
}

func TestTerraformrcMirrorFlagged(t *testing.T) {
	e := NewTerraformEcosystem(nil, nil)
	rc := `provider_installation {
  network_mirror { url = "https://mirror.example.com/" }
}`
	evs := e.Inspect(".terraformrc", []byte(rc))
	if len(evs) != 1 || evs[0].Action != "provider_mirror_config" {
		t.Fatalf("mirror not flagged: %+v", evs)
	}
}

// --- Adversarial fixtures ---------------------------------------------------
//
// Every fixture above is well-formed HCL written from the same mental model as
// the parser, which is why a green suite proved nothing about evasion. These
// cases are all valid HCL that terraform honours, and each one previously made
// a hostile provider invisible.

const commentAfterBraceLock = `provider "evil-registry.io/bad/aws" { # pinned by ops
  version = "1.0.0"
  hashes  = [ "h1:x" ]
}
`

const singleLineBlockLock = `provider "evil-registry.io/bad/aws" { version = "1.0.0" }
`

const unterminatedHashesLock = `provider "registry.terraform.io/hashicorp/aws" {
  version = "1.0.0"
  hashes = [
    "h1:a",
}
provider "evil-registry.io/bad/thing" {
  version = "2.0.0"
}
`

func TestTrailingCommentDoesNotHideProvider(t *testing.T) {
	e := NewTerraformEcosystem(nil, nil)
	evs := e.Inspect(".terraform.lock.hcl", []byte(commentAfterBraceLock))
	if len(evs) != 1 || evs[0].Action != "provider_untrusted_source" {
		t.Fatalf("trailing comment hid the provider: %+v", evs)
	}
}

func TestSingleLineBlockDoesNotHideProvider(t *testing.T) {
	e := NewTerraformEcosystem(nil, nil)
	evs := e.Inspect(".terraform.lock.hcl", []byte(singleLineBlockLock))
	if len(evs) != 1 || evs[0].Action != "provider_untrusted_source" {
		t.Fatalf("single-line block hid the provider: %+v", evs)
	}
}

func TestUnterminatedHashesDoesNotSwallowNextProvider(t *testing.T) {
	locks := parseLockfile(unterminatedHashesLock)
	var found bool
	for _, l := range locks {
		if l.Source == "evil-registry.io/bad/thing" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unterminated hashes swallowed the next provider: %+v", locks)
	}
}

func TestUnparseableLockfileIsItselfAFinding(t *testing.T) {
	e := NewTerraformEcosystem(nil, nil)
	evs := e.Inspect(".terraform.lock.hcl", []byte("this is not hcl at all\n{{{\n"))
	if len(evs) != 1 || evs[0].Action != "provider_lockfile_unparseable" {
		t.Fatalf("unparseable lockfile passed as clean: %+v", evs)
	}
	if evs[0].Severity != SeverityHigh {
		t.Errorf("severity = %s, want high", evs[0].Severity)
	}
}

func TestEmptyLockfileIsNotAFinding(t *testing.T) {
	e := NewTerraformEcosystem(nil, nil)
	if evs := e.Inspect(".terraform.lock.hcl", []byte("\n  \n")); len(evs) != 0 {
		t.Fatalf("empty lockfile flagged: %+v", evs)
	}
}

func TestDevOverridesIsCritical(t *testing.T) {
	e := NewTerraformEcosystem(nil, nil)
	rc := "provider_installation {\n  dev_overrides {\n    \"hashicorp/aws\" = \"/tmp/evil\"\n  }\n}"
	evs := e.Inspect(".terraformrc", []byte(rc))
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d: %+v", len(evs), evs)
	}
	if evs[0].Severity != SeverityCritical {
		t.Errorf("dev_overrides severity = %s, want critical (it bypasses lockfile checksums)", evs[0].Severity)
	}
}
