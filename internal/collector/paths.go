package collector

import (
	"os"
	"path/filepath"
	"strings"
)

// expandPath resolves a configured path: `~` / `~/…` to the current user's home
// directory, then $VAR references.
//
// os.ExpandEnv alone does not touch `~`, so a config written the way operators
// naturally write it — `~/.ssh` — used to be handed to the OS verbatim and
// silently matched nothing. Silent non-coverage is the failure mode this
// package exists to prevent, so expansion is shared by every collector that
// takes paths from config.
func expandPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			p = filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return os.ExpandEnv(p)
}
