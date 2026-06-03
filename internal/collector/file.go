package collector

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// sensitivePatterns marks accesses to these as high/critical severity.
var sensitivePatterns = []struct {
	pattern  string
	severity Severity
}{
	{".env", SeverityHigh},
	{"keystore", SeverityCritical},
	{"wallet.json", SeverityCritical},
	{".pem", SeverityCritical},
	{".key", SeverityCritical},
	{"private_key", SeverityHigh},
	{"mnemonic", SeverityCritical},
	{"seed", SeverityHigh},
	{"secret", SeverityHigh},
	{"credentials", SeverityHigh},
	{".ethereum", SeverityHigh},
	{".bitcoin", SeverityHigh},
	{"id_rsa", SeverityCritical},
	{"id_ed25519", SeverityCritical},
}

func severityForPath(path string) Severity {
	lower := strings.ToLower(path)
	for _, p := range sensitivePatterns {
		if strings.Contains(lower, p.pattern) {
			return p.severity
		}
	}
	return SeverityInfo
}

// FileWatcher uses fsnotify to emit Events when sensitive files are accessed.
type FileWatcher struct {
	paths    []string
	exclude  []string
	suppress *SuppressMatcher
	out      chan<- Event
	watcher  *fsnotify.Watcher
}

func NewFileWatcher(paths, exclude []string, out chan<- Event, suppress ...*SuppressMatcher) (*FileWatcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	var sm *SuppressMatcher
	if len(suppress) > 0 {
		sm = suppress[0]
	}
	return &FileWatcher{paths: paths, exclude: exclude, suppress: sm, out: out, watcher: w}, nil
}

func (fw *FileWatcher) Start() error {
	for _, p := range fw.paths {
		expanded := os.ExpandEnv(p)
		if err := fw.addRecursive(expanded); err != nil {
			slog.Warn("file watcher: cannot watch path", "path", expanded, "err", err)
		}
	}

	go fw.loop()
	return nil
}

func (fw *FileWatcher) Stop() {
	fw.watcher.Close()
}

func (fw *FileWatcher) addRecursive(root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable
		}
		if fw.isExcluded(path) {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return fw.watcher.Add(path)
		}
		return nil
	})
}

func (fw *FileWatcher) isExcluded(path string) bool {
	for _, ex := range fw.exclude {
		if strings.HasPrefix(path, os.ExpandEnv(ex)) {
			return true
		}
	}
	return false
}

func (fw *FileWatcher) loop() {
	for {
		select {
		case event, ok := <-fw.watcher.Events:
			if !ok {
				return
			}
			// Only care about reads and writes to sensitive files
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				sev := severityForPath(event.Name)
				action := "write"
				if event.Has(fsnotify.Create) {
					action = "create"
				}
				e := Event{
					Source:    SourceFile,
					Timestamp: time.Now(),
					Action:    action,
					Resource:  event.Name,
					Severity:  sev,
				}
				if !fw.suppress.IsSuppressed(e) {
					fw.out <- e
				}
			}
			// New subdirectory created — start watching it
			if event.Has(fsnotify.Create) {
				if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
					_ = fw.watcher.Add(event.Name)
				}
			}

		case err, ok := <-fw.watcher.Errors:
			if !ok {
				return
			}
			slog.Error("file watcher error", "err", err)
		}
	}
}
