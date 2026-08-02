//go:build linux

package collector

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// suspiciousChildren maps parent process names to child processes that are
// suspicious when spawned from that parent.
var suspiciousChildren = map[string][]string{
	"node":    {"sh", "bash", "curl", "wget", "python", "python3", "nc", "ncat"},
	"python":  {"sh", "bash", "curl", "wget", "nc", "ncat"},
	"python3": {"sh", "bash", "curl", "wget", "nc", "ncat"},
	"java":    {"sh", "bash", "curl", "wget"},
	"nginx":   {"sh", "bash", "python", "python3"},
}

type procInfo struct {
	pid     int
	ppid    int
	name    string
	cmdline string
	user    string
}

// ProcessWatcher polls /proc to detect suspicious process spawning.
type ProcessWatcher struct {
	interval time.Duration
	suppress *SuppressMatcher
	out      chan<- Event
	seen     map[int]procInfo
	stop     chan struct{}
}

func NewProcessWatcher(interval time.Duration, out chan<- Event, suppress ...*SuppressMatcher) *ProcessWatcher {
	var sm *SuppressMatcher
	if len(suppress) > 0 {
		sm = suppress[0]
	}
	return &ProcessWatcher{
		interval: interval,
		suppress: sm,
		out:      out,
		seen:     make(map[int]procInfo),
		stop:     make(chan struct{}),
	}
}

func (pw *ProcessWatcher) Start() {
	go pw.loop()
}

func (pw *ProcessWatcher) Stop() {
	close(pw.stop)
}

func (pw *ProcessWatcher) loop() {
	ticker := time.NewTicker(pw.interval)
	defer ticker.Stop()

	// Populate baseline — don't alert on existing processes
	pw.scan(false)

	for {
		select {
		case <-pw.stop:
			return
		case <-ticker.C:
			pw.scan(true)
		}
	}
}

func (pw *ProcessWatcher) scan(emit bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		slog.Error("process watcher: cannot read /proc", "err", err)
		return
	}

	current := make(map[int]procInfo)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // not a PID directory
		}
		info, err := readProcInfo(pid)
		if err != nil {
			continue
		}
		current[pid] = info

		if emit {
			if _, existed := pw.seen[pid]; !existed {
				// New process — check if suspicious
				pw.checkProcess(info)
			}
		}
	}

	pw.seen = current
}

func (pw *ProcessWatcher) checkProcess(p procInfo) {
	// Look up parent
	parent, ok := pw.seen[p.ppid]
	if !ok {
		return
	}

	parentName := filepath.Base(parent.name)
	childName := filepath.Base(p.name)

	suspList, parentSuspicious := suspiciousChildren[parentName]
	if !parentSuspicious {
		return
	}

	for _, suspect := range suspList {
		if strings.HasPrefix(childName, suspect) {
			sev := SeverityHigh
			if childName == "sh" || childName == "bash" {
				sev = SeverityCritical
			}
			e := Event{
				Source:    SourceProcess,
				Timestamp: time.Now(),
				PID:       p.pid,
				PPID:      p.ppid,
				Process:   childName,
				CmdLine:   p.cmdline,
				User:      p.user,
				Action:    "spawn",
				Resource:  fmt.Sprintf("%s → %s", parentName, childName),
				Detail:    fmt.Sprintf("parent_cmd=%q child_cmd=%q", parent.cmdline, p.cmdline),
				Severity:  sev,
			}
			if !pw.suppress.IsSuppressed(e) {
				select {
				case pw.out <- e:
				case <-pw.stop:
					return
				}
			}
			return
		}
	}
}

func readProcInfo(pid int) (procInfo, error) {
	base := fmt.Sprintf("/proc/%d", pid)

	statusBytes, err := os.ReadFile(filepath.Join(base, "status"))
	if err != nil {
		return procInfo{}, err
	}

	info := procInfo{pid: pid}
	for _, line := range strings.Split(string(statusBytes), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		val := strings.TrimSpace(parts[1])
		switch parts[0] {
		case "Name":
			info.name = val
		case "PPid":
			info.ppid, _ = strconv.Atoi(val)
		case "Uid":
			info.user = val
		}
	}

	cmdlineBytes, _ := os.ReadFile(filepath.Join(base, "cmdline"))
	info.cmdline = strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")

	return info, nil
}
