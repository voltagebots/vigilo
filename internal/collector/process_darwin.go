//go:build darwin

package collector

import (
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var suspiciousChildren = map[string][]string{
	"node":    {"sh", "bash", "curl", "wget", "python", "python3", "nc", "ncat"},
	"python":  {"sh", "bash", "curl", "wget", "nc", "ncat"},
	"python3": {"sh", "bash", "curl", "wget", "nc", "ncat"},
	"java":    {"sh", "bash", "curl", "wget"},
	"nginx":   {"sh", "bash", "python", "python3"},
}

type procInfo struct {
	pid  int
	ppid int
	name string
	user string
}

// ProcessWatcher polls `ps` on macOS to detect suspicious process spawning.
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

func (pw *ProcessWatcher) Start() { go pw.loop() }
func (pw *ProcessWatcher) Stop()  { close(pw.stop) }

func (pw *ProcessWatcher) loop() {
	ticker := time.NewTicker(pw.interval)
	defer ticker.Stop()
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
	// ps -axo pid=,ppid=,user=,comm= — suppress headers, one process per line
	out, err := exec.Command("ps", "-axo", "pid=,ppid=,user=,comm=").Output()
	if err != nil {
		return
	}
	current := make(map[int]procInfo)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		ppid, _ := strconv.Atoi(fields[1])
		info := procInfo{pid: pid, ppid: ppid, user: fields[2], name: fields[3]}
		current[pid] = info
		if emit {
			if _, existed := pw.seen[pid]; !existed {
				pw.checkProcess(info)
			}
		}
	}
	pw.seen = current
}

func (pw *ProcessWatcher) checkProcess(p procInfo) {
	parent, ok := pw.seen[p.ppid]
	if !ok {
		return
	}
	parentName := filepath.Base(parent.name)
	childName := filepath.Base(p.name)

	suspList, ok := suspiciousChildren[parentName]
	if !ok {
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
				User:      p.user,
				Action:    "spawn",
				Resource:  parentName + " → " + childName,
				Detail:    "suspicious child process",
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
