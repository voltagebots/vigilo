//go:build linux

package collector

import (
	"bufio"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// AuditdWatcher tails /var/log/audit/audit.log and converts SYSCALL+PATH
// records into Events. It requires read access to the audit log
// (typically: vigilo user in the adm group, or run as root).
//
// Auditd is Linux-only and is a richer alternative to /proc polling:
// it captures every file-open syscall, not just fsnotify write/create events.
//
// Enable auditd rules for vigilo with:
//
//	auditctl -w /app/keystore -p rwa -k vigilo_keystore
//	auditctl -w /run/secrets  -p rwa -k vigilo_secrets
//	auditctl -w /app/.env     -p wa  -k vigilo_env
type AuditdWatcher struct {
	logPath  string
	suppress *SuppressMatcher
	out      chan<- Event
	stop     chan struct{}
}

func NewAuditdWatcher(logPath string, out chan<- Event, suppress ...*SuppressMatcher) *AuditdWatcher {
	if logPath == "" {
		logPath = "/var/log/audit/audit.log"
	}
	var sm *SuppressMatcher
	if len(suppress) > 0 {
		sm = suppress[0]
	}
	return &AuditdWatcher{logPath: logPath, suppress: sm, out: out, stop: make(chan struct{})}
}

func (aw *AuditdWatcher) Start() error {
	f, err := os.Open(aw.logPath)
	if err != nil {
		return err
	}
	// Seek to end — only tail new records, don't replay history
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return err
	}
	go aw.tail(f)
	return nil
}

func (aw *AuditdWatcher) Stop() { close(aw.stop) }

// auditRecord holds parsed fields from a single audit log line.
type auditRecord struct {
	serial  string
	recType string
	fields  map[string]string
}

// auditGroup accumulates records sharing the same serial number.
type auditGroup struct {
	records  []auditRecord
	lastSeen time.Time
}

var (
	// msg=audit(1234567890.123:456):
	reMsgSerial = regexp.MustCompile(`msg=audit\(\d+\.\d+:(\d+)\)`)
	// key=value or key="value"
	reField = regexp.MustCompile(`(\w+)=(?:"([^"]*)"|([\S]*))`)
)

func parseLine(line string) (auditRecord, bool) {
	// type=SYSCALL msg=audit(ts:serial): ...
	if !strings.HasPrefix(line, "type=") {
		return auditRecord{}, false
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return auditRecord{}, false
	}

	recType := strings.TrimPrefix(parts[0], "type=")
	sm := reMsgSerial.FindStringSubmatch(line)
	if sm == nil {
		return auditRecord{}, false
	}
	serial := sm[1]

	fields := make(map[string]string)
	for _, m := range reField.FindAllStringSubmatch(line, -1) {
		key := m[1]
		val := m[2]
		if val == "" {
			val = m[3]
		}
		fields[key] = val
	}

	return auditRecord{serial: serial, recType: recType, fields: fields}, true
}

func (aw *AuditdWatcher) tail(f *os.File) {
	defer f.Close()
	scanner := bufio.NewScanner(f)
	groups := make(map[string]*auditGroup)
	flushTicker := time.NewTicker(500 * time.Millisecond)
	defer flushTicker.Stop()

	for {
		select {
		case <-aw.stop:
			return
		case <-flushTicker.C:
			// Flush groups that haven't received a new record in 1s
			cutoff := time.Now().Add(-time.Second)
			for serial, g := range groups {
				if g.lastSeen.Before(cutoff) {
					aw.emitGroup(g)
					delete(groups, serial)
				}
			}
		default:
			if scanner.Scan() {
				rec, ok := parseLine(scanner.Text())
				if !ok {
					continue
				}
				g, exists := groups[rec.serial]
				if !exists {
					g = &auditGroup{}
					groups[rec.serial] = g
				}
				g.records = append(g.records, rec)
				g.lastSeen = time.Now()
			} else {
				// No new lines — sleep briefly before retrying
				time.Sleep(100 * time.Millisecond)
				// Re-open if the file was rotated
				if _, err := f.Stat(); err != nil {
					if nf, err := os.Open(aw.logPath); err == nil {
						f.Close()
						f = nf
						scanner = bufio.NewScanner(f)
					}
				}
			}
		}
	}
}

func (aw *AuditdWatcher) emitGroup(g *auditGroup) {
	// Collect SYSCALL and PATH records
	var syscall auditRecord
	var paths []string
	var key string

	for _, r := range g.records {
		switch r.recType {
		case "SYSCALL":
			syscall = r
			key = r.fields["key"]
		case "PATH":
			if name := r.fields["name"]; name != "" && name != "(null)" {
				paths = append(paths, name)
			}
		}
	}

	if syscall.recType == "" || key == "" {
		return // no matching audit rule triggered — skip
	}

	// Only process events that matched a vigilo audit rule (key starts with "vigilo_")
	if !strings.HasPrefix(key, "vigilo_") {
		return
	}

	exe := syscall.fields["exe"]
	comm := syscall.fields["comm"]
	pidStr := syscall.fields["pid"]
	uid := syscall.fields["uid"]
	syscallNum := syscall.fields["syscall"]

	pid, _ := strconv.Atoi(pidStr)
	action := syscallToAction(syscallNum)

	for _, path := range paths {
		sev := severityForPath(path)
		if sev == SeverityInfo {
			sev = SeverityMedium // auditd rules matched = at least medium
		}

		e := Event{
			Source:    SourceFile,
			Timestamp: time.Now(),
			PID:       pid,
			Process:   comm,
			CmdLine:   exe,
			User:      uid,
			Action:    action,
			Resource:  path,
			Detail:    "auditd rule=" + key,
			Severity:  sev,
		}
		if !aw.suppress.IsSuppressed(e) {
			aw.out <- e
		}
	}
}

func syscallToAction(num string) string {
	switch num {
	case "2", "257": // open, openat
		return "open"
	case "59", "322": // execve, execveat
		return "exec"
	case "87", "263": // unlink, unlinkat
		return "delete"
	case "82", "264": // rename, renameat
		return "rename"
	default:
		return "syscall_" + num
	}
}
