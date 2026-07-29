//go:build darwin

package collector

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var knownSafePorts = map[int]bool{
	80: true, 443: true, 53: true, 22: true,
	8545: true, 8546: true,
	9650: true, 26657: true,
}

var suspiciousPorts = map[int]bool{
	4444: true, 4445: true, 1337: true, 31337: true,
	6666: true, 6667: true, 6668: true,
	9001: true, 9030: true,
}

type connKey struct {
	localIP    string
	localPort  int
	remoteIP   string
	remotePort int
}

// NetworkWatcher polls `netstat` on macOS for new outbound connections.
type NetworkWatcher struct {
	interval time.Duration
	suppress *SuppressMatcher
	ioc      *IOCStore
	out      chan<- Event
	seen     map[connKey]struct{}
	stop     chan struct{}
}

// SetIOCStore attaches an indicator-of-compromise store consulted on every new
// outbound connection (matched before port heuristics so C2-over-443 is caught).
func (nw *NetworkWatcher) SetIOCStore(s *IOCStore) { nw.ioc = s }

func NewNetworkWatcher(interval time.Duration, out chan<- Event, suppress ...*SuppressMatcher) *NetworkWatcher {
	var sm *SuppressMatcher
	if len(suppress) > 0 {
		sm = suppress[0]
	}
	return &NetworkWatcher{
		interval: interval,
		suppress: sm,
		out:      out,
		seen:     make(map[connKey]struct{}),
		stop:     make(chan struct{}),
	}
}

func (nw *NetworkWatcher) Start() { go nw.loop() }
func (nw *NetworkWatcher) Stop()  { close(nw.stop) }

func (nw *NetworkWatcher) loop() {
	ticker := time.NewTicker(nw.interval)
	defer ticker.Stop()
	nw.scan(false)
	for {
		select {
		case <-nw.stop:
			return
		case <-ticker.C:
			nw.scan(true)
		}
	}
}

func (nw *NetworkWatcher) scan(emit bool) {
	// -n: numeric, -f inet: IPv4+6, -p tcp: TCP only
	out, err := exec.Command("netstat", "-n", "-f", "inet", "-p", "tcp").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		// Proto Local-Address Foreign-Address (state)
		if len(fields) < 4 || fields[0] != "tcp4" && fields[0] != "tcp6" {
			continue
		}
		state := ""
		if len(fields) >= 6 {
			state = fields[5]
		} else if len(fields) == 5 {
			state = fields[4]
		}
		if state != "ESTABLISHED" {
			continue
		}
		remote := parseNetstatAddr(fields[4])
		if remote == nil {
			continue
		}
		local := parseNetstatAddr(fields[3])
		if local == nil {
			continue
		}
		c := connKey{
			localIP: local.IP.String(), localPort: local.Port,
			remoteIP: remote.IP.String(), remotePort: remote.Port,
		}
		if _, seen := nw.seen[c]; !seen {
			nw.seen[c] = struct{}{}
			if emit {
				nw.checkConnection(c)
			}
		}
	}
}

func (nw *NetworkWatcher) checkConnection(c connKey) {
	if c.remotePort == 0 {
		return
	}
	remoteIP := net.ParseIP(c.remoteIP)
	if remoteIP == nil || remoteIP.IsLoopback() {
		return
	}

	// IOC match takes precedence — a known-bad IP is flagged regardless of port,
	// catching C2/exfil over 443 that port heuristics treat as "safe".
	if m, ok := nw.ioc.MatchIP(c.remoteIP); ok {
		e := Event{
			Source:    SourceNetwork,
			Timestamp: time.Now(),
			Action:    "connect",
			Resource:  fmt.Sprintf("%s:%d", c.remoteIP, c.remotePort),
			Detail:    "outbound connection to known-bad indicator: " + m.Label,
			Severity:  m.Severity,
		}
		if !nw.suppress.IsSuppressed(e) {
			nw.out <- e
		}
		return
	}

	var sev Severity
	var detail string
	if suspiciousPorts[c.remotePort] {
		sev = SeverityCritical
		detail = fmt.Sprintf("port %d is a known reverse-shell/C2 port", c.remotePort)
	} else if !knownSafePorts[c.remotePort] {
		sev = SeverityMedium
		detail = fmt.Sprintf("connection to non-standard port %d", c.remotePort)
	} else {
		return
	}

	e := Event{
		Source:    SourceNetwork,
		Timestamp: time.Now(),
		Action:    "connect",
		Resource:  fmt.Sprintf("%s:%d", c.remoteIP, c.remotePort),
		Detail:    detail,
		Severity:  sev,
	}
	if !nw.suppress.IsSuppressed(e) {
		nw.out <- e
	}
}

// parseNetstatAddr parses "1.2.3.4.port" or "*.port" format from netstat output.
func parseNetstatAddr(s string) *net.TCPAddr {
	idx := strings.LastIndex(s, ".")
	if idx < 0 {
		return nil
	}
	ipStr := s[:idx]
	portStr := s[idx+1:]
	if portStr == "*" {
		return nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(ipStr)
	if ip == nil && ipStr != "*" {
		return nil
	}
	if ipStr == "*" {
		ip = net.IPv4zero
	}
	return &net.TCPAddr{IP: ip, Port: port}
}
