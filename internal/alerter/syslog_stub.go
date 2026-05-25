//go:build !linux

package alerter

// newSyslogChannel returns nil on non-Linux platforms — syslog is Linux-only.
func newSyslogChannel() channel { return nil }
