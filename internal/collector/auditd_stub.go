//go:build !linux

package collector

// AuditdWatcher is only available on Linux.
// This stub satisfies the compiler on other platforms.
type AuditdWatcher struct{}

func NewAuditdWatcher(_ string, _ chan<- Event, _ ...*SuppressMatcher) *AuditdWatcher {
	return &AuditdWatcher{}
}

func (a *AuditdWatcher) Start() error { return nil }
func (a *AuditdWatcher) Stop()        {}
