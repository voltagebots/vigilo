package web

import (
	"log/slog"
	"sync"

	"github.com/voltagebots/vigilo/internal/collector"
)

const (
	maxSubscribers  = 100
	subscriberBufSz = 64
)

// Broadcaster fans out collector events to all active SSE subscribers.
// Safe for concurrent use. Subscribers are channels of collector.Event.
type Broadcaster struct {
	mu   sync.Mutex
	subs map[chan collector.Event]struct{}
}

func NewBroadcaster() *Broadcaster {
	return &Broadcaster{subs: make(map[chan collector.Event]struct{})}
}

// Subscribe returns a buffered channel that will receive published events.
// Returns nil if the subscriber cap has been reached.
func (b *Broadcaster) Subscribe() <-chan collector.Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.subs) >= maxSubscribers {
		slog.Warn("broadcaster: subscriber cap reached, rejecting new SSE client")
		return nil
	}
	ch := make(chan collector.Event, subscriberBufSz)
	b.subs[ch] = struct{}{}
	return ch
}

// Unsubscribe removes the subscriber channel and closes it.
func (b *Broadcaster) Unsubscribe(ch <-chan collector.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	// The map key is the send-end; we need to match by identity.
	for k := range b.subs {
		if (chan collector.Event)(k) == ch {
			delete(b.subs, k)
			close(k)
			return
		}
	}
}

// Publish sends e to all subscribers. If a subscriber's buffer is full,
// the event is silently dropped for that subscriber (non-blocking).
func (b *Broadcaster) Publish(e collector.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- e:
		default:
			// subscriber too slow — drop silently
		}
	}
}
