// Package memory provides an in-memory IFirewall implementation that records
// ban events instead of touching a real network device. It is intended for
// tests (unit and E2E) where bans need to be asserted.
package memory

import (
	"sync"
	"time"

	"github.com/charleshuang3/caddypaw/pkg/firewall"
)

// Ban records a single ban event issued by the Firewall.
type Ban struct {
	IP              string
	TimeoutInMinute int
	Time            time.Time
}

// Firewall is an in-memory IFirewall. All methods are safe for concurrent use.
type Firewall struct {
	mu   sync.Mutex
	bans []Ban
}

// Interface guard to ensure Firewall satisfies firewall.IFirewall.
var _ firewall.IFirewall = (*Firewall)(nil)

// New returns an empty in-memory firewall.
func New() *Firewall {
	return &Firewall{}
}

// BanIP records a ban event for the given IP.
func (f *Firewall) BanIP(ip string, timeoutInMinute int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bans = append(f.bans, Ban{
		IP:              ip,
		TimeoutInMinute: timeoutInMinute,
		Time:            time.Now(),
	})
}

// Bans returns a copy of all recorded ban events in order.
func (f *Firewall) Bans() []Ban {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Ban, len(f.bans))
	copy(out, f.bans)
	return out
}

// BanCount returns the number of recorded ban events.
func (f *Firewall) BanCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bans)
}

// Reset clears all recorded ban events.
func (f *Firewall) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bans = nil
}
