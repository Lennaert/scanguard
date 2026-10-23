package scanguard

import (
	"context"
	"sync"
	"time"
)

// Counter keeps a sliding-window score per key. Implement it on Redis or
// another shared store to count across several instances.
//
// Keys are IPs for the miss score and "offense:<ip>" for the ban history.
// The two use different windows (Window and OffenseMemory), so an
// implementation must keep each key's window separately.
type Counter interface {
	// Add records weight for key and returns the total within window.
	Add(ctx context.Context, key string, weight int, window time.Duration) (int, error)
	// Reset forgets everything recorded for key.
	Reset(ctx context.Context, key string) error
}

// Event describes a ban.
type Event struct {
	IP         string // what was banned: an IPv4 address or an IPv6 network like "2001:db8:1:2::/64"
	ClientIP   string // the exact address that crossed the threshold
	Score      int
	Path       string // the request that crossed the threshold
	UserAgent  string
	Suspicious bool // whether that path matched SuspiciousPaths
	Reason     string
	Offense    int // 1 for the first ban within OffenseMemory, 2 for the second, ...
	At         time.Time
	Until      time.Time
}

// Action is anything that should happen when an IP is banned.
type Action interface {
	OnBan(ctx context.Context, ev Event) error
}

// ActionFunc adapts a function to Action.
type ActionFunc func(ctx context.Context, ev Event) error

func (f ActionFunc) OnBan(ctx context.Context, ev Event) error { return f(ctx, ev) }

// BanList is the local block list the middleware checks on every request.
// Keys are what Event.IP holds: an IPv4 address or an IPv6 network.
// OnBan stores the ban; it runs synchronously so the next request from that
// IP is already refused.
type BanList interface {
	Action
	Banned(ctx context.Context, ip string) (bool, error)
	Unban(ctx context.Context, ip string) error
}

type hit struct {
	at     time.Time
	weight int
}

type bucket struct {
	hits   []hit
	window time.Duration
}

func (b *bucket) last() time.Time {
	if len(b.hits) == 0 {
		return time.Time{}
	}
	return b.hits[len(b.hits)-1].at
}

// DefaultMaxKeys caps the memory stores. A counter entry takes well under
// 2 KB, so the cap keeps the worst case around 200 MB.
const DefaultMaxKeys = 100_000

// MemoryCounter is an in-process Counter. Stale keys are swept as a side
// effect of Add, so it needs no background goroutine.
type MemoryCounter struct {
	// MaxKeys caps how many keys are tracked; 0 means no cap. When full, a
	// new key evicts the stalest of a small random sample, so an IP that
	// is actively scanning keeps its score. Set it before first use.
	MaxKeys int

	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
	now       func() time.Time
}

func NewMemoryCounter() *MemoryCounter {
	return &MemoryCounter{MaxKeys: DefaultMaxKeys, buckets: make(map[string]*bucket), now: time.Now}
}

func (c *MemoryCounter) Add(_ context.Context, key string, weight int, window time.Duration) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if now.Sub(c.lastSweep) > sweepEvery {
		for k, b := range c.buckets {
			if b.last().Before(now.Add(-b.window)) {
				delete(c.buckets, k)
			}
		}
		c.lastSweep = now
	}

	b := c.buckets[key]
	if b == nil {
		if c.MaxKeys > 0 && len(c.buckets) >= c.MaxKeys {
			c.evict()
		}
		b = &bucket{}
		c.buckets[key] = b
	}
	b.window = window
	cutoff := now.Add(-window)
	i := 0
	for i < len(b.hits) && b.hits[i].at.Before(cutoff) {
		i++
	}
	b.hits = append(b.hits[i:], hit{at: now, weight: weight})

	total := 0
	for _, h := range b.hits {
		total += h.weight
	}
	return total, nil
}

// evict drops the key with the oldest last hit within a random sample.
func (c *MemoryCounter) evict() {
	var victim string
	var oldest time.Time
	n := 0
	for k, b := range c.buckets {
		if n == 0 || b.last().Before(oldest) {
			victim, oldest = k, b.last()
		}
		if n++; n == evictSample {
			break
		}
	}
	delete(c.buckets, victim)
}

func (c *MemoryCounter) Reset(_ context.Context, key string) error {
	c.mu.Lock()
	delete(c.buckets, key)
	c.mu.Unlock()
	return nil
}

// MemoryBanList is an in-process BanList. Expired bans are swept as a side
// effect of OnBan.
type MemoryBanList struct {
	// MaxKeys caps how many bans are kept; 0 means no cap. When full, a
	// new ban evicts the one expiring soonest within a small random
	// sample. Set it before first use.
	MaxKeys int

	mu   sync.RWMutex
	bans expiringSet
	now  func() time.Time
}

func NewMemoryBanList() *MemoryBanList {
	return &MemoryBanList{MaxKeys: DefaultMaxKeys, now: time.Now}
}

func (b *MemoryBanList) OnBan(_ context.Context, ev Event) error {
	b.mu.Lock()
	b.bans.set(ev.IP, ev.Until, b.now(), b.MaxKeys)
	b.mu.Unlock()
	return nil
}

func (b *MemoryBanList) Banned(_ context.Context, ip string) (bool, error) {
	now := b.now()
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.bans.active(ip, now), nil
}

func (b *MemoryBanList) Unban(_ context.Context, ip string) error {
	b.mu.Lock()
	b.bans.delete(ip)
	b.mu.Unlock()
	return nil
}

// List returns the active bans and when each one ends.
func (b *MemoryBanList) List() map[string]time.Time {
	now := b.now()
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make(map[string]time.Time, len(b.bans.m))
	for ip, until := range b.bans.m {
		if now.Before(until) {
			out[ip] = until
		}
	}
	return out
}
