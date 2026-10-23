package scanguard

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func get6(h http.Handler, ip, path string) int {
	return get(h, "["+ip+"]", path)
}

func TestIPv6RotationWithinA64IsBanned(t *testing.T) {
	var got Event
	g, h, _ := newTestGuard(t, func(c *Config) {
		c.Actions = []Action{ActionFunc(func(_ context.Context, ev Event) error { got = ev; return nil })}
	})
	// A fresh address for every probe, all in one /64.
	for i := range 5 {
		get6(h, fmt.Sprintf("2001:db8:1:2::%x", i+1), "/.env")
	}
	g.Shutdown(context.Background())
	if code := get6(h, "2001:db8:1:2:ffff::1", "/"); code != http.StatusForbidden {
		t.Fatalf("same /64: got %d, want 403", code)
	}
	if code := get6(h, "2001:db8:1:3::1", "/"); code != http.StatusOK {
		t.Fatalf("neighbouring /64: got %d, want 200", code)
	}
	if got.IP != "2001:db8:1:2::/64" || got.ClientIP != "2001:db8:1:2::5" {
		t.Fatalf("event IP=%q ClientIP=%q", got.IP, got.ClientIP)
	}
}

func TestIPv6PerAddress(t *testing.T) {
	_, h, _ := newTestGuard(t, func(c *Config) { c.IPv6Prefix = 128 })
	for i := range 5 {
		get6(h, fmt.Sprintf("2001:db8:1:2::%x", i+1), "/.env")
	}
	if code := get6(h, "2001:db8:1:2::5", "/"); code != http.StatusOK {
		t.Fatalf("got %d, want 200 when counting per address", code)
	}
}

func TestIPv4MappedCountsAsIPv4(t *testing.T) {
	_, h, _ := newTestGuard(t, nil)
	for range 5 {
		get6(h, "::ffff:203.0.113.7", "/.env")
	}
	if code := get(h, "203.0.113.7", "/"); code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", code)
	}
}

func TestManualBanKeys(t *testing.T) {
	g, h, _ := newTestGuard(t, nil)
	ctx := context.Background()

	if err := g.Ban(ctx, "2001:db8:9:9::42", "manual"); err != nil {
		t.Fatal(err)
	}
	if code := get6(h, "2001:db8:9:9::1", "/"); code != http.StatusForbidden {
		t.Fatalf("ban of one IPv6 address should cover its /64: got %d", code)
	}
	if err := g.Unban(ctx, "2001:db8:9:9::/64"); err != nil {
		t.Fatal(err)
	}
	if code := get6(h, "2001:db8:9:9::1", "/"); code != http.StatusOK {
		t.Fatalf("after unban: got %d", code)
	}

	if err := g.Ban(ctx, "203.0.113.9/32", "manual"); err != nil {
		t.Fatal(err)
	}
	if code := get(h, "203.0.113.9", "/"); code != http.StatusForbidden {
		t.Fatalf("/32 ban: got %d", code)
	}

	for _, wide := range []string{"203.0.113.0/24", "2001:db8::/48", "nonsense"} {
		if err := g.Ban(ctx, wide, "manual"); err == nil {
			t.Errorf("Ban(%q) should fail", wide)
		}
	}
}

func TestCounterCap(t *testing.T) {
	_, h, clk := newTestGuard(t, func(c *Config) {
		mc := c.Counter.(*MemoryCounter)
		mc.MaxKeys = 100
	})
	// A flood of one-off IPs, with a scanner probing every 20 requests. A key
	// survives eviction as long as it is hit at least once per ~MaxKeys new IPs.
	for i := range 2000 {
		clk.add(time.Millisecond)
		if i%20 == 0 && i < 100 {
			get(h, "203.0.113.7", "/.env")
		}
		get(h, fmt.Sprintf("198.18.%d.%d", i/256, i%256), "/gone")
	}
	if code := get(h, "203.0.113.7", "/"); code != http.StatusForbidden {
		t.Fatalf("active scanner lost its score under a flood: got %d", code)
	}
}

func TestCounterNeverExceedsCap(t *testing.T) {
	c := NewMemoryCounter()
	c.MaxKeys = 50
	for i := range 1000 {
		c.Add(context.Background(), fmt.Sprint(i), 1, time.Minute)
	}
	if n := len(c.buckets); n != 50 {
		t.Fatalf("counter holds %d keys, want 50", n)
	}
}

func TestBanListCap(t *testing.T) {
	b := NewMemoryBanList()
	b.MaxKeys = 10
	now := time.Now()
	for i := range 100 {
		b.OnBan(context.Background(), Event{IP: fmt.Sprint(i), Until: now.Add(time.Duration(i+1) * time.Hour)})
	}
	if n := len(b.List()); n != 10 {
		t.Fatalf("ban list holds %d bans, want 10", n)
	}
	if ok, _ := b.Banned(context.Background(), "99"); !ok {
		t.Fatal("newest ban was evicted")
	}
}
