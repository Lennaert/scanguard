package scanguard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// app serves /, /admin and /static/app.js; everything else is a 404.
func app() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("home")) })
	mux.HandleFunc("/admin", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("admin")) })
	return mux
}

func newTestGuard(t *testing.T, mutate func(*Config)) (*Guard, http.Handler, *clock) {
	t.Helper()
	clk := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	cfg := DefaultConfig()
	counter := NewMemoryCounter()
	counter.now = clk.now
	bans := NewMemoryBanList()
	bans.now = clk.now
	cfg.Counter, cfg.BanList = counter, bans
	if mutate != nil {
		mutate(&cfg)
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g.now = clk.now
	return g, g.Middleware(app()), clk
}

func get(h http.Handler, ip, path string) int {
	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = ip + ":40000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func TestMatch(t *testing.T) {
	tests := []struct {
		pattern, path string
		want          bool
	}{
		{"/admin", "/admin", true},
		{"/admin", "/admin/users", true},
		{"/admin", "/foo/admin.php", true},
		{"/admin", "/administrators-guide", false},
		{"/admin", "/blog/admin-tips", false},
		{"/.env", "/.env", true},
		{"/.env", "/api/.env.local", true},
		{"/.git", "/.git/config", true},
		{"/wp-login", "/WP-LOGIN.PHP", true},
		{".php", "/index.php", true},
		{".php", "/php-tips", false},
		{"../", "/static/../../etc", true},
	}
	for _, tt := range tests {
		if got := Match(tt.pattern, tt.path); got != tt.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

func TestScannerGetsBanned(t *testing.T) {
	_, h, _ := newTestGuard(t, nil)
	scan := []string{"/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/backup.sql"}
	for _, p := range scan {
		if code := get(h, "203.0.113.7", p); code != http.StatusNotFound {
			t.Fatalf("%s: got %d before ban, want 404", p, code)
		}
	}
	if code := get(h, "203.0.113.7", "/"); code != http.StatusForbidden {
		t.Fatalf("after scan: got %d, want 403", code)
	}
	if code := get(h, "198.51.100.1", "/"); code != http.StatusOK {
		t.Fatalf("other ip: got %d, want 200", code)
	}
}

func TestMissingAssetsNeverCount(t *testing.T) {
	_, h, _ := newTestGuard(t, nil)
	for range 500 {
		get(h, "203.0.113.7", "/static/js/main.abc123.js")
		get(h, "203.0.113.7", "/img/removed.png")
	}
	if code := get(h, "203.0.113.7", "/"); code != http.StatusOK {
		t.Fatalf("got %d, want 200", code)
	}
}

func TestExistingRouteDoesNotCount(t *testing.T) {
	_, h, _ := newTestGuard(t, nil)
	for range 100 {
		if code := get(h, "203.0.113.7", "/admin"); code != http.StatusOK {
			t.Fatalf("got %d, want 200", code)
		}
	}
	if code := get(h, "203.0.113.7", "/"); code != http.StatusOK {
		t.Fatalf("got %d, want 200", code)
	}
}

func TestPlainMissesBanAtThreshold(t *testing.T) {
	_, h, _ := newTestGuard(t, nil)
	for range 49 {
		get(h, "203.0.113.7", "/page-that-was-removed")
	}
	if code := get(h, "203.0.113.7", "/"); code != http.StatusOK {
		t.Fatalf("49 misses: got %d, want 200", code)
	}
	get(h, "203.0.113.7", "/page-that-was-removed")
	if code := get(h, "203.0.113.7", "/"); code != http.StatusForbidden {
		t.Fatalf("50 misses: got %d, want 403", code)
	}
}

func TestWindowSlides(t *testing.T) {
	_, h, clk := newTestGuard(t, nil)
	for range 4 {
		get(h, "203.0.113.7", "/.env")
	}
	clk.add(61 * time.Second)
	get(h, "203.0.113.7", "/.env")
	if code := get(h, "203.0.113.7", "/"); code != http.StatusOK {
		t.Fatalf("old hits should have expired: got %d", code)
	}
}

func TestBanExpires(t *testing.T) {
	_, h, clk := newTestGuard(t, nil)
	for range 5 {
		get(h, "203.0.113.7", "/.env")
	}
	if code := get(h, "203.0.113.7", "/"); code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", code)
	}
	clk.add(time.Hour)
	if code := get(h, "203.0.113.7", "/"); code != http.StatusOK {
		t.Fatalf("after ban: got %d, want 200", code)
	}
}

func TestAllowList(t *testing.T) {
	_, h, _ := newTestGuard(t, nil)
	for range 20 {
		get(h, "10.0.0.5", "/.env")
	}
	if code := get(h, "10.0.0.5", "/"); code != http.StatusOK {
		t.Fatalf("private ip got %d, want 200", code)
	}
}

func TestActionsRunOncePerBan(t *testing.T) {
	var calls atomic.Int32
	var got Event
	var mu sync.Mutex
	g, h, _ := newTestGuard(t, func(c *Config) {
		c.Actions = []Action{ActionFunc(func(_ context.Context, ev Event) error {
			calls.Add(1)
			mu.Lock()
			got = ev
			mu.Unlock()
			return nil
		})}
	})

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() { defer wg.Done(); get(h, "203.0.113.7", "/wp-login.php") }()
	}
	wg.Wait()
	if err := g.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("action ran %d times, want 1", n)
	}
	if got.IP != "203.0.113.7" || !got.Suspicious {
		t.Fatalf("unexpected event: %+v", got)
	}
}

func TestNoLocalBanList(t *testing.T) {
	var calls atomic.Int32
	g, h, _ := newTestGuard(t, func(c *Config) {
		c.BanList = nil
		c.Actions = []Action{ActionFunc(func(context.Context, Event) error { calls.Add(1); return nil })}
	})
	for range 5 {
		get(h, "203.0.113.7", "/.env")
	}
	g.Shutdown(context.Background())
	if code := get(h, "203.0.113.7", "/"); code != http.StatusOK {
		t.Fatalf("got %d, want 200 without a local ban list", code)
	}
	if calls.Load() != 1 {
		t.Fatalf("action ran %d times, want 1", calls.Load())
	}
}

func TestUnban(t *testing.T) {
	g, h, _ := newTestGuard(t, nil)
	for range 5 {
		get(h, "203.0.113.7", "/.env")
	}
	if err := g.Unban(context.Background(), "203.0.113.7"); err != nil {
		t.Fatal(err)
	}
	if code := get(h, "203.0.113.7", "/"); code != http.StatusOK {
		t.Fatalf("got %d, want 200", code)
	}
}

func TestHeaderIP(t *testing.T) {
	f := HeaderIP("X-Forwarded-For")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.7")
	if got := f(r); got != "203.0.113.7" {
		t.Fatalf("got %q", got)
	}
	r.Header.Del("X-Forwarded-For")
	if got := f(r); got != "10.0.0.1" {
		t.Fatalf("fallback got %q", got)
	}
}

// scanUntilBanned sends scanner probes until ip is refused.
func scanUntilBanned(t *testing.T, h http.Handler, ip string) {
	t.Helper()
	for range 5 {
		get(h, ip, "/.env")
	}
	if code := get(h, ip, "/"); code != http.StatusForbidden {
		t.Fatalf("got %d, want 403 after scan", code)
	}
}

func TestBansEscalate(t *testing.T) {
	var mu sync.Mutex
	var events []Event
	g, h, clk := newTestGuard(t, func(c *Config) {
		c.Actions = []Action{ActionFunc(func(_ context.Context, ev Event) error {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
			return nil
		})}
	})
	ip := "203.0.113.7"

	steps := []time.Duration{time.Hour, 24 * time.Hour, 7 * 24 * time.Hour, 7 * 24 * time.Hour}
	for i, want := range steps {
		scanUntilBanned(t, h, ip)
		clk.add(want - time.Second)
		if code := get(h, ip, "/"); code != http.StatusForbidden {
			t.Fatalf("ban %d: lifted before %s", i+1, want)
		}
		clk.add(time.Second)
		if code := get(h, ip, "/"); code != http.StatusOK {
			t.Fatalf("ban %d: still banned after %s", i+1, want)
		}
	}

	g.Shutdown(context.Background())
	for i, ev := range events {
		if ev.Offense != i+1 {
			t.Errorf("event %d: Offense = %d, want %d", i, ev.Offense, i+1)
		}
	}
}

func TestOffensesAreForgotten(t *testing.T) {
	_, h, clk := newTestGuard(t, nil)
	ip := "203.0.113.7"
	scanUntilBanned(t, h, ip)
	clk.add(31 * 24 * time.Hour)
	// Unrelated traffic in between triggers the counter's sweep, which must
	// use each key's own window.
	get(h, "198.51.100.1", "/gone")
	scanUntilBanned(t, h, ip)
	clk.add(time.Hour)
	if code := get(h, ip, "/"); code != http.StatusOK {
		t.Fatalf("got %d, want 200: old offense should have been forgotten", code)
	}
}

func TestOffenseSurvivesSweep(t *testing.T) {
	_, h, clk := newTestGuard(t, nil)
	ip := "203.0.113.7"
	scanUntilBanned(t, h, ip)
	clk.add(2 * time.Hour)
	get(h, "198.51.100.1", "/gone") // sweeps the miss buckets
	scanUntilBanned(t, h, ip)
	clk.add(2 * time.Hour)
	if code := get(h, ip, "/"); code != http.StatusForbidden {
		t.Fatalf("got %d, want 403: second ban should last 24h", code)
	}
}

func TestUnbanForgetsOffenses(t *testing.T) {
	g, h, clk := newTestGuard(t, nil)
	ip := "203.0.113.7"
	scanUntilBanned(t, h, ip)
	g.Unban(context.Background(), ip)
	scanUntilBanned(t, h, ip)
	clk.add(time.Hour)
	if code := get(h, ip, "/"); code != http.StatusOK {
		t.Fatalf("got %d, want 200: unban should reset escalation", code)
	}
}

func TestFixedDuration(t *testing.T) {
	_, h, clk := newTestGuard(t, func(c *Config) { c.BanDurations = []time.Duration{time.Hour} })
	ip := "203.0.113.7"
	for range 3 {
		scanUntilBanned(t, h, ip)
		clk.add(time.Hour)
		if code := get(h, ip, "/"); code != http.StatusOK {
			t.Fatalf("got %d, want 200 after a fixed 1h ban", code)
		}
	}
}
