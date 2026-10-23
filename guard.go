// Package scanguard bans IPs that probe for paths your app does not have,
// like /.env, /wp-login.php or /.git/config. Plug Guard.Middleware in front
// of your router; it counts misses per IP and bans an IP once its score
// crosses a threshold within a time window.
package scanguard

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// Guard detects scanners and blocks them.
type Guard struct {
	cfg      Config
	allow    []netip.Prefix
	statuses map[int]bool
	now      func() time.Time

	mu      sync.Mutex
	banning expiringSet // dedupes concurrent bans of one IP

	wg sync.WaitGroup
}

// New builds a Guard from cfg.
func New(cfg Config) (*Guard, error) {
	if cfg.Window <= 0 || cfg.Threshold <= 0 {
		return nil, errors.New("scanguard: Window and Threshold must be positive")
	}
	if len(cfg.BanDurations) == 0 {
		return nil, errors.New("scanguard: BanDurations needs at least one step")
	}
	for _, d := range cfg.BanDurations {
		if d <= 0 {
			return nil, errors.New("scanguard: BanDurations must be positive")
		}
	}
	if cfg.IPv6Prefix < 0 || cfg.IPv6Prefix > 128 {
		return nil, errors.New("scanguard: IPv6Prefix must be between 0 and 128")
	}
	allow, err := parseAllow(cfg.Allow)
	if err != nil {
		return nil, fmt.Errorf("scanguard: bad Allow entry: %w", err)
	}
	if cfg.Counter == nil {
		cfg.Counter = NewMemoryCounter()
	}
	if cfg.ClientIP == nil {
		cfg.ClientIP = RemoteAddr
	}
	if cfg.Blocked == nil {
		cfg.Blocked = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "Forbidden", http.StatusForbidden)
		})
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ActionTimeout <= 0 {
		cfg.ActionTimeout = 10 * time.Second
	}
	statuses := make(map[int]bool, len(cfg.Statuses))
	for _, s := range cfg.Statuses {
		statuses[s] = true
	}
	return &Guard{
		cfg:      cfg,
		allow:    allow,
		statuses: statuses,
		now:      time.Now,
	}, nil
}

// Middleware refuses banned IPs and records misses for everyone else. Put it
// outside your router so it sees the router's 404s. It fits net/http, chi,
// gorilla/mux and anything else that takes func(http.Handler) http.Handler.
func (g *Guard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.Blocked(r) {
			g.cfg.Blocked.ServeHTTP(w, r)
			return
		}
		rec := &recorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		g.Record(r, rec.status())
	})
}

// Blocked reports whether r comes from a banned IP. Use it with Record to
// wire the guard into frameworks that do not use net/http middleware.
func (g *Guard) Blocked(r *http.Request) bool {
	if g.cfg.BanList == nil {
		return false
	}
	ip := g.cfg.ClientIP(r)
	if ip == "" || g.allowed(ip) {
		return false
	}
	banned, err := g.cfg.BanList.Banned(r.Context(), g.subject(ip))
	if err != nil {
		g.cfg.Logger.Error("scanguard: ban lookup failed", "ip", ip, "err", err)
		return false
	}
	return banned
}

// Record counts a response with the given status and bans the IP when it
// crosses the threshold.
func (g *Guard) Record(r *http.Request, status int) {
	if !g.statuses[status] {
		return
	}
	ip := g.cfg.ClientIP(r)
	if ip == "" || g.allowed(ip) {
		return
	}
	weight, suspicious := g.weigh(r.URL.Path)
	if weight <= 0 {
		return
	}
	ctx := context.WithoutCancel(r.Context())
	key := g.subject(ip)
	score, err := g.cfg.Counter.Add(ctx, key, weight, g.cfg.Window)
	if err != nil {
		g.cfg.Logger.Error("scanguard: counter failed", "ip", ip, "err", err)
		return
	}
	if score < g.cfg.Threshold {
		return
	}
	g.ban(ctx, Event{
		IP:         key,
		ClientIP:   ip,
		Score:      score,
		Path:       r.URL.Path,
		UserAgent:  r.UserAgent(),
		Suspicious: suspicious,
		Reason:     fmt.Sprintf("score %d within %s", score, g.cfg.Window),
	})
}

// Ban bans an address or network by hand and runs all actions. An IPv6
// address bans its whole IPv6Prefix network. It counts as an offense, so
// the duration follows the escalation ladder.
func (g *Guard) Ban(ctx context.Context, ip, reason string) error {
	key, err := g.subjectOf(ip)
	if err != nil {
		return err
	}
	g.ban(ctx, Event{IP: key, ClientIP: normalize(ip), Reason: reason})
	return nil
}

// Unban lifts a ban and clears its score and offense history. Like Ban, it
// takes an address or network. Bans pushed to external systems by actions
// are not lifted.
func (g *Guard) Unban(ctx context.Context, ip string) error {
	ip, err := g.subjectOf(ip)
	if err != nil {
		return err
	}
	g.mu.Lock()
	g.banning.delete(ip)
	g.mu.Unlock()
	if err := g.cfg.Counter.Reset(ctx, ip); err != nil {
		return err
	}
	if err := g.cfg.Counter.Reset(ctx, offenseKey(ip)); err != nil {
		return err
	}
	if g.cfg.BanList != nil {
		return g.cfg.BanList.Unban(ctx, ip)
	}
	return nil
}

// Shutdown waits for running actions to finish or ctx to end.
func (g *Guard) Shutdown(ctx context.Context) error {
	done := make(chan struct{})
	go func() { g.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ban fills in At, Offense and Until, then stores the ban and runs actions.
func (g *Guard) ban(ctx context.Context, ev Event) {
	ev.At = g.now()
	g.mu.Lock()
	if g.banning.active(ev.IP, ev.At) {
		g.mu.Unlock()
		return
	}
	// Reserve the IP before the offense lookup so concurrent requests
	// can't ban it twice; the real end time is set below.
	g.banning.set(ev.IP, ev.At.Add(g.cfg.BanDurations[0]), ev.At, DefaultMaxKeys)
	g.mu.Unlock()

	ev.Offense = g.offense(ctx, ev.IP)
	ev.Until = ev.At.Add(g.cfg.BanDurations[min(ev.Offense, len(g.cfg.BanDurations))-1])
	g.mu.Lock()
	g.banning.set(ev.IP, ev.Until, ev.At, DefaultMaxKeys)
	g.mu.Unlock()

	g.cfg.Logger.Warn("scanguard: banned ip",
		"ip", ev.IP, "client_ip", ev.ClientIP, "offense", ev.Offense, "score", ev.Score, "path", ev.Path, "until", ev.Until, "reason", ev.Reason)

	if err := g.cfg.Counter.Reset(ctx, ev.IP); err != nil {
		g.cfg.Logger.Error("scanguard: counter reset failed", "ip", ev.IP, "err", err)
	}
	if g.cfg.BanList != nil {
		if err := g.cfg.BanList.OnBan(ctx, ev); err != nil {
			g.cfg.Logger.Error("scanguard: ban list failed", "ip", ev.IP, "err", err)
		}
	}
	for _, a := range g.cfg.Actions {
		g.wg.Add(1)
		go func(a Action) {
			defer g.wg.Done()
			actx, cancel := context.WithTimeout(ctx, g.cfg.ActionTimeout)
			defer cancel()
			if err := a.OnBan(actx, ev); err != nil {
				g.cfg.Logger.Error("scanguard: action failed", "ip", ev.IP, "err", err)
			}
		}(a)
	}
}

// offense records a ban for ip and returns how many it has had within
// OffenseMemory, this one included. It reuses the Counter, so a shared
// Counter also shares the offense history.
func (g *Guard) offense(ctx context.Context, ip string) int {
	if g.cfg.OffenseMemory <= 0 {
		return 1
	}
	n, err := g.cfg.Counter.Add(ctx, offenseKey(ip), 1, g.cfg.OffenseMemory)
	if err != nil {
		g.cfg.Logger.Error("scanguard: offense count failed", "ip", ip, "err", err)
		return 1
	}
	return max(n, 1)
}

func offenseKey(ip string) string { return "offense:" + ip }

func (g *Guard) allowed(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, p := range g.allow {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// recorder captures the status code while passing everything through.
type recorder struct {
	http.ResponseWriter
	code int
}

func (r *recorder) WriteHeader(code int) {
	if r.code == 0 && code >= 200 {
		r.code = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.code == 0 {
		r.code = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *recorder) status() int {
	if r.code == 0 {
		return http.StatusOK
	}
	return r.code
}

func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("scanguard: underlying ResponseWriter does not support hijacking")
}

// Unwrap lets http.ResponseController reach the original writer.
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
