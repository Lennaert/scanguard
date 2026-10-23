package scanguard

import (
	"log/slog"
	"net/http"
	"time"
)

// Config controls detection and blocking. Start from DefaultConfig and
// change what you need; New uses the fields exactly as given.
type Config struct {
	// Window is how far back hits are counted.
	Window time.Duration
	// Threshold is the score within Window at which an IP gets banned.
	Threshold int
	// SuspiciousWeight is added for a counted response on a path that
	// matches SuspiciousPaths.
	SuspiciousWeight int
	// NotFoundWeight is added for any other counted response. Set it to 0
	// to only react to suspicious paths.
	NotFoundWeight int
	// BanDurations is the escalation ladder: the first ban lasts
	// BanDurations[0], the second BanDurations[1], and so on. Once the
	// ladder runs out, the last step repeats. One entry means a fixed
	// duration.
	BanDurations []time.Duration
	// OffenseMemory is how long a ban counts toward escalation. An IP with
	// no bans in this period starts again at the first step.
	OffenseMemory time.Duration

	// Statuses are the response codes that count as a miss. Default: 404.
	Statuses []int
	// SuspiciousPaths are patterns that scanners probe for. See Match for
	// the matching rules.
	SuspiciousPaths []string
	// IgnoreExtensions are file extensions whose misses never count, so a
	// stale cached frontend or a removed hotlinked image is harmless.
	IgnoreExtensions []string
	// IgnorePrefixes are path prefixes whose misses never count.
	IgnorePrefixes []string

	// IPv6Prefix groups IPv6 clients by network for counting and banning.
	// Providers hand out a /64 (or more) per customer, so a scanner can pick
	// a fresh address for every request; per-address counting would never
	// catch it. 0 or 128 counts every IPv6 address separately.
	IPv6Prefix int

	// Allow lists IPs or CIDRs that are never counted or banned.
	Allow []string

	// Counter keeps the per-IP score. Nil means an in-memory counter.
	Counter Counter
	// BanList is the local block list checked on every request. Nil
	// disables local blocking, e.g. when a firewall action does the work.
	BanList BanList
	// Actions run in the background after an IP is banned: notify Slack,
	// push to Cloudflare, add an iptables rule, and so on.
	Actions []Action
	// ActionTimeout bounds each Action call.
	ActionTimeout time.Duration

	// ClientIP extracts the client IP from a request. Default: RemoteAddr.
	// Behind a proxy or CDN use HeaderIP, or every request looks like it
	// comes from the proxy.
	ClientIP func(*http.Request) string
	// Blocked writes the response for a banned IP. Default: plain 403.
	Blocked http.Handler
	// Logger receives ban and error logs. Default: slog.Default().
	Logger *slog.Logger
}

// DefaultConfig bans an IP when it scores 50 within a minute: 5 misses on
// scanner paths, or 50 ordinary misses. Missing assets (.js, .css, images,
// fonts) never count. The first ban lasts an hour, a second within 30 days
// a day, and every one after that a week.
func DefaultConfig() Config {
	return Config{
		Window:           time.Minute,
		Threshold:        50,
		SuspiciousWeight: 10,
		NotFoundWeight:   1,
		BanDurations:     []time.Duration{time.Hour, 24 * time.Hour, 7 * 24 * time.Hour},
		OffenseMemory:    30 * 24 * time.Hour,
		Statuses:         []int{http.StatusNotFound},
		SuspiciousPaths:  append([]string(nil), DefaultSuspiciousPaths...),
		IgnoreExtensions: append([]string(nil), DefaultIgnoreExtensions...),
		IgnorePrefixes:   []string{"/.well-known/"},
		IPv6Prefix:       64,
		Allow: []string{
			"127.0.0.0/8", "::1/128",
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
		},
		BanList:       NewMemoryBanList(),
		ActionTimeout: 10 * time.Second,
	}
}
