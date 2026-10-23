# scanguard

[![Go Reference](https://pkg.go.dev/badge/github.com/Lennaert/scanguard.svg)](https://pkg.go.dev/github.com/Lennaert/scanguard)
[![CI](https://github.com/Lennaert/scanguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Lennaert/scanguard/actions/workflows/ci.yml)

HTTP middleware for Go that bans IPs probing for paths your app doesn't have, like `/.env`, `/.git/config` or `/wp-login.php`. Think of it as a small fail2ban that lives inside your app. It has no dependencies outside the standard library.

```
go get github.com/Lennaert/scanguard
```

```go
guard, err := scanguard.New(scanguard.DefaultConfig())
if err != nil { log.Fatal(err) }
http.ListenAndServe(":8080", guard.Middleware(router))
```

Works with `net/http`, chi, gorilla/mux, or anything else that takes `func(http.Handler) http.Handler`. Put it **outside** the router so it sees the router's 404s.

## How it decides

Each response with a counted status (default: 404) adds points to the client IP's score:

| Miss on                                             | Points (default) |
| --------------------------------------------------- | ---------------- |
| A scanner path (`/.env`, `/wp-admin`, `.php`, ...)   | 10               |
| An asset (`.js`, `.css`, images, fonts, `.txt` ...)  | 0                |
| `/.well-known/...`                                   | 0                |
| Anything else                                        | 1                |

At 50 points within 1 minute the IP is banned. With these numbers that's 5 scanner probes, or 50 ordinary 404s in a minute. A stale cached React build or a removed hotlinked image never counts.

Repeat offenders get longer bans:

| Ban within 30 days | Duration |
| ------------------ | -------- |
| 1st                | 1 hour   |
| 2nd                | 24 hours |
| 3rd and later      | 1 week   |

A ban counts toward escalation for 30 days (`OffenseMemory`). An IP that stays clean that long starts again at 1 hour. `Event.Offense` tells your actions which step this is, so a Cloudflare action could, for example, only push 3rd-and-later offenders to the edge.

Paths only count when they **miss**. If your app has a real `/admin`, it returns 200 and nothing gets counted. If it doesn't, someone hitting `/admin` is suspicious.

Pattern rules (`scanguard.Match`): a pattern starting with `/` matches at a segment boundary, so `/admin` matches `/admin`, `/admin/x` and `/x/admin.php` but not `/administrators-guide`. Other patterns match anywhere, so `.php` matches `/index.php`.

## Configuration

```go
cfg := scanguard.DefaultConfig()
cfg.Threshold = 30
cfg.BanDurations = []time.Duration{10 * time.Minute, time.Hour, 24 * time.Hour, 30 * 24 * time.Hour}
cfg.OffenseMemory = 7 * 24 * time.Hour
// cfg.BanDurations = []time.Duration{time.Hour} // fixed duration, no escalation
cfg.NotFoundWeight = 0 // only react to scanner paths
cfg.SuspiciousPaths = append(cfg.SuspiciousPaths, "/old-api")
cfg.Statuses = []int{404, 405}
```

### Behind a proxy or CDN

By default the client IP is `RemoteAddr`. Behind Cloudflare, nginx or a load balancer, that is the proxy, so tell scanguard where the real IP is:

```go
cfg.ClientIP = scanguard.HeaderIP("CF-Connecting-IP") // or "X-Real-IP", "X-Forwarded-For"
```

Only do this when all traffic goes through that proxy, because clients can set these headers themselves.

### IPv6

An IPv6 customer usually gets a whole /64 (18 quintillion addresses), so a scanner can use a fresh address for every request. scanguard therefore counts and bans IPv6 by /64: probes from `2001:db8:1:2::1`, `::2`, `::3`... add up to one score, and the ban covers the whole network. `Event.IP` is then `"2001:db8:1:2::/64"` and `Event.ClientIP` is the exact address. Set `cfg.IPv6Prefix = 128` to count per address, or 56/48 to group more widely.

`guard.Ban` and `guard.Unban` take an address or a CIDR. A range wider than the grouping (an IPv4 `/24`, an IPv6 `/48` with the default `/64`) is refused, because the ban list could never match it. Block those at your firewall or CDN.

### Memory limits

The in-memory stores keep at most 100,000 keys each (`DefaultMaxKeys`), so the worst case stays around 200 MB. Change it before first use:

```go
counter := scanguard.NewMemoryCounter()
counter.MaxKeys = 500_000 // 0 = no cap
cfg.Counter = counter
```

When the counter is full, a new IP evicts the stalest key from a random sample of 8. This is the same approximate LRU Redis uses, and it costs O(1). An IP that keeps probing stays fresh and keeps its score. The limit: a scanner hitting less than once per ~`MaxKeys` new IPs can be evicted during a flood. Offense history is old by nature, so it is the first thing to go under pressure. When the ban list is full, the ban that expires soonest is dropped.

### Allow list

The default `Allow` list contains loopback and private ranges (10/8, 172.16/12, 192.168/16, fc00::/7). They are never counted or banned. That way a misconfigured proxy setup can't ban your own load balancer and take the whole site offline with it.

## Plugging in your own pieces

There are three interfaces:

```go
// Counter keeps sliding-window scores. Default: in memory. It also keeps the
// ban history for escalation, under the key "offense:<ip>".
type Counter interface {
    Add(ctx context.Context, key string, weight int, window time.Duration) (int, error)
    Reset(ctx context.Context, key string) error
}

// Action runs when an IP is banned. Add as many as you like; they run in
// the background with a timeout.
type Action interface {
    OnBan(ctx context.Context, ev Event) error
}

// BanList is the local block list checked on every request. Default: in memory.
// Set cfg.BanList = nil to skip local blocking, e.g. if Cloudflare does it.
type BanList interface {
    Action
    Banned(ctx context.Context, ip string) (bool, error)
    Unban(ctx context.Context, ip string) error
}
```

Running several instances? Implement `Counter` and `BanList` on Redis so they share state. A sorted set per key with `ZADD` + `ZREMRANGEBYSCORE` makes a good sliding window, and `SET ip 1 PX <ttl>` works for bans. Set each key's expiry from the `window` passed to `Add`. Miss scores use a 1-minute window but offense keys use 30 days, so one fixed TTL would wipe the ban history.

### Action examples

```go
// Slack
slack := scanguard.ActionFunc(func(ctx context.Context, ev scanguard.Event) error {
    body := fmt.Sprintf(`{"text":"banned %s (%s, last path %s)"}`, ev.IP, ev.Reason, ev.Path)
    req, _ := http.NewRequestWithContext(ctx, "POST", slackWebhookURL, strings.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    resp, err := http.DefaultClient.Do(req)
    if err != nil { return err }
    return resp.Body.Close()
})

// ipset with a timeout, so the kernel drops packets and the ban expires on its own.
// ev.IP can be an IPv6 /64, so use hash:net sets, one per family:
//   ipset create scanners4 hash:net family inet  timeout 0
//   ipset create scanners6 hash:net family inet6 timeout 0
ipset := scanguard.ActionFunc(func(ctx context.Context, ev scanguard.Event) error {
    set := "scanners4"
    if strings.Contains(ev.IP, ":") {
        set = "scanners6"
    }
    secs := strconv.Itoa(int(time.Until(ev.Until).Seconds()))
    return exec.CommandContext(ctx, "ipset", "add", set, ev.IP, "timeout", secs, "-exist").Run()
})

cfg.Actions = []scanguard.Action{slack, ipset}
```

For Cloudflare, an Action that creates an IP Access Rule or adds to a WAF list does the same job at the edge. Use the `ip_range` target when `ev.IP` contains a `/`.

## Other frameworks

For frameworks without `net/http` middleware (gin, echo), call the two building blocks yourself:

```go
if guard.Blocked(req) { /* respond 403 and stop */ }
// ... handle the request ...
guard.Record(req, statusCode)
```

## Manual control

```go
guard.Ban(ctx, "203.0.113.7", "manual") // counts as an offense too
guard.Unban(ctx, "203.0.113.7")         // also forgets its offense history
guard.Shutdown(ctx) // wait for running actions on exit
```

## Try it

```
go run ./example
for p in /.env /.git/config /wp-login.php /phpmyadmin/ /backup.sql /; do
  curl -s -o /dev/null -w "%{http_code} $p\n" -H 'X-Real-IP: 203.0.113.7' localhost:8080$p
done
```

You get five 404s, then a 403.

## Status

Pre-1.0: the API may still change between minor versions. Requires Go 1.22 or newer.

## License

[MIT](LICENSE)
