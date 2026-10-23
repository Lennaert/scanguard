package scanguard

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// RemoteAddr returns the IP of the TCP peer.
func RemoteAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return normalize(host)
}

// HeaderIP reads the client IP from a header set by your proxy or CDN,
// such as "CF-Connecting-IP" or "X-Real-IP", and falls back to RemoteAddr.
// Only use it when every request passes through that proxy: clients can
// send the header themselves.
//
// For X-Forwarded-For it takes the rightmost address, the one added by the
// proxy closest to you; the leftmost one is whatever the client claimed.
func HeaderIP(header string) func(*http.Request) string {
	return func(r *http.Request) string {
		v := r.Header.Get(header)
		if i := strings.LastIndexByte(v, ','); i >= 0 {
			v = v[i+1:]
		}
		if ip := normalize(strings.TrimSpace(v)); ip != "" {
			return ip
		}
		return RemoteAddr(r)
	}
}

func normalize(s string) string {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return ""
	}
	return addr.Unmap().WithZone("").String()
}

func parseAllow(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		if !strings.Contains(s, "/") {
			addr, err := netip.ParseAddr(s)
			if err != nil {
				return nil, err
			}
			out = append(out, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// subject returns the key a client is counted and banned under: the
// address for IPv4, its IPv6Prefix network for IPv6.
func (g *Guard) subject(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Is4() || g.cfg.IPv6Prefix == 0 || g.cfg.IPv6Prefix == 128 {
		return ip
	}
	p, err := addr.Prefix(g.cfg.IPv6Prefix)
	if err != nil {
		return ip
	}
	return p.String()
}

// subjectOf turns user input, an address or a CIDR, into a ban key. The
// ban list matches keys exactly, so a range wider than what clients are
// grouped by (one IPv4 address, one IPv6Prefix network) could never match
// a request and is refused.
func (g *Guard) subjectOf(s string) (string, error) {
	if !strings.Contains(s, "/") {
		ip := normalize(s)
		if ip == "" {
			return "", fmt.Errorf("scanguard: invalid IP %q", s)
		}
		return g.subject(ip), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return "", fmt.Errorf("scanguard: invalid network %q", s)
	}
	group := 32
	if p.Addr().Is6() {
		group = g.cfg.IPv6Prefix
		if group == 0 {
			group = 128
		}
	}
	if p.Bits() < group {
		return "", fmt.Errorf("scanguard: %s is wider than /%d; ban it at the firewall or CDN instead", s, group)
	}
	return g.subject(p.Addr().Unmap().String()), nil
}
