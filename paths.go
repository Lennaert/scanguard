package scanguard

import (
	"path"
	"strings"
)

// DefaultSuspiciousPaths are paths that vulnerability scanners and
// wordlist brute-forcers (gobuster, dirb, nuclei and friends) probe for.
// They only count when the response is a miss, so an app that really has
// /admin is unaffected.
var DefaultSuspiciousPaths = []string{
	// secrets, VCS and editor leftovers
	"/.env", "/.git", "/.svn", "/.hg", "/.aws", "/.ssh", "/.docker",
	"/.vscode", "/.idea", "/.ds_store", "/.htaccess", "/.htpasswd",
	"/config.json", "/credentials", "/id_rsa",
	// WordPress and PHP
	"/wp-admin", "/wp-login", "/wp-content", "/wp-includes", "/wp-config",
	"xmlrpc.php", "/phpmyadmin", "/pma", "/phpinfo", "/vendor/phpunit", ".php",
	// other stacks
	".asp", ".jsp", ".cgi", "/cgi-bin", "/actuator", "/solr", "/jenkins",
	"/manager/html", "/hnap1", "/boaform", "/owa", "/telescope", "/_profiler",
	"/server-status", "/console",
	// admin panels
	"/admin", "/administrator", "/login.action",
	// dumps and backups
	".sql", ".bak", ".old", ".swp", "/backup", "/dump",
	// traversal
	"../", "/etc/passwd",
}

// DefaultIgnoreExtensions are assets whose misses are usually honest:
// a stale cached frontend, a removed image, a crawler asking for robots.txt.
var DefaultIgnoreExtensions = []string{
	".js", ".mjs", ".css", ".map", ".json", ".txt", ".xml",
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".ico",
	".woff", ".woff2", ".ttf", ".eot", ".otf",
	".mp4", ".webm", ".mp3",
}

// Match reports whether path matches pattern. Both are compared in lower
// case. A pattern starting with "/" matches at a segment boundary: "/admin"
// matches "/admin", "/admin/users" and "/x/admin.php" but not
// "/administrators-guide". Any other pattern matches anywhere, so ".php"
// matches "/index.php".
func Match(pattern, p string) bool {
	pattern, p = strings.ToLower(pattern), strings.ToLower(p)
	if !strings.HasPrefix(pattern, "/") {
		return strings.Contains(p, pattern)
	}
	for i := 0; ; {
		j := strings.Index(p[i:], pattern)
		if j < 0 {
			return false
		}
		end := i + j + len(pattern)
		if end == len(p) || p[end] == '/' || p[end] == '.' || strings.HasSuffix(pattern, "/") {
			return true
		}
		i += j + 1
	}
}

// weigh returns the score a miss on p adds and whether p looked suspicious.
func (g *Guard) weigh(p string) (weight int, suspicious bool) {
	for _, pat := range g.cfg.SuspiciousPaths {
		if Match(pat, p) {
			return g.cfg.SuspiciousWeight, true
		}
	}
	lower := strings.ToLower(p)
	for _, prefix := range g.cfg.IgnorePrefixes {
		if strings.HasPrefix(lower, strings.ToLower(prefix)) {
			return 0, false
		}
	}
	ext := path.Ext(lower)
	for _, e := range g.cfg.IgnoreExtensions {
		if ext == strings.ToLower(e) {
			return 0, false
		}
	}
	return g.cfg.NotFoundWeight, false
}
