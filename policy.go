package main

import (
	"net/http"
	"regexp"
	"strings"
)

// Path policy: default deny. A request reaches Kuma without a session only if its method
// and its exact, canonical path match publicRoutes below. Everything else needs a
// signed-in, allowed admin on the admin host, and is a 404 on every other host.
//
// The list comes from Uptime Kuma 2.5.12's source (file:line):
//
//	/                                   server/server.js:264 (entry: status page for a mapped
//	                                    domain, else a redirect to /status/<slug> or /dashboard)
//	/robots.txt                         server/server.js:342
//	/assets/<file>, icons, manifest,    server/server.js:357 (express-static-gzip of dist/, i.e.
//	  /serviceWorker.js                 Vite's hashed /assets/* and public/*: favicon.ico,
//	                                    icon.svg, icon.png, icon-192x192.png, icon-512x512.png,
//	                                    apple-touch-icon.png, manifest.json, serviceWorker.js;
//	                                    index.html links them (index.html:6-8) and src/main.js:49
//	                                    registers the service worker on every page)
//	/upload/<file>                      server/server.js:365 (status page logos)
//	/api/entry-page                     server/routers/api-router.js:27
//	/api/push/<token>   (any method)    server/routers/api-router.js:46 (router.all)
//	/api/badge/<id>/status              server/routers/api-router.js:147
//	/api/badge/<id>/uptime[/<dur>]      server/routers/api-router.js:220
//	/api/badge/<id>/ping[/<dur>]        server/routers/api-router.js:284
//	/api/badge/<id>/avg-response[/<d>]  server/routers/api-router.js:347
//	/api/badge/<id>/cert-exp            server/routers/api-router.js:411
//	/api/badge/<id>/response            server/routers/api-router.js:494
//	/status/<slug>                      server/routers/status-page-router.js:16
//	/status/<slug>/rss                  server/routers/status-page-router.js:22
//	/status                             server/routers/status-page-router.js:28
//	/status-page                        server/routers/status-page-router.js:33
//	/api/status-page/<slug>             server/routers/status-page-router.js:39
//	/api/status-page/heartbeat/<slug>   server/routers/status-page-router.js:64
//	/api/status-page/<slug>/manifest.json        status-page-router.js:113
//	/api/status-page/<slug>/incident-history     status-page-router.js:145
//	/api/status-page/<slug>/badge                status-page-router.js:170
//
// Not public, on purpose: /metrics (server.js:355; with disableAuth, apiAuth in
// server/auth.js:155 lets everyone in), /screenshots/* (uptime-kuma-server.js:208),
// /setup-database-info (server.js:288), /.well-known/change-password (server.js:367),
// /socket.io/ (see below), every other /api/* and every SPA route of src/router.js
// (/dashboard, /add, /list, /settings/*, /manage-status-page, /add-status-page,
// /maintenance*, /setup, /setup-database, /empty...).
//
// socket.io: the public status page does not use it. src/mixins/socket.js:19-23 lists
// /status*, /status-page and / as "noSocketIOPages", and initSocketIO() returns early on
// them; src/pages/StatusPage.vue only calls initSocketIO(true) in edit() (~line 1117),
// the admin's edit mode. The page reads /api/status-page/<slug> and
// /api/status-page/heartbeat/<slug> over plain HTTP (StatusPage.vue:1041, 1061). So
// /socket.io/ is session-only, and the status page's edit mode works on the admin host
// with a session.
//
// Matching is exact and case-sensitive. Express matches case-insensitively and ignores a
// trailing slash, so /STATUS/x or /api/push/<token>/ reach Kuma only with a session: the
// gate errs on the side of asking for one.

const (
	slug    = `[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*` // checkSlug, socket-handlers/status-page-socket-handler.js:544
	token   = `[A-Za-z0-9_-]{1,128}`           // genSecret's alphabet (src/util.ts:534), with room for hand-made tokens
	badgeID = `[0-9]{1,12}`
	dur     = `[0-9]{1,6}[a-z]?`
	file    = `[A-Za-z0-9][A-Za-z0-9._-]{0,200}` // never a dot file; ".." is refused by canonical()
)

var getHead = []string{http.MethodGet, http.MethodHead}

// anyMethod is what Express's router.all answers; CONNECT and TRACE never get this far.
var anyMethod = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions}

type route struct {
	re      *regexp.Regexp
	methods []string
}

func r(pattern string, methods []string) route {
	return route{re: regexp.MustCompile(`^` + pattern + `$`), methods: methods}
}

var publicRoutes = []route{
	r(`/`, getHead),
	r(`/robots\.txt`, getHead),
	r(`/(?:favicon\.ico|icon\.svg|icon\.png|icon-192x192\.png|icon-512x512\.png|apple-touch-icon\.png|manifest\.json|serviceWorker\.js)`, getHead),
	r(`/assets/`+file, getHead), // the gate's own files under /assets/ are matched first (server.go)
	r(`/upload/`+file, getHead),
	r(`/status/?`, getHead),
	r(`/status/`+slug+`/?`, getHead),
	r(`/status/`+slug+`/rss`, getHead),
	r(`/status-page`, getHead),
	r(`/api/entry-page`, getHead),
	r(`/api/push/`+token, anyMethod),
	r(`/api/badge/`+badgeID+`/(?:status|cert-exp|response)`, getHead),
	r(`/api/badge/`+badgeID+`/(?:uptime|ping|avg-response)(?:/`+dur+`)?`, getHead),
	r(`/api/status-page/`+slug, getHead),
	r(`/api/status-page/heartbeat/`+slug, getHead),
	r(`/api/status-page/`+slug+`/(?:manifest\.json|incident-history|badge)`, getHead),
}

// isPublic: Kuma answers this without a session.
func isPublic(method, path string) bool {
	for _, rt := range publicRoutes {
		if rt.re.MatchString(path) {
			for _, m := range rt.methods {
				if m == method {
					return true
				}
			}
			return false
		}
	}
	return false
}

// canonical returns the path the gate decides on, which is also the path Kuma gets, or
// false when the request target is not in the one plain form we accept: origin-form
// ("/..."), printable ASCII only, no percent-encoding at all (no Kuma route needs it, and
// %2f/%2e/%5c are how path tricks hide), no backslash, no empty segment ("//"), no "." or
// ".." segment and no ";". Query strings are not looked at here and are forwarded as sent.
func canonical(r *http.Request) (string, bool) {
	raw := r.RequestURI
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i]
	}
	if raw == "" || raw[0] != '/' || r.URL.IsAbs() || r.URL.Host != "" {
		return "", false
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c <= 0x20 || c >= 0x7f || c == '%' || c == '\\' || c == ';' || c == '#' {
			return "", false
		}
	}
	if raw != "/" {
		for _, seg := range strings.Split(raw[1:], "/") {
			// an empty last segment is a trailing slash, which is fine
			if seg == "." || seg == ".." {
				return "", false
			}
		}
		if strings.Contains(raw, "//") {
			return "", false
		}
	}
	if r.URL.Path != raw || r.URL.RawPath != "" {
		return "", false
	}
	return raw, true
}

// normHost lowercases a Host header and drops the port and a trailing dot.
func normHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i > 0 {
			return h[:i+1]
		}
		return ""
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return strings.TrimSuffix(h, ".")
}

// pushPath matches the push endpoint in any case, so a token never reaches a log even
// when the path was refused.
var pushPath = regexp.MustCompile(`(?i)(/api/push/)[^/?]*`)

// redactPath is what may go in a log: the path without its query, push tokens replaced,
// control characters escaped by %q at the call site, and at most 200 characters.
func redactPath(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if strings.Contains(strings.ToLower(p), "push") {
		// %-encoded variants of "/api/push/" are refused anyway; hide everything after "push"
		if pushPath.MatchString(p) {
			p = pushPath.ReplaceAllString(p, "${1}[redacted]")
		} else if i := strings.Index(strings.ToLower(p), "push"); i >= 0 {
			p = p[:i+4] + "[redacted]"
		}
	}
	if len(p) > 200 {
		p = p[:200] + "..."
	}
	return p
}

// firstSegment is "/api/..." for "/api/push/x": what may be logged of a refused path. At
// most 16 characters, shorter than a push token (32), so an encoded token never fits.
func firstSegment(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if len(p) > 1 {
		if i := strings.IndexByte(p[1:], '/'); i >= 0 {
			p = p[:i+1]
		}
	}
	if len(p) > 16 {
		p = p[:16]
	}
	return p + "..."
}
