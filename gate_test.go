package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"gitlab.gutocarvalho.net/open/gcn/goweb/auth"
)

// Every SPA route of Kuma 2.5.12's src/router.js (children expanded) and every non-public
// server route: without a session none may reach Kuma, on any host.
var privateKuma = []struct{ method, path string }{
	// src/router.js
	{"GET", "/empty"}, {"GET", "/dashboard"}, {"GET", "/dashboard/1"}, {"GET", "/edit/1"},
	{"GET", "/add"}, {"GET", "/clone/1"}, {"GET", "/list"}, {"GET", "/settings"},
	{"GET", "/settings/general"}, {"GET", "/settings/appearance"}, {"GET", "/settings/notifications"},
	{"GET", "/settings/reverse-proxy"}, {"GET", "/settings/tags"}, {"GET", "/settings/monitor-history"},
	{"GET", "/settings/docker-hosts"}, {"GET", "/settings/remote-browsers"}, {"GET", "/settings/security"},
	{"GET", "/settings/api-keys"}, {"GET", "/settings/proxies"}, {"GET", "/settings/about"},
	{"GET", "/manage-status-page"}, {"GET", "/add-status-page"}, {"GET", "/maintenance"},
	{"GET", "/add-maintenance"}, {"GET", "/maintenance/edit/1"}, {"GET", "/maintenance/clone/1"},
	{"GET", "/setup"}, {"GET", "/setup-database"}, {"GET", "/no-such-page"},
	// server/server.js, uptime-kuma-server.js, setup-database.js
	{"GET", "/metrics"}, {"GET", "/screenshots/1.png"}, {"GET", "/setup-database-info"},
	{"POST", "/setup-database"}, {"GET", "/.well-known/change-password"}, {"GET", "/index.html"},
	{"POST", "/test-webhook"}, {"GET", "/_e2e/take-sqlite-snapshot"},
	{"GET", "/socket.io/?EIO=4&transport=polling"}, {"GET", "/socket.io/x?EIO=4&transport=polling"}, {"POST", "/socket.io/?EIO=4&transport=polling&sid=x"},
	// /api/* outside the public list, and wrong methods or shapes of public ones
	{"GET", "/api/status-page"}, {"POST", "/api/status-page/x"}, {"DELETE", "/api/status-page/x"},
	{"POST", "/api/status-page/upload-logo"}, {"GET", "/api/badge/abc/status"},
	{"GET", "/api/badge/1/nope"}, {"GET", "/api/v1/monitors"}, {"GET", "/api/whatever"},
	{"POST", "/status/x"}, {"GET", "/status/x/rss/extra"}, {"GET", "/upload"}, {"GET", "/upload/"},
	{"GET", "/upload/.hidden"}, {"GET", "/assets/"}, {"GET", "/api/push/tok/"}, {"GET", "/api/push/"},
	// case: Express would match these, the gate does not
	{"GET", "/STATUS/x"}, {"GET", "/Metrics"}, {"GET", "/API/push/abc"}, {"GET", "/Dashboard"},
}

func TestPrivateKumaRoutesNeedSession(t *testing.T) {
	g := newGate(t, opts{})
	for _, c := range privateKuma {
		for _, host := range allHosts {
			for _, nav := range []bool{true, false} {
				hdr := []string{"Sec-Fetch-Mode", "cors", "Accept", "application/json"}
				if nav {
					hdr = navigate()
				}
				rec := g.do(t, c.method, host, c.path, nil, hdr...)
				switch {
				case host != adminHost && nav && c.method == "GET" && !strings.HasPrefix(c.path, "/socket.io/"):
					// a status-only host sends a person to the admin host, without the query
					want := "https://" + adminHost + strings.SplitN(c.path, "?", 2)[0]
					if rec.Code != 302 || rec.Header().Get("Location") != want {
						t.Errorf("%s %s on %s (navigation): %d %q, want a redirect to %s", c.method, c.path, host, rec.Code, rec.Header().Get("Location"), want)
					}
				case host != adminHost:
					if rec.Code != 404 {
						t.Errorf("%s %s on %s: %d, want 404", c.method, c.path, host, rec.Code)
					}
				case nav && c.method == "GET" && !strings.HasPrefix(c.path, "/socket.io/"):
					if rec.Code != 302 || !strings.HasPrefix(rec.Header().Get("Location"), "/login?next=") {
						t.Errorf("%s %s (navigation): %d %q, want a redirect to /login", c.method, c.path, rec.Code, rec.Header().Get("Location"))
					}
				default:
					if rec.Code != 401 {
						t.Errorf("%s %s (nav=%v): %d, want 401", c.method, c.path, nav, rec.Code)
					}
				}
			}
		}
	}
	if n := g.kuma.count(); n != 0 {
		t.Fatalf("%d requests reached Kuma without a session: last %+v", n, g.kuma.last())
	}
}

var publicKuma = []struct{ method, path string }{
	{"GET", "/"}, {"HEAD", "/"}, {"GET", "/robots.txt"}, {"GET", "/favicon.ico"}, {"GET", "/icon.svg"},
	{"GET", "/icon.png"}, {"GET", "/icon-192x192.png"}, {"GET", "/icon-512x512.png"},
	{"GET", "/apple-touch-icon.png"}, {"GET", "/manifest.json"}, {"GET", "/serviceWorker.js"},
	{"GET", "/assets/index-D3kJ8a_x.js"}, {"GET", "/assets/index-B1x-9Qz.css"}, {"GET", "/assets/vendor.woff2"},
	{"GET", "/upload/logo1.png"}, {"GET", "/upload/logo1.png?t=123"},
	{"GET", "/status"}, {"GET", "/status/"}, {"GET", "/status/bolha"}, {"GET", "/status/bolha-us/"},
	{"GET", "/status/Bolha"}, {"GET", "/status/bolha/rss"}, {"GET", "/status-page"},
	{"GET", "/api/entry-page"},
	{"GET", "/api/push/AbCdEf0123456789AbCdEf0123456789?status=up&msg=OK&ping="},
	{"POST", "/api/push/AbCdEf0123456789"}, {"PUT", "/api/push/AbCdEf0123456789"}, {"HEAD", "/api/push/x"},
	{"GET", "/api/badge/1/status"}, {"GET", "/api/badge/12/uptime"}, {"GET", "/api/badge/12/uptime/24h"},
	{"GET", "/api/badge/12/ping/720"}, {"GET", "/api/badge/12/avg-response/7d"},
	{"GET", "/api/badge/12/cert-exp?style=flat"}, {"GET", "/api/badge/12/response"},
	{"GET", "/api/status-page/bolha"}, {"GET", "/api/status-page/heartbeat/bolha"},
	{"GET", "/api/status-page/bolha/manifest.json"}, {"GET", "/api/status-page/bolha/incident-history?cursor=abc"},
	{"GET", "/api/status-page/bolha/badge"},
}

func TestPublicPathsPassOnEveryHost(t *testing.T) {
	g := newGate(t, opts{})
	for _, c := range publicKuma {
		for _, host := range allHosts {
			before := g.kuma.count()
			rec := g.do(t, c.method, host, c.path, nil)
			if rec.Code != 200 || g.kuma.count() != before+1 {
				t.Errorf("%s %s on %s: %d, Kuma hits %d->%d", c.method, c.path, host, rec.Code, before, g.kuma.count())
				continue
			}
			h := g.kuma.last()
			want, _, _ := strings.Cut(c.path, "?")
			if h.Method != c.method || h.Path != want || h.Host != host {
				t.Errorf("%s %s on %s: Kuma got %s %s Host %s", c.method, c.path, host, h.Method, h.Path, h.Host)
			}
			// Kuma's own responses keep Kuma's headers: no gate CSP, no noindex.
			if rec.Header().Get("Content-Security-Policy") != "" || rec.Header().Get("X-Robots-Tag") != "" {
				t.Errorf("%s %s: gate headers on a Kuma response", c.method, c.path)
			}
		}
	}
}

func TestUnknownHostIsNotFound(t *testing.T) {
	g := newGate(t, opts{})
	for _, path := range []string{"/", "/status/bolha", "/login", "/dashboard", "/api/push/abc", "/assets/style.css"} {
		if rec := g.do(t, "GET", "evil.example", path, nil, navigate()...); rec.Code != 404 {
			t.Errorf("%s on an unknown host: %d", path, rec.Code)
		}
	}
	if g.kuma.count() != 0 {
		t.Fatal("an unknown host reached Kuma")
	}
	// the health check answers whatever the Host (the probe uses 127.0.0.1:3003)
	if rec := g.do(t, "GET", "127.0.0.1:3003", "/healthz", nil); rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != "ok" {
		t.Fatalf("/healthz: %d", rec.Code)
	}
}

// Host matching ignores case, the port and a trailing dot.
func TestHostForms(t *testing.T) {
	g := newGate(t, opts{})
	for _, h := range []string{"STATUS.gutocarvalho.net", "status.gutocarvalho.net:443", "status.gutocarvalho.net."} {
		if rec := g.do(t, "GET", h, "/login", nil); rec.Code != 302 && rec.Code != 200 {
			t.Errorf("Host %q: /login %d", h, rec.Code)
		}
	}
}

func TestPathTricksAreRejected(t *testing.T) {
	g := newGate(t, opts{})
	cookie := g.login(t, "ana")
	tricks := []string{
		"/status/../dashboard", "/status/./bolha", "/status/x/..", "/api/push/..%2f..%2fmetrics",
		"/api/push/%2e%2e/%2e%2e/metrics", "//dashboard", "//status/bolha", "/status//bolha",
		"/status/%2e%2e/dashboard", "/assets/..%5c..%5cmetrics", "/%64ashboard", "/status/bolha%2F..%2F..%2Fmetrics",
		"/status/bolha;/../../metrics", "/upload/..%2f..%2fkuma.db", "/api/status-page/%62olha",
	}
	for _, p := range tricks {
		for _, host := range allHosts {
			rec := g.do(t, "GET", host, p, nil, "Cookie", cookie)
			if rec.Code != 400 {
				t.Errorf("%s on %s: %d, want 400", p, host, rec.Code)
			}
		}
	}
	// targets httptest.NewRequest would not build
	for _, line := range []string{
		"GET http://evil.example/dashboard HTTP/1.1", "GET /status\\..\\dashboard HTTP/1.1",
		"GET * HTTP/1.1", "GET /status/bolha#x HTTP/1.1",
	} {
		req := rawRequest(t, line)
		if req == nil {
			continue // net/http refuses it before any handler
		}
		req.Header.Set("Cookie", cookie)
		rec := httptest.NewRecorder()
		g.h.ServeHTTP(rec, req)
		if rec.Code != 400 {
			t.Errorf("%q: %d, want 400", line, rec.Code)
		}
	}
	if rec := g.do(t, "TRACE", adminHost, "/", nil); rec.Code != 405 {
		t.Errorf("TRACE: %d", rec.Code)
	}
	if n := g.kuma.count(); n != 0 {
		t.Fatalf("%d tricks reached Kuma: last %+v", n, g.kuma.last())
	}
}

func TestSessionAndAllowlist(t *testing.T) {
	g := newGate(t, opts{})
	ana, bob, eve := g.login(t, "ana"), g.login(t, "bob"), g.login(t, "eve")

	rec := g.do(t, "GET", adminHost, "/dashboard", nil, append(navigate(), "Cookie", ana)...)
	if rec.Code != 200 || g.kuma.count() != 1 || g.kuma.last().Path != "/dashboard" {
		t.Fatalf("allowed admin: %d, hits %d", rec.Code, g.kuma.count())
	}
	// bob is a Fundador (admin) but not in gate.admins; eve is only a viewer
	for name, c := range map[string]string{"bob": bob, "eve": eve} {
		rec := g.do(t, "GET", adminHost, "/dashboard", nil, append(navigate(), "Cookie", c)...)
		if rec.Code != 403 || !strings.Contains(rec.Body.String(), `action="/logout"`) || !strings.Contains(rec.Body.String(), name) {
			t.Errorf("%s: %d, want the 403 page with a sign-out button", name, rec.Code)
		}
		if rec := g.do(t, "GET", adminHost, "/socket.io/?EIO=4&transport=polling", nil, "Cookie", c, "Sec-Fetch-Site", "same-origin"); rec.Code != 403 {
			t.Errorf("%s socket.io: %d", name, rec.Code)
		}
		// goweb's account admin pages are guarded by the allowlist too
		if rec := g.do(t, "GET", adminHost, "/admin/users", nil, append(navigate(), "Cookie", c)...); rec.Code != 403 {
			t.Errorf("%s /admin/users: %d", name, rec.Code)
		}
	}
	if g.kuma.count() != 1 {
		t.Fatal("a refused person reached Kuma")
	}
	// a session is no use on a status-only host (and the cookie is __Host- anyway): a page
	// of the panel there sends the browser to the admin host, same path, no query
	if rec := g.do(t, "GET", bolhaHost, "/manage-status-page?x=1", nil, append(navigate(), "Cookie", ana)...); rec.Code != 302 ||
		rec.Header().Get("Location") != "https://"+adminHost+"/manage-status-page" || g.kuma.count() != 1 {
		t.Errorf("panel page on a status host: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// not a navigation (fetch, script) or socket.io: still nothing there
	if rec := g.do(t, "GET", bolhaHost, "/dashboard", nil); rec.Code != 404 {
		t.Errorf("fetch of /dashboard on a status host: %d", rec.Code)
	}
	if rec := g.do(t, "GET", bolhaHost, "/socket.io/?EIO=4&transport=polling", nil, navigate()...); rec.Code != 404 {
		t.Errorf("socket.io on a status host: %d", rec.Code)
	}
	if rec := g.do(t, "POST", bolhaHost, "/dashboard", nil, navigate()...); rec.Code != 404 {
		t.Errorf("POST on a status host: %d", rec.Code)
	}
	// the redirect keeps where the person was going
	if rec := g.do(t, "GET", adminHost, "/settings/general", nil, navigate()...); rec.Header().Get("Location") != "/login?next=%2Fsettings%2Fgeneral" {
		t.Errorf("next: %q", rec.Header().Get("Location"))
	}
}

// Every admin gets in only when the YAML says so in words: gate.allow_all_admins.
func TestAllowAllAdmins(t *testing.T) {
	g := newGate(t, opts{gate: "gate:\n  allow_all_admins: true\n"})
	if rec := g.do(t, "GET", adminHost, "/dashboard", nil, "Cookie", g.login(t, "bob")); rec.Code != 200 {
		t.Fatalf("bob with allow_all_admins: %d", rec.Code)
	}
	if rec := g.do(t, "GET", adminHost, "/dashboard", nil, "Cookie", g.login(t, "eve")); rec.Code != 403 {
		t.Fatalf("a viewer with allow_all_admins: %d", rec.Code)
	}
}

// A missing, misspelled or empty allowlist stops the start; it never means "everyone".
func TestAllowlistFailsClosed(t *testing.T) {
	for name, gate := range map[string]string{
		"no gate section":          "",
		"gate misspelled":          "gates:\n  admins: [bolha:ana]\n",
		"admins at the top level":  "admins: [bolha:ana]\n",
		"empty gate":               "gate: {}\n",
		"empty admins":             "gate:\n  admins: []\n",
		"admins without a value":   "gate:\n  admins:\n",
		"admins misspelled":        "gate:\n  admin: [bolha:ana]\n",
		"allow_all_admins false":   "gate:\n  allow_all_admins: false\n",
		"both set":                 "gate:\n  admins: [bolha:ana]\n  allow_all_admins: true\n",
		"unknown top-level key":    "gate:\n  admins: [bolha:ana]\nextra: 1\n",
		"allow_all_admins as text": "gate:\n  allow_all_admins: yes please\n",
	} {
		g := gate
		if g == "" {
			g = "\n" // writeConfig's default needs a non-empty gate text to be replaced
		}
		writeConfig(t, opts{gate: g}, "https://bolha.example")
		if _, err := loadConfig(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	writeConfig(t, opts{gate: "gate:\n  allow_all_admins: true\n"}, "https://bolha.example")
	if c, err := loadConfig(); err != nil || !c.allowAll || len(c.admins) != 0 {
		t.Fatalf("allow_all_admins: %+v %v", c.allowAll, err)
	}
}

// The query string reaches Kuma only where Kuma reads it (policy.go): elsewhere a random
// query would bust Kuma's 1000-entry response cache.
func TestPublicQueryOnlyWhereKumaReadsIt(t *testing.T) {
	g := newGate(t, opts{})
	// a list, not a map literal: gofmt 1.26 and 1.27 align long map keys differently
	for _, c := range []struct{ path, want string }{
		{"/?r=1", ""},
		{"/status/bolha?edit", ""},
		{"/status/bolha/rss?r=1", ""},
		{"/status?r=1", ""},
		{"/status-page?r=1", ""},
		{"/api/entry-page?r=1", ""},
		{"/api/status-page/bolha?r=1", ""},
		{"/api/status-page/heartbeat/bolha?r=12345", ""},
		{"/api/status-page/bolha/manifest.json?r=1", ""},
		{"/assets/index-D3kJ8a_x.js?v=2", ""},
		{"/upload/logo1.png?t=123", ""},
		{"/icon.svg?r=1", ""},
		{"/robots.txt?r=1", ""},
		{"/api/push/abc?status=up&msg=OK&ping=12", "status=up&msg=OK&ping=12"},
		{"/api/badge/1/status?label=x&upColor=green", "label=x&upColor=green"},
		{"/api/badge/1/uptime/24h?labelPrefix=a", "labelPrefix=a"},
		{"/api/badge/1/cert-exp?date=true", "date=true"},
		{"/api/badge/1/response?style=flat", "style=flat"},
		{"/api/status-page/bolha/incident-history?cursor=abc", "cursor=abc"},
		{"/api/status-page/bolha/badge?label=Status", "label=Status"},
	} {
		path, want := c.path, c.want
		if rec := g.do(t, "GET", bolhaHost, path, nil); rec.Code != 200 {
			t.Errorf("%s: %d", path, rec.Code)
			continue
		}
		if got := g.kuma.last().RawQuery; got != want {
			t.Errorf("%s: Kuma got query %q, want %q", path, got, want)
		}
	}
	// a signed-in admin's own requests keep theirs
	g.do(t, "GET", adminHost, "/dashboard?x=1", nil, "Cookie", g.login(t, "ana"))
	if got := g.kuma.last().RawQuery; got != "x=1" {
		t.Errorf("private request lost its query: %q", got)
	}
}

// Kuma's admin channel (socket.io, upgrades) must prove its origin; a request carrying
// neither Origin nor Sec-Fetch-Site is refused there, and still passes elsewhere.
func TestSocketIONeedsProvenOrigin(t *testing.T) {
	g := newGate(t, opts{})
	ana := g.login(t, "ana")
	for _, m := range []string{"GET", "POST"} {
		if rec := g.do(t, m, adminHost, "/socket.io/?EIO=4&transport=polling", strings.NewReader("x"), "Cookie", ana); rec.Code != 403 {
			t.Errorf("%s socket.io without Origin or Sec-Fetch-Site: %d", m, rec.Code)
		}
	}
	if g.kuma.count() != 0 {
		t.Fatal("an unproven socket.io request reached Kuma")
	}
	if rec := g.do(t, "GET", adminHost, "/socket.io/?EIO=4&transport=polling", nil, "Cookie", ana, "Origin", "https://"+adminHost+":443"); rec.Code != 200 {
		t.Errorf("Origin with the default port: %d", rec.Code)
	}
	if rec := g.do(t, "POST", adminHost, "/api/whatever", strings.NewReader("x"), "Cookie", ana); rec.Code != 200 {
		t.Errorf("a non-socket.io POST without either header: %d", rec.Code)
	}
}

// KUMAGATE_BASE_URL with an explicit default port still matches the browser's Origin.
func TestBaseURLWithDefaultPort(t *testing.T) {
	writeConfig(t, opts{}, newFakeMastodon(t).URL)
	t.Setenv("KUMAGATE_BASE_URL", "https://"+adminHost+":443")
	t.Setenv("KUMAGATE_UPSTREAM", newFakeKuma(t).srv.URL)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	s, err := newServer(cfg, mustTemplates(t))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/socket.io/", nil)
	r.Header.Set("Origin", "https://"+adminHost)
	if cfg.adminHost != adminHost || !s.sameOrigin(r, true) {
		t.Fatalf("admin host %q, origin %q", cfg.adminHost, s.baseOrig)
	}
	for in, want := range map[string]string{
		"https://Status.Example.org:443": "https://status.example.org",
		"http://x:80":                    "http://x",
		"https://x:8443":                 "https://x:8443",
		"https://[::1]:443":              "https://[::1]",
	} {
		if got := normOrigin(in); got != want {
			t.Errorf("normOrigin(%q) = %q, want %q", in, got, want)
		}
	}
	if normOrigin("null") == normOrigin("garbage") && normOrigin("null") == s.baseOrig {
		t.Error("an unparsable Origin matched")
	}
}

// The "400 non-canonical" line is limited per minute, with a count of what was dropped.
func TestBadPathLogIsRateLimited(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	g := newGate(t, opts{})
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	g.s.badPaths = &logLimiter{max: badPathLogs, now: func() time.Time { return now }}
	for range 500 {
		g.do(t, "GET", adminHost, "/a/../b", nil)
	}
	if n := strings.Count(buf.String(), "non-canonical"); n != badPathLogs {
		t.Fatalf("%d lines logged in a minute, want %d", n, badPathLogs)
	}
	now = now.Add(61 * time.Second)
	g.do(t, "GET", adminHost, "/a/../b", nil)
	if !strings.Contains(buf.String(), "480 similar lines suppressed") {
		t.Fatalf("no suppressed count:\n%s", buf.String())
	}
}

// The local accounts' sign-in limits use the gate's trusted proxies (one setting), so behind
// a container bridge every sign-in is not one shared address.
func TestLocalProviderUsesGateProxies(t *testing.T) {
	writeConfig(t, opts{}, "https://bolha.example")
	t.Setenv("KUMAGATE_TRUSTED_PROXIES", "172.30.0.1")
	c, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	l := c.auth.Providers[0].(*auth.Local)
	if len(l.TrustedProxies) != 1 || l.TrustedProxies[0].String() != "172.30.0.1/32" {
		t.Fatalf("local provider trusts %v", l.TrustedProxies)
	}
	writeConfig(t, opts{local: "      trusted_proxies: [127.0.0.1]\n"}, "https://bolha.example")
	t.Setenv("KUMAGATE_TRUSTED_PROXIES", "172.30.0.1")
	if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "trusted_proxies") {
		t.Fatalf("disagreeing trusted_proxies: %v", err)
	}
	writeConfig(t, opts{local: "      trusted_proxies: [\"::1\", 127.0.0.1]\n"}, "https://bolha.example")
	if _, err := loadConfig(); err != nil {
		t.Fatalf("the same proxies in another order: %v", err)
	}
}

// /logout says what signing out does to open Kuma tabs, and offers local accounts goweb's
// "sign out everywhere", which ends every session of the account.
func TestLogoutExplainsOpenTabs(t *testing.T) {
	g := newGate(t, opts{})
	body := g.do(t, "GET", adminHost, "/logout", nil, "Cookie", g.login(t, "ana")).Body.String()
	if strings.Contains(body, "/account/signout-all") || !strings.Contains(body, "removed from the access list") {
		t.Fatal("Mastodon session: wrong logout page")
	}
	var out, errb strings.Builder
	if users([]string{"add", "vera", "viewer", "--password-stdin"}, strings.NewReader("a long enough password\n"), &out, &errb) != 0 {
		t.Fatal(errb.String())
	}
	rec := g.do(t, "POST", adminHost, "/login", strings.NewReader("name=vera&password=a+long+enough+password&next=%2F"),
		"Content-Type", "application/x-www-form-urlencoded", "Sec-Fetch-Site", "same-origin")
	var vera string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-kuma-gate" {
			vera = c.Name + "=" + c.Value
		}
	}
	if vera == "" {
		t.Fatalf("local sign-in: %d", rec.Code)
	}
	body = g.do(t, "GET", adminHost, "/logout", nil, "Cookie", vera).Body.String()
	if !strings.Contains(body, `action="/account/signout-all"`) {
		t.Fatal("local session: no sign-out-everywhere form")
	}
	g.do(t, "POST", adminHost, "/account/signout-all", nil, "Cookie", vera, "Sec-Fetch-Site", "same-origin")
	if _, ok := g.s.auth.User(withCookie(vera)); ok {
		t.Fatal("the old session still works after sign out everywhere")
	}
}

func withCookie(c string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", c)
	return r
}

func TestCrossOriginIsRefused(t *testing.T) {
	g := newGate(t, opts{})
	ana := g.login(t, "ana")
	for _, hdr := range [][]string{
		{"Origin", "https://evil.example"},
		{"Origin", "https://other.gutocarvalho.net"},
		{"Sec-Fetch-Site", "same-site"},
		{"Sec-Fetch-Site", "cross-site"},
	} {
		rec := g.do(t, "POST", adminHost, "/socket.io/?EIO=4&transport=polling&sid=x", strings.NewReader("x"), append(hdr, "Cookie", ana)...)
		if rec.Code != 403 {
			t.Errorf("%v: %d", hdr, rec.Code)
		}
	}
	// GETs too, anywhere under /socket.io/ (engine.io answers the whole prefix)
	for _, p := range []string{"/socket.io/?EIO=4&transport=polling", "/socket.io/x?EIO=4&transport=polling"} {
		if rec := g.do(t, "GET", adminHost, p, nil, "Cookie", ana, "Sec-Fetch-Site", "same-site"); rec.Code != 403 {
			t.Errorf("same-site GET %s: %d", p, rec.Code)
		}
	}
	if g.kuma.count() != 0 {
		t.Fatal("a cross-origin request reached Kuma")
	}
	rec := g.do(t, "POST", adminHost, "/socket.io/?EIO=4&transport=polling&sid=x", strings.NewReader("x"),
		"Cookie", ana, "Origin", "https://"+adminHost, "Sec-Fetch-Site", "same-origin")
	if rec.Code != 200 || g.kuma.count() != 1 {
		t.Fatalf("same origin: %d", rec.Code)
	}
}

// goweb's routes and stylesheet belong to the gate; the rest of /assets/ is Kuma's.
func TestGateRoutesWinAndKumaAssetsPass(t *testing.T) {
	g := newGate(t, opts{})
	for _, p := range []string{"/login", "/logout", "/release-notes", "/release-notes.json", "/assets/style.css", "/account", "/admin/users", "/login/totp"} {
		g.do(t, "GET", adminHost, p, nil, navigate()...)
	}
	if g.kuma.count() != 0 {
		t.Fatalf("a gate path reached Kuma: %+v", g.kuma.last())
	}
	rec := g.do(t, "GET", adminHost, "/assets/style.css", nil)
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Type"), "text/css") || rec.Header().Get("X-Upstream") != "" {
		t.Fatalf("/assets/style.css: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	rec = g.do(t, "GET", bolhaHost, "/assets/index-D3kJ8a_x.js", nil)
	if rec.Code != 200 || rec.Header().Get("X-Upstream") != "kuma" {
		t.Fatalf("Kuma asset: %d", rec.Code)
	}
	// goweb's sign-in page links the gate's stylesheet
	rec = g.do(t, "GET", adminHost, "/login?provider=local", nil, navigate()...)
	if !strings.Contains(rec.Body.String(), `href="/assets/style.css`) {
		t.Fatalf("local sign-in page: %d", rec.Code)
	}
}

func TestLogoutPage(t *testing.T) {
	g := newGate(t, opts{})
	ana := g.login(t, "ana")
	rec := g.do(t, "GET", adminHost, "/logout", nil, "Cookie", ana)
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, `<form method="post" action="/logout">`) || !strings.Contains(body, `name="csrf"`) || !strings.Contains(body, "ana") {
		t.Fatalf("GET /logout: %d", rec.Code)
	}
	rec = g.do(t, "POST", adminHost, "/logout", nil, "Cookie", ana, "Sec-Fetch-Site", "same-origin")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /logout: %d", rec.Code)
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		cleared = cleared || (c.Name == "__Host-kuma-gate" && c.MaxAge < 0)
	}
	if !cleared {
		t.Fatal("POST /logout did not clear the session")
	}
	if rec := g.do(t, "POST", adminHost, "/logout", nil, "Cookie", ana, "Sec-Fetch-Site", "cross-site"); rec.Code != 403 {
		t.Fatalf("cross-site POST /logout: %d", rec.Code)
	}
}

func TestCookiesAreStripped(t *testing.T) {
	g := newGate(t, opts{})
	ana := g.login(t, "ana")
	cookie := ana + "; __Host-kuma-gate-csrf=c; __Host-kuma-gate-state=s; kuma-gate-lang=pt; theme=dark; __Host-kuma-gate-pending=p"
	g.do(t, "GET", adminHost, "/dashboard", nil, "Cookie", cookie, "Cookie", "other=1")
	if got := g.kuma.last().Header.Values("Cookie"); len(got) != 1 || got[0] != "theme=dark; other=1" {
		t.Fatalf("Kuma got cookies %q", got)
	}
	g.do(t, "GET", bolhaHost, "/status/bolha", nil, "Cookie", "kuma-gate-lang=pt")
	if got := g.kuma.last().Header.Get("Cookie"); got != "" {
		t.Fatalf("Kuma got cookies %q", got)
	}
	// and Kuma cannot set the gate's cookies
	rec := g.do(t, "GET", bolhaHost, "/status/bolha", nil)
	for _, v := range rec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(v, "__Host-kuma-gate") {
			t.Fatalf("Kuma set %q", v)
		}
	}
	if len(rec.Header().Values("Set-Cookie")) != 1 {
		t.Fatalf("Kuma's own cookie lost: %q", rec.Header().Values("Set-Cookie"))
	}
}

func TestForwardedHeaders(t *testing.T) {
	g := newGate(t, opts{})
	// a client that writes the headers itself, directly (not through nginx)
	g.do(t, "GET", bolhaHost, "/status/bolha", nil, "X-Forwarded-For", "6.6.6.6", "X-Forwarded-Proto", "https",
		"X-Forwarded-Host", "evil.example", "X-Real-IP", "6.6.6.6", "Forwarded", "for=6.6.6.6")
	h := g.kuma.last()
	if h.Header.Get("X-Forwarded-For") != "192.0.2.1" || h.Header.Get("X-Real-IP") != "192.0.2.1" ||
		h.Header.Get("X-Forwarded-Proto") != "http" || h.Header.Get("X-Forwarded-Host") != bolhaHost ||
		h.Header.Get("Forwarded") != "" || h.Host != bolhaHost {
		t.Fatalf("untrusted peer: %v host %s", h.Header, h.Host)
	}
	// through nginx (127.0.0.1): its address for the client and its scheme
	g.do(t, "GET", bolhaHost, "/status/bolha", nil, "RemoteAddr", "127.0.0.1:5555",
		"X-Forwarded-For", "6.6.6.6, 203.0.113.9", "X-Forwarded-Proto", "https")
	h = g.kuma.last()
	if h.Header.Get("X-Forwarded-For") != "203.0.113.9" || h.Header.Get("X-Forwarded-Proto") != "https" {
		t.Fatalf("trusted peer: %v", h.Header)
	}
}

func TestBodyLimits(t *testing.T) {
	g := newGate(t, opts{})
	big := strings.Repeat("x", publicBodyLimit+1)
	if rec := g.do(t, "POST", bolhaHost, "/api/push/abc", strings.NewReader(big)); rec.Code != 413 {
		t.Fatalf("big push: %d", rec.Code)
	}
	if g.kuma.count() != 0 {
		t.Fatal("a too-large body reached Kuma")
	}
	ana := g.login(t, "ana")
	// a status page logo through socket.io long-polling (up to socket.io's 1e6 bytes) passes
	logo := strings.Repeat("x", 1_000_000)
	rec := g.do(t, "POST", adminHost, "/socket.io/?EIO=4&transport=polling&sid=x", strings.NewReader(logo), "Cookie", ana, "Sec-Fetch-Site", "same-origin")
	if rec.Code != 200 {
		t.Fatalf("1 MB socket.io POST: %d", rec.Code)
	}
}

func TestPushTokensNeverLogged(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	g := newGate(t, opts{upstream: "http://127.0.0.1:1"}) // Kuma down: the proxy logs its error
	rec := g.do(t, "GET", bolhaHost, "/api/push/SeCrEtToKeN0001?status=up&msg=OK", nil)
	if rec.Code != 502 {
		t.Fatalf("Kuma down: %d", rec.Code)
	}
	g.do(t, "GET", bolhaHost, "/api/push/..%2fSeCrEtToKeN0002", nil)
	g.do(t, "GET", bolhaHost, "/API/PUSH/SeCrEtToKeN0003/", nil)
	g.do(t, "GET", bolhaHost, "/api/%70ush/SeCrEtToKeN0004", nil)
	out := buf.String()
	if strings.Contains(out, "SeCrEtToKeN") || strings.Contains(out, "msg=OK") {
		t.Fatalf("a push token or query reached the log:\n%s", out)
	}
	if !strings.Contains(out, "upstream:") || !strings.Contains(out, "[redacted]") {
		t.Fatalf("expected redacted log lines:\n%s", out)
	}
	for in, want := range map[string]string{
		"/api/push/abc?x=1":   "/api/push/[redacted]",
		"/API/Push/abc/def":   "/API/Push/[redacted]/def",
		"/api/%70ush/abc":     "/api/%70ush/abc", // refused before any lookup; no token shape
		"/status/bolha?q=abc": "/status/bolha",
	} {
		if got := redactPath(in); got != want {
			t.Errorf("redactPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUpstreamDownIsAPage(t *testing.T) {
	g := newGate(t, opts{upstream: "http://127.0.0.1:1"})
	rec := g.do(t, "GET", bolhaHost, "/status/bolha", nil, navigate()...)
	if rec.Code != 502 || !strings.Contains(rec.Body.String(), "Uptime Kuma did not answer") || strings.Contains(rec.Body.String(), "127.0.0.1") {
		t.Fatalf("Kuma down: %d", rec.Code)
	}
}
