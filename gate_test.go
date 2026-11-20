package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
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
	{"GET", "/socket.io/?EIO=4&transport=polling"}, {"POST", "/socket.io/?EIO=4&transport=polling&sid=x"},
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
	// a session is no use on a status-only host (and the cookie is __Host- anyway)
	if rec := g.do(t, "GET", bolhaHost, "/dashboard", nil, append(navigate(), "Cookie", ana)...); rec.Code != 404 {
		t.Errorf("session on a status host: %d", rec.Code)
	}
	// the redirect keeps where the person was going
	if rec := g.do(t, "GET", adminHost, "/settings/general", nil, navigate()...); rec.Header().Get("Location") != "/login?next=%2Fsettings%2Fgeneral" {
		t.Errorf("next: %q", rec.Header().Get("Location"))
	}
}

func TestNoAllowlistLetsEveryAdminIn(t *testing.T) {
	g := newGate(t, opts{admins: "[]"})
	if rec := g.do(t, "GET", adminHost, "/dashboard", nil, "Cookie", g.login(t, "bob")); rec.Code != 200 {
		t.Fatalf("bob without an allowlist: %d", rec.Code)
	}
	if rec := g.do(t, "GET", adminHost, "/dashboard", nil, "Cookie", g.login(t, "eve")); rec.Code != 403 {
		t.Fatalf("a viewer without an allowlist: %d", rec.Code)
	}
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
