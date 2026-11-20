package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.gutocarvalho.net/open/gcn/kuma-gate/internal/relnotes"
)

// Every response the gate writes itself carries the security headers, errors and its
// stylesheet included (Kuma's own responses keep Kuma's: TestPublicPathsPassOnEveryHost).
func TestSecurityHeadersEverywhere(t *testing.T) {
	g := newGate(t, opts{})
	cases := []struct{ host, path string }{
		{adminHost, "/logout"}, {adminHost, "/release-notes"}, {adminHost, "/release-notes.json"},
		{adminHost, "/healthz"}, {adminHost, "/assets/style.css"}, {adminHost, "/login?provider=local"},
		{adminHost, "/dashboard"}, {bolhaHost, "/dashboard"}, {"evil.example", "/"}, {adminHost, "/status/../x"},
	}
	for _, c := range cases {
		h := g.do(t, "GET", c.host, c.path, nil, navigate()...).Header()
		if h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s%s: no nosniff", c.host, c.path)
		}
		csp := h.Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe-inline") {
			t.Errorf("%s%s: weak CSP %q", c.host, c.path, csp)
		}
		if h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s%s: no Referrer-Policy", c.host, c.path)
		}
	}
	ana := g.login(t, "ana")
	h := g.do(t, "GET", adminHost, "/dashboard", nil, "Cookie", g.login(t, "eve"), "Sec-Fetch-Mode", "navigate").Header()
	if h.Get("Content-Security-Policy") == "" {
		t.Error("403 page without CSP")
	}
	_ = ana
}

// The strict CSP only works if no page has inline scripts, styles or event handlers.
func TestPagesHaveNothingInline(t *testing.T) {
	g := newGate(t, opts{})
	eve := g.login(t, "eve")
	pages := []struct{ host, path, cookie string }{
		{adminHost, "/logout", ""}, {adminHost, "/logout", eve}, {adminHost, "/release-notes", ""},
		{adminHost, "/login?provider=local", ""}, {adminHost, "/login", ""}, {bolhaHost, "/nope", ""},
		{adminHost, "/dashboard", eve},
	}
	for _, p := range pages {
		body := g.do(t, "GET", p.host, p.path, nil, append(navigate(), "Cookie", p.cookie)...).Body.String()
		for _, bad := range []string{"<script", "<style", " style=", " onclick=", " onload="} {
			if strings.Contains(body, bad) {
				t.Errorf("%s has inline %q, which the CSP blocks", p.path, bad)
			}
		}
	}
}

func TestReleaseNotes(t *testing.T) {
	g := newGate(t, opts{})
	if rec := g.do(t, "GET", adminHost, "/release-notes", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), `id="v`+releases[0].Version+`"`) {
		t.Fatalf("/release-notes: %d", rec.Code)
	}
	if rec := g.do(t, "GET", adminHost, "/release-notes.json", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"app": "kuma-gate"`) {
		t.Fatalf("/release-notes.json: %d %s", rec.Code, rec.Body)
	}
	if rec := g.do(t, "GET", bolhaHost, "/release-notes", nil); rec.Code != 404 {
		t.Fatalf("/release-notes on a status host: %d", rec.Code)
	}
}

// Every VERSION needs its CHANGELOG.md entry: the release notes page is built from it.
func TestChangelogHasVersion(t *testing.T) {
	if err := relnotes.Check(changelog, versionFile); err != nil {
		t.Fatal(err)
	}
}

func TestLanguage(t *testing.T) {
	g := newGate(t, opts{})
	if body := g.do(t, "GET", adminHost, "/logout", nil, "Accept-Language", "pt-BR,pt;q=0.9").Body.String(); !strings.Contains(body, `lang="pt"`) || !strings.Contains(body, "Novidades") {
		t.Fatal("Accept-Language pt-BR did not give Portuguese")
	}
	if body := g.do(t, "GET", adminHost, "/logout", nil, "Accept-Language", "de").Body.String(); !strings.Contains(body, `lang="en"`) {
		t.Fatal("unknown language did not fall back to KUMAGATE_LANG")
	}
	rec := g.do(t, "GET", adminHost, "/logout?lang=pt", nil, "Accept-Language", "en")
	if !strings.Contains(rec.Body.String(), `lang="pt"`) {
		t.Fatal("?lang=pt ignored")
	}
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == langCookie {
			cookie = c
		}
	}
	if cookie == nil || cookie.Value != "pt" || !cookie.HttpOnly || !cookie.Secure {
		t.Fatalf("language cookie: %+v", cookie)
	}
	if body := g.do(t, "GET", adminHost, "/logout", nil, "Cookie", langCookie+"=pt", "Accept-Language", "en").Body.String(); !strings.Contains(body, `lang="pt"`) {
		t.Fatal("cookie ignored")
	}
}

func TestTextsInBothLanguages(t *testing.T) {
	for key := range translations["en"] {
		if translations["pt"][key] == "" {
			t.Errorf("%q missing in pt", key)
		}
	}
	for key := range translations["pt"] {
		if translations["en"][key] == "" {
			t.Errorf("%q missing in en", key)
		}
	}
}

// A panic costs one request a 500 and never shows its text.
func TestPanicIsContained(t *testing.T) {
	h := recoverPanics(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("secret detail") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("panic: %d %q", rec.Code, rec.Body.String())
	}
}

// The healthcheck must follow KUMAGATE_LISTEN, whatever form it takes.
func TestHealthURL(t *testing.T) {
	for listen, want := range map[string]string{
		":8080":          "http://127.0.0.1:8080/healthz",
		"0.0.0.0:9000":   "http://127.0.0.1:9000/healthz",
		"[::]:9000":      "http://127.0.0.1:9000/healthz",
		"127.0.0.1:3003": "http://127.0.0.1:3003/healthz",
		"[::1]:7000":     "http://[::1]:7000/healthz",
	} {
		got, err := healthURL(listen)
		if err != nil || got != want {
			t.Errorf("healthURL(%q) = %q, %v; want %q", listen, got, err, want)
		}
	}
	if _, err := healthURL("8080"); err == nil {
		t.Error("a bare port without ':' must be rejected")
	}
}

func TestConfig(t *testing.T) {
	writeConfig(t, opts{upstream: ""}, "https://bolha.example")
	c, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.listen != "127.0.0.1:3003" || c.lang != "en" || c.family != "gcn" || c.upstream.String() != "http://127.0.0.1:3001" ||
		c.adminHost != adminHost || !c.statusHosts[bolhaHost] || !c.statusHosts[jornHost] || len(c.trusted) != 2 ||
		!c.admins["bolha:ana"] || !c.admins["local:guto"] || len(c.auth.Providers) != 2 {
		t.Fatalf("defaults: %+v", c)
	}
	bad := map[string]string{
		"KUMAGATE_LISTEN":          "3003",
		"KUMAGATE_LANG":            "fr",
		"KUMAGATE_FAMILY":          "blue",
		"KUMAGATE_UPSTREAM":        "http://127.0.0.1:3001/kuma",
		"KUMAGATE_STATUS_HOSTS":    "https://status.bolha.us",
		"KUMAGATE_TRUSTED_PROXIES": "nginx",
		"KUMAGATE_AUTH":            "local",
		"KUMAGATE_AUTH_CONFIG":     "",
		"KUMAGATE_SECRET":          "short",
	}
	for k, v := range bad {
		old := os.Getenv(k)
		t.Setenv(k, v)
		if _, err := loadConfig(); err == nil {
			t.Errorf("%s=%q accepted", k, v)
		}
		t.Setenv(k, old)
	}
	t.Setenv("KUMAGATE_STATUS_HOSTS", adminHost)
	if _, err := loadConfig(); err == nil {
		t.Error("the admin host as a status host accepted")
	}
	t.Setenv("KUMAGATE_STATUS_HOSTS", "")
	for _, admins := range []string{"[ana]", "[github:ana]", "[bolha:]"} {
		writeConfig(t, opts{admins: admins}, "https://bolha.example")
		if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "gate.admins") {
			t.Errorf("admins %s: %v", admins, err)
		}
	}
	// a typo in the app's section stops the start too
	path := writeConfig(t, opts{}, "https://bolha.example")
	data, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(data), "admins:", "admin:", 1)), 0o600)
	if _, err := loadConfig(); err == nil {
		t.Error("unknown key under gate accepted")
	}
}

// TestFamily: the look follows KUMAGATE_FAMILY (VISUAL.md): the accent and the "part of" link.
func TestFamily(t *testing.T) {
	for fam, link := range map[string]string{"bolha": "https://bolha.io", "gcn": "https://gutocarvalho.net"} {
		g := newGate(t, opts{})
		g.s.cfg.family = fam
		body := g.do(t, "GET", adminHost, "/logout", nil).Body.String()
		for _, want := range []string{`data-family="` + fam + `"`, `href="` + link + `"`, `class="bubble"`, `class="kicker"`, "<em>"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: page lacks %q", fam, want)
			}
		}
	}
}

// kuma-gate user ... manages the accounts file of the YAML's local provider, the same one
// the server signs in with.
func TestUserCLI(t *testing.T) {
	path := writeConfig(t, opts{}, "https://bolha.example")
	var out, errb strings.Builder
	if code := users([]string{"add", "guto", "admin", "--password-stdin"}, strings.NewReader("a long enough password\n"), &out, &errb); code != 0 {
		t.Fatalf("user add: %d %s", code, errb.String())
	}
	out.Reset()
	if code := users([]string{"list"}, nil, &out, &errb); code != 0 || !strings.Contains(out.String(), "guto") {
		t.Fatalf("user list: %d %q %s", code, out.String(), errb.String())
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), "users.json")); err != nil {
		t.Fatalf("accounts file not where the YAML says: %v", err)
	}
	// then guto signs in with the password, and is sent to set up TOTP (admin level)
	g := newGate(t, opts{})
	if code := users([]string{"add", "guto", "admin", "--password-stdin"}, strings.NewReader("a long enough password\n"), &out, &errb); code != 0 {
		t.Fatal(errb.String())
	}
	rec := g.do(t, "POST", adminHost, "/login", strings.NewReader("name=guto&password=a+long+enough+password&next=%2F"),
		"Content-Type", "application/x-www-form-urlencoded", "Sec-Fetch-Site", "same-origin")
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/login/totp") {
		t.Fatalf("local sign-in: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}
