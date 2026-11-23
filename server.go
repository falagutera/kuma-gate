package main

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"gitlab.gutocarvalho.net/open/gcn/goweb/auth"
	"gitlab.gutocarvalho.net/open/gcn/kuma-gate/internal/relnotes"
)

type server struct {
	cfg       config
	tmpl      *template.Template
	auth      *auth.Auth
	proxy     *httputil.ReverseProxy
	gate      http.Handler    // the gate's own pages (sign-in, account, logout, release notes)
	assets    http.Handler    // the gate's own files under /assets/
	ownAssets map[string]bool // their paths: /assets/style.css...
	wsRecheck time.Duration   // how often an open websocket's session is checked again
	baseOrig  string          // scheme://host[:port] of KUMAGATE_BASE_URL, default port dropped
	badPaths  *logLimiter     // the "400 non-canonical" log lines, at most badPathLogs a minute
}

// badPathLogs: scanners send odd paths by the thousand; the disk of the Kuma host is small.
const badPathLogs = 20

func newServer(cfg config, tmpl *template.Template) (*server, error) {
	s := &server{cfg: cfg, tmpl: tmpl, wsRecheck: 30 * time.Second, ownAssets: map[string]bool{},
		badPaths: &logLimiter{max: badPathLogs, now: time.Now}}
	ac := cfg.auth
	ac.App = "kuma-gate" // cookies: __Host-kuma-gate, -state, -csrf, -pending
	ac.Title, ac.Family, ac.Version = "kuma-gate", cfg.family, version
	ac.Lang = s.language
	ac.OnError = s.renderAuthError
	// Sign-in events go to the log (journald), one line each, never a secret.
	ac.OnEvent = func(r *http.Request, e auth.Event) {
		log.Printf("auth: %s provider=%s source=%s account=%q level=%s roles=%q ip=%s detail=%q",
			e.Kind, e.Provider, e.Source, e.Account, e.Level, e.Roles, clientIP(r, s.cfg.trusted), e.Detail)
	}
	var err error
	if s.auth, err = auth.New(ac); err != nil {
		return nil, err
	}
	s.baseOrig = normOrigin(cfg.auth.BaseURL)
	sub, err := fs.Sub(assetFS, "assets")
	if err != nil {
		return nil, err
	}
	err = fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			s.ownAssets["/assets/"+p] = true
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	s.assets = http.StripPrefix("/assets/", http.FileServerFS(sub))
	s.proxy = s.newProxy()

	mux := http.NewServeMux()
	s.auth.Register(mux) // GET /login, /auth/callback, POST /logout; local: /login/totp, /account*, /admin/users*
	mux.HandleFunc("GET /logout", s.handleLogoutPage)
	mux.HandleFunc("GET /release-notes", s.handleNotes)
	mux.Handle("GET /release-notes.json", relnotes.JSONHandler("kuma-gate", version, releases))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { s.renderError(w, r, http.StatusNotFound) })
	s.gate = securityHeaders(mux)
	return s, nil
}

// gatePaths are answered by the gate itself on the admin host, before Kuma is considered.
// Kuma 2.5.12 has none of them: no such Express route (server/server.js, server/routers/)
// and no such Vue route (src/router.js), whose catch-all only shows NotFound.
func isGatePath(p string) bool {
	switch p {
	case "/login", "/login/totp", "/auth/callback", "/logout", "/account", "/admin/users",
		"/release-notes", "/release-notes.json":
		return true
	}
	return strings.HasPrefix(p, "/account/") || strings.HasPrefix(p, "/admin/users/")
}

func (s *server) routes() http.Handler {
	return recoverPanics(http.HandlerFunc(s.serve))
}

// serve is the whole decision, in order. See policy.go for the public list.
func (s *server) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect || r.Method == http.MethodTrace {
		s.renderError(w, r, http.StatusMethodNotAllowed)
		return
	}
	path, ok := canonical(r)
	if !ok {
		// Only the first segment: the rest of a refused path may be an encoded push token.
		s.badPaths.printf("deny: 400 non-canonical path %q host=%q ip=%s", firstSegment(r.RequestURI), r.Host, clientIP(r, s.cfg.trusted))
		s.renderError(w, r, http.StatusBadRequest)
		return
	}
	// The health check answers on any Host: the probe uses 127.0.0.1:<port>.
	if path == "/healthz" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintln(w, "ok")
		})).ServeHTTP(w, r)
		return
	}
	host := normHost(r.Host)
	admin := host == s.cfg.adminHost
	if !admin && !s.cfg.statusHosts[host] {
		s.renderError(w, r, http.StatusNotFound) // unknown host: nothing at all
		return
	}
	// The gate's own stylesheet: goweb's pages load /assets/style.css. Only these exact
	// files; every other /assets/* is Kuma's (Vite's hashed names, never "style.css").
	if s.ownAssets[path] && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		securityHeaders(s.assets).ServeHTTP(w, r)
		return
	}
	if ok, keepQuery := public(r.Method, path); ok && !isUpgrade(r) {
		if !keepQuery {
			r.URL.RawQuery, r.URL.ForceQuery = "", false // see policy.go: Kuma's cache keys on it
		}
		s.forward(w, r, publicBodyLimit, nil)
		return
	}
	if !admin {
		// Status-only host: never a login page here. A person who opens a panel page
		// (the bookmark, the Kuma link "Manage status page") is sent to the same path on
		// the admin host, where the sign-in is: one OAuth callback, one session. The query
		// is dropped and the host is fixed, so this redirects nowhere else. Anything else
		// (API, socket.io, scripts) still gets a 404.
		if isNavigation(r) && !strings.HasPrefix(path, "/socket.io/") {
			setSecurityHeaders(w.Header())
			http.Redirect(w, r, "https://"+s.cfg.adminHost+path, http.StatusFound)
			return
		}
		s.renderError(w, r, http.StatusNotFound)
		return
	}
	if isGatePath(path) {
		if strings.HasPrefix(path, "/admin/users") {
			// goweb lets any local admin manage accounts; here only allowed people may.
			if u, ok := s.auth.User(r); ok && !s.allowed(u) {
				s.forbidden(w, r, u)
				return
			}
		}
		s.gate.ServeHTTP(w, r)
		return
	}
	s.private(w, r, path)
}

// private is everything of Kuma's that needs a session.
func (s *server) private(w http.ResponseWriter, r *http.Request, path string) {
	u, ok := s.auth.User(r)
	if !ok {
		if isNavigation(r) && !strings.HasPrefix(path, "/socket.io/") {
			setSecurityHeaders(w.Header())
			http.Redirect(w, r, "/login?next="+url.QueryEscape(path), http.StatusFound)
			return
		}
		s.deny(w, r, http.StatusUnauthorized)
		return
	}
	if !s.allowed(u) {
		s.forbidden(w, r, u)
		return
	}
	if needsSameOrigin(r, path) && !s.sameOrigin(r, isUpgrade(r) || strings.HasPrefix(path, "/socket.io/")) {
		log.Printf("deny: 403 cross-origin %s %q account=%s origin=%q sec-fetch-site=%q ip=%s",
			r.Method, redactPath(path), u.Key(), r.Header.Get("Origin"), r.Header.Get("Sec-Fetch-Site"), clientIP(r, s.cfg.trusted))
		s.deny(w, r, http.StatusForbidden)
		return
	}
	s.forward(w, r, adminBodyLimit, &u)
}

// allowed: an admin, and in gate.admins unless gate.allow_all_admins is set. An empty list
// lets nobody in (loadConfig refuses to start that way anyway).
func (s *server) allowed(u auth.User) bool {
	if u.Level < auth.Admin {
		return false
	}
	return s.cfg.allowAll || s.cfg.admins[u.Key()]
}

func (s *server) forbidden(w http.ResponseWriter, r *http.Request, u auth.User) {
	log.Printf("deny: 403 account=%s level=%s not allowed (admin level and gate.admins) %s %q ip=%s",
		u.Key(), u.Level, r.Method, redactPath(r.URL.Path), clientIP(r, s.cfg.trusted))
	if !wantsHTML(r) {
		s.deny(w, r, http.StatusForbidden)
		return
	}
	p := s.newPage(w, r)
	p.Status, p.Account = http.StatusForbidden, u.Name
	p.CSRF = s.auth.CSRFInput(w, r)
	s.render(w, http.StatusForbidden, "error.html", p)
}

// deny answers a refusal: the translated page for a browser, a short text for scripts,
// XHR and socket.io.
func (s *server) deny(w http.ResponseWriter, r *http.Request, status int) {
	if wantsHTML(r) {
		s.renderError(w, r, status)
		return
	}
	setSecurityHeaders(w.Header())
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintln(w, http.StatusText(status))
}

// isNavigation: the browser is loading a page (not XHR, fetch, socket.io or a script).
func isNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if isUpgrade(r) {
		return false
	}
	if m := r.Header.Get("Sec-Fetch-Mode"); m != "" {
		return m == "navigate"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html") && r.Header.Get("X-Requested-With") == ""
}

func wantsHTML(r *http.Request) bool { return isNavigation(r) }

func isUpgrade(r *http.Request) bool {
	return r.Header.Get("Upgrade") != "" || headerHasToken(r.Header, "Connection", "upgrade")
}

func headerHasToken(h http.Header, key, token string) bool {
	for _, v := range h.Values(key) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// needsSameOrigin: requests that change state or open a channel must come from Kuma's own
// pages on the admin host: unsafe methods, upgrades and anything socket.io. SameSite=Lax
// already keeps the session cookie off cross-site requests; this also stops a sibling
// subdomain (same site, other origin) from driving Kuma with someone's session.
func needsSameOrigin(r *http.Request, path string) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return isUpgrade(r) || strings.HasPrefix(path, "/socket.io/") // engine.io claims the whole prefix
	}
	return true
}

// sameOrigin: a present Origin must be the admin host's and a present Sec-Fetch-Site must
// be same-origin. With strict (socket.io and upgrades, Kuma's whole admin channel) one of the
// two must also be there: browsers always send Origin on a websocket handshake and
// Sec-Fetch-Site on socket.io's XHRs, so a request with neither is not Kuma's own page.
func (s *server) sameOrigin(r *http.Request, strict bool) bool {
	o := r.Header.Get("Origin")
	if o != "" && normOrigin(o) != s.baseOrig {
		return false
	}
	site := r.Header.Get("Sec-Fetch-Site")
	if site != "" && site != "same-origin" {
		return false
	}
	return !strict || o != "" || site == "same-origin"
}

// normOrigin is scheme://host[:port] in lower case without the scheme's default port, so
// "https://host:443" and "https://host" compare equal. Anything unparsable is "" (never equal
// to the base, which is validated at start).
func normOrigin(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "\x00invalid"
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return strings.ToLower(u.Scheme) + "://" + host
}

// logLimiter prints at most max lines a minute; the next line after a full minute says how
// many were dropped.
type logLimiter struct {
	mu         sync.Mutex
	max        int
	now        func() time.Time
	start      time.Time
	n, dropped int
}

func (l *logLimiter) printf(format string, args ...any) {
	l.mu.Lock()
	now := l.now()
	if now.Sub(l.start) >= time.Minute {
		if l.dropped > 0 {
			log.Printf("deny: %d similar lines suppressed in the last minute", l.dropped)
		}
		l.start, l.n, l.dropped = now, 0, 0
	}
	if l.n >= l.max {
		l.dropped++
		l.mu.Unlock()
		return
	}
	l.n++
	l.mu.Unlock()
	log.Printf(format, args...)
}

// securityHeaders go on every response the gate itself writes (pages, errors, its CSS).
// Not on Kuma's responses: the strict CSP would break Kuma's Vue app and the inline script
// it injects into status pages (server/model/status_page.js ~206), and X-Robots-Tag would
// hide the public status pages from search engines.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w.Header())
		next.ServeHTTP(w, r)
	})
}

func setSecurityHeaders(h http.Header) {
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; script-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	h.Set("X-Robots-Tag", "noindex, nofollow")
}

// recoverPanics turns a panic in one request into a 500 for that request only, and logs
// the stack (with the path redacted). The visitor never sees the panic text.
func recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				log.Printf("panic: %s %q: %v\n%s", r.Method, redactPath(r.URL.Path), v, debug.Stack())
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// page is what every template gets.
type page struct {
	Lang     string
	Family   string // bolha | gcn: picks the accent and the "part of" link (VISUAL.md)
	T        map[string]string
	Version  string
	Path     string
	Notes    bool
	Releases template.HTML
	Status   int
	Detail   string        // a text key with more about an error
	Account  string        // the signed-in person, on the logout and 403 pages
	Local    bool          // a local account: the logout page offers "sign out everywhere"
	CSRF     template.HTML // the sign-out form's token
}

func (s *server) newPage(w http.ResponseWriter, r *http.Request) page {
	lang := s.language(w, r)
	return page{Lang: lang, Family: s.cfg.family, T: translations[lang], Version: version, Path: r.URL.Path}
}

// handleLogoutPage is GET /logout: a page with the POST button (goweb's POST /logout,
// CSRF-protected). Nothing is injected into Kuma's pages: people come here by URL.
func (s *server) handleLogoutPage(w http.ResponseWriter, r *http.Request) {
	p := s.newPage(w, r)
	if u, ok := s.auth.User(r); ok {
		p.Account = u.Name
		p.Local = u.Provider == "local" // goweb's POST /account/signout-all is for local sessions
		p.CSRF = s.auth.CSRFInput(w, r)
	}
	s.render(w, http.StatusOK, "logout.html", p)
}

func (s *server) handleNotes(w http.ResponseWriter, r *http.Request) {
	p := s.newPage(w, r)
	p.Notes, p.Releases = true, relnotes.HTML(releases)
	s.render(w, http.StatusOK, "notes.html", p)
}

// renderError shows a translated error page. Never put an internal error's text (upstream,
// file paths) on a page: log it and show the status.
func (s *server) renderError(w http.ResponseWriter, r *http.Request, status int) {
	setSecurityHeaders(w.Header())
	p := s.newPage(w, r)
	p.Status = status
	s.render(w, status, "error.html", p)
}

// renderAuthError is goweb's OnError: its error keys become a line on the error page.
func (s *server) renderAuthError(w http.ResponseWriter, r *http.Request, status int, key string) {
	setSecurityHeaders(w.Header())
	p := s.newPage(w, r)
	p.Status = status
	if p.T["auth_"+key] != "" {
		p.Detail = "auth_" + key
	}
	s.render(w, status, "error.html", p)
}

// render executes into a buffer first, so a template error becomes a clean 500 instead of
// half a page.
func (s *server) render(w http.ResponseWriter, status int, name string, data page) {
	setSecurityHeaders(w.Header())
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("template %s: %v", name, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	w.Write(buf.Bytes()) // #nosec G104 -- the client went away; nothing to do
}
