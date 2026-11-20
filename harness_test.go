package main

import (
	"bufio"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	adminHost = "status.gutocarvalho.net"
	bolhaHost = "status.bolha.us"
	jornHost  = "status.jornalismo.social"
)

var allHosts = []string{adminHost, bolhaHost, jornHost}

// hit is one request the fake Kuma received.
type hit struct {
	Method, Path, RawQuery, Host string
	Header                       http.Header
}

// fakeKuma records every request; an Upgrade request becomes an echo tunnel.
type fakeKuma struct {
	mu   sync.Mutex
	hits []hit
	srv  *httptest.Server
}

func newFakeKuma(t *testing.T) *fakeKuma {
	t.Helper()
	k := &fakeKuma{}
	k.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k.mu.Lock()
		k.hits = append(k.hits, hit{r.Method, r.URL.Path, r.URL.RawQuery, r.Host, r.Header.Clone()})
		k.mu.Unlock()
		io.Copy(io.Discard, r.Body)
		if r.URL.Query().Get("sleep") != "" {
			time.Sleep(700 * time.Millisecond) // a long-poll held open by socket.io
		}
		if r.Header.Get("Upgrade") == "websocket" {
			conn, brw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			brw.Flush()
			io.Copy(conn, brw) // echo
			return
		}
		w.Header().Set("X-Upstream", "kuma")
		w.Header().Add("Set-Cookie", "__Host-kuma-gate=forged; Path=/")
		w.Header().Add("Set-Cookie", "kuma=1; Path=/")
		io.WriteString(w, "kuma "+r.URL.Path)
	}))
	t.Cleanup(k.srv.Close)
	return k
}

func (k *fakeKuma) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.hits)
}

func (k *fakeKuma) last() hit {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.hits[len(k.hits)-1]
}

// fakeMastodon: the code is the account; ana and bob are Fundador (admin), eve Protetores (viewer).
func newFakeMastodon(t *testing.T) *httptest.Server {
	t.Helper()
	roles := map[string]string{"ana": "Fundador", "bob": "Fundador", "eve": "Protetores", "guto": "Fundador"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			r.ParseForm()
			json.NewEncoder(w).Encode(map[string]string{"access_token": r.PostForm.Get("code")})
		case "/api/v1/accounts/verify_credentials":
			acct := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			out := map[string]any{"acct": acct, "role": map[string]string{"name": roles[acct]}}
			json.NewEncoder(w).Encode(out)
		case "/oauth/revoke":
			w.WriteHeader(200)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

type opts struct {
	admins   string // the gate.admins YAML list
	gate     string // instead of admins: the whole text after the auth section (gate and more)
	local    string // extra lines for the local provider
	ttl      string
	upstream string // override KUMAGATE_UPSTREAM
}

type gate struct {
	s    *server
	h    http.Handler
	kuma *fakeKuma
	cfg  config
}

// writeConfig sets every variable and writes the YAML file of a typical setup.
func writeConfig(t *testing.T, o opts, mastodon string) string {
	t.Helper()
	dir := t.TempDir()
	if o.admins == "" {
		o.admins = "[bolha:ana, local:guto]"
	}
	if o.ttl == "" {
		o.ttl = "4h"
	}
	yaml := `auth:
  session_ttl: ` + o.ttl + `
  providers:
    - id: local
      type: local
      label: Local account
      users_file: ` + filepath.Join(dir, "users.json") + `
` + o.local + `    - id: bolha
      type: mastodon
      label: bolha.us
      instance: ` + mastodon + `
      client_id_env: KUMAGATE_BOLHA_CLIENT_ID
      client_secret_env: KUMAGATE_BOLHA_CLIENT_SECRET
      roles: {Fundador: admin, Protetores: viewer}
` + o.gate
	if o.gate == "" {
		yaml += "gate:\n  admins: " + o.admins + "\n"
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUMAGATE_AUTH_CONFIG", path)
	t.Setenv("KUMAGATE_AUTH", "")
	t.Setenv("KUMAGATE_BASE_URL", "https://"+adminHost)
	t.Setenv("KUMAGATE_SECRET", strings.Repeat("s", 40))
	t.Setenv("KUMAGATE_AUTH_KEY", strings.Repeat("k", 40))
	t.Setenv("KUMAGATE_BOLHA_CLIENT_ID", "id")
	t.Setenv("KUMAGATE_BOLHA_CLIENT_SECRET", "secret")
	t.Setenv("KUMAGATE_STATUS_HOSTS", bolhaHost+", "+jornHost)
	t.Setenv("KUMAGATE_DATA", dir)
	t.Setenv("KUMAGATE_LISTEN", "")
	t.Setenv("KUMAGATE_LANG", "")
	t.Setenv("KUMAGATE_FAMILY", "")
	t.Setenv("KUMAGATE_TRUSTED_PROXIES", "")
	t.Setenv("KUMAGATE_UPSTREAM", o.upstream)
	return path
}

func newGate(t *testing.T, o opts) *gate {
	t.Helper()
	kuma := newFakeKuma(t)
	if o.upstream == "" {
		o.upstream = kuma.srv.URL
	}
	writeConfig(t, o, newFakeMastodon(t).URL)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	s, err := newServer(cfg, mustTemplates(t))
	if err != nil {
		t.Fatal(err)
	}
	return &gate{s: s, h: s.routes(), kuma: kuma, cfg: cfg}
}

// do sends one request straight to the handler. target is the raw request-target, sent
// as is (no client cleans it). header is name, value pairs.
func (g *gate) do(t *testing.T, method, host, target string, body io.Reader, header ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	req.Host = host
	for i := 0; i+1 < len(header); i += 2 {
		if header[i] == "RemoteAddr" {
			req.RemoteAddr = header[i+1]
			continue
		}
		req.Header.Add(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	g.h.ServeHTTP(rec, req)
	return rec
}

// rawRequest parses a request line exactly as written, for targets httptest.NewRequest
// refuses.
func rawRequest(t *testing.T, line string) *http.Request {
	t.Helper()
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(line + "\r\nHost: " + adminHost + "\r\n\r\n")))
	if err != nil {
		return nil
	}
	req.RemoteAddr = "192.0.2.1:1234"
	return req
}

// login signs in at the fake Mastodon as acct and returns the session cookie header.
func (g *gate) login(t *testing.T, acct string) string {
	t.Helper()
	rec := g.do(t, "GET", adminHost, "/login?provider=bolha", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("login: %d %s", rec.Code, rec.Body)
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	var state string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-kuma-gate-state" {
			state = c.Name + "=" + c.Value
		}
	}
	rec = g.do(t, "GET", adminHost, "/auth/callback?code="+acct+"&state="+url.QueryEscape(u.Query().Get("state")), nil, "Cookie", state)
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-kuma-gate" && c.Value != "" {
			return c.Name + "=" + c.Value
		}
	}
	t.Fatalf("callback for %s gave no session: %d %s", acct, rec.Code, rec.Body)
	return ""
}

func navigate() []string { return []string{"Sec-Fetch-Mode", "navigate", "Accept", "text/html"} }

func mustTemplates(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	return tmpl
}
