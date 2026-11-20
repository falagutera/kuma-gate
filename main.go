// kuma-gate is an authenticating reverse proxy in front of Uptime Kuma. Kuma runs with
// "Disable Auth" on and listens only on localhost; kuma-gate is the only way in. People sign
// in with open/gcn/goweb (local accounts with TOTP, Mastodon, OIDC) and only then reach Kuma
// (HTTP and the socket.io websocket). Kuma's public parts (status pages, badges, push) pass
// without a session. See README.md and docs/decisions/0002-kuma-disableauth-behind-the-gate.md.
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gitlab.gutocarvalho.net/open/gcn/goweb/auth"
	"go.yaml.in/yaml/v3"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed assets
var assetFS embed.FS

const envPrefix = "KUMAGATE"

// config holds every setting. They come from KUMAGATE_* environment variables (see
// .env.example) and the YAML file named by KUMAGATE_AUTH_CONFIG (config.example.yaml).
type config struct {
	listen      string          // address to listen on, host:port
	lang        string          // language when the browser asks for neither pt nor en
	family      string          // bolha (yellow) or gcn (red): the look, see VISUAL.md
	upstream    *url.URL        // Uptime Kuma, e.g. http://127.0.0.1:3001
	adminHost   string          // host of KUMAGATE_BASE_URL: the only host where Kuma's admin UI exists
	statusHosts map[string]bool // hosts that serve only Kuma's public paths
	trusted     []netip.Prefix  // proxies whose X-Forwarded-For/-Proto are believed (nginx)
	auth        auth.Config     // sign-in providers (goweb)
	admins      map[string]bool // gate.admins: User.Key() values allowed in
	allowAll    bool            // gate.allow_all_admins: every admin of every provider instead
}

// gateSection is the app's own part of the YAML file (auth.Section reads it, refusing
// unknown keys). Exactly one of the two must be set: an allowlist that is missing or
// misspelled never means "everyone".
type gateSection struct {
	// Admins is the list of people (User.Key(), "<provider-id>:<id>") let through, on top
	// of the admin level.
	Admins []string `yaml:"admins"`
	// AllowAllAdmins lets in every admin of every provider, without a list.
	AllowAllAdmins bool `yaml:"allow_all_admins"`
}

// topLevelKeys are the only keys the YAML file may have.
var topLevelKeys = map[string]bool{"auth": true, "gate": true}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func loadConfig() (config, error) {
	c := config{
		listen: env("KUMAGATE_LISTEN", "127.0.0.1:3003"),
		lang:   env("KUMAGATE_LANG", "en"),
		family: env("KUMAGATE_FAMILY", "gcn"),
	}
	if c.family != "bolha" && c.family != "gcn" {
		return c, fmt.Errorf("KUMAGATE_FAMILY must be bolha or gcn, got %q", c.family)
	}
	if _, _, err := net.SplitHostPort(c.listen); err != nil {
		return c, fmt.Errorf("KUMAGATE_LISTEN must be host:port or :port, got %q", c.listen)
	}
	if _, ok := translations[c.lang]; !ok {
		return c, fmt.Errorf("KUMAGATE_LANG must be pt or en, got %q", c.lang)
	}
	up, err := parseUpstream(env("KUMAGATE_UPSTREAM", "http://127.0.0.1:3001"))
	if err != nil {
		return c, err
	}
	c.upstream = up
	if c.trusted, err = auth.ParseProxies(env("KUMAGATE_TRUSTED_PROXIES", "127.0.0.1,::1")); err != nil {
		return c, fmt.Errorf("KUMAGATE_TRUSTED_PROXIES: a comma-separated list of addresses or CIDRs: %w", err)
	}
	if os.Getenv("KUMAGATE_AUTH_CONFIG") == "" {
		return c, errors.New("KUMAGATE_AUTH_CONFIG is required: the YAML file with the sign-in providers (see config.example.yaml)")
	}
	if os.Getenv("KUMAGATE_AUTH") != "" {
		return c, errors.New("KUMAGATE_AUTH is not used: list the providers in the KUMAGATE_AUTH_CONFIG file")
	}
	if c.auth, err = auth.FromEnv(envPrefix, os.Getenv, env("KUMAGATE_DATA", "/var/lib/kuma-gate")); err != nil {
		return c, err
	}
	base, err := url.Parse(c.auth.BaseURL)
	if err != nil || base.Hostname() == "" || (base.Path != "" && base.Path != "/") || base.RawQuery != "" {
		return c, fmt.Errorf("KUMAGATE_BASE_URL must be the admin host's URL without a path, like https://status.example.org, got %q", c.auth.BaseURL)
	}
	c.adminHost = normHost(base.Host)
	c.statusHosts = map[string]bool{}
	for _, h := range strings.Split(os.Getenv("KUMAGATE_STATUS_HOSTS"), ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		n := normHost(h)
		if n == "" || strings.ContainsAny(h, "/:@ []") {
			return c, fmt.Errorf("KUMAGATE_STATUS_HOSTS: %q is not a host name (no scheme, port or path)", h)
		}
		if n == c.adminHost {
			return c, fmt.Errorf("KUMAGATE_STATUS_HOSTS: %q is the admin host (KUMAGATE_BASE_URL); it already serves the public paths", h)
		}
		c.statusHosts[n] = true
	}
	data, err := auth.ReadConfigFile(os.Getenv("KUMAGATE_AUTH_CONFIG"))
	if err != nil {
		return c, fmt.Errorf("KUMAGATE_AUTH_CONFIG: %w", err)
	}
	if c.admins, c.allowAll, err = parseAdmins(data, c.auth.Providers); err != nil {
		return c, fmt.Errorf("KUMAGATE_AUTH_CONFIG: %w", err)
	}
	if err := shareProxies(c.auth.Providers, c.trusted); err != nil {
		return c, err
	}
	return c, nil
}

// shareProxies gives the local provider the gate's trusted proxies, so its sign-in limits
// count the real client and not nginx (or a container bridge) as one shared address. One
// setting: a different trusted_proxies in the YAML stops the start.
func shareProxies(providers []auth.Provider, trusted []netip.Prefix) error {
	for _, p := range providers {
		l, ok := p.(*auth.Local)
		if !ok {
			continue
		}
		if len(l.TrustedProxies) > 0 && !samePrefixes(l.TrustedProxies, trusted) {
			return fmt.Errorf("KUMAGATE_AUTH_CONFIG: auth.providers.%s.trusted_proxies differs from KUMAGATE_TRUSTED_PROXIES; remove it from the YAML (the gate passes its own to the local accounts)", providerID(p))
		}
		l.TrustedProxies = append([]netip.Prefix(nil), trusted...)
	}
	return nil
}

func samePrefixes(a, b []netip.Prefix) bool {
	set := map[netip.Prefix]bool{}
	for _, p := range a {
		set[p.Masked()] = true
	}
	other := map[netip.Prefix]bool{}
	for _, p := range b {
		if !set[p.Masked()] {
			return false
		}
		other[p.Masked()] = true
	}
	return len(set) == len(other)
}

// parseUpstream checks KUMAGATE_UPSTREAM: an http(s) URL with a host and nothing else, so
// the path the gate decides on is exactly the path Kuma gets.
func parseUpstream(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("KUMAGATE_UPSTREAM must be Kuma's address like http://127.0.0.1:3001 (no path, no user), got %q", s)
	}
	u.Path = ""
	return u, nil
}

// parseAdmins reads the gate section of the YAML file. Each admins entry is
// "<provider-id>:<id>" and the provider must exist. Unknown keys (top level or under gate), a
// missing section or an empty list without allow_all_admins stop the start: a typo must
// never open Kuma to every admin.
func parseAdmins(data []byte, providers []auth.Provider) (map[string]bool, bool, error) {
	var top map[string]any
	if err := yaml.Unmarshal(data, &top); err != nil {
		return nil, false, errors.New("not a YAML mapping")
	}
	for k := range top {
		if !topLevelKeys[k] {
			return nil, false, fmt.Errorf("unknown top-level key %q (only auth and gate)", k)
		}
	}
	var g gateSection
	found, err := auth.Section(data, "gate", &g)
	if err != nil {
		return nil, false, err
	}
	switch {
	case !found || (len(g.Admins) == 0 && !g.AllowAllAdmins):
		return nil, false, errors.New(`gate: list the people allowed in "gate: admins: [<provider-id>:<account>, ...]", or set "gate: allow_all_admins: true" to let in every admin of every provider`)
	case len(g.Admins) > 0 && g.AllowAllAdmins:
		return nil, false, errors.New("gate: set either admins or allow_all_admins, not both")
	case g.AllowAllAdmins:
		return map[string]bool{}, true, nil
	}
	ids := map[string]bool{}
	for _, p := range providers {
		ids[providerID(p)] = true
	}
	out := map[string]bool{}
	for _, a := range g.Admins {
		a = strings.TrimSpace(a)
		src, id, ok := strings.Cut(a, ":")
		if !ok || src == "" || id == "" {
			return nil, false, fmt.Errorf("gate.admins: %q must be <provider-id>:<account>, like local:ana or bolha:ana", a)
		}
		if !ids[src] {
			return nil, false, fmt.Errorf("gate.admins: %q names provider %q, which is not in auth.providers", a, src)
		}
		out[a] = true
	}
	return out, false, nil
}

// providerID is the id goweb gives a provider: its ID, or its kind when empty.
func providerID(p auth.Provider) string {
	switch v := p.(type) {
	case *auth.Local:
		return orKind(v.ID, "local")
	case *auth.Mastodon:
		return orKind(v.ID, "mastodon")
	case *auth.OIDC:
		return orKind(v.ID, "oidc")
	}
	return ""
}

func orKind(id, kind string) string {
	if id != "" {
		return id
	}
	return kind
}

// healthURL is where the healthcheck finds the server. It follows KUMAGATE_LISTEN: a
// wildcard or empty host means "this machine".
func healthURL(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", err
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz", nil
}

func healthcheck() int {
	u, err := healthURL(env("KUMAGATE_LISTEN", "127.0.0.1:3003"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(u) // #nosec G107 -- local health probe, URL built from our own listen address
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

const usage = `usage:
  kuma-gate                 run the gate (settings in KUMAGATE_* variables)
  kuma-gate -healthcheck    probe the local server and exit
  kuma-gate user ...        manage local accounts (the local provider of KUMAGATE_AUTH_CONFIG):
`

// users manages the local accounts with the same settings as the server (it reads the same
// YAML file and variables), so the CLI and the server always use the same accounts file.
func users(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	l, err := localProvider()
	if err == nil {
		err = auth.RunCLI(l.Store, args, stdin, stdout)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func localProvider() (*auth.Local, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	for _, p := range cfg.auth.Providers {
		if l, ok := p.(*auth.Local); ok {
			return l, nil
		}
	}
	return nil, errors.New("there is no local provider (type: local) in KUMAGATE_AUTH_CONFIG")
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "user" {
		os.Exit(users(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	health := flag.Bool("healthcheck", false, "probe the local server and exit (for the container healthcheck)")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage+indent(auth.CLIUsage)) }
	flag.Parse()
	if *health {
		os.Exit(healthcheck())
	}
	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(2)
	}
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		log.Fatal(err)
	}
	s, err := newServer(cfg, tmpl)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Addr:              cfg.listen,
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		// ReadTimeout and WriteTimeout are the budget of the gate's own pages. Proxied
		// requests get their own deadlines (proxy.go, setDeadlines): socket.io long-polling
		// holds a GET for up to ~25 s and a websocket lives for hours. A hijacked
		// (upgraded) connection has its deadlines cleared by net/http, so these never cut
		// a websocket.
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 32 << 10,
		ErrorLog:       log.New(redactingWriter{}, "", log.LstdFlags),
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()
	log.Printf("kuma-gate %s listening on %s; admin host %s, upstream %s, %d status host(s), %d provider(s), admins allowlist: %d, allow all admins: %v",
		version, cfg.listen, cfg.adminHost, cfg.upstream.Redacted(), len(cfg.statusHosts), len(cfg.auth.Providers), len(cfg.admins), cfg.allowAll)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func indent(s string) string {
	return "    " + strings.ReplaceAll(s, "\n", "\n    ") + "\n"
}
