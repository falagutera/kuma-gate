package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"gitlab.gutocarvalho.net/open/gcn/goweb/auth"
)

const (
	// publicBodyLimit: what an anonymous request may send. Push and the status pages take
	// their data from the URL; Kuma's own JSON parser stops at 100 kB (express.json()
	// default, server/server.js:213).
	publicBodyLimit = 128 << 10
	// adminBodyLimit: Kuma's admin UI sends everything over socket.io, including the
	// status page logo as a data URL (status-page-socket-handler.js:292). Kuma leaves
	// socket.io's maxHttpBufferSize at its default of 1e6 bytes
	// (uptime-kuma-server.js:148), so a long-polling POST is never larger; 2 MiB leaves room.
	// Websocket frames are not bodies: after the upgrade the gate only copies bytes and
	// socket.io enforces its own limit.
	adminBodyLimit = 2 << 20

	// Deadlines of a proxied (non-upgrade) request, instead of the server's 10 s / 30 s
	// meant for the gate's own pages: socket.io long-polling holds a GET for up to its
	// ping interval (25 s) and slow admin calls can take longer.
	proxyReadTimeout  = 60 * time.Second
	proxyWriteTimeout = 120 * time.Second
)

func (s *server) newProxy() *httputil.ReverseProxy {
	tr := &http.Transport{
		Proxy:                 nil, // never an HTTP(S)_PROXY from the environment: Kuma is local
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 90 * time.Second, // above socket.io's long-polling wait
		ExpectContinueTimeout: time.Second,
	}
	return &httputil.ReverseProxy{
		Rewrite:        s.rewrite,
		Transport:      tr,
		ModifyResponse: dropGateSetCookies,
		ErrorHandler:   s.proxyError,
		ErrorLog:       log.New(redactingWriter{}, "proxy: ", log.LstdFlags),
	}
}

// rewrite builds the request Kuma gets. Rewrite (unlike Director) starts from a request
// without Forwarded/X-Forwarded-* and without hop-by-hop headers, so nothing the client
// wrote there survives unless set again here.
func (s *server) rewrite(pr *httputil.ProxyRequest) {
	pr.SetURL(s.cfg.upstream) // the upstream has no path: Kuma gets exactly the decided path
	pr.Out.URL.RawPath = ""
	// Kuma needs the public Host: domain-mapped status pages (server/server.js:264,
	// api-router.js:27) and the websocket Origin check, which compares Origin with Host
	// (uptime-kuma-server.js:175-190).
	pr.Out.Host = pr.In.Host
	ip := clientIP(pr.In, s.cfg.trusted)
	// One address only: with "trust proxy" on, Kuma takes the left-most entry
	// (uptime-kuma-server.js:383-395), so a client-written list must never pass.
	pr.Out.Header.Set("X-Forwarded-For", ip)
	pr.Out.Header.Set("X-Real-IP", ip)
	pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
	pr.Out.Header.Set("X-Forwarded-Proto", forwardedProto(pr.In, s.cfg.trusted))
	stripGateCookies(pr.Out.Header)
}

// forward sends the request to Kuma with its body limit and deadlines. u is the signed-in
// person for private requests (nil for public ones).
func (s *server) forward(w http.ResponseWriter, r *http.Request, limit int64, u *auth.User) {
	if r.ContentLength > limit {
		s.deny(w, r, http.StatusRequestEntityTooLarge)
		return
	}
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = http.MaxBytesReader(w, r.Body, limit)
	}
	rc := http.NewResponseController(w)
	ctx := r.Context()
	if isUpgrade(r) {
		// Only reached with a session (public routes never upgrade). net/http clears the
		// connection's deadlines when the proxy hijacks it, so the websocket is not cut by
		// the server's timeouts. Instead the session is checked again every wsRecheck:
		// when it expires, its local account changes, or the person leaves gate.admins,
		// the context ends and ReverseProxy closes both sides. socket.io reconnects, and
		// the new handshake meets the gate again.
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		go s.watchSession(ctx, cancel, r)
	} else {
		_ = rc.SetReadDeadline(time.Now().Add(proxyReadTimeout))   // #nosec G104 -- not every ResponseWriter supports it
		_ = rc.SetWriteDeadline(time.Now().Add(proxyWriteTimeout)) // #nosec G104 -- idem
	}
	s.proxy.ServeHTTP(w, r.WithContext(ctx))
}

func (s *server) watchSession(ctx context.Context, cancel context.CancelFunc, r *http.Request) {
	t := time.NewTicker(s.wsRecheck)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if u, ok := s.auth.User(r); !ok || !s.allowed(u) {
				log.Printf("websocket closed: the session ended or is no longer allowed ip=%s", clientIP(r, s.cfg.trusted))
				cancel()
				return
			}
		}
	}
}

func (s *server) proxyError(w http.ResponseWriter, r *http.Request, err error) {
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig):
		s.deny(w, r, http.StatusRequestEntityTooLarge)
		return
	case errors.Is(err, context.Canceled):
		return // the client left, or a websocket's session ended
	}
	log.Printf("upstream: %s %q: %s", r.Method, redactPath(r.URL.Path), redactText(err.Error()))
	if wantsHTML(r) {
		s.renderError(w, r, http.StatusBadGateway)
		return
	}
	s.deny(w, r, http.StatusBadGateway)
}

// isGateCookie: the gate's own cookies (goweb's session, sign-in state, CSRF and pending
// TOTP, and the language), which Kuma must never see.
func isGateCookie(name string) bool {
	return name == "__Host-kuma-gate" || strings.HasPrefix(name, "__Host-kuma-gate-") || name == langCookie
}

// stripGateCookies removes the gate's cookies from the Cookie header and keeps the rest
// byte for byte.
func stripGateCookies(h http.Header) {
	var keep []string
	for _, line := range h.Values("Cookie") {
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			name, _, _ := strings.Cut(part, "=")
			if isGateCookie(strings.TrimSpace(name)) {
				continue
			}
			keep = append(keep, part)
		}
	}
	h.Del("Cookie")
	if len(keep) > 0 {
		h.Set("Cookie", strings.Join(keep, "; "))
	}
}

// dropGateSetCookies keeps Kuma from setting or clearing the gate's cookies.
func dropGateSetCookies(resp *http.Response) error {
	vals := resp.Header.Values("Set-Cookie")
	if len(vals) == 0 {
		return nil
	}
	resp.Header.Del("Set-Cookie")
	for _, v := range vals {
		name, _, _ := strings.Cut(v, "=")
		if !isGateCookie(strings.TrimSpace(name)) {
			resp.Header.Add("Set-Cookie", v)
		}
	}
	return nil
}

// clientIP is the address of the person: the connection's address, unless it is a trusted
// proxy (nginx), in which case the right-most X-Forwarded-For entry that isn't one. Without
// trusted proxies the header is ignored: anyone can write it. (Same rule as goweb's.)
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return "unknown"
	}
	peer = peer.Unmap()
	if !isTrusted(peer, trusted) {
		return peer.String()
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		if a = a.Unmap(); !isTrusted(a, trusted) {
			return a.String()
		}
	}
	return peer.String()
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// forwardedProto: what nginx says (http or https) when the peer is a trusted proxy,
// otherwise the connection's own scheme.
func forwardedProto(r *http.Request, trusted []netip.Prefix) string {
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return proto
	}
	if peer, err := netip.ParseAddr(host); err == nil && isTrusted(peer.Unmap(), trusted) {
		if p := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))); p == "http" || p == "https" {
			return p
		}
	}
	return proto
}

var queryInText = regexp.MustCompile(`\?[^\s"']*`)

// redactText cleans a log line that may quote a URL: no push tokens, no query strings.
func redactText(s string) string {
	s = pushPath.ReplaceAllString(s, "${1}[redacted]")
	return queryInText.ReplaceAllString(s, "?[query]")
}

// redactingWriter is the log writer of net/http and the proxy, whose messages may quote a
// request URL. Without w it writes where the standard logger writes.
type redactingWriter struct{ w io.Writer }

func (r redactingWriter) Write(p []byte) (int, error) {
	w := r.w
	if w == nil {
		w = log.Writer()
	}
	if _, err := io.WriteString(w, redactText(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}
