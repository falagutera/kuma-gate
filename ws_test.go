package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// liveGate runs the gate on a real listener with very short server timeouts, so a
// websocket that outlives them shows that the upgrade path does not depend on them.
func liveGate(t *testing.T, g *gate) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(g.h)
	srv.Config.ReadTimeout = 300 * time.Millisecond
	srv.Config.WriteTimeout = 300 * time.Millisecond
	srv.Start()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// upgrade sends a websocket handshake and returns the connection and the status line.
func upgrade(t *testing.T, addr, host, path string, header ...string) (net.Conn, *bufio.Reader, string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	req := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
	for i := 0; i+1 < len(header); i += 2 {
		req += header[i] + ": " + header[i+1] + "\r\n"
	}
	if _, err := io.WriteString(conn, req+"\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusSwitchingProtocols {
		io.Copy(io.Discard, res.Body)
	}
	return conn, br, res.Status
}

const wsPath = "/socket.io/?EIO=4&transport=websocket"

func TestWebsocketNeedsSession(t *testing.T) {
	g := newGate(t, opts{})
	addr := liveGate(t, g)
	if _, _, st := upgrade(t, addr, adminHost, wsPath, "Origin", "https://"+adminHost); !strings.HasPrefix(st, "401") {
		t.Errorf("no session: %s", st)
	}
	for _, host := range []string{bolhaHost, jornHost} {
		// not even on a public path: Kuma has no public websocket
		for _, p := range []string{wsPath, "/status/bolha", "/api/push/abc"} {
			if _, _, st := upgrade(t, addr, host, p); !strings.HasPrefix(st, "404") {
				t.Errorf("%s%s: %s", host, p, st)
			}
		}
	}
	ana := g.login(t, "ana")
	if _, _, st := upgrade(t, addr, adminHost, wsPath, "Cookie", ana, "Origin", "https://evil.example"); !strings.HasPrefix(st, "403") {
		t.Errorf("cross-origin websocket: %s", st)
	}
	if _, _, st := upgrade(t, addr, adminHost, wsPath, "Cookie", g.login(t, "bob"), "Origin", "https://"+adminHost); !strings.HasPrefix(st, "403") {
		t.Errorf("not in gate.admins: %s", st)
	}
	if g.kuma.count() != 0 {
		t.Fatalf("a websocket reached Kuma: %+v", g.kuma.last())
	}
}

// With a session the websocket is proxied, outlives the server's Read/WriteTimeout, and
// Kuma sees the public Host (its Origin check compares the two) and no gate cookie.
func TestWebsocketOutlivesServerTimeouts(t *testing.T) {
	g := newGate(t, opts{})
	addr := liveGate(t, g)
	ana := g.login(t, "ana")
	conn, br, st := upgrade(t, addr, adminHost, wsPath, "Cookie", ana+"; theme=dark", "Origin", "https://"+adminHost)
	if !strings.HasPrefix(st, "101") {
		t.Fatalf("handshake: %s", st)
	}
	h := g.kuma.last()
	if h.Host != adminHost || h.Header.Get("Cookie") != "theme=dark" || h.Header.Get("Upgrade") != "websocket" || h.Header.Get("X-Forwarded-For") != "127.0.0.1" {
		t.Fatalf("Kuma got Host %q headers %v", h.Host, h.Header)
	}
	time.Sleep(800 * time.Millisecond) // longer than both server timeouts
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo after the timeouts: %q %v", buf, err)
	}
}

// An open websocket ends when its session does.
func TestWebsocketClosesWhenSessionEnds(t *testing.T) {
	g := newGate(t, opts{ttl: "1s"})
	g.s.wsRecheck = 100 * time.Millisecond
	addr := liveGate(t, g)
	conn, br, st := upgrade(t, addr, adminHost, wsPath, "Cookie", g.login(t, "ana"), "Origin", "https://"+adminHost)
	if !strings.HasPrefix(st, "101") {
		t.Fatalf("handshake: %s", st)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	_, err := br.ReadByte() // Kuma sends nothing; the read ends when the gate closes the tunnel
	if err == nil || time.Since(start) > 4*time.Second {
		t.Fatalf("websocket still open after the session expired: %v after %s", err, time.Since(start))
	}
}

// socket.io starts with HTTP long-polling: a GET held open longer than the server's
// Read/WriteTimeout must still get its answer (proxied requests have their own deadlines).
func TestLongPollingOutlivesServerTimeouts(t *testing.T) {
	g := newGate(t, opts{})
	addr := liveGate(t, g)
	req, _ := http.NewRequest("GET", "http://"+addr+"/socket.io/?EIO=4&transport=polling&sleep=1", nil)
	req.Host = adminHost
	req.Header.Set("Cookie", g.login(t, "ana"))
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || string(body) != "kuma /socket.io/" {
		t.Fatalf("long-poll: %d %q", res.StatusCode, body)
	}
}
