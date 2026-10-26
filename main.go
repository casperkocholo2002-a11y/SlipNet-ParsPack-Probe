package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	maxPayload = 1 << 20
	maxEcho    = 16 << 20
	maxStream  = 8 << 20
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:    64 << 10,
	WriteBufferSize:   64 << 10,
	EnableCompression: false,
	CheckOrigin:       func(*http.Request) bool { return true },
}

type config struct {
	port string

	relayPath       string
	directRelayPath string

	originHost       string
	originPort       string
	originServerName string

	r3FrontHost string
	r3FrontPath string

	workerDirectRelayPath string
	workerDirectHost      string
	workerDirectPath      string

	workerFixedRelayPath string
	workerFixedHost      string
	workerFixedPath      string
}

func env(primary, fallback, def string) string {
	if v := strings.TrimSpace(os.Getenv(primary)); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv(fallback)); v != "" {
		return v
	}
	return def
}

func loadConfig() config {
	port := env("PORT", "port", "3000")
	return config{
		port: port,

		relayPath:       env("RELAY_PATH", "relaypath", "/tunnel"),
		directRelayPath: env("DIRECT_RELAY_PATH", "directrelaypath", "/direct"),

		originHost:       env("ORIGIN_HOST", "originhost", ""),
		originPort:       env("ORIGIN_PORT", "originport", ""),
		originServerName: env("ORIGIN_SERVERNAME", "originservername", ""),

		r3FrontHost: env("R3_FRONT_HOST", "r3fronthost", ""),
		r3FrontPath: env("R3_FRONT_PATH", "r3frontpath", ""),

		workerDirectRelayPath: env("WORKER_DIRECT_RELAY_PATH", "workerdirectrelaypath", "/pw/6b7a4e1c9d8f2a35f4b20caa7e9d3f6c5a11b7c4"),
		workerDirectHost:      env("WORKER_DIRECT_HOST", "workerdirecthost", "ppw-3c19aa324d48.edgecache-628bbe41dc.workers.dev"),
		workerDirectPath:      env("WORKER_DIRECT_PATH", "workerdirectpath", "/w/986b32e37335922c2faab7ce2153a8c9f9c6aff9de334f28"),

		workerFixedRelayPath: env("WORKER_FIXED_RELAY_PATH", "workerfixedrelaypath", "/pf/4e1b9c72a6d0f5e38b4c1a97d2f6e0ab3c8d5f11"),
		workerFixedHost:      env("WORKER_FIXED_HOST", "workerfixedhost", "ppf-56cf1bc939.edgecache-628bbe41dc.workers.dev"),
		workerFixedPath:      env("WORKER_FIXED_PATH", "workerfixedpath", "/ppwf/124b41395c04d8a24b794893309742a2f20b5482116d1e32"),
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	b, _ := json.Marshal(value)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-SlipNet-Probe", "1")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func clampInt(s string, fallback, min, max int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

func rootsTLSConfigNoSNI(verifyName string) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no peer certificate")
			}
			intermediates := x509.NewCertPool()
			for _, cert := range cs.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
				DNSName:       verifyName,
				Roots:         roots,
				Intermediates: intermediates,
			})
			return err
		},
	}, nil
}

func dialPrimary(c config, timeout time.Duration) (net.Conn, error) {
	if c.originHost == "" || c.originPort == "" || c.originServerName == "" {
		return nil, errors.New("primary origin not configured")
	}
	raw, err := net.DialTimeout("tcp", net.JoinHostPort(c.originHost, c.originPort), timeout)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := rootsTLSConfigNoSNI(c.originServerName)
	if err != nil {
		raw.Close()
		return nil, err
	}
	tc := tls.Client(raw, tlsCfg)
	_ = tc.SetDeadline(time.Now().Add(timeout))
	if err := tc.Handshake(); err != nil {
		tc.Close()
		return nil, err
	}
	_ = tc.SetDeadline(time.Time{})
	return tc, nil
}

func dialWebSocket(host, path string) (*websocket.Conn, *http.Response, error) {
	if host == "" || path == "" {
		return nil, nil, errors.New("websocket target not configured")
	}
	d := websocket.Dialer{
		HandshakeTimeout:  15 * time.Second,
		EnableCompression: false,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: host,
			NextProtos: []string{"http/1.1"},
		},
	}
	conn, resp, err := d.Dial("wss://"+host+path, nil)
	if conn != nil {
		conn.SetReadLimit(maxPayload)
	}
	return conn, resp, err
}

func closeWS(c *websocket.Conn) {
	if c == nil {
		return
	}
	_ = c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	_ = c.Close()
}

func bridgeWSWS(client, upstream *websocket.Conn) {
	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			closeWS(client)
			closeWS(upstream)
		})
	}
	copySide := func(dst, src *websocket.Conn) {
		defer closeAll()
		for {
			mt, data, err := src.ReadMessage()
			if err != nil {
				return
			}
			if mt != websocket.BinaryMessage && mt != websocket.TextMessage {
				continue
			}
			if err := dst.WriteMessage(mt, data); err != nil {
				return
			}
		}
	}
	go copySide(upstream, client)
	copySide(client, upstream)
}

func bridgeWSRaw(client *websocket.Conn, upstream net.Conn) {
	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			closeWS(client)
			_ = upstream.Close()
		})
	}

	go func() {
		defer closeAll()
		for {
			mt, data, err := client.ReadMessage()
			if err != nil {
				return
			}
			if mt != websocket.BinaryMessage && mt != websocket.TextMessage {
				continue
			}
			if _, err := upstream.Write(data); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, 64<<10)
	for {
		n, err := upstream.Read(buf)
		if n > 0 {
			if werr := client.WriteMessage(websocket.BinaryMessage, append([]byte(nil), buf[:n]...)); werr != nil {
				closeAll()
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("primary relay read: %v", err)
			}
			closeAll()
			return
		}
	}
}

func handlePrimary(c config, w http.ResponseWriter, r *http.Request) {
	upstream, err := dialPrimary(c, 15*time.Second)
	if err != nil {
		http.Error(w, "origin unavailable", http.StatusBadGateway)
		return
	}
	client, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		upstream.Close()
		return
	}
	client.SetReadLimit(maxPayload)
	bridgeWSRaw(client, upstream)
}

func handleWSRelay(host, path string, w http.ResponseWriter, r *http.Request) {
	upstream, resp, err := dialWebSocket(host, path)
	if err != nil {
		status := http.StatusBadGateway
		if resp != nil && resp.StatusCode >= 400 {
			status = resp.StatusCode
		}
		http.Error(w, "upstream unavailable", status)
		return
	}
	client, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		closeWS(upstream)
		return
	}
	client.SetReadLimit(maxPayload)
	bridgeWSWS(client, upstream)
}

func handleEchoWS(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer closeWS(c)
	c.SetReadLimit(maxPayload)
	for {
		mt, data, err := c.ReadMessage()
		if err != nil {
			return
		}
		if err := c.WriteMessage(mt, data); err != nil {
			return
		}
	}
}

func main() {
	c := loadConfig()
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":                    true,
			"service":               "slipnet-parspack-go-relay",
			"build":                 "go-r3-hidden-relay-v1",
			"relayConfigured":       c.originHost != "" && c.originPort != "" && c.originServerName != "",
			"directRelayConfigured": c.r3FrontHost != "" && c.r3FrontPath != "",
			"originSniSent":         false,
			"directFrontSniSent":    true,
			"directBackendExposed":  false,
			"directRelayMode":       "wss-front",
			"now":                   time.Now().UTC().Format(time.RFC3339Nano),
		})
	})

	mux.HandleFunc("/origin-check", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		conn, err := dialPrimary(c, 5*time.Second)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": "connect_failed", "ms": time.Since(start).Milliseconds()})
			return
		}
		_ = conn.Close()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "connected": true, "ms": time.Since(start).Milliseconds()})
	})

	mux.HandleFunc("/direct-origin-check", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		conn, _, err := dialWebSocket(c.r3FrontHost, c.r3FrontPath)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": "front_connect_failed", "ms": time.Since(start).Milliseconds()})
			return
		}
		closeWS(conn)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "connected": true, "mode": "wss-front", "backendExposed": false, "ms": time.Since(start).Milliseconds()})
	})

	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		lr := io.LimitReader(r.Body, maxEcho+1)
		data, err := io.ReadAll(lr)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		if len(data) > maxEcho {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "bytes": len(data)})
	})

	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		n := clampInt(r.URL.Query().Get("bytes"), 1<<20, 1, maxStream)
		chunk := clampInt(r.URL.Query().Get("chunk"), 16<<10, 1, 64<<10)
		delay := clampInt(r.URL.Query().Get("delay_ms"), 0, 0, 1000)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Probe-Total-Bytes", strconv.Itoa(n))
		buf := make([]byte, chunk)
		for i := range buf {
			buf[i] = 0x53
		}
		for sent := 0; sent < n; {
			want := chunk
			if n-sent < want {
				want = n - sent
			}
			if _, err := w.Write(buf[:want]); err != nil {
				return
			}
			sent += want
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			if delay > 0 {
				time.Sleep(time.Duration(delay) * time.Millisecond)
			}
		}
	})

	mux.HandleFunc("/hold", func(w http.ResponseWriter, r *http.Request) {
		seconds := clampInt(r.URL.Query().Get("seconds"), 30, 1, 120)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "no-store")
		f, _ := w.(http.Flusher)
		for i := 0; i < seconds; i++ {
			if _, err := fmt.Fprintln(w, "tick"); err != nil {
				return
			}
			if f != nil {
				f.Flush()
			}
			time.Sleep(time.Second)
		}
		_, _ = fmt.Fprintln(w, "done")
	})

	mux.HandleFunc("/ws", handleEchoWS)

	server := &http.Server{
		Addr: "0.0.0.0:" + c.port,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case c.relayPath:
				handlePrimary(c, w, r)
				return
			case c.directRelayPath:
				handleWSRelay(c.r3FrontHost, c.r3FrontPath, w, r)
				return
			case c.workerDirectRelayPath:
				handleWSRelay(c.workerDirectHost, c.workerDirectPath, w, r)
				return
			case c.workerFixedRelayPath:
				handleWSRelay(c.workerFixedHost, c.workerFixedPath, w, r)
				return
			default:
				mux.ServeHTTP(w, r)
			}
		}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	log.Printf("slipnet-parspack-go-relay listening on %s", c.port)
	log.Fatal(server.ListenAndServe())
}
