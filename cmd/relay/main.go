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

const buildName = "hidden-origin-go-r1"

type config struct {
	port int

	relayPath        string
	originHost       string
	originPort       int
	originServerName string

	directRelayPath string
	hiddenFrontHost string
	hiddenFrontPath string

	workerDirectRelayPath string
	workerDirectHost      string
	workerDirectPath      string

	workerFixedRelayPath string
	workerFixedHost      string
	workerFixedPath      string
}

func envValue(primary, fallback, def string) string {
	if v := strings.TrimSpace(os.Getenv(primary)); v != "" {
		return v
	}
	if fallback != "" {
		if v := strings.TrimSpace(os.Getenv(fallback)); v != "" {
			return v
		}
	}
	return def
}

func envInt(primary, fallback string, def int) int {
	v := envValue(primary, fallback, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func loadConfig() config {
	return config{
		port: envInt("PORT", "", 3000),

		relayPath:        envValue("RELAY_PATH", "relaypath", "/tunnel"),
		originHost:       envValue("ORIGIN_HOST", "originhost", ""),
		originPort:       envInt("ORIGIN_PORT", "originport", 0),
		originServerName: envValue("ORIGIN_SERVERNAME", "originservername", ""),

		directRelayPath: envValue("DIRECT_RELAY_PATH", "directrelaypath", "/direct"),
		hiddenFrontHost: envValue("HIDDEN_FRONT_HOST", "hiddenfronthost", ""),
		hiddenFrontPath: envValue("HIDDEN_FRONT_PATH", "hiddenfrontpath", ""),

		workerDirectRelayPath: envValue("WORKER_DIRECT_RELAY_PATH", "workerdirectrelaypath", "/pw/6b7a4e1c9d8f2a35f4b20caa7e9d3f6c5a11b7c4"),
		workerDirectHost:      envValue("WORKER_DIRECT_HOST", "workerdirecthost", "ppw-3c19aa324d48.edgecache-628bbe41dc.workers.dev"),
		workerDirectPath:      envValue("WORKER_DIRECT_PATH", "workerdirectpath", "/w/986b32e37335922c2faab7ce2153a8c9f9c6aff9de334f28"),

		workerFixedRelayPath: envValue("WORKER_FIXED_RELAY_PATH", "workerfixedrelaypath", "/pf/4e1b9c72a6d0f5e38b4c1a97d2f6e0ab3c8d5f11"),
		workerFixedHost:      envValue("WORKER_FIXED_HOST", "workerfixedhost", "ppf-56cf1bc939.edgecache-628bbe41dc.workers.dev"),
		workerFixedPath:      envValue("WORKER_FIXED_PATH", "workerfixedpath", "/ppwf/124b41395c04d8a24b794893309742a2f20b5482116d1e32"),
	}
}

type wsStream struct {
	conn    *websocket.Conn
	writeMu sync.Mutex
	readMu  sync.Mutex
	reader  io.Reader
}

func (s *wsStream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	for {
		if s.reader == nil {
			mt, r, err := s.conn.NextReader()
			if err != nil {
				return 0, err
			}
			if mt != websocket.BinaryMessage && mt != websocket.TextMessage {
				continue
			}
			s.reader = r
		}
		n, err := s.reader.Read(p)
		if errors.Is(err, io.EOF) {
			s.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (s *wsStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	w, err := s.conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}
	n, writeErr := w.Write(p)
	closeErr := w.Close()
	if writeErr != nil {
		return n, writeErr
	}
	return n, closeErr
}

func (s *wsStream) Close() error {
	_ = s.conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(time.Second),
	)
	return s.conn.Close()
}

func bridge(client *websocket.Conn, upstream io.ReadWriteCloser) {
	clientStream := &wsStream{conn: client}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, clientStream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientStream, upstream)
		done <- struct{}{}
	}()
	<-done
	_ = clientStream.Close()
	_ = upstream.Close()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
	}
}

func bridgeWebSockets(client, upstream *websocket.Conn) {
	bridge(client, &wsStream{conn: upstream})
}

func verifyWithoutSNI(serverName string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("origin presented no certificate")
		}
		intermediates := x509.NewCertPool()
		for _, cert := range cs.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
			DNSName:       serverName,
			Intermediates: intermediates,
		})
		return err
	}
}

func dialPrimary(cfg config) (net.Conn, error) {
	if cfg.originHost == "" || cfg.originPort < 1 || cfg.originPort > 65535 || cfg.originServerName == "" {
		return nil, errors.New("primary origin not configured")
	}
	raw, err := net.DialTimeout("tcp", net.JoinHostPort(cfg.originHost, strconv.Itoa(cfg.originPort)), 12*time.Second)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyConnection:   verifyWithoutSNI(cfg.originServerName),
		NextProtos:         []string{"http/1.1"},
	})
	_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

func dialWSS(host, path string) (*websocket.Conn, error) {
	if host == "" || path == "" {
		return nil, errors.New("upstream websocket not configured")
	}
	d := websocket.Dialer{
		HandshakeTimeout:  15 * time.Second,
		EnableCompression: false,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: host,
		},
	}
	conn, resp, err := d.Dial("wss://"+host+path, nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	return conn, err
}

func jsonReply(w http.ResponseWriter, status int, v any) {
	body, _ := json.Marshal(v)
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func tcpCheck(host string, port int) (int64, error) {
	if host == "" || port < 1 || port > 65535 {
		return 0, errors.New("not configured")
	}
	start := time.Now()
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		return 0, err
	}
	_ = c.Close()
	return time.Since(start).Milliseconds(), nil
}

func main() {
	cfg := loadConfig()

	upgrader := websocket.Upgrader{
		ReadBufferSize:    64 * 1024,
		WriteBufferSize:   64 * 1024,
		EnableCompression: false,
		CheckOrigin:       func(*http.Request) bool { return true },
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		jsonReply(w, http.StatusOK, map[string]any{
			"ok":                             true,
			"service":                        "slipnet-parspack-go-relay",
			"build":                          buildName,
			"relayConfigured":                cfg.originHost != "" && cfg.originPort > 0 && cfg.originServerName != "",
			"directRelayConfigured":          cfg.hiddenFrontHost != "" && cfg.hiddenFrontPath != "",
			"directOriginShielded":           true,
			"directOriginIpConfigured":       false,
			"directOriginHostnameConfigured": false,
			"originSniSent":                  false,
			"directFrontTlsMin":              "TLSv1.3",
			"workerDirectConfigured":         cfg.workerDirectHost != "" && cfg.workerDirectPath != "",
			"workerFixedConfigured":          cfg.workerFixedHost != "" && cfg.workerFixedPath != "",
			"now":                            time.Now().UTC().Format(time.RFC3339Nano),
		})
	})

	mux.HandleFunc("/origin-check", func(w http.ResponseWriter, r *http.Request) {
		ms, err := tcpCheck(cfg.originHost, cfg.originPort)
		if err != nil {
			jsonReply(w, http.StatusBadGateway, map[string]any{"ok": false, "connected": false, "error": "connect_error"})
			return
		}
		jsonReply(w, http.StatusOK, map[string]any{"ok": true, "connected": true, "ms": ms})
	})

	mux.HandleFunc("/direct-origin-check", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		c, err := dialWSS(cfg.hiddenFrontHost, cfg.hiddenFrontPath)
		if err != nil {
			jsonReply(w, http.StatusBadGateway, map[string]any{"ok": false, "connected": false, "shielded": true, "error": "front_connect_error"})
			return
		}
		_ = c.Close()
		jsonReply(w, http.StatusOK, map[string]any{"ok": true, "connected": true, "shielded": true, "ms": time.Since(start).Milliseconds()})
	})

	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		const max = 16 << 20
		data, err := io.ReadAll(io.LimitReader(r.Body, max+1))
		if err != nil || len(data) > max {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
		jsonReply(w, http.StatusOK, map[string]any{"ok": true, "bytes": len(data)})
	})

	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		n := 1 << 20
		if q := r.URL.Query().Get("bytes"); q != "" {
			if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 8<<20 {
				n = v
			}
		}
		w.Header().Set("content-type", "application/octet-stream")
		w.Header().Set("cache-control", "no-store")
		buf := make([]byte, 32*1024)
		for n > 0 {
			chunk := len(buf)
			if n < chunk {
				chunk = n
			}
			if _, err := w.Write(buf[:chunk]); err != nil {
				return
			}
			n -= chunk
		}
	})

	mux.HandleFunc("/hold", func(w http.ResponseWriter, r *http.Request) {
		seconds := 30
		if q := r.URL.Query().Get("seconds"); q != "" {
			if v, err := strconv.Atoi(q); err == nil && v >= 1 && v <= 120 {
				seconds = v
			}
		}
		flusher, _ := w.(http.Flusher)
		w.Header().Set("content-type", "text/plain")
		for i := 0; i < seconds; i++ {
			_, _ = io.WriteString(w, "tick\n")
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(time.Second)
		}
		_, _ = io.WriteString(w, "done\n")
	})

	handleEchoWS := func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			mt, payload, err := c.ReadMessage()
			if err != nil {
				return
			}
			if err := c.WriteMessage(mt, payload); err != nil {
				return
			}
		}
	}
	mux.HandleFunc("/ws", handleEchoWS)

	mux.HandleFunc(cfg.relayPath, func(w http.ResponseWriter, r *http.Request) {
		upstream, err := dialPrimary(cfg)
		if err != nil {
			http.Error(w, "primary upstream unavailable", http.StatusBadGateway)
			return
		}
		client, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			_ = upstream.Close()
			return
		}
		go bridge(client, upstream)
	})

	mux.HandleFunc(cfg.directRelayPath, func(w http.ResponseWriter, r *http.Request) {
		upstream, err := dialWSS(cfg.hiddenFrontHost, cfg.hiddenFrontPath)
		if err != nil {
			http.Error(w, "shielded upstream unavailable", http.StatusBadGateway)
			return
		}
		client, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			_ = upstream.Close()
			return
		}
		go bridgeWebSockets(client, upstream)
	})

	if cfg.workerDirectRelayPath != cfg.directRelayPath && cfg.workerDirectRelayPath != cfg.relayPath {
		mux.HandleFunc(cfg.workerDirectRelayPath, func(w http.ResponseWriter, r *http.Request) {
			upstream, err := dialWSS(cfg.workerDirectHost, cfg.workerDirectPath)
			if err != nil {
				http.Error(w, "worker upstream unavailable", http.StatusBadGateway)
				return
			}
			client, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				_ = upstream.Close()
				return
			}
			go bridgeWebSockets(client, upstream)
		})
	}

	if cfg.workerFixedRelayPath != cfg.directRelayPath && cfg.workerFixedRelayPath != cfg.relayPath && cfg.workerFixedRelayPath != cfg.workerDirectRelayPath {
		mux.HandleFunc(cfg.workerFixedRelayPath, func(w http.ResponseWriter, r *http.Request) {
			upstream, err := dialWSS(cfg.workerFixedHost, cfg.workerFixedPath)
			if err != nil {
				http.Error(w, "fixed worker upstream unavailable", http.StatusBadGateway)
				return
			}
			client, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				_ = upstream.Close()
				return
			}
			go bridgeWebSockets(client, upstream)
		})
	}

	addr := fmt.Sprintf("0.0.0.0:%d", cfg.port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       75 * time.Second,
	}
	log.Printf("%s listening on %s", buildName, addr)
	log.Fatal(srv.ListenAndServe())
}
