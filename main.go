package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

const (
	maxEcho   = 16 * 1024 * 1024
	maxStream = 8 * 1024 * 1024
	maxWS     = 1024 * 1024
	buildID   = "go-green-v1-concurrency-guard"
)

type app struct {
	guard    *sessionGuard
	upgrader websocket.Upgrader
	sessions sync.WaitGroup
}

type directConfig struct {
	host       string
	port       int
	servername string
	path       string
}

func envValue(primary, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(primary)); v != "" {
		return v
	}
	if fallback != "" {
		return strings.TrimSpace(os.Getenv(fallback))
	}
	return ""
}

func envInt(primary, fallback string) int {
	v := envValue(primary, fallback)
	n, _ := strconv.Atoi(v)
	return n
}

func relayPath() string {
	if v := envValue("RELAY_PATH", "relaypath"); v != "" {
		return v
	}
	return "/tunnel"
}

func directRelayPath() string {
	if v := envValue("DIRECT_RELAY_PATH", "directrelaypath"); v != "" {
		return v
	}
	return "/direct"
}

func workerDirectRelayPath() string {
	if v := envValue("WORKER_DIRECT_RELAY_PATH", "workerdirectrelaypath"); v != "" {
		return v
	}
	return "/pw/6b7a4e1c9d8f2a35f4b20caa7e9d3f6c5a11b7c4"
}

func workerDirectHost() string {
	if v := envValue("WORKER_DIRECT_HOST", "workerdirecthost"); v != "" {
		return v
	}
	return "ppw-3c19aa324d48.edgecache-628bbe41dc.workers.dev"
}

func workerDirectPath() string {
	if v := envValue("WORKER_DIRECT_PATH", "workerdirectpath"); v != "" {
		return v
	}
	return "/w/986b32e37335922c2faab7ce2153a8c9f9c6aff9de334f28"
}

func workerFixedRelayPath() string {
	if v := envValue("WORKER_FIXED_RELAY_PATH", "workerfixedrelaypath"); v != "" {
		return v
	}
	return "/pf/4e1b9c72a6d0f5e38b4c1a97d2f6e0ab3c8d5f11"
}

func workerFixedHost() string {
	if v := envValue("WORKER_FIXED_HOST", "workerfixedhost"); v != "" {
		return v
	}
	return "ppf-56cf1bc939.edgecache-628bbe41dc.workers.dev"
}

func workerFixedPath() string {
	if v := envValue("WORKER_FIXED_PATH", "workerfixedpath"); v != "" {
		return v
	}
	return "/ppwf/124b41395c04d8a24b794893309742a2f20b5482116d1e32"
}

func normalizeDirectOrigin(value string) string {
	if value == "cdn.cspf.online" {
		return "slipnet.wordpresscsp.ir"
	}
	return value
}

func getDirectConfig() directConfig {
	return directConfig{
		host:       normalizeDirectOrigin(envValue("DIRECT_ORIGIN_HOST", "directoriginhost")),
		port:       envInt("DIRECT_ORIGIN_PORT", "directoriginport"),
		servername: normalizeDirectOrigin(envValue("DIRECT_ORIGIN_SERVERNAME", "directoriginservername")),
		path:       envValue("DIRECT_ORIGIN_PATH", "directoriginpath"),
	}
}

func (d directConfig) valid() bool {
	return d.host != "" && d.servername != "" && d.path != "" && d.port > 0 && d.port <= 65535
}

func (d directConfig) websocketURL() string {
	host := d.servername
	if d.port != 443 {
		host = net.JoinHostPort(d.servername, strconv.Itoa(d.port))
	}
	u := url.URL{Scheme: "wss", Host: host, Path: d.path}
	return u.String()
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "json_error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	w.Header().Set("x-slipnet-probe", "1")
	w.Header().Set("content-length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func clampInt(raw string, fallback, min, max int) int {
	n, err := strconv.Atoi(raw)
	if err != nil {
		n = fallback
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

func tuneTCP(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
}

func manualVerifyCertificate(state tls.ConnectionState, servername string) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("no_peer_certificate")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		DNSName:       servername,
		Intermediates: intermediates,
	}
	_, err := state.PeerCertificates[0].Verify(opts)
	return err
}

func dialPrimaryOrigin() (net.Conn, error) {
	host := envValue("ORIGIN_HOST", "originhost")
	port := envInt("ORIGIN_PORT", "originport")
	servername := envValue("ORIGIN_SERVERNAME", "originservername")
	if host == "" || servername == "" || port < 1 || port > 65535 {
		return nil, errors.New("origin_not_configured")
	}

	dialer := net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	raw, err := dialer.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	tuneTCP(raw)

	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
		VerifyConnection: func(state tls.ConnectionState) error {
			return manualVerifyCertificate(state, servername)
		},
	}
	tlsConn := tls.Client(raw, cfg)
	_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

func (a *app) health(w http.ResponseWriter, r *http.Request) {
	d := getDirectConfig()
	originConfigured := envValue("ORIGIN_HOST", "originhost") != "" &&
		envInt("ORIGIN_PORT", "originport") > 0 &&
		envValue("ORIGIN_SERVERNAME", "originservername") != ""

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                      true,
		"service":                 "slipnet-parspack-ingress-probe",
		"runtime":                 runtime.Version(),
		"relayConfigured":         originConfigured,
		"directRelayConfigured":   d.valid(),
		"originSniSent":           false,
		"directOriginSniSent":     true,
		"originTlsMin":            "TLSv1.3",
		"directRelayMode":         "wss",
		"workerDirectConfigured":  workerDirectHost() != "" && workerDirectPath() != "",
		"workerFixedConfigured":   workerFixedHost() != "" && workerFixedPath() != "",
		"workerRelayMode":         "wss",
		"concurrencyGuardEnabled": a.guard.enabled,
		"concurrencyGuardRoute":   a.guard.route,
		"build":                   buildID,
		"now":                     time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (a *app) originCheck(w http.ResponseWriter, r *http.Request) {
	host := envValue("ORIGIN_HOST", "originhost")
	port := envInt("ORIGIN_PORT", "originport")
	if host == "" || port < 1 || port > 65535 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "origin_check_not_configured"})
		return
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok": false, "connected": false, "error": "connect_error", "ms": time.Since(start).Milliseconds(),
		})
		return
	}
	defer conn.Close()
	tuneTCP(conn)
	_ = conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	banner := ""
	if n > 0 {
		banner = printableASCII(buf[:n])
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "connected": true, "ms": time.Since(start).Milliseconds(), "banner": banner,
	})
}

func printableASCII(in []byte) string {
	var b strings.Builder
	for _, c := range in {
		if c == '\r' || c == '\n' || (c >= 0x20 && c <= 0x7e) {
			b.WriteByte(c)
		}
		if b.Len() >= 160 {
			break
		}
	}
	return b.String()
}

func (a *app) directOriginCheck(w http.ResponseWriter, r *http.Request) {
	d := getDirectConfig()
	if !d.valid() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "direct_origin_check_not_configured"})
		return
	}
	start := time.Now()
	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second, EnableCompression: false}
	conn, resp, err := dialer.Dial(d.websocketURL(), nil)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok": false, "connected": false, "error": "wss_connect_error", "ms": time.Since(start).Milliseconds(),
		})
		return
	}
	_ = conn.Close()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "connected": true, "mode": "wss", "ms": time.Since(start).Milliseconds(),
	})
}

func (a *app) echoHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r.Body, maxEcho+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "read_error"})
		return
	}
	if n > maxEcho {
		w.Header().Set("connection", "close")
		w.Header().Set("x-slipnet-probe", "1")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "bytes": n, "sha256": hex.EncodeToString(h.Sum(nil)),
	})
}

func (a *app) streamHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	total := clampInt(q.Get("bytes"), 1024*1024, 1, maxStream)
	chunkSize := clampInt(q.Get("chunk"), 16*1024, 1, 64*1024)
	delayMS := clampInt(q.Get("delay_ms"), 0, 0, 1000)
	w.Header().Set("content-type", "application/octet-stream")
	w.Header().Set("cache-control", "no-store")
	w.Header().Set("x-slipnet-probe", "1")
	w.Header().Set("x-probe-total-bytes", strconv.Itoa(total))
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	chunk := bytes.Repeat([]byte{0x53}, chunkSize)
	for sent := 0; sent < total; {
		n := chunkSize
		if total-sent < n {
			n = total - sent
		}
		if _, err := w.Write(chunk[:n]); err != nil {
			return
		}
		sent += n
		if flusher != nil {
			flusher.Flush()
		}
		if delayMS > 0 {
			time.Sleep(time.Duration(delayMS) * time.Millisecond)
		}
	}
}

func (a *app) holdHTTP(w http.ResponseWriter, r *http.Request) {
	seconds := clampInt(r.URL.Query().Get("seconds"), 30, 1, 120)
	w.Header().Set("content-type", "text/plain")
	w.Header().Set("cache-control", "no-store")
	w.Header().Set("x-slipnet-probe", "1")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for i := 0; i < seconds; i++ {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			_, _ = io.WriteString(w, "tick\n")
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
	_, _ = io.WriteString(w, "done\n")
}

func (a *app) upgrade(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	conn, err := a.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(maxWS)
	return conn, nil
}

func readInitialPayload(ws *websocket.Conn, needed int, timeout time.Duration) ([]byte, error) {
	_ = ws.SetReadDeadline(time.Now().Add(timeout))
	defer ws.SetReadDeadline(time.Time{})
	var out []byte
	for len(out) < needed {
		mt, reader, err := ws.NextReader()
		if err != nil {
			return nil, err
		}
		if mt != websocket.BinaryMessage && mt != websocket.TextMessage {
			continue
		}
		part, err := io.ReadAll(io.LimitReader(reader, maxWS+1))
		if err != nil {
			return nil, err
		}
		if len(part) > maxWS || len(out)+len(part) > maxWS {
			return nil, errors.New("initial_payload_too_large")
		}
		out = append(out, part...)
	}
	return out, nil
}

func wsToConn(ws *websocket.Conn, dst net.Conn) error {
	for {
		mt, reader, err := ws.NextReader()
		if err != nil {
			return err
		}
		if mt != websocket.BinaryMessage && mt != websocket.TextMessage {
			continue
		}
		if _, err := io.Copy(dst, reader); err != nil {
			return err
		}
	}
}

func connToWS(src net.Conn, ws *websocket.Conn) error {
	buf := make([]byte, 64*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			_ = ws.SetWriteDeadline(time.Now().Add(15 * time.Second))
			if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			return err
		}
	}
}

func proxyRaw(ws *websocket.Conn, origin net.Conn) {
	errc := make(chan error, 2)
	go func() { errc <- wsToConn(ws, origin) }()
	go func() { errc <- connToWS(origin, ws) }()
	<-errc
}

func copyWSMessages(dst, src *websocket.Conn) error {
	for {
		mt, reader, err := src.NextReader()
		if err != nil {
			return err
		}
		if mt != websocket.BinaryMessage && mt != websocket.TextMessage {
			continue
		}
		_ = dst.SetWriteDeadline(time.Now().Add(15 * time.Second))
		writer, err := dst.NextWriter(mt)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(writer, reader)
		closeErr := writer.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
}

func proxyWebSockets(a, b *websocket.Conn) {
	errc := make(chan error, 2)
	go func() { errc <- copyWSMessages(b, a) }()
	go func() { errc <- copyWSMessages(a, b) }()
	<-errc
}

func (a *app) echoWS(w http.ResponseWriter, r *http.Request) {
	ws, err := a.upgrade(w, r)
	if err != nil {
		return
	}
	a.sessions.Add(1)
	defer a.sessions.Done()
	defer ws.Close()
	for {
		mt, data, err := ws.ReadMessage()
		if err != nil {
			return
		}
		_ = ws.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if err := ws.WriteMessage(mt, data); err != nil {
			return
		}
	}
}

func (a *app) primaryRelayWS(w http.ResponseWriter, r *http.Request) {
	origin, err := dialPrimaryOrigin()
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	ws, err := a.upgrade(w, r)
	if err != nil {
		_ = origin.Close()
		return
	}

	a.sessions.Add(1)
	defer a.sessions.Done()
	defer ws.Close()
	defer origin.Close()

	var meta *sessionMeta
	if a.guard.enabled {
		ip := sourceIP(r, a.guard.route)
		if ip != "" {
			initial, err := readInitialPayload(ws, 17, 5*time.Second)
			if err != nil {
				return
			}
			meta, _, err = a.guard.newMeta(r, initial[:17])
			if err != nil {
				return
			}
			if meta != nil {
				opened := a.guard.emit(meta, "open")
				if opened != nil && opened.Locked {
					return
				}
			}
			if _, err := origin.Write(initial); err != nil {
				a.guard.closeAsync(meta)
				return
			}
		}
	}
	if meta != nil {
		defer a.guard.closeAsync(meta)
		stopHB := make(chan struct{})
		var once sync.Once
		defer once.Do(func() { close(stopHB) })
		go func() {
			ticker := time.NewTicker(a.guard.heartbeat)
			defer ticker.Stop()
			for {
				select {
				case <-stopHB:
					return
				case <-ticker.C:
					state := a.guard.emit(meta, "heartbeat")
					if state != nil && state.Known && state.SessionKnown != nil && !*state.SessionKnown {
						state = a.guard.emit(meta, "open")
					}
					if state != nil && state.Locked {
						once.Do(func() { close(stopHB) })
						_ = ws.Close()
						_ = origin.Close()
						return
					}
				}
			}
		}()
	}
	proxyRaw(ws, origin)
}

func dialBackendWebSocket(target string) (*websocket.Conn, error) {
	dialer := websocket.Dialer{
		HandshakeTimeout:  15 * time.Second,
		EnableCompression: false,
		NetDialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	conn, resp, err := dialer.Dial(target, nil)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(maxWS)
	return conn, nil
}

func (a *app) proxyToBackendWS(w http.ResponseWriter, r *http.Request, target string) {
	backend, err := dialBackendWebSocket(target)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	client, err := a.upgrade(w, r)
	if err != nil {
		_ = backend.Close()
		return
	}
	a.sessions.Add(1)
	defer a.sessions.Done()
	defer client.Close()
	defer backend.Close()
	proxyWebSockets(client, backend)
}

func (a *app) directRelayWS(w http.ResponseWriter, r *http.Request) {
	d := getDirectConfig()
	if !d.valid() {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	a.proxyToBackendWS(w, r, d.websocketURL())
}

func workerURL(host, path string) string {
	u := url.URL{Scheme: "wss", Host: host, Path: path}
	return u.String()
}

func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/health":
		a.health(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/origin-check":
		a.originCheck(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/direct-origin-check":
		a.directOriginCheck(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/echo":
		a.echoHTTP(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/stream":
		a.streamHTTP(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/hold":
		a.holdHTTP(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/ws":
		a.echoWS(w, r)
	case r.Method == http.MethodGet && r.URL.Path == relayPath():
		a.primaryRelayWS(w, r)
	case r.Method == http.MethodGet && r.URL.Path == directRelayPath():
		a.directRelayWS(w, r)
	case r.Method == http.MethodGet && r.URL.Path == workerDirectRelayPath():
		a.proxyToBackendWS(w, r, workerURL(workerDirectHost(), workerDirectPath()))
	case r.Method == http.MethodGet && r.URL.Path == workerFixedRelayPath():
		a.proxyToBackendWS(w, r, workerURL(workerFixedHost(), workerFixedPath()))
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "not_found"})
	}
}

func main() {
	port := envInt("PORT", "")
	if port <= 0 || port > 65535 {
		port = 8080
	}
	a := &app{
		guard: newSessionGuard("parspack"),
		upgrader: websocket.Upgrader{
			ReadBufferSize:    64 * 1024,
			WriteBufferSize:   64 * 1024,
			EnableCompression: false,
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
	}

	srv := &http.Server{
		Addr:              ":" + strconv.Itoa(port),
		Handler:           a,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errc := make(chan error, 1)
	go func() {
		log.Printf("slipnet-parspack-go listening on %d build=%s", port, buildID)
		errc <- srv.ListenAndServe()
	}()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigc:
		log.Printf("shutdown signal=%s", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = srv.Shutdown(ctx)
		cancel()

		drained := make(chan struct{})
		go func() {
			a.sessions.Wait()
			close(drained)
		}()
		select {
		case <-drained:
			log.Printf("websocket sessions drained")
		case <-time.After(25 * time.Second):
			log.Printf("websocket drain deadline reached")
		}
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}
}
