package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

const (
	maxEchoBytes = 16 << 20
	maxWSBytes   = 16 << 20
)

type config struct {
	Port        string
	IngressPath string
	FrontHost   string
	FrontPath   string
}

func loadConfig() (config, error) {
	cfg := config{
		Port:        env("PORT", "8080"),
		IngressPath: env("INGRESS_PATH", "/direct"),
		FrontHost:   strings.TrimSpace(os.Getenv("FRONT_HOST")),
		FrontPath:   strings.TrimSpace(os.Getenv("FRONT_PATH")),
	}
	if !strings.HasPrefix(cfg.IngressPath, "/") {
		return config{}, errors.New("INGRESS_PATH must start with /")
	}
	if cfg.FrontHost == "" {
		return config{}, errors.New("FRONT_HOST is required")
	}
	if strings.Contains(cfg.FrontHost, "/") || strings.Contains(cfg.FrontHost, "://") {
		return config{}, errors.New("FRONT_HOST must be a hostname only")
	}
	if cfg.FrontPath == "" || !strings.HasPrefix(cfg.FrontPath, "/") {
		return config{}, errors.New("FRONT_PATH must start with /")
	}
	return cfg, nil
}

func env(k, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return fallback
}

type app struct {
	cfg      config
	upgrader websocket.Upgrader
	dialer   websocket.Dialer
}

func newApp(cfg config) *app {
	return &app{
		cfg: cfg,
		upgrader: websocket.Upgrader{
			ReadBufferSize:    64 << 10,
			WriteBufferSize:   64 << 10,
			EnableCompression: false,
			CheckOrigin:       func(*http.Request) bool { return true },
		},
		dialer: websocket.Dialer{
			HandshakeTimeout: 12 * time.Second,
			EnableCompression: false,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				ServerName: cfg.FrontHost,
			},
			Proxy: http.ProxyFromEnvironment,
		},
	}
}

func (a *app) frontURL() string {
	return "wss://" + a.cfg.FrontHost + a.cfg.FrontPath
}

func jsonReply(w http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "json_error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	w.Header().Set("content-length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (a *app) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonReply(w, http.StatusOK, map[string]any{
		"ok":                  true,
		"service":             "slipnet-parspack-go-hidden-front",
		"build":               "go-hidden-front-r3-v1",
		"directRelayConfigured": true,
		"hiddenBackend":       true,
		"originIpEmbedded":    false,
		"originDomainEmbedded": false,
		"frontConfigured":     true,
		"directRelayMode":     "wss",
		"tlsMin":              "TLSv1.3",
		"now":                 time.Now().UTC().Format(time.RFC3339),
	})
}

func (a *app) checkFront(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	started := time.Now()
	conn, resp, err := a.dialer.DialContext(r.Context(), a.frontURL(), nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		jsonReply(w, http.StatusBadGateway, map[string]any{
			"ok": false,
			"connected": false,
			"error": "front_connect_failed",
			"ms": time.Since(started).Milliseconds(),
		})
		return
	}
	_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	_ = conn.Close()
	jsonReply(w, http.StatusOK, map[string]any{
		"ok": true,
		"connected": true,
		"mode": "wss-hidden-front",
		"ms": time.Since(started).Milliseconds(),
	})
}

func (a *app) echo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	reader := http.MaxBytesReader(w, r.Body, maxEchoBytes)
	defer reader.Close()
	h := sha256.New()
	n, err := io.Copy(h, reader)
	if err != nil {
		http.Error(w, "read_error", http.StatusBadRequest)
		return
	}
	jsonReply(w, http.StatusOK, map[string]any{
		"ok": true,
		"bytes": n,
		"sha256": hex.EncodeToString(h.Sum(nil)),
	})
}

func (a *app) stream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	n := 1 << 20
	if raw := r.URL.Query().Get("bytes"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 8<<20 {
			n = v
		}
	}
	w.Header().Set("content-type", "application/octet-stream")
	w.Header().Set("cache-control", "no-store")
	w.Header().Set("x-probe-total-bytes", strconv.Itoa(n))
	buf := make([]byte, 32<<10)
	for i := range buf {
		buf[i] = 0x53
	}
	remaining := n
	for remaining > 0 {
		chunk := len(buf)
		if remaining < chunk {
			chunk = remaining
		}
		if _, err := w.Write(buf[:chunk]); err != nil {
			return
		}
		remaining -= chunk
	}
}

func (a *app) echoWS(w http.ResponseWriter, r *http.Request) {
	client, err := a.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer client.Close()
	client.SetReadLimit(maxWSBytes)
	for {
		mt, payload, err := client.ReadMessage()
		if err != nil {
			return
		}
		if err := client.WriteMessage(mt, payload); err != nil {
			return
		}
	}
}

func (a *app) relay(w http.ResponseWriter, r *http.Request) {
	upstream, resp, err := a.dialer.DialContext(r.Context(), a.frontURL(), nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	client, err := a.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer client.Close()

	client.SetReadLimit(maxWSBytes)
	upstream.SetReadLimit(maxWSBytes)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 2)
	var once sync.Once

	pump := func(dst, src *websocket.Conn) {
		for {
			mt, payload, err := src.ReadMessage()
			if err != nil {
				errCh <- err
				return
			}
			if err := dst.WriteMessage(mt, payload); err != nil {
				errCh <- err
				return
			}
		}
	}

	go pump(upstream, client)
	go pump(client, upstream)

	select {
	case <-ctx.Done():
	case <-errCh:
	}

	once.Do(func() {
		deadline := time.Now().Add(time.Second)
		_ = client.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), deadline)
		_ = upstream.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), deadline)
	})
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	a := newApp(cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", a.health)
	mux.HandleFunc("/direct-origin-check", a.checkFront)
	mux.HandleFunc("/origin-check", a.checkFront)
	mux.HandleFunc("/echo", a.echo)
	mux.HandleFunc("/stream", a.stream)
	mux.HandleFunc("/ws", a.echoWS)
	mux.HandleFunc(cfg.IngressPath, a.relay)

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	go func() {
		log.Printf("slipnet go hidden-front relay listening on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}
