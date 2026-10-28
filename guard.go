package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const defaultTelemetryURL = "https://monitor.cspf.shop/api/v2ray-session/telemetry"

type telemetryResponse struct {
	Known         bool   `json:"known"`
	SessionKnown  *bool  `json:"session_known"`
	Locked        bool   `json:"locked"`
	Reason        string `json:"reason"`
	ActiveSources int    `json:"active_sources"`
}

type sessionMeta struct {
	UUID      string
	Hash      string
	IP        string
	SessionID string
}

type sessionGuard struct {
	enabled      bool
	route        string
	telemetryURL string
	heartbeat    time.Duration
	client       *http.Client
}

func newSessionGuard(route string) *sessionGuard {
	enabled := strings.TrimSpace(envValue("CONCURRENCY_GUARD", "")) != "0"
	url := envValue("SESSION_TELEMETRY_URL", "sessiontelemetryurl")
	if url == "" {
		url = defaultTelemetryURL
	}
	return &sessionGuard{
		enabled:      enabled,
		route:        strings.ToLower(strings.TrimSpace(route)),
		telemetryURL: url,
		heartbeat:    5 * time.Second,
		client:       &http.Client{Timeout: 1800 * time.Millisecond},
	}
}

func normalizeIP(raw string, forwarded bool) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if strings.Contains(value, ",") {
		parts := strings.Split(value, ",")
		clean := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				clean = append(clean, p)
			}
		}
		if len(clean) == 0 {
			return ""
		}
		if forwarded {
			value = clean[len(clean)-1]
		} else {
			value = clean[0]
		}
	}
	if strings.HasPrefix(value, "::ffff:") {
		value = strings.TrimPrefix(value, "::ffff:")
	}
	if i := strings.IndexByte(value, '%'); i >= 0 {
		value = value[:i]
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func sourceIP(r *http.Request, route string) string {
	if r == nil {
		return ""
	}
	h := r.Header
	type candidate struct {
		value     string
		forwarded bool
	}
	var candidates []candidate
	if strings.EqualFold(strings.TrimSpace(route), "arvan") {
		candidates = []candidate{
			{h.Get("ar-real-ip"), false},
			{h.Get("x-client-ip"), false},
			{h.Get("x-real-ip"), false},
			{h.Get("x-forwarded-for"), true},
		}
	} else {
		candidates = []candidate{
			{h.Get("x-real-ip"), false},
			{h.Get("x-forwarded-for"), true},
			{h.Get("x-client-ip"), false},
			{h.Get("ar-real-ip"), false},
		}
	}
	for _, c := range candidates {
		if ip := normalizeIP(c.value, c.forwarded); ip != "" {
			return ip
		}
	}
	host := strings.TrimSpace(r.RemoteAddr)
	if splitHost, _, err := net.SplitHostPort(host); err == nil {
		host = splitHost
	}
	return normalizeIP(host, false)
}

func uuidFromHeader(header []byte) string {
	if len(header) < 17 {
		return ""
	}
	b := header[1:17]
	hexv := hex.EncodeToString(b)
	if len(hexv) != 32 {
		return ""
	}
	return strings.ToLower(fmt.Sprintf(
		"%s-%s-%s-%s-%s",
		hexv[0:8], hexv[8:12], hexv[12:16], hexv[16:20], hexv[20:32],
	))
}

func uuidHash(uuid string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(uuid)))
	return hex.EncodeToString(sum[:])
}

func randomSessionID() (string, error) {
	buf := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func telemetryProof(uuid, hash, ip, route, event string, ts int64, sessionID string) string {
	msg := strings.Join([]string{hash, ip, route, event, fmt.Sprintf("%d", ts), sessionID}, "|")
	mac := hmac.New(sha256.New, []byte(uuid))
	_, _ = mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func (g *sessionGuard) newMeta(r *http.Request, header []byte) (*sessionMeta, string, error) {
	if !g.enabled {
		return nil, "", nil
	}
	ip := sourceIP(r, g.route)
	if ip == "" {
		return nil, "source_ip_unavailable", nil
	}
	uuid := uuidFromHeader(header)
	if uuid == "" {
		return nil, "", fmt.Errorf("invalid_vless_uuid")
	}
	sessionID, err := randomSessionID()
	if err != nil {
		return nil, "", err
	}
	return &sessionMeta{
		UUID:      uuid,
		Hash:      uuidHash(uuid),
		IP:        ip,
		SessionID: sessionID,
	}, "", nil
}

func (g *sessionGuard) emit(meta *sessionMeta, event string) *telemetryResponse {
	if !g.enabled || meta == nil {
		return nil
	}
	ts := time.Now().Unix()
	payload := map[string]any{
		"uuid_hash":  meta.Hash,
		"source_ip":  meta.IP,
		"route":      g.route,
		"event":      event,
		"ts":         ts,
		"session_id": meta.SessionID,
		"proof": telemetryProof(
			meta.UUID,
			meta.Hash,
			meta.IP,
			g.route,
			event,
			ts,
			meta.SessionID,
		),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	req, err := http.NewRequest(http.MethodPost, g.telemetryURL, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("content-type", "application/json")
	res, err := g.client.Do(req)
	if err != nil {
		return nil
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		return nil
	}
	var out telemetryResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, 64*1024)).Decode(&out); err != nil {
		return nil
	}
	return &out
}

func (g *sessionGuard) closeAsync(meta *sessionMeta) {
	if !g.enabled || meta == nil {
		return
	}
	go func() {
		_ = g.emit(meta, "close")
	}()
}
