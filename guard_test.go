package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeIP(t *testing.T) {
	tests := []struct {
		raw       string
		forwarded bool
		want      string
	}{
		{"1.2.3.4", false, "1.2.3.4"},
		{"::ffff:1.2.3.4", false, "1.2.3.4"},
		{"2001:db8::1", false, "2001:db8::1"},
		{"1.1.1.1, 2.2.2.2", false, "1.1.1.1"},
		{"1.1.1.1, 2.2.2.2", true, "2.2.2.2"},
		{"not-an-ip", false, ""},
	}
	for _, tt := range tests {
		if got := normalizeIP(tt.raw, tt.forwarded); got != tt.want {
			t.Fatalf("normalizeIP(%q,%v)=%q want %q", tt.raw, tt.forwarded, got, tt.want)
		}
	}
}

func TestUUIDFromHeader(t *testing.T) {
	header := make([]byte, 17)
	header[0] = 0
	copy(header[1:], []byte{
		0x12, 0x34, 0x56, 0x78,
		0x12, 0x34,
		0x56, 0x78,
		0x9a, 0xbc,
		0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
	})
	want := "12345678-1234-5678-9abc-def012345678"
	if got := uuidFromHeader(header); got != want {
		t.Fatalf("uuidFromHeader=%q want %q", got, want)
	}
}

func TestSourceIPParsPackOrder(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "http://example.test/tunnel", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Real-IP", "203.0.113.10")
	r.Header.Set("X-Forwarded-For", "198.51.100.1, 198.51.100.2")
	if got := sourceIP(r, "parspack"); got != "203.0.113.10" {
		t.Fatalf("sourceIP=%q", got)
	}

	r.Header.Del("X-Real-IP")
	if got := sourceIP(r, "parspack"); got != "198.51.100.2" {
		t.Fatalf("xff sourceIP=%q", got)
	}
}

func TestTelemetryProof(t *testing.T) {
	uuid := "12345678-1234-5678-9abc-def012345678"
	hash := uuidHash(uuid)
	got := telemetryProof(uuid, hash, "203.0.113.10", "parspack", "open", 1700000000, "00112233445566778899aabb")

	msg := hash + "|203.0.113.10|parspack|open|1700000000|00112233445566778899aabb"
	mac := hmac.New(sha256.New, []byte(uuid))
	_, _ = mac.Write([]byte(msg))
	want := hex.EncodeToString(mac.Sum(nil))
	if got != want {
		t.Fatalf("proof mismatch")
	}
}

func TestTelemetryFallback(t *testing.T) {
	primaryCalls := 0
	fallbackCalls := 0

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryCalls++
		http.Error(w, "unavailable", http.StatusBadGateway)
	}))
	defer primary.Close()

	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalls++
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte("{\"known\":true,\"session_known\":true,\"locked\":false,\"active_sources\":1}"))
	}))
	defer fallback.Close()

	uuid := "12345678-1234-5678-9abc-def012345678"
	g := &sessionGuard{
		enabled:           true,
		route:             "parspack",
		telemetryURL:      primary.URL,
		telemetryFallback: fallback.URL,
		client:            &http.Client{},
	}
	meta := &sessionMeta{
		UUID:      uuid,
		Hash:      uuidHash(uuid),
		IP:        "203.0.113.10",
		SessionID: "00112233445566778899aabb",
	}

	out := g.emit(meta, "open")
	if out == nil || !out.Known || out.ActiveSources != 1 {
		t.Fatalf("fallback response not accepted: %#v", out)
	}
	if primaryCalls != 1 || fallbackCalls != 1 {
		t.Fatalf("unexpected call counts primary=%d fallback=%d", primaryCalls, fallbackCalls)
	}
}
