package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBridgeServerRequiresBearerAuthAndRejectsPublicBind(t *testing.T) {
	if _, err := NewBridgeServer("0.0.0.0:9391", "secret", "", "", "", ""); err == nil {
		t.Fatalf("expected NewBridgeServer to reject 0.0.0.0 public bind")
	}

	srv, err := NewBridgeServer("127.0.0.1:0", "bridge-test-token", "", "", "", "")
	if err != nil {
		t.Fatalf("NewBridgeServer: %v", err)
	}
	handler := srv.routes()

	// /_health and /_ready are readable without token.
	for _, p := range []string{"/_health", "/_ready"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s returned %d, want 200", p, rec.Code)
		}
	}

	// Protected routes reject missing or wrong bearer token with 401.
	reqUnauth := httptest.NewRequest(http.MethodGet, "/v1/tunnels", nil)
	recUnauth := httptest.NewRecorder()
	handler.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated GET /v1/tunnels, got %d", recUnauth.Code)
	}

	reqBad := httptest.NewRequest(http.MethodPost, "/v1/tunnels/open", bytes.NewBufferString(`{}`))
	reqBad.Header.Set("Authorization", "Bearer wrong-token")
	recBad := httptest.NewRecorder()
	handler.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong bearer token, got %d", recBad.Code)
	}

	// Valid bearer token accesses /v1/tunnels cleanly.
	reqAuth := httptest.NewRequest(http.MethodGet, "/v1/tunnels", nil)
	reqAuth.Header.Set("Authorization", "Bearer bridge-test-token")
	recAuth := httptest.NewRecorder()
	handler.ServeHTTP(recAuth, reqAuth)
	if recAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 for authenticated GET /v1/tunnels, got %d", recAuth.Code)
	}
	var parsed map[string]any
	if err := json.Unmarshal(recAuth.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("decode /v1/tunnels response: %v", err)
	}
	if okVal, _ := parsed["ok"].(bool); !okVal {
		t.Fatalf("expected ok:true in /v1/tunnels response, got %v", parsed)
	}
}
