package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
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

func TestBridgeDBInspectorHTTPRoutes(t *testing.T) {
	root := t.TempDir()
	dbFile := filepath.Join(root, "app.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbFile))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE orders (id INTEGER PRIMARY KEY, total TEXT NOT NULL); INSERT INTO orders (id, total) VALUES (9007199254740993, '98765432109876543210.4321');`)
	_ = db.Close()
	if err != nil {
		t.Fatalf("seed db: %v", err)
	}

	srv, err := NewBridgeServer("127.0.0.1:0", "bridge-db-tok", "", "", "", "")
	if err != nil {
		t.Fatalf("NewBridgeServer: %v", err)
	}
	srv.SetSQLiteRoot(root)
	h := srv.routes()

	call := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer bridge-db-tok")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := call("/v1/db/schema", `{"engine":"sqlite","sqlite_path":"../../outside.db"}`); rec.Code != 403 {
		t.Fatalf("expected 403 GRAB-E401 traversal block, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call("/v1/db/rows", `{"target":{"engine":"sqlite","sqlite_path":"app.db"},"table":"orders","page":"1","limit":"150"}`); rec.Code != 422 {
		t.Fatalf("expected 422 for limit>100, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call("/v1/db/query", `{"target":{"engine":"sqlite","sqlite_path":"app.db"},"sql":"DELETE FROM orders"}`); rec.Code != 403 {
		t.Fatalf("expected 403 for mutation in read-only query, got %d: %s", rec.Code, rec.Body.String())
	}
	rec := call("/v1/db/rows", `{"target":{"engine":"sqlite","sqlite_path":"app.db"},"table":"orders","page":"1","limit":"25"}`)
	if rec.Code != 200 || !bytes.Contains(rec.Body.Bytes(), []byte("98765432109876543210.4321")) {
		t.Fatalf("unexpected /v1/db/rows (%d): %s", rec.Code, rec.Body.String())
	}
}
