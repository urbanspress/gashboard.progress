package main

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
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

func startRouteTestUDPServer(t *testing.T, answerIP *string, mu *sync.Mutex) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			req := buf[:n]
			qEnd := 12
			for qEnd < n && req[qEnd] != 0 {
				l := int(req[qEnd])
				if qEnd+1+l >= n {
					break
				}
				qEnd += 1 + l
			}
			if qEnd+5 > n {
				continue
			}
			qType := binary.BigEndian.Uint16(req[qEnd+1 : qEnd+3])
			question := req[12 : qEnd+5]

			var resp bytes.Buffer
			var hdr [12]byte
			copy(hdr[0:2], req[0:2])
			binary.BigEndian.PutUint16(hdr[2:4], 0x8180)
			binary.BigEndian.PutUint16(hdr[4:6], 1)
			resp.Write(hdr[:])
			resp.Write(question)

			mu.Lock()
			ipStr := *answerIP
			mu.Unlock()
			parsed := net.ParseIP(ipStr).To4()
			if qType == 1 && parsed != nil {
				out := resp.Bytes()
				binary.BigEndian.PutUint16(out[6:8], 1)
				resp.Write([]byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04})
				resp.Write(parsed)
			}
			_, _ = pc.WriteTo(resp.Bytes(), addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestBridgeDNSAndHTTPSHTTPRoutes(t *testing.T) {
	var ncMu sync.Mutex
	setCalls := 0
	storedEmail := []struct {
		name, typ, addr, mx, ttl string
	}{
		{"@", "MX", "mail.protonmail.ch.", "10", "1800"},
		{"@", "TXT", "v=spf1 include:_spf.protonmail.ch ~all", "", "1800"},
		{"protonmail._domainkey", "CNAME", "dkim.protonmail.ch.", "", "1800"},
	}
	webRecords := []struct {
		name, typ, addr, ttl string
	}{
		{"@", "A", "198.51.100.10", "300"},
		{"www", "CNAME", "example.com.", "300"},
	}

	ncSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		cmd := r.Form.Get("Command")
		ncMu.Lock()
		defer ncMu.Unlock()
		switch cmd {
		case "namecheap.domains.dns.getHosts":
			var hostsXML strings.Builder
			idx := 1
			for _, rec := range storedEmail {
				hostsXML.WriteString(fmt.Sprintf(`<host HostId="%d" Name="%s" Type="%s" Address="%s" MXPref="%s" TTL="%s" />`, idx, rec.name, rec.typ, rec.addr, rec.mx, rec.ttl))
				idx++
			}
			for _, rec := range webRecords {
				hostsXML.WriteString(fmt.Sprintf(`<host HostId="%d" Name="%s" Type="%s" Address="%s" MXPref="10" TTL="%s" />`, idx, rec.name, rec.typ, rec.addr, rec.ttl))
				idx++
			}
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?><ApiResponse Status="OK"><Errors /><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.com" EmailType="CUSTOM">` + hostsXML.String() + `</DomainDNSGetHostsResult></CommandResponse></ApiResponse>`))
		case "namecheap.domains.dns.setHosts":
			setCalls++
			var nextWeb []struct{ name, typ, addr, ttl string }
			for i := 1; i <= 32; i++ {
				hn := r.Form.Get(fmt.Sprintf("HostName%d", i))
				if hn == "" {
					break
				}
				rt := r.Form.Get(fmt.Sprintf("RecordType%d", i))
				ad := r.Form.Get(fmt.Sprintf("Address%d", i))
				tt := r.Form.Get(fmt.Sprintf("TTL%d", i))
				if rt == "A" || rt == "AAAA" || (rt == "CNAME" && hn == "www") {
					nextWeb = append(nextWeb, struct{ name, typ, addr, ttl string }{hn, rt, ad, tt})
				}
			}
			webRecords = nextWeb
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?><ApiResponse Status="OK"><Errors /><CommandResponse Type="namecheap.domains.dns.setHosts"><DomainDNSSetHostsResult Domain="example.com" IsSuccess="true" /></CommandResponse></ApiResponse>`))
		}
	}))
	defer ncSrv.Close()

	var dnsMu sync.Mutex
	dnsAnswer := "198.51.100.10"
	udpResolver := startRouteTestUDPServer(t, &dnsAnswer, &dnsMu)

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"status":"ready"}`))
	}))
	defer tlsSrv.Close()
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsSrv.Certificate().Raw}))

	srv, err := NewBridgeServer("127.0.0.1:0", "bridge-dns-tok", "", "", "", "")
	if err != nil {
		t.Fatalf("NewBridgeServer: %v", err)
	}
	srv.SetNamecheapURL(ncSrv.URL)
	srv.SetDNSResolvers([]string{udpResolver})
	srv.SetHTTPSProbe(tlsSrv.URL+"/_ready", certPEM)
	h := srv.routes()

	call := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer bridge-dns-tok")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	creds := `{"api_user":"alice","api_key":"secret-nc-key","client_ip":"203.0.113.5","sandbox":true}`
	rec := call("/v1/dns/namecheap/plan", fmt.Sprintf(`{"credentials":%s,"domain":"example.com","target_ip":"203.0.113.77","ttl":"300","configure_www":true}`, creds))
	if rec.Code != 200 || setCalls != 0 || !bytes.Contains(rec.Body.Bytes(), []byte(`"preserved_email_count":"2"`)) || !bytes.Contains(rec.Body.Bytes(), []byte(`"preserved_other_count":"1"`)) {
		t.Fatalf("plan failed (%d, setCalls=%d): %s", rec.Code, setCalls, rec.Body.String())
	}

	recApply := call("/v1/dns/namecheap/apply", fmt.Sprintf(`{"credentials":%s,"domain":"example.com","target_ip":"203.0.113.77","ttl":"300","configure_www":true}`, creds))
	if recApply.Code != 200 || setCalls != 1 || bytes.Contains(recApply.Body.Bytes(), []byte("secret-nc-key")) {
		t.Fatalf("apply failed (%d, setCalls=%d): %s", recApply.Code, setCalls, recApply.Body.String())
	}
	var applyBody struct {
		ExistingHosts []any  `json:"existing_hosts"`
		EmailType     string `json:"email_type"`
	}
	if err := json.Unmarshal(recApply.Body.Bytes(), &applyBody); err != nil {
		t.Fatalf("decode apply response: %v", err)
	}

	// Unpropagated DNS must return 422 GASH-E422 when fail_on_unpropagated is true.
	recPropFail := call("/v1/dns/propagation/check", `{"domain":"example.com","expected_ip":"203.0.113.77","edge_proxy":"caddy","fail_on_unpropagated":true}`)
	if recPropFail.Code != 422 || !bytes.Contains(recPropFail.Body.Bytes(), []byte("GASH-E422")) {
		t.Fatalf("expected 422 GASH-E422 before propagation, got %d: %s", recPropFail.Code, recPropFail.Body.String())
	}

	// Switch authoritative UDP mock to cutover IP, verify propagation + HTTPS probe pass.
	dnsMu.Lock()
	dnsAnswer = "203.0.113.77"
	dnsMu.Unlock()
	recPropOK := call("/v1/dns/propagation/check", `{"domain":"example.com","expected_ip":"203.0.113.77","edge_proxy":"caddy","fail_on_unpropagated":true}`)
	if recPropOK.Code != 200 || !bytes.Contains(recPropOK.Body.Bytes(), []byte(`"propagated":true`)) {
		t.Fatalf("expected propagation ok after cutover, got %d: %s", recPropOK.Code, recPropOK.Body.String())
	}

	recHTTPS := call("/v1/https/verify", fmt.Sprintf(`{"domain":"example.com","edge_proxy":"caddy","upstream_ready_url":"http://%s"}`, strings.TrimPrefix(ncSrv.URL, "http://")))
	// ncSrv does not assert path, returns 200; verify tls_verified also ran against default tlsSrv.
	if recHTTPS.Code != 200 || !bytes.Contains(recHTTPS.Body.Bytes(), []byte(`"tls_verified":true`)) {
		t.Fatalf("expected HTTPS verify tls_verified:true, got %d: %s", recHTTPS.Code, recHTTPS.Body.String())
	}

	prevRaw, _ := json.Marshal(applyBody.ExistingHosts)
	recRestore := call("/v1/dns/namecheap/restore", fmt.Sprintf(`{"credentials":%s,"domain":"example.com","email_type":%q,"previous_hosts":%s}`, creds, applyBody.EmailType, prevRaw))
	if recRestore.Code != 200 || setCalls != 2 {
		t.Fatalf("restore failed (%d, setCalls=%d): %s", recRestore.Code, setCalls, recRestore.Body.String())
	}

	// SSRF guard rejects non-Namecheap external override endpoint.
	srv.SetNamecheapURL("https://attacker.example/xml.response")
	recSSRF := call("/v1/dns/namecheap/hosts", fmt.Sprintf(`{"credentials":%s,"domain":"example.com"}`, creds))
	if recSSRF.Code != 403 || !bytes.Contains(recSSRF.Body.Bytes(), []byte("GASH-E501")) {
		t.Fatalf("expected 403 GASH-E501 SSRF block, got %d: %s", recSSRF.Code, recSSRF.Body.String())
	}
}
