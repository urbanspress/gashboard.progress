package tests

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func buildBridgeBinary(t *testing.T) string {
	t.Helper()
	binName := "gashboard-bridge-test"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(t.TempDir(), binName)
	cmd := exec.Command("go", "build", "-o", binPath, "../bridge/cmd/gashboard-bridge")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build bridge binary failed: %v\n%s", err, string(out))
	}
	return binPath
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen ephemeral: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func makeKnownHostTestEntry(t *testing.T, host string) (string, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(pub)
	sum := sha256.Sum256(pub)
	fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	return fmt.Sprintf("%s ssh-ed25519 %s integration@vps", host, b64), fp
}

func postBridgeJSON(t *testing.T, url, token string, payload any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("HTTP POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	var parsed map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("Decode response from %s: %v", url, err)
	}
	return resp.StatusCode, parsed
}

func TestBridgeBinaryLoopbackKnownHostsAndTunnelLifecycle(t *testing.T) {
	binPath := buildBridgeBinary(t)

	// 1. Refuse 0.0.0.0 public bind on startup.
	badCmd := exec.Command(binPath, "--listen", "0.0.0.0:9399")
	if out, err := badCmd.CombinedOutput(); err == nil {
		t.Fatalf("expected bridge binary to refuse 0.0.0.0 bind, got output: %s", string(out))
	} else if !strings.Contains(string(out), "GASH-E501") {
		t.Fatalf("expected GASH-E501 diagnostic on public bind refusal, got: %s", string(out))
	}

	// 2. Prepare known_hosts file and dummy loopback DB echo server.
	khLine, fp := makeKnownHostTestEntry(t, "e2e-db.example")
	khFile := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(khFile, []byte(khLine+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile known_hosts: %v", err)
	}

	dbLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen DB echo: %v", err)
	}
	defer dbLn.Close()
	go func() {
		for {
			c, aErr := dbLn.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				msg, _ := bufio.NewReader(conn).ReadString('\n')
				_, _ = conn.Write([]byte("PONG:" + msg))
			}(c)
		}
	}()

	listenAddr := freeLoopbackAddr(t)
	token := "e2e-bridge-secret-token"
	cmd := exec.Command(binPath, "--listen", listenAddr, "--known-hosts", khFile)
	cmd.Env = append(os.Environ(), "GASHBOARD_BRIDGE_TOKEN="+token)
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start bridge binary: %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}()

	baseURL := "http://" + listenAddr
	ready := false
	for i := 0; i < 40; i++ {
		if r, err := http.Get(baseURL + "/_ready"); err == nil {
			_ = r.Body.Close()
			if r.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("bridge did not become ready at %s\nlogs:\n%s", baseURL, outBuf.String())
	}

	// 3. Reject unauthenticated request.
	status, _ := postBridgeJSON(t, baseURL+"/v1/tunnels/open", "", map[string]any{})
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", status)
	}

	// 4. Reject unknown host / wrong fingerprint with 403 GASH-E502.
	status, body := postBridgeJSON(t, baseURL+"/v1/ssh/verify-host", token, map[string]any{
		"host":        "unknown-node.example",
		"port":        22,
		"fingerprint": fp,
	})
	if status != http.StatusForbidden || body["code"] != "GASH-E502" {
		t.Fatalf("expected 403 GASH-E502 for unpinned host, got status=%d body=%v", status, body)
	}

	// 5. Open 8 tunnels over HTTP, forward TCP traffic, reject 9th, and close cleanly.
	var tunnelAddrs []string
	var tunnelIDs []string
	for i := 0; i < 8; i++ {
		st, openBody := postBridgeJSON(t, baseURL+"/v1/tunnels/open", token, map[string]any{
			"node_id":              fmt.Sprintf("vps-%d", i+1),
			"ssh_host":             "e2e-db.example",
			"ssh_port":             22,
			"host_key_fingerprint": fp,
			"engine":               "postgres",
			"local_port":           0,
			"remote_target_addr":   dbLn.Addr().String(),
			"ttl_minutes":          15,
		})
		if st != http.StatusOK || openBody["ok"] != true {
			t.Fatalf("open tunnel #%d failed: status=%d body=%v", i+1, st, openBody)
		}
		tun := openBody["tunnel"].(map[string]any)
		tunnelIDs = append(tunnelIDs, tun["id"].(string))
		tunnelAddrs = append(tunnelAddrs, tun["local_addr"].(string))
	}

	// Verify live TCP data flows over 127.0.0.1 tunnel #1.
	conn, err := net.DialTimeout("tcp", tunnelAddrs[0], 2*time.Second)
	if err != nil {
		t.Fatalf("Dial %s: %v", tunnelAddrs[0], err)
	}
	_, _ = conn.Write([]byte("HELLO_DB\n"))
	reply, err := bufio.NewReader(conn).ReadString('\n')
	_ = conn.Close()
	if err != nil || reply != "PONG:HELLO_DB\n" {
		t.Fatalf("unexpected TCP tunnel echo: %q (err=%v)", reply, err)
	}

	// Verify 9th tunnel returns 429 GASH-E503.
	st9, body9 := postBridgeJSON(t, baseURL+"/v1/tunnels/open", token, map[string]any{
		"node_id":              "vps-9",
		"ssh_host":             "e2e-db.example",
		"ssh_port":             22,
		"host_key_fingerprint": fp,
		"engine":               "redis",
		"remote_target_addr":   dbLn.Addr().String(),
	})
	if st9 != http.StatusTooManyRequests || body9["code"] != "GASH-E503" {
		t.Fatalf("expected 429 GASH-E503 on 9th tunnel, got status=%d body=%v", st9, body9)
	}

	// Close tunnel #1 cleanly.
	stClose, _ := postBridgeJSON(t, baseURL+"/v1/tunnels/close", token, map[string]any{"id": tunnelIDs[0]})
	if stClose != http.StatusOK {
		t.Fatalf("expected 200 on /v1/tunnels/close, got %d", stClose)
	}
	if _, err := net.DialTimeout("tcp", tunnelAddrs[0], 300*time.Millisecond); err == nil {
		t.Fatalf("expected closed tunnel %s to refuse new TCP connections", tunnelAddrs[0])
	}
}
