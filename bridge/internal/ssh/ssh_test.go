package ssh

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func makeTestEd25519KnownHostsLine(t *testing.T, host string) (string, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(pub)
	fp, err := ComputeKeyFingerprint(b64)
	if err != nil {
		t.Fatalf("ComputeKeyFingerprint: %v", err)
	}
	return fmt.Sprintf("%s ssh-ed25519 %s test@vps", host, b64), fp
}

func TestValidateLoopbackBindRejectsPublicAddresses(t *testing.T) {
	bad := []string{
		"",
		"0.0.0.0:9391",
		":::9391",
		"*:9391",
		"192.168.1.50:9391",
		"10.0.0.5:9391",
	}
	for _, addr := range bad {
		if _, err := ValidateLoopbackBind(addr); err == nil {
			t.Fatalf("expected error for non-loopback address %q", addr)
		} else {
			var be *BridgeError
			if !errors.As(err, &be) || be.Code != ErrLoopbackRequired {
				t.Fatalf("expected %s for %q, got %v", ErrLoopbackRequired, addr, err)
			}
		}
	}

	good := []string{"127.0.0.1:9391", "localhost:9391", "[::1]:9391"}
	for _, addr := range good {
		if _, err := ValidateLoopbackBind(addr); err != nil {
			t.Fatalf("unexpected error for valid loopback address %q: %v", addr, err)
		}
	}
}

func TestKnownHostsVerifierStrictPinning(t *testing.T) {
	line, fp := makeTestEd25519KnownHostsLine(t, "prod-vps.example")
	_, wrongFP := makeTestEd25519KnownHostsLine(t, "other.example")

	ver, err := NewKnownHostsVerifier([]string{line})
	if err != nil {
		t.Fatalf("NewKnownHostsVerifier: %v", err)
	}

	gotFP, err := ver.VerifyFingerprint("prod-vps.example", 22, fp)
	if err != nil || gotFP != fp {
		t.Fatalf("expected pinned host key verification to succeed, got fp=%q err=%v", gotFP, err)
	}

	if _, err := ver.VerifyFingerprint("unknown-vps.example", 22, fp); err == nil {
		t.Fatalf("expected unknown host to be rejected")
	} else {
		var be *BridgeError
		if !errors.As(err, &be) || be.Code != ErrHostKeyRejected {
			t.Fatalf("expected %s, got %v", ErrHostKeyRejected, err)
		}
	}

	if _, err := ver.VerifyFingerprint("prod-vps.example", 22, wrongFP); err == nil {
		t.Fatalf("expected mismatched host key to be rejected")
	} else {
		var be *BridgeError
		if !errors.As(err, &be) || be.Code != ErrHostKeyRejected {
			t.Fatalf("expected %s, got %v", ErrHostKeyRejected, err)
		}
	}
}

func TestTunnelManagerLoopbackForwardingLimitAndCleanup(t *testing.T) {
	line, fp := makeTestEd25519KnownHostsLine(t, "db-vps.example")
	ver, err := NewKnownHostsVerifier([]string{line})
	if err != nil {
		t.Fatalf("NewKnownHostsVerifier: %v", err)
	}

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen echo: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, aErr := echoLn.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				msg, _ := r.ReadString('\n')
				_, _ = conn.Write([]byte("DB_OK:" + msg))
			}(c)
		}
	}()

	mgr := NewTunnelManager(ver)
	defer mgr.CloseAll()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if _, err := mgr.OpenTunnel(ctx, TunnelConfig{
		NodeID:             "node-bad",
		SSHHost:            "rogue.example",
		SSHPort:            22,
		HostKeyFingerprint: fp,
		Engine:             "postgres",
		RemoteTargetAddr:   echoLn.Addr().String(),
	}); err == nil {
		t.Fatalf("expected tunnel open to reject unpinned SSH host")
	}

	var opened []TunnelRecord
	for i := 0; i < MaxConcurrentTunnels; i++ {
		rec, oErr := mgr.OpenTunnel(ctx, TunnelConfig{
			NodeID:             fmt.Sprintf("node-%d", i+1),
			SSHHost:            "db-vps.example",
			SSHPort:            22,
			HostKeyFingerprint: fp,
			Engine:             "postgres",
			RequestedLocalPort: 0,
			RemoteTargetAddr:   echoLn.Addr().String(),
			TTLMinutes:         10,
		})
		if oErr != nil {
			t.Fatalf("OpenTunnel #%d failed: %v", i+1, oErr)
		}
		if rec.LocalHost != "127.0.0.1" || !strings.HasPrefix(rec.LocalAddr, "127.0.0.1:") {
			t.Fatalf("tunnel #%d bound non-loopback address %q", i+1, rec.LocalAddr)
		}
		opened = append(opened, rec)
	}

	conn, err := net.DialTimeout("tcp", opened[0].LocalAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial loopback tunnel %s: %v", opened[0].LocalAddr, err)
	}
	_, _ = conn.Write([]byte("SELECT 1;\n"))
	reply, err := bufio.NewReader(conn).ReadString('\n')
	_ = conn.Close()
	if err != nil || reply != "DB_OK:SELECT 1;\n" {
		t.Fatalf("unexpected tunnel forwarding response %q (err=%v)", reply, err)
	}

	if _, err := mgr.OpenTunnel(ctx, TunnelConfig{
		NodeID:             "node-9",
		SSHHost:            "db-vps.example",
		SSHPort:            22,
		HostKeyFingerprint: fp,
		Engine:             "redis",
		RemoteTargetAddr:   echoLn.Addr().String(),
	}); err == nil {
		t.Fatalf("expected 9th concurrent tunnel to be rejected")
	} else {
		var be *BridgeError
		if !errors.As(err, &be) || be.Code != ErrTunnelLimit {
			t.Fatalf("expected %s, got %v", ErrTunnelLimit, err)
		}
	}

	if !mgr.CloseTunnel(opened[0].ID) {
		t.Fatalf("expected CloseTunnel(%s) to return true", opened[0].ID)
	}
	if len(mgr.ListTunnels()) != MaxConcurrentTunnels-1 {
		t.Fatalf("expected %d active tunnels after close, got %d", MaxConcurrentTunnels-1, len(mgr.ListTunnels()))
	}
	if _, dErr := net.DialTimeout("tcp", opened[0].LocalAddr, 300*time.Millisecond); dErr == nil {
		t.Fatalf("expected closed tunnel listener %s to refuse connections", opened[0].LocalAddr)
	}

	closedCount := mgr.CloseAll()
	if closedCount != MaxConcurrentTunnels-1 || len(mgr.ListTunnels()) != 0 {
		t.Fatalf("expected CloseAll to close remaining %d tunnels, closed=%d remaining=%d", MaxConcurrentTunnels-1, closedCount, len(mgr.ListTunnels()))
	}
}
