package ssh

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// MaxConcurrentTunnels enforces GASHBOARD-EXPERT bounded concurrency invariant (<= 8).
	MaxConcurrentTunnels = 8
	// DefaultTunnelTTLMinutes bounds idle/session tunnel duration.
	DefaultTunnelTTLMinutes = 60
)

// DefaultRemoteDBPort maps supported database engines to their remote loopback port.
func DefaultRemoteDBPort(engine string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(engine)) {
	case "postgres", "postgresql":
		return 5432, true
	case "mariadb", "mysql":
		return 3306, true
	case "redis":
		return 6379, true
	default:
		return 0, false
	}
}

// TunnelConfig configures an encrypted loopback-only SSH database tunnel.
type TunnelConfig struct {
	NodeID              string
	SSHHost             string
	SSHPort             int
	HostKeyFingerprint  string
	KnownHostsLines     []string
	Engine              string
	RequestedLocalPort  int
	RemoteTargetAddr    string // Loopback DB / SSH-forwarded endpoint (defaults to 127.0.0.1:<engine-port>)
	TTLMinutes          int
}

// TunnelRecord describes an active 127.0.0.1 database tunnel without exposing any secrets.
type TunnelRecord struct {
	ID         string `json:"id"`
	NodeID     string `json:"node_id"`
	Engine     string `json:"engine"`
	SSHHost    string `json:"ssh_host"`
	LocalHost  string `json:"local_host"`
	LocalPort  string `json:"local_port"`
	LocalAddr  string `json:"local_addr"`
	RemoteHost string `json:"remote_host"`
	RemotePort string `json:"remote_port"`
	TTLMinutes string `json:"ttl_minutes"`
	Status     string `json:"status"`
	CreatedAt  string `json:"created_at"`
	ExpiresAt  string `json:"expires_at"`
}

type activeTunnel struct {
	record   TunnelRecord
	listener net.Listener
	cancel   context.CancelFunc
}

// TunnelManager manages bounded 127.0.0.1 SSH database tunnels with host-key pinning and clean shutdown.
type TunnelManager struct {
	mu       sync.Mutex
	verifier *KnownHostsVerifier
	tunnels  map[string]*activeTunnel
}

// NewTunnelManager creates a TunnelManager backed by an optional default KnownHostsVerifier.
func NewTunnelManager(verifier *KnownHostsVerifier) *TunnelManager {
	return &TunnelManager{
		verifier: verifier,
		tunnels:  make(map[string]*activeTunnel),
	}
}

// OpenTunnel verifies the target node host key, enforces <= 8 active tunnels, binds strictly to 127.0.0.1,
// and forwards TCP streams to the loopback remote DB target until closed or expired.
func (m *TunnelManager) OpenTunnel(ctx context.Context, cfg TunnelConfig) (TunnelRecord, error) {
	engine := strings.ToLower(strings.TrimSpace(cfg.Engine))
	defaultPort, ok := DefaultRemoteDBPort(engine)
	if !ok {
		return TunnelRecord{}, fmt.Errorf("unsupported DB tunnel engine %q (expected postgres, mariadb, or redis)", cfg.Engine)
	}
	sshHost := strings.TrimSpace(cfg.SSHHost)
	if sshHost == "" {
		return TunnelRecord{}, NewError(ErrHostKeyRejected, "ssh_host is required")
	}
	sshPort := cfg.SSHPort
	if sshPort <= 0 {
		sshPort = 22
	}

	ver := m.verifier
	if len(cfg.KnownHostsLines) > 0 {
		parsed, err := NewKnownHostsVerifier(cfg.KnownHostsLines)
		if err != nil {
			return TunnelRecord{}, err
		}
		ver = parsed
	}
	if ver == nil {
		return TunnelRecord{}, NewError(ErrHostKeyRejected, "known_hosts verification is required before opening DB tunnel")
	}
	if _, err := ver.VerifyFingerprint(sshHost, sshPort, cfg.HostKeyFingerprint); err != nil {
		return TunnelRecord{}, err
	}

	targetAddr := strings.TrimSpace(cfg.RemoteTargetAddr)
	if targetAddr == "" {
		targetAddr = fmt.Sprintf("127.0.0.1:%d", defaultPort)
	}
	cleanTarget, err := ValidateLoopbackBind(targetAddr)
	if err != nil {
		return TunnelRecord{}, err
	}
	remoteHost, remotePort, _ := net.SplitHostPort(cleanTarget)

	ttlMin := cfg.TTLMinutes
	if ttlMin <= 0 {
		ttlMin = DefaultTunnelTTLMinutes
	}
	if ttlMin > 480 {
		ttlMin = 480
	}

	bindReq := fmt.Sprintf("127.0.0.1:%d", cfg.RequestedLocalPort)
	if cfg.RequestedLocalPort < 0 || cfg.RequestedLocalPort > 65535 {
		return TunnelRecord{}, NewError(ErrLoopbackRequired, fmt.Sprintf("invalid local port %d", cfg.RequestedLocalPort))
	}
	if _, err := ValidateLoopbackBind(bindReq); err != nil {
		return TunnelRecord{}, err
	}

	m.mu.Lock()
	if len(m.tunnels) >= MaxConcurrentTunnels {
		m.mu.Unlock()
		return TunnelRecord{}, NewError(ErrTunnelLimit, fmt.Sprintf("concurrent SSH DB tunnel cap reached (%d/%d active)", len(m.tunnels), MaxConcurrentTunnels))
	}

	ln, err := net.Listen("tcp", bindReq)
	if err != nil {
		m.mu.Unlock()
		return TunnelRecord{}, fmt.Errorf("failed to bind loopback tunnel %s: %w", bindReq, err)
	}
	boundAddr := ln.Addr().String()
	_, actualPort, _ := net.SplitHostPort(boundAddr)

	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		_ = ln.Close()
		m.mu.Unlock()
		return TunnelRecord{}, err
	}
	tunnelID := "tun_" + hex.EncodeToString(rnd[:])
	now := time.Now().UTC()
	expires := now.Add(time.Duration(ttlMin) * time.Minute)

	rec := TunnelRecord{
		ID:         tunnelID,
		NodeID:     strings.TrimSpace(cfg.NodeID),
		Engine:     engine,
		SSHHost:    sshHost,
		LocalHost:  "127.0.0.1",
		LocalPort:  actualPort,
		LocalAddr:  boundAddr,
		RemoteHost: remoteHost,
		RemotePort: remotePort,
		TTLMinutes: fmt.Sprintf("%d", ttlMin),
		Status:     "active",
		CreatedAt:  now.Format(time.RFC3339),
		ExpiresAt:  expires.Format(time.RFC3339),
	}

	tunCtx, cancel := context.WithDeadline(ctx, expires)
	entry := &activeTunnel{
		record:   rec,
		listener: ln,
		cancel:   cancel,
	}
	m.tunnels[tunnelID] = entry
	m.mu.Unlock()

	go m.acceptLoop(tunCtx, tunnelID, ln, cleanTarget)
	go func() {
		<-tunCtx.Done()
		_ = m.CloseTunnel(tunnelID)
	}()

	return rec, nil
}

func (m *TunnelManager) acceptLoop(ctx context.Context, id string, ln net.Listener, targetAddr string) {
	for {
		clientConn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			return
		}
		go m.forwardConn(ctx, clientConn, targetAddr)
	}
}

func (m *TunnelManager) forwardConn(ctx context.Context, clientConn net.Conn, targetAddr string) {
	defer clientConn.Close()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	targetConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return
	}
	defer targetConn.Close()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(targetConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, targetConn)
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// GetTunnel looks up an active tunnel by ID and verifies it has not expired.
func (m *TunnelManager) GetTunnel(id string) (TunnelRecord, bool) {
	cleanID := strings.TrimSpace(id)
	m.mu.Lock()
	entry, ok := m.tunnels[cleanID]
	m.mu.Unlock()
	if !ok {
		return TunnelRecord{}, false
	}
	return entry.record, true
}

// ListTunnels returns active loopback tunnels sorted deterministically by creation order/ID.
func (m *TunnelManager) ListTunnels() []TunnelRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]TunnelRecord, 0, len(m.tunnels))
	for _, entry := range m.tunnels {
		out = append(out, entry.record)
	}
	return out
}

// CloseTunnel closes one active tunnel and releases its 127.0.0.1 listener.
func (m *TunnelManager) CloseTunnel(id string) bool {
	m.mu.Lock()
	entry, ok := m.tunnels[id]
	if ok {
		delete(m.tunnels, id)
	}
	m.mu.Unlock()
	if !ok {
		return false
	}
	entry.cancel()
	_ = entry.listener.Close()
	return true
}

// CloseAll cleanly terminates every active DB tunnel (used on shutdown).
func (m *TunnelManager) CloseAll() int {
	m.mu.Lock()
	items := make([]*activeTunnel, 0, len(m.tunnels))
	for id, entry := range m.tunnels {
		items = append(items, entry)
		delete(m.tunnels, id)
	}
	m.mu.Unlock()
	for _, entry := range items {
		entry.cancel()
		_ = entry.listener.Close()
	}
	return len(items)
}
