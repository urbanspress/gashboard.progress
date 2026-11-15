package ssh

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// ErrLoopbackRequired rejects any non-loopback or wildcard bind address.
	ErrLoopbackRequired = "GASH-E501"
	// ErrHostKeyRejected rejects missing or mismatched SSH known_hosts fingerprints.
	ErrHostKeyRejected = "GASH-E502"
	// ErrTunnelLimit rejects opening more than MaxConcurrentTunnels tunnels.
	ErrTunnelLimit = "GASH-E503"
)

// BridgeError carries structured Gashboard security and transport codes.
type BridgeError struct {
	Code    string `json:"code"`
	Message string `json:"error"`
}

func (e *BridgeError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// NewError builds a structured BridgeError.
func NewError(code, msg string) *BridgeError {
	return &BridgeError{Code: code, Message: msg}
}

// ValidateLoopbackBind enforces ADR-005 / ADR-017 zero public attack surface.
// Only 127.0.0.1:<port>, localhost:<port>, or [::1]:<port> are accepted.
func ValidateLoopbackBind(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", NewError(ErrLoopbackRequired, "listen address cannot be empty; expected 127.0.0.1:<port>")
	}
	host, port, err := net.SplitHostPort(trimmed)
	if err != nil {
		return "", NewError(ErrLoopbackRequired, fmt.Sprintf("invalid bind address %q: %v", raw, err))
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "*" {
		return "", NewError(ErrLoopbackRequired, fmt.Sprintf("forbidden public bind %q: Gashboard bridge must bind strictly to 127.0.0.1", raw))
	}
	if !strings.EqualFold(host, "localhost") {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return "", NewError(ErrLoopbackRequired, fmt.Sprintf("forbidden non-loopback bind %q: use 127.0.0.1:<port>", raw))
		}
	}
	pNum, err := strconv.Atoi(port)
	if err != nil || pNum < 0 || pNum > 65535 {
		return "", NewError(ErrLoopbackRequired, fmt.Sprintf("invalid port %q in bind address %q", port, raw))
	}
	return net.JoinHostPort(host, port), nil
}

// ValidateLoopbackURL ensures outbound HTTP targets from the local bridge stay on 127.0.0.1 / localhost (SSH-tunneled grabtaculousd).
func ValidateLoopbackURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, NewError(ErrLoopbackRequired, fmt.Sprintf("invalid loopback control URL %q", rawURL))
	}
	host := u.Hostname()
	if host == "" {
		return nil, NewError(ErrLoopbackRequired, "control URL host is required")
	}
	if !strings.EqualFold(host, "localhost") {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, NewError(ErrLoopbackRequired, fmt.Sprintf("refusing non-loopback control target %q: remote grabtaculousd must be reached via 127.0.0.1 SSH tunnel", host))
		}
	}
	return u, nil
}

// KnownHostEntry represents one parsed OpenSSH known_hosts entry.
type KnownHostEntry struct {
	HostPattern string
	KeyType     string
	KeyBase64   string
	Fingerprint string
}

// KnownHostsVerifier enforces strict SSH host-key fingerprint pinning (zero InsecureIgnoreHostKey).
type KnownHostsVerifier struct {
	entries map[string][]KnownHostEntry
}

// ComputeKeyFingerprint computes an OpenSSH-compatible SHA256:<base64> fingerprint from base64 public key wire bytes.
func ComputeKeyFingerprint(keyBase64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(keyBase64))
	if err != nil || len(raw) == 0 {
		return "", NewError(ErrHostKeyRejected, "invalid base64 SSH public key")
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

// NewKnownHostsVerifier parses OpenSSH known_hosts lines into a strict host-key verifier.
func NewKnownHostsVerifier(lines []string) (*KnownHostsVerifier, error) {
	v := &KnownHostsVerifier{
		entries: make(map[string][]KnownHostEntry),
	}
	for idx, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return nil, NewError(ErrHostKeyRejected, fmt.Sprintf("malformed known_hosts line %d", idx+1))
		}
		hostsField, keyType, keyB64 := fields[0], fields[1], fields[2]
		fp, err := ComputeKeyFingerprint(keyB64)
		if err != nil {
			return nil, fmt.Errorf("known_hosts line %d: %w", idx+1, err)
		}
		for _, pattern := range strings.Split(hostsField, ",") {
			norm := normalizeKnownHostPattern(pattern)
			if norm == "" {
				continue
			}
			v.entries[norm] = append(v.entries[norm], KnownHostEntry{
				HostPattern: norm,
				KeyType:     keyType,
				KeyBase64:   keyB64,
				Fingerprint: fp,
			})
		}
	}
	return v, nil
}

// LoadKnownHostsFile loads an OpenSSH known_hosts file from disk.
func LoadKnownHostsFile(path string) (*KnownHostsVerifier, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, NewError(ErrHostKeyRejected, fmt.Sprintf("cannot open known_hosts %q: %v", path, err))
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return NewKnownHostsVerifier(lines)
}

func normalizeKnownHostPattern(pattern string) string {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return ""
	}
	return strings.ToLower(p)
}

func hostLookupKeys(host string, port int) []string {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return nil
	}
	if port > 0 && port != 22 {
		return []string{fmt.Sprintf("[%s]:%d", h, port), h}
	}
	return []string{h, fmt.Sprintf("[%s]:22", h)}
}

// VerifyPublicKey checks whether the supplied host/port and base64 SSH key match a pinned entry.
func (v *KnownHostsVerifier) VerifyPublicKey(host string, port int, keyType, keyBase64 string) (string, error) {
	if v == nil || len(v.entries) == 0 {
		return "", NewError(ErrHostKeyRejected, fmt.Sprintf("host key verification failed for %s: empty known_hosts store", host))
	}
	fp, err := ComputeKeyFingerprint(keyBase64)
	if err != nil {
		return "", err
	}
	var matchedEntries []KnownHostEntry
	for _, k := range hostLookupKeys(host, port) {
		if list, ok := v.entries[k]; ok {
			matchedEntries = append(matchedEntries, list...)
		}
	}
	if len(matchedEntries) == 0 {
		return "", NewError(ErrHostKeyRejected, fmt.Sprintf("unknown SSH host %q (not present in known_hosts; strict host-key pinning enforced)", host))
	}
	for _, e := range matchedEntries {
		if (keyType == "" || e.KeyType == keyType) && subtle.ConstantTimeCompare([]byte(e.Fingerprint), []byte(fp)) == 1 {
			return fp, nil
		}
	}
	return "", NewError(ErrHostKeyRejected, fmt.Sprintf("SSH host key mismatch for %q: presented %s does not match pinned known_hosts fingerprint", host, fp))
}

// VerifyFingerprint checks whether the supplied host/port and SHA256:<b64> fingerprint match a pinned entry.
func (v *KnownHostsVerifier) VerifyFingerprint(host string, port int, presentedFingerprint string) (string, error) {
	if v == nil || len(v.entries) == 0 {
		return "", NewError(ErrHostKeyRejected, fmt.Sprintf("host key verification failed for %s: empty known_hosts store", host))
	}
	fp := strings.TrimSpace(presentedFingerprint)
	if !strings.HasPrefix(fp, "SHA256:") || len(fp) < 15 {
		return "", NewError(ErrHostKeyRejected, fmt.Sprintf("invalid SSH fingerprint format %q (expected SHA256:...)", presentedFingerprint))
	}
	var matchedEntries []KnownHostEntry
	for _, k := range hostLookupKeys(host, port) {
		if list, ok := v.entries[k]; ok {
			matchedEntries = append(matchedEntries, list...)
		}
	}
	if len(matchedEntries) == 0 {
		return "", NewError(ErrHostKeyRejected, fmt.Sprintf("unknown SSH host %q (not present in known_hosts; strict host-key pinning enforced)", host))
	}
	for _, e := range matchedEntries {
		if subtle.ConstantTimeCompare([]byte(e.Fingerprint), []byte(fp)) == 1 {
			return fp, nil
		}
	}
	return "", NewError(ErrHostKeyRejected, fmt.Sprintf("SSH host key mismatch for %q: presented %s does not match pinned known_hosts fingerprint", host, fp))
}

// ControlClient proxies authenticated requests to a host-key-verified SSH-tunneled grabtaculousd loopback endpoint.
type ControlClient struct {
	httpClient *http.Client
	verifier   *KnownHostsVerifier
}

// NewControlClient constructs a loopback-enforcing Grabtaculous client with host-key pinning.
func NewControlClient(verifier *KnownHostsVerifier) *ControlClient {
	return &ControlClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		verifier:   verifier,
	}
}

// VerifyHost verifies a node against known_hosts before any control RPC or tunnel operation proceeds.
func (c *ControlClient) VerifyHost(host string, port int, presentedFingerprint string, dynamicVerifier *KnownHostsVerifier) (string, error) {
	ver := dynamicVerifier
	if ver == nil {
		ver = c.verifier
	}
	if ver == nil {
		return "", NewError(ErrHostKeyRejected, "no known_hosts verifier configured")
	}
	return ver.VerifyFingerprint(host, port, presentedFingerprint)
}

// ProxyGrabtaculous validates host pinning + strict loopback URL and forwards an authenticated API call to grabtaculousd.
func (c *ControlClient) ProxyGrabtaculous(ctx context.Context, targetURL, bearerToken, method, apiPath string, body []byte) (int, []byte, error) {
	u, err := ValidateLoopbackURL(targetURL)
	if err != nil {
		return 0, nil, err
	}
	cleanPath := "/" + strings.TrimLeft(strings.TrimSpace(apiPath), "/")
	if strings.Contains(cleanPath, "..") {
		return 0, nil, NewError(ErrLoopbackRequired, "invalid path traversal in grabtaculous path")
	}
	fullURL := strings.TrimRight(u.String(), "/") + cleanPath

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if tok := strings.TrimSpace(bearerToken); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, raw, nil
}

// ValidateSSHOptions enforces safe argument-vector SSH parameters when shelling out to OpenSSH (`ssh`).
func ValidateSSHOptions(sshUser, host string, port int, knownHostsPath string) ([]string, error) {
	user := strings.TrimSpace(sshUser)
	h := strings.TrimSpace(host)
	if user == "" || h == "" || strings.ContainsAny(user+h, " \t\r\n;|&$`<>\"'") {
		return nil, errors.New("invalid SSH user or host")
	}
	if port <= 0 || port > 65535 {
		port = 22
	}
	kh := strings.TrimSpace(knownHostsPath)
	if kh == "" {
		return nil, NewError(ErrHostKeyRejected, "known_hosts file path is required")
	}
	return []string{
		"-N", "-T",
		"-o", "BatchMode=yes",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + kh,
		"-p", strconv.Itoa(port),
	}, nil
}
