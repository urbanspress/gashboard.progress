package dns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	gssh "gashboard/bridge/internal/ssh"
)

var defaultPublicResolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// PropagationRequest configures a DNS propagation preflight check prior to Let's Encrypt issuance.
type PropagationRequest struct {
	Domain       string `json:"domain"`
	ExpectedIPv4 string `json:"expected_ip"`
	ExpectedIPv6 string `json:"expected_ipv6"`
	EdgeProxy    string `json:"edge_proxy"`
}

// ResolverCheck captures DNS resolution results observed from a single resolver endpoint.
type ResolverCheck struct {
	Resolver     string   `json:"resolver"`
	ResolvedIPv4 []string `json:"resolved_ipv4"`
	ResolvedIPv6 []string `json:"resolved_ipv6"`
	Matched      bool     `json:"matched"`
	Error        string   `json:"error,omitempty"`
}

// PropagationResult reports whether live DNS resolution matches the target VPS before ACME runs.
type PropagationResult struct {
	OK               bool            `json:"ok"`
	Domain           string          `json:"domain"`
	ExpectedIPv4     string          `json:"expected_ip"`
	ExpectedIPv6     string          `json:"expected_ipv6,omitempty"`
	EdgeProxy        string          `json:"edge_proxy"`
	Propagated       bool            `json:"propagated"`
	SkippedForTunnel bool            `json:"skipped_for_tunnel"`
	ResolvedIPv4     []string        `json:"resolved_ips"`
	ResolvedIPv6     []string        `json:"resolved_ipv6s"`
	Resolvers        []ResolverCheck `json:"resolvers"`
	CheckedAt        string          `json:"checked_at"`
	Message          string          `json:"message"`
}

// CheckPropagation queries configured DNS resolvers (or public + authoritative resolvers)
// to confirm domain A/AAAA records match the target VPS before allowing ACME issuance.
func CheckPropagation(ctx context.Context, req PropagationRequest, configuredResolvers []string) (*PropagationResult, error) {
	domain, err := ValidateDomain(req.Domain)
	if err != nil {
		return nil, err
	}
	edgeProxy := strings.ToLower(strings.TrimSpace(req.EdgeProxy))
	if edgeProxy == "" {
		edgeProxy = "caddy"
	}
	if edgeProxy != "caddy" && edgeProxy != "nginx" && edgeProxy != "cloudflare-tunnel" {
		return nil, newErr(422, ErrValidation, fmt.Sprintf("edge_proxy must be caddy, nginx, or cloudflare-tunnel (got %q)", req.EdgeProxy))
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	if edgeProxy == "cloudflare-tunnel" {
		return &PropagationResult{
			OK:               true,
			Domain:           domain,
			ExpectedIPv4:     strings.TrimSpace(req.ExpectedIPv4),
			ExpectedIPv6:     strings.TrimSpace(req.ExpectedIPv6),
			EdgeProxy:        edgeProxy,
			Propagated:       true,
			SkippedForTunnel: true,
			ResolvedIPv4:     []string{},
			ResolvedIPv6:     []string{},
			Resolvers:        []ResolverCheck{},
			CheckedAt:        nowStr,
			Message:          "Cloudflare Tunnel mode routes encrypted origin traffic via cloudflared; direct ACME IP propagation gate skipped cleanly.",
		}, nil
	}

	exp4 := strings.TrimSpace(req.ExpectedIPv4)
	parsed4 := net.ParseIP(exp4)
	if parsed4 == nil || parsed4.To4() == nil {
		return nil, newErr(422, ErrValidation, fmt.Sprintf("expected_ip must be a valid IPv4 address (got %q)", req.ExpectedIPv4))
	}
	exp4 = parsed4.To4().String()

	exp6 := strings.TrimSpace(req.ExpectedIPv6)
	if exp6 != "" {
		parsed6 := net.ParseIP(exp6)
		if parsed6 == nil || parsed6.To4() != nil {
			return nil, newErr(422, ErrValidation, fmt.Sprintf("expected_ipv6 must be a valid IPv6 address (got %q)", req.ExpectedIPv6))
		}
		exp6 = parsed6.String()
	}

	resolvers := normalizeResolverList(configuredResolvers)
	if len(resolvers) == 0 {
		resolvers = append(resolvers, defaultPublicResolvers...)
		if authNS := discoverAuthoritativeResolvers(ctx, domain); len(authNS) > 0 {
			resolvers = append(resolvers, authNS...)
		}
	}

	checks := make([]ResolverCheck, 0, len(resolvers))
	all4Map := make(map[string]struct{})
	all6Map := make(map[string]struct{})
	allMatched := len(resolvers) > 0

	for _, resAddr := range resolvers {
		chk := querySingleResolver(ctx, resAddr, domain, exp4, exp6)
		for _, ip := range chk.ResolvedIPv4 {
			all4Map[ip] = struct{}{}
		}
		for _, ip := range chk.ResolvedIPv6 {
			all6Map[ip] = struct{}{}
		}
		if !chk.Matched {
			allMatched = false
		}
		checks = append(checks, chk)
	}

	all4 := sortedKeys(all4Map)
	all6 := sortedKeys(all6Map)

	msg := fmt.Sprintf("Live DNS propagation verified: %s resolves cleanly to %s across %d resolver(s). Safe to run ACME HTTPS issuance.", domain, exp4, len(checks))
	if !allMatched {
		msg = fmt.Sprintf(
			"Let's Encrypt rate-limit guard: %s resolves to [%s] instead of target VPS IP %s. Wait for DNS propagation before provisioning HTTPS.",
			domain,
			strings.Join(all4, ", "),
			exp4,
		)
	}

	return &PropagationResult{
		OK:           true,
		Domain:       domain,
		ExpectedIPv4: exp4,
		ExpectedIPv6: exp6,
		EdgeProxy:    edgeProxy,
		Propagated:   allMatched,
		ResolvedIPv4: all4,
		ResolvedIPv6: all6,
		Resolvers:    checks,
		CheckedAt:    nowStr,
		Message:      msg,
	}, nil
}

func normalizeResolverList(raw []string) []string {
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool)
	for _, r := range raw {
		clean := strings.TrimSpace(r)
		if clean == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(clean); err != nil {
			clean = net.JoinHostPort(clean, "53")
		}
		if !seen[clean] {
			seen[clean] = true
			out = append(out, clean)
		}
	}
	return out
}

func discoverAuthoritativeResolvers(ctx context.Context, domain string) []string {
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return nil
	}
	root := strings.Join(labels[len(labels)-2:], ".")
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	nss, err := net.DefaultResolver.LookupNS(lookupCtx, root)
	if err != nil {
		return nil
	}
	var out []string
	for _, ns := range nss {
		host := strings.TrimSuffix(strings.TrimSpace(ns.Host), ".")
		if host != "" {
			out = append(out, net.JoinHostPort(host, "53"))
			if len(out) >= 2 {
				break
			}
		}
	}
	return out
}

func querySingleResolver(ctx context.Context, resolverAddr, domain, exp4, exp6 string) ResolverCheck {
	qCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2500 * time.Millisecond}
			return d.DialContext(dialCtx, network, resolverAddr)
		},
	}

	var resolved4 []string
	ips4, err4 := resolver.LookupNetIP(qCtx, "ip4", domain)
	if err4 == nil {
		for _, ip := range ips4 {
			if ip.Is4() {
				resolved4 = append(resolved4, ip.String())
			}
		}
	}

	var resolved6 []string
	var err6 error
	if exp6 != "" {
		var ips6 []netip.Addr
		ips6, err6 = resolver.LookupNetIP(qCtx, "ip6", domain)
		if err6 == nil {
			for _, ip := range ips6 {
				if ip.Is6() {
					resolved6 = append(resolved6, ip.String())
				}
			}
		}
	}

	sort.Strings(resolved4)
	sort.Strings(resolved6)

	errMsg := ""
	if err4 != nil {
		errMsg = err4.Error()
	} else if err6 != nil {
		errMsg = err6.Error()
	}

	matched4 := len(resolved4) > 0 && containsOnlyExpected(resolved4, exp4)
	matched6 := exp6 == "" || (len(resolved6) > 0 && containsOnlyExpected(resolved6, exp6))
	return ResolverCheck{
		Resolver:     resolverAddr,
		ResolvedIPv4: resolved4,
		ResolvedIPv6: resolved6,
		Matched:      errMsg == "" && matched4 && matched6,
		Error:        errMsg,
	}
}

func containsOnlyExpected(ips []string, expected string) bool {
	found := false
	for _, ip := range ips {
		if ip == expected {
			found = true
		} else {
			return false
		}
	}
	return found
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// VerifyHTTPSRequest configures post-deploy loopback /_ready and optional HTTPS TLS verification.
type VerifyHTTPSRequest struct {
	Domain           string `json:"domain"`
	EdgeProxy        string `json:"edge_proxy"`
	UpstreamReadyURL string `json:"upstream_ready_url"`
	HTTPSProbeURL    string `json:"https_probe_url"`
	TrustedCertPEM   string `json:"trusted_cert_pem"`
}

// VerifyHTTPSResult reports /_ready and TLS verification status.
type VerifyHTTPSResult struct {
	OK            bool   `json:"ok"`
	Domain        string `json:"domain"`
	EdgeProxy     string `json:"edge_proxy"`
	ReadyStatus   string `json:"ready_status"`
	TLSVerified   bool   `json:"tls_verified"`
	HTTPSStatus   string `json:"https_status,omitempty"`
	TLSProtocol   string `json:"tls_protocol,omitempty"`
}

// VerifyReadyAndTLS confirms the loopback Grisp / Grabtaculous /_ready endpoint returns HTTP 200
// and, when an HTTPS probe URL is configured, verifies a valid TLS handshake and /_ready === 200.
func VerifyReadyAndTLS(ctx context.Context, req VerifyHTTPSRequest) (*VerifyHTTPSResult, error) {
	domain, err := ValidateDomain(req.Domain)
	if err != nil {
		return nil, err
	}
	readyStatus := "200"
	if upURL := strings.TrimSpace(req.UpstreamReadyURL); upURL != "" {
		u, err := gssh.ValidateLoopbackURL(upURL)
		if err != nil {
			return nil, newErr(403, ErrSSRFBlocked, err.Error())
		}
		client := &http.Client{Timeout: 5 * time.Second}
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, newErr(502, ErrDNSGateway, err.Error())
		}
		resp, err := client.Do(httpReq)
		if err != nil {
			return nil, newErr(502, ErrDNSGateway, fmt.Sprintf("upstream /_ready probe failed: %v", err))
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, newErr(502, ErrDNSGateway, fmt.Sprintf("upstream /_ready returned HTTP %d", resp.StatusCode))
		}
		var bodyDoc map[string]any
		if json.Unmarshal(raw, &bodyDoc) == nil {
			if okVal, has := bodyDoc["ok"].(bool); has && !okVal {
				return nil, newErr(502, ErrDNSGateway, "upstream /_ready reported ok=false")
			}
		}
	}

	tlsVerified := false
	httpsStatus := ""
	tlsProto := ""

	if probeRaw := strings.TrimSpace(req.HTTPSProbeURL); probeRaw != "" {
		pu, err := url.Parse(probeRaw)
		if err != nil || pu.Scheme != "https" {
			return nil, newErr(422, ErrValidation, fmt.Sprintf("https_probe_url must use https:// (got %q)", probeRaw))
		}
		host := strings.ToLower(pu.Hostname())
		isLoopback := host == "localhost"
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			isLoopback = true
		}
		if host != domain && !isLoopback {
			return nil, newErr(403, ErrSSRFBlocked, fmt.Sprintf("https_probe_url host %q does not match domain %q or loopback test endpoint", host, domain))
		}

		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		if pemTxt := strings.TrimSpace(req.TrustedCertPEM); pemTxt != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(pemTxt)) {
				return nil, newErr(422, ErrValidation, "invalid trusted_cert_pem certificate")
			}
			tlsCfg.RootCAs = pool
		}
		client := &http.Client{
			Timeout: 8 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		}
		hReq, err := http.NewRequestWithContext(ctx, http.MethodGet, pu.String(), nil)
		if err != nil {
			return nil, newErr(502, ErrDNSGateway, err.Error())
		}
		hResp, err := client.Do(hReq)
		if err != nil {
			return nil, newErr(502, ErrDNSGateway, fmt.Sprintf("HTTPS probe failed: %v", err))
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(hResp.Body, 1<<20))
		_ = hResp.Body.Close()
		if hResp.StatusCode != http.StatusOK {
			return nil, newErr(502, ErrDNSGateway, fmt.Sprintf("HTTPS /_ready returned HTTP %d", hResp.StatusCode))
		}
		tlsVerified = true
		httpsStatus = fmt.Sprintf("%d", hResp.StatusCode)
		if hResp.TLS != nil && hResp.TLS.Version == tls.VersionTLS13 {
			tlsProto = "TLSv1.3"
		} else {
			tlsProto = "TLSv1.2"
		}
	}

	return &VerifyHTTPSResult{
		OK:          true,
		Domain:      domain,
		EdgeProxy:   strings.TrimSpace(req.EdgeProxy),
		ReadyStatus: readyStatus,
		TLSVerified: tlsVerified,
		HTTPSStatus: httpsStatus,
		TLSProtocol: tlsProto,
	}, nil
}
