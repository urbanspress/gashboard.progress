package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gashboard/bridge/internal/dbinspect"
	gdns "gashboard/bridge/internal/dns"
	"gashboard/bridge/internal/localcli"
	gssh "gashboard/bridge/internal/ssh"
)

// Version identifies the Gashboard Go SSH sidecar release version.
var Version = "1.0.0"

const defaultListenAddr = "127.0.0.1:9391"

type BridgeServer struct {
	listenAddr     string
	token          string
	knownHosts     *gssh.KnownHostsVerifier
	client         *gssh.ControlClient
	tunnels        *gssh.TunnelManager
	inspector      *dbinspect.Inspector
	ncClient       *gdns.NamecheapClient
	dnsResolvers   []string
	httpsProbeURL  string
	trustedCertPEM string
	sqliteRoot     string
	grabmanBin     string
	grabtacBin     string
	grabBin        string
	httpSrv        *http.Server
	boundAddr      string
}

func NewBridgeServer(listenAddr, bridgeToken, knownHostsFile, grabmanBin, grabtacBin, grabBin string) (*BridgeServer, error) {
	cleanAddr, err := gssh.ValidateLoopbackBind(listenAddr)
	if err != nil {
		return nil, err
	}
	tok := strings.TrimSpace(bridgeToken)
	if tok == "" {
		tok = strings.TrimSpace(os.Getenv("GASHBOARD_BRIDGE_TOKEN"))
	}
	if tok == "" {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		tok = hex.EncodeToString(b[:])
	}
	var kh *gssh.KnownHostsVerifier
	if strings.TrimSpace(knownHostsFile) != "" {
		kh, err = gssh.LoadKnownHostsFile(strings.TrimSpace(knownHostsFile))
		if err != nil {
			return nil, err
		}
	} else {
		kh, _ = gssh.NewKnownHostsVerifier(nil)
	}
	sqliteRoot := strings.TrimSpace(os.Getenv("GASHBOARD_SQLITE_ROOT"))
	if sqliteRoot == "" {
		sqliteRoot = "storage"
	}
	tunnels := gssh.NewTunnelManager(kh)
	bs := &BridgeServer{
		listenAddr:     cleanAddr,
		token:          tok,
		knownHosts:     kh,
		client:         gssh.NewControlClient(kh),
		tunnels:        tunnels,
		inspector:      dbinspect.NewInspector(sqliteRoot, tunnels),
		ncClient:       gdns.NewNamecheapClient(os.Getenv("GASHBOARD_NAMECHEAP_URL")),
		dnsResolvers:   parseCSV(os.Getenv("GASHBOARD_DNS_RESOLVERS")),
		httpsProbeURL:  strings.TrimSpace(os.Getenv("GASHBOARD_HTTPS_PROBE_URL")),
		trustedCertPEM: strings.TrimSpace(os.Getenv("GASHBOARD_HTTPS_TRUSTED_CERT_PEM")),
		sqliteRoot:     sqliteRoot,
		grabmanBin:     grabmanBin,
		grabtacBin:     grabtacBin,
		grabBin:        grabBin,
	}
	bs.httpSrv = &http.Server{
		Handler:           bs.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      35 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	return bs, nil
}

// SetSQLiteRoot configures the confined workspace root for local SQLite inspection and snapshots.
func (s *BridgeServer) SetSQLiteRoot(dir string) {
	clean := strings.TrimSpace(dir)
	if clean == "" {
		clean = "storage"
	}
	s.sqliteRoot = clean
	s.inspector = dbinspect.NewInspector(clean, s.tunnels)
}

// SetNamecheapURL configures an override Namecheap XML API URL (strictly official or loopback for tests).
func (s *BridgeServer) SetNamecheapURL(raw string) {
	s.ncClient.SetOverrideURL(raw)
}

// SetDNSResolvers overrides the DNS resolver host:port endpoints queried during propagation preflight checks.
func (s *BridgeServer) SetDNSResolvers(resolvers []string) {
	out := make([]string, 0, len(resolvers))
	for _, r := range resolvers {
		if trimmed := strings.TrimSpace(r); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	s.dnsResolvers = out
}

// SetHTTPSProbe configures optional default HTTPS /_ready probe URL and trusted test CA PEM.
func (s *BridgeServer) SetHTTPSProbe(probeURL, trustedCertPEM string) {
	s.httpsProbeURL = strings.TrimSpace(probeURL)
	s.trustedCertPEM = strings.TrimSpace(trustedCertPEM)
}

func parseCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func (s *BridgeServer) Token() string       { return s.token }
func (s *BridgeServer) BoundAddress() string { return s.boundAddr }

func (s *BridgeServer) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	s.boundAddr = ln.Addr().String()
	errCh := make(chan error, 1)
	go func() {
		if srvErr := s.httpSrv.Serve(ln); srvErr != nil && !errors.Is(srvErr, http.ErrServerClosed) {
			errCh <- srvErr
			return
		}
		errCh <- nil
	}()
	select {
	case <-ctx.Done():
		s.tunnels.CloseAll()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(shutCtx)
		return <-errCh
	case srvErr := <-errCh:
		s.tunnels.CloseAll()
		return srvErr
	}
}

func (s *BridgeServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_health", s.handleHealth)
	mux.HandleFunc("GET /_ready", s.handleReady)
	mux.HandleFunc("POST /v1/ssh/verify-host", s.requireAuth(s.handleVerifyHost))
	mux.HandleFunc("GET /v1/tunnels", s.requireAuth(s.handleListTunnels))
	mux.HandleFunc("POST /v1/tunnels/open", s.requireAuth(s.handleOpenTunnel))
	mux.HandleFunc("POST /v1/tunnels/close", s.requireAuth(s.handleCloseTunnel))
	mux.HandleFunc("POST /v1/grabman/doctor", s.requireAuth(s.handleGrabmanDoctor))
	mux.HandleFunc("POST /v1/grabman/solve-verify", s.requireAuth(s.handleGrabmanSolveVerify))
	mux.HandleFunc("POST /v1/grabman/dna-preview", s.requireAuth(s.handleGrabmanDNAPreview))
	mux.HandleFunc("POST /v1/grabtaculous/proxy", s.requireAuth(s.handleGrabtaculousProxy))
	mux.HandleFunc("POST /v1/db/schema", s.requireAuth(handleDBRoute(s.handleDBSchema)))
	mux.HandleFunc("POST /v1/db/rows", s.requireAuth(handleDBRoute(s.handleDBRows)))
	mux.HandleFunc("POST /v1/db/query", s.requireAuth(handleDBRoute(s.handleDBQuery)))
	mux.HandleFunc("POST /v1/db/mutate/plan", s.requireAuth(handleDBRoute(s.handleDBMutatePlan)))
	mux.HandleFunc("POST /v1/db/mutate/execute", s.requireAuth(handleDBRoute(s.handleDBMutateExecute)))
	mux.HandleFunc("POST /v1/db/export", s.requireAuth(handleDBRoute(s.handleDBExport)))
	mux.HandleFunc("POST /v1/db/restore", s.requireAuth(handleDBRoute(s.handleDBRestore)))
	mux.HandleFunc("POST /v1/dns/namecheap/hosts", s.requireAuth(handleDBRoute(s.handleDNSNamecheapHosts)))
	mux.HandleFunc("POST /v1/dns/namecheap/plan", s.requireAuth(handleDBRoute(s.handleDNSNamecheapPlan)))
	mux.HandleFunc("POST /v1/dns/namecheap/apply", s.requireAuth(handleDBRoute(s.handleDNSNamecheapApply)))
	mux.HandleFunc("POST /v1/dns/namecheap/restore", s.requireAuth(handleDBRoute(s.handleDNSNamecheapRestore)))
	mux.HandleFunc("POST /v1/dns/propagation/check", s.requireAuth(handleDBRoute(s.handleDNSPropagationCheck)))
	mux.HandleFunc("POST /v1/https/verify", s.requireAuth(handleDBRoute(s.handleHTTPSVerify)))
	return mux
}

func (s *BridgeServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"ok":    false,
				"code":  gssh.ErrLoopbackRequired,
				"error": "missing Bearer GASHBOARD_BRIDGE_TOKEN",
			})
			return
		}
		provided := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
		if subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"ok":    false,
				"code":  gssh.ErrLoopbackRequired,
				"error": "invalid GASHBOARD_BRIDGE_TOKEN",
			})
			return
		}
		next(w, r)
	}
}

func (s *BridgeServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"service": "gashboard-bridge",
		"version": Version,
		"bind":    s.boundAddr,
	})
}

func (s *BridgeServer) handleReady(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"ready":          true,
		"service":        "gashboard-bridge",
		"version":        Version,
		"active_tunnels": len(s.tunnels.ListTunnels()),
		"max_tunnels":    gssh.MaxConcurrentTunnels,
	})
}

type verifyHostReq struct {
	Host            string   `json:"host"`
	Port            int      `json:"port"`
	Fingerprint     string   `json:"fingerprint"`
	KnownHostsLines []string `json:"known_hosts_lines"`
}

func (s *BridgeServer) handleVerifyHost(w http.ResponseWriter, r *http.Request) {
	var req verifyHostReq
	if err := decodeJSON(r, &req); err != nil {
		writeBridgeErr(w, http.StatusBadRequest, err)
		return
	}
	ver := s.knownHosts
	if len(req.KnownHostsLines) > 0 {
		parsed, err := gssh.NewKnownHostsVerifier(req.KnownHostsLines)
		if err != nil {
			writeBridgeErr(w, http.StatusForbidden, err)
			return
		}
		ver = parsed
	}
	fp, err := s.client.VerifyHost(req.Host, req.Port, req.Fingerprint, ver)
	if err != nil {
		writeBridgeErr(w, http.StatusForbidden, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "verified": true, "fingerprint": fp})
}

func (s *BridgeServer) handleListTunnels(w http.ResponseWriter, _ *http.Request) {
	items := s.tunnels.ListTunnels()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"tunnels":        items,
		"active_count":   len(items),
		"max_concurrent": gssh.MaxConcurrentTunnels,
	})
}

type openTunnelReq struct {
	NodeID             string   `json:"node_id"`
	SSHHost            string   `json:"ssh_host"`
	SSHPort            int      `json:"ssh_port"`
	HostKeyFingerprint string   `json:"host_key_fingerprint"`
	KnownHostsLines    []string `json:"known_hosts_lines"`
	Engine             string   `json:"engine"`
	RequestedLocalPort int      `json:"local_port"`
	RemoteTargetAddr   string   `json:"remote_target_addr"`
	TTLMinutes         int      `json:"ttl_minutes"`
}

func (s *BridgeServer) handleOpenTunnel(w http.ResponseWriter, r *http.Request) {
	var req openTunnelReq
	if err := decodeJSON(r, &req); err != nil {
		writeBridgeErr(w, http.StatusBadRequest, err)
		return
	}
	rec, err := s.tunnels.OpenTunnel(context.Background(), gssh.TunnelConfig{
		NodeID:             req.NodeID,
		SSHHost:            req.SSHHost,
		SSHPort:            req.SSHPort,
		HostKeyFingerprint: req.HostKeyFingerprint,
		KnownHostsLines:    req.KnownHostsLines,
		Engine:             req.Engine,
		RequestedLocalPort: req.RequestedLocalPort,
		RemoteTargetAddr:   req.RemoteTargetAddr,
		TTLMinutes:         req.TTLMinutes,
	})
	if err != nil {
		status := http.StatusUnprocessableEntity
		var be *gssh.BridgeError
		if errors.As(err, &be) {
			switch be.Code {
			case gssh.ErrHostKeyRejected:
				status = http.StatusForbidden
			case gssh.ErrTunnelLimit:
				status = http.StatusTooManyRequests
			}
		}
		writeBridgeErr(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tunnel": rec})
}

type closeTunnelReq struct {
	ID string `json:"id"`
}

func (s *BridgeServer) handleCloseTunnel(w http.ResponseWriter, r *http.Request) {
	var req closeTunnelReq
	if err := decodeJSON(r, &req); err != nil {
		writeBridgeErr(w, http.StatusBadRequest, err)
		return
	}
	closed := s.tunnels.CloseTunnel(strings.TrimSpace(req.ID))
	if !closed {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "tunnel not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "closed_id": req.ID})
}

type workspaceReq struct {
	Workspace string `json:"workspace"`
	Strict    bool   `json:"strict"`
}

func (s *BridgeServer) handleGrabmanDoctor(w http.ResponseWriter, r *http.Request) {
	var req workspaceReq
	if err := decodeJSON(r, &req); err != nil {
		writeBridgeErr(w, http.StatusBadRequest, err)
		return
	}
	rep, code, err := localcli.Doctor(r.Context(), s.grabmanBin, req.Workspace, s.grabBin, req.Strict)
	if err != nil {
		writeBridgeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": code == 0, "exit_code": code, "report": rep})
}

func (s *BridgeServer) handleGrabmanSolveVerify(w http.ResponseWriter, r *http.Request) {
	var req workspaceReq
	if err := decodeJSON(r, &req); err != nil {
		writeBridgeErr(w, http.StatusBadRequest, err)
		return
	}
	rep, code, err := localcli.SolveVerify(r.Context(), s.grabmanBin, req.Workspace)
	if err != nil {
		writeBridgeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	status := http.StatusOK
	if code != 0 {
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, map[string]any{"ok": code == 0, "exit_code": code, "result": rep})
}

type dnaPreviewReq struct {
	OldDNAFile string `json:"old_dna_file"`
	NewDNAFile string `json:"new_dna_file"`
}

func (s *BridgeServer) handleGrabmanDNAPreview(w http.ResponseWriter, r *http.Request) {
	var req dnaPreviewReq
	if err := decodeJSON(r, &req); err != nil {
		writeBridgeErr(w, http.StatusBadRequest, err)
		return
	}
	valRes, code, err := localcli.DNAValidate(r.Context(), s.grabmanBin, req.NewDNAFile)
	if err != nil || code != 0 {
		if err == nil {
			err = fmt.Errorf("grabman dna validate failed")
		}
		writeBridgeErr(w, http.StatusUnprocessableEntity, err)
		return
	}
	var diffRes map[string]any
	if strings.TrimSpace(req.OldDNAFile) != "" {
		diffRes, _, err = localcli.DNADiff(r.Context(), s.grabmanBin, req.OldDNAFile, req.NewDNAFile)
		if err != nil {
			writeBridgeErr(w, http.StatusUnprocessableEntity, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"validation": valRes,
		"diff":       diffRes,
	})
}

type grabtacProxyReq struct {
	SSHHost            string          `json:"ssh_host"`
	SSHPort            int             `json:"ssh_port"`
	HostKeyFingerprint string          `json:"host_key_fingerprint"`
	KnownHostsLines    []string        `json:"known_hosts_lines"`
	TargetURL          string          `json:"target_url"`
	BearerToken        string          `json:"bearer_token"`
	Method             string          `json:"method"`
	APIPath            string          `json:"api_path"`
	Payload            json.RawMessage `json:"payload"`
}

func (s *BridgeServer) handleGrabtaculousProxy(w http.ResponseWriter, r *http.Request) {
	var req grabtacProxyReq
	if err := decodeJSON(r, &req); err != nil {
		writeBridgeErr(w, http.StatusBadRequest, err)
		return
	}
	ver := s.knownHosts
	if len(req.KnownHostsLines) > 0 {
		parsed, err := gssh.NewKnownHostsVerifier(req.KnownHostsLines)
		if err != nil {
			writeBridgeErr(w, http.StatusForbidden, err)
			return
		}
		ver = parsed
	}
	if _, err := s.client.VerifyHost(req.SSHHost, req.SSHPort, req.HostKeyFingerprint, ver); err != nil {
		writeBridgeErr(w, http.StatusForbidden, err)
		return
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method != "GET" && method != "POST" {
		writeBridgeErr(w, http.StatusBadRequest, fmt.Errorf("unsupported proxy method %q", req.Method))
		return
	}
	status, raw, err := s.client.ProxyGrabtaculous(r.Context(), req.TargetURL, req.BearerToken, method, req.APIPath, req.Payload)
	if err != nil {
		writeBridgeErr(w, http.StatusBadGateway, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func handleDBRoute[Req any, Res any](fn func(context.Context, Req) (Res, int, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req Req
		if err := decodeJSON(r, &req); err != nil {
			writeBridgeErr(w, http.StatusBadRequest, err)
			return
		}
		res, status, err := fn(r.Context(), req)
		if err != nil {
			writeBridgeErr(w, status, err)
			return
		}
		writeJSON(w, status, res)
	}
}

func (s *BridgeServer) handleDBSchema(ctx context.Context, req dbinspect.TargetSpec) (*dbinspect.SchemaResult, int, error) {
	return s.inspector.InspectSchema(ctx, req)
}

func (s *BridgeServer) handleDBRows(ctx context.Context, req dbinspect.RowsRequest) (*dbinspect.RowsResult, int, error) {
	return s.inspector.BrowseRows(ctx, req)
}

func (s *BridgeServer) handleDBQuery(ctx context.Context, req dbinspect.QueryRequest) (*dbinspect.QueryResult, int, error) {
	return s.inspector.RunReadOnlyQuery(ctx, req)
}

func (s *BridgeServer) handleDBMutatePlan(ctx context.Context, req dbinspect.MutatePlanRequest) (*dbinspect.MutatePlanResult, int, error) {
	return s.inspector.PlanMutation(ctx, req)
}

func (s *BridgeServer) handleDBMutateExecute(ctx context.Context, req dbinspect.MutateExecuteRequest) (*dbinspect.MutateExecuteResult, int, error) {
	return s.inspector.ExecuteMutation(ctx, req)
}

func (s *BridgeServer) handleDBExport(ctx context.Context, req dbinspect.ExportRequest) (*dbinspect.ExportResult, int, error) {
	return s.inspector.ExportSQL(ctx, req)
}

func (s *BridgeServer) handleDBRestore(ctx context.Context, req dbinspect.RestoreRequest) (*dbinspect.RestoreResult, int, error) {
	return s.inspector.RestoreSnapshot(ctx, req)
}

type dnsCredentialsPayload struct {
	APIUser  string `json:"api_user"`
	APIKey   string `json:"api_key"`
	ClientIP string `json:"client_ip"`
	Sandbox  bool   `json:"sandbox"`
}

func (p dnsCredentialsPayload) toCreds() (gdns.Credentials, error) {
	u := strings.TrimSpace(p.APIUser)
	k := strings.TrimSpace(p.APIKey)
	ip := strings.TrimSpace(p.ClientIP)
	if u == "" || k == "" || ip == "" {
		return gdns.Credentials{}, &gdns.Error{
			HTTPStatus: http.StatusUnprocessableEntity,
			Code:       gdns.ErrValidation,
			Message:    "api_user, api_key, and client_ip are required for Namecheap API access",
		}
	}
	return gdns.Credentials{
		APIUser:  u,
		APIKey:   k,
		ClientIP: ip,
		Sandbox:  p.Sandbox,
	}, nil
}

func dnsErrStatus(err error, fallback int) int {
	var de *gdns.Error
	if errors.As(err, &de) && de.HTTPStatus >= 400 {
		return de.HTTPStatus
	}
	return fallback
}

type dnsHostsRequest struct {
	Credentials dnsCredentialsPayload `json:"credentials"`
	Domain      string                `json:"domain"`
	RootDomain  string                `json:"root_domain"`
	Subdomain   string                `json:"subdomain"`
}

type dnsHostsResponse struct {
	OK         bool              `json:"ok"`
	Domain     string            `json:"domain"`
	RootDomain string            `json:"root_domain"`
	SLD        string            `json:"sld"`
	TLD        string            `json:"tld"`
	Subdomain  string            `json:"subdomain"`
	EmailType  string            `json:"email_type"`
	Hosts      []gdns.HostRecord `json:"hosts"`
}

func (s *BridgeServer) handleDNSNamecheapHosts(ctx context.Context, req dnsHostsRequest) (*dnsHostsResponse, int, error) {
	creds, err := req.Credentials.toCreds()
	if err != nil {
		return nil, dnsErrStatus(err, 422), err
	}
	fqdn, rootDomain, sld, tld, sub, err := gdns.ParseDomainParts(req.Domain, req.RootDomain, req.Subdomain)
	if err != nil {
		return nil, dnsErrStatus(err, 422), err
	}
	res, err := s.ncClient.GetHosts(ctx, creds, sld, tld)
	if err != nil {
		return nil, dnsErrStatus(err, 502), err
	}
	return &dnsHostsResponse{
		OK:         true,
		Domain:     fqdn,
		RootDomain: rootDomain,
		SLD:        sld,
		TLD:        tld,
		Subdomain:  sub,
		EmailType:  res.EmailType,
		Hosts:      res.Hosts,
	}, http.StatusOK, nil
}

type dnsPlanRequest struct {
	Credentials  dnsCredentialsPayload `json:"credentials"`
	Domain       string                `json:"domain"`
	RootDomain   string                `json:"root_domain"`
	Subdomain    string                `json:"subdomain"`
	TargetIPv4   string                `json:"target_ip"`
	TargetIPv6   string                `json:"target_ipv6"`
	TTL          string                `json:"ttl"`
	EdgeProxy    string                `json:"edge_proxy"`
	RecordMode   string                `json:"record_mode"`
	CNAMETarget  string                `json:"cname_target"`
	ConfigureWWW bool                  `json:"configure_www"`
}

type dnsPlanResponse struct {
	OK                  bool              `json:"ok"`
	Domain              string            `json:"domain"`
	RootDomain          string            `json:"root_domain"`
	SLD                 string            `json:"sld"`
	TLD                 string            `json:"tld"`
	Subdomain           string            `json:"subdomain"`
	EmailType           string            `json:"email_type"`
	ExistingHosts       []gdns.HostRecord `json:"existing_hosts"`
	MergedHosts         []gdns.HostRecord `json:"merged_hosts"`
	Diffs               []gdns.RecordDiff `json:"diffs"`
	PreservedEmailCount string            `json:"preserved_email_count"`
	PreservedOtherCount string            `json:"preserved_other_count"`
	BackupSHA256        string            `json:"backup_sha256"`
	PlainSummary        string            `json:"plain_summary"`
}

func (req dnsPlanRequest) toPlanInput() gdns.RecordPlanInput {
	return gdns.RecordPlanInput{
		Domain:       req.Domain,
		RootDomain:   req.RootDomain,
		Subdomain:    req.Subdomain,
		TargetIPv4:   req.TargetIPv4,
		TargetIPv6:   req.TargetIPv6,
		TTL:          req.TTL,
		EdgeProxy:    req.EdgeProxy,
		RecordMode:   req.RecordMode,
		CNAMETarget:  req.CNAMETarget,
		ConfigureWWW: req.ConfigureWWW,
	}
}

func managedHostsMap(subdomain string, configureWWW bool) map[string]bool {
	m := map[string]bool{strings.ToLower(strings.TrimSpace(subdomain)): true}
	if configureWWW && strings.TrimSpace(subdomain) == "@" {
		m["www"] = true
	}
	return m
}

func (s *BridgeServer) handleDNSNamecheapPlan(ctx context.Context, req dnsPlanRequest) (*dnsPlanResponse, int, error) {
	creds, err := req.Credentials.toCreds()
	if err != nil {
		return nil, dnsErrStatus(err, 422), err
	}
	_, _, sld, tld, _, err := gdns.ParseDomainParts(req.Domain, req.RootDomain, req.Subdomain)
	if err != nil {
		return nil, dnsErrStatus(err, 422), err
	}
	live, err := s.ncClient.GetHosts(ctx, creds, sld, tld)
	if err != nil {
		return nil, dnsErrStatus(err, 502), err
	}
	merged, err := gdns.MergeHostsEmailSafe(live.Hosts, live.EmailType, req.toPlanInput())
	if err != nil {
		return nil, dnsErrStatus(err, 422), err
	}
	return &dnsPlanResponse{
		OK:                  true,
		Domain:              merged.FQDN,
		RootDomain:          merged.RootDomain,
		SLD:                 merged.SLD,
		TLD:                 merged.TLD,
		Subdomain:           merged.Subdomain,
		EmailType:           merged.EmailType,
		ExistingHosts:       merged.ExistingHosts,
		MergedHosts:         merged.MergedHosts,
		Diffs:               merged.Diffs,
		PreservedEmailCount: merged.PreservedEmailCount,
		PreservedOtherCount: merged.PreservedOtherCount,
		BackupSHA256:        merged.BackupSHA256,
		PlainSummary:        merged.PlainSummary,
	}, http.StatusOK, nil
}

func (s *BridgeServer) handleDNSNamecheapApply(ctx context.Context, req dnsPlanRequest) (*dnsPlanResponse, int, error) {
	creds, err := req.Credentials.toCreds()
	if err != nil {
		return nil, dnsErrStatus(err, 422), err
	}
	_, _, sld, tld, _, err := gdns.ParseDomainParts(req.Domain, req.RootDomain, req.Subdomain)
	if err != nil {
		return nil, dnsErrStatus(err, 422), err
	}
	live, err := s.ncClient.GetHosts(ctx, creds, sld, tld)
	if err != nil {
		return nil, dnsErrStatus(err, 502), err
	}
	merged, err := gdns.MergeHostsEmailSafe(live.Hosts, live.EmailType, req.toPlanInput())
	if err != nil {
		return nil, dnsErrStatus(err, 422), err
	}
	if err := gdns.AssertEmailRecordsPreserved(live.Hosts, merged.MergedHosts, managedHostsMap(merged.Subdomain, req.ConfigureWWW)); err != nil {
		return nil, dnsErrStatus(err, 422), err
	}
	if err := s.ncClient.SetHosts(ctx, creds, merged.SLD, merged.TLD, merged.EmailType, merged.MergedHosts); err != nil {
		return nil, dnsErrStatus(err, 502), err
	}
	return &dnsPlanResponse{
		OK:                  true,
		Domain:              merged.FQDN,
		RootDomain:          merged.RootDomain,
		SLD:                 merged.SLD,
		TLD:                 merged.TLD,
		Subdomain:           merged.Subdomain,
		EmailType:           merged.EmailType,
		ExistingHosts:       merged.ExistingHosts,
		MergedHosts:         merged.MergedHosts,
		Diffs:               merged.Diffs,
		PreservedEmailCount: merged.PreservedEmailCount,
		PreservedOtherCount: merged.PreservedOtherCount,
		BackupSHA256:        merged.BackupSHA256,
		PlainSummary:        merged.PlainSummary,
	}, http.StatusOK, nil
}

type dnsRestoreRequest struct {
	Credentials   dnsCredentialsPayload `json:"credentials"`
	Domain        string                `json:"domain"`
	RootDomain    string                `json:"root_domain"`
	Subdomain     string                `json:"subdomain"`
	EmailType     string                `json:"email_type"`
	PreviousHosts []gdns.HostRecord     `json:"previous_hosts"`
}

type dnsRestoreResponse struct {
	OK           bool              `json:"ok"`
	Domain       string            `json:"domain"`
	RootDomain   string            `json:"root_domain"`
	EmailType    string            `json:"email_type"`
	BackupSHA256 string            `json:"backup_sha256"`
	Restored     []gdns.HostRecord `json:"restored_hosts"`
}

func (s *BridgeServer) handleDNSNamecheapRestore(ctx context.Context, req dnsRestoreRequest) (*dnsRestoreResponse, int, error) {
	creds, err := req.Credentials.toCreds()
	if err != nil {
		return nil, dnsErrStatus(err, 422), err
	}
	if len(req.PreviousHosts) == 0 {
		return nil, http.StatusUnprocessableEntity, &gdns.Error{
			HTTPStatus: http.StatusUnprocessableEntity,
			Code:       gdns.ErrValidation,
			Message:    "previous_hosts snapshot cannot be empty",
		}
	}
	fqdn, rootDomain, sld, tld, _, err := gdns.ParseDomainParts(req.Domain, req.RootDomain, req.Subdomain)
	if err != nil {
		return nil, dnsErrStatus(err, 422), err
	}
	if err := s.ncClient.SetHosts(ctx, creds, sld, tld, req.EmailType, req.PreviousHosts); err != nil {
		return nil, dnsErrStatus(err, 502), err
	}
	return &dnsRestoreResponse{
		OK:           true,
		Domain:       fqdn,
		RootDomain:   rootDomain,
		EmailType:    req.EmailType,
		BackupSHA256: gdns.ComputeHostsSHA256(req.PreviousHosts),
		Restored:     req.PreviousHosts,
	}, http.StatusOK, nil
}

type dnsPropagationCheckRequest struct {
	Domain             string `json:"domain"`
	ExpectedIPv4       string `json:"expected_ip"`
	ExpectedIPv6       string `json:"expected_ipv6"`
	EdgeProxy          string `json:"edge_proxy"`
	FailOnUnpropagated bool   `json:"fail_on_unpropagated"`
}

func (s *BridgeServer) handleDNSPropagationCheck(ctx context.Context, req dnsPropagationCheckRequest) (*gdns.PropagationResult, int, error) {
	res, err := gdns.CheckPropagation(ctx, gdns.PropagationRequest{
		Domain:       req.Domain,
		ExpectedIPv4: req.ExpectedIPv4,
		ExpectedIPv6: req.ExpectedIPv6,
		EdgeProxy:    req.EdgeProxy,
	}, s.dnsResolvers)
	if err != nil {
		return nil, dnsErrStatus(err, 422), err
	}
	if req.FailOnUnpropagated && !res.Propagated {
		return nil, http.StatusUnprocessableEntity, &gdns.Error{
			HTTPStatus: http.StatusUnprocessableEntity,
			Code:       gdns.ErrValidation,
			Message:    res.Message,
		}
	}
	return res, http.StatusOK, nil
}

func (s *BridgeServer) handleHTTPSVerify(ctx context.Context, req gdns.VerifyHTTPSRequest) (*gdns.VerifyHTTPSResult, int, error) {
	if strings.TrimSpace(req.HTTPSProbeURL) == "" && s.httpsProbeURL != "" {
		req.HTTPSProbeURL = s.httpsProbeURL
	}
	if strings.TrimSpace(req.TrustedCertPEM) == "" && s.trustedCertPEM != "" {
		req.TrustedCertPEM = s.trustedCertPEM
	}
	res, err := gdns.VerifyReadyAndTLS(ctx, req)
	if err != nil {
		return nil, dnsErrStatus(err, 502), err
	}
	return res, http.StatusOK, nil
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeBridgeErr(w http.ResponseWriter, status int, err error) {
	payload := map[string]any{"ok": false, "error": err.Error()}
	var be *gssh.BridgeError
	if errors.As(err, &be) {
		payload["code"] = be.Code
	}
	var ie *dbinspect.InspectorError
	if errors.As(err, &ie) {
		payload["code"] = ie.Code
	}
	var de *gdns.Error
	if errors.As(err, &de) {
		payload["code"] = de.Code
		if de.HTTPStatus >= 400 {
			status = de.HTTPStatus
		}
	}
	writeJSON(w, status, payload)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	raw, err := json.Marshal(payload)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"ok":false,"error":"internal JSON error"}` + "\n"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(raw, '\n'))
}

func main() {
	listenAddr := flag.String("listen", defaultListenAddr, "Strictly 127.0.0.1:<port> loopback bind address")
	knownHostsFile := flag.String("known-hosts", "", "Optional OpenSSH known_hosts file path")
	grabmanBin := flag.String("grabman-bin", "", "Optional grabman binary path")
	grabtacBin := flag.String("grabtaculous-bin", "", "Optional grabtaculous binary path")
	grabBin := flag.String("grab-bin", "", "Optional GRAB binary path")
	sqliteRoot := flag.String("sqlite-root", "", "Confined SQLite storage directory (default ./storage)")
	namecheapURL := flag.String("namecheap-url", "", "Optional Namecheap API override URL (official or loopback test)")
	dnsResolvers := flag.String("dns-resolvers", "", "Optional comma-separated DNS resolver host:port list")
	showVersion := flag.Bool("version", false, "Print version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("gashboard-bridge v%s\n", Version)
		return
	}
	srv, err := NewBridgeServer(*listenAddr, "", *knownHostsFile, *grabmanBin, *grabtacBin, *grabBin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gashboard-bridge: %v\n", err)
		os.Exit(1)
	}
	if strings.TrimSpace(*sqliteRoot) != "" {
		srv.SetSQLiteRoot(*sqliteRoot)
	}
	if strings.TrimSpace(*namecheapURL) != "" {
		srv.SetNamecheapURL(*namecheapURL)
	}
	if strings.TrimSpace(*dnsResolvers) != "" {
		srv.SetDNSResolvers(parseCSV(*dnsResolvers))
	}
	fmt.Printf("gashboard-bridge v%s listening strictly on %s\n", Version, *listenAddr)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "gashboard-bridge: %v\n", err)
		os.Exit(1)
	}
}
