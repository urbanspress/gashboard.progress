package dns

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	NamecheapProdEndpoint    = "https://api.namecheap.com/xml.response"
	NamecheapSandboxEndpoint = "https://api.sandbox.namecheap.com/xml.response"

	ErrValidation  = "GASH-E422"
	ErrSSRFBlocked = "GASH-E501"
	ErrDNSGateway  = "GASH-E502"
)

// Error represents a structured DNS client or validation error with an error code and HTTP status.
type Error struct {
	HTTPStatus int
	Code       string
	Message    string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func newErr(status int, code, msg string) *Error {
	return &Error{HTTPStatus: status, Code: code, Message: msg}
}

var reDomainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var reHostRecordName = regexp.MustCompile(`^(?:@|\*|[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*)$`)

// Credentials carries decrypted Namecheap credentials strictly in memory for outbound API calls.
// Zero fields may ever be logged or serialized into HTTP responses.
type Credentials struct {
	APIUser  string
	APIKey   string
	ClientIP string
	Sandbox  bool
}

// HostRecord mirrors one Namecheap domain DNS host entry.
type HostRecord struct {
	HostID             string `json:"host_id,omitempty"`
	Name               string `json:"name"`
	Type               string `json:"type"`
	Address            string `json:"address"`
	MXPref             string `json:"mx_pref,omitempty"`
	TTL                string `json:"ttl"`
	AssociatedAppTitle string `json:"associated_app_title,omitempty"`
	FriendlyName       string `json:"friendly_name,omitempty"`
	IsActive           string `json:"is_active,omitempty"`
	IsDDNSEnabled      string `json:"is_ddns_enabled,omitempty"`
}

// RecordPlanInput describes the desired web host DNS changes for a domain.
type RecordPlanInput struct {
	Domain       string `json:"domain"`
	RootDomain   string `json:"root_domain"`
	Subdomain    string `json:"subdomain"`
	TargetIPv4   string `json:"target_ip"`
	TargetIPv6   string `json:"target_ipv6"`
	TTL          string `json:"ttl"`
	EdgeProxy    string `json:"edge_proxy"`
	RecordMode   string `json:"record_mode"`
	CNAMETarget  string `json:"cname_target"`
	ConfigureWWW bool   `json:"configure_www"`
}

// RecordDiff summarizes one before/after DNS change or preserved email record in plain English.
type RecordDiff struct {
	Action          string `json:"action"`
	Name            string `json:"name"`
	Type            string `json:"type"`
	PreviousAddress string `json:"previous_address"`
	NextAddress     string `json:"next_address"`
	TTL             string `json:"ttl"`
	Reason          string `json:"reason"`
}

// MergedPlan captures the full email-safe DNS diff and exact pre-write snapshot digest.
type MergedPlan struct {
	FQDN                string       `json:"domain"`
	RootDomain          string       `json:"root_domain"`
	SLD                 string       `json:"sld"`
	TLD                 string       `json:"tld"`
	Subdomain           string       `json:"subdomain"`
	EmailType           string       `json:"email_type"`
	ExistingHosts       []HostRecord `json:"existing_hosts"`
	MergedHosts         []HostRecord `json:"merged_hosts"`
	Diffs               []RecordDiff `json:"diffs"`
	PreservedEmailCount string       `json:"preserved_email_count"`
	PreservedOtherCount string       `json:"preserved_other_count"`
	BackupSHA256        string       `json:"backup_sha256"`
	PlainSummary        string       `json:"plain_summary"`
}

// GetHostsResult holds parsed records returned by namecheap.domains.dns.getHosts.
type GetHostsResult struct {
	Domain    string       `json:"domain"`
	EmailType string       `json:"email_type"`
	Hosts     []HostRecord `json:"hosts"`
}

// ResolveNamecheapEndpoint validates that Namecheap calls strictly target official endpoints
// or an explicitly configured loopback test endpoint (preventing SSRF credential exfiltration).
func ResolveNamecheapEndpoint(overrideURL string, sandbox bool) (string, error) {
	trimmed := strings.TrimSpace(overrideURL)
	if trimmed == "" {
		if sandbox {
			return NamecheapSandboxEndpoint, nil
		}
		return NamecheapProdEndpoint, nil
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", newErr(422, ErrSSRFBlocked, fmt.Sprintf("invalid Namecheap API endpoint %q", overrideURL))
	}
	lowerHost := strings.ToLower(u.Hostname())
	if (lowerHost == "api.namecheap.com" || lowerHost == "api.sandbox.namecheap.com") && u.Scheme == "https" {
		return u.String(), nil
	}
	if u.Scheme == "http" || u.Scheme == "https" {
		if lowerHost == "localhost" {
			return u.String(), nil
		}
		if ip := net.ParseIP(lowerHost); ip != nil && ip.IsLoopback() {
			return u.String(), nil
		}
	}
	return "", newErr(403, ErrSSRFBlocked, fmt.Sprintf("blocked non-allowlisted Namecheap endpoint host %q (SSRF protection)", lowerHost))
}

// ValidateDomain checks that raw is a valid ASCII DNS hostname.
func ValidateDomain(raw string) (string, error) {
	clean := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if len(clean) < 3 || len(clean) > 253 {
		return "", newErr(422, ErrValidation, fmt.Sprintf("invalid domain name %q", raw))
	}
	labels := strings.Split(clean, ".")
	if len(labels) < 2 {
		return "", newErr(422, ErrValidation, fmt.Sprintf("domain %q must include a TLD (e.g. example.com)", raw))
	}
	for _, lbl := range labels {
		if !reDomainLabel.MatchString(lbl) {
			return "", newErr(422, ErrValidation, fmt.Sprintf("invalid hostname label %q in domain %q", lbl, raw))
		}
	}
	return clean, nil
}

// ParseDomainParts splits a domain + optional rootDomain/subdomain into Namecheap SLD, TLD, host label, and FQDN.
func ParseDomainParts(domainRaw, rootDomainRaw, subdomainRaw string) (fqdn, rootDomain, sld, tld, hostLabel string, err error) {
	cleanSub := strings.ToLower(strings.TrimSpace(subdomainRaw))
	cleanDomain := ""
	if strings.TrimSpace(domainRaw) != "" {
		cleanDomain, err = ValidateDomain(domainRaw)
		if err != nil {
			return "", "", "", "", "", err
		}
	}
	cleanRoot := ""
	if strings.TrimSpace(rootDomainRaw) != "" {
		cleanRoot, err = ValidateDomain(rootDomainRaw)
		if err != nil {
			return "", "", "", "", "", err
		}
	}

	if cleanRoot == "" {
		if cleanDomain == "" {
			return "", "", "", "", "", newErr(422, ErrValidation, "domain or root_domain is required")
		}
		labels := strings.Split(cleanDomain, ".")
		if len(labels) >= 3 && (cleanSub == "" || cleanSub == labels[0]) {
			if cleanSub == "" {
				cleanSub = labels[0]
			}
			cleanRoot = strings.Join(labels[1:], ".")
		} else {
			cleanRoot = cleanDomain
			if cleanSub == "" {
				cleanSub = "@"
			}
		}
	} else {
		if cleanSub == "" {
			if cleanDomain != "" && cleanDomain != cleanRoot && strings.HasSuffix(cleanDomain, "."+cleanRoot) {
				cleanSub = strings.TrimSuffix(cleanDomain, "."+cleanRoot)
			} else {
				cleanSub = "@"
			}
		}
	}

	if cleanSub != "@" {
		for _, lbl := range strings.Split(cleanSub, ".") {
			if !reDomainLabel.MatchString(lbl) {
				return "", "", "", "", "", newErr(422, ErrValidation, fmt.Sprintf("invalid subdomain label %q", cleanSub))
			}
		}
	}

	rootLabels := strings.Split(cleanRoot, ".")
	if len(rootLabels) < 2 {
		return "", "", "", "", "", newErr(422, ErrValidation, fmt.Sprintf("invalid root domain %q", cleanRoot))
	}
	sld = rootLabels[0]
	tld = strings.Join(rootLabels[1:], ".")

	if cleanSub == "@" {
		fqdn = cleanRoot
	} else {
		fqdn = cleanSub + "." + cleanRoot
	}
	return fqdn, cleanRoot, sld, tld, cleanSub, nil
}

// NamecheapClient communicates with Namecheap's XML DNS API using form-encoded POST requests.
type NamecheapClient struct {
	httpClient  *http.Client
	overrideURL string
}

// NewNamecheapClient constructs a Namecheap client with bounded timeouts and optional loopback test endpoint.
func NewNamecheapClient(overrideURL string) *NamecheapClient {
	return &NamecheapClient{
		httpClient:  &http.Client{Timeout: 20 * time.Second},
		overrideURL: strings.TrimSpace(overrideURL),
	}
}

// SetOverrideURL updates the configured Namecheap endpoint override (e.g., for local loopback testing).
func (c *NamecheapClient) SetOverrideURL(raw string) {
	c.overrideURL = strings.TrimSpace(raw)
}

type xmlApiResponse struct {
	XMLName          xml.Name          `xml:"ApiResponse"`
	Status           string            `xml:"Status,attr"`
	Errors           []xmlApiError     `xml:"Errors>Error"`
	RequestedCommand string            `xml:"RequestedCommand"`
	CommandResponse  xmlCommandWrapper `xml:"CommandResponse"`
}

type xmlApiError struct {
	Number  string `xml:"Number,attr"`
	Message string `xml:",chardata"`
}

type xmlCommandWrapper struct {
	Type          string                 `xml:"Type,attr"`
	GetHosts      *xmlGetHostsResult     `xml:"DomainDNSGetHostsResult"`
	SetHosts      *xmlSetHostsResult     `xml:"DomainDNSSetHostsResult"`
}

type xmlGetHostsResult struct {
	Domain        string       `xml:"Domain,attr"`
	EmailType     string       `xml:"EmailType,attr"`
	IsUsingOurDNS string       `xml:"IsUsingOurDNS,attr"`
	Hosts         []xmlDNSHost `xml:"host"`
}

type xmlSetHostsResult struct {
	Domain    string `xml:"Domain,attr"`
	IsSuccess string `xml:"IsSuccess,attr"`
}

type xmlDNSHost struct {
	HostID             string `xml:"HostId,attr"`
	Name               string `xml:"Name,attr"`
	Type               string `xml:"Type,attr"`
	Address            string `xml:"Address,attr"`
	MXPref             string `xml:"MXPref,attr"`
	TTL                string `xml:"TTL,attr"`
	AssociatedAppTitle string `xml:"AssociatedAppTitle,attr"`
	FriendlyName       string `xml:"FriendlyName,attr"`
	IsActive           string `xml:"IsActive,attr"`
	IsDDNSEnabled      string `xml:"IsDDNSEnabled,attr"`
}

func validateCreds(creds Credentials) error {
	if strings.TrimSpace(creds.APIUser) == "" || strings.TrimSpace(creds.APIKey) == "" {
		return newErr(422, ErrValidation, "Namecheap API user and API key are required")
	}
	ip := net.ParseIP(strings.TrimSpace(creds.ClientIP))
	if ip == nil {
		return newErr(422, ErrValidation, "Namecheap whitelisted Client IP must be a valid IPv4 or IPv6 address")
	}
	return nil
}

func scrubSecretError(err error, creds Credentials) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	for _, secret := range []string{creds.APIKey, creds.APIUser, creds.ClientIP} {
		s := strings.TrimSpace(secret)
		if s != "" {
			msg = strings.ReplaceAll(msg, s, "[REDACTED]")
		}
	}
	return msg
}

func (c *NamecheapClient) postFormXML(ctx context.Context, creds Credentials, form url.Values) (*xmlApiResponse, error) {
	if err := validateCreds(creds); err != nil {
		return nil, err
	}
	endpoint, err := ResolveNamecheapEndpoint(c.overrideURL, creds.Sandbox)
	if err != nil {
		return nil, err
	}

	form.Set("ApiUser", strings.TrimSpace(creds.APIUser))
	form.Set("ApiKey", strings.TrimSpace(creds.APIKey))
	form.Set("UserName", strings.TrimSpace(creds.APIUser))
	form.Set("ClientIp", strings.TrimSpace(creds.ClientIP))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, newErr(502, ErrDNSGateway, "failed constructing Namecheap API request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/xml, text/xml")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, newErr(502, ErrDNSGateway, fmt.Sprintf("Namecheap API request failed: %s", scrubSecretError(err, creds)))
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, newErr(502, ErrDNSGateway, "failed reading Namecheap API response")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, newErr(502, ErrDNSGateway, fmt.Sprintf("Namecheap HTTP %d", resp.StatusCode))
	}

	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = true
	var parsed xmlApiResponse
	if err := dec.Decode(&parsed); err != nil {
		return nil, newErr(502, ErrDNSGateway, fmt.Sprintf("malformed Namecheap XML response: %v", err))
	}
	if !strings.EqualFold(strings.TrimSpace(parsed.Status), "OK") {
		var parts []string
		for _, e := range parsed.Errors {
			parts = append(parts, fmt.Sprintf("[%s] %s", strings.TrimSpace(e.Number), strings.TrimSpace(e.Message)))
		}
		if len(parts) == 0 {
			parts = append(parts, "Namecheap returned ERROR status")
		}
		return nil, newErr(422, ErrValidation, scrubSecretError(errors.New(strings.Join(parts, "; ")), creds))
	}
	return &parsed, nil
}

// GetHosts retrieves all existing DNS host records for sld.tld via namecheap.domains.dns.getHosts.
func (c *NamecheapClient) GetHosts(ctx context.Context, creds Credentials, sld, tld string) (GetHostsResult, error) {
	form := url.Values{}
	form.Set("Command", "namecheap.domains.dns.getHosts")
	form.Set("SLD", strings.TrimSpace(sld))
	form.Set("TLD", strings.TrimSpace(tld))

	parsed, err := c.postFormXML(ctx, creds, form)
	if err != nil {
		return GetHostsResult{}, err
	}
	if parsed.CommandResponse.GetHosts == nil {
		return GetHostsResult{}, newErr(502, ErrDNSGateway, "Namecheap response missing DomainDNSGetHostsResult")
	}
	gh := parsed.CommandResponse.GetHosts
	out := make([]HostRecord, 0, len(gh.Hosts))
	for _, h := range gh.Hosts {
		ttl := strings.TrimSpace(h.TTL)
		if ttl == "" {
			ttl = "1800"
		}
		mx := strings.TrimSpace(h.MXPref)
		if mx == "" {
			mx = "10"
		}
		out = append(out, HostRecord{
			HostID:             strings.TrimSpace(h.HostID),
			Name:               strings.TrimSpace(h.Name),
			Type:               strings.ToUpper(strings.TrimSpace(h.Type)),
			Address:            strings.TrimSpace(h.Address),
			MXPref:             mx,
			TTL:                ttl,
			AssociatedAppTitle: strings.TrimSpace(h.AssociatedAppTitle),
			FriendlyName:       strings.TrimSpace(h.FriendlyName),
			IsActive:           strings.TrimSpace(h.IsActive),
			IsDDNSEnabled:      strings.TrimSpace(h.IsDDNSEnabled),
		})
	}
	return GetHostsResult{
		Domain:    strings.TrimSpace(gh.Domain),
		EmailType: strings.TrimSpace(gh.EmailType),
		Hosts:     out,
	}, nil
}

// SetHosts writes the complete host record list via namecheap.domains.dns.setHosts.
func (c *NamecheapClient) SetHosts(ctx context.Context, creds Credentials, sld, tld, emailType string, hosts []HostRecord) error {
	if len(hosts) == 0 {
		return newErr(422, ErrValidation, "refusing to call setHosts with empty host record list")
	}
	form := url.Values{}
	form.Set("Command", "namecheap.domains.dns.setHosts")
	form.Set("SLD", strings.TrimSpace(sld))
	form.Set("TLD", strings.TrimSpace(tld))
	if et := strings.TrimSpace(emailType); et != "" {
		form.Set("EmailType", et)
	}
	for i, h := range hosts {
		idx := strconv.Itoa(i + 1)
		name := strings.TrimSpace(h.Name)
		if !reHostRecordName.MatchString(name) {
			return newErr(422, ErrValidation, fmt.Sprintf("unsafe DNS host name %q", h.Name))
		}
		recType := strings.ToUpper(strings.TrimSpace(h.Type))
		ttl := strings.TrimSpace(h.TTL)
		if ttl == "" {
			ttl = "300"
		}
		mxPref := strings.TrimSpace(h.MXPref)
		if mxPref == "" {
			mxPref = "10"
		}
		form.Set("HostName"+idx, name)
		form.Set("RecordType"+idx, recType)
		form.Set("Address"+idx, strings.TrimSpace(h.Address))
		form.Set("TTL"+idx, ttl)
		if recType == "MX" || recType == "MXE" {
			form.Set("MXPref"+idx, mxPref)
		}
	}

	parsed, err := c.postFormXML(ctx, creds, form)
	if err != nil {
		return err
	}
	if parsed.CommandResponse.SetHosts != nil {
		okStr := strings.TrimSpace(parsed.CommandResponse.SetHosts.IsSuccess)
		if okStr != "" && !strings.EqualFold(okStr, "true") {
			return newErr(502, ErrDNSGateway, "Namecheap setHosts reported IsSuccess=false")
		}
	}
	return nil
}

// IsEmailOrProtectedRecord returns true for records that must never be altered or dropped by web DNS automation.
func IsEmailOrProtectedRecord(rec HostRecord) bool {
	switch strings.ToUpper(strings.TrimSpace(rec.Type)) {
	case "MX", "MXE", "TXT", "SRV", "CAA", "NS", "URL", "URL301", "FRAME":
		return true
	default:
		return false
	}
}

func hostSignature(h HostRecord) string {
	mx := strings.TrimSpace(h.MXPref)
	if mx == "" {
		mx = "10"
	}
	ttl := strings.TrimSpace(h.TTL)
	if ttl == "" {
		ttl = "1800"
	}
	return strings.ToLower(strings.TrimSpace(h.Name)) + "|" +
		strings.ToUpper(strings.TrimSpace(h.Type)) + "|" +
		strings.TrimSpace(h.Address) + "|" +
		mx + "|" + ttl
}

// AssertEmailRecordsPreserved verifies fail-closed that every MX, TXT (SPF/DKIM/DMARC), SRV, CAA,
// and unrelated host record in before exists byte-identical in after.
func AssertEmailRecordsPreserved(before, after []HostRecord, managedWebHosts map[string]bool) error {
	afterCounts := make(map[string]int, len(after))
	for _, h := range after {
		afterCounts[hostSignature(h)]++
	}
	for _, h := range before {
		isWebType := false
		switch strings.ToUpper(strings.TrimSpace(h.Type)) {
		case "A", "AAAA", "CNAME":
			isWebType = true
		}
		if IsEmailOrProtectedRecord(h) || !isWebType || !managedWebHosts[strings.ToLower(strings.TrimSpace(h.Name))] {
			sig := hostSignature(h)
			if afterCounts[sig] <= 0 {
				return newErr(422, ErrValidation, fmt.Sprintf("email-safe preservation invariant failed: record %s %s (%s) would be modified or removed", h.Type, h.Name, h.Address))
			}
			afterCounts[sig]--
		}
	}
	return nil
}

// ComputeHostsSHA256 computes a deterministic SHA-256 digest of a HostRecord list.
func ComputeHostsSHA256(hosts []HostRecord) string {
	raw, _ := json.Marshal(hosts)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// MergeHostsEmailSafe computes a deterministic email-preserving DNS update plan from live Namecheap records.
func MergeHostsEmailSafe(existing []HostRecord, emailType string, plan RecordPlanInput) (MergedPlan, error) {
	fqdn, rootDomain, sld, tld, hostLabel, err := ParseDomainParts(plan.Domain, plan.RootDomain, plan.Subdomain)
	if err != nil {
		return MergedPlan{}, err
	}

	ttlStr := strings.TrimSpace(plan.TTL)
	if ttlStr == "" {
		ttlStr = "300"
	}
	ttlInt, tErr := strconv.Atoi(ttlStr)
	if tErr != nil || ttlInt < 60 || ttlInt > 86400 {
		return MergedPlan{}, newErr(422, ErrValidation, "ttl must be an exact integer string between 60 and 86400")
	}

	mode := strings.ToLower(strings.TrimSpace(plan.RecordMode))
	if mode == "" {
		mode = "a"
	}

	ip4 := strings.TrimSpace(plan.TargetIPv4)
	if mode != "cname" {
		parsed4 := net.ParseIP(ip4)
		if parsed4 == nil || parsed4.To4() == nil {
			return MergedPlan{}, newErr(422, ErrValidation, fmt.Sprintf("invalid IPv4 target_ip %q", plan.TargetIPv4))
		}
		ip4 = parsed4.To4().String()
	}

	ip6 := strings.TrimSpace(plan.TargetIPv6)
	if ip6 != "" {
		parsed6 := net.ParseIP(ip6)
		if parsed6 == nil || parsed6.To4() != nil {
			return MergedPlan{}, newErr(422, ErrValidation, fmt.Sprintf("invalid IPv6 target_ipv6 %q", plan.TargetIPv6))
		}
		ip6 = parsed6.String()
	}

	cnameTarget := strings.TrimSpace(plan.CNAMETarget)
	if mode == "cname" {
		if hostLabel == "@" {
			return MergedPlan{}, newErr(422, ErrValidation, "root apex '@' cannot use CNAME mode in standard DNS; use A/AAAA")
		}
		cleanTarget, cErr := ValidateDomain(cnameTarget)
		if cErr != nil {
			return MergedPlan{}, newErr(422, ErrValidation, fmt.Sprintf("invalid cname_target %q", plan.CNAMETarget))
		}
		cnameTarget = cleanTarget + "."
	}

	managedHosts := map[string]bool{
		strings.ToLower(hostLabel): true,
	}
	if plan.ConfigureWWW && hostLabel == "@" {
		managedHosts["www"] = true
	}

	merged := make([]HostRecord, 0, len(existing)+4)
	diffs := make([]RecordDiff, 0, len(existing)+4)
	preservedEmailCount := 0
	preservedOtherCount := 0
	prevByHostType := make(map[string]HostRecord)

	for _, h := range existing {
		normType := strings.ToUpper(strings.TrimSpace(h.Type))
		normName := strings.ToLower(strings.TrimSpace(h.Name))
		isWebType := normType == "A" || normType == "AAAA" || normType == "CNAME"

		if IsEmailOrProtectedRecord(h) {
			merged = append(merged, h)
			preservedEmailCount++
			diffs = append(diffs, RecordDiff{
				Action:          "keep_email",
				Name:            h.Name,
				Type:            normType,
				PreviousAddress: h.Address,
				NextAddress:     h.Address,
				TTL:             h.TTL,
				Reason:          "Preserved intact (email/verification record)",
			})
			continue
		}
		if !isWebType || !managedHosts[normName] {
			merged = append(merged, h)
			preservedOtherCount++
			diffs = append(diffs, RecordDiff{
				Action:          "keep_other",
				Name:            h.Name,
				Type:            normType,
				PreviousAddress: h.Address,
				NextAddress:     h.Address,
				TTL:             h.TTL,
				Reason:          "Preserved intact (unrelated host record)",
			})
			continue
		}
		prevByHostType[normName+"|"+normType] = h
	}

	addOrUpdateWeb := func(name, recType, addr, reason string) {
		prev, existed := prevByHostType[strings.ToLower(name)+"|"+recType]
		action := "add"
		prevAddr := ""
		if existed {
			action = "update"
			prevAddr = prev.Address
			if prev.Address == addr && prev.TTL == ttlStr {
				action = "unchanged"
			}
		}
		merged = append(merged, HostRecord{
			Name:    name,
			Type:    recType,
			Address: addr,
			MXPref:  "10",
			TTL:     ttlStr,
		})
		diffs = append(diffs, RecordDiff{
			Action:          action,
			Name:            name,
			Type:            recType,
			PreviousAddress: prevAddr,
			NextAddress:     addr,
			TTL:             ttlStr,
			Reason:          reason,
		})
	}

	if mode == "cname" {
		addOrUpdateWeb(hostLabel, "CNAME", cnameTarget, fmt.Sprintf("Point %s to %s", fqdn, cnameTarget))
	} else {
		addOrUpdateWeb(hostLabel, "A", ip4, fmt.Sprintf("Point %s to target VPS IPv4 %s", fqdn, ip4))
		if ip6 != "" {
			addOrUpdateWeb(hostLabel, "AAAA", ip6, fmt.Sprintf("Point %s to target VPS IPv6 %s", fqdn, ip6))
		}
	}

	if plan.ConfigureWWW && hostLabel == "@" {
		wwwTarget := rootDomain + "."
		addOrUpdateWeb("www", "CNAME", wwwTarget, fmt.Sprintf("Point www.%s to %s", rootDomain, rootDomain))
	}

	if err := AssertEmailRecordsPreserved(existing, merged, managedHosts); err != nil {
		return MergedPlan{}, err
	}

	backupSHA := ComputeHostsSHA256(existing)
	summary := fmt.Sprintf(
		"Configure %s (%s) pointing to %s while preserving %d email/TXT records and %d unrelated host records intact.",
		fqdn,
		strings.ToUpper(mode),
		ip4,
		preservedEmailCount,
		preservedOtherCount,
	)
	if mode == "cname" {
		summary = fmt.Sprintf(
			"Configure %s (CNAME -> %s) while preserving %d email/TXT records and %d unrelated host records intact.",
			fqdn,
			cnameTarget,
			preservedEmailCount,
			preservedOtherCount,
		)
	}

	return MergedPlan{
		FQDN:                fqdn,
		RootDomain:          rootDomain,
		SLD:                 sld,
		TLD:                 tld,
		Subdomain:           hostLabel,
		EmailType:           emailType,
		ExistingHosts:       existing,
		MergedHosts:         merged,
		Diffs:               diffs,
		PreservedEmailCount: strconv.Itoa(preservedEmailCount),
		PreservedOtherCount: strconv.Itoa(preservedOtherCount),
		BackupSHA256:        backupSHA,
		PlainSummary:        summary,
	}, nil
}
