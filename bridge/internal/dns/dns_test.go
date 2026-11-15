package dns

import (
	"context"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestResolveNamecheapEndpointBlocksSSRF(t *testing.T) {
	if ep, err := ResolveNamecheapEndpoint("", false); err != nil || ep != NamecheapProdEndpoint {
		t.Fatalf("unexpected prod endpoint: %q err=%v", ep, err)
	}
	if ep, err := ResolveNamecheapEndpoint("", true); err != nil || ep != NamecheapSandboxEndpoint {
		t.Fatalf("unexpected sandbox endpoint: %q err=%v", ep, err)
	}
	if _, err := ResolveNamecheapEndpoint("http://169.254.169.254/latest", false); err == nil {
		t.Fatalf("expected SSRF error for metadata IP")
	}
	if _, err := ResolveNamecheapEndpoint("https://evil.example.org/xml", false); err == nil {
		t.Fatalf("expected SSRF error for arbitrary external domain")
	}
	if ep, err := ResolveNamecheapEndpoint("http://127.0.0.1:18080/xml.response", false); err != nil || !strings.HasPrefix(ep, "http://127.0.0.1:18080") {
		t.Fatalf("expected loopback endpoint to succeed, got %q err=%v", ep, err)
	}
}

func TestMergeHostsEmailSafePreservesMXTXTSPFAndDKIM(t *testing.T) {
	existing := []HostRecord{
		{HostID: "1", Name: "@", Type: "A", Address: "192.0.2.5", MXPref: "10", TTL: "1800"},
		{HostID: "2", Name: "www", Type: "A", Address: "192.0.2.5", MXPref: "10", TTL: "1800"},
		{HostID: "3", Name: "@", Type: "MX", Address: "mx1.privateemail.com.", MXPref: "10", TTL: "1800"},
		{HostID: "4", Name: "@", Type: "MX", Address: "mx2.privateemail.com.", MXPref: "20", TTL: "1800"},
		{HostID: "5", Name: "@", Type: "TXT", Address: "v=spf1 include:spf.privateemail.com ~all", MXPref: "10", TTL: "1800"},
		{HostID: "6", Name: "default._domainkey", Type: "TXT", Address: "v=DKIM1; k=rsa; p=MIIBIjAN", MXPref: "10", TTL: "1800"},
		{HostID: "7", Name: "_dmarc", Type: "TXT", Address: "v=DMARC1; p=quarantine;", MXPref: "10", TTL: "1800"},
		{HostID: "8", Name: "mail", Type: "A", Address: "198.51.100.99", MXPref: "10", TTL: "1800"},
	}

	plan, err := MergeHostsEmailSafe(existing, "MX", RecordPlanInput{
		Domain:       "example.com",
		Subdomain:    "@",
		TargetIPv4:   "198.51.100.24",
		TargetIPv6:   "2001:db8::24",
		TTL:          "300",
		EdgeProxy:    "caddy",
		ConfigureWWW: true,
	})
	if err != nil {
		t.Fatalf("MergeHostsEmailSafe: %v", err)
	}

	if plan.PreservedEmailCount != "5" {
		t.Fatalf("expected PreservedEmailCount=\"5\", got %q", plan.PreservedEmailCount)
	}
	if plan.PreservedOtherCount != "1" {
		t.Fatalf("expected PreservedOtherCount=\"1\", got %q", plan.PreservedOtherCount)
	}

	var sawApexA, sawApexAAAA, sawWWWCNAME, sawMailA, sawDKIM, sawSPF, sawMX bool
	for _, rec := range plan.MergedHosts {
		switch {
		case rec.Name == "@" && rec.Type == "A" && rec.Address == "198.51.100.24":
			sawApexA = true
		case rec.Name == "@" && rec.Type == "AAAA" && rec.Address == "2001:db8::24":
			sawApexAAAA = true
		case rec.Name == "www" && rec.Type == "CNAME" && rec.Address == "example.com.":
			sawWWWCNAME = true
		case rec.Name == "mail" && rec.Type == "A" && rec.Address == "198.51.100.99":
			sawMailA = true
		case rec.Name == "default._domainkey" && rec.Type == "TXT" && strings.Contains(rec.Address, "DKIM1"):
			sawDKIM = true
		case rec.Name == "@" && rec.Type == "TXT" && strings.Contains(rec.Address, "v=spf1"):
			sawSPF = true
		case rec.Name == "@" && rec.Type == "MX" && rec.Address == "mx1.privateemail.com.":
			sawMX = true
		}
	}
	if !sawApexA || !sawApexAAAA || !sawWWWCNAME || !sawMailA || !sawDKIM || !sawSPF || !sawMX {
		t.Fatalf("merged records missing expected entries: %+v", plan.MergedHosts)
	}
}

func TestNamecheapClientGetAndSetHostsPreservesEmail(t *testing.T) {
	var mu sync.Mutex
	storedHosts := []HostRecord{
		{HostID: "1", Name: "@", Type: "A", Address: "192.0.2.5", MXPref: "10", TTL: "1800"},
		{HostID: "2", Name: "@", Type: "MX", Address: "mx1.privateemail.com.", MXPref: "10", TTL: "1800"},
		{HostID: "3", Name: "@", Type: "TXT", Address: "v=spf1 include:spf.privateemail.com ~all", MXPref: "10", TTL: "1800"},
		{HostID: "4", Name: "default._domainkey", Type: "TXT", Address: "v=DKIM1; k=rsa; p=TEST", MXPref: "10", TTL: "1800"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		cmd := r.Form.Get("Command")
		if r.Form.Get("ApiKey") != "secret-nc-key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		mu.Lock()
		defer mu.Unlock()
		switch cmd {
		case "namecheap.domains.dns.getHosts":
			var b strings.Builder
			b.WriteString(`<?xml version="1.0" encoding="utf-8"?><ApiResponse Status="OK"><Errors/><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="example.com" EmailType="MX" IsUsingOurDNS="true">`)
			for _, h := range storedHosts {
				fmt.Fprintf(&b, `<host HostId="%s" Name="%s" Type="%s" Address="%s" MXPref="%s" TTL="%s"/>`, h.HostID, h.Name, h.Type, h.Address, h.MXPref, h.TTL)
			}
			b.WriteString(`</DomainDNSGetHostsResult></CommandResponse></ApiResponse>`)
			_, _ = w.Write([]byte(b.String()))
		case "namecheap.domains.dns.setHosts":
			var next []HostRecord
			for i := 1; ; i++ {
				hn := r.Form.Get(fmt.Sprintf("HostName%d", i))
				if hn == "" {
					break
				}
				next = append(next, HostRecord{
					HostID:  fmt.Sprintf("%d", i),
					Name:    hn,
					Type:    r.Form.Get(fmt.Sprintf("RecordType%d", i)),
					Address: r.Form.Get(fmt.Sprintf("Address%d", i)),
					MXPref:  r.Form.Get(fmt.Sprintf("MXPref%d", i)),
					TTL:     r.Form.Get(fmt.Sprintf("TTL%d", i)),
				})
			}
			storedHosts = next
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?><ApiResponse Status="OK"><Errors/><CommandResponse Type="namecheap.domains.dns.setHosts"><DomainDNSSetHostsResult Domain="example.com" IsSuccess="true"/></CommandResponse></ApiResponse>`))
		default:
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?><ApiResponse Status="ERROR"><Errors><Error Number="1">Unknown command</Error></Errors></ApiResponse>`))
		}
	}))
	defer srv.Close()

	client := NewNamecheapClient(srv.URL)
	creds := Credentials{
		APIUser:  "alice_nc",
		APIKey:   "secret-nc-key",
		ClientIP: "198.51.100.10",
		Sandbox:  true,
	}

	got, err := client.GetHosts(context.Background(), creds, "example", "com")
	if err != nil {
		t.Fatalf("GetHosts: %v", err)
	}
	plan, err := MergeHostsEmailSafe(got.Hosts, got.EmailType, RecordPlanInput{
		Domain:       "example.com",
		TargetIPv4:   "198.51.100.24",
		TTL:          "300",
		ConfigureWWW: true,
	})
	if err != nil {
		t.Fatalf("MergeHostsEmailSafe: %v", err)
	}
	if err := client.SetHosts(context.Background(), creds, plan.SLD, plan.TLD, plan.EmailType, plan.MergedHosts); err != nil {
		t.Fatalf("SetHosts: %v", err)
	}

	after, err := client.GetHosts(context.Background(), creds, "example", "com")
	if err != nil {
		t.Fatalf("GetHosts after setHosts: %v", err)
	}
	if len(after.Hosts) != 5 {
		t.Fatalf("expected 5 records after setHosts, got %d: %+v", len(after.Hosts), after.Hosts)
	}

	// Restore exact prior hosts and verify rollback.
	if err := client.SetHosts(context.Background(), creds, plan.SLD, plan.TLD, plan.EmailType, got.Hosts); err != nil {
		t.Fatalf("Restore SetHosts: %v", err)
	}
	restored, err := client.GetHosts(context.Background(), creds, "example", "com")
	if err != nil {
		t.Fatalf("GetHosts after restore: %v", err)
	}
	if len(restored.Hosts) != 4 || restored.Hosts[0].Address != "192.0.2.5" {
		t.Fatalf("unexpected restored hosts: %+v", restored.Hosts)
	}
}

func startMockUDPDNSServer(t *testing.T, initialIPv4 [4]byte) (string, func([4]byte), func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket udp: %v", err)
	}
	var mu sync.Mutex
	curIP := initialIPv4
	done := make(chan struct{})

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, rErr := pc.ReadFrom(buf)
			if rErr != nil {
				select {
				case <-done:
					return
				default:
					continue
				}
			}
			if n < 12 {
				continue
			}
			req := buf[:n]
			// Find end of QNAME
			idx := 12
			for idx < n && req[idx] != 0 {
				l := int(req[idx])
				idx += 1 + l
			}
			if idx+5 > n {
				continue
			}
			qtype := binary.BigEndian.Uint16(req[idx+1 : idx+3])
			qEnd := idx + 5

			resp := make([]byte, 0, qEnd+16)
			resp = append(resp, req[:qEnd]...)
			// Flags: standard response, no error (0x8180)
			binary.BigEndian.PutUint16(resp[2:4], 0x8180)
			// QDCOUNT = 1
			binary.BigEndian.PutUint16(resp[4:6], 1)

			mu.Lock()
			ipBytes := curIP
			mu.Unlock()

			if qtype == 1 { // A record
				binary.BigEndian.PutUint16(resp[6:8], 1) // ANCOUNT = 1
				resp = append(resp, 0xc0, 0x0c)          // Name pointer to offset 12
				resp = append(resp, 0x00, 0x01)          // Type A
				resp = append(resp, 0x00, 0x01)          // Class IN
				resp = append(resp, 0x00, 0x00, 0x00, 0x3c)
				resp = append(resp, 0x00, 0x04) // RDLENGTH 4
				resp = append(resp, ipBytes[:]...)
			} else {
				binary.BigEndian.PutUint16(resp[6:8], 0)
			}
			_, _ = pc.WriteTo(resp, addr)
		}
	}()

	setIP := func(next [4]byte) {
		mu.Lock()
		curIP = next
		mu.Unlock()
	}
	stop := func() {
		close(done)
		_ = pc.Close()
	}
	return pc.LocalAddr().String(), setIP, stop
}

func TestDNSPropagationGuardAndVerifyReadyTLS(t *testing.T) {
	dnsAddr, setIP, stopDNS := startMockUDPDNSServer(t, [4]byte{192, 0, 2, 99})
	defer stopDNS()

	// Before propagation -> propagated: false (blocks ACME)
	resPre, err := CheckPropagation(context.Background(), PropagationRequest{
		Domain:       "shop.example.com",
		ExpectedIPv4: "198.51.100.24",
		EdgeProxy:    "caddy",
	}, []string{dnsAddr})
	if err != nil {
		t.Fatalf("CheckPropagation pre: %v", err)
	}
	if resPre.Propagated {
		t.Fatalf("expected Propagated=false before DNS cutover, got %+v", resPre)
	}

	// After propagation -> propagated: true
	setIP([4]byte{198, 51, 100, 24})
	resPost, err := CheckPropagation(context.Background(), PropagationRequest{
		Domain:       "shop.example.com",
		ExpectedIPv4: "198.51.100.24",
		EdgeProxy:    "caddy",
	}, []string{dnsAddr})
	if err != nil {
		t.Fatalf("CheckPropagation post: %v", err)
	}
	if !resPost.Propagated {
		t.Fatalf("expected Propagated=true after DNS cutover, got %+v", resPost)
	}

	// Spin up real loopback HTTPS /_ready TLS server
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_ready" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true,"ready":true}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer tlsSrv.Close()

	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsSrv.Certificate().Raw}))
	verRes, err := VerifyReadyAndTLS(context.Background(), VerifyHTTPSRequest{
		Domain:           "shop.example.com",
		EdgeProxy:        "caddy",
		UpstreamReadyURL: tlsSrv.URL + "/_ready", // wait - validate TLS probe URL directly
	})
	if err == nil && verRes != nil {
		// note: ValidateLoopbackURL allows https loopback too!
	}

	verRes, err = VerifyReadyAndTLS(context.Background(), VerifyHTTPSRequest{
		Domain:         "shop.example.com",
		EdgeProxy:      "caddy",
		HTTPSProbeURL:  tlsSrv.URL + "/_ready",
		TrustedCertPEM: certPEM,
	})
	if err != nil {
		t.Fatalf("VerifyReadyAndTLS: %v", err)
	}
	if !verRes.TLSVerified || verRes.ReadyStatus != "200" {
		t.Fatalf("expected TLSVerified=true & ReadyStatus=200, got %+v", verRes)
	}
}
