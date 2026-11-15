# GASHBOARD-SPEC-003: Gashboard `v0.3.0` — Namecheap DNS + Auto-HTTPS Wizard

- **Status:** Specification in Review (Awaiting Project-Owner Approval — zero `v0.3.0` application code written)
- **Milestone:** `v0.3.0` — Step 5 Zero-Guesswork Domain DNS & Automatic HTTPS Orchestration
- **Foundational Upstream & Peer Baselines:**
  - **GRAB:** `v1.1.0` (`urbanspress/grab` — `use server`, `use data`, `use cache`, `use http`, `use json`, `use crypto` AES-256-GCM, `use env`, `ADR-005`, `ADR-017`, `ADR-025c`)
  - **Grex JS:** `v1.0.0` (`urbanspress/grex-js` — 20 semantic elements, `signal`/`computed`/`effect`, `setSafeText`, `validateElementNode()`, `auditAccessibility()`, zero wrapper-`<div>` DOM)
  - **`grabman` & Grabtaculous:** `v0.1.0` (`urbanspress/grabman`, `urbanspress/grabtaculous` — `grabtaculousd` Caddy / Nginx+Certbot / Cloudflare Tunnel edge config, Pre-Deploy Snapshots, rollback over `127.0.0.1` SSH)
  - **Gashboard:** `v0.1.0` & `v0.2.0` ([`GASHBOARD-SPEC-001.md`](GASHBOARD-SPEC-001.md), [`GASHBOARD-SPEC-002.md`](GASHBOARD-SPEC-002.md))
- **Governance:** Read alongside [`GASHBOARD-EXPERT.md`](../GASHBOARD-EXPERT.md), [`AGENTS.md`](../AGENTS.md), and [`docs/ROADMAP.md`](../docs/ROADMAP.md).

---

## 1. Purpose & `v0.3.0` Scope

**Gashboard `v0.3.0`** eliminates manual DNS registrar copy-pasting and Let's Encrypt certificate lockouts for non-coders and operators by introducing a guided **Namecheap DNS + Auto-HTTPS Wizard**. Users securely store their Namecheap API credentials in Gashboard's encrypted local vault, configure domain `A`/`AAAA`/`CNAME` records in 1 click without touching existing email records (`MX`/`TXT`/`SPF`/`DKIM`), verify live DNS propagation before ACME runs, and wire HTTPS cleanly through **Grabtaculous** with 1-click rollback.

### Included in `v0.3.0`
1. **Encrypted Namecheap Credential Vault (`src/gashboard.grab`, `migrations/003_dns_vault.grab`):**
   - Stores Namecheap **API User**, **API Key**, and **Whitelisted Client IP** encrypted at rest in SQLite via **GRAB `v1.1.0`** `use crypto` (`crypto.encrypt_aead` AES-256-GCM) keyed from `GASHBOARD_MASTER_KEY` (`use env`).
   - Credentials are **never** returned in plaintext to the browser DOM, URL query strings, or server logs (`GET /api/dns/namecheap/status` returns only masked metadata such as `configured: true`, `api_user_masked`, and `client_ip`).

2. **1-Click DNS Record Provisioner & Email-Safe Merge (`public/gashboard/dns-https-wizard.js`, `bridge/internal/dns/`):**
   - Pure **`Grex JS v1.0.0`** semantic wizard (`divCount === 0`, `innerHTMLWriteCount === 0`, `100%` WCAG AA contrast & keyboard navigation).
   - Inspects existing domain host records via Namecheap `namecheap.domains.dns.getHosts`.
   - Computes a plain-English diff plan to configure `A`, `AAAA` (when IPv6 is present on the target VPS), and `CNAME` (`@` / `www` / chosen subdomain) records pointing to the selected VPS node.
   - **Email Record Preservation Invariant:** Automatically preserves all existing `MX`, `TXT` (`SPF`, `_dmarc`, `_domainkey` / `DKIM`), `SRV`, and unrelated subdomain records intact when calling `namecheap.domains.dns.setHosts`—snapshot-saving the exact prior host record list in SQLite before any write.

3. **Live DNS Propagation & Let's Encrypt Rate-Limit Guard (`bridge/internal/dns/preflight.go`):**
   - Performs live DNS resolution checks against authoritative nameservers and public resolvers before allowing Auto-HTTPS certificate issuance.
   - Blocks ACME issuance (`422 GASH-E422` + clear plain-English status showing expected IP vs. resolved IP) until the target domain resolves cleanly to the selected VPS IP—preventing operators from hitting Let's Encrypt failed-validation rate limits.

4. **Grabtaculous Auto-HTTPS Wiring & Instant 1-Click Rollback:**
   - Supports three edge HTTPS modes managed by **Grabtaculous**:
     - **Caddy** (automatic ACME HTTPS),
     - **Nginx + Certbot**, or
     - **Cloudflare Tunnel**.
   - Keeps **Grisp** unprivileged on loopback (`127.0.0.1:8765`–`8772`) behind the edge proxy—never binding Grisp directly to privileged public ports `80`/`443`.
   - Gated behind **`X-CSRF-Token` + single-use `approval_token`** (`403 GASH-E403` invalid, `409 GASH-E409` replay), verifies live HTTPS + `/_ready === 200` health after rollout, and provides a **1-Click DNS + Edge Config Rollback** button that restores both the prior Namecheap DNS host snapshot and the **Grabtaculous** Pre-Deploy Snapshot.

### Explicitly Deferred to `v1.0.0+`
- Multi-registrar adapters beyond Namecheap (Cloudflare DNS API, Route 53, Porkbun).
- Scheduled automated fleet certificate renewal telemetry history (`v1.0.0`).

---

## 2. Planned `v0.3.0` Repository Additions (`C:\Development\gashboard`)

```text
gashboard/
├── migrations/
│   └── 003_dns_vault.grab                 # Encrypted Namecheap credentials + DNS host snapshots & rollbacks
├── src/
│   └── gashboard.grab                     # Adds /api/dns/* and /api/https/* routes + approval gates
├── public/gashboard/
│   ├── dns-https-wizard.js                # Pure Grex JS v1.0.0 Namecheap DNS + Auto-HTTPS Wizard UI
│   └── dashboard.js                       # Adds DNS & Auto-HTTPS Wizard navigation tab
├── bridge/internal/dns/
│   ├── namecheap.go                       # Structured Namecheap XML API client + email-safe record merger
│   ├── preflight.go                       # Live DNS propagation & Let's Encrypt rate-limit guard
│   └── dns_test.go                        # Mock Namecheap + DNS resolver tests (MX/TXT preservation, preflight)
└── tests/
    ├── unit_ui_dom.test.js                # Extended: divCount === 0, zero innerHTML, WCAG AA on dns-https-wizard.js
    ├── unit_contracts.test.js             # Extended: masked vault contract, 422 preflight guard, 403/409 replay
    └── integration_e2e.py                 # Extended: mock Namecheap + DNS preflight + Grabtaculous HTTPS + rollback
```

---

## 3. Security Architecture & Human-in-the-Loop Gates

| Control | Guarantee |
|---|---|
| **Encrypted Vault (`crypto.encrypt_aead`)** | Namecheap `ApiKey`, `ApiUser`, and `ClientIp` are encrypted with `AES-256-GCM` in SQLite; plaintext keys never enter DOM attributes, browser logs, or server responses. |
| **Email & Unrelated Record Preservation** | `namecheap.domains.dns.setHosts` always merges from the live `getHosts` list and asserts every existing `MX`, `TXT` (`SPF`/`DKIM`/`DMARC`), and unrelated record remains byte-identical before applying. |
| **Let's Encrypt Rate-Limit Guard** | `POST /api/https/apply` refuses to trigger ACME (`422 GASH-E422`) unless `POST /api/dns/propagation/check` confirms live DNS resolution matches the target VPS IP (or `cloudflare-tunnel` mode is selected). |
| **Unprivileged Grisp Loopback (`ADR-005`)** | Remote `Grisp` workers stay bound strictly to `127.0.0.1:8765`–`8772`; public `80`/`443` traffic terminates exclusively at Caddy, Nginx, or Cloudflare Tunnel. |
| **CSRF + Single-Use `approval_token`** | Applying DNS changes, provisioning Auto-HTTPS, and triggering 1-click DNS + Edge Rollback each require `X-CSRF-Token` and a single-use `approval_token` (`403`/`409`). |

---

## 4. Planned GRAB `v1.1.0` HTTP Endpoints (`v0.3.0` Additions)

| Route | Auth / Safety Gate | Behavior |
|---|---|---|
| `GET /api/dns/namecheap/status` | Loopback read-only | Returns masked Namecheap vault status (`configured`, `api_user_masked`, `client_ip`)—never secrets. |
| `POST /api/dns/namecheap/save` | `X-CSRF-Token` | Encrypts and stores Namecheap `api_user`, `api_key`, and `client_ip` via `crypto.encrypt_aead`. |
| `POST /api/dns/plan` | `X-CSRF-Token` | Reads current Namecheap hosts, computes `A`/`AAAA`/`CNAME` diff while preserving `MX`/`TXT`/`SPF`/`DKIM`, mints `approval_token`. |
| `POST /api/dns/apply` | `X-CSRF-Token` + single-use `approval_token` | Saves prior DNS host snapshot, updates Namecheap records, returns `rollback_approval_token`. |
| `POST /api/dns/propagation/check` | `X-CSRF-Token` | Checks authoritative & public DNS resolution against target VPS IP (`propagated: yes/no`). |
| `POST /api/https/plan` | `X-CSRF-Token` | Enforces propagation preflight (unless `cloudflare-tunnel`), previews Caddy/Nginx+Certbot/Cloudflare config, mints `approval_token`. |
| `POST /api/https/apply` | `X-CSRF-Token` + single-use `approval_token` | Dispatches TLS edge config to `grabtaculousd` over SSH (`127.0.0.1:8765-8772` upstream), verifies HTTPS + `/_ready === 200`. |
| `POST /api/https/rollback` | `X-CSRF-Token` + single-use `approval_token` | Restores prior Namecheap DNS host snapshot + **Grabtaculous** Pre-Deploy Snapshot in 1 click. |

---

## 5. `v0.3.0` Acceptance & Verification Gates

`Gashboard v0.3.0` is eligible for completion and synchronized `origin` + `stable` release **only** when **100%** of these gates pass:
1. **`grab check` & Canonical `grab format` Parity:** Zero errors on `src/gashboard.grab` and `migrations/003_dns_vault.grab` with byte-for-byte `grab format` parity.
2. **Pure `Grex JS v1.0.0`, Masked Vault & Contract Tests (`node --test tests/*.test.js`):**
   - `divCount === 0`, `innerHTMLWriteCount === 0`, and `100%` `auditAccessibility()` pass across `dns-https-wizard.js`.
   - Proves Namecheap secrets are never exposed in responses, `422` propagation preflight blocks premature ACME, and `403`/`409` single-use tokens hold.
3. **Go Namecheap & DNS Preflight Suite (`go test -count=1 ./...` + `govulncheck ./...`):**
   - Zero vulnerabilities; proves `MX`/`TXT`/`SPF`/`DKIM` preservation on host merges, strict XML parsing, and DNS mismatch rejection.
4. **Live E2E Integration (`python tests/integration_e2e.py`):**
   - Runs encrypted Namecheap credential save -> DNS host plan & apply -> propagation preflight block/pass -> `grabtaculousd` Auto-HTTPS rollout -> 1-click DNS + Edge Snapshot Rollback.
5. **Release Artifacts & Snapshot Sync:** Generates `docs/releases/pdf/Gashboard-v0.3.0-Guide.pdf`, `dist/` binaries/bundle + `SHA256SUMS.txt`, runs `sync-notebook-sources.ps1`, and publishes synchronized `v0.3.0` GitHub Releases with the **SemVer + 6-Layer Ecosystem Compatibility Matrix**.
