# GASHBOARD-SPEC-100: Gashboard `v1.0.0` Production Contract Freeze & Independent Pre-`v1.0.0` Cross-Layer Audit

- **Status:** Specification in Review (Awaiting Project-Owner Approval Prior to `v1.0.0` Implementation & Release Tagging)
- **Target Release:** `v1.0.0` (`MAJOR.MINOR.PATCH` — Step 5 Multi-VPS Control Panel, Visual DB Manager & Auto-HTTPS Production Freeze)
- **Foundational Baselines:**
  - **GRAB:** `v1.1.0` (`urbanspress/grab` — `Grisp`, `server.asset`, `use crypto` AES-256-GCM, `use data`, `use cache`, `use env`, `ADR-005`, `ADR-017`, `ADR-025c`)
  - **Grex JS:** `v1.0.0` (`urbanspress/grex-js` — 20 semantic elements, reactive signals, `createTheme`, `computeContrastRatio`, `auditAccessibility`, zero wrapper-`<div>` schema)
  - **GrabLab CMS:** `v1.0.1` (`urbanspress/grablab-cms`)
  - **Grex Theme Builder:** `v1.0.0` (`urbanspress/grex-builder`)
  - **Groxy AI:** `v1.0.0` (`urbanspress/groxy-ai` — `groxy-site-dna-v0.4.0`)
  - **`grabman` & Grabtaculous:** `v1.0.0` Step 5 Freeze Companions (`specifications/GRABMAN-SPEC-100.md`, `specifications/GRABTACULOUS-SPEC-100.md`)
- **Governance:** Read alongside [`GASHBOARD-EXPERT.md`](../GASHBOARD-EXPERT.md), [`AGENTS.md`](../AGENTS.md), [`GASHBOARD-SPEC-001.md`](GASHBOARD-SPEC-001.md), [`GASHBOARD-SPEC-002.md`](GASHBOARD-SPEC-002.md), [`GASHBOARD-SPEC-003.md`](GASHBOARD-SPEC-003.md), and [`docs/ROADMAP.md`](../docs/ROADMAP.md).

---

## 1. Executive Summary (Plain English)

With `v0.1.0` (Multi-VPS Control Panel, 1-Click Marketplace, SSH DB Tunnels, `Site DNA` Fleet Deployer), `v0.2.0` (WCAG AA Light/Dark Theme Switcher & Built-In Visual Database Manager), and `v0.3.0` (Encrypted Namecheap DNS + Auto-HTTPS Wizard) delivered, an independent pre-`v1.0.0` cross-layer security, DOM, SSH tunnel, DB manager, DNS, and numeric-fidelity audit (`Orchestrator (Argon)`) was conducted across all of **`gashboard`** alongside **`grabtaculous`** and **`grabman`**.

During the audit, **two subtle edge cases were discovered and immediately hardened**:
1. **Target-Bound Approval Token Enforcement (`GROXY-SAFE-001`):** Reinforced `/api/marketplace/deploy`, `/api/fleet/dna/deploy`, `/api/fleet/rollback`, `/api/db/mutate/execute`, `/api/dns/apply`, `/api/https/apply`, and the DNS rollback leg of `/api/https/rollback` in [`src/gashboard.grab`](../src/gashboard.grab) so every single-use `approval_token` verifies any supplied target ID (`snapshot_id`, `node_id`, `plan_id`, `blueprint_id`, `preview_id`, `dna_digest`, `target_id`, `domain`) against the minted approval payload and fails closed with `403 GASH-E403` on mismatch.
2. **`GRAB-E401` Sensitive Segment Parity in SQLite Path Guard:** Updated [`bridge/internal/dbinspect/security.go`](../bridge/internal/dbinspect/security.go) (`sensitiveSegments` & `hasSensitiveSegment`) so SQLite path confinement rejects `id_ecdsa`, `id_dsa`, `*.pem`, `*.key`, `*.p12`, and `*.pfx` path segments with `403 GRAB-E401`, achieving 100% parity with `grabman` and `grabtaculous`.

All four verification gates (static `grab check` + canonical `grab format`, Node DOM/WCAG AA/contract tests, Go bridge tests + `govulncheck`, and live 6-layer end-to-end integration) re-ran after these hardening fixes and **passed 100%**.

---

## 2. Independent Pre-`v1.0.0` Cross-Layer Audit Evidence

### 2.1 Security, SSH Tunnel, DB Manager & DNS/Auto-HTTPS Audit (`ADR-005`, `ADR-017`, `GROXY-SAFE-001`)

| Control Area | Audited Files | Verified Evidence |
|---|---|---|
| **100% Loopback-Only Binding & Bearer Auth** | [`src/gashboard.grab`](../src/gashboard.grab), [`bridge/cmd/gashboard-bridge/main.go`](../bridge/cmd/gashboard-bridge/main.go), [`bridge/internal/ssh/tunnel.go`](../bridge/internal/ssh/tunnel.go) | Gashboard binds strictly to `127.0.0.1:9390`. `gashboard-bridge` binds strictly to `127.0.0.1:9391` (`ValidateLoopbackBind` rejects `0.0.0.0`, `::`, wildcards, or non-loopback IPs with `GASH-E501`), enforces `subtle.ConstantTimeCompare` Bearer auth (`GASHBOARD_BRIDGE_TOKEN`) on all `/v1/*` routes, and binds SSH DB tunnels strictly to `127.0.0.1:<port>` (<= `MaxConcurrentTunnels = 8`, clean teardown on close/shutdown). |
| **Strict OpenSSH `known_hosts` Pinning & Structured Argv** | [`bridge/internal/ssh/client.go`](../bridge/internal/ssh/client.go), [`bridge/internal/localcli/grabman.go`](../bridge/internal/localcli/grabman.go) | `KnownHostsVerifier` validates host keys against pinned `SHA256:<base64>` / OpenSSH `known_hosts` lines (`GASH-E502` on mismatch); zero `InsecureIgnoreHostKey` usage anywhere. All local `grabman`/`grab` calls use structured `exec.CommandContext` argv slices (zero shell-string interpolation). |
| **AES-256-GCM Encrypted Secrets at Rest** | [`src/gashboard.grab`](../src/gashboard.grab), [`migrations/001_gashboard_schema.grab`](../migrations/001_gashboard_schema.grab), [`migrations/002_db_manager_and_theme.grab`](../migrations/002_db_manager_and_theme.grab), [`migrations/003_dns_vault.grab`](../migrations/003_dns_vault.grab) | SSH node credentials, DB tunnel sessions, and Namecheap (`api_user`, `api_key`, `client_ip`) credentials are encrypted via **GRAB `v1.1.0`** `crypto.encrypt_aead` (`v1:...` AEAD ciphertexts keyed from `GASHBOARD_MASTER_KEY`). API JSON responses, server logs, and DOM elements emit only masked hints (`api_user_masked`, `client_ip_masked`), never plaintext secrets or `v1:...` ciphertexts. |
| **Visual DB Manager Read-Only Defaults & Pre-Mutation Snapshots** | [`bridge/internal/dbinspect/inspector.go`](../bridge/internal/dbinspect/inspector.go), [`bridge/internal/dbinspect/security.go`](../bridge/internal/dbinspect/security.go), [`bridge/internal/dbinspect/snapshot.go`](../bridge/internal/dbinspect/snapshot.go) | Local SQLite paths are confined inside `GASHBOARD_SQLITE_ROOT` (`GRAB-E401`). All browse/query sessions enforce `PRAGMA query_only = ON` (SQLite) or `sql.TxOptions{ReadOnly: true}` / `SET TRANSACTION READ ONLY` (PostgreSQL/MariaDB). Pagination caps at `MaxRowsPerPage = 100`. Mutating SQL/DDL requires `POST /api/db/mutate/plan` + automatic SHA-256 `TableSnapshot` capture + single-use `approval_token` execution (`409` on replay). |
| **Email-Safe Namecheap DNS Merger & `422` ACME Preflight Guard** | [`bridge/internal/dns/namecheap.go`](../bridge/internal/dns/namecheap.go), [`bridge/internal/dns/preflight.go`](../bridge/internal/dns/preflight.go), [`src/gashboard.grab`](../src/gashboard.grab) | `namecheap.domains.dns.setHosts` fetches `getHosts` first, computes a SHA-256 backup snapshot, preserves all existing `MX`, `TXT` (`SPF`, `DKIM`, `_dmarc`), `CAA`, `SRV`, and `NS` records byte-identical (failing closed on email drop), and `POST /api/https/plan` / `/api/https/apply` block ACME Let's Encrypt issuance with `422 GASH-E422` until authoritative/public DNS convergence completes (unless `cloudflare-tunnel` mode). |
| **CSRF (`403`) & Target-Bound Replay Protection (`409` / `403`)** | [`src/gashboard.grab`](../src/gashboard.grab) | Every mutating `POST` route requires `X-CSRF-Token` (`403 GASH-E403`). Every destructive/deploy/rollback route requires a single-use, target-bound `approval_token` (`403 GASH-E403` on missing/scope/target mismatch, `409 GASH-E409` on replay). |

### 2.2 Pure `Grex JS v1.0.0`, Zero Wrapper-`<div>` DOM, Light/Dark WCAG AA & `ADR-025c` Audit

| Frontend & Wire Audit Area | Audited Files | Verified Evidence |
|---|---|---|
| **Vendored `Grex JS v1.0.0` SHA-256 Parity** | [`public/grex/grex.js`](../public/grex/grex.js), [`public/grex/grex.elements.json`](../public/grex/grex.elements.json), [`tests/unit_contracts.test.js`](../tests/unit_contracts.test.js) | Byte-for-byte SHA-256 match against `C:\Development\grex-js\dist\`: `c1e28d74a7ecf19182e225644fa244aa8600658dd1ff8895c133bfc64976b6d6` (`grex.js`) and `c54c4bcf15ec8fea2dec4ef41975ba85a4b555dd400604e59c78883a8bbdebc9` (`grex.elements.json`). |
| **Zero Wrapper-`<div>` & Zero Unsafe DOM Writes** | [`views/dashboard.grab.html`](../views/dashboard.grab.html), [`public/gashboard/*.js`](../public/gashboard/), [`tests/unit_ui_dom.test.js`](../tests/unit_ui_dom.test.js) | `divCount === 0`, `innerHTMLWriteCount === 0`, zero `eval()`, zero `new Function()`, and zero `javascript:`/`vbscript:`/`data:` URLs across initial mount and every interactive UI flow (VPS registration, Marketplace deploy, SSH tunnel lifecycle, `Site DNA` deploy/rollback, Visual DB Manager query/mutate/restore, DNS + Auto-HTTPS wizard). |
| **Zero-FOUC SSR Light/Dark Theme & WCAG AA >= 4.5:1** | [`views/dashboard.grab.html`](../views/dashboard.grab.html), [`public/gashboard/theme.js`](../public/gashboard/theme.js), [`public/gashboard/gashboard.css`](../public/gashboard/gashboard.css) | Server renders `<html lang="en" data-grex-theme="{initial_theme}">` directly from SQLite `ui_preferences` (`zero` flash on reload). Both `THEME_PALETTES.light` and `THEME_PALETTES.dark` pass 10/10 contrast pairs (`>= 4.5:1` via `computeContrastRatio()`) and `100%` `auditAccessibility()` checks. |
| **`ADR-025c` Exact Base-10 Numeric Preservation** | [`src/gashboard.grab`](../src/gashboard.grab), [`bridge/internal/dbinspect/format.go`](../bridge/internal/dbinspect/format.go), [`public/gashboard/api-client.js`](../public/gashboard/api-client.js) | Preserves 64-bit `INTEGER` (`9007199254740993` > `Number.MAX_SAFE_INTEGER`) and exact `DECIMAL` (`12345678901234567890.1234`, `1000.00`) as base-10 wire strings across SQLite/Postgres/MariaDB row scans, `Site DNA` bundles, VPS telemetry, DNS TTLs, and browser state. |

### 2.3 Verification Gate Outputs Observed (Post-Hardening)
1. **Gate 1 (`grab check` + `grab format` parity + zero-`<div>` scan):** `PASS` on `src/gashboard.grab`, `migrations/001_gashboard_schema.grab`, `migrations/002_db_manager_and_theme.grab`, `migrations/003_dns_vault.grab`, and `views/dashboard.grab.html`.
2. **Gate 2 (`node --test tests/unit_ui_dom.test.js tests/unit_contracts.test.js`):** `PASS` (`7/7` tests passing, `0` failures, `0` skipped).
3. **Gate 3 (`go build ./...`, `go test -count=1 ./...`, `govulncheck ./...`):** `PASS` across `bridge/cmd/gashboard-bridge`, `bridge/internal/dbinspect`, `bridge/internal/dns`, `bridge/internal/ssh`, and `tests`; `No vulnerabilities found.`
4. **Gate 4 (`python tests/integration_e2e.py`):** `PASS` (`ALL 4 GASHBOARD v0.3.0 VERIFICATION GATES PASSED 100%`), including the new `403 GASH-E403` approval-token target-mismatch regression test and clean-tree verification across all peer repos.

---

## 3. Frozen `v1.0.0` Contract Specifications (For Step 6 Groxy Desk)

Upon project-owner approval of this specification, the `v1.0.0` release implementation freezes the following runtime contracts for Step 6 (**Groxy Desk**) and all `v1.x` updates:

### 3.1 Version Promotion Targets (`0.3.0` -> `1.0.0`)
- [`src/gashboard.grab`](../src/gashboard.grab): `set gash_version to "1.0.0"`
- [`views/dashboard.grab.html`](../views/dashboard.grab.html): `<meta name="gashboard-version" content="1.0.0">`, header badge, and footer text
- [`public/gashboard/dashboard.js`](../public/gashboard/dashboard.js): `export const GASHBOARD_VERSION = "1.0.0"`
- [`bridge/cmd/gashboard-bridge/main.go`](../bridge/cmd/gashboard-bridge/main.go): `var Version = "1.0.0"`
- [`package.json`](../package.json): `"version": "1.0.0"`

### 3.2 Frozen Gashboard HTTP API Surface (`127.0.0.1:9390`)

- **System & UI:** `GET /_health`, `GET /_ready`, `GET /`, `GET /gashboard`
- **Multi-VPS Fleet & Vault:** `GET /api/vps`, `POST /api/vps/register` (`X-CSRF-Token`), `POST /api/vps/{id}/probe` (`X-CSRF-Token`)
- **1-Click App Marketplace:** `GET /api/marketplace/catalog`, `POST /api/marketplace/plan` (`X-CSRF-Token`), `POST /api/marketplace/deploy` (`X-CSRF-Token` + single-use target-bound `approval_token`)
- **SSH DB Tunnels (`127.0.0.1`, max 8):** `GET /api/tunnels`, `POST /api/tunnels/open` (`X-CSRF-Token`), `POST /api/tunnels/close` (`X-CSRF-Token`)
- **`Site DNA` Fleet Deployer & Rollback:** `POST /api/fleet/dna/preview` (`X-CSRF-Token`), `POST /api/fleet/dna/deploy` (`X-CSRF-Token` + single-use `approval_token`), `GET /api/fleet/snapshots`, `POST /api/fleet/rollback` (`X-CSRF-Token` + single-use target-bound `approval_token`)
- **Theme Preferences:** `GET /api/preferences/theme`, `POST /api/preferences/theme` (`X-CSRF-Token`)
- **Visual Database Manager:** `GET /api/db/targets`, `GET /api/db/schema`, `POST /api/db/schema`, `POST /api/db/rows` (`<= 100`/page), `POST /api/db/query` (read-only), `POST /api/db/mutate/plan`, `POST /api/db/mutate/execute` (`approval_token`), `POST /api/db/export`, `GET /api/db/snapshots`, `POST /api/db/snapshots/restore` (`approval_token`)
- **Namecheap DNS & Auto-HTTPS Wizard:** `GET /api/dns/namecheap/status`, `POST /api/dns/namecheap/save`, `POST /api/dns/plan`, `POST /api/dns/apply` (`approval_token`), `GET /api/dns/snapshots`, `POST /api/dns/rollback` (`approval_token`), `POST /api/dns/propagation/check`, `POST /api/https/plan`, `POST /api/https/apply` (`approval_token`), `POST /api/https/rollback` (`approval_token`)

### 3.3 Frozen `gashboard-bridge` Loopback API Surface (`127.0.0.1:9391`)

- **Public Local Health:** `GET /_health`, `GET /_ready`
- **Bearer-Protected (`Authorization: Bearer <GASHBOARD_BRIDGE_TOKEN>`):**
  - SSH & Local CLI: `POST /v1/ssh/verify-host`, `GET /v1/tunnels`, `POST /v1/tunnels/open`, `POST /v1/tunnels/close`, `POST /v1/grabman/doctor`, `POST /v1/grabman/solve-verify`, `POST /v1/grabman/dna-preview`, `POST /v1/grabtaculous/proxy`
  - Visual DB Inspector: `POST /v1/db/schema`, `POST /v1/db/rows`, `POST /v1/db/query`, `POST /v1/db/mutate/plan`, `POST /v1/db/mutate/execute`, `POST /v1/db/export`, `POST /v1/db/restore`
  - Namecheap DNS & Auto-HTTPS: `POST /v1/dns/namecheap/hosts`, `POST /v1/dns/namecheap/plan`, `POST /v1/dns/namecheap/apply`, `POST /v1/dns/namecheap/restore`, `POST /v1/dns/propagation/check`, `POST /v1/https/verify`

### 3.4 Frozen DOM Contracts & Error Code Registry
- **Root & Theme:** `<html data-grex-theme="light|dark">`, `<meta name="gashboard-csrf">`, `<meta name="gashboard-version">`, `#gashboard-theme-toggle`, `#gashboard-root`
- **Module Sections & Interactive Anchors:** `#gash-hero-section`, `#gash-vps-panel`, `#gash-marketplace-panel`, `#gash-tunnels-panel`, `#gash-fleet-dna-panel`, `#gashboard-dns-https-wizard`, `#gashboard-db-manager`, plus action selectors (`[data-probe-node]`, `[data-close-tunnel]`, `[data-rollback-snapshot]`, `[data-dns-rollback-id]`, `[data-https-rollback-id]`).
- **Frozen Error Codes:** `GRAB-E401`, `GASH-E403`, `GASH-E409`, `GASH-E422`, `GASH-E500`, `GASH-E501`, `GASH-E502`, `GASH-E503`.

---

## 4. `v1.0.0` Approval & Release Acceptance Gates

No `v1.0.0` version bump or release tags may be published until the project owner approves this specification. Once approved:
1. Bump version markers in `gashboard` to `"1.0.0"` across `src/gashboard.grab`, `views/dashboard.grab.html`, `public/gashboard/dashboard.js`, `bridge/cmd/gashboard-bridge/main.go`, and `package.json`.
2. Update and re-run all 4 verification gates (`grab check` + `grab format` byte-for-byte parity, `node --test tests/*.test.js`, `go build`/`go test -count=1`/`govulncheck`, and `python tests/integration_e2e.py`) with 100% passing results.
3. Build release packages (`gashboard-bridge` static binaries, Gashboard app bundle, `SHA256SUMS.txt`), generate `docs/releases/pdf/Gashboard-v1.0.0-Guide.pdf`, run `sync-notebook-sources.ps1`, and publish synchronized `v1.0.0` releases on `urbanspress/gashboard.progress` and `urbanspress/gashboard.stable`.
