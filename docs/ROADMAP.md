# Gashboard Roadmap

**Repositories:** `urbanspress/gashboard.progress` (active development) / `urbanspress/gashboard.stable` (verified releases)  
**Foundational Baselines:** **GRAB `v1.1.0`**, **Grex JS `v1.0.0`**, **GrabLab CMS `v1.0.1`**, **Grex Theme Builder `v1.0.0`**, **Groxy AI `v1.0.0`**, **`grabman v1.0.0`**, and **Grabtaculous `v1.0.0`**

**Status Labels:**
- **Specification in Review** — Specification drafted and awaiting explicit project-owner approval before any `.grab`, `.js`, or Go implementation code is written.
- **Approved** — Authorized by the project owner for implementation.
- **Complete** — Implemented, `grab check` / `grab format` clean, Go bridge tests + Node zero-`<div>` DOM/A11y tests + cross-layer E2E passing `100%`, walkthrough PDF generated, and synchronized to `origin` + `stable`.
- **Planned** — Future milestone awaiting prior milestone completion and spec drafting.

---

## `v0.1.0` — Discreet Pure `Grex JS v1.0.0` Multi-VPS Control Panel, 1-Click App Marketplace UI, Encrypted SSH DB Tunneling & `Site DNA` Fleet Deployer

**Status:** Complete (`v0.1.0` Released — [`specifications/GASHBOARD-SPEC-001.md`](../specifications/GASHBOARD-SPEC-001.md))

Delivered Scope:
- **Discreet Localhost Control Plane (`127.0.0.1`-Only):** Runs locally on the user's workstation (`GRAB v1.1.0` + `Grex JS v1.0.0` zero-`<div>` UI paired with a `127.0.0.1` Go SSH bridge), eliminating public VPS control-panel login pages (`ADR-005`, `ADR-017`).
- **Multi-VPS Fleet Inventory & Live Health Telemetry:** Key-authenticated, `known_hosts`-pinned VPS server inventory displaying live `Grisp` worker health, `/_ready` probes, edge TLS domains, and exact `ADR-025c` resource numbers.
- **1-Click App Marketplace UI:** Point-and-click deployment wizard powered by **Grabtaculous** blueprints—highlighting **`GrabLab CMS v1.0.1 + Grex Theme Builder v1.0.0 + Groxy AI v1.0.0`**, custom domain + Caddy/Nginx/Cloudflare SSL wiring, `--read-only` security preview, and `grabman doctor` preflight validation.
- **Encrypted SSH Database Tunneling (`127.0.0.1`):** 1-click loopback port forwards (`127.0.0.1:<local_port>`) to remote PostgreSQL, MariaDB, and Redis containers over encrypted SSH without exposing database ports publicly.
- **`Site DNA` Fleet Deployer & 1-Click Snapshot Rollback:** Imports **Groxy AI** `Site DNA` (`GET /api/groxy/site-dna/export`), runs `grabman` diff & `grabman.lock` verification, executes zero-downtime **Grabtaculous** `Grisp` fleet rollouts behind `X-CSRF-Token` + single-use `approval_token`, and surfaces 1-click Pre-Deploy Snapshot Rollbacks.

---

## `v0.2.0` — Light/Dark Theme Switcher & Built-In phpMyAdmin-Style Visual Database Manager

**Status:** Complete ([`specifications/GASHBOARD-SPEC-002.md`](../specifications/GASHBOARD-SPEC-002.md), [`CHANGELOG.md`](../CHANGELOG.md))

Delivered Scope:
- **WCAG AA Light/Dark Theme Switcher:** Reactive **`Grex JS v1.0.0`** theme toggle (`createTheme` / `computeContrastRatio() >= 4.5:1`), persisted in local preferences and SQLite, with zero wrapper `<div>` elements, zero FOUC, and intact `:focus-visible` rings.
- **Built-In phpMyAdmin-Style Database Manager:** Operates strictly over Gashboard's `known_hosts`-pinned `127.0.0.1` SSH tunnels (`PostgreSQL`, `MariaDB`) or confined local SQLite (never exposing a public phpMyAdmin/Adminer port), featuring a semantic visual schema & table explorer, paginated row browser (`<= 100` rows/page) with exact `ADR-025c` numeric string fidelity, read-only `SELECT`/`EXPLAIN` query runner by default, and `GROXY-SAFE-001` human-in-the-loop write/DDL gates (`X-CSRF-Token` + single-use `approval_token` + Pre-Mutation Snapshot).

---

## `v0.3.0` — Namecheap DNS + Auto-HTTPS Wizard

**Status:** Complete (`v0.3.0` Released — [`specifications/GASHBOARD-SPEC-003.md`](../specifications/GASHBOARD-SPEC-003.md), [`CHANGELOG.md`](../CHANGELOG.md))

Delivered Scope:
- **Encrypted Namecheap Credential Vault:** Stores Namecheap API User, API Key, and Whitelisted Client IP encrypted at rest in SQLite via **GRAB `v1.1.0`** `crypto.encrypt_aead` (AES-256-GCM)—never rendered in plaintext in the DOM, responses, or logs.
- **1-Click DNS Record Provisioner & Propagation Preflight:** Configures `A`, `AAAA`, and `CNAME` (`@` / `www` / subdomain) records while preserving existing `MX`/`TXT`/`SPF`/`DKIM` email records intact, and verifies live DNS propagation before ACME issuance (`422 GASH-E422`) to avoid Let's Encrypt rate-limit lockouts.
- **Grabtaculous Auto-HTTPS Wiring & Instant Rollback:** Dispatches Caddy, Nginx + Certbot, or Cloudflare Tunnel configuration to `grabtaculousd` over SSH (keeping Grisp unprivileged on `127.0.0.1:8765-8772`), verifies live HTTPS + `/_ready`, and supports 1-click DNS + Edge config rollback behind `X-CSRF-Token` + single-use `approval_token` (`403`/`409`).

---

## `v1.0.0` — Production Freeze, Independent `Orchestrator (Argon)` Multi-Repo Audit & Desktop Launcher Packaging

**Status:** Complete (`v1.0.0` Released — [`specifications/GASHBOARD-SPEC-100.md`](../specifications/GASHBOARD-SPEC-100.md), [`CHANGELOG.md`](../CHANGELOG.md))

Delivered Scope:
- Completed independent pre-`v1.0.0` multi-repository cross-layer security, pure-`Grex JS v1.0.0` zero-`<div>`/WCAG AA DOM, SSH tunnel, Visual DB Manager, Namecheap DNS/Auto-HTTPS, and `ADR-025c` contract audit; remediated two discovered hardening items (target-binding `approval_token` validation in `src/gashboard.grab` and expanded SSH key/TLS credential segment blocking in `bridge/internal/dbinspect/security.go` + `403 GASH-E403` E2E regression test) (`specifications/GASHBOARD-SPEC-100.md`).
- Froze Gashboard `v1.0.0` across `src/gashboard.grab`, `views/dashboard.grab.html`, `public/gashboard/dashboard.js`, `public/gashboard/api-client.js`, `bridge/cmd/gashboard-bridge/main.go`, and `package.json`, aligned cleanly with `grabman v1.0.0` and `Grabtaculous v1.0.0` while keeping all 5 upstream `v1.x` repositories (`GRAB v1.1.0`, `Grex JS v1.0.0`, `GrabLab CMS v1.0.1`, `Grex Theme Builder v1.0.0`, `Groxy AI v1.0.0`) untouched.
- Passed all 4 verification gates `100%` (`grab check` + byte-for-byte `grab format` parity, `node --test tests/*.test.js`, `go build`/`go test -count=1`/`govulncheck` with `0` vulnerabilities, and 6-layer `tests/integration_e2e.py`), generated `docs/releases/pdf/Gashboard-v1.0.0-Guide.pdf` + `dist/` packages (`gashboard-ssh-windows-amd64.exe`, `gashboard-ssh-linux-amd64`, `gashboard-v1.0.0-bundle.zip`, `SHA256SUMS.txt`), and synchronized `v1.0.0` on `origin` and `stable` (providing the frozen Step 5 foundation for **Step 6 — Groxy Desk**).
