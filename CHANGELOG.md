# Changelog

All notable changes to **Gashboard** (`urbanspress/gashboard.progress` / `urbanspress/gashboard.stable`) are documented in this file.

The format follows Semantic Versioning (`MAJOR.MINOR.PATCH`) and the GRAB Ecosystem **SemVer + 6-Layer Compatibility Matrix Standard**.

---

## [0.2.0] - 2026-11-15

### Added
- **WCAG AA Light/Dark Theme Switcher (`public/gashboard/theme.js`, `public/gashboard/gashboard.css`, `views/dashboard.grab.html`, `src/gashboard.grab`):**
  - Reactive **`Grex JS v1.0.0`** `createTheme()` toggle (`[data-grex-theme="light" | "dark"]`) in the dashboard header with `>= 4.5:1` verified contrast (`computeContrastRatio()`) across all semantic surfaces and visible `:focus-visible` outlines.
  - Persists user choice in both SQLite (`ui_preferences` via `POST /api/preferences/theme`) and local storage, rendering `data-grex-theme` server-side in `views/dashboard.grab.html` for zero FOUC on refresh.
- **Built-In phpMyAdmin-Style Visual Database Manager (`bridge/internal/dbinspect/`, `bridge/cmd/gashboard-bridge/`, `migrations/002_db_manager_and_theme.grab`, `src/gashboard.grab`, `public/gashboard/db-manager.js`):**
  - Operates strictly over Gashboard's `known_hosts`-pinned `127.0.0.1` SSH tunnels (`PostgreSQL`, `MariaDB`) or workspace-confined local SQLite (`--sqlite-root`; rejects path traversal and `.env`/`.ssh`/`.git` targets with `403 GRAB-E401`)—never exposing a public database admin port on any VPS and rejecting direct remote DB hosts (`422 GASH-E422`).
  - **Schema & Table Explorer:** Pure `Grex JS v1.0.0` semantic inspection of databases, tables, columns, types, indexes, foreign keys, and row counts (`divCount === 0`, `innerHTMLWriteCount === 0`).
  - **Paginated Row Browser & `ADR-025c` Fidelity:** Filters, sorts, and paginates (`1 <= limit <= 100`) rows with parameterized identifiers/values while preserving all `BIGINT`/`DECIMAL`/`NUMERIC` values as exact base-10 wire strings (rejecting float drift).
  - **Guarded Read-Only Query Runner & `GROXY-SAFE-001` Write Gate:** Defaults `POST /api/db/query` to strictly single-statement read-only transactions (`SELECT`/`SHOW`/`DESCRIBE`/`EXPLAIN`, blocking writes/DDL/multi-statement SQL with `403 GASH-E403`). Every mutation, DDL change, or SQL import goes through `/api/db/mutate/plan` -> automatic SHA-256-verified **Pre-Mutation Snapshot** -> `/api/db/mutate/execute` (`X-CSRF-Token` + single-use `approval_token`; `403` invalid, `409` replay), plus SQL export (`/api/db/export`) and **1-Click Pre-Mutation Snapshot Restore** (`/api/db/snapshots/restore`).

### Verification
- **Gate 1 (GRAB & Format Parity):** `grab check` + canonical `grab format` byte-for-byte parity + zero `<div>` / zero `innerHTML` scans — **100% Pass**.
- **Gate 2 (Unit, Zero-`<div>` DOM, WCAG AA & Contracts):** `node --test tests/*.test.js` verifying Light/Dark `>= 4.5:1` contrast, `divCount === 0`, `innerHTMLWriteCount === 0`, `ADR-025c` string fidelity, and CSRF/replay guards — **100% Pass**.
- **Gate 3 (Go Bridge):** `go build ./...`, `go test -count=1 ./...` (including tunneled Postgres wire & Pre-Mutation Snapshot tests), and `govulncheck ./...` (`0` vulnerabilities) — **100% Pass**.
- **Gate 4 (Live 6-Layer E2E Integration):** `python tests/integration_e2e.py` verifying persisted Dark/Light SSR reload, live tunneled PostgreSQL query over `127.0.0.1` SSH tunnel, `GRAB-E401` confinement, `limit <= 100` cap, blocked unapproved write, approved row mutation + automatic Pre-Mutation Snapshot + `409` replay rejection, 1-click Snapshot restore, and untouched peer repos — **100% Pass**.

---

## [0.1.0] - 2026-11-15

### Added
- **Discreet `127.0.0.1` Pure `Grex JS v1.0.0` + `GRAB v1.1.0` Control Panel (`src/gashboard.grab`, `views/dashboard.grab.html`, `public/gashboard/*.js`, `gashboard.css`):**
  - Strictly loopback-only workstation binding (`127.0.0.1`) with zero public VPS control-panel ports (`ADR-005`, `ADR-017`).
  - Zero wrapper `<div>` elements (`divCount === 0`), zero `innerHTML` writes (`innerHTMLWriteCount === 0`), `server.asset` asset fingerprinting, `100%` WCAG AA UI audit pass, `X-CSRF-Token`, and single-use `approval_token` enforcement (`403 GASH-E403` / `409 GASH-E409`).
  - SQLite-backed persistence (`migrations/001_gashboard_schema.grab`) with `use crypto` `AES-256-GCM` encryption (`v1:...` ciphertexts) for SSH credentials/tokens.
  - Strict `ADR-025c` exact base-10 wire string validation for numeric metrics, ports, and prices (`422 GASH-E422`).
- **Pure Go Loopback SSH & Local CLI Bridge (`bridge/cmd/gashboard-bridge/`, `bridge/internal/ssh/`, `bridge/internal/localcli/`):**
  - Strict `known_hosts` OpenSSH host-key fingerprint pinning (`SHA256:...`; rejecting unknown/mismatched host keys with `403 GASH-E502`).
  - Encrypted SSH tunnel manager forwarding up to 8 concurrent private `127.0.0.1:<local_port>` loopback connections (PostgreSQL, MariaDB, Redis) with `429 GASH-E503` bounded-cap enforcement and automatic cleanup on shutdown/close.
  - Live integration with frozen `grabman v0.1.0` (`doctor`, `solve --verify`, `dna`) and `grabtaculous v0.1.0` (`grabtaculousd` `/_ready`, `/v1/deploy`, `/v1/rollout`, `/v1/rollback`).
- **1-Click App Marketplace & `Site DNA` Fleet Deployer:**
  - Point-and-click deployment planning & execution for **GrabLab CMS `v1.0.1` + Grex Theme Builder `v1.0.0` + Groxy AI `v1.0.0`** stacks with `--read-only` container hardening and Caddy/Nginx/Cloudflare Tunnel edge configuration.
  - Portable **Groxy AI** `Site DNA` (`groxy-site-dna-v0.4.0`) preview, lockfile verification, live zero-downtime `Grisp` rollout, and 1-click Pre-Deploy Snapshot rollback.
- **Verification & Release Tooling:**
  - `tests/unit_ui_dom.test.js`, `tests/unit_contracts.test.js`, `tests/helpers/dom-shim.js`, `tests/ssh_tunnel_test.go`, `bridge/.../*_test.go`, and live 6-layer `tests/integration_e2e.py`.
  - Plain-English walkthrough guide generator (`docs/releases/generate_release_guides.py` -> `docs/releases/pdf/Gashboard-v0.1.0-Guide.pdf`) and reproducible release bundler (`scripts/package_release.py`).

### Verification
- **Gate 1 (GRAB & Templates):** `grab check` + byte-for-byte `grab format` parity + zero `<div>` and zero `innerHTML` scans — **100% Pass**.
- **Gate 2 (UI/DOM & Go Bridge):** `node --test tests/*.test.js` (`7/7` pass), `go test -count=1 ./...` (`100%` pass), and `govulncheck ./...` (`0` vulnerabilities) — **100% Pass**.
- **Gate 3 (Live 6-Layer Cross-Stack E2E):** `python tests/integration_e2e.py` exercising live `Gashboard v0.1.0` + `gashboard-bridge` + `grabtaculousd v0.1.0` + `grabman v0.1.0` + `Groxy AI Site DNA` — **100% Pass**.
