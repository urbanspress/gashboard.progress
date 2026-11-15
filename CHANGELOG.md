# Changelog

All notable changes to **Gashboard** (`urbanspress/gashboard.progress` / `urbanspress/gashboard.stable`) are documented in this file.

The format follows Semantic Versioning (`MAJOR.MINOR.PATCH`) and the GRAB Ecosystem **SemVer + 6-Layer Compatibility Matrix Standard**.

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
