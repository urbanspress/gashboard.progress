# GASHBOARD-SPEC-001: Gashboard `v0.1.0` Discreet Pure `Grex JS v1.0.0` Multi-VPS Control Panel, 1-Click Marketplace UI, Encrypted SSH DB Tunneling & `Site DNA` Fleet Deployer

- **Status:** Complete (`v0.1.0` Released)
- **Milestone:** `v0.1.0` — Step 5 Discreet Local Control Panel & Fleet Orchestration UI
- **Foundational Upstream & Peer Baselines:**
  - **GRAB:** `v1.1.0` (`urbanspress/grab` — `grab serve --allow-scripts`, `server.asset`, `use server`, `use data`, `use cache`, `use http`, `use json`, `use crypto` Argon2id + AES-256-GCM, `use env`, `ADR-005`, `ADR-017`, `ADR-025c`, `ADR-028a..c`)
  - **Grex JS:** `v1.0.0` (`urbanspress/grex-js` — `grex.elements.json` 20 semantic elements, `signal`/`computed`/`effect`, `setSafeText`, `validateElementNode()`, `auditAccessibility()`, zero wrapper-`<div>` DOM)
  - **GrabLab CMS:** `v1.0.1` (`GRABLAB-SPEC-100.md` — 1-click CMS stack target)
  - **Grex Theme Builder:** `v1.0.0` (`GREX-BUILDER-SPEC-100.md` — 1-click exclusive visual theme stack target)
  - **Groxy AI:** `v1.0.0` (`GROXY-AI-SPEC-005.md` — portable `Site DNA` export `GET /api/groxy/site-dna/export`)
  - **`grabman` & Grabtaculous:** `v0.1.0` (`GRABMAN-SPEC-001.md`, `GRABTACULOUS-SPEC-001.md` — lockfile verification, `grabtaculousd` SSH-tunneled control API, catalog blueprints, `--read-only` rollouts & snapshot rollbacks)
- **Governance:** Read alongside [`GASHBOARD-EXPERT.md`](../GASHBOARD-EXPERT.md), [`AGENTS.md`](../AGENTS.md), and [`docs/ROADMAP.md`](../docs/ROADMAP.md).

---

## 1. Purpose & `v0.1.0` Scope

**Gashboard `v0.1.0`** gives non-coders, designers, and engineers a clean, modern, **zero-bloat** control panel for managing multiple VPS servers, deploying full **GrabLab + Grex + Groxy AI** sites in one click, opening encrypted local database tunnels, and pushing `Site DNA` updates across servers—**all running strictly on your local computer (`127.0.0.1`) so your VPS never exposes a public control-panel login page to attackers.**

### Included in `v0.1.0`
1. **Discreet Pure `Grex JS v1.0.0` + `GRAB v1.1.0` Control Panel UI (`src/gashboard.grab`, `views/dashboard.grab.html`, `public/gashboard/*.js`):**
   - Runs natively on `grab serve --addr 127.0.0.1:9390 --allow-scripts` (strict `script-src 'self'` CSP, `server.asset` cache-busting, zero Node bundlers, zero Electron/Chromium bloat).
   - Built strictly from the 20 semantic elements in `grex.elements.json` (`divCount === 0`, `innerHTMLWriteCount === 0`, 100% WCAG AA contrast & keyboard navigation).
   - Stores local VPS inventory, tunnel profiles, and deployment audit logs in SQLite (`use data`) with sensitive SSH key passphrases/tokens encrypted via `crypto.encrypt_aead` (`GRAB v1.1.0` AES-256-GCM) using an environment-injected master key (`use env`).
2. **Loopback Go SSH Tunnel & `grabman`/`Grabtaculous` Bridge (`bridge/`):**
   - Lightweight `go 1.26.0` loopback-only sidecar (`127.0.0.1:9391`) authenticated via per-session `crypto.random_urlsafe` bearer secret (`use env`)—never directly exposed outside `127.0.0.1`.
   - Uses `golang.org/x/crypto/ssh` with mandatory `known_hosts` host-key verification (zero `/bin/sh -c` shell interpolation) to reach remote `grabtaculousd` daemons, verify `grabman doctor` / `grabman.lock`, and forward encrypted `127.0.0.1` DB ports.
3. **Multi-VPS Fleet Inventory & Live Health Dashboard:**
   - Manage Staging, Production, and Client VPS nodes with plain-English health indicators (`/ _health` & `/_ready`, active `Grisp` worker counts, CPU/RAM/disk usage formatted with exact `ADR-025c` decimal strings, active edge TLS domain, and `grabtaculousd` version).
4. **1-Click App Marketplace Frontend (Powered by Grabtaculous Catalog):**
   - Interactive plain-English installer featuring **GrabLab CMS `v1.0.1` + Grex Theme Builder `v1.0.0` + Groxy AI `v1.0.0`** alongside curated companion apps (Postgres 18, MariaDB 11.8, Redis, analytics, object storage, automation, webmail).
   - Shows a clear pre-deploy review card (`--read-only` container checks, edge SSL mode **Caddy / Nginx / Cloudflare Tunnel**, `grabman doctor` preflight result) gated by `X-CSRF-Token` + single-use `approval_token` before launching deployment.
5. **Encrypted SSH Database Tunneling (`127.0.0.1`):**
   - 1-click **Open Secure DB Tunnel** button forwarding `127.0.0.1:<local_port>` -> remote `127.0.0.1:<5432|3306|6379>` over encrypted SSH (`max 8` concurrent tunnels, explicit idle/max-duration caps, 1-click **Close Tunnel** revocation).
   - Remote PostgreSQL, MariaDB, and Redis containers never bind to `0.0.0.0`, and Gashboard prints exact safe local connection guidance (`127.0.0.1:<local_port>`) without exposing passwords in the DOM or browser history.
6. **`Site DNA` Fleet Deployer & 1-Click Snapshot Rollback Console:**
   - Import portable **`Site DNA`** JSON bundles exported from **Groxy AI `v1.0.0`** (`GET /api/groxy/site-dna/export`) or local workspaces.
   - Invokes **`grabman dna validate`** + **`grabman dna diff`** + **`grabman solve --verify`** to show a plain-English visual preview of design-token, redirect, product, and lockfile changes before targeting one or more VPS nodes.
   - Dispatches zero-downtime `Grisp` rollouts through **Grabtaculous**, monitors live `/_ready` progression, and surfaces a permanent **1-Click Rollback to Pre-Deploy Snapshot** button per deployment.

### Explicitly Deferred to `v0.2.0+`
- Native Windows WebView2 binary packaging (consolidated into **Step 6 — Groxy Desk**).
- Multi-user team RBAC & enterprise SSO.
- Automated recurring fleet backup scheduling UI.

---

## 2. Planned `v0.1.0` Repository Layout (`C:\Development\gashboard`)

```text
gashboard/
├── GASHBOARD-EXPERT.md
├── AGENTS.md
├── HANDOFF.md
├── README.md
├── LICENSE
├── .gitignore
├── go.mod                                  # For local 127.0.0.1 Go SSH & grabman bridge (go 1.26.0, golang.org/x/crypto)
├── grab.data.json                          # Local SQLite config for Gashboard inventory & audit log
├── grab.platform.json                      # Local cache/rate-limit config
├── migrations/
│   └── 001_gashboard_schema.grab           # Servers, marketplace installs, active tunnels, Site DNA deploy history
├── src/
│   └── gashboard.grab                      # GRAB v1.1.0 web app, CSRF/approval gates, crypto vault & bridge client
├── views/
│   └── dashboard.grab.html                 # Zero-<div> semantic Grex JS v1.0.0 control panel shell
├── public/
│   └── gashboard/
│       ├── gashboard.css                   # Clean semantic styles (WCAG AA Light/Dark tokens, :focus-visible)
│       ├── grex.js                         # Vendored frozen Grex JS v1.0.0 runtime (SHA-256 locked)
│       ├── api-client.js                   # CSRF-aware exact-decimal JSON client (ADR-025c)
│       ├── marketplace.js                  # 1-Click GrabLab + Grex + Groxy AI & companion installer panel
│       ├── tunnels.js                      # 127.0.0.1 Encrypted SSH DB tunnel lifecycle UI
│       ├── fleet-dna.js                    # Site DNA diff previewer, fleet deployer & 1-click rollback console
│       └── dashboard.js                    # Root Grex JS v1.0.0 reactive panel orchestrator
├── bridge/
│   ├── cmd/gashboard-bridge/main.go        # Strictly 127.0.0.1 authenticated SSH + grabman local sidecar
│   └── internal/
│       ├── ssh/
│       │   ├── client.go                   # Host-key-pinned golang.org/x/crypto/ssh transport to grabtaculousd
│       │   └── tunnel.go                   # Bounded 127.0.0.1 local port forwarder (<= 8 active tunnels)
│       └── localcli/
│           └── grabman.go                  # Strict argument-vector invocation of grabman doctor/solve/dna
├── docs/
│   ├── ROADMAP.md
│   └── badges/
│       ├── built-with-grab.svg
│       ├── powered-by-grex-js.svg
│       ├── ecosystem-step-5.svg
│       └── spec-in-review.svg
├── specifications/
│   └── GASHBOARD-SPEC-001.md
└── tests/
    ├── unit_ui_dom.test.js                 # Zero wrapper-<div> (divCount === 0), zero innerHTML, WCAG AA tests
    ├── unit_contracts.test.js              # ADR-025c exact precision, CSRF & single-use approval_token tests
    ├── ssh_tunnel_test.go                  # Go test suite: loopback bind, known_hosts rejection, bounded tunnel cap
    └── integration_e2e.py                  # Full 6-layer E2E: GRAB + Grex JS + grabman + grabtaculous + gashboard
```

---

## 3. Security Architecture & Human-in-the-Loop Gates

### 3.1 Off-Server Threat Elimination (`ADR-005`, `ADR-017`)
| Layer | Isolation Guarantee |
|---|---|
| **Workstation UI (`127.0.0.1:9390`)** | Runs exclusively on local loopback (`grab serve --allow-scripts` without `--allow-public`), minting per-session `X-CSRF-Token` headers. |
| **Go SSH Bridge (`127.0.0.1:9391`)** | Bound strictly to `127.0.0.1`; rejects calls lacking the per-launch `GASHBOARD_BRIDGE_TOKEN` (`crypto.random_urlsafe`); zero shell interpolation (`exec.Command` with fixed allowlisted subcommands / native `x/crypto/ssh`). |
| **SSH Host-Key Pinning** | Refuses unknown or changed VPS host fingerprints (`known_hosts` required; explicit operator trust confirmation flow—never `InsecureIgnoreHostKey`). |
| **Encrypted SSH DB Tunnels** | Binds `127.0.0.1:<port>` only; max `8` active tunnels; configurable TTL (default `60m`); auto-closes cleanly on shutdown (`SIGINT`/`SIGTERM`). |
| **Single-Use `approval_token` Gate** | Deploying a Marketplace stack, pushing a `Site DNA` fleet rollout, or executing a Snapshot Rollback requires a fresh `X-CSRF-Token` + single-use `approval_token` (`403` invalid, `409` replay). |

---

## 4. GRAB `v1.1.0` HTTP Endpoints (`src/gashboard.grab`)

| Route | Auth / Safety Gate | Behavior |
|---|---|---|
| `GET /_health`, `GET /_ready` | Loopback read-only | Service liveness & readiness (checks SQLite + bridge connectivity). |
| `GET /` & `GET /gashboard` | Mints `X-CSRF-Token` | Renders pure `Grex JS v1.0.0` zero-`<div>` control panel UI (`views/dashboard.grab.html`) using `server.asset`. |
| `GET /api/vps` | Read-only JSON | Lists registered VPS nodes, pinned host fingerprints, and cached health status (`ADR-025c` string numbers). |
| `POST /api/vps/register` | `X-CSRF-Token` | Registers/tests a VPS host (`known_hosts` verified) and stores encrypted SSH metadata (`crypto.encrypt_aead`). |
| `POST /api/vps/{id}/probe` | `X-CSRF-Token` | Queries remote `grabtaculousd` over SSH for live `Grisp` worker health, `/_ready`, and TLS domains. |
| `GET /api/marketplace/catalog` | Read-only JSON | Returns **Grabtaculous** pinned blueprints (`grablab-grex-bundle`, `grablab-full-stack`, `grab-grisp-app`, companions). |
| `POST /api/marketplace/plan` | `X-CSRF-Token` | Runs `grabman doctor` + Compose `--read-only` preview and mints single-use `approval_token`. |
| `POST /api/marketplace/deploy` | `X-CSRF-Token` + single-use `approval_token` | Triggers **Grabtaculous** 1-click deployment over SSH with automatic Pre-Deploy Snapshot creation. |
| `GET /api/tunnels` | Read-only JSON | Lists active `127.0.0.1` SSH DB tunnels (host, engine, local loopback port, expires_at). |
| `POST /api/tunnels/open` | `X-CSRF-Token` | Opens a `127.0.0.1` SSH tunnel to a remote private DB (`postgres`, `mariadb`, or `redis`). |
| `POST /api/tunnels/close` | `X-CSRF-Token` | Cleanly closes a specific active tunnel. |
| `POST /api/fleet/dna/preview` | `X-CSRF-Token` | Imports **Groxy AI** `Site DNA` JSON, runs `grabman dna validate/diff` + `grabman solve --verify`, and mints `approval_token`. |
| `POST /api/fleet/dna/deploy` | `X-CSRF-Token` + single-use `approval_token` | Executes zero-downtime `Grisp` fleet rollout via **Grabtaculous** across selected VPS nodes. |
| `GET /api/fleet/snapshots` | Read-only JSON | Lists remote Pre-Deploy Snapshots with SHA-256 verification status. |
| `POST /api/fleet/rollback` | `X-CSRF-Token` + single-use `approval_token` | Triggers 1-click atomic **Grabtaculous** Pre-Deploy Snapshot Rollback and verifies `/_ready === 200`. |

---

## 5. `v0.1.0` Acceptance & Verification Gates

`Gashboard v0.1.0` is eligible for completion and synchronized `origin` + `stable` promotion **only** when **100%** of these gates pass:
1. **GRAB CLI Static & Canonical Format Parity:**
   - `grab check --platform-config grab.platform.json --db-config grab.data.json src/gashboard.grab` and `.grab.html` template compilation exit `0`.
   - Non-destructive `grab format src/gashboard.grab` stdout matches `src/gashboard.grab` byte-for-byte.
2. **Pure `Grex JS v1.0.0`, Zero Wrapper-`<div>` & WCAG AA Verification (`tests/unit_ui_dom.test.js`, `tests/unit_contracts.test.js`):**
   - Verifies `divCount === 0` across `views/dashboard.grab.html` and every panel in `public/gashboard/*.js` (`marketplace.js`, `tunnels.js`, `fleet-dna.js`, `dashboard.js`).
   - Verifies `innerHTMLWriteCount === 0`, zero `eval()`/`new Function()`, zero unsafe URLs, `100%` `auditAccessibility()` pass, exact `ADR-025c` string precision, `X-CSRF-Token` (`403`), and single-use `approval_token` (`403`/`409` replay) enforcement.
3. **Go Loopback SSH Bridge & Tunnel Security Suite (`bridge/`: `go test -count=1 ./...`, `govulncheck ./...`):**
   - Proves bridge refuses unauthenticated calls, binds DB tunnels strictly to `127.0.0.1`, enforces `known_hosts` verification (rejecting unknown host keys), caps concurrent tunnels at `8`, and tears down tunnels cleanly on shutdown.
4. **Live 6-Layer Cross-Repo E2E Integration (`python tests/integration_e2e.py`):**
   - Wires **GRAB `v1.1.0` + Grex JS `v1.0.0` + Groxy AI `v1.0.0` (`Site DNA` export) + `grabman v0.1.0` + Grabtaculous `v0.1.0` + Gashboard `v0.1.0`** against a local test SSH/daemon loop:
     - Verifies 1-click Marketplace plan & `--read-only` deploy (`GrabLab + Grex + Groxy AI`).
     - Verifies `127.0.0.1` SSH DB tunnel open/forward/close lifecycle.
     - Verifies `Site DNA` import -> `grabman` lockfile check -> zero-downtime rollout -> 1-click Pre-Deploy Snapshot Rollback.
5. **Plain-English Release Guide & Dual-Repo Promotion (upon `v0.1.0` completion):**
   - Generates `docs/releases/pdf/Gashboard-v0.1.0-Guide.pdf`, `dist/` bundle + `SHA256SUMS.txt`, runs `sync-notebook-sources.ps1`, and publishes synchronized `v0.1.0` GitHub Releases with the mandatory **Release Type & Affected Layers** + **6-Layer Ecosystem Compatibility Matrix** block to `urbanspress/gashboard.progress` and `urbanspress/gashboard.stable`.
