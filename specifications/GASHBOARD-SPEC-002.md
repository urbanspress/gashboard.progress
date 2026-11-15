# GASHBOARD-SPEC-002: Gashboard `v0.2.0` — Light/Dark Theme Switcher & Built-In phpMyAdmin-Style Visual Database Manager

- **Status:** Specification in Review (Awaiting Project-Owner Approval — zero `v0.2.0` application code written)
- **Milestone:** `v0.2.0` — Step 5 Visual Database Operations & Accessible Theme System
- **Foundational Upstream & Peer Baselines:**
  - **GRAB:** `v1.1.0` (`urbanspress/grab` — `grab serve --allow-scripts`, `server.asset`, `use server`, `use data`, `use cache`, `use http`, `use json`, `use crypto` AES-256-GCM, `use env`, `ADR-005`, `ADR-017`, `ADR-025c`)
  - **Grex JS:** `v1.0.0` (`urbanspress/grex-js` — `grex.elements.json` 20 semantic elements, `createTheme`, `computeContrastRatio`, `signal`/`computed`/`effect`, `setSafeText`, `validateElementNode()`, `auditAccessibility()`, zero wrapper-`<div>` DOM)
  - **`grabman` & Grabtaculous:** `v0.1.0` (`urbanspress/grabman`, `urbanspress/grabtaculous` — `grabtaculousd` Pre-Deploy / Pre-Mutation Snapshots & rollback over `127.0.0.1` SSH)
  - **Gashboard:** `v0.1.0` ([`GASHBOARD-SPEC-001.md`](GASHBOARD-SPEC-001.md) — loopback `127.0.0.1` control plane, `gashboard-bridge`, `<= 8` concurrent SSH DB tunnels)
- **Governance:** Read alongside [`GASHBOARD-EXPERT.md`](../GASHBOARD-EXPERT.md), [`AGENTS.md`](../AGENTS.md), and [`docs/ROADMAP.md`](../docs/ROADMAP.md).

---

## 1. Purpose & `v0.2.0` Scope

**Gashboard `v0.2.0`** removes the need to expose phpMyAdmin, Adminer, or pgAdmin on any public server port—or even install a separate desktop SQL client—by adding a **built-in phpMyAdmin-style visual database manager** that operates strictly inside Gashboard's encrypted `127.0.0.1` SSH database tunnels and local SQLite workspace, paired with an accessible **WCAG AA Light/Dark Theme Switcher**.

### Included in `v0.2.0`
1. **WCAG AA Light/Dark Theme Switcher (`public/gashboard/theme.js`, `public/gashboard/gashboard.css`, `src/gashboard.grab`):**
   - Reactive **`Grex JS v1.0.0`** theme controller built with `createTheme` and verified by `computeContrastRatio()` (`>= 4.5:1` for normal text, `>= 3.0:1` for large text and UI borders across all Light and Dark semantic surfaces).
   - Zero wrapper `<div>` elements (`divCount === 0`), zero `innerHTML` writes, intact `:focus-visible` keyboard focus rings in both themes, and **zero FOUC** (Flash of Unstyled Content) by applying the persisted `data-gashboard-theme` attribute from SQLite preferences (`GET /api/preferences/theme`) and local preference storage before first paint.
   - Accessible `<button>` toggle in the top `<header>`/`<nav>` bar with clear `aria-pressed` state and plain-English label (`"Switch to Dark Mode"` / `"Switch to Light Mode"`).

2. **Built-In phpMyAdmin-Style Visual Database Manager (`public/gashboard/db-manager.js`, `src/gashboard.grab`, `bridge/internal/dbinspect/`):**
   - **Loopback-Only Tunnel Transport (`ADR-005`, `ADR-017`):** Connects exclusively through Gashboard's `known_hosts`-pinned `127.0.0.1` SSH tunnels (`PostgreSQL`, `MariaDB`) or confined local SQLite (`storage/gashboard.db` / allowlisted workspace `.db` paths)—never opening a public phpMyAdmin/Adminer web port on any VPS.
   - **Semantic Visual Schema & Table Explorer:** Browse databases, schemas, tables, column names/types/nullability, indexes, foreign keys, and exact row counts using pure `Grex JS v1.0.0` semantic elements (`<table>`, `<thead>`, `<tbody>`, `<section>`, `<nav>`, `<aside>`, `<form>`, `<dialog>`, `<details>`; `divCount === 0`, `innerHTMLWriteCount === 0`).
   - **Paginated Row Browser, Safe Filter & Exact `ADR-025c` Numeric Fidelity:**
     - Inspect and filter table rows with strictly bounded page limits (`1 <= limit <= 100` rows/page; `422 GASH-E422` if exceeded) and parameterized filters (zero SQL string concatenation).
     - Preserves every `GrabDecimal`, `GrabInteger`, `NUMERIC`, `DECIMAL`, `BIGINT`, and primary-key ID as an **exact base-10 wire string** across Go bridge JSON, GRAB server routes, and the browser UI—guaranteeing zero IEEE-754 floating-point drift.
   - **Guarded Query Runner & Human-in-the-Loop Write/Migration Gate (`GROXY-SAFE-001`):**
     - **Read-Only Default:** `SELECT`, `SHOW`, `DESCRIBE`, and `EXPLAIN` inspection runs safely in read-only transaction mode with bounded row limits and query timeout (`<= 10s`).
     - **Human-in-the-Loop Mutation Gate:** Any `INSERT`, `UPDATE`, `DELETE`, DDL change (`CREATE`/`ALTER`/`DROP`), or SQL import/export operation is blocked from direct execution and must pass a **2-step preview + confirmation**:
       1. `POST /api/db/mutate/plan` classifies the operation, displays a plain-English impact summary (affected table/rows, rollback plan), triggers/verifies an automatic **Pre-Mutation Snapshot** (local SQLite backup or **Grabtaculous** remote snapshot), and mints a single-use `approval_token`.
       2. `POST /api/db/mutate/execute` requires `X-CSRF-Token` + single-use `approval_token` (`403 GASH-E403` if invalid/missing, `409 GASH-E409` on replay).

### Explicitly Deferred to `v0.3.0+`
- Namecheap DNS & Auto-HTTPS Wizard (`v0.3.0`, [`GASHBOARD-SPEC-003.md`](GASHBOARD-SPEC-003.md)).
- Multi-server fleet canary promotion & scheduled off-peak backup verification (`v0.4.0+` / `v1.0.0`).

---

## 2. Planned `v0.2.0` Repository Additions (`C:\Development\gashboard`)

```text
gashboard/
├── migrations/
│   └── 002_theme_and_db_prefs.grab        # Persists UI theme preference & DB audit/snapshot history
├── src/
│   └── gashboard.grab                     # Adds /api/preferences/theme and /api/db/* routes
├── views/
│   └── dashboard.grab.html                # Pre-paint theme attribute + DB Manager navigation tab
├── public/gashboard/
│   ├── gashboard.css                      # WCAG AA Light & Dark custom properties + zero-FOUC rules
│   ├── theme.js                           # Grex JS v1.0.0 createTheme + computeContrastRatio() switcher
│   ├── db-manager.js                      # Pure Grex JS phpMyAdmin-style schema/row/query/mutation UI
│   └── dashboard.js                       # Integrates theme toggle & Database Manager panel
├── bridge/internal/dbinspect/
│   ├── inspector.go                       # Parameterized Postgres/MariaDB/SQLite schema & row inspector
│   └── inspector_test.go                  # Go unit tests: read-only default, <=100 row cap, ADR-025c strings
└── tests/
    ├── unit_ui_dom.test.js                # Extended: Light/Dark >= 4.5:1 contrast, divCount === 0 on db-manager.js
    ├── unit_contracts.test.js             # Extended: ADR-025c string fidelity, <=100 page cap, 403/409 mutation gate
    └── integration_e2e.py                 # Extended: live DB inspection over 127.0.0.1 SSH tunnel + snapshot mutation gate
```

---

## 3. Security Architecture & `ADR-025c` / `GROXY-SAFE-001` Contracts

| Control | Guarantee |
|---|---|
| **Zero Public DB Admin Exposure (`ADR-005`)** | Remote DB inspection routes exclusively through an active `gashboard-bridge` `127.0.0.1` SSH tunnel (`tun_*`). Direct public IP/port DB connections are rejected (`422 GASH-E422`). |
| **Zero SQL Injection** | Schema explorer and row browser use allowlisted catalog queries and parameterized placeholders (`$1`, `?`). Identifier names (database/table/column) are validated against strict `[A-Za-z0-9_]+` allowlists. |
| **Read-Only Default + `GROXY-SAFE-001` Gate** | `POST /api/db/query` executes inside a read-only transaction (`SET TRANSACTION READ ONLY` / SQLite `query_only = ON`) and rejects mutating statements (`403 GASH-E403`). Writes/DDL must pass `plan` -> Pre-Mutation Snapshot -> `execute` with `X-CSRF-Token` + single-use `approval_token`. |
| **Exact `ADR-025c` Wire Strings** | All numeric database values (`NUMERIC`, `DECIMAL`, `BIGINT`, `GrabDecimal`, `GrabInteger`) and pagination bounds (`page`, `limit`) travel as base-10 wire strings—never converted to JS/JSON floats. |
| **Credential Isolation** | Database credentials entered for a tunnel session are encrypted in memory/vault via `crypto.encrypt_aead` and never echoed in `/api/db/*` responses, DOM attributes, or logs. |

---

## 4. Planned GRAB `v1.1.0` HTTP Endpoints (`v0.2.0` Additions)

| Route | Auth / Safety Gate | Behavior |
|---|---|---|
| `GET /api/preferences/theme` | Loopback read-only | Returns active theme (`"light"` or `"dark"`) and WCAG AA token metadata. |
| `POST /api/preferences/theme` | `X-CSRF-Token` | Validates `"light"` / `"dark"`, persists to SQLite, and returns updated theme state. |
| `GET /api/db/targets` | Loopback read-only | Lists inspectable DB targets: active `127.0.0.1` SSH tunnels + confined local SQLite targets. |
| `GET /api/db/schema` | Loopback read-only | Lists databases, tables, columns, types, indexes, foreign keys, and exact base-10 row counts. |
| `POST /api/db/rows` | `X-CSRF-Token` | Paginated row browser + safe column filter (`limit <= 100`, `ADR-025c` base-10 string preservation). |
| `POST /api/db/query` | `X-CSRF-Token` | Read-only `SELECT`/`EXPLAIN` query runner (`query_only` / `READ ONLY` transaction enforced). |
| `POST /api/db/mutate/plan` | `X-CSRF-Token` | Previews write/DDL/import statement, creates/verifies Pre-Mutation Snapshot, mints `approval_token`. |
| `POST /api/db/mutate/execute` | `X-CSRF-Token` + single-use `approval_token` | Executes approved mutation/DDL/import (`403` invalid, `409` replay) and logs audit record. |

---

## 5. `v0.2.0` Acceptance & Verification Gates

`Gashboard v0.2.0` is eligible for completion and synchronized `origin` + `stable` release **only** when **100%** of these gates pass:
1. **`grab check` & Canonical `grab format` Parity:** Zero errors on `src/gashboard.grab`, `migrations/002_theme_and_db_prefs.grab`, and `views/dashboard.grab.html`, with byte-for-byte `grab format` parity.
2. **Pure `Grex JS v1.0.0`, Light/Dark WCAG AA & Zero-`<div>` Tests (`node --test tests/*.test.js`):**
   - `divCount === 0`, `innerHTMLWriteCount === 0`, and `100%` `auditAccessibility()` pass across Light and Dark modes (`computeContrastRatio() >= 4.5:1`).
   - Exact `ADR-025c` numeric string preservation (`"12345678901234567890.1234"` intact without float rounding), `limit <= 100` enforcement, and `403`/`409` mutation gate tests pass.
3. **Go DB Inspector & Security Suite (`go test -count=1 ./...` + `govulncheck ./...`):**
   - Zero vulnerabilities; proves read-only default enforcement, identifier allowlisting, parameterized filtering, and loopback-only tunnel targeting.
4. **Live E2E Integration (`python tests/integration_e2e.py`):**
   - Exercises theme switching, live table/schema inspection and paginated row browsing over an active `127.0.0.1` tunnel + local SQLite, read-only query rejection of mutating SQL, and Pre-Mutation Snapshot + single-use `approval_token` mutation flow (`409` on replay).
5. **Release Artifacts & Snapshot Sync:** Generates `docs/releases/pdf/Gashboard-v0.2.0-Guide.pdf`, `dist/` binaries/bundle + `SHA256SUMS.txt`, runs `sync-notebook-sources.ps1`, and publishes synchronized `v0.2.0` GitHub Releases with the **SemVer + 6-Layer Ecosystem Compatibility Matrix**.
