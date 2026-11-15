# Gashboard Roadmap

**Repositories:** `urbanspress/gashboard.progress` (active development) / `urbanspress/gashboard.stable` (verified releases)  
**Foundational Baselines:** **GRAB `v1.1.0`**, **Grex JS `v1.0.0`**, **GrabLab CMS `v1.0.1`**, **Grex Theme Builder `v1.0.0`**, **Groxy AI `v1.0.0`**, **`grabman v0.1.0`**, and **Grabtaculous `v0.1.0`**

**Status Labels:**
- **Specification in Review** — Specification drafted and awaiting explicit project-owner approval before any `.grab`, `.js`, or Go implementation code is written.
- **Approved** — Authorized by the project owner for implementation.
- **Complete** — Implemented, `grab check` / `grab format` clean, Go bridge tests + Node zero-`<div>` DOM/A11y tests + cross-layer E2E passing `100%`, walkthrough PDF generated, and synchronized to `origin` + `stable`.
- **Planned** — Future milestone awaiting prior milestone completion and spec drafting.

---

## `v0.1.0` — Discreet Pure `Grex JS v1.0.0` Multi-VPS Control Panel, 1-Click App Marketplace UI, Encrypted SSH DB Tunneling & `Site DNA` Fleet Deployer

**Status:** Specification in Review ([`specifications/GASHBOARD-SPEC-001.md`](../specifications/GASHBOARD-SPEC-001.md))

Planned Scope (Awaiting Approval):
- **Discreet Localhost Control Plane (`127.0.0.1`-Only):** Runs locally on the user's workstation (`GRAB v1.1.0` + `Grex JS v1.0.0` zero-`<div>` UI paired with a `127.0.0.1` Go SSH bridge), eliminating public VPS control-panel login pages (`ADR-005`, `ADR-017`).
- **Multi-VPS Fleet Inventory & Live Health Telemetry:** Key-authenticated, `known_hosts`-pinned VPS server inventory displaying live `Grisp` worker health, `/_ready` probes, edge TLS domains, and exact `ADR-025c` resource numbers.
- **1-Click App Marketplace UI:** Point-and-click deployment wizard powered by **Grabtaculous** blueprints—highlighting **`GrabLab CMS v1.0.1 + Grex Theme Builder v1.0.0 + Groxy AI v1.0.0`**, custom domain + Caddy/Nginx/Cloudflare SSL wiring, `--read-only` security preview, and `grabman doctor` preflight validation.
- **Encrypted SSH Database Tunneling (`127.0.0.1`):** 1-click loopback port forwards (`127.0.0.1:<local_port>`) to remote PostgreSQL, MariaDB, and Redis containers over encrypted SSH without exposing database ports publicly.
- **`Site DNA` Fleet Deployer & 1-Click Snapshot Rollback:** Imports **Groxy AI** `Site DNA` (`GET /api/groxy/site-dna/export`), runs `grabman` diff & `grabman.lock` verification, executes zero-downtime **Grabtaculous** `Grisp` fleet rollouts behind `X-CSRF-Token` + single-use `approval_token`, and surfaces 1-click Pre-Deploy Snapshot Rollbacks.

---

## `v0.2.0` — Fleet Canary Promotion, Scheduled Off-Peak Snapshot Verification & Multi-Server Metrics History

**Status:** Planned

Planned Scope:
- One-click **Staging -> Production** `Site DNA` diff & canary rollout promotion across tagged server groups.
- Encrypted local telemetry retention and off-peak backup integrity checks.

---

## `v1.0.0` — Production Freeze, Desktop Launcher Packaging & Full 6-Layer E2E Verification

**Status:** Planned

Planned Scope:
- Independent `Orchestrator (Argon)` cross-layer security, SSH tunnel, zero-`<div>` DOM, WCAG AA, and rollout/rollback audit across all 6 ecosystem layers.
- Branded release archive, walkthrough PDF, and synchronized `v1.0.0` release on `origin` and `stable` (providing the direct runtime foundation for **Step 6 — Groxy Desk**).
