# Gashboard

![Built with GRAB v1.1.0](docs/badges/built-with-grab.svg)
![Powered by Grex JS v1.0.0](docs/badges/powered-by-grex-js.svg)
![GRAB Ecosystem Step 5 — Gashboard](docs/badges/ecosystem-step-5.svg)
![v0.1.0 Spec — In Review](docs/badges/spec-in-review.svg)

**Gashboard** is the Discreet Pure **`Grex JS v1.0.0`** Multi-VPS Web Control Panel, 1-Click App Marketplace UI (**GrabLab CMS + Grex Theme Builder + Groxy AI**), Encrypted `127.0.0.1` SSH Database Tunneling Manager, and `Site DNA` Fleet Deployer for **Step 5 of the Post-1.0 GRAB Ecosystem**.

- **Current Status:** `v0.1.0` — **Released** ([`specifications/GASHBOARD-SPEC-001.md`](specifications/GASHBOARD-SPEC-001.md) implemented, verified 100% across all 3 gates, and published on `origin` & `stable`).
- **Walkthrough Guide (PDF):** [`docs/releases/pdf/Gashboard-v0.1.0-Guide.pdf`](docs/releases/pdf/Gashboard-v0.1.0-Guide.pdf)
- **Changelog:** [`CHANGELOG.md`](CHANGELOG.md)
- **Development Repo (`origin`):** `https://github.com/urbanspress/gashboard.progress`
- **Production Release Repo (`stable`):** `https://github.com/urbanspress/gashboard.stable`

---

## Quick Start (`v0.1.0` Local Workstation)

```powershell
# 1. Run SQLite schema migration once
grab migrate --db-config grab.data.json --allow-db main:migrate migrations/001_gashboard_schema.grab

# 2. Start the 127.0.0.1 Go SSH & CLI bridge
go run ./bridge/cmd/gashboard-bridge --listen 127.0.0.1:9450 --known-hosts $HOME\.ssh\known_hosts

# 3. Start Gashboard strictly on loopback 127.0.0.1:9390
grab serve --addr 127.0.0.1:9390 --allow-scripts --static public `
  --db-config grab.data.json --allow-db main:read-write `
  --platform-config grab.platform.json --allow-cache gashboard:read-write `
  --allow-read . --allow-write storage `
  --allow-env GASHBOARD_MASTER_KEY,GASHBOARD_BRIDGE_URL,GASHBOARD_BRIDGE_TOKEN,GASHBOARD_GRABTACULOUS_URL,GASHBOARD_GRABTACULOUS_TOKEN `
  --allow-net 127.0.0.1:9450,127.0.0.1:9440 src/gashboard.grab
```

Open `http://127.0.0.1:9390/gashboard` in your browser. For plain-English setup and SSH tunnel instructions, see [`docs/releases/pdf/Gashboard-v0.1.0-Guide.pdf`](docs/releases/pdf/Gashboard-v0.1.0-Guide.pdf).

---

## Core Architecture Pillars (`v0.1.0`)

1. **Zero Public VPS Login Attack Surface (`ADR-005`, `ADR-017`):**
   - **Gashboard** lives purely on your local workstation (`127.0.0.1`), managing remote servers via encrypted, `known_hosts`-pinned SSH connections to **Grabtaculous**—never opening a public control-panel web port on your VPS.
2. **Pure `Grex JS v1.0.0` + `GRAB v1.1.0` Zero-`<div>` Control Panel:**
   - Built with zero Node build bundlers, zero wrapper `<div>` elements (`divCount === 0`), zero `innerHTML` writes, `100%` WCAG AA contrast/accessibility, `server.asset` asset fingerprinting, AES-256-GCM encrypted vault storage (`use crypto`), and exact `ADR-025c` resource numbers.
3. **1-Click App Marketplace (`GrabLab CMS + Grex Theme Builder + Groxy AI`):**
   - Deploy hardened `--read-only` **GrabLab CMS `v1.0.1` + Grex Theme Builder `v1.0.0` + Groxy AI `v1.0.0`** stacks (and curated self-hosted companion apps) with automatic **Caddy** / **Nginx** / **Cloudflare Tunnel** SSL and `grabman doctor` preflight verification.
4. **Encrypted SSH Database Tunneling (`127.0.0.1`) & `Site DNA` Fleet Deployer:**
   - Create instant loopback `127.0.0.1` SSH tunnels to remote PostgreSQL, MariaDB, or Redis instances, import portable **Groxy AI** `Site DNA` snapshots validated by **`grabman`**, execute zero-downtime `Grisp` rollouts via **Grabtaculous**, and roll back in 1 click to Pre-Deploy Snapshots.

---

## 6-Layer Ecosystem Compatibility Matrix

| Ecosystem Layer | Repository | Required Version Range | Role |
|---|---|---|---|
| **Core Language, Bytecode VM & Grisp Server** | `urbanspress/grab` | `>= v1.1.0 (< v2.0.0)` | Executes Gashboard `.grab`/`.grab.html`, `use crypto`, `use data`, `server.asset` |
| **Reactive Frontend Runtime & 20-Element Library** | `urbanspress/grex-js` | `>= v1.0.0 (< v2.0.0)` | Reactive signals, 20 semantic elements, `auditAccessibility()` |
| **Flagship Zero-Plugin CMS** | `urbanspress/grablab-cms` | `>= v1.0.1 (< v2.0.0)` | Deployed & managed via 1-click Marketplace stacks |
| **Exclusive `mode: "visual"` Theme & Studio** | `urbanspress/grex-builder` | `>= v1.0.0 (< v2.0.0)` | Pre-wired exclusive visual theme & `GRAB-DESIGN-SYSTEM.md` source |
| **Autonomous Design, Content & SEO Agent** | `urbanspress/groxy-ai` | `>= v1.0.0 (< v2.0.0)` | Supplies `Site DNA` exports (`groxy-site-dna-v0.4.0`) & optional AI stack |
| **Scaffolder, Orchestrator & Discreet VPS Panel** | `urbanspress/grabman`, `urbanspress/grabtaculous`, `urbanspress/gashboard` | `>= v0.1.0` | Lockfile verification, `--read-only` orchestration, SSH DB tunnels & pure `Grex JS` control panel |

---

## Governance & Specifications

- [Agent Rules (`AGENTS.md`)](AGENTS.md)
- [Engineering Invariants (`GASHBOARD-EXPERT.md`)](GASHBOARD-EXPERT.md)
- [`v0.1.0` Specification (`specifications/GASHBOARD-SPEC-001.md`)](specifications/GASHBOARD-SPEC-001.md)
- [Roadmap (`docs/ROADMAP.md`)](docs/ROADMAP.md)
- [Handoff Log (`HANDOFF.md`)](HANDOFF.md)
- [License (`LICENSE` — MIT)](LICENSE)
