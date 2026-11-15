# HANDOFF.md — Gashboard

- **Current Owner:** Google Antigravity (`v0.2.0` & `v0.3.0` Specifications Drafted; awaiting explicit project-owner approval before any `v0.2.0` or `v0.3.0` implementation code is written)
- **Current Milestone State:**
  - **`v0.1.0` — `Complete`** ([`specifications/GASHBOARD-SPEC-001.md`](specifications/GASHBOARD-SPEC-001.md), [`CHANGELOG.md`](CHANGELOG.md), published on `origin` & `stable`)
  - **`v0.2.0` — `Specification in Review`** ([`specifications/GASHBOARD-SPEC-002.md`](specifications/GASHBOARD-SPEC-002.md)) — Zero `v0.2.0` application code written per Spec-First Approval Gate.
  - **`v0.3.0` — `Specification in Review`** ([`specifications/GASHBOARD-SPEC-003.md`](specifications/GASHBOARD-SPEC-003.md)) — Zero `v0.3.0` application code written per Spec-First Approval Gate.
- **Next Action:** Project owner reviews [`specifications/GASHBOARD-SPEC-002.md`](specifications/GASHBOARD-SPEC-002.md) and [`specifications/GASHBOARD-SPEC-003.md`](specifications/GASHBOARD-SPEC-003.md) and approves before implementing **`v0.2.0`** on **`Google Hydrogen (High)`** / **`(Extra)`** (keeping **`Orchestrator (Argon)`** queued for the pre-`v1.0.0` Step 5 audit once `v0.2.0` and `v0.3.0` are complete).

---

## Frozen Upstream Contracts (Unmodified)
- **GRAB:** `v1.1.0` (`urbanspress/grab`)
- **Grex JS:** `v1.0.0` (`urbanspress/grex-js`)
- **GrabLab CMS:** `v1.0.1` (`urbanspress/grablab-cms`)
- **Grex Theme Builder:** `v1.0.0` (`urbanspress/grex-builder`)
- **Groxy AI:** `v1.0.0` (`urbanspress/groxy-ai`)
- **`grabman`:** `v0.1.0` (`urbanspress/grabman`)
- **Grabtaculous:** `v0.1.0` (`urbanspress/grabtaculous`)

---

## Recent Completion Log
1. **`v0.1.0` Released (`e73a05e`, tag `v0.1.0`):** Pure `Grex JS v1.0.0` zero-`<div>` control panel, `GRAB v1.1.0` server + `AES-256-GCM` vault, Go `127.0.0.1` SSH bridge (`known_hosts` pinning, `<= 8` DB tunnels), 1-click Marketplace, `Site DNA` fleet deployer + 1-click rollback, PDF guide, and synchronized GitHub Releases on `origin` and `stable`.
2. **Pre-`v1.0.0` Feature Expansion Specs Drafted (Docs Only):**
   - Drafted [`specifications/GASHBOARD-SPEC-002.md`](specifications/GASHBOARD-SPEC-002.md) (`v0.2.0`: WCAG AA Light/Dark Theme Switcher + Built-In phpMyAdmin-Style Visual Database Manager over `127.0.0.1` SSH tunnels & local SQLite).
   - Drafted [`specifications/GASHBOARD-SPEC-003.md`](specifications/GASHBOARD-SPEC-003.md) (`v0.3.0`: Namecheap DNS + Auto-HTTPS Wizard with `AES-256-GCM` credential vault, `MX`/`TXT`/`SPF`/`DKIM` preservation, propagation preflight guard, and Grabtaculous HTTPS + 1-click rollback).
   - Updated [`docs/ROADMAP.md`](docs/ROADMAP.md) and pushed docs-only changes to `origin/main` (`stable` untouched on `v0.1.0`).

---

## Next Step Model Guidance
- **Recommended Model Once Specs Are Approved:** **`Google Hydrogen (High)`** (or **`Google Hydrogen (Extra)`** for multi-layer Go DB/DNS bridge + GRAB + `Grex JS` UI wiring) to implement **`v0.2.0`** first, then **`v0.3.0`**.
- **Pre-`v1.0.0` Audit Gate:** After `v0.2.0` and `v0.3.0` are implemented and verified, pause and switch to **`Orchestrator (Argon)`** for the independent cross-layer pre-`v1.0.0` Step 5 audit.
