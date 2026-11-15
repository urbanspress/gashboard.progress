# AGENTS.md — Gashboard

**Gashboard** (`urbanspress/gashboard.progress` / `urbanspress/gashboard.stable`, local directory `C:\Development\gashboard`) is the Discreet Pure **`Grex JS v1.0.0`** Multi-VPS Control Panel, 1-Click App Marketplace Frontend, Encrypted SSH Database Tunneling Manager, and `Site DNA` Fleet Deployer for **Step 5 of the Post-1.0 GRAB Ecosystem**.

---

## 1. Core Invariants & Upstream Scope
1. **Read [`GASHBOARD-EXPERT.md`](GASHBOARD-EXPERT.md) first** before drafting any specification, editing any file, or reviewing any pull request.
2. **Respect Ecosystem Layer Boundaries:** Build **Gashboard** purely on **GRAB `v1.1.0`** (`grab serve --allow-scripts`, `server.asset`, `use server`, `use data`, `use cache`, `use crypto`, `use env`), **Grex JS `v1.0.0`** (`grex.elements.json`, `validateElementNode`, `auditAccessibility`, reactive signals), **`grabman v0.1.0`** (`grabman init`, `grabman doctor`, `grabman solve`, `grabman dna`), and **Grabtaculous `v0.1.0`** (`grabtaculousd` SSH-tunneled loopback control plane, catalog, zero-downtime `Grisp` rollouts, snapshot rollbacks). Never duplicate core GRAB compiler internals, `grex-js` core source, or `grabtaculous` container logic inside `gashboard`.
3. **Discreet Off-Server Control Plane (`ADR-005`, `ADR-017`):** Gashboard runs locally on the operator's workstation (`127.0.0.1` loopback default)—eliminating public web control-panel login ports on remote VPS servers. All SSH connections require strict host-key verification (`known_hosts`) and key/agent authentication, and SSH database tunnels bind strictly to `127.0.0.1`.
4. **Zero Build-Step / Zero Wrapper-`<div>` Pure `Grex JS v1.0.0` UI:** All Gashboard templates (`views/*.grab.html`) and reactive scripts (`public/gashboard/*.js`) MUST contain zero wrapper `<div>` elements (`divCount === 0`), zero `innerHTML` writes, zero React/Vue/Node bundlers, and 100% WCAG AA pass (`auditAccessibility()`).

---

## 2. Workflow, Spec Gate & Verification Gates
- **Spec-First Approval Gate:** Do NOT write `gashboard` application code (`src/`, `views/`, `public/`, `bridge/`, `migrations/`, `tests/`) until the active milestone specification (starting with `specifications/GASHBOARD-SPEC-001.md`) has been reviewed and explicitly approved by the project owner.
- **Plain-English User Communication:** The project owner directs development in plain English. Always explain VPS management, SSH DB tunnels, `Site DNA` fleet rollouts, and snapshot rollbacks simply without unnecessary jargon. Handle all file edits, git commands, and terminal verification directly.
- **No Unapproved Commits/Pushes:** Do not commit, push, or publish releases without explicit project-owner approval (explicitly requested repository bootstraps excepted).
- **Mandatory Test & Lint Gate:** Before marking any implementation milestone complete or requesting release promotion:
  1. Run `grab check` on all `.grab` and `.grab.html` files with zero errors and confirm non-destructive `grab format <file>` byte-for-byte parity.
  2. Run `go build ./...`, `go test -count=1 ./...`, and `govulncheck ./...` on the Go local SSH/bridge sidecar (`bridge/`).
  3. Verify `divCount === 0`, `innerHTMLWriteCount === 0`, zero unsafe URLs, `100%` `auditAccessibility()` pass, and exact `ADR-025c` numeric preservation across all Gashboard UI views (`node --test tests/*.test.js`).
  4. Run the full cross-layer integration suite (`grab` + `Grex JS` + `grabman` + `grabtaculous` + `gashboard`) with **100% passing results**.

---

## 3. Two-Repository Workflow & Release Protection
- **Repository Roles:**
  - `origin` (`https://github.com/urbanspress/gashboard.progress.git`): Active development repository for specifications, drafts, work-in-progress checkpoints, and milestone commits.
  - `stable` (`https://github.com/urbanspress/gashboard.stable.git`): Production release repository for 100% verified milestone releases only.
- **Strict `stable` Protection:** All AI agents and models MUST push work-in-progress commits, unapproved specs, and partial checkpoints ONLY to `origin` (`urbanspress/gashboard.progress`). Pushing to `stable` (`urbanspress/gashboard.stable`) is strictly forbidden unless the milestone is 100% `Complete` in `docs/ROADMAP.md`, all verification gates pass 100%, and `HANDOFF.md` records no pending milestone tasks.
- **Synchronized Releases & Walkthrough PDFs:** Whenever a completed milestone (`v0.1.0` onward) is promoted to `stable`, push `main` and annotated version tags in strict ascending chronological order to both `origin` and `stable`, generate the plain-English walkthrough PDF (`docs/releases/pdf/Gashboard-v<X.Y.Z>-Guide.pdf`), packaged release archive, and `SHA256SUMS.txt`, and publish matching GitHub Releases + assets on **both** repositories (`urbanspress/gashboard.progress` and `urbanspress/gashboard.stable`).

### SemVer (MAJOR.MINOR.PATCH) & 6-Layer Ecosystem Compatibility Matrix Standard
1. **Strict `MAJOR.MINOR.PATCH` Semantic Versioning (`ADR-027c`):**
   - **`0.x.y` (`PRE-1.0`):** Pre-`1.0.0` Step 5 control-panel & fleet-deployer deliverables establishing UI, SSH tunnel, and `Site DNA` compatibility ahead of `v1.0.0` freeze.
   - **`1.0.x` (`PATCH`):** Strictly for non-breaking bug fixes, security hardening, documentation polish, and cross-layer audit patches (`100%` drop-in compatible).
   - **`1.x.0` (`MINOR`):** For backwards-compatible new features, additive panel cards, or marketplace workflow refinements.
   - **`2.0.0` (`MAJOR`):** Reserved for breaking architectural or contract changes—**never used without explicit project-owner approval (`ADR-027c`)**.
2. **Mandatory Release Compatibility Badge & 6-Layer Matrix Block:**
   - Every GitHub Release across both `.progress` and `.stable` repositories MUST display at the top of its release notes:
     1. A **Release Type & Affected Layers** summary callout (`PRE-1.0 (v0.x.y)` | `PATCH (v1.0.x)` | `MINOR (v1.x.0)`, which layer(s) changed, and whether any neighboring layer requires an upgrade).
     2. A **6-Layer Ecosystem Compatibility Matrix** Markdown table covering all six ecosystem layers:

````markdown
### Release Type & Affected Layers
- **Release Version & SemVer Tier:** `v<X.Y.Z>` (`PRE-1.0 v0.x.y` | `PATCH 1.0.x — Non-Breaking Bug/Security/Audit Patch` | `MINOR 1.x.0 — Backwards-Compatible Feature Release`)
- **Affected Layer(s):** `<Layer Name>` (`urbanspress/<repo>`)
- **Neighboring Layer Upgrade Required?** `No — 100% drop-in compatible` (or explicit version requirement if `Yes`)

| Ecosystem Layer | Repository | Required Version Range | Touched in This Release? | Neighbor Upgrade Required? |
|---|---|---|---|---|
| **Core Language, Bytecode VM & Grisp Server** | `urbanspress/grab` | `>= v1.1.0 (< v2.0.0)` | `Yes` / `No` | `No` |
| **Reactive Frontend Runtime & 20-Element Library** | `urbanspress/grex-js` | `>= v1.0.0 (< v2.0.0)` | `Yes` / `No` | `No` |
| **Flagship Zero-Plugin CMS** | `urbanspress/grablab-cms` | `>= v1.0.1 (< v2.0.0)` | `Yes` / `No` | `No` |
| **Exclusive `mode: "visual"` Theme & Studio** | `urbanspress/grex-builder` | `>= v1.0.0 (< v2.0.0)` | `Yes` / `No` | `No` |
| **Autonomous Design, Content & SEO Agent** | `urbanspress/groxy-ai` | `>= v1.0.0 (< v2.0.0)` | `Yes` / `No` | `No` |
| **Scaffolder, Orchestrator & Discreet VPS Panel** | `urbanspress/grabman`, `urbanspress/grabtaculous`, `urbanspress/gashboard` | `>= v0.1.0` | `Yes` / `No` | `No` |
````

### Mandatory Milestone Snapshot Rule
- **Ecosystem Snapshot Sync:** At the end of every milestone (before closing the milestone or pushing release promotions), every agent MUST run:
  ```powershell
  powershell -ExecutionPolicy Bypass -File C:\Development\GRAB\scripts\sync-notebook-sources.ps1
  ```
  so `C:\Development\ECOSYSTEM-SNAPSHOT.md` always reflects the latest Git branches, commits, tags, `AGENTS.md`, `*-EXPERT.md`, `HANDOFF.md`, `docs\ROADMAP.md`, and `specifications\*.md` across all discovered `C:\Development\*` repositories.

---

## 4. 4-Tier Model Routing & Tandem Handoff Protocol

### 4-Tier Antigravity Model Routing
Before ending a turn or starting a new phase, advise the project owner which Antigravity model and effort level to select for the next step so AI Pro quota is used efficiently:
1. **`Google Hydrogen (Medium)`:** Pre-implementation specifications (`*-SPEC-*.md`), documentation, governance updates, and single-module edits.
2. **`Google Hydrogen (High)`:** Standard feature milestone implementations (`v0.1.0` UI panels, SSH tunnel APIs, unit/DOM test suites).
3. **`Orchestrator (Argon)`:** Second-opinion pre-`v1.0.0` security/DOM/SSH/contract audits, multi-repo cross-layer integrations (`gashboard` + `grabtaculous` + `grabman` + `Groxy AI`), and complex refactors where Argon-level planning + automated delegation saves tokens.
4. **`Google Hydrogen (Extra)`:** Reserved for multi-server orchestration (`Gashboard + Grabtaculous + grabman`), encrypted SSH tunnel + fleet rollout flows, and stubborn cross-layer bugs.
- **Mandatory Pause & Swap Prompt Rule:** Every active AI agent MUST pause at milestone boundaries or before high-risk cross-layer/pre-`v1.0.0` audits and explicitly tell the user when to switch to `Orchestrator (Argon)`, including a clear 1-sentence reason why `Orchestrator (Argon)` is recommended next.

### Tier 1 vs. Tier 2 Strict Single-Module/Package Routing
- **Tier 1 — Frontier Models (`Google Hydrogen`, `Gemini 4 Argon`, `GPT-6.1 Sol`, `Claude Opus/Sonnet`):** Authorized to draft specifications, implement multi-layer GRAB + Grex JS + Go SSH bridge modules, and execute cross-layer verification suites.
- **Tier 2 — Fast Workhorse & Backup Models (`Gemini 3.8 Flash`, `OpenCode`, `Cline`, `Kilo Code`):** Must operate in **Strict Single-Module / Single-Package Mode** for all changes:
  1. **Read `GASHBOARD-EXPERT.md` first** before making any edit.
  2. **Scope edits to one `.grab` file, one JS UI module, or one Go package at a time**.
  3. **Verify immediately after every edit** (`grab check`, `grab format` stdout comparison, `go test -count=1 ./<package>`, or targeted Node UI tests) before moving to the next file.

### Tandem Handoff Protocol (`Google Antigravity <-> OpenAI Codex`)
- **Google Antigravity -> Codex:** If an issue remains unresolved after 2 attempts on `Google Hydrogen (Extra)` or `Orchestrator (Argon)`, stop editing, revert only the specific files edited during the failed attempt (asking the owner first if pre-existing uncommitted work would be affected), record what was tried in `HANDOFF.md`, update `Current Owner: OpenAI Codex`, and say: `"Ready to hand off to Codex. Type use-codex to continue."`
- **Codex -> Google Antigravity:** When Codex completes an architectural or verification task, update `HANDOFF.md`, set `Current Owner: Google Antigravity`, and say: `"Core task complete—ready to hand off to Google Antigravity. Type use-antigravity to continue."`
- **Automatic Pickup:** On pickup (`use-antigravity` or `use-codex`), immediately read `GASHBOARD-EXPERT.md`, `AGENTS.md`, and `HANDOFF.md`, verify baseline checks, and continue the next pending task.
