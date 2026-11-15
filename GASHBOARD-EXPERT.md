# GASHBOARD-EXPERT.md — Non-Negotiable Engineering Invariants

This checklist defines the **never-break invariants** for **Gashboard** (`urbanspress/gashboard`), the Discreet Pure **`Grex JS v1.0.0`** Multi-VPS Control Panel, 1-Click App Marketplace UI, Encrypted SSH Database Tunneling Manager, and `Site DNA` Fleet Deployer in **Step 5 of the Post-1.0 GRAB Ecosystem**. Every specification, view, SSH bridge route, and PR must satisfy all four pillars.

---

## 1. Zero Public Attack Surface & Strictly Verified SSH Transport (`ADR-005`, `ADR-017`)
- **Off-Server Loopback Execution Only:** Gashboard MUST bind strictly to `127.0.0.1` on the user's workstation—eliminating public VPS admin-panel login portals entirely. Never expose Gashboard or its Go SSH bridge sidecar on `0.0.0.0` by default.
- **No Shell-String Interpolation & Strict `known_hosts` Pinning:** All SSH sessions and `127.0.0.1` database tunnels MUST use structured argument vectors / native `golang.org/x/crypto/ssh` with explicit host-key fingerprint verification (`known_hosts`)—never `/bin/sh -c` string concatenation or `InsecureIgnoreHostKey`.
- **Loopback-Only Database Tunnels:** Remote PostgreSQL, MariaDB, and Redis tunnels MUST bind strictly to `127.0.0.1:<local_port>` with bounded concurrency (`<= 8` concurrent tunnels), explicit idle/session timeouts, and zero plaintext secret exposure in browser DOM, logs, or URL query strings.
- **Encrypted Credential Storage (`use crypto`):** Any stored SSH key metadata or local vault secrets MUST use GRAB `v1.1.0` `crypto.encrypt_aead` (AES-256-GCM) with keys sourced solely from host environment variables (`use env`)—never committed to Git.

---

## 2. Pure `Grex JS v1.0.0` & Zero Wrapper-`<div>` Semantic DOM Compliance
- **Zero Build Bloat:** Gashboard UI runs directly on **GRAB `v1.1.0`** (`grab serve --allow-scripts`, `server.asset`) and **`Grex JS v1.0.0`** signals—zero Node bundlers, React, Vue, Vite, or Electron runtime overhead.
- **Zero Wrapper `<div>` Guarantee (`GREX-SCHEMA-001`):** Every `.grab.html` template and dynamically mounted panel MUST satisfy `divCount === 0` (`<section>`, `<header>`, `<nav>`, `<main>`, `<article>`, `<aside>`, `<footer>`, `<table>`, `<form>`, `<dialog>`, `<details>`) with `innerHTMLWriteCount === 0`, zero `eval()`/`new Function()`, and zero unsafe URLs (`javascript:`, `vbscript:`, `file:`, `data:`).
- **100% WCAG AA Accessibility (`auditAccessibility()`):** Contrast ratios `>= 4.5:1` (`>= 3.0:1` large text), accessible labels on all inputs/selects/buttons, sequential heading hierarchy (`<h1>`–`<h6>`), and visible `:focus-visible` keyboard focus rings.
- **Exact Numeric Integrity (`ADR-025c`):** Preserve base-10 `GrabDecimal` / `GrabInteger` wire strings across `Site DNA`, server resource metrics, port allocations, and lockfile version comparisons without float drift.

---

## 3. Human-in-the-Loop Safety & Pre-Deploy Snapshot Discipline
- **CSRF + Single-Use Approval Token Gate:** Every mutating `POST` action (deploying marketplace stacks, opening/closing SSH tunnels, running `Site DNA` fleet rollouts, triggering **Grabtaculous** snapshot rollbacks) MUST enforce `X-CSRF-Token`, and fleet/destructive operations MUST require an explicit single-use `approval_token` previewed in plain English.
- **Mandatory Lockfile + Snapshot Gate:** Gashboard MUST never trigger a **Grabtaculous** rollout without first validating `grabman.lock` (`grabman solve --verify`) and displaying the active Pre-Deploy Snapshot status so 1-click rollback is always one click away.

---

## 4. Dual-Repo SemVer & Committed Badge Discipline
- **Committed Emerald `#10B981` Vector Badges:** Keep `docs/badges/built-with-grab.svg`, `docs/badges/powered-by-grex-js.svg`, `docs/badges/ecosystem-step-5.svg`, and `docs/badges/spec-in-review.svg` (or release badge) committed and displayed in `README.md`.
- **Strict `stable` Protection & 6-Layer Matrix:** Never push unverified builds to `urbanspress/gashboard.stable`. Every release across both repos MUST include the **Release Type & Affected Layers** summary, **6-Layer Ecosystem Compatibility Matrix**, and plain-English walkthrough PDF (`docs/releases/pdf/Gashboard-v<X.Y.Z>-Guide.pdf`).
