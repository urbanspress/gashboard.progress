#!/usr/bin/env python3
"""
Gashboard v0.1.0 — Plain-English Release Guide HTML & PDF Generator.
Renders `docs/releases/html/Gashboard-v<VERSION>-Guide.html` and prints it to
`docs/releases/pdf/Gashboard-v<VERSION>-Guide.pdf` using headless Chrome or Edge.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
HTML_DIR = REPO_ROOT / "docs" / "releases" / "html"
PDF_DIR = REPO_ROOT / "docs" / "releases" / "pdf"

BROWSER_CANDIDATES = [
    os.environ.get("GASHBOARD_PDF_BROWSER", ""),
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "msedge",
    "google-chrome",
    "chromium",
]


def find_browser() -> str:
    for cand in BROWSER_CANDIDATES:
        if not cand:
            continue
        p = Path(cand)
        if p.exists():
            return str(p)
        resolved = shutil.which(cand)
        if resolved:
            return resolved
    raise FileNotFoundError("No headless Chrome or Microsoft Edge browser found to render PDF guide.")


def build_html(version: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Gashboard v{version} Plain-English Walkthrough Guide</title>
  <style>
    @page {{ size: letter; margin: 0.7in 0.7in 0.75in 0.7in; }}
    body {{ font-family: "Segoe UI", -apple-system, Roboto, sans-serif; color: #0f172a; line-height: 1.55; font-size: 10.5pt; margin: 0; }}
    header {{ border-bottom: 3px solid #047857; padding-bottom: 12px; margin-bottom: 18px; }}
    h1 {{ font-size: 20pt; margin: 0 0 6px 0; color: #064e3b; }}
    h2 {{ font-size: 13.5pt; margin: 20px 0 8px 0; color: #047857; border-bottom: 1px solid #cbd5e1; padding-bottom: 4px; page-break-after: avoid; }}
    h3 {{ font-size: 11pt; margin: 12px 0 4px 0; color: #0f172a; page-break-after: avoid; }}
    p, li {{ color: #1e293b; margin: 0 0 8px 0; }}
    ul, ol {{ padding-left: 20px; margin: 6px 0 12px 0; }}
    code, pre {{ font-family: "Consolas", "Courier New", monospace; background: #f1f5f9; border: 1px solid #cbd5e1; border-radius: 5px; font-size: 9pt; }}
    code {{ padding: 1px 5px; }}
    pre {{ padding: 10px 12px; white-space: pre-wrap; page-break-inside: avoid; }}
    table {{ width: 100%; border-collapse: collapse; margin: 10px 0 16px 0; font-size: 9.2pt; page-break-inside: avoid; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 6px 8px; text-align: left; vertical-align: top; }}
    th {{ background: #ecfdf5; color: #064e3b; font-weight: 700; }}
    .callout {{ background: #ecfdf5; border-left: 4px solid #047857; padding: 10px 12px; margin: 12px 0; border-radius: 4px; page-break-inside: avoid; }}
    .meta {{ color: #475569; font-size: 9.5pt; }}
  </style>
</head>
<body>
  <header>
    <h1>Gashboard v{version} — Plain-English Operator Guide</h1>
    <p class="meta">Discreet Pure Grex JS v1.0.0 Multi-VPS Control Panel, Encrypted 127.0.0.1 SSH Database Tunnels &amp; Site DNA Fleet Deployer</p>
  </header>

  <section class="callout">
    <strong>Why Gashboard Is Different (Plain-English Summary):</strong><br>
    Traditional hosting panels leave an admin login page open on the public internet (like port 8080 or 8443) for bots to attack.
    <strong>Gashboard does the opposite:</strong> the dashboard lives safely on <em>your own computer</em> (<code>127.0.0.1</code> only) and connects to your servers exclusively over encrypted SSH keys pinned in your <code>known_hosts</code> file. No public control-panel ports, no exposed database ports, and 1-click rollbacks before every deployment.
  </section>

  <h2>1. What Is Included in Gashboard v{version}</h2>
  <ul>
    <li><strong>Stealth 127.0.0.1 Control Panel (GRAB v1.1.0 + Pure Grex JS v1.0.0):</strong> Refuses public <code>0.0.0.0</code> bindings by default. Contains zero wrapper <code>&lt;div&gt;</code> tags, zero <code>innerHTML</code> writes, 100% WCAG AA accessible contrast, and exact base-10 decimals (<code>ADR-025c</code>).</li>
    <li><strong>AES-256-GCM Local Credential Vault:</strong> Any SSH passphrases or agent references you register are encrypted immediately using GRAB <code>use crypto</code> AES-256-GCM before touching local SQLite storage, and never sent back in API responses.</li>
    <li><strong>Pure Go Loopback SSH &amp; Tunnel Sidecar (<code>gashboard-bridge</code>):</strong> Enforces OpenSSH <code>known_hosts</code> host-key fingerprint pinning (zero <code>InsecureIgnoreHostKey</code>), opens up to 8 concurrent <code>127.0.0.1:&lt;port&gt;</code> private tunnels to PostgreSQL, MariaDB, or Redis, and proxies remote <code>grabtaculousd</code> nodes safely.</li>
    <li><strong>1-Click Hardened App Marketplace:</strong> Deploys GrabLab CMS + Grex Theme Builder + Groxy AI or private databases in read-only hardened containers with automatic Caddy, Nginx, or Cloudflare Tunnel SSL—after generating a safety plan and single-use approval confirmation.</li>
    <li><strong>Portable Site DNA Fleet Deployer &amp; Instant Rollbacks:</strong> Validates Groxy AI <code>Site DNA</code> bundles against <code>grabman.lock</code>, triggers zero-downtime <code>grabtaculous</code> rollouts, and lets you revert any server in one click via automatic Pre-Deploy Snapshots.</li>
  </ul>

  <h2>2. Quickstart: Starting Gashboard Locally</h2>
  <ol>
    <li><strong>Start the Local Go SSH Bridge (Terminal 1):</strong>
      <pre>set GASHBOARD_BRIDGE_TOKEN=replace-with-random-secret
gashboard-ssh-windows-amd64.exe --listen 127.0.0.1:9391 --known-hosts %USERPROFILE%\\.ssh\\known_hosts</pre>
    </li>
    <li><strong>Initialize Local SQLite Vault &amp; Start Gashboard (Terminal 2):</strong>
      <pre>grab migrate --db-config grab.data.json --allow-db main:migrate migrations\\001_gashboard_schema.grab
set GASHBOARD_MASTER_KEY=replace-with-strong-passphrase
set GASHBOARD_BRIDGE_URL=http://127.0.0.1:9391
grab serve --addr 127.0.0.1:9390 --allow-scripts --static public ^
  --db-config grab.data.json --allow-db main:read-write ^
  --platform-config grab.platform.json --allow-cache gashboard:read-write ^
  --allow-read . --allow-write storage ^
  --allow-env GASHBOARD_MASTER_KEY,GASHBOARD_BRIDGE_URL,GASHBOARD_BRIDGE_TOKEN ^
  --allow-net 127.0.0.1,localhost src\\gashboard.grab</pre>
    </li>
    <li><strong>Open Your Private Browser Control Panel:</strong> Navigate to <code>http://127.0.0.1:9390/gashboard</code>.</li>
  </ol>

  <h2>3. Daily Operator Workflows</h2>
  <h3>Adding a VPS Server Safely</h3>
  <p>Enter your server label, SSH host/IP, port, and OpenSSH <code>SHA256:...</code> fingerprint from <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>. Gashboard pins the fingerprint and rejects any impostor server with code <code>GASH-E502</code>.</p>

  <h3>Opening a Private Database Tunnel</h3>
  <p>Select PostgreSQL, MariaDB, or Redis and click <strong>Open Secure DB Tunnel</strong>. Gashboard binds strictly to <code>127.0.0.1:&lt;local_port&gt;</code> (capped at 8 active tunnels) and displays a password-free connection command such as <code>psql -h 127.0.0.1 -p 15432 -U &lt;db_user&gt; &lt;database&gt;</code>.</p>

  <h3>Deploying &amp; Rolling Back Site DNA</h3>
  <p>Paste a portable Groxy AI <code>Site DNA</code> JSON bundle, click <strong>Validate Site DNA &amp; Lockfile Diff</strong>, inspect the preview card, and click <strong>Approve &amp; Push Zero-Downtime Rollout</strong>. A single-use <code>approval_token</code> is consumed, a Pre-Deploy Snapshot is saved automatically, and <strong>1-Click Rollback</strong> restores the previous known-good state with <code>/_ready</code> HTTP <code>200</code> verification.</p>

  <h2>4. 6-Layer Ecosystem Compatibility Matrix (SemVer PRE-1.0)</h2>
  <table>
    <thead>
      <tr><th>Ecosystem Layer</th><th>Repository</th><th>Compatible Range</th><th>Touched in v{version}</th><th>Upgrade Required?</th></tr>
    </thead>
    <tbody>
      <tr><td>Core Language, VM &amp; Grisp</td><td><code>urbanspress/grab</code></td><td><code>&gt;= v1.1.0 (&lt; v2.0.0)</code></td><td>No</td><td>No</td></tr>
      <tr><td>Reactive UI &amp; 20-Element Spec</td><td><code>urbanspress/grex-js</code></td><td><code>&gt;= v1.0.0 (&lt; v2.0.0)</code></td><td>No</td><td>No</td></tr>
      <tr><td>Flagship Zero-Plugin CMS</td><td><code>urbanspress/grablab-cms</code></td><td><code>&gt;= v1.0.1 (&lt; v2.0.0)</code></td><td>No</td><td>No</td></tr>
      <tr><td>Visual Theme Builder Studio</td><td><code>urbanspress/grex-builder</code></td><td><code>&gt;= v1.0.0 (&lt; v2.0.0)</code></td><td>No</td><td>No</td></tr>
      <tr><td>Autonomous Content &amp; SEO Agent</td><td><code>urbanspress/groxy-ai</code></td><td><code>&gt;= v1.0.0 (&lt; v2.0.0)</code></td><td>No</td><td>No</td></tr>
      <tr><td>Scaffolder, Orchestrator &amp; Panel</td><td><code>grabman</code>, <code>grabtaculous</code>, <code>gashboard</code></td><td><code>&gt;= v0.1.0</code></td><td><strong>Yes (gashboard v{version})</strong></td><td>No (additive Step 5 release)</td></tr>
    </tbody>
  </table>

  <h2>5. Verification &amp; Security Guarantees</h2>
  <ul>
    <li><strong>Zero-Wrapper-<code>&lt;div&gt;</code> UI &amp; WCAG AA:</strong> Checked across HTML templates, all modular JS panels, and mounted Grex JS DOM audits.</li>
    <li><strong>CSRF &amp; Single-Use Approval Replay Defense:</strong> All mutating POST routes enforce <code>X-CSRF-Token</code> (<code>403</code>) and consume deployment/rollback <code>approval_token</code> secrets once (<code>409</code> on replay).</li>
    <li><strong>Zero Go Vulnerabilities:</strong> Audited with <code>govulncheck ./...</code> on Go 1.27.4 before packaging static binaries.</li>
  </ul>
</body>
</html>
"""


def render_pdf(browser_bin: str, html_path: Path, pdf_path: Path):
    PDF_DIR.mkdir(parents=True, exist_ok=True)
    user_data = Path(tempfile.mkdtemp(prefix="gash_pdf_chrome_"))
    try:
        cmd = [
            browser_bin,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--no-first-run",
            f"--user-data-dir={user_data}",
            "--no-pdf-header-footer",
            f"--print-to-pdf={pdf_path}",
            html_path.resolve().as_uri(),
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=45)
        deadline = time.time() + 10
        while time.time() < deadline and (not pdf_path.exists() or pdf_path.stat().st_size < 1000):
            time.sleep(0.2)
        if proc.returncode != 0 and (not pdf_path.exists() or pdf_path.stat().st_size < 1000):
            raise RuntimeError(f"PDF render failed ({proc.returncode}): {proc.stderr}")
        header = pdf_path.read_bytes()[:5]
        if header != b"%PDF-":
            raise RuntimeError(f"Invalid PDF header {header!r} in {pdf_path}")
    finally:
        shutil.rmtree(user_data, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Generate Gashboard HTML & PDF walkthrough release guide.")
    parser.add_argument("--version", default="0.1.0", help="Release version without leading v (e.g. 0.1.0)")
    args = parser.parse_args()
    version = args.version.lstrip("v")

    HTML_DIR.mkdir(parents=True, exist_ok=True)
    PDF_DIR.mkdir(parents=True, exist_ok=True)
    html_path = HTML_DIR / f"Gashboard-v{version}-Guide.html"
    pdf_path = PDF_DIR / f"Gashboard-v{version}-Guide.pdf"

    html_path.write_text(build_html(version), encoding="utf-8")
    browser = find_browser()
    render_pdf(browser, html_path, pdf_path)
    print(f"Generated {html_path} ({html_path.stat().st_size} bytes)")
    print(f"Generated {pdf_path} ({pdf_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
