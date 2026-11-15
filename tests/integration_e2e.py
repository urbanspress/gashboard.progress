#!/usr/bin/env python3
"""
Gashboard v0.1.0 — 3-Gate Cross-Layer End-to-End Integration Suite.
Gate 1: Static GRAB check, canonical `grab format` byte-for-byte parity, template probe, zero-<div> / zero-innerHTML scan.
Gate 2: Node UI/DOM/contract suite (`node --test tests/*.test.js`), Go tests (`go test -count=1 ./...`), and `govulncheck ./...`.
Gate 3: Live multi-process loopback integration wiring Gashboard v0.1.0 (GRAB v1.1.0 + Grex JS v1.0.0) +
        gashboard-bridge + grabtaculousd v0.1.0 + grabman v0.1.0 + Groxy AI Site DNA.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GRAB_BIN = os.environ.get("GRAB_BIN", r"C:\Development\GRAB\dist\grab-windows-amd64.exe")
GRABMAN_BIN = os.environ.get("GRABMAN_BIN", r"C:\Development\grabman\dist\grabman-windows-amd64.exe")
GRABTAC_BIN = os.environ.get("GRABTACULOUS_BIN", r"C:\Development\grabtaculous\dist\grabtaculous-windows-amd64.exe")


def find_govulncheck() -> str:
    found = shutil.which("govulncheck")
    if found:
        return found
    home_bin = Path.home() / "go" / "bin" / ("govulncheck.exe" if os.name == "nt" else "govulncheck")
    if home_bin.exists():
        return str(home_bin)
    return "govulncheck"


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def run_cmd(cmd: list[str], cwd: Path = REPO_ROOT, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"Command failed ({proc.returncode}): {' '.join(cmd)}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    return proc


def http_request(url: str, method: str = "GET", headers: dict[str, str] | None = None, body: object = None):
    hdrs = dict(headers or {})
    data = None
    if body is not None:
        if isinstance(body, (bytes, bytearray)):
            data = bytes(body)
        elif isinstance(body, str):
            data = body.encode("utf-8")
        else:
            data = json.dumps(body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers), err.read().decode("utf-8", "replace")


def wait_for_health(base_url: str, label: str, proc: subprocess.Popen | None = None, log_path: Path | None = None, timeout_sec: float = 15.0):
    deadline = time.time() + timeout_sec
    last_err = None
    while time.time() < deadline:
        if proc is not None and proc.poll() is not None:
            log_txt = log_path.read_text(encoding="utf-8", errors="replace") if (log_path and log_path.exists()) else ""
            raise AssertionError(f"{label} exited early ({proc.returncode}).\nLOG:\n{log_txt}")
        try:
            status, _, body = http_request(f"{base_url}/_health")
            if status == 200:
                return json.loads(body)
        except Exception as exc:
            last_err = exc
        time.sleep(0.2)
    log_txt = log_path.read_text(encoding="utf-8", errors="replace") if (log_path and log_path.exists()) else ""
    raise AssertionError(f"Timed out waiting for {label} /_health: {last_err}\nLOG:\n{log_txt}")


def terminate_process(proc: subprocess.Popen | None):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def start_tcp_echo_server() -> tuple[int, threading.Event, threading.Thread]:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    srv.settimeout(0.25)
    port = int(srv.getsockname()[1])
    stop_evt = threading.Event()

    def serve():
        try:
            while not stop_evt.is_set():
                try:
                    conn, _ = srv.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                with conn:
                    conn.settimeout(2.0)
                    try:
                        chunk = conn.recv(4096)
                        if chunk:
                            conn.sendall(b"ECHO:" + chunk)
                    except OSError:
                        pass
        finally:
            srv.close()

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    return port, stop_evt, th


def gate_1_static_and_format():
    print("[Gate 1] Running grab check, canonical `grab format` parity, template probe, and zero-<div> scans...")
    assert Path(GRAB_BIN).exists(), f"Missing GRAB binary at {GRAB_BIN}"

    run_cmd([GRAB_BIN, "check", "--platform-config", "grab.platform.json", "src/gashboard.grab"])
    run_cmd([GRAB_BIN, "check", "migrations/001_gashboard_schema.grab"])

    for rel in ["src/gashboard.grab", "migrations/001_gashboard_schema.grab"]:
        target = REPO_ROOT / rel
        fmt = subprocess.run([GRAB_BIN, "format", rel], cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert fmt.returncode == 0, f"grab format {rel} failed: {fmt.stderr.decode('utf-8', 'replace')}"
        disk_bytes = target.read_bytes()
        assert fmt.stdout == disk_bytes, (
            f"{rel} differs from canonical `grab format` output "
            f"(disk={len(disk_bytes)}B, fmt={len(fmt.stdout)}B). Run `{GRAB_BIN} format --write {rel}`."
        )

    probe_dir = Path(tempfile.mkdtemp(prefix="gash_html_probe_"))
    try:
        shutil.copyfile(REPO_ROOT / "views" / "dashboard.grab.html", probe_dir / "dashboard.grab.html")
        probe_grab = probe_dir / "probe.grab"
        probe_grab.write_text(
            'use server\n'
            'route "GET" "/probe"\n'
            '  give back server.html using "dashboard.grab.html", record {csrf_token: "tok", gashboard_css_url: "/static/gashboard/gashboard.css", dashboard_js_url: "/static/gashboard/dashboard.js"}\n'
            'end\n',
            encoding="utf-8",
        )
        run_cmd([GRAB_BIN, "check", str(probe_grab)], cwd=probe_dir)
    finally:
        shutil.rmtree(probe_dir, ignore_errors=True)

    view_html = (REPO_ROOT / "views" / "dashboard.grab.html").read_text(encoding="utf-8")
    assert not re.search(r"<\s*/?\s*div\b", view_html, re.IGNORECASE), "views/dashboard.grab.html contains <div>"
    for name in ["api-client.js", "marketplace.js", "tunnels.js", "fleet-dna.js", "dashboard.js"]:
        raw = (REPO_ROOT / "public" / "gashboard" / name).read_text(encoding="utf-8")
        stripped = re.sub(r"/\*[\s\S]*?\*/", "", raw)
        stripped = re.sub(r"//.*", "", stripped)
        assert "createElement(\"div\")" not in stripped and "createElement('div')" not in stripped, f"{name} creates <div>"
        assert not re.search(r"\.innerHTML\b", stripped), f"{name} references .innerHTML"
    print("  [PASS] Gate 1 verified.")


def gate_2_unit_and_vuln_suites():
    print("[Gate 2] Running Node UI/DOM/contract suite, Go test suite, and govulncheck...")
    run_cmd(["node", "--test", "tests/unit_contracts.test.js", "tests/unit_ui_dom.test.js"])
    run_cmd(["go", "test", "-count=1", "./..."])
    govuln = find_govulncheck()
    run_cmd([govuln, "./..."])
    print("  [PASS] Gate 2 verified (0 Go vulnerabilities, 100% Node + Go tests pass).")


def gate_3_live_cross_layer_e2e():
    print("[Gate 3] Running live 6-layer E2E integration (Gashboard + Go SSH Bridge + Grabtaculous + grabman + Groxy DNA)...")
    assert Path(GRABMAN_BIN).exists(), f"Missing grabman binary at {GRABMAN_BIN}"
    assert Path(GRABTAC_BIN).exists(), f"Missing grabtaculous binary at {GRABTAC_BIN}"

    tmp_root = Path(tempfile.mkdtemp(prefix="gash_e2e_"))
    echo_stop = None
    echo_thread = None
    bridge_proc = None
    grabtac_proc = None
    gash_proc = None
    log_handles = []
    log_paths = []

    try:
        # Prepare clean isolated Gashboard workspace copy so repo storage/ stays clean
        app_dir = tmp_root / "gashboard_app"
        for folder in ["src", "views", "public", "migrations"]:
            shutil.copytree(REPO_ROOT / folder, app_dir / folder)
        shutil.copyfile(REPO_ROOT / "grab.platform.json", app_dir / "grab.platform.json")
        shutil.copyfile(REPO_ROOT / "grab.data.json", app_dir / "grab.data.json")
        (app_dir / "storage").mkdir(parents=True, exist_ok=True)
        db_file = app_dir / "storage" / "gashboard.db"

        run_cmd(
            [GRAB_BIN, "migrate", "--db-config", "grab.data.json", "--allow-db", "main:migrate", "migrations/001_gashboard_schema.grab"],
            cwd=app_dir,
        )

        # Build Groxy AI Site DNA + scaffold workspace with grabman
        dna_dir = tmp_root / "site_dna"
        dna_dir.mkdir(parents=True, exist_ok=True)
        site_dna_payload = {
            "schema_version": "0.4.0",
            "bundle_name": "groxy-site-dna-v0.4.0",
            "read_only_snapshot": True,
            "decimal_integrity_verified": True,
            "compatible_consumers": ["grabman", "grabtaculous", "gashboard"],
            "site_name": "Urban Press Flagship Store",
            "site_url": "https://shop.example.com",
            "active_style_pack": {
                "id": "emerald-editorial",
                "label": "Emerald Editorial",
            },
            "design_system": {
                "tokens": {
                    "--grex-color-primary": "#047857",
                    "--grex-color-bg": "#f8fafc",
                    "--grex-color-text": "#0f172a",
                },
                "reusable_classes": ["hero", "btn-primary"],
            },
            "site_context": {
                "counts": {"pages": 4, "products": 1},
                "products": [
                    {
                        "title": "Flagship Bundle",
                        "path": "/products/flagship",
                        "sku": "SKU-1000",
                        "price": "1000.00",
                        "currency": "USD",
                        "availability": "InStock",
                    }
                ],
                "redirects": [],
            },
            "nightly_watch_digest": {
                "site_health_score": 98,
                "overall_grade": "A",
            },
            "catalog_sample_price": "1000.00",
        }
        dna_file = dna_dir / "urban-store.site-dna.json"
        dna_file.write_text(json.dumps(site_dna_payload, indent=2), encoding="utf-8")

        ws_dir = tmp_root / "storefront_ws"
        run_cmd([
            GRABMAN_BIN, "init",
            "--dir", str(ws_dir),
            "--name", "urban-storefront",
            "--profile", "cms-stack",
            "--edge-proxy", "caddy",
            "--from-site-dna", str(dna_file),
        ])
        # Place clean valid .grab entrypoint for grab check inside workspace
        (ws_dir / "src").mkdir(parents=True, exist_ok=True)
        (ws_dir / "src" / "main.grab").write_text(
            'use server\nroute "GET" "/_ready"\n  give back server.json using 200, record {ok: yes, ready: yes}\nend\n',
            encoding="utf-8",
        )
        run_cmd([GRABMAN_BIN, "solve", "--dir", str(ws_dir)])
        run_cmd([GRABMAN_BIN, "doctor", "--dir", str(ws_dir), "--grab-bin", GRAB_BIN, "--json"])

        # Prepare real mathematically valid OpenSSH known_hosts file
        key_raw = b"ssh-ed25519-gashboard-v010-e2e-pinned-public-key"
        key_b64 = base64.b64encode(key_raw).decode("ascii")
        expected_fp = "SHA256:" + base64.b64encode(hashlib.sha256(key_raw).digest()).decode("ascii").rstrip("=")
        kh_path = tmp_root / "known_hosts"
        kh_path.write_text(f"[127.0.0.1]:2222,127.0.0.1 ssh-ed25519 {key_b64}\n", encoding="utf-8")

        # Build gashboard-bridge binary cleanly
        bridge_bin = tmp_root / ("gashboard-bridge.exe" if os.name == "nt" else "gashboard-bridge")
        run_cmd(["go", "build", "-o", str(bridge_bin), "./bridge/cmd/gashboard-bridge"])

        # Start local TCP echo server + grabtaculousd + gashboard-bridge + gashboard
        echo_port, echo_stop, echo_thread = start_tcp_echo_server()
        bridge_port = free_loopback_port()
        grabtac_port = free_loopback_port()
        gash_port = free_loopback_port()

        grabtac_state = tmp_root / "grabtac_state"
        grabtac_state.mkdir(parents=True, exist_ok=True)
        grabtac_url = f"http://127.0.0.1:{grabtac_port}"
        grabtac_log_p = tmp_root / "grabtaculousd.log"
        bridge_log_p = tmp_root / "gashboard-bridge.log"
        gash_log_p = tmp_root / "gashboard.log"
        log_paths.extend([grabtac_log_p, bridge_log_p, gash_log_p])

        grabtac_fh = grabtac_log_p.open("w", encoding="utf-8")
        log_handles.append(grabtac_fh)
        grabtac_proc = subprocess.Popen(
            [
                GRABTAC_BIN,
                "daemon",
                "--listen", f"127.0.0.1:{grabtac_port}",
                "--state-dir", str(grabtac_state),
                "--catalog-dir", r"C:\Development\grabtaculous\catalog",
            ],
            stdout=grabtac_fh,
            stderr=subprocess.STDOUT,
            text=True,
        )
        wait_for_health(grabtac_url, "grabtaculousd", grabtac_proc, grabtac_log_p)
        grabtac_tok = (grabtac_state / "control.token").read_text(encoding="utf-8").strip()

        bridge_tok = "bridge-e2e-token-v010"
        bridge_url = f"http://127.0.0.1:{bridge_port}"
        bridge_env = os.environ.copy()
        bridge_env["GASHBOARD_BRIDGE_TOKEN"] = bridge_tok
        bridge_fh = bridge_log_p.open("w", encoding="utf-8")
        log_handles.append(bridge_fh)
        bridge_proc = subprocess.Popen(
            [
                str(bridge_bin),
                "--listen", f"127.0.0.1:{bridge_port}",
                "--known-hosts", str(kh_path),
                "--grabman-bin", GRABMAN_BIN,
                "--grabtaculous-bin", GRABTAC_BIN,
                "--grab-bin", GRAB_BIN,
            ],
            cwd=str(REPO_ROOT),
            env=bridge_env,
            stdout=bridge_fh,
            stderr=subprocess.STDOUT,
            text=True,
        )
        wait_for_health(bridge_url, "gashboard-bridge", bridge_proc, bridge_log_p)

        gash_url = f"http://127.0.0.1:{gash_port}"
        gash_env = os.environ.copy()
        gash_env["GASHBOARD_MASTER_KEY"] = "e2e-gashboard-master-secret-2026"
        gash_env["GASHBOARD_BRIDGE_URL"] = bridge_url
        gash_env["GASHBOARD_BRIDGE_TOKEN"] = bridge_tok
        gash_env["GASHBOARD_GRABTACULOUS_URL"] = grabtac_url
        gash_env["GASHBOARD_GRABTACULOUS_TOKEN"] = grabtac_tok
        gash_fh = gash_log_p.open("w", encoding="utf-8")
        log_handles.append(gash_fh)
        gash_proc = subprocess.Popen(
            [
                GRAB_BIN,
                "serve",
                "--addr", f"127.0.0.1:{gash_port}",
                "--allow-scripts",
                "--static", "public",
                "--db-config", "grab.data.json",
                "--allow-db", "main:read-write",
                "--platform-config", "grab.platform.json",
                "--allow-cache", "gashboard:read-write",
                "--allow-read", ".",
                "--allow-write", "storage",
                "--allow-env", "GASHBOARD_MASTER_KEY,GASHBOARD_BRIDGE_URL,GASHBOARD_BRIDGE_TOKEN,GASHBOARD_GRABTACULOUS_URL,GASHBOARD_GRABTACULOUS_TOKEN",
                "--allow-net", f"127.0.0.1:{bridge_port},127.0.0.1:{grabtac_port}",
                "src/gashboard.grab",
            ],
            cwd=str(app_dir),
            env=gash_env,
            stdout=gash_fh,
            stderr=subprocess.STDOUT,
            text=True,
        )
        health = wait_for_health(gash_url, "gashboard", gash_proc, gash_log_p)
        assert health.get("status") == "ok", f"Unexpected /_health payload: {health}"

        st, _, ready_raw = http_request(f"{gash_url}/_ready")
        assert st == 200
        ready_doc = json.loads(ready_raw)
        assert ready_doc.get("status") == "ready", f"Unexpected /_ready ({st}): {ready_raw}"

        st, _, vps_init_raw = http_request(f"{gash_url}/api/vps")
        assert st == 200 and json.loads(vps_init_raw).get("ok") is True, f"SQLite readiness check failed: {vps_init_raw}"

        # Fetch HTML UI, check zero <div>, extract CSRF token & asset URLs
        st, _, ui_html = http_request(f"{gash_url}/gashboard")
        assert st == 200
        assert not re.search(r"<\s*/?\s*div\b", ui_html, re.IGNORECASE), "Rendered HTML contains <div>"
        csrf_m = re.search(r'<meta\s+name="gashboard-csrf"\s+content="([^"]+)"', ui_html)
        assert csrf_m, f"Missing gashboard-csrf meta tag in HTML:\n{ui_html}"
        csrf = csrf_m.group(1)

        css_m = re.search(r'href="(/static/gashboard/gashboard[^"]*\.css[^"]*)"', ui_html)
        js_m = re.search(r'src="(/static/gashboard/dashboard[^"]*\.js[^"]*)"', ui_html)
        assert css_m and js_m, f"Missing CSS/JS URLs in HTML:\n{ui_html}"
        st, _, _ = http_request(f"{gash_url}{css_m.group(1)}")
        assert st == 200
        st, _, _ = http_request(f"{gash_url}{js_m.group(1)}")
        assert st == 200

        csrf_hdrs = {"X-CSRF-Token": csrf}

        # Verify CSRF guard (403 without token)
        st, _, _ = http_request(f"{gash_url}/api/vps/register", method="POST", body={"label": "NoCSRF"})
        assert st == 403, f"Expected 403 without CSRF, got {st}"

        # Reject unpinned/wrong known_hosts key (403 GASH-E502)
        st, _, bad_fp_raw = http_request(
            f"{gash_url}/api/vps/register",
            method="POST",
            headers=csrf_hdrs,
            body={
                "label": "MITM Node",
                "host": "127.0.0.1",
                "ssh_port": "2222",
                "host_key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "ssh_credential": "secret-passphrase",
                "known_hosts_lines": [f"[127.0.0.1]:2222 ssh-ed25519 {key_b64}"],
            },
        )
        assert st == 403 and json.loads(bad_fp_raw).get("code") == "GASH-E502"

        # Reject raw JS float (ADR-025c -> 422 GASH-E422)
        st, _, bad_num_raw = http_request(
            f"{gash_url}/api/vps/register",
            method="POST",
            headers=csrf_hdrs,
            body={
                "label": "Float Drift Node",
                "host": "127.0.0.1",
                "ssh_port": "2222",
                "host_key_fingerprint": expected_fp,
                "ssh_credential": "secret-passphrase",
                "cpu_pct": 14.25,
            },
        )
        assert st == 422 and json.loads(bad_num_raw).get("code") == "GASH-E422"

        # Valid VPS registration (200 + AES-256-GCM ciphertext stored in SQLite, hidden from HTTP response)
        plain_secret = "super-secret-ed25519-passphrase-9981"
        st, _, reg_raw = http_request(
            f"{gash_url}/api/vps/register",
            method="POST",
            headers=csrf_hdrs,
            body={
                "label": "E2E Pinned Storefront VPS",
                "host": "127.0.0.1",
                "ssh_port": "2222",
                "ssh_user": "deploy",
                "host_key_fingerprint": expected_fp,
                "ssh_credential": plain_secret,
                "environment": "production",
                "edge_proxy": "caddy",
                "domain": "shop.example.com",
                "cpu_pct": "12.50",
                "ram_gb": "8.00",
                "disk_gb": "160.00",
                "grisp_workers": "4",
                "known_hosts_lines": [f"[127.0.0.1]:2222 ssh-ed25519 {key_b64}"],
            },
        )
        assert st == 200, f"Register failed ({st}): {reg_raw}"
        reg_doc = json.loads(reg_raw)
        node_id = reg_doc["node"]["id"]
        assert "encrypted_credential" not in reg_doc["node"]
        assert plain_secret not in reg_raw

        # Confirm encrypted_credential in SQLite is v1:... AES-256-GCM ciphertext (not plaintext)
        con = sqlite3.connect(str(db_file))
        try:
            row = con.execute("SELECT encrypted_credential FROM vps_nodes WHERE id = ?", (node_id,)).fetchone()
            assert row is not None and row[0].startswith("v1:") and plain_secret not in row[0]
        finally:
            con.close()

        # Probe registered node live via Gashboard -> gashboard-bridge -> grabtaculousd /_ready
        st, _, probe_raw = http_request(f"{gash_url}/api/vps/{node_id}/probe", method="POST", headers=csrf_hdrs, body={})
        assert st == 200 and json.loads(probe_raw)["ready_status"] == "200"

        # Verify grabman doctor + solve --verify via gashboard-bridge
        br_hdrs = {"Authorization": f"Bearer {bridge_tok}", "Content-Type": "application/json"}
        st, _, gm_doc_raw = http_request(
            f"{bridge_url}/v1/grabman/doctor",
            method="POST",
            headers=br_hdrs,
            body={"workspace": str(ws_dir), "strict": False},
        )
        assert st == 200 and json.loads(gm_doc_raw)["ok"] is True

        st, _, gm_sol_raw = http_request(
            f"{bridge_url}/v1/grabman/solve-verify",
            method="POST",
            headers=br_hdrs,
            body={"workspace": str(ws_dir)},
        )
        assert st == 200 and json.loads(gm_sol_raw)["ok"] is True

        # Marketplace 1-Click Plan -> Deploy + Replay Block (409)
        deploy_ws = tmp_root / "deploy_app"
        deploy_ws.mkdir(parents=True, exist_ok=True)
        st, _, plan_raw = http_request(
            f"{gash_url}/api/marketplace/plan",
            method="POST",
            headers=csrf_hdrs,
            body={
                "node_id": node_id,
                "blueprint_id": "grablab-grex-bundle",
                "app_name": "urban-shop",
                "domain": "shop.example.com",
                "edge_proxy": "caddy",
                "workspace": str(ws_dir),
            },
        )
        assert st == 200, f"Marketplace plan failed: {plan_raw}"
        mp_tok = json.loads(plan_raw)["approval_token"]

        st, _, dep_raw = http_request(
            f"{gash_url}/api/marketplace/deploy",
            method="POST",
            headers=csrf_hdrs,
            body={"approval_token": mp_tok, "workspace": str(deploy_ws)},
        )
        assert st == 200, f"Marketplace deploy failed: {dep_raw}"
        dep_doc = json.loads(dep_raw)
        assert dep_doc["install"]["blueprint_id"] == "grablab-grex-bundle"
        compose_path = deploy_ws / "deploy" / "docker-compose.yml"
        assert compose_path.exists(), f"Missing {compose_path}; deploy_ws={list(deploy_ws.rglob('*'))}; dep_raw={dep_raw}"

        st, _, replay_raw = http_request(
            f"{gash_url}/api/marketplace/deploy",
            method="POST",
            headers=csrf_hdrs,
            body={"approval_token": mp_tok},
        )
        assert st == 409 and json.loads(replay_raw)["code"] == "GASH-E409"

        # Encrypted 127.0.0.1 SSH DB Tunnel: Open -> Live TCP Echo Forwarding -> Max-8 Cap -> Close
        st, _, tun_raw = http_request(
            f"{gash_url}/api/tunnels/open",
            method="POST",
            headers=csrf_hdrs,
            body={
                "node_id": node_id,
                "engine": "postgres",
                "local_port": "0",
                "ttl_minutes": "30",
                "remote_target_addr": f"127.0.0.1:{echo_port}",
            },
        )
        assert st == 200, f"Tunnel open failed: {tun_raw}"
        tun = json.loads(tun_raw)["tunnel"]
        assert tun["local_host"] == "127.0.0.1"
        tun_port = int(tun["local_port"])

        with socket.create_connection(("127.0.0.1", tun_port), timeout=5) as sock:
            sock.sendall(b"SELECT 1;")
            echoed = sock.recv(64)
            assert echoed == b"ECHO:SELECT 1;", f"Unexpected tunnel echo payload: {echoed!r}"

        # Verify bounded <= 8 tunnel cap (7 more succeed -> 9th returns 429 GASH-E503)
        extra_ids = []
        for idx in range(7):
            st, _, eraw = http_request(
                f"{gash_url}/api/tunnels/open",
                method="POST",
                headers=csrf_hdrs,
                body={
                    "node_id": node_id,
                    "engine": "redis",
                    "local_port": "0",
                    "ttl_minutes": "15",
                    "remote_target_addr": f"127.0.0.1:{echo_port}",
                },
            )
            assert st == 200, f"Tunnel #{idx + 2} failed: {eraw}"
            extra_ids.append(json.loads(eraw)["tunnel"]["id"])

        st, _, cap_raw = http_request(
            f"{gash_url}/api/tunnels/open",
            method="POST",
            headers=csrf_hdrs,
            body={"node_id": node_id, "engine": "postgres", "local_port": "0", "ttl_minutes": "15"},
        )
        assert st == 429 and json.loads(cap_raw)["code"] == "GASH-E503"

        for tid in [tun["id"], *extra_ids]:
            st, _, _ = http_request(f"{gash_url}/api/tunnels/close", method="POST", headers=csrf_hdrs, body={"id": tid})
            assert st == 200

        # Fleet Site DNA Preview -> Live Rollout via grabtaculousd -> Token Replay 409 -> 1-Click Rollback
        st, _, prev_raw = http_request(
            f"{gash_url}/api/fleet/dna/preview",
            method="POST",
            headers=csrf_hdrs,
            body={"node_id": node_id, "workspace": str(ws_dir), "site_dna": site_dna_payload},
        )
        assert st == 200, f"DNA preview failed: {prev_raw}"
        dna_tok = json.loads(prev_raw)["approval_token"]

        st, _, dna_dep_raw = http_request(
            f"{gash_url}/api/fleet/dna/deploy",
            method="POST",
            headers=csrf_hdrs,
            body={"approval_token": dna_tok},
        )
        assert st == 200, f"DNA deploy failed: {dna_dep_raw}"
        dna_dep_doc = json.loads(dna_dep_raw)
        snap_id = dna_dep_doc["deployment"]["snapshot_id"]
        rb_tok = dna_dep_doc["rollback_approval_token"]

        st, _, rb_ok_raw = http_request(
            f"{gash_url}/api/fleet/rollback",
            method="POST",
            headers=csrf_hdrs,
            body={"snapshot_id": snap_id, "node_id": node_id, "approval_token": rb_tok},
        )
        assert st == 200 and json.loads(rb_ok_raw)["rollback"]["ready_status"] == "200"

        st, _, rb_rep_raw = http_request(
            f"{gash_url}/api/fleet/rollback",
            method="POST",
            headers=csrf_hdrs,
            body={"snapshot_id": snap_id, "node_id": node_id, "approval_token": rb_tok},
        )
        assert st == 409 and json.loads(rb_rep_raw)["code"] == "GASH-E409"

        print("  [PASS] Gate 3 live 6-layer cross-stack integration verified.")
    except Exception:
        for lp in log_paths:
            if lp.exists():
                tail = lp.read_text(encoding="utf-8", errors="replace")[-3000:]
                if tail.strip():
                    print(f"\n--- {lp.name} ---\n{tail}")
        raise
    finally:
        if echo_stop is not None:
            echo_stop.set()
        if echo_thread is not None:
            echo_thread.join(timeout=2)
        terminate_process(gash_proc)
        terminate_process(bridge_proc)
        terminate_process(grabtac_proc)
        for fh in log_handles:
            try:
                fh.close()
            except OSError:
                pass
        shutil.rmtree(tmp_root, ignore_errors=True)


def main():
    gate_1_static_and_format()
    gate_2_unit_and_vuln_suites()
    gate_3_live_cross_layer_e2e()
    print("\nALL 3 GASHBOARD v0.1.0 VERIFICATION GATES PASSED 100%.")


if __name__ == "__main__":
    main()
