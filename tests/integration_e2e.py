#!/usr/bin/env python3
"""
Gashboard v1.0.0 — 4-Gate Cross-Layer End-to-End Verification Suite.
Gate 1: Static GRAB check, canonical `grab format` byte-for-byte parity, template probe, zero-<div> / zero-innerHTML scan.
Gate 2: Node unit, zero-<div> DOM, Light/Dark WCAG AA >= 4.5:1 & contract suite (`node --test tests/*.test.js`).
Gate 3: Go loopback SSH & DB inspector bridge (`go build ./...`, `go test -count=1 ./...`, `govulncheck ./...`).
Gate 4: Live multi-process 6-layer integration (theme persistence, 127.0.0.1 tunneled DB + SQLite inspection,
        encrypted Namecheap vault, email-safe DNS diff/apply, UDP DNS propagation gate, Grabtaculous Auto-HTTPS
        Caddyfile + /_ready verification, 1-click DNS + Edge rollback, replay 409, and clean 7-repo git status).
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import re
import shutil
import socket
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
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


def start_fake_pg_v3_server() -> tuple[int, threading.Event, threading.Thread]:
    """Minimal loopback PostgreSQL v3 wire responder used exclusively to verify tunneled pgx transport."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.25)
    port = int(srv.getsockname()[1])
    stop_evt = threading.Event()

    def pg_msg(mtype: bytes, payload: bytes) -> bytes:
        return mtype + struct.pack(">I", 4 + len(payload)) + payload

    def recv_exact(sock: socket.socket, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise EOFError("closed")
            buf.extend(chunk)
        return bytes(buf)

    def row_desc() -> bytes:
        cols = [(b"id", 20, 8), (b"price", 1700, -1)]
        out = bytearray(struct.pack(">H", len(cols)))
        for name, oid, sz in cols:
            out.extend(name + b"\x00")
            out.extend(struct.pack(">IhIhih", 0, 0, oid, sz, -1, 0))
        return bytes(out)

    def data_row(bin_int: bool) -> bytes:
        out = bytearray(struct.pack(">H", 2))
        if bin_int:
            out.extend(struct.pack(">Iq", 8, 9007199254740993))
        else:
            v0 = b"9007199254740993"
            out.extend(struct.pack(">I", len(v0)) + v0)
        v1 = b"12345678901234567890.1234"
        out.extend(struct.pack(">I", len(v1)) + v1)
        return bytes(out)

    def handle_conn(conn: socket.socket):
        with conn:
            conn.settimeout(5.0)
            try:
                sz_raw = recv_exact(conn, 4)
                sz = struct.unpack(">I", sz_raw)[0]
                payload = recv_exact(conn, sz - 4)
                if len(payload) >= 4 and struct.unpack(">I", payload[:4])[0] == 80877103:
                    conn.sendall(b"N")
                    sz = struct.unpack(">I", recv_exact(conn, 4))[0]
                    recv_exact(conn, sz - 4)
                conn.sendall(pg_msg(b"R", b"\x00\x00\x00\x00") + pg_msg(b"S", b"server_version\x0018.1\x00") + pg_msg(b"Z", b"I"))

                in_tx = False
                last_q = ""
                bin_int = False
                while True:
                    hdr = recv_exact(conn, 5)
                    mtype = hdr[0:1]
                    mlen = struct.unpack(">I", hdr[1:5])[0] - 4
                    body = recv_exact(conn, mlen)
                    if mtype == b"X":
                        return
                    if mtype == b"Q":
                        up_q = body.rstrip(b"\x00").decode("utf-8", "replace").strip().upper()
                        if "BEGIN" in up_q:
                            in_tx = True
                            conn.sendall(pg_msg(b"C", b"BEGIN\x00"))
                        elif "ROLLBACK" in up_q:
                            in_tx = False
                            conn.sendall(pg_msg(b"C", b"ROLLBACK\x00"))
                        elif up_q.startswith("SELECT"):
                            conn.sendall(pg_msg(b"T", row_desc()) + pg_msg(b"D", data_row(False)) + pg_msg(b"C", b"SELECT 1\x00"))
                        else:
                            conn.sendall(pg_msg(b"C", b"OK\x00"))
                        conn.sendall(pg_msg(b"Z", b"T" if in_tx else b"I"))
                    elif mtype == b"P":
                        parts = body.split(b"\x00", 2)
                        if len(parts) >= 2:
                            last_q = parts[1].decode("utf-8", "replace")
                        conn.sendall(pg_msg(b"1", b""))
                    elif mtype == b"D":
                        if last_q.strip().upper().startswith("SELECT"):
                            conn.sendall(pg_msg(b"T", row_desc()))
                        else:
                            conn.sendall(pg_msg(b"n", b""))
                    elif mtype == b"B":
                        bin_int = len(body) >= 4 and struct.unpack(">H", body[-4:-2])[0] == 1
                        conn.sendall(pg_msg(b"2", b""))
                    elif mtype == b"E":
                        up = last_q.strip().upper()
                        if up.startswith("BEGIN"):
                            in_tx = True
                            conn.sendall(pg_msg(b"C", b"BEGIN\x00"))
                        elif up.startswith("ROLLBACK"):
                            in_tx = False
                            conn.sendall(pg_msg(b"C", b"ROLLBACK\x00"))
                        elif up.startswith("SELECT"):
                            conn.sendall(pg_msg(b"D", data_row(bin_int)) + pg_msg(b"C", b"SELECT 1\x00"))
                        else:
                            conn.sendall(pg_msg(b"C", b"OK\x00"))
                    elif mtype == b"S":
                        conn.sendall(pg_msg(b"Z", b"T" if in_tx else b"I"))
            except (EOFError, OSError, struct.error):
                return

    def serve():
        try:
            while not stop_evt.is_set():
                try:
                    c, _ = srv.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                threading.Thread(target=handle_conn, args=(c,), daemon=True).start()
        finally:
            srv.close()

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    return port, stop_evt, th


def start_mock_namecheap_server():
    """Start a local 127.0.0.1 HTTP mock for Namecheap XML getHosts/setHosts with email-record fixture state."""
    lock = threading.Lock()
    state = {
        "email_type": "CUSTOM",
        "set_calls": 0,
        "last_auth": {},
        "hosts": [
            {"host_id": "1", "name": "@", "type": "MX", "address": "mail.protonmail.ch.", "mx_pref": "10", "ttl": "1800"},
            {"host_id": "2", "name": "@", "type": "TXT", "address": "v=spf1 include:_spf.protonmail.ch ~all", "mx_pref": "10", "ttl": "1800"},
            {"host_id": "3", "name": "protonmail._domainkey", "type": "CNAME", "address": "dkim.protonmail.ch.", "mx_pref": "10", "ttl": "1800"},
            {"host_id": "4", "name": "_dmarc", "type": "TXT", "address": "v=DMARC1; p=quarantine", "mx_pref": "10", "ttl": "1800"},
            {"host_id": "5", "name": "@", "type": "A", "address": "198.51.100.10", "mx_pref": "10", "ttl": "300"},
            {"host_id": "6", "name": "www", "type": "CNAME", "address": "example.com.", "mx_pref": "10", "ttl": "300"},
        ],
    }

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(ln).decode("utf-8")
            form = urllib.parse.parse_qs(raw, keep_blank_values=True)
            cmd = form.get("Command", [""])[0]
            with lock:
                state["last_auth"] = {
                    "ApiUser": form.get("ApiUser", [""])[0],
                    "ApiKey": form.get("ApiKey", [""])[0],
                    "ClientIp": form.get("ClientIp", [""])[0],
                }
                if cmd == "namecheap.domains.dns.getHosts":
                    xml_rows = []
                    for h in state["hosts"]:
                        xml_rows.append(
                            f'<host HostId="{h["host_id"]}" Name="{h["name"]}" Type="{h["type"]}" '
                            f'Address="{h["address"]}" MXPref="{h["mx_pref"]}" TTL="{h["ttl"]}" />'
                        )
                    body = (
                        '<?xml version="1.0" encoding="utf-8"?>'
                        '<ApiResponse Status="OK"><Errors />'
                        '<CommandResponse Type="namecheap.domains.dns.getHosts">'
                        f'<DomainDNSGetHostsResult Domain="example.com" EmailType="{state["email_type"]}">'
                        + "".join(xml_rows)
                        + "</DomainDNSGetHostsResult></CommandResponse></ApiResponse>"
                    )
                elif cmd == "namecheap.domains.dns.setHosts":
                    state["set_calls"] += 1
                    next_hosts = []
                    idx = 1
                    while f"HostName{idx}" in form:
                        next_hosts.append({
                            "host_id": str(idx),
                            "name": form[f"HostName{idx}"][0],
                            "type": form[f"RecordType{idx}"][0],
                            "address": form[f"Address{idx}"][0],
                            "mx_pref": form.get(f"MXPref{idx}", ["10"])[0],
                            "ttl": form.get(f"TTL{idx}", ["300"])[0],
                        })
                        idx += 1
                    state["hosts"] = next_hosts
                    body = (
                        '<?xml version="1.0" encoding="utf-8"?>'
                        '<ApiResponse Status="OK"><Errors />'
                        '<CommandResponse Type="namecheap.domains.dns.setHosts">'
                        '<DomainDNSSetHostsResult Domain="example.com" IsSuccess="true" />'
                        "</CommandResponse></ApiResponse>"
                    )
                else:
                    self.send_response(400)
                    self.end_headers()
                    return
            payload = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return f"http://127.0.0.1:{port}", state, lock, srv


def start_mock_udp_dns_server(initial_ip: str = "198.51.100.10"):
    """Start a local 127.0.0.1 UDP DNS responder returning configurable IPv4 A records."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.2)
    port = sock.getsockname()[1]
    stop_evt = threading.Event()
    answer_ref = {"ip": initial_ip}
    lock = threading.Lock()

    def serve():
        try:
            while not stop_evt.is_set():
                try:
                    data, addr = sock.recvfrom(512)
                except TimeoutError:
                    continue
                except OSError:
                    break
                if len(data) < 12:
                    continue
                pos = 12
                while pos < len(data) and data[pos] != 0:
                    ln = data[pos]
                    if pos + 1 + ln >= len(data):
                        break
                    pos += 1 + ln
                if pos + 5 > len(data):
                    continue
                qtype = struct.unpack(">H", data[pos + 1 : pos + 3])[0]
                question = data[12 : pos + 5]
                hdr = bytearray(12)
                hdr[0:2] = data[0:2]
                struct.pack_into(">HHHHH", hdr, 2, 0x8180, 1, 1 if qtype == 1 else 0, 0, 0)
                resp = bytearray(hdr) + question
                if qtype == 1:
                    with lock:
                        ip_bytes = socket.inet_aton(answer_ref["ip"])
                    resp.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04")
                    resp.extend(ip_bytes)
                sock.sendto(bytes(resp), addr)
        finally:
            sock.close()

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    return f"127.0.0.1:{port}", answer_ref, lock, stop_evt, th


def gate_1_static_and_format():
    print("[Gate 1] Running grab check, canonical `grab format` parity, template probe, and zero-<div> scans...")
    assert Path(GRAB_BIN).exists(), f"Missing GRAB binary at {GRAB_BIN}"

    run_cmd([GRAB_BIN, "check", "--platform-config", "grab.platform.json", "src/gashboard.grab"])
    run_cmd([GRAB_BIN, "check", "migrations/001_gashboard_schema.grab"])
    run_cmd([GRAB_BIN, "check", "migrations/002_db_manager_and_theme.grab"])
    run_cmd([GRAB_BIN, "check", "migrations/003_dns_vault.grab"])

    for rel in ["src/gashboard.grab", "migrations/001_gashboard_schema.grab", "migrations/002_db_manager_and_theme.grab", "migrations/003_dns_vault.grab"]:
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
            '  give back server.html using "dashboard.grab.html", record {csrf_token: "tok", gashboard_css_url: "/static/gashboard/gashboard.css", dashboard_js_url: "/static/gashboard/dashboard.js", initial_theme: "light"}\n'
            'end\n',
            encoding="utf-8",
        )
        run_cmd([GRAB_BIN, "check", str(probe_grab)], cwd=probe_dir)
    finally:
        shutil.rmtree(probe_dir, ignore_errors=True)

    view_html = (REPO_ROOT / "views" / "dashboard.grab.html").read_text(encoding="utf-8")
    assert not re.search(r"<\s*/?\s*div\b", view_html, re.IGNORECASE), "views/dashboard.grab.html contains <div>"
    for name in ["api-client.js", "theme.js", "marketplace.js", "tunnels.js", "fleet-dna.js", "dns-https-wizard.js", "db-manager.js", "dashboard.js"]:
        raw = (REPO_ROOT / "public" / "gashboard" / name).read_text(encoding="utf-8")
        stripped = re.sub(r"/\*[\s\S]*?\*/", "", raw)
        stripped = re.sub(r"//.*", "", stripped)
        assert "createElement(\"div\")" not in stripped and "createElement('div')" not in stripped, f"{name} creates <div>"
        assert not re.search(r"\.innerHTML\b", stripped), f"{name} references .innerHTML"
    print("  [PASS] Gate 1 verified.")


def gate_2_unit_dom_wcag_and_contracts():
    print("[Gate 2] Running Node UI/DOM/WCAG AA/contract suite (`node --test tests/*.test.js`)...")
    run_cmd(["node", "--test", "tests/unit_contracts.test.js", "tests/unit_ui_dom.test.js"])
    print("  [PASS] Gate 2 verified.")


def gate_3_go_bridge_build_test_vuln():
    print("[Gate 3] Running Go build, unit/E2E tests, and govulncheck (0 vulnerabilities)...")
    run_cmd(["go", "build", "./..."])
    run_cmd(["go", "test", "-count=1", "./..."])
    govuln = find_govulncheck()
    run_cmd([govuln, "./..."])
    print("  [PASS] Gate 3 verified (0 vulnerabilities).")


def gate_4_live_6layer_e2e():
    print("[Gate 4] Running live 6-layer E2E integration (Gashboard v1.0.0 + Namecheap DNS + Auto-HTTPS + Bridge DB + Grabtaculous v1.0.0 + grabman v1.0.0 + Groxy DNA)...")
    assert Path(GRABMAN_BIN).exists(), f"Missing grabman binary at {GRABMAN_BIN}"
    assert Path(GRABTAC_BIN).exists(), f"Missing grabtaculous binary at {GRABTAC_BIN}"

    tmp_root = Path(tempfile.mkdtemp(prefix="gash_e2e_"))
    echo_stop = None
    echo_thread = None
    pg_stop = None
    pg_thread = None
    nc_srv = None
    dns_stop = None
    dns_thread = None
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

        # Verify v0.1.0 -> v0.2.0 -> v0.3.0 incremental SQLite migration
        run_cmd(
            [GRAB_BIN, "migrate", "--db-config", "grab.data.json", "--allow-db", "main:migrate", "migrations/001_gashboard_schema.grab"],
            cwd=app_dir,
        )
        run_cmd(
            [GRAB_BIN, "migrate", "--db-config", "grab.data.json", "--allow-db", "main:migrate", "migrations/002_db_manager_and_theme.grab"],
            cwd=app_dir,
        )
        run_cmd(
            [GRAB_BIN, "migrate", "--db-config", "grab.data.json", "--allow-db", "main:migrate", "migrations/003_dns_vault.grab"],
            cwd=app_dir,
        )

        # Seed confined demo SQLite DB inside workspace storage/ for Visual DB Manager E2E
        demo_db = app_dir / "storage" / "demo_store.db"
        dcon = sqlite3.connect(str(demo_db))
        try:
            dcon.executescript(
                """
                CREATE TABLE invoices (
                    id INTEGER PRIMARY KEY,
                    sku TEXT NOT NULL,
                    amount_exact TEXT NOT NULL,
                    qty INTEGER NOT NULL
                );
                CREATE INDEX idx_invoices_sku ON invoices(sku);
                INSERT INTO invoices (id, sku, amount_exact, qty) VALUES
                    (9007199254740993, 'SKU-ALPHA', '12345678901234567890.1234', 42),
                    (9007199254740995, 'SKU-BETA', '99.9500', 7);
                """
            )
            dcon.commit()
        finally:
            dcon.close()

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

        # Start local TCP echo server + fake PG v3 responder + Mock Namecheap XML + Mock UDP DNS + grabtaculousd + gashboard-bridge + gashboard
        echo_port, echo_stop, echo_thread = start_tcp_echo_server()
        pg_port, pg_stop, pg_thread = start_fake_pg_v3_server()
        nc_url, nc_state, nc_lock, nc_srv = start_mock_namecheap_server()
        udp_resolver, dns_ans_ref, dns_lock, dns_stop, dns_thread = start_mock_udp_dns_server("198.51.100.10")
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
                "--sqlite-root", str(app_dir / "storage"),
                "--namecheap-url", nc_url,
                "--dns-resolvers", udp_resolver,
            ],
            cwd=str(REPO_ROOT),
            env=bridge_env,
            stdout=bridge_fh,
            stderr=subprocess.STDOUT,
            text=True,
        )
        bridge_health = wait_for_health(bridge_url, "gashboard-bridge", bridge_proc, bridge_log_p)
        assert bridge_health.get("version") == "1.0.0", f"Unexpected bridge /_health payload: {bridge_health}"

        gash_url = f"http://127.0.0.1:{gash_port}"
        gash_env = os.environ.copy()
        gash_env["GASHBOARD_MASTER_KEY"] = "e2e-gashboard-master-secret-2026"
        gash_env["GASHBOARD_BRIDGE_URL"] = bridge_url
        gash_env["GASHBOARD_BRIDGE_TOKEN"] = bridge_tok
        gash_env["GASHBOARD_GRABTACULOUS_URL"] = grabtac_url
        gash_env["GASHBOARD_GRABTACULOUS_TOKEN"] = grabtac_tok
        gash_env["GASHBOARD_UPSTREAM_READY_URL"] = f"{grabtac_url}/_ready"
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
                "--allow-env", "GASHBOARD_MASTER_KEY,GASHBOARD_BRIDGE_URL,GASHBOARD_BRIDGE_TOKEN,GASHBOARD_GRABTACULOUS_URL,GASHBOARD_GRABTACULOUS_TOKEN,GASHBOARD_UPSTREAM_READY_URL,GASHBOARD_HTTPS_PROBE_URL",
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
        assert '<meta name="gashboard-version" content="1.0.0">' in ui_html, f"Expected v1.0.0 meta tag in HTML:\n{ui_html}"
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
        mp_rb_tok = dep_doc["rollback_approval_token"]
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

        # Mismatched approval_token target binding must fail closed with 403 GASH-E403 (GROXY-SAFE-001)
        st, _, rb_mismatch_raw = http_request(
            f"{gash_url}/api/fleet/rollback",
            method="POST",
            headers=csrf_hdrs,
            body={"snapshot_id": snap_id, "node_id": node_id, "approval_token": mp_rb_tok},
        )
        assert st == 403 and json.loads(rb_mismatch_raw)["code"] == "GASH-E403", f"Expected 403 GASH-E403 on mismatched rollback token, got {st} {rb_mismatch_raw}"

        # ----------------------------------------------------------------------
        # v0.2.0 E2E: Light/Dark Theme Switcher Persistence (Zero-FOUC SSR + SQLite)
        # ----------------------------------------------------------------------
        assert 'data-grex-theme="light"' in ui_html, "Expected initial SSR theme light"
        assert 'id="gashboard-theme-toggle"' in ui_html, "Missing theme toggle button in HTML"
        st, _, bad_theme_raw = http_request(
            f"{gash_url}/api/preferences/theme",
            method="POST",
            headers=csrf_hdrs,
            body={"theme": "neon"},
        )
        assert st == 422 and json.loads(bad_theme_raw)["code"] == "GASH-E422"

        st, _, set_dark_raw = http_request(
            f"{gash_url}/api/preferences/theme",
            method="POST",
            headers=csrf_hdrs,
            body={"theme": "dark"},
        )
        assert st == 200 and json.loads(set_dark_raw)["theme"] == "dark"

        st, _, dark_html = http_request(f"{gash_url}/gashboard")
        assert st == 200 and 'data-grex-theme="dark"' in dark_html, "Reloaded SSR HTML did not apply persisted dark theme (FOUC risk)"
        st, _, _ = http_request(f"{gash_url}/api/preferences/theme", method="POST", headers=csrf_hdrs, body={"theme": "light"})
        assert st == 200

        # ----------------------------------------------------------------------
        # v0.2.0 E2E: Visual DB Manager over 127.0.0.1 SSH Tunnel + Confined SQLite
        # ----------------------------------------------------------------------
        # 1. Open active 127.0.0.1 tunnel pointing to fake PG v3 responder and query via Gashboard -> Bridge -> Tunnel
        st, _, pg_tun_raw = http_request(
            f"{gash_url}/api/tunnels/open",
            method="POST",
            headers=csrf_hdrs,
            body={
                "node_id": node_id,
                "engine": "postgres",
                "local_port": "0",
                "ttl_minutes": "15",
                "remote_target_addr": f"127.0.0.1:{pg_port}",
            },
        )
        assert st == 200, f"Open PG tunnel failed: {pg_tun_raw}"
        pg_tun_id = json.loads(pg_tun_raw)["tunnel"]["id"]

        st, _, db_tgts_raw = http_request(f"{gash_url}/api/db/targets")
        assert st == 200
        db_targets = json.loads(db_tgts_raw)["targets"]
        assert any(t["target_id"] == "sqlite:gashboard.db" for t in db_targets)
        assert any(t.get("tunnel_id") == pg_tun_id for t in db_targets)

        st, _, pg_q_raw = http_request(
            f"{gash_url}/api/db/query",
            method="POST",
            headers=csrf_hdrs,
            body={
                "target": {"engine": "postgres", "tunnel_id": pg_tun_id, "db_user": "deploy", "db_name": "store"},
                "sql": "SELECT id, price FROM catalog",
            },
        )
        assert st == 200, f"Tunneled PG read-only query failed: {pg_q_raw}"
        pg_q_doc = json.loads(pg_q_raw)
        assert pg_q_doc["read_only"] is True
        assert pg_q_doc["rows"][0]["id"] == "9007199254740993"
        assert pg_q_doc["rows"][0]["price"] == "12345678901234567890.1234"

        st, _, _ = http_request(f"{gash_url}/api/tunnels/close", method="POST", headers=csrf_hdrs, body={"id": pg_tun_id})
        assert st == 200

        # 2. Enforce GRAB-E401 confinement, ADR-005 direct host rejection, limit <= 100 cap, and read-only write block
        st, _, trav_raw = http_request(f"{gash_url}/api/db/schema?engine=sqlite&sqlite_path=../../etc/passwd")
        assert st == 403 and json.loads(trav_raw)["code"] == "GRAB-E401"

        st, _, pub_raw = http_request(
            f"{gash_url}/api/db/query",
            method="POST",
            headers=csrf_hdrs,
            body={"target": {"engine": "postgres", "host": "198.51.100.24", "db_name": "prod"}, "sql": "SELECT 1"},
        )
        assert st == 422 and json.loads(pub_raw)["code"] == "GASH-E422"

        demo_target = {"target_id": "sqlite:demo_store.db", "engine": "sqlite", "sqlite_path": "demo_store.db"}
        st, _, cap101_raw = http_request(
            f"{gash_url}/api/db/rows",
            method="POST",
            headers=csrf_hdrs,
            body={"target": demo_target, "table": "invoices", "page": "1", "limit": "101"},
        )
        assert st == 422 and json.loads(cap101_raw)["code"] == "GASH-E422"

        st, _, ro_blk_raw = http_request(
            f"{gash_url}/api/db/query",
            method="POST",
            headers=csrf_hdrs,
            body={"target": demo_target, "sql": "DELETE FROM invoices WHERE sku = 'SKU-ALPHA'"},
        )
        assert st == 403 and json.loads(ro_blk_raw)["code"] == "GASH-E403"

        # 3. Confined SQLite schema inspection + paginated rows + exact ADR-025c base-10 wire strings
        st, _, sc_raw = http_request(f"{gash_url}/api/db/schema?engine=sqlite&sqlite_path=demo_store.db")
        assert st == 200, f"SQLite schema failed: {sc_raw}"
        sc_doc = json.loads(sc_raw)
        assert sc_doc["tables"][0]["name"] == "invoices" and sc_doc["tables"][0]["row_count"] == "2"

        st, _, rows_raw = http_request(
            f"{gash_url}/api/db/rows",
            method="POST",
            headers=csrf_hdrs,
            body={"target": demo_target, "table": "invoices", "page": "1", "limit": "25", "filter_col": "sku", "filter_op": "eq", "filter_val": "SKU-ALPHA"},
        )
        assert st == 200, f"Browse rows failed: {rows_raw}"
        rows_doc = json.loads(rows_raw)
        assert rows_doc["rows"][0]["id"] == "9007199254740993"
        assert rows_doc["rows"][0]["amount_exact"] == "12345678901234567890.1234"

        # 4. GROXY-SAFE-001 Mutation Gate: Plan -> Pre-Mutation Snapshot -> Execute -> 409 Replay -> 1-Click Snapshot Restore
        st, _, bad_exec_raw = http_request(
            f"{gash_url}/api/db/mutate/execute",
            method="POST",
            headers=csrf_hdrs,
            body={"approval_token": "bogus-unminted-token"},
        )
        assert st == 403 and json.loads(bad_exec_raw)["code"] == "GASH-E403"

        st, _, mplan_raw = http_request(
            f"{gash_url}/api/db/mutate/plan",
            method="POST",
            headers=csrf_hdrs,
            body={"target": demo_target, "sql": "UPDATE invoices SET amount_exact = '0.0001' WHERE sku = 'SKU-ALPHA'"},
        )
        assert st == 200, f"DB mutate plan failed: {mplan_raw}"
        mplan_doc = json.loads(mplan_raw)
        db_snap_id = mplan_doc["snapshot_id"]
        mut_tok = mplan_doc["approval_token"]
        assert mplan_doc["pre_row_count"] == "2"

        st, _, mexec_raw = http_request(
            f"{gash_url}/api/db/mutate/execute",
            method="POST",
            headers=csrf_hdrs,
            body={"approval_token": mut_tok},
        )
        assert st == 200, f"DB mutate execute failed: {mexec_raw}"
        mexec_doc = json.loads(mexec_raw)
        assert mexec_doc["execution"]["affected_rows"] == "1"
        rb_db_tok = mexec_doc["restore_approval_token"]

        st, _, mrep_raw = http_request(
            f"{gash_url}/api/db/mutate/execute",
            method="POST",
            headers=csrf_hdrs,
            body={"approval_token": mut_tok},
        )
        assert st == 409 and json.loads(mrep_raw)["code"] == "GASH-E409"

        st, _, changed_rows_raw = http_request(
            f"{gash_url}/api/db/rows",
            method="POST",
            headers=csrf_hdrs,
            body={"target": demo_target, "table": "invoices", "page": "1", "limit": "25", "sort_col": "id"},
        )
        assert st == 200 and json.loads(changed_rows_raw)["rows"][0]["amount_exact"] == "0.0001"

        # 1-Click Pre-Mutation Snapshot Rollback -> restores exact ADR-025c decimal + blocks replay with 409
        st, _, restore_raw = http_request(
            f"{gash_url}/api/db/snapshots/restore",
            method="POST",
            headers=csrf_hdrs,
            body={"snapshot_id": db_snap_id, "approval_token": rb_db_tok},
        )
        assert st == 200, f"DB snapshot restore failed: {restore_raw}"
        assert json.loads(restore_raw)["restore"]["restored_rows"] == "2"

        st, _, restore_rep_raw = http_request(
            f"{gash_url}/api/db/snapshots/restore",
            method="POST",
            headers=csrf_hdrs,
            body={"snapshot_id": db_snap_id, "approval_token": rb_db_tok},
        )
        assert st == 409 and json.loads(restore_rep_raw)["code"] == "GASH-E409"

        st, _, restored_rows_raw = http_request(
            f"{gash_url}/api/db/rows",
            method="POST",
            headers=csrf_hdrs,
            body={"target": demo_target, "table": "invoices", "page": "1", "limit": "25", "sort_col": "id"},
        )
        assert st == 200 and json.loads(restored_rows_raw)["rows"][0]["amount_exact"] == "12345678901234567890.1234"

        # 4.5 v0.3.0 Namecheap Encrypted Vault, Email-Safe DNS Diff/Apply, Propagation Gate, Auto-HTTPS & 1-Click Rollback
        nc_secret_key = "nc-e2e-secret-key-030-xyz"
        nc_secret_user = "ncops_e2e_user"
        nc_secret_ip = "203.0.113.42"
        st, _, nc_st_raw = http_request(f"{gash_url}/api/dns/namecheap/status")
        assert st == 200 and json.loads(nc_st_raw)["configured"] is False

        st, _, nc_save_raw = http_request(
            f"{gash_url}/api/dns/namecheap/save",
            method="POST",
            headers=csrf_hdrs,
            body={"api_user": nc_secret_user, "api_key": nc_secret_key, "client_ip": nc_secret_ip, "sandbox": True},
        )
        assert st == 200, f"Namecheap vault save failed ({st}): {nc_save_raw}"
        nc_save_doc = json.loads(nc_save_raw)
        assert nc_save_doc["configured"] is True
        assert nc_secret_key not in nc_save_raw and nc_secret_user not in nc_save_raw and nc_secret_ip not in nc_save_raw

        st, _, nc_st2_raw = http_request(f"{gash_url}/api/dns/namecheap/status")
        assert st == 200 and nc_secret_key not in nc_st2_raw and nc_secret_user not in nc_st2_raw

        con = sqlite3.connect(str(db_file))
        try:
            vrow = con.execute("SELECT api_user_enc, api_key_enc, client_ip_enc, api_user_masked, client_ip_masked FROM dns_provider_credentials WHERE provider = 'namecheap'").fetchone()
            assert vrow is not None
            assert vrow[0].startswith("v1:") and vrow[1].startswith("v1:") and vrow[2].startswith("v1:")
            assert nc_secret_user not in vrow[0] and nc_secret_key not in vrow[1] and nc_secret_ip not in vrow[2]
        finally:
            con.close()

        # DNS Plan preserves MX + SPF TXT + DMARC TXT + DKIM CNAME & updates @ A -> target VPS IP 203.0.113.88
        target_vps_ip = "203.0.113.88"
        st, _, bad_ttl_raw = http_request(
            f"{gash_url}/api/dns/plan",
            method="POST",
            headers=csrf_hdrs,
            body={"node_id": node_id, "domain": "example.com", "target_ip": target_vps_ip, "ttl": 300},
        )
        assert st == 422 and json.loads(bad_ttl_raw)["code"] == "GASH-E422"

        st, _, dns_plan_raw = http_request(
            f"{gash_url}/api/dns/plan",
            method="POST",
            headers=csrf_hdrs,
            body={"node_id": node_id, "domain": "example.com", "target_ip": target_vps_ip, "ttl": "300", "edge_proxy": "caddy", "configure_www": True},
        )
        assert st == 200, f"DNS plan failed ({st}): {dns_plan_raw}"
        dns_plan_doc = json.loads(dns_plan_raw)
        dns_tok = dns_plan_doc["approval_token"]
        assert dns_plan_doc["plan"]["preserved_email_count"] == "3"
        assert nc_state["set_calls"] == 0

        # Apply DNS with single-use token + verify email records intact in Mock Namecheap state + block token replay
        st, _, dns_apply_raw = http_request(
            f"{gash_url}/api/dns/apply",
            method="POST",
            headers=csrf_hdrs,
            body={"approval_token": dns_tok},
        )
        assert st == 200, f"DNS apply failed ({st}): {dns_apply_raw}"
        dns_apply_doc = json.loads(dns_apply_raw)
        dns_snap_id = dns_apply_doc["dns_snapshot_id"]
        dns_rb_tok = dns_apply_doc["rollback_approval_token"]
        with nc_lock:
            assert nc_state["set_calls"] == 1
            assert nc_state["last_auth"]["ApiUser"] == nc_secret_user
            assert nc_state["last_auth"]["ApiKey"] == nc_secret_key
            assert any(h["type"] == "MX" and h["address"] == "mail.protonmail.ch." for h in nc_state["hosts"])
            assert any(h["type"] == "TXT" and "v=spf1" in h["address"] for h in nc_state["hosts"])
            assert any(h["name"] == "protonmail._domainkey" and h["address"] == "dkim.protonmail.ch." for h in nc_state["hosts"])
            assert any(h["name"] == "@" and h["type"] == "A" and h["address"] == target_vps_ip for h in nc_state["hosts"])

        st, _, dns_rep_raw = http_request(
            f"{gash_url}/api/dns/apply",
            method="POST",
            headers=csrf_hdrs,
            body={"approval_token": dns_tok},
        )
        assert st == 409 and json.loads(dns_rep_raw)["code"] == "GASH-E409"

        # Before UDP DNS propagates to 203.0.113.88, /api/https/plan MUST fail 422 GASH-E422 to guard Let's Encrypt rate limits
        st, _, pre_prop_raw = http_request(
            f"{gash_url}/api/https/plan",
            method="POST",
            headers=csrf_hdrs,
            body={
                "node_id": node_id,
                "domain": "example.com",
                "expected_ip": target_vps_ip,
                "edge_proxy": "caddy",
                "workspace": str(ws_dir),
                "blueprint_id": "grab-grisp-app",
                "app_name": "urban-edge",
                "dns_snapshot_id": dns_snap_id,
                "workers": "2",
            },
        )
        assert st == 422 and json.loads(pre_prop_raw)["code"] == "GASH-E422", f"Expected 422 before propagation, got {st}: {pre_prop_raw}"

        # Flip Mock UDP DNS responder to cutover VPS IP 203.0.113.88 and verify live check + Auto-HTTPS deploy via Grabtaculous
        with dns_lock:
            dns_ans_ref["ip"] = target_vps_ip
        st, _, prop_chk_raw = http_request(
            f"{gash_url}/api/dns/propagation/check",
            method="POST",
            headers=csrf_hdrs,
            body={"node_id": node_id, "domain": "example.com", "expected_ip": target_vps_ip, "edge_proxy": "caddy"},
        )
        assert st == 200 and json.loads(prop_chk_raw)["propagation"]["propagated"] is True

        st, _, hplan_raw = http_request(
            f"{gash_url}/api/https/plan",
            method="POST",
            headers=csrf_hdrs,
            body={
                "node_id": node_id,
                "domain": "example.com",
                "expected_ip": target_vps_ip,
                "edge_proxy": "caddy",
                "workspace": str(ws_dir),
                "blueprint_id": "grab-grisp-app",
                "app_name": "urban-edge",
                "dns_snapshot_id": dns_snap_id,
                "workers": "2",
            },
        )
        assert st == 200, f"HTTPS plan failed after propagation ({st}): {hplan_raw}"
        h_tok = json.loads(hplan_raw)["approval_token"]

        st, _, happly_raw = http_request(
            f"{gash_url}/api/https/apply",
            method="POST",
            headers=csrf_hdrs,
            body={"approval_token": h_tok},
        )
        assert st == 200, f"HTTPS apply failed ({st}): {happly_raw}"
        happly_doc = json.loads(happly_raw)
        rollout_id = happly_doc["rollout"]["id"]
        https_rb_tok = happly_doc["rollback_approval_token"]
        assert happly_doc["rollout"]["ready_status"] == "200"
        deploy_info = happly_doc["deploy"]["deploy"]
        worker_ports = deploy_info.get("worker_ports", [])
        assert len(worker_ports) >= 1 and all(8765 <= p <= 8772 for p in worker_ports), f"Unexpected worker_ports: {worker_ports}"
        caddy_file = ws_dir / "deploy" / "Caddyfile"
        assert caddy_file.exists(), f"Expected Grabtaculous to write {caddy_file}"
        caddy_txt = caddy_file.read_text(encoding="utf-8")
        assert "example.com" in caddy_txt and f"127.0.0.1:{worker_ports[0]}" in caddy_txt and "health_uri /_ready" in caddy_txt, caddy_txt

        # 1-Click Rollback restores Grabtaculous edge snapshot + Namecheap pre-cutover DNS records + rejects 409 replay
        st, _, hrb_raw = http_request(
            f"{gash_url}/api/https/rollback",
            method="POST",
            headers=csrf_hdrs,
            body={"rollout_id": rollout_id, "approval_token": https_rb_tok, "rollback_dns": True, "dns_approval_token": dns_rb_tok},
        )
        assert st == 200, f"HTTPS+DNS 1-click rollback failed ({st}): {hrb_raw}"
        hrb_doc = json.loads(hrb_raw)
        assert hrb_doc["rollback"]["status"] == "rolled_back"
        with nc_lock:
            assert nc_state["set_calls"] == 2
            assert any(h["name"] == "@" and h["type"] == "A" and h["address"] == "198.51.100.10" for h in nc_state["hosts"])
            assert any(h["type"] == "MX" and h["address"] == "mail.protonmail.ch." for h in nc_state["hosts"])

        st, _, hrb_rep_raw = http_request(
            f"{gash_url}/api/https/rollback",
            method="POST",
            headers=csrf_hdrs,
            body={"rollout_id": rollout_id, "approval_token": https_rb_tok},
        )
        assert st == 409 and json.loads(hrb_rep_raw)["code"] == "GASH-E409"

        # 5. Verify all 7 upstream/peer repositories remain strictly untouched
        upstream_repos = [
            Path(r"C:\Development\GRAB"),
            Path(r"C:\Development\grex-js"),
            Path(r"C:\Development\grablab-cms"),
            Path(r"C:\Development\grex-builder"),
            Path(r"C:\Development\groxy-ai"),
            Path(r"C:\Development\grabman"),
            Path(r"C:\Development\grabtaculous"),
        ]
        for repo in upstream_repos:
            if repo.exists():
                gs = run_cmd(["git", "status", "--short"], cwd=repo)
                assert gs.stdout.strip() == "", f"Upstream/peer repo {repo} is dirty:\n{gs.stdout}"

        print("  [PASS] Gate 4 live 6-layer cross-stack integration + v1.0.0 Namecheap DNS & Auto-HTTPS Wizard verified (all 7 peer repos clean).")
    except Exception:
        for lp in log_paths:
            if lp.exists():
                tail = lp.read_text(encoding="utf-8", errors="replace")[-3000:]
                if tail.strip():
                    print(f"\n--- {lp.name} ---\n{tail}")
        raise
    finally:
        if nc_srv is not None:
            nc_srv.shutdown()
            nc_srv.server_close()
        if dns_stop is not None:
            dns_stop.set()
        if dns_thread is not None:
            dns_thread.join(timeout=2)
        if echo_stop is not None:
            echo_stop.set()
        if echo_thread is not None:
            echo_thread.join(timeout=2)
        if pg_stop is not None:
            pg_stop.set()
        if pg_thread is not None:
            pg_thread.join(timeout=2)
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
    gate_2_unit_dom_wcag_and_contracts()
    gate_3_go_bridge_build_test_vuln()
    gate_4_live_6layer_e2e()
    print("\nALL 4 GASHBOARD v1.0.0 VERIFICATION GATES PASSED 100%.")


if __name__ == "__main__":
    main()
