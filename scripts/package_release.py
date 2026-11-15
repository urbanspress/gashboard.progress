#!/usr/bin/env python3
"""
Gashboard v0.2.0 — Cross-Platform Go SSH Sidecar Binary & Release Archive Packager.
Builds static CGO_ENABLED=0 bridge binaries (`windows/amd64`, `linux/amd64`), verifies the
walkthrough PDF, creates `dist/gashboard-v<VERSION>-bundle.zip`, and emits `dist/SHA256SUMS.txt`.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = REPO_ROOT / "dist"


def sha256_hex(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_bridge_binary(goos: str, goarch: str, out_path: Path, version: str):
    env = os.environ.copy()
    env["CGO_ENABLED"] = "0"
    env["GOOS"] = goos
    env["GOARCH"] = goarch
    cmd = [
        "go",
        "build",
        "-trimpath",
        "-ldflags",
        f"-s -w -X main.Version={version}",
        "-o",
        str(out_path),
        "./bridge/cmd/gashboard-bridge",
    ]
    proc = subprocess.run(cmd, cwd=str(REPO_ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"Failed building {out_path.name}: {proc.stderr}\n{proc.stdout}")


def add_path_to_zip(zf: zipfile.ZipFile, src_path: Path, arc_prefix: str = ""):
    if src_path.is_dir():
        for item in sorted(src_path.rglob("*")):
            if item.is_file() and "__pycache__" not in item.parts:
                rel = item.relative_to(REPO_ROOT).as_posix()
                zf.write(item, f"{arc_prefix}{rel}")
    elif src_path.is_file():
        rel = src_path.relative_to(REPO_ROOT).as_posix()
        zf.write(src_path, f"{arc_prefix}{rel}")


def main():
    parser = argparse.ArgumentParser(description="Package Gashboard release binaries, bundle zip, PDF, and SHA256SUMS.")
    parser.add_argument("--version", default="0.2.0", help="Release version without leading v (e.g. 0.2.0)")
    args = parser.parse_args()
    version = args.version.lstrip("v")

    if DIST_DIR.exists():
        shutil.rmtree(DIST_DIR)
    DIST_DIR.mkdir(parents=True, exist_ok=True)

    win_bin = DIST_DIR / "gashboard-ssh-windows-amd64.exe"
    lin_bin = DIST_DIR / "gashboard-ssh-linux-amd64"
    build_bridge_binary("windows", "amd64", win_bin, version)
    build_bridge_binary("linux", "amd64", lin_bin, version)

    pdf_src = REPO_ROOT / "docs" / "releases" / "pdf" / f"Gashboard-v{version}-Guide.pdf"
    if not pdf_src.exists():
        raise FileNotFoundError(f"Missing release PDF guide {pdf_src}; run generate_release_guides.py first.")
    pdf_dst = DIST_DIR / pdf_src.name
    shutil.copyfile(pdf_src, pdf_dst)

    bundle_zip = DIST_DIR / f"gashboard-v{version}-bundle.zip"
    bundle_sources = [
        REPO_ROOT / "src",
        REPO_ROOT / "views",
        REPO_ROOT / "public",
        REPO_ROOT / "migrations",
        REPO_ROOT / "bridge",
        REPO_ROOT / "grab.data.json",
        REPO_ROOT / "grab.platform.json",
        REPO_ROOT / "go.mod",
        REPO_ROOT / "go.sum",
        REPO_ROOT / "README.md",
        REPO_ROOT / "CHANGELOG.md",
        REPO_ROOT / "GASHBOARD-EXPERT.md",
        REPO_ROOT / "AGENTS.md",
        pdf_src,
    ]
    with zipfile.ZipFile(bundle_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for src in bundle_sources:
            if src.exists():
                add_path_to_zip(zf, src)
        zf.write(win_bin, f"bin/{win_bin.name}")
        zf.write(lin_bin, f"bin/{lin_bin.name}")

    release_assets = sorted([win_bin, lin_bin, pdf_dst, bundle_zip], key=lambda p: p.name)
    sums_lines = [f"{sha256_hex(p)}  {p.name}" for p in release_assets]
    sums_path = DIST_DIR / "SHA256SUMS.txt"
    sums_path.write_text("\n".join(sums_lines) + "\n", encoding="utf-8")

    for line in sums_lines:
        print(line)
    print(f"Packaged Gashboard v{version} assets cleanly into {DIST_DIR}")


if __name__ == "__main__":
    main()
