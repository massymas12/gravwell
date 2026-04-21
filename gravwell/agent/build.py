#!/usr/bin/env python3
"""
Build gravwell-collect.exe (Windows) or gravwell-collect (Linux/macOS)
as a standalone single-file executable using PyInstaller.

Usage:
    python build.py            # build for current platform
    python build.py --clean    # wipe build/ and dist/ first

This module is intentionally dependency-free (stdlib only) so it can be
imported from GitHub Actions runners that only have PyInstaller installed.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
AGENT = HERE / "collect.py"


# ── Script customisation ──────────────────────────────────────────────────────

def generate_script(server: str = "", token: str = "") -> str:
    """Return collect.py with server/token defaults pre-filled.

    The generated script still accepts --server / --key at runtime;
    these are just convenience defaults so the user doesn't have to
    type them every time.
    """
    source = AGENT.read_text(encoding="utf-8")

    config_block = (
        "\n# ── Embedded configuration (pre-configured by GravWell server) ──────────────\n"
        f"_EMBEDDED_SERVER: str = {repr(server)}\n"
        f"_EMBEDDED_KEY: str    = {repr(token)}\n"
        "# ─────────────────────────────────────────────────────────────────────────────\n"
    )
    import re
    source = re.sub(r'VERSION = "[^"]+"\n',
                    lambda m: m.group() + config_block, source, count=1)

    source = source.replace(
        'parser.add_argument("--server", "-s", default="", help="GravWell server URL")',
        'parser.add_argument("--server", "-s", default=_EMBEDDED_SERVER, help="GravWell server URL")',
    )
    source = source.replace(
        'parser.add_argument("--key", "-k", default="", help="API key for server upload")',
        'parser.add_argument("--key", "-k", default=_EMBEDDED_KEY, help="API key for server upload")',
    )

    return source
DIST = Path.cwd() / "dist"
BUILD = Path.cwd() / "build"

EXE_NAME = "gravwell-collect"


def main() -> None:
    ap = argparse.ArgumentParser(description="Build GravWell collection agent executable")
    ap.add_argument("--clean", action="store_true", help="Remove build/ and dist/ before building")
    args = ap.parse_args()

    if args.clean:
        for d in (DIST, BUILD):
            if d.exists():
                shutil.rmtree(d)
                print(f"Removed {d}")

    # Install PyInstaller if not present
    if not shutil.which("pyinstaller"):
        print("PyInstaller not found — installing…")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "pyinstaller"],
            check=True,
        )

    cmd = [
        "pyinstaller",
        "--onefile",
        "--clean",
        "--name", EXE_NAME,
        # Hidden imports for stdlib modules loaded at runtime
        "--hidden-import", "xml.etree.ElementTree",
        "--hidden-import", "ssl",
        "--hidden-import", "urllib.request",
        str(AGENT),
    ]

    print(f"Running: {' '.join(cmd)}")
    subprocess.check_call(cmd)

    suffix = ".exe" if sys.platform == "win32" else ""
    out = DIST / (EXE_NAME + suffix)
    if out.exists():
        size_mb = out.stat().st_size / 1_048_576
        print(f"\nBuild complete: {out}  ({size_mb:.1f} MB)")
        print("\nDeploy to target machines and run:")
        print(f"  {out.name}")
        print(f"  {out.name} --server https://your-gravwell-server --key YOUR_TOKEN")
    else:
        print("Build may have failed — check PyInstaller output above", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
