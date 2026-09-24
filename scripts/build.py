#!/usr/bin/env python3
"""Build standalone executables with PyInstaller.

Usage:
    python scripts/build.py --all
    python scripts/build.py --only gui --name-suffix -x86_64
"""

from __future__ import annotations

import argparse
import os
import sys

import PyInstaller.__main__

GUI_ENTRY = "nk_gui.py"
SERVER_ENTRY = "nk_server.py"


def build(entry: str, name: str, windowed: bool, onefile: bool = True) -> None:
    args = [
        entry,
        "--name",
        name,
        "--paths",
        ".",
        "--noconfirm",
        "--clean",
        "--collect-submodules",
        "noknowledge",
        "--hidden-import",
        "noknowledge",
    ]
    if onefile:
        args.append("--onefile")
    if windowed:
        args.append("--windowed")
    print(f"::group::PyInstaller {' '.join(args)}")
    PyInstaller.__main__.run(args)
    print("::endgroup::")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", choices=["gui", "server", "all"], default="all")
    parser.add_argument("--name-suffix", default="")
    parser.add_argument("--onedir", action="store_true", help="build a folder instead of one file")
    args = parser.parse_args(argv)
    onefile = not args.onedir

    os.makedirs("dist", exist_ok=True)
    if args.only in ("gui", "all"):
        build(GUI_ENTRY, f"nk-gui{args.name_suffix}", windowed=True, onefile=onefile)
    if args.only in ("server", "all"):
        build(SERVER_ENTRY, f"nk-server{args.name_suffix}", windowed=False, onefile=onefile)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())