#!/usr/bin/env python3
"""
build_exe.py - package the NetCut dashboard into a single Windows .exe.

    python build_exe.py

Produces  dist\\NetCutDashboard.exe  - a self-contained launcher that starts the local
dashboard server and opens your browser. The exe is built with a UAC manifest, so Windows
asks for Administrator automatically (needed for the ARP engine). Npcap must be installed
on the machine that runs it (it is a system driver and cannot be bundled).
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--onefile",
        "--name", "NetCutDashboard",
        "--uac-admin",                       # request Administrator on launch
        "--collect-all", "scapy",            # pull in scapy's many submodules + data
        "--collect-all", "cryptography",     # for HTTPS interception (CA + per-site certs)
        "--add-data", f"{HERE / 'web'}{';'}web",   # bundle the dashboard files
        "--hidden-import", "net_tree",
        "--hidden-import", "mini_nmap",
        "--hidden-import", "netcut",
        "--hidden-import", "mitm_tls",
        "--paths", str(HERE),
        str(HERE / "netcut_gui.py"),
    ]
    print("Running:", " ".join(args), "\n")
    rc = subprocess.call(args)
    exe = HERE / "dist" / "NetCutDashboard.exe"
    if rc == 0 and exe.exists():
        print(f"\n  Built: {exe}  ({exe.stat().st_size // (1024*1024)} MB)")
        print("  Double-click it (approve the UAC prompt) to open the dashboard.")
    else:
        print(f"\n  Build failed (exit {rc}).")
        sys.exit(rc or 1)


if __name__ == "__main__":
    main()
