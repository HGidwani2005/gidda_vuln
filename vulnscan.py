#!/usr/bin/env python3
"""
linux-vulnscan
A minimal local Linux vulnerability scanner.


Checks performed (safe, local):
- Detect package manager and list upgradable packages (apt, dnf, pacman)
- Check SSH configuration for RootLogin or PasswordAuthentication
- Detect presence and status of common firewalls (ufw, firewall-cmd)
- Find SUID/SGID binaries in /usr/bin and /usr/local/bin
- Find world-writable files under /etc and /usr (limited depth)
- List listening TCP ports from /proc/net/tcp and /proc/net/tcp6
- Basic kernel / distro info
- Produce JSON and simple HTML report


Run with `--help` for options.
"""


import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime


# ---- Helpers ----


def run_cmd(cmd):
try:
out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, shell=True, universal_newlines=True, timeout=20)
return out.strip()
except Exception:
return ""




def detect_package_manager():
for pkg in ("apt", "dnf", "pacman", "zypper"):
path = shutil.which(pkg)
if path:
return pkg
return None




def list_upgradable(pkg_manager):
if not pkg_manager:
return []
if pkg_manager == "apt":
out = run_cmd("apt list --upgradable 2>/dev/null | sed '1d'")
# lines like: package/version arch [upgradable from: old]
pkgs = [line.split('/')[0] for line in out.splitlines() if line]
return pkgs
if pkg_manager == "dnf":
out = run_cmd("dnf check-update --refresh 2>/dev/null || true")
# dnf outputs a table of packages; parse simple
pkgs = []
for line in out.splitlines():
if line and not line.startswith("Last metadata") and not line.startswith("\\"):


parts = line.split()
if len(parts) >= 1 and "/" in parts[0]:
run_checks(args)
