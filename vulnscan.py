#!/usr/bin/env python3
"""
linux-vulnscan - lightweight local Linux vulnerability scanner (safe, local checks)

Checks performed (non-intrusive):
 - Detect package manager and list upgradable packages (apt, dnf, pacman, zypper)
 - Check SSH config for PermitRootLogin / PasswordAuthentication
 - Detect common firewalls (ufw, firewalld)
 - Find SUID/SGID binaries (in /usr/bin and /usr/local/bin by default)
 - Find world-writable files under /etc and /usr (limited depth)
 - List listening TCP ports (from /proc/net/tcp and tcp6)
 - Basic system/distro info
 - Produce JSON and simple HTML report
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from typing import List, Dict, Any

# ----- simple terminal colors (no external deps) -----
def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

if _supports_color():
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    BLUE = "\033[34m"
    RESET = "\033[0m"
else:
    GREEN = YELLOW = RED = BLUE = RESET = ""


def run_cmd(cmd: str, timeout: int = 20) -> str:
    """Run a shell command and return its stdout (or empty string on error)."""
    try:
        out = subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, shell=True, universal_newlines=True, timeout=timeout
        )
        return out.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return ""
    except Exception:
        return ""


def detect_package_manager() -> str | None:
    """Return one of 'apt','dnf','pacman','zypper' or None if not found."""
    for pkg in ("apt", "dnf", "pacman", "zypper"):
        if shutil.which(pkg):
            return pkg
    return None


def list_upgradable(pkg_manager: str | None) -> List[str]:
    """Return a list (strings) describing upgradable packages (best-effort)."""
    if not pkg_manager:
        return []

    results: List[str] = []
    if pkg_manager == "apt":
        # apt output: "package/version arch [upgradable from: old]"
        out = run_cmd("apt list --upgradable 2>/dev/null")
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("Listing..."):
                continue
            # normalize to package name (before '/')
            results.append(line)
        return results

    if pkg_manager == "dnf":
        # dnf outputs groups of lines; keep non-empty non-metadata lines
        out = run_cmd("dnf check-update --refresh 2>/dev/null || true")
        for line in out.splitlines():
            if not line or line.startswith("Last metadata") or line.startswith("Amazon"):
                continue
            results.append(line)
        return results

    if pkg_manager == "pacman":
        out = run_cmd("pacman -Qu 2>/dev/null")
        for line in out.splitlines():
            if line.strip():
                results.append(line.strip())
        return results

    if pkg_manager == "zypper":
        out = run_cmd("zypper list-updates 2>/dev/null")
        for line in out.splitlines():
            if line.strip():
                results.append(line.strip())
        return results

    return results


def check_ssh_config() -> Dict[str, Any]:
    """Read /etc/ssh/sshd_config and return basic findings."""
    sshd = "/etc/ssh/sshd_config"
    findings: Dict[str, Any] = {}
    if os.path.exists(sshd):
        try:
            with open(sshd, "r", errors="ignore") as f:
                txt = f.read()
            m_rl = re.search(r"^\s*PermitRootLogin\s+(\S+)", txt, re.M | re.I)
            m_pa = re.search(r"^\s*PasswordAuthentication\s+(\S+)", txt, re.M | re.I)
            findings["found"] = True
            findings["PermitRootLogin"] = m_rl.group(1) if m_rl else "unspecified"
            findings["PasswordAuthentication"] = m_pa.group(1) if m_pa else "unspecified"
        except Exception as e:
            findings["error"] = str(e)
    else:
        findings["found"] = False
    return findings


def check_firewall() -> Dict[str, str]:
    """Return status of common firewalls (ufw, firewalld)."""
    res: Dict[str, str] = {}
    if shutil.which("ufw"):
        out = run_cmd("ufw status verbose")
        res["ufw"] = out.splitlines()[0] if out else "unknown"
    if shutil.which("firewall-cmd"):
        out = run_cmd("firewall-cmd --state")
        res["firewalld"] = out or "unknown"
    return res


def find_suid_sgid(paths: List[str] = None) -> List[str]:
    """Find SUID/SGID binaries in given paths (default common bin dirs)."""
    if paths is None:
        paths = ["/usr/bin", "/usr/local/bin"]
    results: List[str] = []
    for base in paths:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            for name in files:
                full = os.path.join(root, name)
                try:
                    st = os.stat(full)
                    mode = st.st_mode
                    if mode & stat.S_ISUID or mode & stat.S_ISGID:
                        results.append(full)
                except Exception:
                    continue
    return results


def find_world_writable(paths: List[str] = None, max_depth: int = 3) -> List[str]:
    """Find world-writable regular files under given paths (limited depth)."""
    if paths is None:
        paths = ["/etc", "/usr"]
    results: List[str] = []
    for base in paths:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            depth = root.count(os.sep) - base.count(os.sep)
            if depth > max_depth:
                dirs[:] = []
                continue
            for name in files:
                full = os.path.join(root, name)
                try:
                    st = os.stat(full)
                    if stat.S_ISREG(st.st_mode) and (st.st_mode & 0o0002):
                        results.append(full)
                except Exception:
                    continue
    return results


def list_listening_ports() -> List[int]:
    """Return a sorted list of listening TCP ports (reads /proc/net/tcp and tcp6)."""
    ports = set()
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r") as f:
                lines = f.read().splitlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) < 4:
                    continue
                local = parts[1]
                state = parts[3]
                # 0A is LISTEN state
                if state != "0A":
                    continue
                try:
                    _, hex_port = local.split(":")
                    port = int(hex_port, 16)
                    ports.add(port)
                except Exception:
                    continue
        except Exception:
            continue
    return sorted(ports)


def get_os_release() -> Dict[str, str]:
    """Parse /etc/os-release if present to return distro info."""
    info: Dict[str, str] = {}
    if os.path.exists("/etc/os-release"):
        try:
            with open("/etc/os-release", "r") as f:
                for line in f:
                    if "=" in line:
                        k, v = line.rstrip().split("=", 1)
                        info[k] = v.strip().strip('"')
        except Exception:
            pass
    return info


def get_system_info() -> Dict[str, Any]:
    """Return a dict with basic system information."""
    osrel = get_os_release()
    return {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "hostname": platform.node(),
        "python_version": platform.python_version(),
        "distro_pretty": osrel.get("PRETTY_NAME", ""),
    }


def generate_html_report(report: Dict[str, Any], outpath: str) -> bool:
    """Write a very simple HTML report."""
    title = f"linux-vulnscan report - {report.get('timestamp','')}"
    try:
        with open(outpath, "w") as f:
            f.write("<!doctype html><html><head><meta charset='utf-8'>")
            f.write(f"<title>{title}</title></head><body>")
            f.write(f"<h1>{title}</h1>\n")
            f.write("<h2>Summary</h2>\n")
            f.write("<pre>\n")
            f.write(json.dumps(report.get("summary", {}), indent=2))
            f.write("\n</pre>\n")
            f.write("<h2>Full report</h2>\n")
            f.write("<pre>\n")
            f.write(json.dumps(report, indent=2))
            f.write("\n</pre>\n")
            f.write("</body></html>")
        return True
    except Exception:
        return False


def generate_report(
    system: Dict[str, Any],
    upgradable: List[str],
    ssh: Dict[str, Any],
    fw: Dict[str, str],
    suid: List[str],
    world: List[str],
    ports: List[int],
) -> Dict[str, Any]:
    """Aggregate findings into a report dictionary."""
    summary = {
        "upgradable_count": len(upgradable),
        "suid_count": len(suid),
        "world_writable_count": len(world),
        "listening_ports_count": len(ports),
    }
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system": system,
        "summary": summary,
        "upgradable_packages": upgradable,
        "ssh_config": ssh,
        "firewall": fw,
        "suid_sgid_binaries": suid,
        "world_writable_files": world,
        "listening_tcp_ports": ports,
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="linux-vulnscan - lightweight local vulnerability scanner")
    parser.add_argument("-o", "--output", help="Write JSON output to file")
    parser.add_argument("--html", help="Write simple HTML report")
    parser.add_argument("--quiet", action="store_true", help="Suppress console output")
    parser.add_argument("--full", action="store_true", help="Print full lists to console (may be long)")
    args = parser.parse_args()

    if not args.quiet:
        print(f"{BLUE}🔎 Detecting package manager and local issues...{RESET}")

    pkg = detect_package_manager()
    if pkg:
        if not args.quiet:
            print(f"{YELLOW}🔎 Using {pkg} to check for upgradable packages...{RESET}")
    else:
        if not args.quiet:
            print(f"{YELLOW}⚠ No supported package manager found (apt/dnf/pacman/zypper). Skipping package checks.{RESET}")

    upgradable = list_upgradable(pkg)
    ssh = check_ssh_config()
    fw = check_firewall()
    suid = find_suid_sgid()
    world = find_world_writable()
    ports = list_listening_ports()
    system = get_system_info()

    report = generate_report(system, upgradable, ssh, fw, suid, world, ports)

    # write JSON
    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2)
            if not args.quiet:
                print(f"{GREEN}Wrote JSON report to {args.output}{RESET}")
        except Exception as e:
            print(f"{RED}Failed to write JSON report: {e}{RESET}", file=sys.stderr)

    # write HTML
    if args.html:
        ok = generate_html_report(report, args.html)
        if ok:
            if not args.quiet:
                print(f"{GREEN}Wrote HTML report to {args.html}{RESET}")
        else:
            print(f"{RED}Failed to write HTML report{RESET}", file=sys.stderr)

    # Console summary
    if not args.quiet:
        print()
        print(f"{BLUE}=== Summary ==={RESET}")
        print(f"Host: {system.get('hostname','-')}  Distro: {system.get('distro_pretty','-')}")
        print(f"Upgradable packages: {len(upgradable)}")
        print(f"SUID/SGID binaries found: {len(suid)}")
        print(f"World-writable files found: {len(world)}")
        print(f"Listening TCP ports: {', '.join(map(str, ports)) if ports else 'none'}")
        if ssh.get("found"):
            print(f"SSH - PermitRootLogin: {ssh.get('PermitRootLogin')}, PasswordAuthentication: {ssh.get('PasswordAuthentication')}")
        else:
            print("SSH config: not found")
        if fw:
            for k, v in fw.items():
                print(f"Firewall ({k}): {v}")
        else:
            print("Firewall: none detected")

        # big lists only if user asked
        if args.full:
            if upgradable:
                print()
                print(f"{YELLOW}-- Upgradable packages (sample / full list) --{RESET}")
                for line in upgradable:
                    print(line)
            if suid:
                print()
                print(f"{YELLOW}-- SUID/SGID binaries --{RESET}")
                for p in suid:
                    print(p)
            if world:
                print()
                print(f"{YELLOW}-- World-writable files --{RESET}")
                for p in world:
                    print(p)

        else:
            print()
            print(f"To see full lists (may be long), re-run with the {YELLOW}--full{RESET} flag.")
            print(f"To save full output, use {YELLOW}-o report.json{RESET} and/or {YELLOW}--html report.html{RESET}")

    # If no output requested and not quiet, also show short hint
    if not args.output and not args.html and not args.quiet:
        print()
        print("Tip: save results to a file with -o report.json and open the HTML with --html report.html")

if __name__ == "__main__":
    main()
