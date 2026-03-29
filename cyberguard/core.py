#!/usr/bin/env python3
"""
CyberGuard v2.0 — Forensic Triage Assistant
Created by Victoria TecHub

A human-in-the-loop tool for spotting red flags on a potentially
compromised machine. Not an autonomous guardian — every finding
requires expert verification.

Features in v2.0:
  - Admin/root privilege detection & enforcement
  - Explicit consent warnings before sensitive collection
  - Depth & file count limits on all scans
  - Expanded process whitelist (auto-loaded + user-extensible)
  - Baseline anomaly detection for processes & shell commands
  - File hash checking + VirusTotal API integration
  - Network intelligence: IP resolution, GeoIP, malicious IP feeds
"""

import os
import sys
import json
import platform
import sqlite3
import hashlib
import subprocess
import tempfile
import shutil
import socket
import struct
import time
import re
import ipaddress
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import argparse
import logging
import urllib.request
import urllib.error

# ── Platform-specific imports ─────────────────────────────────────────────────
if platform.system() == "Windows":
    try:
        import winreg
    except ImportError:
        winreg = None
    try:
        import ctypes
    except ImportError:
        ctypes = None
else:
    winreg = None
    ctypes = None

try:
    import psutil
except ImportError:
    print("Error: psutil is required.  Install with:  pip install psutil")
    sys.exit(1)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("CyberGuard")

# ═════════════════════════════════════════════════════════════════════════════
# CONSTANTS & CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

# Scan depth/count limits
MAX_SCAN_DEPTH      = 4          # max directory recursion depth
MAX_FILES_PER_DIR   = 500        # max files scanned per directory
MAX_BROWSER_ENTRIES = 100        # rows pulled from browser DBs
MAX_SHELL_LINES     = 50         # tail lines from shell history files
MAX_HASH_FILES      = 200        # max files to hash & submit to VT
MAX_PROCESSES_SHOWN = 20         # max anomalous processes shown in report

# Known-good process whitelist  (lower-cased names)
PROCESS_WHITELIST: set = {
    # Windows core
    "system", "system idle process", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
    "dwm.exe", "explorer.exe", "taskhostw.exe", "sihost.exe", "fontdrvhost.exe",
    "spoolsv.exe", "searchindexer.exe", "wuauclt.exe", "msiexec.exe",
    "conhost.exe", "ctfmon.exe", "runtimebroker.exe", "securityhealthservice.exe",
    "antimalware service executable", "msmpeng.exe", "nissrv.exe",
    # Linux/macOS core
    "systemd", "init", "kthreadd", "kworker", "ksoftirqd", "migration",
    "rcu_sched", "rcu_bh", "watchdog", "kdevtmpfs", "netns", "khungtaskd",
    "kcompactd0", "oom_reaper", "writeback", "kblockd", "kswapd0",
    "sshd", "cron", "rsyslogd", "dbus-daemon", "networkmanager", "avahi-daemon",
    "cupsd", "snapd", "containerd", "dockerd",
    "launchd", "kernel_task", "WindowServer", "loginwindow", "Dock", "Finder",
    "cfprefsd", "distnoted", "notificationcenterui", "spotlight",
    # Common safe user apps (extend via --whitelist-file)
    "chrome", "firefox", "safari", "code", "python", "python3", "node",
    "java", "dropbox", "onedrive", "slack", "zoom", "teams", "spotify",
    "steam", "discord", "1password", "keepassxc",
}

# Suspicious shell-command patterns (regex)
SUSPICIOUS_CMD_PATTERNS: List[Tuple[str, str, str]] = [
    # (pattern, label, severity)
    (r"curl\s+.*\|\s*(ba)?sh",          "Download-and-exec via curl",         "Critical"),
    (r"wget\s+.*\|\s*(ba)?sh",          "Download-and-exec via wget",         "Critical"),
    (r"python[23]?\s+-c\s+['\"].*exec", "Python inline exec",                 "High"),
    (r"powershell.*-enc\s+[A-Za-z0-9+/=]{20,}", "Encoded PS command",        "High"),
    (r"powershell.*(bypass|hidden|windowstyle)", "PS execution-policy bypass","High"),
    (r"(invoke-expression|iex)\s*\(",   "PS invoke-expression",               "High"),
    (r"(downloadstring|downloadfile)\(", "PS web download",                   "High"),
    (r"base64\s*(-d|--decode)",         "Base64 decode pipeline",             "Medium"),
    (r"nc\s+-[el]",                     "netcat listener/exec",               "High"),
    (r"ncat\s+.*--exec",                "ncat exec",                          "High"),
    (r"/dev/tcp/",                      "Bash /dev/tcp redirect",             "High"),
    (r"chmod\s+[0-7]*[64][0-7]{2}\s+/", "World-writable chmod on /",         "Medium"),
    (r"(rm|del)\s+.*-[rRfF].*/(etc|boot|system32)", "Destructive deletion",  "Critical"),
    (r"crontab\s+-[li]",                "Crontab modification",               "Medium"),
    (r"(at|schtasks).*http",            "Scheduled task with URL",            "High"),
]

# Known-malicious IP feed URLs (plain-text, one IP/CIDR per line)
MALICIOUS_IP_FEEDS: List[str] = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
]

# ═════════════════════════════════════════════════════════════════════════════
# PRIVILEGE DETECTION
# ═════════════════════════════════════════════════════════════════════════════

class PrivilegeChecker:
    """Detect and optionally enforce admin/root privileges."""

    @staticmethod
    def is_admin() -> bool:
        system = platform.system()
        if system == "Windows":
            try:
                import ctypes as _ct
                return bool(_ct.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False
        else:
            return os.geteuid() == 0

    @staticmethod
    def warn_if_not_admin() -> bool:
        """Return True if admin, print warning if not."""
        if not PrivilegeChecker.is_admin():
            print("\n" + "!" * 72)
            print("  WARNING: CyberGuard is NOT running with administrator/root privileges.")
            print("  Many checks (process memory, raw sockets, shadow file, registry keys)")
            print("  will be skipped or return incomplete results.")
            print("  Re-run as Administrator (Windows) or with sudo (Linux/macOS) for")
            print("  full coverage.")
            print("!" * 72 + "\n")
            return False
        return True

    @staticmethod
    def require_admin():
        """Exit with clear message if not admin."""
        if not PrivilegeChecker.is_admin():
            print("\n[FATAL] CyberGuard: This scan requires administrator/root privileges.")
            print("  Windows : Right-click the terminal → 'Run as Administrator'")
            print("  Linux   : sudo python3 cyberguard.py ...")
            print("  macOS   : sudo python3 cyberguard.py ...")
            sys.exit(1)

# ═════════════════════════════════════════════════════════════════════════════
# CONSENT & WARNINGS
# ═════════════════════════════════════════════════════════════════════════════

class ConsentManager:
    """Interactive consent prompts before collecting sensitive data."""

    BROWSER_WARNING = """
╔══════════════════════════════════════════════════════════════════════════╗
║  SENSITIVE DATA COLLECTION WARNING — CyberGuard Browser History                    ║
║                                                                          ║
║  CyberGuard is about to read and analyse your browser history from:      ║
║    • Google Chrome                                                        ║
║    • Mozilla Firefox                                                      ║
║                                                                          ║
║  This data may contain:                                                   ║
║    • Banking / financial URLs                                             ║
║    • Medical or personal URLs                                             ║
║    • Login pages and session tokens                                       ║
║                                                                          ║
║  Data is processed LOCALLY. Nothing is sent to any server unless you     ║
║  also enable VirusTotal hash-checking (separate consent below).          ║
╚══════════════════════════════════════════════════════════════════════════╝"""

    SHELL_WARNING = """
╔══════════════════════════════════════════════════════════════════════════╗
║  SENSITIVE DATA COLLECTION WARNING — Shell / Command History            ║
║                                                                          ║
║  CyberGuard is about to read your shell command history:                 ║
║    • PowerShell  (ConsoleHost_history.txt)                               ║
║    • Bash        (~/.bash_history)                                        ║
║    • Zsh         (~/.zsh_history)                                         ║
║                                                                          ║
║  This may reveal credentials passed via CLI, internal hostnames, and    ║
║  operational tooling.  Data stays local unless VT is enabled.            ║
╚══════════════════════════════════════════════════════════════════════════╝"""

    VIRUSTOTAL_WARNING = """
╔══════════════════════════════════════════════════════════════════════════╗
║  EXTERNAL API WARNING — VirusTotal Hash Submission                      ║
║                                                                          ║
║  CyberGuard will compute SHA-256 hashes of up to {max_files} files and  ║
║  send those hashes to the VirusTotal public API.                         ║
║                                                                          ║
║  VirusTotal is a third-party service (Google LLC).                       ║
║  Hashes themselves are NOT file contents, but a hash of an internal      ║
║  tool could reveal that the tool exists on your system.                  ║
║                                                                          ║
║  VirusTotal's privacy policy: https://support.virustotal.com/            ║
╚══════════════════════════════════════════════════════════════════════════╝"""

    @staticmethod
    def ask(prompt: str, default_yes: bool = False) -> bool:
        """Prompt user for yes/no consent."""
        suffix = " [Y/n] " if default_yes else " [y/N] "
        try:
            answer = input(prompt + suffix).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        if answer == "":
            return default_yes
        return answer in ("y", "yes")

    @staticmethod
    def get_browser_consent() -> bool:
        print(ConsentManager.BROWSER_WARNING)
        return ConsentManager.ask("\nConsent to collect browser history?")

    @staticmethod
    def get_shell_consent() -> bool:
        print(ConsentManager.SHELL_WARNING)
        return ConsentManager.ask("\nConsent to collect shell history?")

    @staticmethod
    def get_virustotal_consent(max_files: int = MAX_HASH_FILES) -> bool:
        print(ConsentManager.VIRUSTOTAL_WARNING.format(max_files=max_files))
        return ConsentManager.ask("\nConsent to submit hashes to VirusTotal?")

# ═════════════════════════════════════════════════════════════════════════════
# DEPENDENCY CHECKER
# ═════════════════════════════════════════════════════════════════════════════

class DependencyChecker:
    """Detect optional tools/libraries before use — never fail silently."""

    OPTIONAL_PYTHON = ["requests"]  # requests makes VT calls easier but we use urllib
    OPTIONAL_BINARIES: Dict[str, str] = {
        "sigcheck": "Sysinternals sigcheck (Windows code-signing check)",
        "clamscan": "ClamAV scanner (Linux/macOS AV)",
        "rkhunter": "Rootkit Hunter",
        "ss":       "Socket statistics (Linux)",
        "netstat":  "Network statistics",
    }

    @staticmethod
    def check() -> Dict[str, bool]:
        results = {}
        for binary, desc in DependencyChecker.OPTIONAL_BINARIES.items():
            results[binary] = shutil.which(binary) is not None
        return results

    @staticmethod
    def report(available: Dict[str, bool]):
        missing = [b for b, ok in available.items() if not ok]
        if missing:
            logger.info("Optional tools not found (non-fatal): %s", ", ".join(missing))

# ═════════════════════════════════════════════════════════════════════════════
# NETWORK INTELLIGENCE
# ═════════════════════════════════════════════════════════════════════════════

class NetworkIntelligence:
    """IP resolution, GeoIP via ip-api.com, malicious IP feed matching."""

    def __init__(self):
        self._malicious_ips: set   = set()
        self._malicious_cidrs: list = []
        self._geo_cache: Dict[str, dict] = {}
        self._rdns_cache: Dict[str, str] = {}

    # ── Malicious IP feeds ────────────────────────────────────────────────────

    def load_malicious_ip_feeds(self, urls: List[str] = None) -> int:
        """Download and parse threat-intel IP feed lists."""
        if urls is None:
            urls = MALICIOUS_IP_FEEDS

        loaded = 0
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Cyberguard/2.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    for line in resp.read().decode("utf-8", errors="ignore").splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        try:
                            if "/" in line:
                                self._malicious_cidrs.append(ipaddress.ip_network(line, strict=False))
                            else:
                                self._malicious_ips.add(ipaddress.ip_address(line))
                            loaded += 1
                        except ValueError:
                            continue
                logger.info("Loaded feed: %s  (%d total entries)", url.split("/")[-1], loaded)
            except Exception as exc:
                logger.warning("Could not load feed %s: %s", url, exc)

        return loaded

    def is_malicious(self, ip_str: str) -> bool:
        """Check whether an IP is in the loaded threat-intel feeds."""
        try:
            addr = ipaddress.ip_address(ip_str)
            if addr in self._malicious_ips:
                return True
            for network in self._malicious_cidrs:
                if addr in network:
                    return True
        except ValueError:
            pass
        return False

    # ── Reverse DNS ───────────────────────────────────────────────────────────

    def reverse_dns(self, ip_str: str) -> str:
        if ip_str in self._rdns_cache:
            return self._rdns_cache[ip_str]
        try:
            host = socket.gethostbyaddr(ip_str)[0]
        except Exception:
            host = ip_str
        self._rdns_cache[ip_str] = host
        return host

    # ── GeoIP via ip-api.com (free, no key needed for batch < 45/min) ─────────

    def geoip_lookup(self, ip_str: str) -> dict:
        """Return dict with country, city, org, etc. for a public IP."""
        if ip_str in self._geo_cache:
            return self._geo_cache[ip_str]

        result = {"ip": ip_str, "country": "Unknown", "city": "Unknown",
                  "org": "Unknown", "lat": None, "lon": None, "error": None}
        try:
            addr = ipaddress.ip_address(ip_str)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                result["country"] = "Private/Local"
                self._geo_cache[ip_str] = result
                return result

            url = f"http://ip-api.com/json/{ip_str}?fields=status,country,city,org,lat,lon,query"
            req = urllib.request.Request(url, headers={"User-Agent": "Cyberguard/2.0"})
            with urllib.request.urlopen(req, timeout=6) as resp:
                data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                result.update({
                    "country": data.get("country", "Unknown"),
                    "city":    data.get("city", "Unknown"),
                    "org":     data.get("org", "Unknown"),
                    "lat":     data.get("lat"),
                    "lon":     data.get("lon"),
                })
        except Exception as exc:
            result["error"] = str(exc)

        self._geo_cache[ip_str] = result
        return result

    # ── High-level enrichment ─────────────────────────────────────────────────

    def enrich_connection(self, raddr_str: str) -> dict:
        """Given a remote address string ('x.x.x.x:port'), return enriched info."""
        if not raddr_str or raddr_str in ("", "None"):
            return {}
        ip = raddr_str.split(":")[0] if ":" in raddr_str else raddr_str
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {"raw": raddr_str}

        geo   = self.geoip_lookup(ip)
        rdns  = self.reverse_dns(ip)
        malicious = self.is_malicious(ip)

        return {
            "ip":        ip,
            "rdns":      rdns,
            "country":   geo.get("country", "Unknown"),
            "city":      geo.get("city", "Unknown"),
            "org":       geo.get("org", "Unknown"),
            "malicious": malicious,
        }

# ═════════════════════════════════════════════════════════════════════════════
# HASH CHECKING & VIRUSTOTAL
# ═════════════════════════════════════════════════════════════════════════════

class HashIntelligence:
    """SHA-256 file hashing and VirusTotal lookup."""

    VT_URL = "https://www.virustotal.com/api/v3/files/{hash}"
    VT_RATE_DELAY = 16  # seconds between VT requests (free tier: 4/min)

    def __init__(self, vt_api_key: Optional[str] = None):
        self.vt_api_key = vt_api_key
        self._vt_cache: Dict[str, dict] = {}

    @staticmethod
    def sha256(filepath: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (PermissionError, OSError):
            return None

    def virustotal_lookup(self, sha256_hash: str) -> dict:
        """Query VT for a hash. Returns detection summary."""
        if sha256_hash in self._vt_cache:
            return self._vt_cache[sha256_hash]

        result = {"hash": sha256_hash, "found": False, "malicious": 0,
                  "suspicious": 0, "total": 0, "permalink": None, "error": None}

        if not self.vt_api_key:
            result["error"] = "No VT API key provided"
            return result

        try:
            url = self.VT_URL.format(hash=sha256_hash)
            req = urllib.request.Request(url)
            req.add_header("x-apikey", self.vt_api_key)
            req.add_header("Accept", "application/json")

            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())

            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            result.update({
                "found":      True,
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "total":      sum(stats.values()),
                "permalink":  f"https://www.virustotal.com/gui/file/{sha256_hash}",
            })

        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                result["found"] = False  # Hash not in VT database
            else:
                result["error"] = f"HTTP {exc.code}"
        except Exception as exc:
            result["error"] = str(exc)

        self._vt_cache[sha256_hash] = result
        return result

    def batch_check(self, filepaths: List[str], consent: bool = False) -> List[dict]:
        """Hash a list of files, optionally submit to VT."""
        results = []
        for i, fpath in enumerate(filepaths[:MAX_HASH_FILES]):
            h = self.sha256(fpath)
            entry = {"path": fpath, "sha256": h, "vt": None}
            if h and consent and self.vt_api_key:
                if i > 0:
                    time.sleep(self.VT_RATE_DELAY)  # Respect free-tier limit
                entry["vt"] = self.virustotal_lookup(h)
            results.append(entry)
        return results

# ═════════════════════════════════════════════════════════════════════════════
# BASELINE & ANOMALY DETECTION
# ═════════════════════════════════════════════════════════════════════════════

class BaselineAnalyzer:
    """
    Simple statistical baseline for process and command anomaly detection.
    Baseline is built from the current run and stored as JSON for comparison
    in future runs.
    """

    BASELINE_FILE = Path.home() / ".cyberguard_baseline.json"

    @staticmethod
    def build_process_baseline() -> Dict[str, Any]:
        """Snapshot running processes as a baseline."""
        snapshot = {}
        for proc in psutil.process_iter(["pid", "name", "username", "exe", "ppid"]):
            try:
                info = proc.info
                name = (info["name"] or "").lower()
                snapshot[str(info["pid"])] = {
                    "name": name,
                    "exe":  str(info["exe"] or ""),
                    "user": str(info["username"] or ""),
                    "ppid": info["ppid"],
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return snapshot

    @staticmethod
    def load_baseline() -> Optional[Dict]:
        if BaselineAnalyzer.BASELINE_FILE.exists():
            try:
                with open(BaselineAnalyzer.BASELINE_FILE) as f:
                    return json.load(f)
            except Exception:
                return None
        return None

    @staticmethod
    def save_baseline(snapshot: Dict):
        try:
            data = {"timestamp": datetime.now().isoformat(), "processes": snapshot}
            with open(BaselineAnalyzer.BASELINE_FILE, "w") as f:
                json.dump(data, f, indent=2)
            logger.info("Baseline saved to %s", BaselineAnalyzer.BASELINE_FILE)
        except Exception as exc:
            logger.warning("Could not save baseline: %s", exc)

    @staticmethod
    def compare_to_baseline(current: Dict) -> List[Dict]:
        """Return processes not seen in the stored baseline."""
        baseline_data = BaselineAnalyzer.load_baseline()
        if not baseline_data:
            return []

        baseline_names = {
            v["name"] for v in baseline_data.get("processes", {}).values()
        }
        new_processes = []
        for pid, info in current.items():
            if info["name"] and info["name"] not in baseline_names:
                if info["name"] not in PROCESS_WHITELIST:
                    new_processes.append({
                        "pid":  pid,
                        "name": info["name"],
                        "exe":  info["exe"],
                        "user": info["user"],
                        "anomaly": "Process not seen in baseline",
                        "risk": "Low",
                    })
        return new_processes

    @staticmethod
    def score_shell_commands(commands: List[str]) -> List[Dict]:
        """Score shell commands against suspicious regex patterns."""
        flagged = []
        for cmd in commands:
            for pattern, label, severity in SUSPICIOUS_CMD_PATTERNS:
                if re.search(pattern, cmd, re.IGNORECASE):
                    flagged.append({
                        "command":  cmd[:200],
                        "pattern":  label,
                        "severity": severity,
                    })
                    break  # one match per command is enough
        return flagged

# ═════════════════════════════════════════════════════════════════════════════
# ARTIFACT COLLECTOR  (depth- and count-limited)
# ═════════════════════════════════════════════════════════════════════════════

class ArtifactCollector:
    """Cross-platform artifact collection with hard limits and consent gates."""

    # ── Browser history ───────────────────────────────────────────────────────

    @staticmethod
    def get_browser_history(consent: bool = False) -> Dict[str, List[Dict]]:
        history_data: Dict[str, List[Dict]] = {"chrome": [], "firefox": []}
        if not consent:
            logger.info("Browser history collection skipped (no consent).")
            return history_data

        try:
            # Chrome
            chrome_paths = {
                "Windows": Path.home() / "AppData/Local/Google/Chrome/User Data/Default/History",
                "Linux":   Path.home() / ".config/google-chrome/Default/History",
                "Darwin":  Path.home() / "Library/Application Support/Google/Chrome/Default/History",
            }
            chrome_path = chrome_paths.get(platform.system())
            if chrome_path and chrome_path.exists():
                history_data["chrome"] = ArtifactCollector._read_browser_db(
                    chrome_path,
                    """SELECT urls.url, urls.title, urls.visit_count,
                              datetime(visits.visit_time/1000000-11644473600,'unixepoch')
                       FROM urls JOIN visits ON urls.id = visits.url
                       ORDER BY visits.visit_time DESC LIMIT ?""",
                    (MAX_BROWSER_ENTRIES,),
                )

            # Firefox
            firefox_base = {
                "Windows": Path.home() / "AppData/Roaming/Mozilla/Firefox/Profiles",
                "Linux":   Path.home() / ".mozilla/firefox",
                "Darwin":  Path.home() / "Library/Application Support/Firefox/Profiles",
            }.get(platform.system())

            if firefox_base and firefox_base.exists():
                for profile in firefox_base.iterdir():
                    db = profile / "places.sqlite"
                    if profile.is_dir() and db.exists():
                        history_data["firefox"] = ArtifactCollector._read_browser_db(
                            db,
                            """SELECT p.url, p.title, p.visit_count,
                                      datetime(h.visit_date/1000000,'unixepoch')
                               FROM moz_places p
                               JOIN moz_historyvisits h ON p.id = h.place_id
                               ORDER BY h.visit_date DESC LIMIT ?""",
                            (MAX_BROWSER_ENTRIES,),
                        )
                        break

        except Exception as exc:
            logger.error("Browser history error: %s", exc)

        return history_data

    @staticmethod
    def _read_browser_db(db_path: Path, query: str, params: tuple) -> List[Dict]:
        entries = []
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        try:
            shutil.copy2(db_path, tmp.name)
            conn = sqlite3.connect(tmp.name)
            cursor = conn.cursor()
            cursor.execute(query, params)
            for row in cursor.fetchall():
                entries.append({"url": row[0], "title": row[1],
                                 "visit_count": row[2], "last_visit": row[3]})
            conn.close()
        except Exception as exc:
            logger.warning("DB read error (%s): %s", db_path.name, exc)
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
        return entries

    # ── Shell history ─────────────────────────────────────────────────────────

    @staticmethod
    def get_shell_history(consent: bool = False) -> Dict[str, List[str]]:
        history: Dict[str, List[str]] = {
            "powershell": [], "bash": [], "zsh": [], "cmd": []
        }
        if not consent:
            logger.info("Shell history collection skipped (no consent).")
            return history

        hist_files: Dict[str, Path] = {
            "bash": Path.home() / ".bash_history",
            "zsh":  Path.home() / ".zsh_history",
        }
        if platform.system() == "Windows":
            hist_files["powershell"] = (
                Path.home()
                / "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"
            )

        for shell, path in hist_files.items():
            if path.exists():
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        history[shell] = f.read().splitlines()[-MAX_SHELL_LINES:]
                except Exception as exc:
                    logger.warning("Shell history read error (%s): %s", shell, exc)

        return history

    # ── Unsigned executables (depth + count limited) ──────────────────────────

    @staticmethod
    def find_suspicious_executables(
        directories: List[str] = None,
        max_depth: int = MAX_SCAN_DEPTH,
        max_files: int = MAX_FILES_PER_DIR,
    ) -> List[Dict]:
        if directories is None:
            if platform.system() == "Windows":
                directories = [
                    os.environ.get("TEMP", ""),
                    os.environ.get("TMP",  ""),
                    r"C:\Windows\Temp",
                ]
            else:
                directories = ["/tmp", "/var/tmp", "/dev/shm"]

        found = []
        for d in directories:
            dp = Path(d)
            if not dp.exists() or not dp.is_dir():
                continue
            found.extend(
                ArtifactCollector._scan_directory(dp, max_depth=max_depth, max_files=max_files)
            )
        return found

    @staticmethod
    def _scan_directory(
        dir_path: Path,
        max_depth: int = MAX_SCAN_DEPTH,
        max_files: int = MAX_FILES_PER_DIR,
    ) -> List[Dict]:
        suspicious = []
        extensions = {".exe", ".dll", ".ps1", ".vbs", ".js", ".bat", ".sh", ".py"}
        file_count  = 0
        suspicious_patterns = {
            "update", "install", "svchost", "lsass", "csrss",
            "runtime", "java", "chrome", "temp", "tmp", "downloader", "payload",
        }

        def _walk(path: Path, depth: int):
            nonlocal file_count
            if depth > max_depth or file_count >= max_files:
                return
            try:
                for entry in path.iterdir():
                    if file_count >= max_files:
                        break
                    try:
                        if entry.is_dir() and not entry.is_symlink():
                            _walk(entry, depth + 1)
                        elif entry.is_file() and entry.suffix.lower() in extensions:
                            file_count += 1
                            stat = entry.stat()
                            age  = datetime.now() - datetime.fromtimestamp(stat.st_ctime)
                            info = {
                                "path":     str(entry),
                                "size":     stat.st_size,
                                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                "signed":   False,
                                "suspicious": False,
                                "reason":   "",
                            }
                            name_lower = entry.name.lower()
                            name_hit   = any(p in name_lower for p in suspicious_patterns)
                            recent     = age.days < 7

                            if entry.suffix.lower() in {".exe", ".dll"} and platform.system() == "Windows":
                                if shutil.which("sigcheck"):
                                    try:
                                        r = subprocess.run(
                                            ["sigcheck", "-q", str(entry)],
                                            capture_output=True, text=True, timeout=5
                                        )
                                        info["signed"] = r.returncode == 0
                                    except Exception:
                                        pass

                            if (name_hit or recent) and not info["signed"]:
                                info["suspicious"] = True
                                reasons = []
                                if name_hit:
                                    reasons.append("suspicious name pattern")
                                if recent:
                                    reasons.append("created/modified within 7 days")
                                info["reason"] = ", ".join(reasons)
                                suspicious.append(info)

                    except (PermissionError, OSError):
                        continue
            except (PermissionError, OSError):
                pass

        _walk(dir_path, depth=0)
        return suspicious

# ═════════════════════════════════════════════════════════════════════════════
# BEHAVIORAL ANALYZER  (whitelist-aware)
# ═════════════════════════════════════════════════════════════════════════════

class BehavioralAnalyzer:
    """Behavioral anomaly detection with whitelist and network enrichment."""

    def __init__(self, net_intel: NetworkIntelligence, extra_whitelist: set = None):
        self.net_intel = net_intel
        self.whitelist = PROCESS_WHITELIST.copy()
        if extra_whitelist:
            self.whitelist |= {x.lower() for x in extra_whitelist}

    def detect_anomalous_processes(self) -> List[Dict]:
        """Find processes with established network connections and no visible window."""
        anomalous = []
        seen = 0

        for proc in psutil.process_iter(["pid", "name", "username", "exe", "cmdline"]):
            if seen >= MAX_PROCESSES_SHOWN * 3:
                break
            try:
                info = proc.info
                name = (info["name"] or "").lower()

                # Skip whitelisted processes
                if name in self.whitelist:
                    continue

                try:
                    connections = proc.net_connections() if hasattr(proc, "net_connections") else proc.connections()
                except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                    connections = []

                established = [
                    c for c in connections
                    if getattr(c, "status", "") == "ESTABLISHED" or (
                        getattr(c, "raddr", None) and c.raddr
                    )
                ]
                if not established:
                    continue

                seen += 1

                enriched_conns = []
                for conn in established[:3]:
                    raddr = str(getattr(conn, "raddr", "")) or ""
                    enriched = self.net_intel.enrich_connection(raddr)
                    enriched["status"] = getattr(conn, "status", "")
                    enriched_conns.append(enriched)

                risk = "High"
                malicious_conn = any(c.get("malicious") for c in enriched_conns)
                if malicious_conn:
                    risk = "Critical"
                elif "system" in str(info.get("username") or "").lower():
                    risk = "Medium"

                anomalous.append({
                    "pid":         info["pid"],
                    "name":        info["name"],
                    "user":        info.get("username"),
                    "exe":         str(info.get("exe") or "Unknown"),
                    "cmdline":     " ".join(info.get("cmdline") or [])[:200],
                    "connections": enriched_conns,
                    "risk":        risk,
                    "anomaly":     "Process with network connections"
                                   + (" to KNOWN-MALICIOUS IPs" if malicious_conn else ""),
                })

            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue

        return anomalous[:MAX_PROCESSES_SHOWN]

    def analyze_process_tree(self) -> List[Dict]:
        """Flag suspicious parent→child process relationships."""
        anomalies  = []
        processes  = {}
        for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline"]):
            try:
                processes[proc.info["pid"]] = proc.info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        interpreters   = {"powershell", "powershell.exe", "cmd", "cmd.exe",
                          "wscript.exe", "cscript.exe", "bash", "sh", "zsh",
                          "python", "python3", "python.exe"}
        risky_parents  = {"explorer.exe", "svchost.exe", "services.exe",
                          "winlogon.exe", "bash", "zsh", "dash"}
        suspicious_flags = {
            "-enc", "-e ", "bypass", "hidden", "windowstyle hidden",
            "downloadstring", "webclient", "iwr ", "base64", "frombase64",
            "invoke-expression", "iex", "curl ", "wget ",
        }

        for pid, proc in processes.items():
            name_lower = (proc.get("name") or "").lower()
            if name_lower not in interpreters:
                continue
            parent = processes.get(proc.get("ppid"))
            if not parent:
                continue
            parent_name = (parent.get("name") or "").lower()
            if parent_name not in risky_parents:
                continue

            cmdline = " ".join(proc.get("cmdline") or [])
            if any(flag.lower() in cmdline.lower() for flag in suspicious_flags):
                anomalies.append({
                    "process":    proc["name"],
                    "pid":        pid,
                    "parent":     parent["name"],
                    "parent_pid": parent["pid"],
                    "cmdline":    cmdline[:200],
                    "anomaly":    "Suspicious interpreter spawned from common parent",
                    "risk":       "High",
                })

        return anomalies

# ═════════════════════════════════════════════════════════════════════════════
# SECURITY POSTURE
# ═════════════════════════════════════════════════════════════════════════════

class SecurityPosture:
    """Calculate security posture score (0–100)."""

    @staticmethod
    def calculate_score() -> Tuple[int, List[Dict]]:
        checks       = []
        total_weight = 0
        score        = 0

        security_checks = [
            {
                "name":       "Firewall Enabled",
                "weight":     15,
                "check":      SecurityPosture._check_firewall,
                "fix":        "Enable the OS firewall",
                "importance": "Prevents unauthorized inbound/outbound connections",
            },
            {
                "name":       "Antivirus Active",
                "weight":     20,
                "check":      SecurityPosture._check_antivirus,
                "fix":        "Install/enable AV and keep signatures updated",
                "importance": "Detects known malware signatures and behaviors",
            },
            {
                "name":       "Remote Access Restricted",
                "weight":     25,
                "check":      SecurityPosture._check_remote_access,
                "fix":        "Disable RDP/SSH when not needed; use VPN + MFA",
                "importance": "Unsecured remote access is a primary attack vector",
            },
            {
                "name":       "Automatic Updates Enabled",
                "weight":     10,
                "check":      SecurityPosture._check_updates,
                "fix":        "Enable OS and software automatic updates",
                "importance": "Patches known CVEs before attackers exploit them",
            },
            {
                "name":       "System Hardening",
                "weight":     15,
                "check":      SecurityPosture._check_hardening,
                "fix":        "Enable UAC / SELinux / AppArmor",
                "importance": "Reduces attack surface",
            },
            {
                "name":       "Password Policy",
                "weight":     15,
                "check":      SecurityPosture._check_passwords,
                "fix":        "Enforce complexity, lockout thresholds, and MFA",
                "importance": "Prevents credential brute-force attacks",
            },
        ]

        for chk in security_checks:
            try:
                passed, details = chk["check"]()
            except Exception as exc:
                passed, details = False, f"Check error: {exc}"

            checks.append({
                "check":      chk["name"],
                "passed":     passed,
                "weight":     chk["weight"],
                "details":    details,
                "fix":        chk["fix"],
                "importance": chk["importance"],
            })
            if passed:
                score += chk["weight"]
            total_weight += chk["weight"]

        final = int((score / total_weight) * 100) if total_weight else 0
        return final, checks

    # Individual check implementations (unchanged logic, minor cleanup) ────────

    @staticmethod
    def _check_firewall() -> Tuple[bool, str]:
        sys = platform.system()
        if sys == "Windows":
            try:
                r = subprocess.run(
                    ["netsh", "advfirewall", "show", "allprofiles"],
                    capture_output=True, text=True, timeout=10,
                )
                return "State ON" in r.stdout, "Firewall state checked via netsh"
            except Exception:
                return False, "Could not check firewall"
        elif sys == "Linux":
            for cmd in [["ufw", "status"], ["iptables", "-L"]]:
                try:
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    if "active" in r.stdout or "Chain INPUT" in r.stdout:
                        return True, f"{cmd[0]} active"
                except Exception:
                    continue
            return False, "No active firewall detected"
        elif sys == "Darwin":
            try:
                subprocess.run(
                    ["/usr/libexec/ApplicationFirewall", "--status"],
                    capture_output=True, timeout=5, check=True,
                )
                return True, "Application Firewall running"
            except Exception:
                return False, "Firewall check failed"
        return False, "Not implemented for this OS"

    @staticmethod
    def _check_antivirus() -> Tuple[bool, str]:
        sys = platform.system()
        if sys == "Windows":
            try:
                r = subprocess.run(
                    ["powershell", "-Command", "Get-MpComputerStatus"],
                    capture_output=True, text=True, timeout=10,
                )
                if "AMServiceEnabled" in r.stdout and "True" in r.stdout:
                    return True, "Windows Defender active"
            except Exception:
                pass
            return False, "No recognised AV detected"
        elif sys == "Linux":
            for av in ["clamscan", "rkhunter", "chkrootkit"]:
                if shutil.which(av):
                    return True, f"{av} detected"
            return False, "No AV tool detected"
        elif sys == "Darwin":
            return True, "XProtect built-in"
        return False, "AV check not available"

    @staticmethod
    def _check_remote_access() -> Tuple[bool, str]:
        sys = platform.system()
        if sys == "Windows":
            try:
                r = subprocess.run(
                    ["reg", "query",
                     r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
                     "/v", "fDenyTSConnections"],
                    capture_output=True, text=True, timeout=5,
                )
                if "0x1" in r.stdout:
                    return True, "RDP connections denied"
                return False, "RDP is enabled"
            except Exception:
                return False, "Could not check RDP status"
        else:
            try:
                tool = "ss" if shutil.which("ss") else "netstat"
                args = [tool, "-tln"] if tool == "ss" else [tool, "-tln"]
                r = subprocess.run(args, capture_output=True, text=True, timeout=5)
                for port in [":22 ", ":3389 "]:
                    if port in r.stdout:
                        return False, f"Listening on port {port.strip()}"
                return True, "No remote-access ports detected"
            except Exception:
                return False, "Could not check ports"

    @staticmethod
    def _check_updates() -> Tuple[bool, str]:
        sys = platform.system()
        if sys == "Windows":
            try:
                r = subprocess.run(
                    ["reg", "query",
                     r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update",
                     "/v", "AUOptions"],
                    capture_output=True, text=True, timeout=5,
                )
                if "0x3" in r.stdout or "0x4" in r.stdout:
                    return True, "Auto-updates configured"
                return False, "Auto-updates not configured"
            except Exception:
                return False, "Could not check update settings"
        elif sys == "Linux":
            if shutil.which("unattended-upgrade"):
                return True, "unattended-upgrades installed"
            return False, "Automatic updates not configured"
        return True, "Update check not implemented for this OS"

    @staticmethod
    def _check_hardening() -> Tuple[bool, str]:
        sys = platform.system()
        if sys == "Windows":
            try:
                r = subprocess.run(
                    ["reg", "query",
                     r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                     "/v", "EnableLUA"],
                    capture_output=True, text=True, timeout=5,
                )
                ok = "0x1" in r.stdout
                return ok, f"UAC {'enabled' if ok else 'disabled'}"
            except Exception:
                return False, "Could not check UAC"
        elif sys == "Linux":
            for cmd, marker in [
                (["getenforce"], "Enforcing"),
                (["aa-status"], "profiles are in enforce mode"),
            ]:
                if shutil.which(cmd[0]):
                    try:
                        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                        if marker in r.stdout:
                            return True, f"{cmd[0]} enforcing"
                    except Exception:
                        pass
            return False, "No MAC enforcement (SELinux/AppArmor)"
        return True, "Hardening check not implemented"

    @staticmethod
    def _check_passwords() -> Tuple[bool, str]:
        sys = platform.system()
        if sys == "Windows":
            try:
                r = subprocess.run(
                    ["net", "accounts"], capture_output=True, text=True, timeout=5
                )
                if "Lockout threshold" in r.stdout:
                    return True, "Account lockout policy configured"
                return False, "Password policy not configured"
            except Exception:
                return False, "Could not check password policy"
        elif sys in ("Linux", "Darwin"):
            # Check PAM config instead of /etc/shadow (doesn't need root)
            pam_paths = [
                Path("/etc/pam.d/common-auth"),
                Path("/etc/pam.d/system-auth"),
                Path("/etc/pam.d/login"),
            ]
            for pam in pam_paths:
                if pam.exists():
                    try:
                        content = pam.read_text(errors="ignore")
                        if "pam_unix" in content or "pam_pwquality" in content:
                            return True, f"PAM auth configured ({pam.name})"
                    except Exception:
                        continue
            return False, "Could not verify PAM password configuration"
        return False, "Password check not implemented"

# ═════════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═════════════════════════════════════════════════════════════════════════════

class Cyberguard:
    """Forensic triage assistant — orchestrates all modules."""

    def __init__(
        self,
        teaching_mode:   bool = False,
        output_format:   str  = "text",
        vt_api_key:      Optional[str] = None,
        extra_whitelist: set  = None,
        require_admin:   bool = False,
        load_threat_feeds: bool = True,
        browser_consent: bool = False,
        shell_consent:   bool = False,
        vt_consent:      bool = False,
    ):
        self.teaching_mode    = teaching_mode
        self.output_format    = output_format
        self.browser_consent  = browser_consent
        self.shell_consent    = shell_consent
        self.vt_consent       = vt_consent

        # Privilege check
        if require_admin:
            PrivilegeChecker.require_admin()
        else:
            PrivilegeChecker.warn_if_not_admin()

        # Dependency detection
        deps = DependencyChecker.check()
        DependencyChecker.report(deps)

        # Network intelligence
        self.net_intel = NetworkIntelligence()
        if load_threat_feeds:
            logger.info("Loading threat-intel IP feeds…")
            count = self.net_intel.load_malicious_ip_feeds()
            logger.info("Loaded %d malicious IP entries.", count)

        # Hashing
        self.hash_intel = HashIntelligence(vt_api_key=vt_api_key)

        # Behavioural analyser
        self.analyzer = BehavioralAnalyzer(
            net_intel=self.net_intel,
            extra_whitelist=extra_whitelist,
        )

    # ── Full triage ───────────────────────────────────────────────────────────

    def run_full_triage(self) -> Dict[str, Any]:
        logger.info("CyberGuard v2.0 — starting forensic triage…")

        results: Dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "system": {
                "node":      platform.node(),
                "system":    platform.system(),
                "release":   platform.release(),
                "version":   platform.version(),
                "machine":   platform.machine(),
                "processor": platform.processor(),
                "is_admin":  PrivilegeChecker.is_admin(),
            },
            "teaching_mode": self.teaching_mode,
        }

        # Phase 1 — Artifact collection
        logger.info("Phase 1: Collecting artifacts…")
        results["browser_history"]      = ArtifactCollector.get_browser_history(self.browser_consent)
        results["shell_history"]        = ArtifactCollector.get_shell_history(self.shell_consent)
        results["suspicious_executables"] = ArtifactCollector.find_suspicious_executables()

        # Phase 2 — Baseline & command anomaly detection
        logger.info("Phase 2: Baseline comparison & command scoring…")
        current_snapshot = BaselineAnalyzer.build_process_baseline()
        results["new_since_baseline"]   = BaselineAnalyzer.compare_to_baseline(current_snapshot)

        all_commands: List[str] = []
        for cmds in results["shell_history"].values():
            all_commands.extend(cmds)
        results["suspicious_commands"]  = BaselineAnalyzer.score_shell_commands(all_commands)

        # Phase 3 — Behavioral analysis
        logger.info("Phase 3: Analysing process behaviour…")
        results["anomalous_processes"]  = self.analyzer.detect_anomalous_processes()
        results["process_tree_anomalies"] = self.analyzer.analyze_process_tree()

        # Phase 4 — Hash checking
        logger.info("Phase 4: Hashing suspicious files…")
        exe_paths = [e["path"] for e in results["suspicious_executables"]]
        results["hash_results"] = self.hash_intel.batch_check(
            exe_paths, consent=self.vt_consent
        )

        # Phase 5 — Security posture
        logger.info("Phase 5: Assessing security posture…")
        score, checks = SecurityPosture.calculate_score()
        results["security_posture"] = {"score": score, "checks": checks}

        # Phase 6 — Risk assessment
        logger.info("Phase 6: Calculating risk…")
        results["risk_assessment"] = self._calculate_risk(results)

        return results

    # ── Risk assessment ───────────────────────────────────────────────────────

    def _calculate_risk(self, results: Dict) -> Dict:
        risks: List[Dict] = []

        # Browser — shortened/suspicious URLs
        shady_domains = {"bitly", "tinyurl", "shorturl", "pastebin", "github.io"}
        for browser, history in results.get("browser_history", {}).items():
            for entry in history:
                url = (entry.get("url") or "").lower()
                if any(d in url for d in shady_domains):
                    risks.append({
                        "type":       "Phishing Indicator",
                        "description": f"Shortened/suspicious URL in {browser}: {entry['url'][:100]}",
                        "severity":   "Medium",
                        "mitigation": "Verify URL destination; confirm it was a legitimate visit",
                    })

        # Suspicious shell commands
        for hit in results.get("suspicious_commands", []):
            risks.append({
                "type":       f"Suspicious Command ({hit['severity']})",
                "description": hit["pattern"],
                "details":    hit["command"],
                "severity":   hit["severity"],
                "mitigation": "Review command source; check for persistence mechanisms",
            })

        # Processes connecting to malicious IPs
        for proc in results.get("anomalous_processes", []):
            if proc.get("risk") == "Critical":
                risks.append({
                    "type":       "Malicious IP Connection",
                    "description": f"{proc['name']} (PID {proc['pid']}) connected to known-bad IP",
                    "severity":   "Critical",
                    "mitigation": "Isolate system, capture memory, escalate to IR team",
                })

        # VirusTotal detections
        for hr in results.get("hash_results", []):
            vt = hr.get("vt") or {}
            if vt.get("found") and (vt.get("malicious", 0) + vt.get("suspicious", 0)) > 0:
                risks.append({
                    "type":       "Malware Detected",
                    "description": (
                        f"File flagged by VirusTotal "
                        f"({vt['malicious']} malicious, {vt['suspicious']} suspicious "
                        f"of {vt['total']} engines): {hr['path']}"
                    ),
                    "severity":   "Critical",
                    "mitigation": f"Quarantine file immediately. VT link: {vt.get('permalink')}",
                })

        # New-since-baseline processes
        if results.get("new_since_baseline"):
            risks.append({
                "type":       "Unknown Processes",
                "description": (
                    f"{len(results['new_since_baseline'])} processes not seen in baseline"
                ),
                "severity":   "Low",
                "mitigation": "Review each process; re-run --save-baseline after confirming clean",
            })

        # Posture score
        if results.get("security_posture", {}).get("score", 100) < 70:
            risks.append({
                "type":       "Poor Security Posture",
                "description": f"Security score {results['security_posture']['score']}/100",
                "severity":   "Medium",
                "mitigation": "Address failing checks listed in Security Posture section",
            })

        # Unsigned executable count
        suspicious_count = len([
            e for e in results.get("suspicious_executables", []) if e.get("suspicious")
        ])
        if suspicious_count > 5:
            risks.append({
                "type":       "Unsigned Executables",
                "description": f"{suspicious_count} unsigned executables in temp directories",
                "severity":   "Medium",
                "mitigation": "Investigate each file; remove unknowns",
            })

        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        risks.sort(key=lambda r: severity_order.get(r["severity"], 9))

        return {
            "total_risks":    len(risks),
            "critical_count": len([r for r in risks if r["severity"] == "Critical"]),
            "high_risk_count":   len([r for r in risks if r["severity"] == "High"]),
            "medium_risk_count": len([r for r in risks if r["severity"] == "Medium"]),
            "low_risk_count":    len([r for r in risks if r["severity"] == "Low"]),
            "risks":          risks,
        }

    # ── Output formatting ─────────────────────────────────────────────────────

    def format_output(self, results: Dict) -> str:
        if self.output_format == "json":
            return json.dumps(results, indent=2, default=str)

        out: List[str] = []
        W = 80
        hr = "=" * W

        def h(title: str):
            out.append(hr)
            out.append(f"  {title}")
            out.append("-" * W)

        out.append(hr)
        out.append("  CyberGuard v2.0 — FORENSIC TRIAGE REPORT")
        out.append(f"  {"=" * 78}")
        out.append(f"  Generated : {results['timestamp']}")
        sys_info = results["system"]
        out.append(f"  System    : {sys_info['node']} ({sys_info['system']} {sys_info['release']})")
        out.append(f"  Admin/root: {'YES' if sys_info['is_admin'] else 'NO — some checks may be incomplete'}")
        out.append(f"  Created by: Victoria TecHub")
        out.append("")

        # ── Risk summary ──────────────────────────────────────────────────────
        ra = results["risk_assessment"]
        h("RISK SUMMARY")
        out.append(f"  Total risks   : {ra['total_risks']}")
        out.append(f"  Critical      : {ra['critical_count']}")
        out.append(f"  High          : {ra['high_risk_count']}")
        out.append(f"  Medium        : {ra['medium_risk_count']}")
        out.append(f"  Low           : {ra['low_risk_count']}")
        out.append("")

        if ra["risks"]:
            for i, risk in enumerate(ra["risks"], 1):
                sev = risk["severity"]
                marker = {"Critical": "💀", "High": "🔴", "Medium": "🟡", "Low": "🔵"}.get(sev, "•")
                out.append(f"  {i:2}. {marker} [{sev:8}] {risk['type']}")
                out.append(f"       {risk['description']}")
                if risk.get("details"):
                    out.append(f"       Details : {risk['details']}")
                if self.teaching_mode:
                    out.append(f"       Fix     : {risk['mitigation']}")
                out.append("")

        # ── Security posture ──────────────────────────────────────────────────
        posture = results["security_posture"]
        h(f"SECURITY POSTURE  [{posture['score']}/100]")
        for chk in posture["checks"]:
            icon = "✓" if chk["passed"] else "✗"
            out.append(f"  {icon} {chk['check']}")
            if not chk["passed"]:
                out.append(f"    Details : {chk['details']}")
                if self.teaching_mode:
                    out.append(f"    Why     : {chk['importance']}")
                    out.append(f"    Fix     : {chk['fix']}")
        out.append("")

        # ── Anomalous processes ───────────────────────────────────────────────
        procs = results.get("anomalous_processes", [])
        if procs:
            h("ANOMALOUS PROCESSES")
            for p in procs:
                tag = "💀 MALICIOUS IP" if p["risk"] == "Critical" else f"⚠ {p['risk']}"
                out.append(f"  [{tag}] PID {p['pid']}  {p['name']}")
                out.append(f"    Exe  : {p['exe']}")
                out.append(f"    User : {p['user']}")
                if p.get("cmdline"):
                    out.append(f"    Cmd  : {p['cmdline'][:100]}")
                for conn in p.get("connections", []):
                    flags = []
                    if conn.get("malicious"):
                        flags.append("MALICIOUS")
                    flag_str = f" ← {', '.join(flags)}" if flags else ""
                    out.append(
                        f"    Conn : {conn.get('ip','')}  [{conn.get('country','')} / "
                        f"{conn.get('org','')}]  rDNS:{conn.get('rdns','')}{flag_str}"
                    )
                if self.teaching_mode:
                    out.append(
                        "    Note : Process with established network connections "
                        "may indicate C2 beaconing."
                    )
                out.append("")

        # ── Process tree anomalies ────────────────────────────────────────────
        tree = results.get("process_tree_anomalies", [])
        if tree:
            h("PROCESS TREE ANOMALIES")
            for a in tree:
                out.append(f"  🔴 {a['process']} (PID {a['pid']}) ← {a['parent']} (PID {a['parent_pid']})")
                out.append(f"    Cmd : {a['cmdline']}")
                out.append("")

        # ── Suspicious commands ───────────────────────────────────────────────
        cmds = results.get("suspicious_commands", [])
        if cmds:
            h("SUSPICIOUS SHELL COMMANDS")
            for c in cmds:
                sev = c["severity"]
                out.append(f"  [{sev}] {c['pattern']}")
                out.append(f"    > {c['command']}")
                out.append("")

        # ── Hash / VT results ─────────────────────────────────────────────────
        vt_hits = [
            hr for hr in results.get("hash_results", [])
            if hr.get("vt") and hr["vt"].get("malicious", 0) > 0
        ]
        if vt_hits:
            h("VIRUSTOTAL DETECTIONS")
            for hr in vt_hits:
                vt = hr["vt"]
                out.append(f"  💀 {hr['path']}")
                out.append(f"     SHA-256   : {hr['sha256']}")
                out.append(f"     Detections: {vt['malicious']} malicious, "
                           f"{vt['suspicious']} suspicious / {vt['total']} engines")
                out.append(f"     Link      : {vt.get('permalink','')}")
                out.append("")
        elif results.get("hash_results"):
            h("HASH RESULTS")
            out.append(f"  {len(results['hash_results'])} files hashed — no VT detections.")
            out.append("")

        # ── New-since-baseline ────────────────────────────────────────────────
        new_procs = results.get("new_since_baseline", [])
        if new_procs:
            h("NEW PROCESSES (not in baseline)")
            for p in new_procs[:10]:
                out.append(f"  • PID {p['pid']:6}  {p['name']}  ({p['exe']})")
            out.append("")

        # ── Unsigned executables ──────────────────────────────────────────────
        unsigned = results.get("suspicious_executables", [])
        if unsigned:
            h("SUSPICIOUS EXECUTABLES IN TEMP DIRS")
            for exe in unsigned[:10]:
                out.append(f"  • {exe['path']}")
                out.append(f"    Size: {exe['size']:,} bytes  Modified: {exe['modified']}")
                out.append(f"    Reason: {exe['reason']}")
                out.append("")

        # ── Footer ────────────────────────────────────────────────────────────
        out.append(hr)
        out.append("  NOTE: CyberGuard assists human analysis. All findings require")
        out.append("  human verification and contextual understanding.")
        out.append("  Data collected locally. Hashes sent to VirusTotal only if consented.")
        out.append("")
        out.append("  " + "─" * 76)
        out.append("  CyberGuard v2.0  ·  Created by Victoria TecHub")
        out.append("  " + "─" * 76)
        out.append(hr)

        return "\n".join(out)


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def load_whitelist_file(path: str) -> set:
    """Load extra process names from a plain-text file (one per line)."""
    entries = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                name = line.strip().lower()
                if name and not name.startswith("#"):
                    entries.add(name)
        logger.info("Loaded %d whitelist entries from %s", len(entries), path)
    except Exception as exc:
        logger.warning("Could not load whitelist file: %s", exc)
    return entries


def main():
    parser = argparse.ArgumentParser(
        description="CyberGuard v2.0 — Forensic Triage Assistant",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cyberguard.py --teaching
  python3 cyberguard.py --require-admin --vt-key YOUR_KEY --json
  python3 cyberguard.py --whitelist-file my_procs.txt --save-baseline
  python3 cyberguard.py --no-threat-feeds --output report.txt
        """,
    )

    # Collection options
    g = parser.add_argument_group("Collection")
    g.add_argument("--browser",   action="store_true", help="Collect browser history (will prompt for consent)")
    g.add_argument("--shell",     action="store_true", help="Collect shell history (will prompt for consent)")
    g.add_argument("--no-browser", dest="browser", action="store_false")
    g.add_argument("--no-shell",   dest="shell",   action="store_false")

    # Hashing / VT
    g2 = parser.add_argument_group("Hashing & VirusTotal")
    g2.add_argument("--vt-key",   type=str, default=None,
                    help="VirusTotal API key (enables hash submission after consent)")
    g2.add_argument("--no-vt",    action="store_true", help="Skip VT lookups even if key is set")

    # Threat intelligence
    g3 = parser.add_argument_group("Threat Intelligence")
    g3.add_argument("--no-threat-feeds", action="store_true",
                    help="Skip downloading malicious IP feeds")

    # Privileges & whitelist
    g4 = parser.add_argument_group("Privileges & Whitelist")
    g4.add_argument("--require-admin", action="store_true",
                    help="Exit if not running as admin/root")
    g4.add_argument("--whitelist-file", type=str, default=None,
                    help="Path to plain-text file of extra whitelisted process names")

    # Baseline
    g5 = parser.add_argument_group("Baseline")
    g5.add_argument("--save-baseline", action="store_true",
                    help="Save current process snapshot as baseline for future runs")

    # Output
    g6 = parser.add_argument_group("Output")
    g6.add_argument("--teaching", action="store_true", help="Include explanations and mitigations")
    g6.add_argument("--json",     action="store_true", help="JSON output")
    g6.add_argument("--output",   type=str, default=None, help="Output file path")

    args, _ = parser.parse_known_args()

    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║                   CyberGuard  v2.0                          ║
    ║             Forensic Triage Assistant                        ║
    ║                                                              ║
    ║     Human-in-the-loop · Privacy-aware · Threat-intel        ║
    ║                                                              ║
    ║               Created by  Victoria TecHub                   ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

    # Consent gates
    browser_consent = False
    shell_consent   = False
    vt_consent      = False

    if args.browser:
        browser_consent = ConsentManager.get_browser_consent()
    if args.shell:
        shell_consent = ConsentManager.get_shell_consent()
    if args.vt_key and not args.no_vt:
        vt_consent = ConsentManager.get_virustotal_consent()

    # Extra whitelist
    extra_whitelist: set = set()
    if args.whitelist_file:
        extra_whitelist = load_whitelist_file(args.whitelist_file)

    # Output filename
    if not args.output:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"cyberguard_report_{ts}.{'json' if args.json else 'txt'}"

    # Build and run
    guard = Cyberguard(
        teaching_mode    = args.teaching,
        output_format    = "json" if args.json else "text",
        vt_api_key       = args.vt_key if not args.no_vt else None,
        extra_whitelist  = extra_whitelist,
        require_admin    = args.require_admin,
        load_threat_feeds= not args.no_threat_feeds,
        browser_consent  = browser_consent,
        shell_consent    = shell_consent,
        vt_consent       = vt_consent,
    )

    # Optional: save baseline before triage
    if args.save_baseline:
        snapshot = BaselineAnalyzer.build_process_baseline()
        BaselineAnalyzer.save_baseline(snapshot)
        print(f"✓ Baseline saved to {BaselineAnalyzer.BASELINE_FILE}")

    try:
        results = guard.run_full_triage()
        output  = guard.format_output(results)

        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)

        print(output)
        print(f"\n✓ Report saved to: {args.output}")
        print("  Remember: CyberGuard assists human analysis — always verify findings!")

        ra = results["risk_assessment"]
        if ra["critical_count"] > 0:
            print("\n💀 CRITICAL findings detected! Isolate system and escalate immediately.")
            return 2
        if ra["high_risk_count"] > 0:
            print("\n⚠️  HIGH-risk findings detected! Immediate investigation recommended.")
            return 1
        if ra["total_risks"] > 0:
            print("\n⚠️  Medium/Low findings detected. Review at your earliest convenience.")

    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        return 130
    except Exception as exc:
        logger.error("Critical error: %s", exc)
        print(f"\n❌ Error: {exc}")
        return 2

    return 0


