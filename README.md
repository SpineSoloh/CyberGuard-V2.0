# 🛡️ CyberGuard v2.0

> **Created by [Victoria TecHub](https://github.com/YOUR_USERNAME)**

**CyberGuard v2.0** — Forensic Triage Assistant. Human-in-the-loop, privacy-aware, threat-intel enabled.

CyberGuard v2.0 helps you spot red flags on a machine that may be compromised. It is a
**decision-support tool**, not an autonomous guardian — every finding requires human verification.

---

## ⚡ Install CyberGuard v2.0 in 30 seconds (no Python needed)

### Linux / macOS
```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/cyberguard/main/scripts/install.sh | bash
```

### Windows (PowerShell — run as Administrator for best results)
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
irm https://raw.githubusercontent.com/YOUR_USERNAME/cyberguard/main/scripts/install.ps1 | iex
```

### Download pre-built binary
Go to the [CyberGuard Releases page](https://github.com/YOUR_USERNAME/cyberguard/releases/latest)
and download the binary for your OS. No Python, no pip, no dependencies.

| Platform       | File                              |
|----------------|-----------------------------------|
| Linux x86_64   | `cyberguard-linux-x86_64`         |
| Windows x86_64 | `cyberguard-windows-x86_64.exe`   |
| macOS x86_64   | `cyberguard-macos-x86_64`         |

```bash
# Linux/macOS: make executable, then run
chmod +x cyberguard-linux-x86_64
sudo ./cyberguard-linux-x86_64 --require-admin --teaching
```

---

## 🐍 Install with pip (if you have Python 3.9+)

```bash
# From PyPI
pip install cyberguard

# Latest from GitHub
pip install git+https://github.com/YOUR_USERNAME/cyberguard.git
```

---

## 🚀 Quick start

```bash
# Basic scan — no sensitive data collected, no network calls
cyberguard

# Full scan with human-readable explanations
cyberguard --teaching

# Full privileged scan (recommended — unlocks all checks)
sudo cyberguard --require-admin --teaching

# Include browser & shell history (will prompt for explicit consent)
cyberguard --browser --shell --teaching

# Hash suspicious files + submit to VirusTotal (will prompt for consent)
cyberguard --vt-key YOUR_VIRUSTOTAL_API_KEY

# Save a clean-state baseline, then scan against it next time
cyberguard --save-baseline
cyberguard                        # new processes flagged vs baseline

# Add trusted processes so they don't appear as anomalies
cyberguard --whitelist-file my_trusted_procs.txt

# Output as JSON (pipe to jq, SIEM, etc.)
cyberguard --json --output report.json

# All options
cyberguard --help
```

---

## 📋 What CyberGuard v2.0 checks

| Phase | Check | Needs admin? |
|-------|-------|-------------|
| 1 | Browser history (Chrome, Firefox) | No — but requires consent |
| 1 | Shell history (bash, zsh, PowerShell) | No — but requires consent |
| 1 | Suspicious executables in temp dirs | No |
| 2 | Process baseline comparison | No |
| 2 | Shell command anomaly scoring (14 regex patterns) | No |
| 3 | Processes with network connections → IP enrichment | Partial |
| 3 | Process tree anomalies (parent→child relationships) | No |
| 4 | SHA-256 file hashing + VirusTotal lookup | No |
| 5 | Firewall status | Yes (full) |
| 5 | Antivirus status | Yes (full) |
| 5 | Remote access exposure (RDP, SSH) | Yes (full) |
| 5 | Automatic update settings | Yes (full) |
| 5 | System hardening (UAC, SELinux, AppArmor) | Yes (full) |
| 5 | Password policy | Yes (full) |
| 6 | Network intelligence: rDNS, GeoIP, malicious IP feed matching | No |

---

## 🔒 Privacy model

- **CyberGuard v2.0 runs entirely locally** by default — no data leaves your machine.
- **Sensitive collection is opt-in:**
  - `--browser` — prompts before reading browser history
  - `--shell`   — prompts before reading shell history
  - `--vt-key`  — prompts before sending file hashes to VirusTotal
- **VirusTotal** receives file *hashes only* (not file contents). SHA-256 hashes
  cannot be reversed to reconstruct your files.
- Threat-intel IP feeds are downloaded from public sources
  ([abuse.ch](https://feodotracker.abuse.ch), [IPSum](https://github.com/stamparm/ipsum))
  at scan time. You can disable this with `--no-threat-feeds`.

---

## 🗂️ CLI reference

```
usage: cyberguard [options]

Collection:
  --browser           Collect browser history (consent prompt shown)
  --shell             Collect shell history  (consent prompt shown)
  --no-browser        Skip browser history   (default)
  --no-shell          Skip shell history     (default)

Hashing & VirusTotal:
  --vt-key KEY        VirusTotal API key — enables hash submission
  --no-vt             Skip VT even if --vt-key is set

Threat Intelligence:
  --no-threat-feeds   Skip downloading malicious IP feeds

Privileges & Whitelist:
  --require-admin     Exit if not running as root/Administrator
  --whitelist-file F  Path to plain-text file of trusted process names (one per line)

Baseline:
  --save-baseline     Snapshot current processes as baseline for future runs

Output:
  --teaching          Include "why it matters" + mitigation guidance
  --json              Machine-readable JSON output
  --output FILE       Write report to FILE (default: cyberguard_report_TIMESTAMP.txt)

  --help              Show this message
```

---

## 📄 Whitelist file format

Create a plain text file with one process name per line (case-insensitive).
Lines starting with `#` are treated as comments.

```text
# my_trusted_procs.txt
mycompany-agent
internal-monitoring-daemon
custom-updater
```

Pass it with `--whitelist-file my_trusted_procs.txt`.

---

## 🔑 Getting a VirusTotal API key

1. Sign up for free at [virustotal.com](https://www.virustotal.com)
2. Go to your profile → **API key**
3. Pass it to CyberGuard v2.0: `cyberguard --vt-key YOUR_KEY`

Free tier: 4 lookups/minute. CyberGuard v2.0 automatically rate-limits to stay within this.

---

## 🏗️ CyberGuard v2.0 repository structure

```
cyberguard/
├── cyberguard/
│   ├── __init__.py      — package metadata
│   ├── __main__.py      — entry point (python -m cyberguard)
│   └── core.py          — all logic: collection, analysis, reporting
├── scripts/
│   ├── install.sh       — Linux/macOS one-liner installer
│   └── install.ps1      — Windows PowerShell one-liner installer
├── tests/
│   └── test_basic.py    — smoke tests
├── .github/
│   └── workflows/
│       └── release.yml  — builds binaries + creates GitHub Release on tag push
├── pyproject.toml       — pip packaging config
├── LICENSE              — MIT
└── README.md
```

---

## 🤝 Contributing

1. Fork the repo
2. `pip install -e .` to install in dev mode
3. Make your changes in `cyberguard/core.py`
4. Test: `python -m cyberguard --no-threat-feeds`
5. Open a pull request

To cut a release and trigger binary builds, push a version tag:
```bash
git tag v2.1.0
git push origin v2.1.0
```
GitHub Actions will build binaries for Linux, Windows, and macOS, then publish a release automatically.

---


---

## 👤 Credits

CyberGuard v2.0 is designed and built by **Victoria TecHub**.

## ⚠️ Disclaimer

CyberGuard v2.0 is a **decision-support tool**. All findings require human verification
and contextual understanding. False positives are possible and expected — especially
for processes and shell commands. Do not take automated action based solely on CyberGuard v2.0 output without expert review.
