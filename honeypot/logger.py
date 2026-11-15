"""
Thread-safe Logging Engine for the IoT Telnet Honeypot.
Logs events across:
1. SQLite Database (relational queries and analytics)
2. JSON Lines (structured log forwarding / ELK / Splunk compatibility)
3. Standard Log File + Formatted Console Output
"""

import os
import json
import sqlite3
import logging
import threading
from datetime import datetime
from pathlib import Path
from honeypot.config import DB_FILE, JSONL_FILE, TEXT_LOG_FILE

# ANSI color codes for terminal
try:
    import colorama
    colorama.init(autoreset=True)
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
except ImportError:
    GREEN = YELLOW = RED = CYAN = MAGENTA = RESET = BOLD = ""

class HoneypotLogger:
    def __init__(self, db_path=DB_FILE, jsonl_path=JSONL_FILE, log_path=TEXT_LOG_FILE):
        self.db_path = str(db_path)
        self.jsonl_path = str(jsonl_path)
        self.log_path = str(log_path)
        self._lock = threading.Lock()
        
        # Setup file logger
        self.logger = logging.getLogger("IoTHoneypot")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        
        # Avoid duplicate handlers if re-initialized
        if not self.logger.handlers:
            # File handler
            fh = logging.FileHandler(self.log_path, encoding="utf-8")
            fh.setLevel(logging.INFO)
            fh_formatter = logging.Formatter(
                "[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
            )
            fh.setFormatter(fh_formatter)
            self.logger.addHandler(fh)

            # Console handler
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            ch_formatter = logging.Formatter(
                "%(message)s"
            )
            ch.setFormatter(ch_formatter)
            self.logger.addHandler(ch)

        self._init_database()

    def _get_connection(self):
        """Creates a dedicated SQLite connection with timeout."""
        conn = sqlite3.connect(self.db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_database(self):
        """Initializes database tables if they do not exist."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS sessions (
                        session_id TEXT PRIMARY KEY,
                        client_ip TEXT NOT NULL,
                        client_port INTEGER NOT NULL,
                        started_at TEXT NOT NULL,
                        ended_at TEXT,
                        authenticated INTEGER DEFAULT 0,
                        auth_username TEXT,
                        auth_password TEXT,
                        total_commands INTEGER DEFAULT 0
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS auth_attempts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT NOT NULL,
                        client_ip TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        username TEXT NOT NULL,
                        password TEXT NOT NULL,
                        success INTEGER NOT NULL,
                        known_iot_signature TEXT,
                        threat_level TEXT,
                        FOREIGN KEY(session_id) REFERENCES sessions(session_id)
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS commands (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT NOT NULL,
                        client_ip TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        raw_command TEXT NOT NULL,
                        matched_signature TEXT,
                        botnet_family TEXT,
                        severity TEXT,
                        extracted_urls TEXT,
                        FOREIGN KEY(session_id) REFERENCES sessions(session_id)
                    )
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(client_ip)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_username ON auth_attempts(username)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id)")
                conn.commit()

    def _write_jsonl(self, event_type, data):
        """Appends a structured event to the JSONL log file."""
        record = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            **data
        }
        with open(self.jsonl_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def log_session_start(self, session_id, client_ip, client_port):
        """Records a new incoming connection."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    "INSERT INTO sessions (session_id, client_ip, client_port, started_at) VALUES (?, ?, ?, ?)",
                    (session_id, client_ip, client_port, now),
                )
                conn.commit()
            self._write_jsonl("connection_opened", {
                "session_id": session_id,
                "client_ip": client_ip,
                "client_port": client_port
            })
        msg = f"{CYAN}[+]{RESET} Connection established from {BOLD}{client_ip}:{client_port}{RESET} (Session: {session_id[:8]})"
        self.logger.info(msg)

    def log_auth_attempt(self, session_id, client_ip, username, password, success, cred_analysis):
        """Records a login credential attempt."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        known_sig = cred_analysis.get("signature", "Unknown")
        threat_level = cred_analysis.get("threat_level", "MEDIUM")
        status_str = "ACCEPTED" if success else "FAILED"

        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO auth_attempts 
                    (session_id, client_ip, timestamp, username, password, success, known_iot_signature, threat_level)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (session_id, client_ip, now, username, password, int(success), known_sig, threat_level),
                )
                if success:
                    conn.execute(
                        "UPDATE sessions SET authenticated = 1, auth_username = ?, auth_password = ? WHERE session_id = ?",
                        (username, password, session_id),
                    )
                conn.commit()
            
            self._write_jsonl("auth_attempt", {
                "session_id": session_id,
                "client_ip": client_ip,
                "username": username,
                "password": password,
                "success": bool(success),
                "signature": known_sig,
                "threat_level": threat_level
            })

        color = GREEN if success else RED
        sig_info = f" -> Known: {BOLD}{known_sig}{RESET}" if cred_analysis.get("is_known_iot") else ""
        msg = (
            f"{color}[*]{RESET} Auth [{client_ip}] {BOLD}{username}:{password}{RESET} "
            f"({color}{status_str}{RESET}){sig_info}"
        )
        self.logger.info(msg)

    def log_command(self, session_id, client_ip, command_str, cmd_analysis):
        """Records an executed command."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        matches = cmd_analysis.get("matches", [])
        sig_names = ", ".join([m["name"] for m in matches]) if matches else "None"
        botnet_families = ", ".join(set([m["botnet"] for m in matches])) if matches else "Unclassified"
        severity = cmd_analysis.get("highest_severity", "LOW")
        urls_str = ", ".join(cmd_analysis.get("extracted_urls", []))

        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO commands 
                    (session_id, client_ip, timestamp, raw_command, matched_signature, botnet_family, severity, extracted_urls)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (session_id, client_ip, now, command_str, sig_names, botnet_families, severity, urls_str),
                )
                conn.execute(
                    "UPDATE sessions SET total_commands = total_commands + 1 WHERE session_id = ?",
                    (session_id,),
                )
                conn.commit()

            self._write_jsonl("command_executed", {
                "session_id": session_id,
                "client_ip": client_ip,
                "command": command_str,
                "matched_signatures": sig_names,
                "botnet_family": botnet_families,
                "severity": severity,
                "urls": cmd_analysis.get("extracted_urls", [])
            })

        sev_color = RED if severity in ("CRITICAL", "HIGH") else (YELLOW if severity == "MEDIUM" else GREEN)
        flag_str = f" [{sev_color}{severity}{RESET} | {botnet_families}]" if matches else ""
        msg = f"{MAGENTA}[CMD]{RESET} [{client_ip}] {BOLD}`{command_str}`{RESET}{flag_str}"
        self.logger.info(msg)

    def log_session_end(self, session_id, client_ip, reason="Disconnected"):
        """Records the termination of a connection session."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    "UPDATE sessions SET ended_at = ? WHERE session_id = ?",
                    (now, session_id),
                )
                conn.commit()
            self._write_jsonl("connection_closed", {
                "session_id": session_id,
                "client_ip": client_ip,
                "reason": reason
            })
        msg = f"{CYAN}[-]{RESET} Connection closed: {client_ip} (Session: {session_id[:8]}, Reason: {reason})"
        self.logger.info(msg)

