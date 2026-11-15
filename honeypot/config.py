"""
Configuration settings for the IoT Telnet Honeypot.
"""

import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
REPORTS_DIR = BASE_DIR / "reports"

# Ensure directories exist
LOG_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Network settings
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 2323  # Non-privileged port by default (use 23 for standard telnet if running as root/admin)
SOCKET_BACKLOG = 50
SESSION_TIMEOUT = 120  # Seconds before inactive session is dropped
MAX_BUFFER_SIZE = 4096

# Emulated Device Profiles
DEVICE_PROFILES = {
    "busybox_router": {
        "name": "Generic BusyBox Linux Router",
        "login_prompt": "\r\nUser Access Verification\r\n\r\nUsername: ",
        "password_prompt": "Password: ",
        "welcome_banner": (
            "\r\n"
            "BusyBox v1.16.1 (2013-05-18 09:34:11 CST) built-in shell (ash)\r\n"
            "Enter 'help' for a list of built-in commands.\r\n\r\n"
        ),
        "shell_prompt": "# ",
    },
    "ip_camera": {
        "name": "Xiongmai / HiSilicon IP Camera",
        "login_prompt": "\r\n(none) login: ",
        "password_prompt": "Password: ",
        "welcome_banner": (
            "\r\n"
            "Welcome to HiSilicon Linux.\r\n"
            "BusyBox v1.20.2 (2015-11-04 15:02:11 CST) built-in shell (ash)\r\n"
            "Enter 'help' for a list of built-in commands.\r\n\r\n"
        ),
        "shell_prompt": "# ",
    },
    "dahua_dvr": {
        "name": "Dahua DVR Surveillance System",
        "login_prompt": "\r\n\r\nDVR login: ",
        "password_prompt": "Password: ",
        "welcome_banner": (
            "\r\n"
            "DAHUA Embedded Linux System v2.6.38\r\n"
            "Terminal shell initialized.\r\n\r\n"
        ),
        "shell_prompt": "~ # ",
    },
}

ACTIVE_PROFILE = "busybox_router"

# Honeypot interactive behavior
# When True, accepts any login attempt so we can record subsequent shell commands.
# If False, will reject all logins (pure credential collector).
ALLOW_SHELL_ACCESS = True

# Number of failed login attempts before allowing access (simulates brute-force crack)
ACCEPT_AFTER_ATTEMPTS = 1

# Database and Log file paths
DB_FILE = LOG_DIR / "honeypot.db"
JSONL_FILE = LOG_DIR / "honeypot_events.jsonl"
TEXT_LOG_FILE = LOG_DIR / "honeypot.log"

