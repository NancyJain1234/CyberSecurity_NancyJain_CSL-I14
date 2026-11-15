#!/usr/bin/env python3
"""
IoT Telnet Honeypot - Main Server Runner
Captures credential stuffing attacks and botnet execution chains.
"""

import sys
import argparse
import signal
from honeypot.config import DEFAULT_HOST, DEFAULT_PORT, DEVICE_PROFILES, ACTIVE_PROFILE
from honeypot.telnet_server import TelnetHoneypotServer
from honeypot.logger import HoneypotLogger

BANNER = r"""
  ___     _____   _____     _ net   _   _                             _   
 |_ _|___|_   _| |_   _|___| |_ __ | | | | ___  _ __   ___ _   _ _ __ | |_ 
  | |/ _ \ | |     | | / _ \ | '_ \| |_| |/ _ \| '_ \ / _ \ | | | '_ \| __|
  | | (_) || |     | ||  __/ | | | |  _  | (_) | | | |  __/ |_| | |_) | |_ 
 |___\___/ |_|     |_| \___|_|_| |_|_| |_|\___/|_| |_|\___|\__, | .__/ \__|
                                                           |___/|_|        
     Low-Interaction Telnet Honeypot for IoT Botnet Capture & Analysis
"""

def print_banner():
    print(BANNER)
    print("=" * 76)
    print("  Author: Cybersecurity Project | Target: Mirai, Qbot, Hajime, Gafgyt")
    print("=" * 76 + "\n")

def list_profiles():
    print("Available Emulated Device Profiles:")
    print("-" * 50)
    for key, p in DEVICE_PROFILES.items():
        print(f"  * {key:16} : {p['name']}")
    print("-" * 50)

def main():
    parser = argparse.ArgumentParser(
        description="Low-Interaction IoT Telnet Honeypot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"Host address to bind (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=DEFAULT_PORT,
        help=f"Port number to listen on (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--profile",
        default=ACTIVE_PROFILE,
        choices=list(DEVICE_PROFILES.keys()),
        help=f"Emulated device profile (default: {ACTIVE_PROFILE})",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List all supported device profiles and exit",
    )

    args = parser.parse_args()

    if args.list_profiles:
        list_profiles()
        return

    print_banner()

    logger = HoneypotLogger()
    server = TelnetHoneypotServer(
        host=args.host,
        port=args.port,
        profile=args.profile,
        logger=logger,
    )

    def handle_signal(sig, frame):
        print("\n[!] Received shutdown signal...")
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        server.start()
        server.serve_forever()
    except Exception as e:
        print(f"[!] Server terminated: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

