"""
Low-Interaction IoT Shell Emulator.
Emulates a BusyBox Linux shell common in routers, IP cameras, and DVRs.
Safely responds with convincing mock outputs to entice botnets to reveal
their full attack payload without executing anything on the host.
"""

import re

class ShellEmulator:
    def __init__(self, prompt="# "):
        self.prompt = prompt
        self.current_directory = "/root"

    def execute(self, cmd_line):
        """
        Processes a single command line (or chained commands with ;, &&, ||)
        and returns simulated stdout/stderr string and a boolean indicating if session should exit.
        """
        raw_cmd = cmd_line.strip()
        if not raw_cmd:
            return "", False

        # Check for exit
        if raw_cmd in ("exit", "quit", "logout"):
            return "logout\r\n", True

        # Handle chained commands (e.g., "cd /tmp; wget http://...; chmod 777 ...; ./...")
        # Break by delimiters: ;, &&, ||
        sub_commands = re.split(r";|&&|\|\|", raw_cmd)
        outputs = []

        for sub in sub_commands:
            sub = sub.strip()
            if not sub:
                continue

            # Strip leading "/bin/busybox " or "busybox " if present
            normalized = re.sub(r"^/bin/busybox\s+", "", sub)
            normalized = re.sub(r"^busybox\s+", "", normalized)

            # Route to mock handlers
            out = self._dispatch_command(normalized, original=sub)
            if out:
                outputs.append(out)

        combined_output = "\r\n".join(outputs)
        if combined_output:
            combined_output += "\r\n"
        return combined_output, False

    def _dispatch_command(self, cmd, original):
        """Dispatches normalized single command to specific handlers."""
        # 1. Shell breakout commands typical in Mirai initialization
        if cmd in ("enable", "system", "shell", "sh", "bash"):
            return ""

        # 2. Echo handling (including Mirai echo tests: echo -e, echo -ne, echo '...')
        if cmd.startswith("echo"):
            match = re.search(r"echo\s+(?:-[neE]+\s+)?['\"]?(.*?)['\"]?$", cmd)
            if match:
                text = match.group(1).strip()
                # Check for escaped characters
                return text
            return ""

        # 3. Mount points inspection
        if "cat /proc/mounts" in cmd or cmd == "mount":
            return (
                "rootfs / rootfs rw 0 0\r\n"
                "/dev/root / squashfs ro 0 0\r\n"
                "proc /proc proc rw 0 0\r\n"
                "ramfs /var ramfs rw 0 0\r\n"
                "ramfs /tmp ramfs rw 0 0\r\n"
                "tmpfs /dev/shm tmpfs rw 0 0"
            )

        # 4. CPU architecture inspection
        if "cat /proc/cpuinfo" in cmd:
            return (
                "system type             : Atheros AR9344 rev 2\r\n"
                "machine                 : TP-LINK TL-WDR4300 v1\r\n"
                "processor               : 0\r\n"
                "cpu model               : MIPS 74Kc V4.12\r\n"
                "BogoMIPS                : 278.93\r\n"
                "wait instruction        : yes\r\n"
                "microsecond timers      : yes\r\n"
                "tlb_entries             : 32\r\n"
                "extra interrupt vector  : yes\r\n"
                "hardware watchpoint     : yes, count: 4, address/irw mask: [0x0ffc, 0x0ffc, 0x0ffb, 0x0ffb]\r\n"
                "isa                     : mips1 mips2 mips32r1 mips32r2\r\n"
                "ASEs implemented        : mips16 dsp dsp2"
            )

        # 5. Kernel & System info
        if cmd.startswith("uname"):
            if "-a" in cmd:
                return "Linux router 2.6.36 #1 Sun May 18 10:20:12 CST 2014 mips GNU/Linux"
            elif "-m" in cmd:
                return "mips"
            elif "-r" in cmd:
                return "2.6.36"
            return "Linux"

        # 6. User identity
        if cmd in ("id", "whoami"):
            if cmd == "id":
                return "uid=0(root) gid=0(root) groups=0(root)"
            return "root"

        # 7. Process list (ps)
        if cmd.startswith("ps"):
            return (
                "  PID USER       VSZ STAT COMMAND\r\n"
                "    1 root       864 S    init\r\n"
                "    2 root         0 SW   [kthreadd]\r\n"
                "    3 root         0 SW   [ksoftirqd/0]\r\n"
                "  210 root       712 S    /sbin/hotplug2 --override --persistent\r\n"
                "  340 root       728 S    /sbin/syslogd -C16\r\n"
                "  355 root       892 S    /usr/sbin/telnetd -p 23\r\n"
                "  412 root      1148 S    /usr/sbin/httpd\r\n"
                "  512 root       980 S    /bin/sh"
            )

        # 8. Directory navigation
        if cmd.startswith("cd"):
            parts = cmd.split(maxsplit=1)
            target = parts[1] if len(parts) > 1 else "/root"
            self.current_directory = target
            return ""

        # 9. Directory listing (ls)
        if cmd.startswith("ls"):
            if "/tmp" in cmd or self.current_directory == "/tmp":
                return "hosts  resolv.conf  run"
            return "bin  dev  etc  home  lib  mnt  proc  root  sbin  sys  tmp  usr  var"

        # 10. File downloaders (wget, curl, tftp)
        if cmd.startswith("wget"):
            # Extract target filename or url
            match = re.search(r"https?://([^/\s]+)/(\S+)", cmd)
            host = match.group(1) if match else "remote_host"
            filename = match.group(2) if match else "payload.bin"
            return (
                f"Connecting to {host} ({host}:80)\r\n"
                f"saving to '{filename}'\r\n"
                f"'{filename}' saved"
            )

        if cmd.startswith("curl"):
            return ""

        if cmd.startswith("tftp"):
            return "tftp: transfer complete"

        # 11. Permission modification (chmod)
        if cmd.startswith("chmod"):
            return ""

        # 12. Execution of local binaries (./something, /tmp/something)
        if cmd.startswith("./") or cmd.startswith("/tmp/") or cmd.startswith("/var/"):
            return ""

        # 13. Killing processes (kill, killall, pkill)
        if cmd.startswith("kill") or cmd.startswith("pkill"):
            return ""

        # 14. Removing files (rm)
        if cmd.startswith("rm"):
            return ""

        # 15. Network configuration
        if cmd.startswith("ifconfig") or cmd.startswith("ip"):
            return (
                "br-lan    Link encap:Ethernet  HWaddr 14:CC:20:AA:BB:CC\r\n"
                "          inet addr:192.168.1.1  Bcast:192.168.1.255  Mask:255.255.255.0\r\n"
                "          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\r\n"
                "eth0      Link encap:Ethernet  HWaddr 14:CC:20:AA:BB:CD\r\n"
                "          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1"
            )

        # 16. Help / BusyBox builtins
        if cmd in ("help", "?"):
            return (
                "Built-in commands:\r\n"
                "------------------\r\n"
                "  . : [ [[ alias bg break cd chdir continue eval exec exit export\r\n"
                "  false fg getopts hash help jobs kill let local pwd read readonly\r\n"
                "  return set shift test times trap true type ulimit umask unalias\r\n"
                "  unset wait"
            )

        # 17. Default fallback: command not found (typical BusyBox ash error)
        cmd_name = cmd.split()[0] if cmd.split() else cmd
        return f"sh: {cmd_name}: not found"

