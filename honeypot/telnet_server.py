"""
Telnet Server Protocol Handler for IoT Honeypot.
Handles RFC 854 Telnet negotiations, credential capture,
and interactive IoT shell emulation.
"""

import socket
import threading
import uuid
import time
from honeypot.config import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    SOCKET_BACKLOG,
    SESSION_TIMEOUT,
    DEVICE_PROFILES,
    ACTIVE_PROFILE,
    ALLOW_SHELL_ACCESS,
    ACCEPT_AFTER_ATTEMPTS,
)
from honeypot.signatures import analyze_credential, analyze_command
from honeypot.shell_emulator import ShellEmulator
from honeypot.logger import HoneypotLogger

# Telnet Command Constants (RFC 854)
IAC  = bytes([255])  # Interpret As Command
DONT = bytes([254])
DO   = bytes([253])
WONT = bytes([252])
WILL = bytes([251])
SB   = bytes([250])  # Subnegotiation
SE   = bytes([240])  # End of subnegotiation

# Options
OPT_ECHO = bytes([1])
OPT_SGA  = bytes([3])  # Suppress Go Ahead

class TelnetClientHandler(threading.Thread):
    def __init__(self, client_sock, client_addr, logger, profile_name=ACTIVE_PROFILE):
        super().__init__(daemon=True)
        self.sock = client_sock
        self.client_ip, self.client_port = client_addr
        self.logger = logger
        self.session_id = str(uuid.uuid4())
        self.profile = DEVICE_PROFILES.get(profile_name, DEVICE_PROFILES["busybox_router"])
        self.shell = ShellEmulator(prompt=self.profile["shell_prompt"])
        self.sock.settimeout(SESSION_TIMEOUT)

    def send_raw(self, data):
        """Sends raw bytes to client safely."""
        try:
            if isinstance(data, str):
                data = data.encode("utf-8", errors="replace")
            self.sock.sendall(data)
            return True
        except (socket.error, BrokenPipeError):
            return False

    def read_line(self, echo=True):
        """
        Reads a line of text while parsing Telnet IAC negotiations
        and handling backspaces and line endings.
        """
        line_bytes = bytearray()
        
        while True:
            try:
                b = self.sock.recv(1)
            except (socket.timeout, socket.error):
                return None

            if not b:
                return None

            byte_val = b[0]

            # Handle Telnet IAC (0xFF)
            if byte_val == 255:
                # Read verb
                verb = self.sock.recv(1)
                if not verb:
                    return None
                verb_val = verb[0]
                if verb_val in (251, 252, 253, 254):  # WILL, WONT, DO, DONT
                    opt = self.sock.recv(1)
                    # Respond with DONT/WONT to refuse complex options
                    if verb_val == 253:  # Client requested DO
                        if opt not in (OPT_ECHO, OPT_SGA):
                            self.send_raw(IAC + WONT + opt)
                    elif verb_val == 251:  # Client sent WILL
                        self.send_raw(IAC + DONT + opt)
                elif verb_val == 250:  # SB (subnegotiation)
                    # Consume until SE (240)
                    while True:
                        sub = self.sock.recv(1)
                        if not sub or sub[0] == 240:
                            break
                continue

            # Handle Backspace / Delete
            if byte_val in (8, 127):
                if line_bytes:
                    line_bytes.pop()
                    if echo:
                        self.send_raw(b"\x08 \x08")
                continue

            # Handle Carriage Return / Line Feed
            if byte_val in (10, 13):
                # Peek or consume trailing \n or \0 if \r was received
                if byte_val == 13:
                    try:
                        self.sock.settimeout(0.05)
                        next_b = self.sock.recv(1)
                        if next_b and next_b[0] not in (10, 0):
                            # Put back byte if not \n or \0
                            line_bytes.append(next_b[0])
                    except (socket.timeout, socket.error):
                        pass
                    finally:
                        self.sock.settimeout(SESSION_TIMEOUT)
                
                if echo:
                    self.send_raw(b"\r\n")
                break

            # Normal character
            line_bytes.append(byte_val)
            if echo:
                self.send_raw(b)

        return line_bytes.decode("utf-8", errors="replace").strip()

    def run(self):
        """Main lifecycle of a client connection."""
        self.logger.log_session_start(self.session_id, self.client_ip, self.client_port)

        try:
            # 1. Send Telnet initialization negotiations
            # We will echo and suppress go-ahead
            self.send_raw(IAC + WILL + OPT_ECHO + IAC + WILL + OPT_SGA + IAC + DO + OPT_SGA)
            time.sleep(0.1)

            # 2. Authentication Loop
            attempts = 0
            max_attempts = 3
            authenticated = False

            while attempts < max_attempts and not authenticated:
                attempts += 1
                
                # Send Login Prompt
                if not self.send_raw(self.profile["login_prompt"]):
                    break
                username = self.read_line(echo=True)
                if username is None:
                    break

                # Send Password Prompt
                if not self.send_raw(self.profile["password_prompt"]):
                    break
                # Do not echo password for realism
                password = self.read_line(echo=False)
                if password is None:
                    break

                # Analyze credential against known IoT botnet databases
                cred_analysis = analyze_credential(username, password)
                
                # Determine login outcome
                if ALLOW_SHELL_ACCESS and attempts >= ACCEPT_AFTER_ATTEMPTS:
                    authenticated = True
                    self.logger.log_auth_attempt(
                        self.session_id, self.client_ip, username, password, True, cred_analysis
                    )
                    break
                else:
                    self.logger.log_auth_attempt(
                        self.session_id, self.client_ip, username, password, False, cred_analysis
                    )
                    self.send_raw("\r\n\r\nLogin incorrect\r\n")

            if not authenticated:
                self.send_raw("\r\nToo many login attempts. Connection closed.\r\n")
                self.logger.log_session_end(self.session_id, self.client_ip, "Max auth attempts reached")
                return

            # 3. Authenticated Shell Interaction
            self.send_raw(self.profile["welcome_banner"])

            # Command loop
            while True:
                if not self.send_raw(self.profile["shell_prompt"]):
                    break

                cmd_line = self.read_line(echo=True)
                if cmd_line is None:
                    break

                cmd_line = cmd_line.strip()
                if not cmd_line:
                    continue

                # Analyze command for threat signatures & botnet behaviors
                cmd_analysis = analyze_command(cmd_line)
                self.logger.log_command(self.session_id, self.client_ip, cmd_line, cmd_analysis)

                # Process simulated execution
                output, should_exit = self.shell.execute(cmd_line)
                if output:
                    self.send_raw(output)

                if should_exit:
                    break

            self.logger.log_session_end(self.session_id, self.client_ip, "Session completed normally")

        except Exception as e:
            self.logger.log_session_end(self.session_id, self.client_ip, f"Error: {e}")
        finally:
            try:
                self.sock.close()
            except Exception:
                pass


class TelnetHoneypotServer:
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, profile=ACTIVE_PROFILE, logger=None):
        self.host = host
        self.port = port
        self.profile = profile
        self.logger = logger or HoneypotLogger()
        self.server_sock = None
        self.is_running = False

    def start(self):
        """Binds and starts listening on the Telnet socket."""
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_sock.bind((self.host, self.port))
            self.server_sock.listen(SOCKET_BACKLOG)
            self.is_running = True
        except PermissionError:
            print(f"[!] Permission denied binding to port {self.port}. Try using port >= 1024 (e.g., 2323) or run as administrator/root.")
            raise
        except Exception as e:
            print(f"[!] Failed to bind server: {e}")
            raise

    def serve_forever(self):
        """Accepts incoming connections in an infinite loop."""
        print(f"[*] IoT Telnet Honeypot is active and listening on {self.host}:{self.port}")
        print(f"[*] Profile: {self.profile} (Emulating {DEVICE_PROFILES.get(self.profile, {}).get('name')})")
        print(f"[*] Ready to capture IoT botnet credentials and commands.\n")

        try:
            while self.is_running:
                try:
                    client_sock, client_addr = self.server_sock.accept()
                    handler = TelnetClientHandler(
                        client_sock, client_addr, self.logger, self.profile
                    )
                    handler.start()
                except socket.error:
                    if not self.is_running:
                        break
        except KeyboardInterrupt:
            print("\n[*] Stopping IoT Telnet Honeypot gracefully...")
        finally:
            self.stop()

    def stop(self):
        """Stops the honeypot listener."""
        self.is_running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass

