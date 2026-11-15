"""
Threat Signatures and Heuristics for IoT Botnet Analysis
Identifies known IoT malware families, reconnaissance commands,
and payload delivery mechanisms.
"""

import re

# Known default IoT credentials targeted by Mirai, Hajime, Bashlite, etc.
IOT_DEFAULT_CREDENTIALS = {
    ("root", "xc3511"): "Mirai Default (H.264 DVR)",
    ("root", "vizxv"): "Mirai Default (IP Camera)",
    ("root", "admin"): "Generic IoT Default",
    ("admin", "admin"): "Generic Router / Switch",
    ("root", "888888"): "Dahua DVR / Camera",
    ("root", "default"): "Generic Embedded Device",
    ("root", "123456"): "Xiongmai IP Camera",
    ("default", "oxhlwSG8"): "Mirai (Philips Hue / Embedded)",
    ("root", "54321"): "Generic CCTV DVR",
    ("root", "pass"): "ZTE Router / Embedded",
    ("support", "support"): "Broadcom ADSL Modem",
    ("user", "user"): "Generic IoT User",
    ("admin", "1234"): "Generic IoT Admin",
    ("root", "root"): "Default Embedded Linux",
    ("guest", "guest"): "Generic Guest Account",
}

# Signatures for categorizing captured commands
COMMAND_SIGNATURES = [
    {
        "name": "Mirai Shell Escape",
        "pattern": r"^(enable|system|shell|sh|bash)$",
        "severity": "HIGH",
        "botnet": "Mirai / Gafgyt",
        "description": "Attempts to escape restricted shell or enter privileged mode",
    },
    {
        "name": "Writable Partition Reconnaissance",
        "pattern": r"cat\s+/proc/mounts|/bin/busybox\s+cat\s+/proc/mounts|mount",
        "severity": "MEDIUM",
        "botnet": "Mirai / Bashlite",
        "description": "Scans for writable/executable directories (e.g., /tmp, /var/run, /dev/shm)",
    },
    {
        "name": "CPU Architecture Probing",
        "pattern": r"cat\s+/proc/cpuinfo|uname\s+-m|/bin/busybox\s+cat\s+/proc/cpuinfo",
        "severity": "MEDIUM",
        "botnet": "Multi-architecture Botnet (Mirai/Qbot)",
        "description": "Identifies CPU arch (arm, mips, x86) to select appropriate binary payload",
    },
    {
        "name": "Malware Downloader (HTTP/Wget)",
        "pattern": r"wget\s+https?://[^\s]+|curl\s+-[a-zA-Z]*O\s+https?://[^\s]+",
        "severity": "CRITICAL",
        "botnet": "Generic Dropper",
        "description": "Attempts to download malicious binary via HTTP/HTTPS",
    },
    {
        "name": "Malware Downloader (TFTP/FTP)",
        "pattern": r"tftp\s+-[gGrR]\s+|ftpget\s+",
        "severity": "CRITICAL",
        "botnet": "IoT Dropper",
        "description": "Attempts to download malicious payload using TFTP or FTP",
    },
    {
        "name": "Echo Byte Dropper (Hex/Octal injection)",
        "pattern": r"echo\s+-[neE]\s+[\'\"]?\\x[0-9a-fA-F]{2}",
        "severity": "CRITICAL",
        "botnet": "Hajime / Fileless Dropper",
        "description": "Directly writes binary payload using raw byte escape sequences",
    },
    {
        "name": "Payload Permission Modification",
        "pattern": r"chmod\s+(\+x|777|755)\s+",
        "severity": "HIGH",
        "botnet": "Generic Dropper",
        "description": "Makes downloaded binary executable",
    },
    {
        "name": "Process Killer / Botnet Warfare",
        "pattern": r"killall\s+-9|pkill\s+|kill\s+-9\s+\$\(ps",
        "severity": "HIGH",
        "botnet": "Mirai / Rival Killer",
        "description": "Terminates competing botnets, miners, or telnet/ssh listeners",
    },
    {
        "name": "Trace Cleanup / Anti-Forensics",
        "pattern": r"history\s+-c|rm\s+-rf\s+/var/log|rm\s+-rf\s+.*\.sh",
        "severity": "MEDIUM",
        "botnet": "Anti-Forensics",
        "description": "Cleans bash history, logs, or temporary installer scripts",
    },
    {
        "name": "BusyBox Direct Invocation",
        "pattern": r"/bin/busybox\s+[a-zA-Z]+",
        "severity": "LOW",
        "botnet": "IoT Botnet Standard",
        "description": "Bypasses shell alias traps by directly calling BusyBox multi-call binary",
    },
    {
        "name": "System Reconnaissance",
        "pattern": r"^(uname\s+-a|ifconfig|ip\s+addr|id|whoami|ps|uptime|free(\s+-[mh])?)$",
        "severity": "LOW",
        "botnet": "Reconnaissance",
        "description": "General system enumeration and environment discovery",
    },
]

def analyze_credential(username, password):
    """
    Check if a credential pair matches known IoT botnet target lists.
    """
    pair = (username.strip(), password.strip())
    known_name = IOT_DEFAULT_CREDENTIALS.get(pair)
    if known_name:
        return {
            "is_known_iot": True,
            "signature": known_name,
            "threat_level": "HIGH",
        }
    return {
        "is_known_iot": False,
        "signature": "Custom / Unknown Dictionary Pair",
        "threat_level": "MEDIUM",
    }

def analyze_command(command_str):
    """
    Match a captured command string against IoT botnet signatures.
    Returns a list of matched signature dictionaries.
    """
    matches = []
    clean_cmd = command_str.strip()
    
    for sig in COMMAND_SIGNATURES:
        if re.search(sig["pattern"], clean_cmd, re.IGNORECASE):
            matches.append({
                "name": sig["name"],
                "severity": sig["severity"],
                "botnet": sig["botnet"],
                "description": sig["description"],
            })
            
    # Extract URLs if downloader detected
    urls = re.findall(r"https?://[^\s\'\"\;\`]+", clean_cmd)
    
    return {
        "command": clean_cmd,
        "matches": matches,
        "extracted_urls": urls,
        "highest_severity": max([m["severity"] for m in matches], default="NONE", key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}.get(x, 0)),
    }

