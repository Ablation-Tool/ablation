"""
cisco_ftd_re.py — Cisco Firepower Threat Defense (FTD) firmware RE module

Target: FTD 6.x/7.x qcow2 images
  /media/cowboy/research/cisco-firmware/firepower/
  firepower6-FTD-6.2.0-362.qcow2
  firepower6-FTD-6.3.0-83.qcow2
  firepower6-FTD-6.6.0.qcow2
  firepower6-FTD-6.7.0-65.qcow2

Attack surface vs ASA:
  - Snort2/Snort3 IPS engine (C, inline packet inspection, rule parser)
  - FMC management channel (HTTPS star/leaf, auth token handling)
  - FTD REST API (port 443, ftd_api daemon, Java)
  - lina variant (VPN/NAT, differs from ASA lina by FTD sensor API hooks)
  - SFDataCorrelator / SFMbservice (Cisco proprietary event correlation)
  - sfDBd (Sourcefire database daemon, SQLite-based policy store)

RE methodology (synthesized from chainsaw corpus):
  PMA quadrant 1 (basic static) first: strings + imports before disassembly
  RE4B Ch5.4.4: suspicious strings (no RFC/library match) = backdoor candidates
  RE4B Ch5.6: magic constant detection (MD5/SHA/AES/CRC init values)
  RE4B App9.2: Shannon entropy per 4K block (>7.5 = encrypted, 6-7.5 = compressed)
  IDA Pro Book Ch12: FLAIR sigs for stripped binaries (stripped ELF recovery)
  Fuzzing Ch6: Snort rule parser = block-based mutation target

Usage:
  python3 main.py --ftd-re --ftd-image /media/cowboy/research/cisco-firmware/firepower/firepower6-FTD-6.7.0-65.qcow2
  python3 main.py --ftd-re --ftd-rootfs /mnt/ftd-root
  python3 main.py --ftd-binary /mnt/ftd-root/usr/bin/snort
"""

import os
import re
import math
import struct
import subprocess
import tempfile
import shutil
from pathlib import Path


# ---------------------------------------------------------------------------
# Key FTD binary targets (PMA Ch1: capability fingerprint by binary name)
# ---------------------------------------------------------------------------
FTD_BINARIES = {
    "snort":             "Snort IPS engine — rule parser, packet inspection, alert generation",
    "lina":              "FTD lina variant — VPN/NAT/firewall (modified ASA lina)",
    "sfmbservice":       "SFMbservice — Cisco proprietary message broker / sensor relay",
    "SFDataCorrelator":  "SFDataCorrelator — event correlation, SFDB writes",
    "sfDBd":             "sfDBd — Sourcefire SQLite policy/event DB daemon",
    "sftunnel":          "sftunnel — FMC<->FTD encrypted tunnel (SSL/cert auth)",
    "pm":                "Process manager — FTD init/daemon supervisor",
    "lc_3d":             "Intrusion policy engine",
    "snort3":            "Snort3 (7.x images)",
    "ftd_api":           "FTD REST API daemon",
}

# Common locations of FTD binaries in rootfs
FTD_SEARCH_PATHS = [
    "usr/bin", "usr/sbin", "usr/local/bin", "sbin", "bin",
    "ngfw/usr/bin", "ngfw/usr/sbin",
    "opt/cisco/csp/applications",
]

# ---------------------------------------------------------------------------
# Magic constants (RE4B Ch5.6) — identify crypto primitives without disassembly
# ---------------------------------------------------------------------------
MAGIC_CONSTANTS = {
    # MD5 init vector (all four words)
    b"\x01\x23\x45\x67": "MD5_A_init (LE: 0x67452301)",
    b"\x89\xAB\xCD\xEF": "MD5_B_init (LE: 0xEFCDAB89)",
    b"\xFE\xDC\xBA\x98": "MD5_C_init (LE: 0x98BADCFE)",
    b"\x76\x54\x32\x10": "MD5_D_init (LE: 0x10325476)",
    # SHA-1 / SHA-256
    b"\x67\xE6\x09\x6A": "SHA256_H0 (0x6A09E667 LE)",
    b"\x85\xAE\x67\xBB": "SHA256_H1 (0xBB67AE85 LE)",
    # CRC32 polynomial (Ethernet/PKZIP)
    b"\x20\x83\xB8\xED": "CRC32_poly (0xEDB88320 LE)",
    # Snort-specific: GID 1 = standard detection engine
    b"\x01\x00\x00\x00": "Snort_GID_1",
    # FMC tunnel magic (from strings in sftunnel)
    b"SFTU": "sftunnel_magic_prefix",
    b"SFDB": "Sourcefire_DB_magic",
    b"SFEV": "SF_event_blob_magic",
    # Cisco PIX/ASA DTLS variant magic
    b"\xDE\xAD\xBE\xEF": "generic_debug_magic",
    # snortd config magic
    b"SNORT": "Snort_config_marker",
}

# String patterns indicating attack surface (RE4B Ch5.4.4: no RFC/library match = suspicious)
SUSPICIOUS_PATTERNS = [
    # Backdoor/debug URL candidates: alphanumeric string that doesn't match any known URI path
    (r"/[A-Za-z]{6,20}[0-9]{4,12}$", "suspicious_url_no_match"),
    # Hardcoded credentials
    (r"(?i)(password|passwd|secret|key|token|credential)\s*[:=]\s*\S{4,}", "credential_literal"),
    # Undocumented REST endpoints
    (r"/api/v\d+/[a-z_]+/[a-z_]+/debug", "debug_api_endpoint"),
    (r"/api/v\d+/[a-z_]+/[a-z_]+/test", "test_api_endpoint"),
    # FMC channel magic strings
    (r"X-Auth-Token", "fmc_auth_token_header"),
    (r"FMC-UUID", "fmc_uuid_header"),
    (r"X-FTD-", "ftd_proprietary_header"),
    # Snort rule debug/assertion strings (RE4B Ch5.5: assert conditions reveal var names)
    (r"ParseRule.*failed", "snort_rule_parse_assert"),
    (r"pcre_compile.*error", "snort_pcre_compile_error"),
    (r"content.*too long", "snort_content_length_assert"),
    # sfDBd / SQLite injection surface
    (r"SELECT.*FROM.*policy", "sfdb_policy_query"),
    (r"INSERT.*INTO.*events", "sfdb_event_insert"),
    # sftunnel protocol
    (r"tunnel.*auth.*fail", "sftunnel_auth_failure"),
    (r"ssl.*handshake.*error", "ssl_handshake_error"),
    # Embedded passwords (Type 0/7 patterns in FTD configs)
    (r"\$1\$[A-Za-z0-9./]{8}\$[A-Za-z0-9./]{22}", "md5crypt_hash"),
    (r"\$6\$[A-Za-z0-9./]{8}\$", "sha512crypt_hash"),
]

# SUID/SGID known-dangerous binaries on FTD
SUID_DANGEROUS = {
    "python", "python3", "perl", "ruby", "php", "bash", "sh",
    "nmap", "tcpdump", "vim", "vi", "nano", "less", "more",
    "awk", "gawk", "sed", "find", "wget", "curl", "nc", "netcat",
    "cp", "mv", "chmod", "chown", "dd", "tar", "rsync",
    "sudo", "su",
}

# ---------------------------------------------------------------------------
# Entropy analysis (RE4B App9.2)
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte. Calibrated to Linux `ent` output."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    h = 0.0
    for f in freq:
        if f > 0:
            p = f / n
            h -= p * math.log2(p)
    return h


def entropy_classify(h: float) -> str:
    if h > 7.5:
        return "ENCRYPTED"
    elif h > 6.0:
        return "COMPRESSED"
    elif h > 3.5:
        return "PLAINTEXT_CODE"
    else:
        return "SPARSE_DATA"


def analyze_entropy_sections(filepath: str, block_size: int = 4096) -> list:
    """
    Per-block entropy scan (RE4B App9.2 methodology).
    Returns high-entropy regions with file offset for further analysis.
    """
    results = []
    try:
        with open(filepath, "rb") as f:
            offset = 0
            while True:
                block = f.read(block_size)
                if not block:
                    break
                h = shannon_entropy(block)
                cls = entropy_classify(h)
                if cls in ("ENCRYPTED", "COMPRESSED"):
                    results.append({
                        "offset": offset,
                        "size": len(block),
                        "entropy": round(h, 3),
                        "class": cls,
                    })
                offset += len(block)
    except (IOError, PermissionError):
        pass
    return results


# ---------------------------------------------------------------------------
# Strings analysis (PMA Ch1 + RE4B Ch5.4)
# ---------------------------------------------------------------------------

def extract_strings(filepath: str, min_len: int = 6) -> list:
    """
    Extract printable ASCII strings from binary (like `strings -n 6`).
    Returns list of (offset, string) tuples.
    """
    results = []
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except (IOError, PermissionError):
        return results

    pattern = re.compile(rb"[ -~]{" + str(min_len).encode() + rb",}")
    for m in pattern.finditer(data):
        results.append((m.start(), m.group().decode("ascii", errors="replace")))
    return results


def classify_strings(strings: list) -> dict:
    """
    Classify extracted strings into security-relevant categories.
    Uses suspicious pattern matching (RE4B Ch5.4.4).
    """
    findings = {
        "credentials": [],
        "urls_and_paths": [],
        "suspicious": [],
        "crypto_refs": [],
        "protocol_headers": [],
        "debug_and_assert": [],
        "version_strings": [],
    }

    crypto_keywords = {"openssl", "EVP_", "RSA_", "EC_", "BN_", "SSL_", "TLS_", "SHA", "MD5", "AES", "HMAC"}
    cred_keywords = re.compile(r"(?i)(password|passwd|secret|api.?key|token|credential|auth)")
    version_re = re.compile(r"\d+\.\d+\.\d+[\.\d-]*")
    url_re = re.compile(r"(/[a-zA-Z0-9_/.-]{4,}|https?://\S+)")

    for offset, s in strings:
        sl = s.lower()

        if cred_keywords.search(s):
            findings["credentials"].append((offset, s))
        elif any(k.lower() in sl for k in crypto_keywords):
            findings["crypto_refs"].append((offset, s))
        elif s.startswith("X-") or ":" in s[:30] and len(s) < 60:
            findings["protocol_headers"].append((offset, s))
        elif url_re.search(s):
            findings["urls_and_paths"].append((offset, s))
        elif version_re.search(s) and len(s) < 50:
            findings["version_strings"].append((offset, s))
        elif any(kw in sl for kw in ["assert", "failed", "error", "debug", "TODO", "FIXME", "HACK"]):
            findings["debug_and_assert"].append((offset, s))

        for pattern, label in SUSPICIOUS_PATTERNS:
            if re.search(pattern, s):
                findings["suspicious"].append((offset, s, label))
                break

    return findings


# ---------------------------------------------------------------------------
# Magic constant scan (RE4B Ch5.6)
# ---------------------------------------------------------------------------

def scan_magic_constants(filepath: str) -> list:
    """Scan binary for known crypto/protocol magic constants."""
    hits = []
    try:
        data = open(filepath, "rb").read()
    except (IOError, PermissionError):
        return hits

    for magic, label in MAGIC_CONSTANTS.items():
        offset = 0
        while True:
            pos = data.find(magic, offset)
            if pos == -1:
                break
            hits.append({"offset": pos, "magic": magic.hex(), "label": label})
            offset = pos + 1

    return hits


# ---------------------------------------------------------------------------
# Import analysis (PMA Ch1: capability fingerprinting from linked functions)
# ---------------------------------------------------------------------------

IMPORT_CAPABILITIES = {
    # Networking
    "socket": "RAW_SOCKET", "connect": "NETWORK_CLIENT", "bind": "NETWORK_SERVER",
    "sendto": "UDP_SEND", "recvfrom": "UDP_RECV", "listen": "TCP_SERVER",
    "SSL_connect": "TLS_CLIENT", "SSL_accept": "TLS_SERVER",
    "ssl_new": "SSL_CONTEXT", "SSL_CTX_new": "TLS_CONTEXT_CREATE",
    # Crypto
    "EVP_EncryptInit": "AES_ENCRYPT", "EVP_DecryptInit": "AES_DECRYPT",
    "RSA_sign": "RSA_SIGN", "RSA_verify": "RSA_VERIFY",
    "RAND_bytes": "CRYPTO_RNG", "SHA256_Init": "SHA256",
    "MD5_Init": "MD5_HASH", "HMAC": "HMAC_AUTH",
    "EC_KEY_new": "EC_CRYPTO", "ECDSA_sign": "ECDSA_SIGN",
    # Database
    "sqlite3_exec": "SQLITE_EXEC", "sqlite3_prepare": "SQLITE_QUERY",
    "sqlite3_open": "SQLITE_OPEN", "mysql_query": "MYSQL_QUERY",
    # Privilege / access
    "setuid": "SETUID", "setgid": "SETGID", "execve": "EXEC_PROCESS",
    "system": "SHELL_EXEC", "popen": "POPEN_EXEC", "fork": "FORK_PROCESS",
    "chroot": "CHROOT", "ptrace": "PTRACE",
    # File / IPC
    "mmap": "MEMORY_MAP", "dlopen": "DYNAMIC_LOAD", "dlsym": "DYNAMIC_SYMBOL",
    "shm_open": "SHARED_MEMORY", "inotify_init": "INOTIFY",
    # Snort-specific
    "pcap_open_live": "PACKET_CAPTURE", "pcap_dispatch": "PACKET_DISPATCH",
    "nfq_open": "NETFILTER_QUEUE", "ip_queue": "IP_QUEUE",
}


def analyze_imports(filepath: str) -> dict:
    """
    nm -D for dynamic symbols, objdump for PLT stubs.
    Maps imported functions to capability categories (PMA Ch1 methodology).
    """
    result = {"symbols": [], "capabilities": set(), "raw": ""}

    try:
        r = subprocess.run(
            ["nm", "-D", "--defined-extern", filepath],
            capture_output=True, timeout=30
        )
        r2 = subprocess.run(
            ["nm", "-D", filepath],
            capture_output=True, timeout=30
        )
        combined = (r.stdout + r2.stdout).decode("utf-8", errors="replace")
        result["raw"] = combined[:5000]

        for line in combined.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                sym = parts[-1]
                result["symbols"].append(sym)
                for kw, cap in IMPORT_CAPABILITIES.items():
                    if kw.lower() in sym.lower():
                        result["capabilities"].add(cap)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Also try readelf -s
    try:
        r = subprocess.run(
            ["readelf", "-s", "--wide", filepath],
            capture_output=True, timeout=30
        )
        out = r.stdout.decode("utf-8", errors="replace")
        result["raw"] += "\n" + out[:3000]
        for line in out.splitlines():
            if "FUNC" in line and "GLOBAL" in line:
                parts = line.split()
                if parts:
                    sym = parts[-1]
                    for kw, cap in IMPORT_CAPABILITIES.items():
                        if kw.lower() in sym.lower():
                            result["capabilities"].add(cap)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    result["capabilities"] = sorted(result["capabilities"])
    return result


# ---------------------------------------------------------------------------
# SUID / writable surface enumeration (Privilege Escalation Ch10-12)
# ---------------------------------------------------------------------------

def enumerate_privilege_surface(rootfs: str) -> dict:
    """
    SUID binaries, world-writable dirs, cron jobs.
    Applies the PrivEsc methodology: enumerate every writable/elevated path.
    """
    result = {
        "suid_binaries": [],
        "sgid_binaries": [],
        "world_writable_dirs": [],
        "world_writable_files": [],
        "cron_jobs": [],
        "sudoers": [],
        "dangerous_suid": [],
    }

    # SUID/SGID binaries
    try:
        r = subprocess.run(
            ["find", rootfs, "-perm", "-4000", "-type", "f"],
            capture_output=True, timeout=60
        )
        for path in r.stdout.decode().splitlines():
            rel = path.replace(rootfs, "")
            result["suid_binaries"].append(rel)
            if any(d in rel for d in SUID_DANGEROUS):
                result["dangerous_suid"].append(rel)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    try:
        r = subprocess.run(
            ["find", rootfs, "-perm", "-2000", "-type", "f"],
            capture_output=True, timeout=60
        )
        for path in r.stdout.decode().splitlines():
            result["sgid_binaries"].append(path.replace(rootfs, ""))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # World-writable directories
    try:
        r = subprocess.run(
            ["find", rootfs, "-perm", "-0002", "-type", "d"],
            capture_output=True, timeout=60
        )
        for path in r.stdout.decode().splitlines():
            result["world_writable_dirs"].append(path.replace(rootfs, ""))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # World-writable files (sensitive)
    for sensitive in ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/crontab"]:
        full = rootfs + sensitive
        if os.path.exists(full):
            mode = oct(os.stat(full).st_mode)
            if "2" in mode[-3:] or "6" in mode[-3:] or "7" in mode[-3:]:
                result["world_writable_files"].append(f"{sensitive} ({mode})")

    # Cron jobs (PrivEsc Ch12: cron PATH hijack, wildcard injection)
    for cron_dir in ["/etc/cron.d", "/etc/cron.daily", "/var/spool/cron"]:
        full = rootfs + cron_dir
        if os.path.isdir(full):
            for f in os.listdir(full):
                fp = os.path.join(full, f)
                try:
                    content = open(fp).read()
                    result["cron_jobs"].append({
                        "file": cron_dir + "/" + f,
                        "content": content[:300],
                    })
                except (IOError, PermissionError):
                    pass

    # Sudoers
    sudoers = rootfs + "/etc/sudoers"
    if os.path.exists(sudoers):
        try:
            result["sudoers"] = open(sudoers).read()[:500]
        except (IOError, PermissionError):
            pass

    return result


# ---------------------------------------------------------------------------
# qcow2 extraction (nbd mount → partition table → rootfs)
# ---------------------------------------------------------------------------

def mount_qcow2(qcow2_path: str, mountpoint: str) -> tuple:
    """
    Mount qcow2 via qemu-nbd.
    Returns (nbd_device, partition_list) or (None, []) on failure.

    Requires: qemu-nbd binary, nbd kernel module loaded, root.
    """
    import glob

    # Find free nbd device
    nbd_dev = None
    for i in range(16):
        dev = f"/dev/nbd{i}"
        if os.path.exists(dev):
            # Check if already connected
            r = subprocess.run(
                ["blockdev", "--getsize64", dev],
                capture_output=True, timeout=5
            )
            if r.returncode == 0 and r.stdout.strip() == b"0":
                nbd_dev = dev
                break

    if not nbd_dev:
        nbd_dev = "/dev/nbd0"

    try:
        # Connect qcow2 to nbd device
        subprocess.run(
            ["qemu-nbd", "--connect", nbd_dev, qcow2_path],
            timeout=30, check=True
        )
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
        return None, []

    import time
    time.sleep(2)  # let kernel enumerate partitions

    # List partitions
    parts = glob.glob(nbd_dev + "p*")
    if not parts:
        # Try reading partition table directly
        r = subprocess.run(
            ["fdisk", "-l", nbd_dev],
            capture_output=True, timeout=10
        )
        parts = []
        for line in r.stdout.decode().splitlines():
            if nbd_dev in line and "Linux" in line:
                p = line.split()[0]
                parts.append(p)

    return nbd_dev, sorted(parts)


def find_rootfs_partition(partitions: list) -> str:
    """Identify the root filesystem partition (largest ext4 partition or /ngfw root)."""
    best = None
    best_size = 0
    for part in partitions:
        try:
            r = subprocess.run(
                ["blkid", "-s", "TYPE", "-o", "value", part],
                capture_output=True, timeout=5
            )
            fstype = r.stdout.decode().strip()
            if fstype in ("ext4", "ext3", "xfs", "squashfs"):
                size = subprocess.run(
                    ["blockdev", "--getsize64", part],
                    capture_output=True, timeout=5
                )
                sz = int(size.stdout.strip())
                if sz > best_size:
                    best_size = sz
                    best = part
        except (subprocess.TimeoutExpired, ValueError):
            pass
    return best


def unmount_qcow2(nbd_dev: str, mountpoint: str):
    """Clean up nbd mount."""
    try:
        subprocess.run(["umount", mountpoint], timeout=10)
    except Exception:
        pass
    try:
        subprocess.run(["qemu-nbd", "--disconnect", nbd_dev], timeout=10)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Snort rule parser attack surface (Fuzzing Ch6: block-based mutation targets)
# ---------------------------------------------------------------------------

SNORT_RULE_FUNCTIONS = [
    # Snort 2.x rule parser entry points (targets for SPIKE/Peach block-based fuzzing)
    "ParseRuleOptions",
    "AddRuleOption",
    "ParseIpOptionList",
    "ParsePortList",
    "ProcessFlowOptions",
    "IpsOptionFuncLookupAdd",
    "RegisterRuleOption",
    # Content matching (Boyer-Moore, PCRE)
    "BoyerMooreSearch",
    "BoyerMooreCaseInsensitiveSearch",
    "pcre_exec",
    "pcre_compile",
    "SnortPcre",
    # Snort 3.x
    "RuleParser::parse",
    "IpsOption::create",
    "ContentModule::begin",
    # Buffer handling in rules
    "SnortConfig::add_detection_filter",
    "PatternMatchData::parse",
    # Alert generation (post-match)
    "GenerateSnortAlert",
    "CallLogFuncs",
]

def find_snort_parser_surface(snort_binary: str) -> list:
    """
    Use nm/strings to identify Snort rule parser functions.
    These are the block-based fuzzing entry points (Fuzzing Ch6).
    """
    hits = []
    strings_list = [s for _, s in extract_strings(snort_binary, min_len=8)]
    all_strings = "\n".join(strings_list)

    for func in SNORT_RULE_FUNCTIONS:
        if func in all_strings:
            hits.append(func)
        # Also check mangled C++ names
        if f"_{func}" in all_strings or f"Z{len(func)}{func}" in all_strings:
            hits.append(func + " (via mangling)")

    # Check nm output
    try:
        r = subprocess.run(
            ["nm", "-C", snort_binary],
            capture_output=True, timeout=30
        )
        nm_out = r.stdout.decode("utf-8", errors="replace")
        for func in SNORT_RULE_FUNCTIONS:
            if func in nm_out:
                hits.append(func + " (nm confirmed)")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return list(set(hits))


# ---------------------------------------------------------------------------
# Hardcoded credential hunting
# ---------------------------------------------------------------------------

CRED_CONFIG_PATHS = [
    "etc/cisco/cisco.conf",
    "etc/snort/snort.conf",
    "ngfw/etc/sf/ims.conf",
    "ngfw/etc/sf/database.conf",
    "etc/sf/database.conf",
    "etc/sf/ims.conf",
    "opt/cisco/platform/etc/platform.cfg",
    "etc/cisco/sfdb.conf",
    "etc/sf/SFDBConnectionConfig.cfg",
    "etc/resolv.conf",
    "etc/passwd",
    "etc/shadow",
    "home",
    "root",
]

CRED_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*(\S+)"),
    re.compile(r"(?i)(secret|key|token|apikey)\s*[=:]\s*(\S+)"),
    re.compile(r"(?i)(username|user)\s*[=:]\s*(\S+)"),
    re.compile(r"\$1\$[A-Za-z0-9./]{8}\$[A-Za-z0-9./]{22}"),  # MD5crypt
    re.compile(r"\$6\$[A-Za-z0-9./]{16,}\$[A-Za-z0-9./]{86}"),  # SHA512crypt
    re.compile(r"(?i)cisco\s+type\s+[057]\s+\S+"),  # Cisco IOS type 0/5/7
    re.compile(r"[A-Za-z0-9+/]{32,}={0,2}"),  # base64 blobs (possible creds/keys)
]


def hunt_credentials(rootfs: str) -> list:
    """
    Walk config paths and extract credential-shaped strings.
    Returns list of (file, line, match) hits.
    """
    findings = []

    for cfg_rel in CRED_CONFIG_PATHS:
        cfg_full = os.path.join(rootfs, cfg_rel)
        if not os.path.exists(cfg_full):
            continue

        if os.path.isdir(cfg_full):
            # Walk directory
            for dirpath, _, files in os.walk(cfg_full):
                for fname in files:
                    fp = os.path.join(dirpath, fname)
                    findings.extend(_scan_file_for_creds(fp, rootfs))
        else:
            findings.extend(_scan_file_for_creds(cfg_full, rootfs))

    return findings


def _scan_file_for_creds(filepath: str, rootfs: str) -> list:
    results = []
    try:
        with open(filepath, "r", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                for pattern in CRED_PATTERNS:
                    m = pattern.search(line)
                    if m:
                        results.append({
                            "file": filepath.replace(rootfs, ""),
                            "line": lineno,
                            "match": line.strip()[:200],
                        })
                        break
    except (IOError, PermissionError):
        pass
    return results


# ---------------------------------------------------------------------------
# Binary inventory: find FTD binaries in rootfs
# ---------------------------------------------------------------------------

def find_ftd_binaries(rootfs: str) -> dict:
    """Locate key FTD binaries in the extracted root filesystem."""
    found = {}
    for binary_name, description in FTD_BINARIES.items():
        for search_dir in FTD_SEARCH_PATHS:
            full = os.path.join(rootfs, search_dir, binary_name)
            if os.path.isfile(full):
                size = os.path.getsize(full)
                found[binary_name] = {
                    "path": full.replace(rootfs, ""),
                    "abs_path": full,
                    "size": size,
                    "description": description,
                }
                break

        if binary_name not in found:
            # Recursive find
            try:
                r = subprocess.run(
                    ["find", rootfs, "-name", binary_name, "-type", "f"],
                    capture_output=True, timeout=30
                )
                hits = r.stdout.decode().splitlines()
                if hits:
                    full = hits[0]
                    size = os.path.getsize(full)
                    found[binary_name] = {
                        "path": full.replace(rootfs, ""),
                        "abs_path": full,
                        "size": size,
                        "description": description,
                    }
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

    return found


# ---------------------------------------------------------------------------
# Per-binary deep analysis
# ---------------------------------------------------------------------------

def analyze_binary(binary_info: dict) -> dict:
    """
    Full static analysis of one FTD binary.
    PMA quadrant 1 (basic static) methodology: strings → imports → entropy.
    """
    path = binary_info["abs_path"]
    result = {
        "binary": binary_info["path"],
        "size": binary_info["size"],
        "strings_summary": {},
        "magic_constants": [],
        "entropy_regions": [],
        "imports": {},
        "snort_parser_surface": [],
    }

    # 1. Strings analysis (PMA Ch1 + RE4B Ch5.4)
    strings = extract_strings(path)
    result["strings_summary"] = classify_strings(strings)
    result["string_count"] = len(strings)

    # 2. Magic constant scan (RE4B Ch5.6)
    result["magic_constants"] = scan_magic_constants(path)[:20]  # top 20

    # 3. Shannon entropy scan (RE4B App9.2)
    result["entropy_regions"] = analyze_entropy_sections(path)[:10]  # top 10

    # 4. Import analysis (PMA Ch1)
    result["imports"] = analyze_imports(path)

    # 5. Snort parser surface (only for snort binary)
    if "snort" in binary_info["path"].lower():
        result["snort_parser_surface"] = find_snort_parser_surface(path)

    # 6. .eh_frame function boundaries (Learning Linux Binary Analysis Ch.2)
    result["eh_frame_functions"] = extract_eh_frame_functions(path)
    result["function_count_eh_frame"] = len(result["eh_frame_functions"])

    # 7. PLT call inventory (Practical Binary Analysis Ch.5)
    plt_calls = scan_plt_calls(path)
    result["plt_call_count"] = len(plt_calls)
    result["plt_security_calls"] = [
        (off, sym) for off, sym in plt_calls
        if any(k in sym for k in ("system", "execv", "popen", "dlopen", "fork",
                                   "SSL_", "EVP_", "BN_", "RAND_"))
    ]

    # 8. Vtable scan for C++ class hierarchy (Snort3, sfmbservice)
    if any(x in binary_info["path"].lower() for x in ("snort3", "snort", "sfmb")):
        vtables = scan_vtables(path)
        result["vtable_count"] = len(vtables)
        result["vtable_samples"] = [
            {"offset": hex(off), "ptr_count": len(ptrs), "ptrs": [hex(p) for p in ptrs[:5]]}
            for off, ptrs in vtables[:10]
        ]

    # 9. GOT hook detection (LLBA Ch6)
    result["got_high_value_targets"] = detect_got_hooks(path)

    # 10. Entry point anomaly (LLBA Ch6)
    result["entry_point"] = detect_entry_point_anomaly(path)

    # 11. XOR obfuscation scan (Mastering RE Ch8)
    result["xor_candidates"] = scan_xor_obfuscation(path)

    return result


# ---------------------------------------------------------------------------
# Main RE class
# ---------------------------------------------------------------------------

class CiscoFTDRE:
    """
    Cisco FTD firmware RE module.

    Usage:
      # From qcow2 image:
      re = CiscoFTDRE(image_path="/media/cowboy/.../firepower6-FTD-6.7.0-65.qcow2")

      # From already-extracted rootfs:
      re = CiscoFTDRE(rootfs_path="/mnt/ftd-root")

      # Single binary:
      re = CiscoFTDRE(binary_path="/mnt/ftd-root/usr/bin/snort")

      findings = re.run()
    """

    def __init__(self, image_path=None, rootfs_path=None, binary_path=None):
        self.image_path = image_path
        self.rootfs_path = rootfs_path
        self.binary_path = binary_path
        self._tmp_mountpoint = None
        self._nbd_dev = None

    def run(self) -> list:
        findings = []

        if self.binary_path:
            findings += self._analyze_single_binary(self.binary_path)
            return findings

        rootfs = self.rootfs_path
        mounted = False

        if not rootfs and self.image_path:
            rootfs, mounted = self._extract_qcow2()

        if not rootfs:
            findings.append({
                "id": "FTD-ERR",
                "severity": "INFO",
                "title": "No rootfs available",
                "detail": "Provide --ftd-image (qcow2) or --ftd-rootfs (extracted dir) or --ftd-binary",
                "evidence": {},
            })
            return findings

        try:
            findings += self._run_full_analysis(rootfs)
        finally:
            if mounted:
                self._cleanup_mount()

        return findings

    def _extract_qcow2(self):
        """Mount qcow2 via qemu-nbd and return rootfs mountpoint."""
        mp = tempfile.mkdtemp(prefix="ftd-rootfs-")
        self._tmp_mountpoint = mp

        print(f"[*] Mounting qcow2: {self.image_path}")
        nbd_dev, partitions = mount_qcow2(self.image_path, mp)
        if not nbd_dev:
            print("[-] qemu-nbd mount failed. Try: sudo modprobe nbd max_part=8")
            shutil.rmtree(mp, ignore_errors=True)
            return None, False

        self._nbd_dev = nbd_dev
        print(f"[+] nbd device: {nbd_dev}, partitions: {partitions}")

        root_part = find_rootfs_partition(partitions)
        if not root_part:
            print("[-] Could not identify root partition")
            unmount_qcow2(nbd_dev, mp)
            shutil.rmtree(mp, ignore_errors=True)
            return None, False

        print(f"[+] Root partition: {root_part}")
        try:
            subprocess.run(
                ["mount", "-o", "ro", root_part, mp],
                timeout=15, check=True
            )
            return mp, True
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            print(f"[-] mount failed: {e}. Trying squashfs...")
            try:
                subprocess.run(
                    ["mount", "-t", "squashfs", "-o", "ro", root_part, mp],
                    timeout=15, check=True
                )
                return mp, True
            except Exception:
                unmount_qcow2(nbd_dev, mp)
                shutil.rmtree(mp, ignore_errors=True)
                return None, False

    def _cleanup_mount(self):
        if self._tmp_mountpoint:
            unmount_qcow2(self._nbd_dev or "", self._tmp_mountpoint)
            shutil.rmtree(self._tmp_mountpoint, ignore_errors=True)

    def _run_full_analysis(self, rootfs: str) -> list:
        findings = []
        print(f"\n[*] FTD rootfs: {rootfs}")

        # Phase 1: Binary inventory
        print("[*] Phase 1: Binary inventory")
        binaries = find_ftd_binaries(rootfs)
        print(f"[+] Found {len(binaries)} FTD binaries: {list(binaries.keys())}")

        findings.append({
            "id": "FTD-INV",
            "severity": "INFO",
            "title": f"FTD binary inventory: {len(binaries)} binaries found",
            "detail": "\n".join(f"  {k}: {v['path']} ({v['size']//1024}KB)" for k, v in binaries.items()),
            "evidence": {b: v["path"] for b, v in binaries.items()},
        })

        # Phase 2: Per-binary analysis (PMA quadrant 1)
        print("[*] Phase 2: Per-binary static analysis")
        for name, binfo in binaries.items():
            print(f"  [*] Analyzing {name}...")
            analysis = analyze_binary(binfo)

            # Extract findings from analysis
            creds = analysis["strings_summary"].get("credentials", [])
            suspicious = analysis["strings_summary"].get("suspicious", [])
            encrypted_regions = [r for r in analysis["entropy_regions"] if r["class"] == "ENCRYPTED"]

            if creds:
                findings.append({
                    "id": f"FTD-CRED-{name.upper()}",
                    "severity": "HIGH",
                    "title": f"{name}: {len(creds)} credential-shaped strings",
                    "detail": f"Binary {binfo['path']} contains strings matching credential patterns",
                    "evidence": {
                        "samples": [s for _, s in creds[:5]],
                        "count": len(creds),
                    },
                })

            if suspicious:
                findings.append({
                    "id": f"FTD-SUSP-{name.upper()}",
                    "severity": "MEDIUM",
                    "title": f"{name}: {len(suspicious)} suspicious strings (backdoor candidates)",
                    "detail": f"Strings in {binfo['path']} match no known RFC/library/error convention (RE4B Ch5.4.4 methodology)",
                    "evidence": {
                        "samples": [(s, label) for _, s, label in suspicious[:5]],
                    },
                })

            if encrypted_regions:
                findings.append({
                    "id": f"FTD-ENC-{name.upper()}",
                    "severity": "MEDIUM",
                    "title": f"{name}: {len(encrypted_regions)} high-entropy regions (possible embedded crypto/configs)",
                    "detail": f"Shannon entropy >7.5 bits/byte at {len(encrypted_regions)} regions in {binfo['path']} (RE4B App9.2)",
                    "evidence": {
                        "regions": encrypted_regions[:3],
                    },
                })

            if analysis["snort_parser_surface"]:
                findings.append({
                    "id": "FTD-SNORT-PARSER",
                    "severity": "HIGH",
                    "title": f"Snort: {len(analysis['snort_parser_surface'])} rule parser entry points identified",
                    "detail": (
                        "Block-based fuzzing targets (SPIKE/Peach methodology): "
                        "mutate rule options while preserving 'alert tcp any any -> any any (' prefix. "
                        "Each ParseRuleOptions call is an unchecked input boundary."
                    ),
                    "evidence": {
                        "functions": analysis["snort_parser_surface"],
                        "fuzzer_template": 'alert tcp any any -> any any (content:"|FUZZ|"; sid:1; rev:1;)',
                    },
                })

            if analysis["magic_constants"]:
                crypto_hits = [h for h in analysis["magic_constants"] if any(
                    x in h["label"] for x in ["MD5", "SHA", "AES", "CRC32"])]
                if crypto_hits:
                    findings.append({
                        "id": f"FTD-CRYPTO-{name.upper()}",
                        "severity": "INFO",
                        "title": f"{name}: {len(crypto_hits)} crypto primitive magic constants detected",
                        "detail": f"RE4B Ch5.6: magic constant scan confirms cryptographic primitives in {binfo['path']}",
                        "evidence": {"hits": crypto_hits[:5]},
                    })

            # GOT high-value targets (LLBA Ch6)
            if analysis.get("got_high_value_targets"):
                findings.append({
                    "id": f"FTD-GOT-{name.upper()}",
                    "severity": "HIGH",
                    "title": f"{name}: {len(analysis['got_high_value_targets'])} high-value GOT targets",
                    "detail": "GOT entries for system/execve/popen/dlopen — redirect via heap/stack overflow for code execution (LLBA Ch6)",
                    "evidence": {"targets": analysis["got_high_value_targets"]},
                })

            # Entry point anomaly (LLBA Ch6)
            ep = analysis.get("entry_point", {})
            if ep.get("anomaly"):
                findings.append({
                    "id": f"FTD-EP-ANOMALY-{name.upper()}",
                    "severity": "HIGH",
                    "title": f"{name}: entry point outside .text — possible packing or injection",
                    "detail": ep.get("note", ""),
                    "evidence": ep,
                })

            # XOR obfuscation (Mastering RE Ch8)
            if analysis.get("xor_candidates"):
                findings.append({
                    "id": f"FTD-XOR-{name.upper()}",
                    "severity": "MEDIUM",
                    "title": f"{name}: {len(analysis['xor_candidates'])} XOR obfuscation patterns",
                    "detail": "Loop-based XOR with non-zero/non-0xff key — possible string or code obfuscation (Mastering RE Ch8)",
                    "evidence": {"candidates": analysis["xor_candidates"]},
                })

        # Phase 3: Privilege escalation surface (PrivEsc Ch10-12)
        print("[*] Phase 3: Privilege escalation surface")
        privesc = enumerate_privilege_surface(rootfs)

        if privesc["dangerous_suid"]:
            findings.append({
                "id": "FTD-SUID-DANGER",
                "severity": "CRITICAL",
                "title": f"Dangerous SUID binaries on FTD: {len(privesc['dangerous_suid'])}",
                "detail": "SUID binaries that allow shell escape or arbitrary execution (PrivEsc methodology)",
                "evidence": {"paths": privesc["dangerous_suid"]},
            })

        if privesc["suid_binaries"]:
            findings.append({
                "id": "FTD-SUID-ALL",
                "severity": "HIGH",
                "title": f"SUID binary inventory: {len(privesc['suid_binaries'])} binaries",
                "detail": "Complete SUID/SGID surface on FTD rootfs. Each is a potential LPE vector.",
                "evidence": {
                    "suid": privesc["suid_binaries"][:20],
                    "sgid": privesc["sgid_binaries"][:10],
                },
            })

        if privesc["world_writable_dirs"]:
            findings.append({
                "id": "FTD-WRITABLE-DIRS",
                "severity": "MEDIUM",
                "title": f"{len(privesc['world_writable_dirs'])} world-writable directories",
                "detail": "World-writable directories can be used for cron PATH hijack or library injection",
                "evidence": {"dirs": privesc["world_writable_dirs"][:20]},
            })

        if privesc["cron_jobs"]:
            findings.append({
                "id": "FTD-CRON",
                "severity": "HIGH",
                "title": f"FTD cron jobs: {len(privesc['cron_jobs'])} scheduled tasks",
                "detail": "Cron jobs on FTD may be exploitable via PATH hijack or wildcard injection (PrivEsc Ch12)",
                "evidence": {"jobs": privesc["cron_jobs"][:5]},
            })

        # Phase 4: Hardcoded credential hunting
        print("[*] Phase 4: Credential hunting in config files")
        cred_hits = hunt_credentials(rootfs)
        if cred_hits:
            findings.append({
                "id": "FTD-HARDCRED",
                "severity": "CRITICAL",
                "title": f"{len(cred_hits)} hardcoded credential candidates in FTD config files",
                "detail": "Credential-shaped strings in FTD config paths. May include default passwords, API tokens, DB creds.",
                "evidence": {"samples": cred_hits[:10]},
            })

        # Phase 5: DLL hijack surface (Learning Linux Binary Analysis Ch.4)
        print("[*] Phase 5: DLL hijack surface check")
        dll_surface = check_dll_hijack_surface(rootfs)
        critical_dll = [h for h in dll_surface if h["severity"] == "CRITICAL"]
        high_dll = [h for h in dll_surface if h["severity"] == "HIGH"]
        if critical_dll:
            findings.append({
                "id": "FTD-DLLHIJACK-CRIT",
                "severity": "CRITICAL",
                "title": f"{len(critical_dll)} world-writable FTD library directories",
                "detail": "World-writable /usr/local/sf/lib/ paths allow .so injection into snort/lina/sfmbservice at next daemon restart.",
                "evidence": {"paths": critical_dll},
            })
        if high_dll:
            findings.append({
                "id": "FTD-DLLHIJACK-HIGH",
                "severity": "HIGH",
                "title": f"{len(high_dll)} group-writable FTD library directories",
                "detail": "Group-writable lib dirs viable for DLL hijack if attacker has FTD group membership.",
                "evidence": {"paths": high_dll},
            })

        # Phase 6: FTD runtime state collection (Cisco forensics pattern)
        print("[*] Phase 6: FTD runtime state collection")
        state = collect_ftd_runtime_state(rootfs)
        present = {k: v for k, v in state.items() if v.get("type") != "absent"}
        findings.append({
            "id": "FTD-STATE",
            "severity": "INFO",
            "title": f"FTD runtime state: {len(present)}/{len(state)} key paths present",
            "detail": "Cisco forensics collection: config dirs, cron, shadow, sudoers, init scripts.",
            "evidence": {k: v for k, v in present.items()},
        })

        return findings

    def _analyze_single_binary(self, path: str) -> list:
        """Analyze a single binary file."""
        if not os.path.isfile(path):
            return [{
                "id": "FTD-ERR",
                "severity": "INFO",
                "title": f"Binary not found: {path}",
                "detail": "",
                "evidence": {},
            }]

        binfo = {
            "path": path,
            "abs_path": path,
            "size": os.path.getsize(path),
            "description": "User-specified binary",
        }

        findings = []
        analysis = analyze_binary(binfo)

        print(f"[+] {path}: {binfo['size']//1024}KB")
        print(f"[+] Strings: {analysis['string_count']} total")
        print(f"[+] Capabilities: {analysis['imports'].get('capabilities', [])}")
        print(f"[+] Encrypted regions: {len(analysis['entropy_regions'])}")
        print(f"[+] Magic constants: {len(analysis['magic_constants'])}")

        findings.append({
            "id": "FTD-BIN",
            "severity": "INFO",
            "title": f"Binary analysis: {os.path.basename(path)}",
            "detail": f"Size: {binfo['size']} bytes | Strings: {analysis['string_count']} | "
                      f"Caps: {', '.join(analysis['imports'].get('capabilities', ['unknown']))}",
            "evidence": {
                "version_strings": [s for _, s in analysis["strings_summary"].get("version_strings", [])[:5]],
                "credential_strings": [s for _, s in analysis["strings_summary"].get("credentials", [])[:5]],
                "suspicious": [(s, l) for _, s, l in analysis["strings_summary"].get("suspicious", [])[:5]],
                "snort_parser": analysis.get("snort_parser_surface", []),
                "entropy_regions": analysis["entropy_regions"][:5],
                "capabilities": analysis["imports"].get("capabilities", []),
            },
        })

        return findings


# ---------------------------------------------------------------------------
# Snort rule fuzzer (block-based, Fuzzing Ch6 SPIKE methodology)
# ---------------------------------------------------------------------------

def generate_snort_fuzz_corpus(output_dir: str, count: int = 500) -> list:
    """
    Generate a Snort rule fuzzing corpus using block-based mutation (Fuzzing Ch6).

    Strategy:
    - Preserve mandatory structure: 'alert tcp any any -> any any (...)'
    - Mutate rule body: content, pcre, flags, sid, rev fields
    - Use malformed-value arsenal: buffer overflows, integer boundaries, format strings,
      NUL bytes, oversized content patterns

    Returns list of generated rule file paths.
    """
    import random
    os.makedirs(output_dir, exist_ok=True)
    generated = []

    # Malformed value arsenal (Fuzzing Ch6: Generator.pm MalformedValues pattern)
    OVERFLOW_STRS = ["A" * n for n in [16, 64, 256, 1024, 4096, 65535]]
    INT_BOUNDARIES = ["-1", "0", "1", "254", "255", "256", "65534", "65535", "65536",
                      "2147483647", "2147483648", "4294967295"]
    FORMAT_STRINGS = ["%s", "%x", "%n", "%s%s%s%s%s%s%s%s", "%.1000d"]
    NULL_VARIANTS = ["\x00", "\x00" * 4, "\xff\xff\xff\xff"]

    # Content mutations: binary patterns that violate Snort parser assumptions
    content_mutations = (
        OVERFLOW_STRS
        + [f"|{i:02x}|" for i in range(256)]  # hex byte literals
        + FORMAT_STRINGS
        + ["!\"content\"", "!\"\"", "!\"" + "A" * 256 + "\""]
        + ["content:\"\"; depth:0;", "content:\"\"; offset:-1;"]
    )

    # pcre mutations
    pcre_mutations = [
        "/(.*){10000}/",  # catastrophic backtracking
        "/(?P<name>.*){1000}/",
        "/[a-zA-Z0-9]{65536}/",
        "/" + "A" * 1024 + "/",
        "/\\1\\1\\1\\1\\1\\1\\1\\1/",  # backreference loop
        "/(a+)+/",  # evil regex
    ]

    # sid/rev boundary values
    sid_mutations = INT_BOUNDARIES + ["-1", "4294967296", "0"]

    rules = []

    for i in range(count):
        action = random.choice(["alert", "log", "pass", "drop", "reject"])
        proto = random.choice(["tcp", "udp", "icmp", "ip"])
        src = random.choice(["any", "192.168.0.0/16", "!any", "$HOME_NET"])
        dst = random.choice(["any", "!any", "$EXTERNAL_NET"])
        sport = random.choice(["any", "80", "443", "0", "65535", "any:1024"])
        dport = random.choice(["any", "80", "443", "0:1023"])

        # Randomly pick mutation vector
        vector = random.randint(0, 5)
        if vector == 0:
            # content mutation
            content = random.choice(content_mutations)
            body = f'content:"{content}"; sid:{i+1}; rev:1;'
        elif vector == 1:
            # pcre mutation
            pcre = random.choice(pcre_mutations)
            body = f'pcre:"{pcre}"; sid:{i+1}; rev:1;'
        elif vector == 2:
            # sid boundary
            sid = random.choice(sid_mutations)
            body = f'content:"test"; sid:{sid}; rev:1;'
        elif vector == 3:
            # nested options
            depth = random.choice(INT_BOUNDARIES)
            offset = random.choice(INT_BOUNDARIES)
            body = f'content:"test"; depth:{depth}; offset:{offset}; sid:{i+1}; rev:1;'
        elif vector == 4:
            # multiple content with bad logic
            body = (f'content:"{random.choice(OVERFLOW_STRS[:3])}"; '
                    f'content:"{random.choice(FORMAT_STRINGS)}"; '
                    f'sid:{i+1}; rev:1;')
        else:
            # empty / malformed
            body = f'sid:{i+1}; rev:1;'

        rule = f'{action} {proto} {src} {sport} -> {dst} {dport} ({body})\n'
        rules.append(rule)

    # Write in batches of 50 rules per file
    batch_size = 50
    for batch_i in range(0, len(rules), batch_size):
        batch = rules[batch_i:batch_i + batch_size]
        fname = os.path.join(output_dir, f"fuzz_{batch_i//batch_size:04d}.rules")
        with open(fname, "w") as f:
            f.writelines(batch)
        generated.append(fname)

    return generated


# ---------------------------------------------------------------------------
# ELF deep analysis — function boundaries + PLT inventory + vtable scan
# (Learning Linux Binary Analysis Ch.2, Practical Binary Analysis Ch.5/Ch.8)
# ---------------------------------------------------------------------------

def _parse_section_addr_size(readelf_S_output: str, section_name: str):
    """
    Parse (addr, size) for a named ELF section from 'readelf -S --wide' output.

    Handles both bracket formats:
      [12] .text ... → parts idx: [12]=0, name=1, type=2, addr=3, offset=4, size=5
      [ 1] .text ... → parts idx: [=0, 1]=1, name=2, type=3, addr=4, offset=5, size=6
    Robust: find section name token, use relative offset from there.
    """
    target = f" {section_name} "
    for line in readelf_S_output.splitlines():
        if target not in line:
            continue
        parts = line.split()
        # Find index of section name in parts
        try:
            ni = next(i for i, p in enumerate(parts) if p == section_name)
        except StopIteration:
            continue
        # addr = ni+1, offset = ni+2, size = ni+3 (all hex strings)
        try:
            addr = int(parts[ni + 1], 16)
            size = int(parts[ni + 3], 16)
            return addr, size
        except (IndexError, ValueError):
            pass
    return 0, 0


def extract_eh_frame_functions(filepath: str) -> list:
    """
    Extract function boundaries from .eh_frame FDE entries.

    Even stripped binaries retain .eh_frame for C++ exception unwinding.
    Each FDE = one function. readelf --debug-dump=frames gives start+length.
    Returns list of (start_addr, length, end_addr) tuples.

    Learning Linux Binary Analysis Ch.2: "exception frames survive stripping"
    """
    results = []
    try:
        r = subprocess.run(
            ["readelf", "--debug-dump=frames", filepath],
            capture_output=True, text=True, timeout=60
        )
        # Parse FDE blocks: "FDE ... pc=0xADDR..0xADDR"
        for m in re.finditer(r'FDE.*?pc=(0x[0-9a-f]+)\.\.(0x[0-9a-f]+)', r.stdout):
            start = int(m.group(1), 16)
            end = int(m.group(2), 16)
            results.append((start, end - start, end))
    except Exception:
        pass
    return results


def scan_plt_calls(filepath: str) -> list:
    """
    Find all PLT indirect calls via 'ff 25 xx xx xx xx' (jmp *[rip+disp]) pattern.

    x86-64 PLT stub: ff 25 <32-bit-rip-relative-offset> -> GOT entry.
    Combined with readelf -r this maps each PLT slot to its symbol.
    Returns list of (offset, symbol_name) pairs.

    Practical Binary Analysis Ch.5: PLT/GOT inventory without disassembler.
    """
    results = []
    # Get relocations for symbol name mapping
    sym_map = {}
    try:
        r = subprocess.run(["readelf", "-r", filepath], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[2] in ("R_X86_64_JUMP_SLO", "R_X86_64_JUMP_SLOT"):
                try:
                    addr = int(parts[0], 16)
                    sym = parts[4] if len(parts) > 4 else parts[3]
                    sym_map[addr] = sym
                except ValueError:
                    pass
    except Exception:
        pass

    # Scan binary for PLT stub pattern
    try:
        data = open(filepath, "rb").read()
        pattern = b"\xff\x25"
        offset = 0
        while True:
            idx = data.find(pattern, offset)
            if idx == -1:
                break
            results.append((idx, sym_map.get(idx, "unknown")))
            offset = idx + 1
    except Exception:
        pass
    return results


def scan_vtables(filepath: str, ptr_size: int = 8) -> list:
    """
    Heuristic vtable scan for C++ binaries (Snort3 is C++ throughout).

    Vtable = array of code pointers at 8-byte aligned addresses in .rodata/.data.rel.ro.
    Pattern: N consecutive 8-byte values all pointing into .text segment.
    Minimum vtable size: 2 pointers (skip empty vtables).

    Practical Binary Analysis Ch.8: vtable arrays for class hierarchy recovery.
    Returns list of (offset, [ptr1, ptr2, ...]) for each candidate vtable.
    """
    results = []
    try:
        data = open(filepath, "rb").read()
        r = subprocess.run(["readelf", "-S", "--wide", filepath],
                           capture_output=True, text=True)
        text_start, text_size = _parse_section_addr_size(r.stdout, ".text")
        text_end = text_start + text_size

        if not (text_start and text_end):
            return results

        # Scan for aligned arrays of pointers into .text
        step = ptr_size
        i = 0
        while i < len(data) - ptr_size * 2:
            if i % step != 0:
                i += 1
                continue
            ptrs = []
            j = i
            while j + ptr_size <= len(data):
                val = struct.unpack_from("<Q", data, j)[0]
                if text_start <= val < text_end:
                    ptrs.append(val)
                    j += ptr_size
                else:
                    break
            if len(ptrs) >= 3:
                results.append((i, ptrs))
                i = j
            else:
                i += step
    except Exception:
        pass
    return results


def check_dll_hijack_surface(rootfs: str) -> list:
    """
    Check /usr/local/sf/lib/ and other FTD library paths for write permissions.

    If any FTD-user-writable lib dir exists, DLL hijack via .so injection is viable.
    Library loading order on FTD: LD_LIBRARY_PATH -> /usr/local/sf/lib/ -> system lib paths.

    Learning Linux Binary Analysis Ch.4: shared lib loading and hijack surface.
    """
    findings = []
    lib_paths = [
        "usr/local/sf/lib",
        "usr/local/sf/lib/plugins",
        "ngfw/usr/local/sf/lib",
        "opt/cisco/csp/lib",
    ]
    for rel in lib_paths:
        full = os.path.join(rootfs, rel)
        if not os.path.exists(full):
            continue
        stat = os.stat(full)
        mode = stat.st_mode
        world_write = bool(mode & 0o002)
        group_write = bool(mode & 0o020)
        findings.append({
            "path": full,
            "world_writable": world_write,
            "group_writable": group_write,
            "mode_octal": oct(mode),
            "severity": "CRITICAL" if world_write else ("HIGH" if group_write else "INFO"),
        })
    return findings


def detect_got_hooks(filepath: str) -> list:
    """
    Check GOT entries for hook indicators.

    GOT[0]=dynamic segment, GOT[1]=link_map, GOT[2]=_dl_runtime_resolve.
    GOT[3+] must point into PLT stubs or resolved .so text ranges.
    An entry pointing outside these ranges = GOT overwrite / rootkit hook.

    LLBA Ch6: PLT/GOT hook detection methodology.
    Returns list of suspicious GOT entries.
    """
    suspicious = []
    try:
        r = subprocess.run(["readelf", "-S", "--wide", filepath],
                           capture_output=True, text=True)
        plt_start, plt_sz = _parse_section_addr_size(r.stdout, ".plt")
        plt_end = plt_start + plt_sz
        text_start, text_sz = _parse_section_addr_size(r.stdout, ".text")
        text_end = text_start + text_sz

        # Get GOT entries via readelf -r
        r2 = subprocess.run(["readelf", "-r", filepath], capture_output=True, text=True)
        for line in r2.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and "JUMP_SLOT" in parts[2]:
                try:
                    got_addr = int(parts[0], 16)
                    # In a non-running binary we can't read the runtime value,
                    # but we can flag entries where the symbol is a known dangerous function
                    sym = parts[4] if len(parts) > 4 else ""
                    if sym in ("system", "execve", "execvp", "popen", "dlopen"):
                        suspicious.append({
                            "got_addr": hex(got_addr),
                            "symbol": sym,
                            "note": "High-value GOT target — redirect here for code execution",
                        })
                except (ValueError, IndexError):
                    pass
    except Exception:
        pass
    return suspicious


def detect_entry_point_anomaly(filepath: str) -> dict:
    """
    Check if binary entry point is within .text segment.

    Entry not in .text = packed, injected, or shellcode-headed binary.
    LLBA Ch6: entry point anomaly = indicator of compromise or packing.
    """
    result = {"anomaly": False, "entry": None, "text_range": None, "note": ""}
    try:
        r = subprocess.run(["readelf", "-h", filepath], capture_output=True, text=True)
        entry = None
        for line in r.stdout.splitlines():
            if "Entry point address" in line:
                entry = int(line.split()[-1], 16)
                break
        if entry is None:
            return result
        result["entry"] = hex(entry)

        r2 = subprocess.run(["readelf", "-S", "--wide", filepath],
                            capture_output=True, text=True)
        ts, tsz = _parse_section_addr_size(r2.stdout, ".text")
        if ts and tsz:
            te = ts + tsz
            result["text_range"] = f"{hex(ts)}-{hex(te)}"
            if not (ts <= entry < te):
                result["anomaly"] = True
                result["note"] = f"Entry {hex(entry)} outside .text ({hex(ts)}-{hex(te)}) — packed/injected?"
    except Exception:
        pass
    return result


def scan_xor_obfuscation(filepath: str) -> list:
    """
    Heuristic scan for XOR-based string/code obfuscation.

    Pattern: XOR with non-zero single-byte key in a loop over a buffer.
    Mastering RE Ch8: loop-based XOR/arithmetic decryption identification.
    Byte pattern: 30 xx (xor [mem], reg8) or 34 xx (xor al, imm8) repeated
    with incrementing address = decryption loop signature.

    Returns list of (offset, key_candidate) for each candidate loop.
    """
    results = []
    try:
        data = open(filepath, "rb").read()
        # XOR immediate patterns: 34 xx (xor al,imm), 80 f1 xx (xor cl,imm)
        # Simple scan: find sequences of 'xor' opcodes with non-zero non-0xff operands
        i = 0
        while i < len(data) - 2:
            b = data[i]
            # xor reg8, imm8 patterns
            if b == 0x34 and data[i+1] not in (0x00, 0xff):
                results.append({"offset": hex(i), "pattern": "xor al,imm8",
                                 "key": hex(data[i+1])})
            elif b == 0x80 and i+2 < len(data) and (data[i+1] & 0xf8) == 0xf0:
                key = data[i+2]
                if key not in (0x00, 0xff):
                    results.append({"offset": hex(i), "pattern": "xor r/m8,imm8",
                                    "key": hex(key)})
            i += 1
        # Deduplicate by key — keep first 5 unique keys
        seen = set()
        deduped = []
        for r in results:
            if r["key"] not in seen:
                seen.add(r["key"])
                deduped.append(r)
            if len(deduped) >= 5:
                break
        return deduped
    except Exception:
        return []


def collect_ftd_runtime_state(rootfs: str) -> dict:
    """
    Collect FTD configuration and state from key filesystem paths.

    Cisco Router and Switch Forensics: volatile data collection pattern.
    FTD-specific paths confirmed via Cisco documentation and book context.
    """
    FTD_STATE_PATHS = {
        "detection_rules": "etc/sf/detection.rules",
        "snort_config": "etc/sf/snort.conf",
        "ims_config": "etc/sf/ims.conf",
        "ngfw_config_dir": "ngfw/etc/sf",
        "var_sf": "var/sf",
        "local_sf_bin": "usr/local/sf/bin",
        "local_sf_lib": "usr/local/sf/lib",
        "etc_cron": "etc/cron.d",
        "shadow": "etc/shadow",
        "passwd": "etc/passwd",
        "sudoers_d": "etc/sudoers.d",
        "init_d": "etc/init.d",
        "systemd": "etc/systemd/system",
    }
    state = {}
    for key, rel in FTD_STATE_PATHS.items():
        full = os.path.join(rootfs, rel)
        if os.path.isdir(full):
            state[key] = {"type": "dir", "path": full,
                          "contents": os.listdir(full)[:50]}
        elif os.path.isfile(full):
            try:
                content = open(full, "rb").read(4096)
                state[key] = {"type": "file", "path": full,
                              "size": os.path.getsize(full),
                              "preview": content.decode(errors="replace")[:512]}
            except Exception:
                state[key] = {"type": "file", "path": full, "error": "unreadable"}
        else:
            state[key] = {"type": "absent"}
    return state
