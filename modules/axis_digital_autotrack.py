"""
AXIS Digital Auto Tracking (DigitalAutotracking) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Digital Auto Tracking, appId 6789
Version: 1.0.0 (Lua ACAP — no ELF binary; all 11 Lua files AES-encrypted)
REQEMBDEVVERSION: 1.20 (ancient SDK — runs on cameras no longer receiving firmware updates)
LICENSEPAGE: none

Architecture: rule-engine Lua ACAP; no standalone binary.
All Lua files encrypted (encryption="1" in DigitalAutotracking.xml).
encpwd: proprietary binary blob used by Axis Lua engine for decryption.
Native libraries: digitalAutotracking.so + system.so loaded at runtime by Lua engine.

Key encrypted Lua files:
  main.lua, tracker.lua, stabilizer.lua, regulator.lua, pacemaker.lua,
  paramreader.lua, scenefilter.lua, superobject.lua, middleclass.lua,
  tools.lua, timer.lua

post_install.sh: shttpclient fetches license form over plain HTTP from axis.com.
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-DAT"
LABEL = "DigitalAutotracking: DNS MITM admin XSS, Lua key extraction, lib injection"

ENCRYPTED_LUA_FILES = [
    "middleclass.lua", "tools.lua", "timer.lua", "paramreader.lua",
    "scenefilter.lua", "superobject.lua", "pacemaker.lua", "regulator.lua",
    "tracker.lua", "stabilizer.lua", "main.lua",
]

FINDINGS = [
    {
        "id": "AXIS-DAT-01",
        "severity": "HIGH",
        "title": "Admin XSS via DNS MITM + shttpclient license form inject",
        "detail": (
            "post_install.sh: shttpclient fetches "
            "http://www.axis.com/techsup/compatible_applications/cam_form.php?type=free "
            "over plain HTTP (no TLS, no auth). "
            "Response is injected directly into the admin license form HTML. "
            "Attacker controls DNS for www.axis.com on camera network (MITM or rogue DNS): "
            "serve malicious JavaScript -> stored XSS in admin panel. "
            "Triggers on ACAP install or license form load."
        ),
        "shell_command": "shttpclient -sT 4 -o /dev/stdout http://www.axis.com/techsup/.../cam_form.php?type=free",
        "prerequisite": "DNS MITM on camera network + DAT install trigger",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-DAT-02",
        "severity": "MEDIUM",
        "title": "Lua decryption key (encpwd) extraction via LD_PRELOAD hook",
        "detail": (
            "All 11 Lua source files are AES-encrypted; encpwd is the per-package key blob. "
            "Axis Lua engine decrypts files at load time. "
            "Hook the Lua engine's decryption function via LD_PRELOAD on the Lua interpreter: "
            "intercept plaintext Lua source at decrypt time -> full algorithm recovery. "
            "Same mechanism as VMD3-1 / CL-1 (LD_PRELOAD on Lua runtime)."
        ),
        "prerequisite": "Code execution on camera; LD_PRELOAD accessible on Lua interpreter",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-DAT-03",
        "severity": "MEDIUM",
        "title": "Lua runtime library injection via engine search path",
        "detail": (
            "'<library name=\"digitalAutotracking\"/>' loaded by Axis Lua engine at runtime. "
            "If the Lua engine library search path prepends a writable directory, "
            "substitute digitalAutotracking.so with a malicious shared library "
            "-> code execution in the Lua engine process. "
            "APPID=6789 REQEMBDEVVERSION=1.20: runs on cameras no longer patched."
        ),
        "prerequisite": "Write access to Lua engine library search path directory",
        "status": "UNPATCHED",
        "cve": None,
    },
]
