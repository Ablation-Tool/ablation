"""
AXIS Video Motion Detection 3 (vmd3) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Video Motion Detection 3 (VMD3), appId 46396
Version: 3.2.0  Arch: ARTPEC-5 (Lua runtime)
LICENSEPAGE: none  APPTYPE: lua

Same encrypted-Lua pattern as Digital Auto Tracking.
Files: combined.lua (AES-encrypted), encpwd (per-package key blob), VMD3.xml (config).
VMD3.xml: geometry-based zone config with polygon definitions (float x/y, range -1.0 to 1.0).
ARTPEC-5 cameras may not receive firmware updates -> extended attack surface on unpatched hardware.
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-VMD3"
LABEL = "VMD3: LD_PRELOAD Lua decrypt, polygon float injection"

FINDINGS = [
    {
        "id": "AXIS-VMD3-01",
        "severity": "MEDIUM",
        "title": "Encrypted Lua source recovery via LD_PRELOAD hook on ARTPEC-5 Lua interpreter",
        "detail": (
            "combined.lua is AES-encrypted; encpwd is the per-package key blob. "
            "ARTPEC-5 firmware Lua rule engine decrypts combined.lua at load time. "
            "LD_PRELOAD hook on luaL_loadbuffer or lua_pcall on the Lua interpreter: "
            "intercept plaintext Lua source before execution. "
            "Identical to DAT-02 and CL-01. "
            "Recovers VMD3 detection logic and any embedded parameters."
        ),
        "prerequisite": "Shell access on ARTPEC-5 camera (admin) or LD_PRELOAD accessible on Lua interpreter",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-VMD3-02",
        "severity": "LOW",
        "title": "VMD3.xml polygon float injection via NaN/Inf values",
        "detail": (
            "VMD3.xml: detection zone polygons defined as float x/y coordinate pairs "
            "(knownTypeName='geometry.polygon'). "
            "Zone polygon coordinates: range -1.0 to 1.0 normalized to frame dimensions. "
            "Set x or y to NaN or Inf in VMD3.xml config -> "
            "firmware geometry library receives invalid float -> "
            "floating-point exception or geometry crash -> VMD3 detection disabled. "
            "Admin can write VMD3.xml; poisoned coordinates silently break detection."
        ),
        "config_file": "VMD3.xml",
        "prerequisite": "Admin-level camera auth to write VMD3.xml",
        "status": "UNPATCHED",
        "cve": None,
    },
]
