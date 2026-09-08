"""
AXIS Cross Line Detection (CrossLineDetection) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Cross Line Detection, appId 3051
Version: 1.1.5  Arch: ARTPEC-5 Lua runtime
APPTYPE=lua  LICENSEPAGE=axis  STARTMODE=once

Lua-only ACAP (same Lua runtime as VMD3 3.2.0, Digital Auto Tracking 1.0.0).
Lua files:
  dbgutils.lua (plaintext) - scene history traversal, merge/split tracking
  lineTouching.lua (encrypted, encryption="1" in XML)
CrossLineDetection.xml: geometry.segment trigger, line_touching function, direction=both.
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-CL"
LABEL = "CrossLine: LD_PRELOAD Lua decrypt, geometry float injection, scene history API"

FINDINGS = [
    {
        "id": "AXIS-CL-01",
        "severity": "MEDIUM",
        "title": "LD_PRELOAD on Lua interpreter: lineTouching.lua plaintext recovery",
        "detail": (
            "Lua runtime decrypts lineTouching.lua using encpwd blob at load time. "
            "LD_PRELOAD hook on luaL_loadbuffer or lua_pcall "
            "intercepts plaintext Lua source before execution. "
            "Identical to VMD3-01 and DAT-02. "
            "Recovers cross-line detection logic and any embedded parameters/credentials."
        ),
        "file": "lineTouching.lua (encrypted, encpwd blob)",
        "prerequisite": "Shell access on camera (admin) or LD_PRELOAD accessible on Lua interpreter",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-CL-02",
        "severity": "LOW",
        "title": "CrossLineDetection.xml geometry float injection: detection disabled via NaN/Inf",
        "detail": (
            "CrossLine segment defined by two <point x='-0.5' y='0.0'/> elements in XML config. "
            "Set x or y to NaN or Inf: geometry.segment constructor receives invalid float "
            "-> rule engine exception -> CrossLine silently stops detecting crossings. "
            "Admin writes config; poisoned coords disable detection without visible error."
        ),
        "config_file": "CrossLineDetection.xml",
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-CL-03",
        "severity": "LOW",
        "title": "Scene history API exposed via dbgutils.lua — full per-frame scene data access",
        "detail": (
            "dbgutils.lua (plaintext, always loaded) calls: "
            "sceneHistory.getActiveSceneObjects, getSceneObjectMergers, "
            "getSceneObjectSplits, getDeletedSceneObjectIds. "
            "If an operator can inject custom Lua (via cog.* namespace extension "
            "or by replacing dbgutils.lua in the ACAP package): "
            "full per-frame scene data accessible: object IDs, positions, velocities, "
            "merge/split events."
        ),
        "file": "dbgutils.lua (plaintext)",
        "prerequisite": "Operator ability to modify Lua scripts or XML config",
        "status": "UNPATCHED",
        "cve": None,
    },
]
