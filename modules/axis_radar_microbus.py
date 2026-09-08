"""
AXIS Radar Integration for Microbus (radar_microbus) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Radar Integration for Microbus (radar_microbus), appId 414271
Version: 1.0.1  Arch: ARM32 armhf stripped
CGI: administrator /control.cgi (admin-only)

Architecture: daemon subscribes to radar events via libfdipc.so.1 (fast IPC).
Radar scene data from libradar_scene_subscriber.so.0 (dynamically loaded via dlopen).
Protobuf (libprotobuf.so.26) decodes radar event messages.
Config persisted via atomic rename (fsync + rename pattern).
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-RDR"
LABEL = "radar_microbus: libradar_scene_subscriber.so sub, CGI socket race, param injection"

FINDINGS = [
    {
        "id": "AXIS-RDR-01",
        "severity": "HIGH",
        "title": "libradar_scene_subscriber.so.0 runtime substitution via dlopen",
        "detail": (
            "'Failed to load radar scene subscriber library!' — "
            "libradar_scene_subscriber.so.0 loaded via dlopen at runtime. "
            "'Could not load symbol \\'%s\\': %s' and 'dlerror' confirm dynamic loading. "
            "If libradar_scene_subscriber.so.0 path is accessible to another ACAP "
            "and writable before radar_microbus starts: substitute with malicious .so "
            "-> code execution in radar_microbus context."
        ),
        "library": "libradar_scene_subscriber.so.0",
        "prerequisite": "Write access to library path before radar_microbus start",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-RDR-02",
        "severity": "LOW",
        "title": "CGI Unix socket TOCTOU race on cleanup",
        "detail": (
            "'Failed to create directory for CGI socket' / 'Failed to remove old CGI socket'. "
            "CGI communicates via Unix domain socket; path computed dynamically. "
            "Socket directory created/removed on start/shutdown. "
            "Race condition: between socket removal and recreation, "
            "attacker creates socket at same path -> CGI requests redirected to attacker socket."
        ),
        "prerequisite": "Local process on camera racing during radar_microbus restart",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-RDR-03",
        "severity": "MEDIUM",
        "title": "Speed limit parameter injection via admin control.cgi",
        "detail": (
            "radar_microbus configures bus speed limit and detection parameters "
            "via /control.cgi at admin level. "
            "Parameter values stored in config and passed to libprotobuf deserialization. "
            "If speed limit or bus config parameters lack bounds validation: "
            "admin-supplied extreme values -> integer overflow in protobuf field "
            "or out-of-range value in hardware config write."
        ),
        "cgi": "administrator /control.cgi",
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
]
