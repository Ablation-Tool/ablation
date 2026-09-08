"""
AXIS Loitering Guard (loiteringguard) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Loitering Guard (loiteringguard), appId 46775
Version: 2.3.8  Arch: ARM32 armhf stripped
CGI: administrator /control.cgi (admin-only)
LICENSEPAGE: none (no liblicensekey.so)

Same libscene.so/libgeometry.so/libfixmath.so stack as VMD 4.4.4.
Multi-camera support via SocketCameraContainer.
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-LG"
LABEL = "loiteringguard: SocketCameraContainer SSRF, libscene.so substitution"

FINDINGS = [
    {
        "id": "AXIS-LG-01",
        "severity": "MEDIUM",
        "title": "SocketCameraContainer SSRF via admin control.cgi",
        "detail": (
            "SocketCameraContainer class opens device file descriptors to remote cameras "
            "for multi-camera loitering detection. "
            "Camera connection target from CGI JSON config. "
            "If camera host/port is admin-configurable via /control.cgi JSON: "
            "set to attacker-controlled host -> socket SSRF from camera to arbitrary endpoint."
        ),
        "cgi": "administrator /control.cgi",
        "class": "SocketCameraContainer",
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-LG-02",
        "severity": "LOW",
        "title": "libscene.so / libgeometry.so substitution",
        "detail": (
            "libscene.so and libgeometry.so loaded from camera firmware path. "
            "Same substitution surface as VMD-04. "
            "If library search path prepends writable directory: substitute with malicious .so "
            "-> code execution in loiteringguard process."
        ),
        "libs": ["libscene.so", "libgeometry.so", "libfixmath.so.0"],
        "prerequisite": "Write access to library search path directory",
        "status": "UNPATCHED",
        "cve": None,
    },
]
