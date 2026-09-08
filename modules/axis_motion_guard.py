"""
AXIS Motion Guard (motionguard) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Motion Guard (motionguard), appId 48170
Version: 2.3.8  Arch: aarch64 stripped (2.2.3 was armhf)
CGI: administrator /control.cgi (admin-only)
LICENSEPAGE: none

Same SocketCameraContainer pattern as Fence Guard + Loitering Guard.
Adds D-Bus file descriptor passing: g_dbus_proxy_call_with_unix_fd_list_sync.
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-MG"
LABEL = "motionguard: SocketCameraContainer SSRF, D-Bus FD leak"

FINDINGS = [
    {
        "id": "AXIS-MG-01",
        "severity": "MEDIUM",
        "title": "SocketCameraContainer SSRF via admin control.cgi",
        "detail": (
            "Same pattern as LG-01 and FG-01. "
            "Symbol _ZTV21SocketCameraContainerC2... confirmed present. "
            "Admin control.cgi camera host config -> socket SSRF to arbitrary endpoint. "
            "Camera opens TCP connection to attacker-configured remote camera host."
        ),
        "class": "SocketCameraContainer",
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-MG-02",
        "severity": "LOW",
        "title": "D-Bus file descriptor passing — FD leak or starvation",
        "detail": (
            "g_dbus_proxy_call_with_unix_fd_list_sync passes file descriptor list over D-Bus. "
            "Attacker D-Bus client that can interact with motionguard's D-Bus interface: "
            "consume or steal FDs from motionguard -> resource starvation (FD exhaustion) "
            "or FD confusion if motionguard expects specific FD type but receives attacker-controlled FD."
        ),
        "prerequisite": "D-Bus access to motionguard interface (from another ACAP or camera shell)",
        "status": "UNPATCHED",
        "cve": None,
    },
]
