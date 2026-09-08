"""
AXIS Fence Guard (fenceguard) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Fence Guard (fenceguard), appId 47775
Version: 2.3.8  Arch: aarch64 stripped
CGI: administrator /control.cgi (admin-only)
LICENSEPAGE: none

Same SocketCameraContainer + libscene.so/libgeometry.so stack as Loitering Guard + VMD.
Adds ONVIF_StateEventProducer (like VMD 4.4.4).
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-FG"
LABEL = "fenceguard: SocketCameraContainer SSRF, ONVIF_StateEventProducer injection"

FINDINGS = [
    {
        "id": "AXIS-FG-01",
        "severity": "MEDIUM",
        "title": "SocketCameraContainer SSRF via admin control.cgi",
        "detail": (
            "Same pattern as Loitering Guard LG-01. "
            "ZTV21SocketCameraContainer class present in symbol table. "
            "Admin control.cgi camera host config -> socket SSRF to attacker-controlled camera. "
            "Opens TCP connection from camera to attacker-configured host."
        ),
        "class": "SocketCameraContainer",
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-FG-02",
        "severity": "LOW",
        "title": "ONVIF_StateEventProducer event injection via sendStartEvent",
        "detail": (
            "ZN24ONVIF_StateEventProducer14sendStartEventERK24StateEventProducerHandleRKl "
            "confirms Fence Guard sends ONVIF state events. "
            "If ONVIF state event payload is user-influenced via CGI param: "
            "ONVIF injection to event consumers (ONVIF clients, VMS platforms). "
            "Malformed event payload may crash ONVIF client or VMS integration."
        ),
        "class": "ONVIF_StateEventProducer",
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
]
