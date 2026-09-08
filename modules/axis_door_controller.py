"""
AXIS Door Controller Extension (DoorControllerExtension) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Door Controller Extension (DoorControllerExtension), appId 414114
Version: 1.1.5  Arch: ARM32 armhf NOT STRIPPED
STARTMODE=never — setup tool only, not a persistent daemon

Minimal binary: only main + _start symbols. libc.so.6 only dependency.
No libaxhttp, no libaxparameter, no libcurl.
Binary is a stub launcher or config writer; actual door controller integration
lives in camera firmware (door controller SDK).
LICENSEPAGE=axis (Axis license server, not local liblicensekey.so).
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-DCE"
LABEL = "DoorControllerExtension: developer build path disclosure"

BUILD_PATH_LEAK = (
    "/home/svcj/workspace/Teams/NB/Accesscontrol/"
    "AXIS_Door_Controller_Extension/Build-Acap-Products/armv7hf_Build/app"
)

FINDINGS = [
    {
        "id": "AXIS-DCE-01",
        "severity": "INFO",
        "title": "Build path disclosure: developer home + team structure in production binary",
        "detail": (
            "String in production binary: "
            "/home/svcj/workspace/Teams/NB/Accesscontrol/"
            "AXIS_Door_Controller_Extension/Build-Acap-Products/armv7hf_Build/app. "
            "Discloses: developer username svcj, team path Teams/NB/Accesscontrol, "
            "build structure Build-Acap-Products/<arch>_Build/app. "
            "OPSEC finding: username usable for internal directory/repo enumeration. "
            "Team path NB/Accesscontrol = Network Business / Access Control division."
        ),
        "build_path": BUILD_PATH_LEAK,
        "developer_username": "svcj",
        "team_path": "Teams/NB/Accesscontrol",
        "prerequisite": "Static analysis of EAP binary (strings)",
        "status": "UNPATCHED",
        "cve": None,
    },
]
