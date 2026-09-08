"""
AXIS Live Privacy Shield (liveprivacyshield) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Live Privacy Shield (liveprivacyshield), appId 346005
Version: 2.8.8  Arch: ARM32 armhf stripped
LICENSEPAGE: none  APPUSR: sdk

D-Bus heavy: g_dbus_proxy_call_sync, g_dbus_proxy_get_cached_property.
Implements video privacy masking overlay via D-Bus calls to camera firmware services.
CGI via FCGX socket (socket name from environment variable).
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-LPS"
LABEL = "liveprivacyshield: FCGX socket redirect, D-Bus method injection, privacy DoS"

FINDINGS = [
    {
        "id": "AXIS-LPS-01",
        "severity": "LOW",
        "title": "FCGX socket name from environment variable — CGI socket path redirection",
        "detail": (
            "'Could not get the FCGI socket name from the environment'. "
            "CGI handled via FCGX socket; socket name from environment variable. "
            "If another ACAP on the camera can set the environment variable "
            "before liveprivacyshield starts: redirect CGI calls to attacker-controlled socket. "
            "Attacker socket receives all admin CGI requests to the privacy shield."
        ),
        "prerequisite": "Environment variable manipulation from co-resident ACAP before liveprivacyshield start",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-LPS-02",
        "severity": "MEDIUM",
        "title": "D-Bus method name injection via Mor::DBusService::execute",
        "detail": (
            "'Cannot handle passed Method in Mor::DBusService::execute.' "
            "Method name passed as string to D-Bus execute() dispatch function. "
            "If method name comes from CGI input: D-Bus method injection -> "
            "call unintended D-Bus methods on camera firmware services. "
            "Check manifest.json for CGI access level (may be viewer/operator exposed)."
        ),
        "class": "Mor::DBusService",
        "prerequisite": "CGI access to liveprivacyshield (access level from manifest; likely operator)",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-LPS-03",
        "severity": "HIGH",
        "title": "Privacy masking DoS — single point of failure, GDPR implication",
        "detail": (
            "'Failed to start PrivacyShield service. Exiting' — "
            "process exit on startup failure disables all privacy masking. "
            "If PrivacyShield crash is triggerable via malformed CGI: "
            "crash -> privacy masking removed from all video streams. "
            "GDPR Art. 5/6 implication: masking configured for privacy protection of natural persons "
            "silently removed -> real-time unmasked video feeds exposed. "
            "Single restart restores but masking gap may be logged or captured by attackers."
        ),
        "gdpr_note": "Privacy masking removal on GDPR-protected streams = reportable incident in EU",
        "prerequisite": "Ability to crash liveprivacyshield (OOM, SIGKILL, malformed CGI)",
        "status": "UNPATCHED",
        "cve": None,
    },
]
