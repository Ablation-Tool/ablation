"""
AXIS Speaker Functionality for Singlewire InformaCast (InformaCastAcap) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Speaker Functionality for Singlewire InformaCast (InformaCastAcap)
appId: 414050  version: 1.0.8  arch: ARM32 armhf NOT STRIPPED

Identical structure to UCS/SipThirdPartyIntegration: license gate + daemon dependency sentinel.
Service dependency: /usr/lib/systemd/system/informacast-client.service
Integration flag: /etc/dynamic/informacast-client/enabled
Default port: 8081 (Singlewire InformaCast)
LD_PRELOAD detection NOT confirmed (unlike UCS which explicitly tests it).
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-IC"
LABEL = "InformaCast: ServerAddress SSRF, service spoof, liblicensekey bypass"

FINDINGS = [
    {
        "id": "AXIS-IC-01",
        "severity": "HIGH",
        "title": "ServerAddress SSRF — route audio alerts to attacker InformaCast server",
        "detail": (
            "ServerAddress parameter is empty by default and operator-writable. "
            "Set ServerAddress to attacker IP:8081. "
            "informacast-client connects and transmits alert broadcasts (audio content, "
            "camera identity, alert metadata) to attacker-controlled server. "
            "Default port 8081 is the Singlewire InformaCast default. "
            "Connection cleartext by default (no TLS configured out-of-box)."
        ),
        "param": "ServerAddress (operator-writable, default empty)",
        "default_port": 8081,
        "prerequisite": "Operator-level axparameter write",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-IC-02",
        "severity": "MEDIUM",
        "title": "informacast-client service file spoof — ACAP installs without real service",
        "detail": (
            "post_install.sh: 'test -f /usr/lib/systemd/system/informacast-client.service || exit 77'. "
            "Exit 77 = abort installation. "
            "Create minimal /usr/lib/systemd/system/informacast-client.service "
            "(zero-byte or minimal unit file, chmod 644): satisfies check. "
            "ACAP installs and sets /etc/dynamic/informacast-client/enabled "
            "without a real InformaCast client. "
            "Camera reports InformaCast capability without operational service."
        ),
        "service_path": "/usr/lib/systemd/system/informacast-client.service",
        "prerequisite": "Write access to /usr/lib/systemd/system/ (admin or post-RCE)",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-IC-03",
        "severity": "HIGH",
        "title": "liblicensekey.so stub bypass via LD_PRELOAD (no detection confirmed)",
        "detail": (
            "InformaCast binary NOT confirmed to test LD_PRELOAD or /etc/ld.so.preload "
            "(unlike UCS/SipThirdPartyIntegration which explicitly calls test_ld_preload). "
            "LD_PRELOAD injection of stub liblicensekey.so exporting "
            "licensekey_verify/licensekey_verify_ex returning success: "
            "license check bypassed, InformaCast ACAP activated without valid license. "
            "Stub: 'int licensekey_verify(...) { return 0; }'"
        ),
        "libs": ["liblicensekey.so.1"],
        "bypass_method": "LD_PRELOAD stub liblicensekey.so",
        "prerequisite": "ACAP process user ability to set LD_PRELOAD",
        "status": "UNPATCHED",
        "cve": None,
    },
]
