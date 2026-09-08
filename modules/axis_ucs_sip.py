"""
AXIS Client for Unified Communication Systems (SipThirdPartyIntegration) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Client for UCS (SipThirdPartyIntegration), appId 414930
Version: 1.0.2  Arch: aarch64 (SHA 0fa6c8) + armhf (SHA 8b2941)  NOT STRIPPED

Architecture: almost entirely a license check + sipd availability sentinel.
Actual SIP functionality lives in sipd (Axis camera daemon, not this package).
STARTMODE=once (runs once at install time, not a persistent daemon).

LD_PRELOAD / /etc/ld.so.preload detection explicitly present:
  test_ld_preload, test_ld_so_preload, dir_contains_overriding_lib.
dlopen bypass is the viable path (not LD_PRELOAD injection).
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-UCS"
LABEL = "SipThirdPartyIntegration: sipd spoof, flag injection, dlopen bypass, TOCTOU, SIP attack surface"

LD_PRELOAD_DETECTION_FUNCS = [
    "test_ld_preload",
    "test_ld_so_preload",
    "test_ld_so_preload.constprop.0",
    "dir_contains_overriding_lib",
]

FINDINGS = [
    {
        "id": "AXIS-UCS-01",
        "severity": "LOW",
        "title": "sipd absence spoofing — capability stub bypass",
        "detail": (
            "post_install.sh: 'test -f /usr/bin/sipd || exit 77'. "
            "Create minimal /usr/bin/sipd (empty file, chmod +x). "
            "Satisfies check -> ACAP installs. "
            "No real SIP daemon -> camera shows UCS capability without active SIP. "
            "Useful for capability spoofing in mixed-camera deployments or "
            "to satisfy prerequisites for other integration checks."
        ),
        "sipd_path": "/usr/bin/sipd",
        "prerequisite": "Write access to /usr/bin/ (admin or post-RCE)",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-UCS-02",
        "severity": "MEDIUM",
        "title": "third-party-integration-enabled flag manipulation — SIP features without license",
        "detail": (
            "Binary creates/removes /etc/dynamic/sipd/acaps/third-party-integration-enabled "
            "to signal sipd that third-party integration is active. "
            "Write this file without a licensed ACAP: "
            "sipd processes SIP from third-party systems without valid license. "
            "Writable by ACAP process user — co-resident ACAP can enable it."
        ),
        "flag_path": "/etc/dynamic/sipd/acaps/third-party-integration-enabled",
        "prerequisite": "ACAP process user write access to /etc/dynamic/sipd/acaps/",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-UCS-03",
        "severity": "HIGH",
        "title": "liblicensekey.so stub bypass via dlopen path control",
        "detail": (
            "Binary explicitly detects LD_PRELOAD and /etc/ld.so.preload. "
            "dlopen bypass is viable: place stub liblicensekey.so "
            "(exporting licensekey_verify/licensekey_verify_ex returning success) "
            "in dlopen search path ahead of system library. "
            "RUNPATH manipulation at /usr/local/packages/SipThirdPartyIntegration/ "
            "not blocked by the LD_PRELOAD detection code."
        ),
        "bypass_method": "stub liblicensekey.so in dlopen RUNPATH ahead of system path",
        "stub_exports": ["licensekey_verify", "licensekey_verify_ex", "licensekey_dyn_verify_ex"],
        "prerequisite": "Write access to /usr/local/packages/SipThirdPartyIntegration/",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-UCS-04",
        "severity": "MEDIUM",
        "title": "STARTMODE=once TOCTOU on LD anti-tamper check",
        "detail": (
            "dir_contains_overriding_lib / file_overrides_symbols / test_ld_so_preload "
            "checks run only at STARTMODE=once install time. "
            "A malicious shared object placed in sipd LD_LIBRARY_PATH AFTER "
            "SipThirdPartyIntegration already created the enabled file "
            "will not be detected (no re-check on sipd restart). "
            "Chain: install co-resident ACAP -> wait for UCS install -> write malicious .so "
            "to shared path on sipd search order -> sipd loads attacker lib on next restart."
        ),
        "prerequisite": "Write access to sipd LD_LIBRARY_PATH directory after UCS install completes",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-UCS-05",
        "severity": "HIGH",
        "title": "sipd SIP attack surface once third-party integration enabled",
        "detail": (
            "Once /etc/dynamic/sipd/acaps/third-party-integration-enabled exists, "
            "sipd processes SIP from third-party systems. "
            "Standard SIP attack surface: "
            "REGISTER flood (auth replay), "
            "malformed SDP/SIP headers (sipd parser bugs), "
            "SIP digest credential capture via MITM proxy, "
            "unauthenticated INVITE if sipd trust policy misconfigured -> unauthorized call. "
            "sipd crash via malformed headers = DoS of all camera SIP functionality."
        ),
        "sip_port": "5060 (SIP) / 5061 (SIPS)",
        "prerequisite": "Network access to sipd port once third-party integration is active",
        "status": "UNPATCHED",
        "cve": None,
    },
]
