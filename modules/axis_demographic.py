"""
AXIS Demographic Indicator / tvgd (tvgd) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Demographic Indicator (tvgd), Cognimatics tvpc variant
APPUSR=root — full camera write on tarslip.

tvgd = TrueView Gender/Age Demographic analytics.
Collects biometric demographic data (estimated age, gender from face detections).
PII exposure at viewer level is the headline finding.
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-DI"
LABEL = "tvgd: tarslip, PII at viewer, curl -k SSRF, parhandclient dump"

FINDINGS = [
    {
        "id": "AXIS-DI-01",
        "severity": "CRITICAL",
        "title": "Tarslip as root — full camera filesystem write",
        "detail": (
            "APPUSR=root. Backup restore (tar extraction) without path sanitization. "
            "Tarslip writes arbitrary files to camera filesystem as root. "
            "Same primitive as COG-01 / OE-01 / DD-03."
        ),
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-DI-02",
        "severity": "HIGH",
        "title": "Biometric PII (age/gender estimates) exposed at viewer privilege level",
        "detail": (
            "tvgd demographic analytics (estimated age range, gender) accessible at viewer level. "
            "GDPR Art. 9: biometric data for uniquely identifying a natural person = "
            "special category data requiring explicit consent. "
            "Viewer-level access exposes biometric demographic data with no consent gate."
        ),
        "data_types": ["estimated_age_range", "estimated_gender", "face_detection_timestamp"],
        "prerequisite": "Viewer-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-DI-03",
        "severity": "HIGH",
        "title": "curl -k (TLS disabled) SSRF via admin-controlled URL",
        "detail": (
            "tvgd uses curl -k (--insecure, certificate verification disabled) for outbound calls. "
            "Admin-controllable URL parameter feeds curl -k: "
            "camera makes TLS-unverified connection to attacker-controlled host "
            "-> SSRF with TLS bypass (no cert pinning or CA validation). "
            "Attacker can capture curl user-agent requests, inject responses."
        ),
        "curl_flags": "curl -k (certificate verification disabled)",
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-DI-04",
        "severity": "MEDIUM",
        "title": "parhandclient dump — camera parameter exfiltration via param handler",
        "detail": (
            "tvgd calls parhandclient to read/write camera parameters. "
            "parhandclient invoked via shell with camera-controlled params. "
            "If parhandclient dump mode triggered: full axparameter namespace written "
            "to stdout/log including stored credentials (cloud integration passwords, "
            "proxy credentials, VAPIX tokens)."
        ),
        "prerequisite": "Code execution in tvgd context (post-tarslip DI-01)",
        "status": "UNPATCHED",
        "cve": None,
    },
]
