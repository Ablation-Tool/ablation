"""
AXIS Direction Detector (tvpc variant) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Direction Detector (Cognimatics tvpc), appId 413742 variant
APPUSR=root — same binary base as People Counter, Occupancy Estimator.

Direction Detector tracks movement direction (up/down/in/out) per zone.
Backup restore and FTP coredump exfil present in all tvpc variants.
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-DD"
LABEL = "DirectionDetector: mount bind as root, FTP exfil, dual tarslip"

FINDINGS = [
    {
        "id": "AXIS-DD-01",
        "severity": "HIGH",
        "title": "privacy.sh mount --bind as root — filesystem overlay via Direction Detector context",
        "detail": (
            "privacy.sh uses 'mount --bind' as root (APPUSR=root). "
            "Post-compromise of Direction Detector process: "
            "arbitrary bind mount -> overlay /etc or /usr with attacker-controlled content "
            "-> persistent rootkit on camera. "
            "Same primitive as OE-08 (Occupancy Estimator) and People Counter."
        ),
        "prerequisite": "Code execution in Direction Detector process (via tarslip DD-03 or other)",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-DD-02",
        "severity": "MEDIUM",
        "title": "FTP coredump exfiltration to Cognimatics server",
        "detail": (
            "Direction Detector (tvpc) exfiltrates process coredumps via FTP to "
            "Cognimatics server on crash. "
            "Coredump exposes: active memory (direction count data, zone configs, "
            "VAPIX tokens, camera serial). "
            "Same as COG-03 — present in all Cognimatics tvpc variants."
        ),
        "protocol": "FTP",
        "prerequisite": "Process crash (triggered by signal or exploit)",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-DD-03",
        "severity": "CRITICAL",
        "title": "Dual .restore_backup tarslip as root",
        "detail": (
            "Direction Detector has two separate backup restore code paths (primary + fallback). "
            "Both perform tar extraction without path sanitization as root (APPUSR=root). "
            "Either path exploitable for tarslip -> full filesystem write. "
            "Dual paths increase attack surface: one path may have reduced auth check."
        ),
        "prerequisite": "Admin-level camera auth (primary path); possibly lower for fallback path",
        "status": "UNPATCHED",
        "cve": None,
    },
]
