"""
AXIS People Counter (Cognimatics tvpc base) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: Cognimatics tvpc base binary (shared across multiple ACAPs)
APPUSR=root in all Cognimatics tvpc variants — maximum blast radius.

This module covers findings in the core Cognimatics tvpc binary that apply across
all variants (People Counter, Occupancy Estimator, Direction Detector, Queue Monitor).
Variant-specific findings are in their respective modules.

debugar.cgi.org: developer CGI endpoint left in production binary (commented out
or otherwise dormant, but credential string present).
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-COG"
LABEL = "Cognimatics tvpc: tarslip as root, dev cred, coredump exfil, SNMP, SWEET32"

FINDINGS = [
    {
        "id": "AXIS-COG-01",
        "severity": "CRITICAL",
        "title": "Tarslip as root — full camera filesystem write (APPUSR=root)",
        "detail": (
            "All Cognimatics tvpc variants run as root (APPUSR=root). "
            "Backup restore endpoint performs tar extraction with no path sanitization. "
            "Malicious tar with ../../ traversal entries: "
            "attacker writes any file on camera filesystem as root. "
            "Persistent rootkit via /etc/init.d/ or /usr/sbin/ replacement. "
            "Affects: People Counter, Occupancy Estimator, Direction Detector, Queue Monitor."
        ),
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-COG-02",
        "severity": "HIGH",
        "title": "debugar.cgi.org hardcoded developer credential: root:pass",
        "detail": (
            "debugar.cgi.org binary string in tvpc production binary. "
            "Credential root:pass present in associated context. "
            "Developer CGI endpoint left in production. "
            "If debugar.cgi is reachable on development build or via firmware downgrade: "
            "full admin access with root:pass credential."
        ),
        "credential": "root:pass",
        "endpoint": "debugar.cgi.org",
        "prerequisite": "Development build or firmware downgrade",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-COG-03",
        "severity": "MEDIUM",
        "title": "Coredump exfiltration to Cognimatics FTP server",
        "detail": (
            "tvpc binary initiates FTP upload of coredump files to Cognimatics FTP server "
            "on crash. Coredump contains process memory at time of crash: "
            "active axparameter credentials, VAPIX tokens, counting data, camera serial. "
            "Transmitted to third-party without customer notification."
        ),
        "protocol": "FTP",
        "destination": "Cognimatics FTP server",
        "prerequisite": "tvpc process crash (triggered by any unhandled exception or signal)",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-COG-04",
        "severity": "MEDIUM",
        "title": "mini_snmpd community string 'public' — SNMP read access",
        "detail": (
            "tvpc starts mini_snmpd with community string 'public'. "
            "Default public community string: any network host can query "
            "SNMP OIDs including system info, interface stats, process list. "
            "Combined with camera network position: camera OS fingerprint, "
            "active process list, network interface details."
        ),
        "snmp_community": "public",
        "prerequisite": "Network access to camera UDP 161",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-COG-05",
        "severity": "MEDIUM",
        "title": "DES-CBC3-SHA cipher suite enabled — SWEET32 CVE-2016-2183",
        "detail": (
            "tvpc TLS configuration enables DES-CBC3-SHA cipher suite. "
            "CVE-2016-2183 (SWEET32): 3DES 64-bit block size enables birthday attack "
            "with ~32GB of captured traffic -> plaintext recovery. "
            "Affects SSL/TLS connections from tvpc (camera-to-dashboard, camera-to-server). "
            "Cipher should be disabled; TLS_AES_*/CHACHA20_POLY1305 only."
        ),
        "cipher": "DES-CBC3-SHA",
        "cve": "CVE-2016-2183",
        "prerequisite": "Network position to capture tvpc TLS traffic (~32GB)",
        "status": "UNPATCHED",
    },
]
