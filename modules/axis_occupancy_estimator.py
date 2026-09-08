"""
AXIS Occupancy Estimator (tvpc variant) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Occupancy Estimator (Cognimatics tvpc), appId 413742
APPUSR=root — maximum blast radius for all write primitives.

Shares binary base with People Counter tvpc variants.
Key differences: OccCoCounterAddress SSRF, SFTP exfil to upload.cognimatics.com,
connection_key.json admin endpoint.

TCP 23456 (event injection) and TCP 4066 (master/slave MITM) present in all tvpc variants.
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-OE"
LABEL = "OccupancyEstimator: tarslip as root, SSRF, FTP cred, SFTP exfil"

FINDINGS = [
    {
        "id": "AXIS-OE-01",
        "severity": "CRITICAL",
        "title": "Tarslip via .restore_backup as root — full camera filesystem write",
        "detail": (
            "APPUSR=root. .restore_backup CGI endpoint invokes tar extraction. "
            "Malicious tar with path traversal (../../) entries: "
            "attacker writes any file on camera filesystem as root. "
            "Persistence: write /etc/init.d/ script, replace /usr/sbin/ binary, "
            "or inject into /etc/rcS.d/. No path sanitization visible in binary."
        ),
        "cgi": ".restore_backup (admin)",
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-OE-02",
        "severity": "HIGH",
        "title": "TCP 23456 unauthenticated event injection",
        "detail": (
            "Occupancy Estimator binds TCP 23456 with no authentication. "
            "Any host reachable to camera can inject synthetic occupancy count events. "
            "Same as PC-03 (People Counter). Vector: forge entries/exits -> "
            "corrupted occupancy data in analytics dashboard."
        ),
        "port": 23456,
        "prerequisite": "Network access to camera TCP 23456",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-OE-03",
        "severity": "MEDIUM",
        "title": "Counter.SlavePass in TCP 4066 master/slave protocol — MITM key intercept",
        "detail": (
            "Multi-camera aggregation uses TCP 4066 master/slave protocol. "
            "Counter.SlavePass is transmitted for slave authentication. "
            "No observed TLS wrapping on this channel. "
            "MITM on camera LAN: intercept SlavePass -> authenticate as slave -> "
            "inject false counts into aggregated dataset."
        ),
        "port": 4066,
        "param": "Counter.SlavePass",
        "prerequisite": "Network MITM on camera LAN segment (TCP 4066)",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-OE-04",
        "severity": "HIGH",
        "title": "TrueviewVAPIX — persistence via legacy VAPIX credential store",
        "detail": (
            "TrueviewVAPIX service account credentials stored in axparameter. "
            "Credential survives firmware upgrade in some configurations. "
            "Attacker with admin access reads TrueviewVAPIX creds from axparameter "
            "-> persistent VAPIX access even after password rotation."
        ),
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-OE-05",
        "severity": "MEDIUM",
        "title": "Viewer-level access to full counting API",
        "detail": (
            "Occupancy counting API endpoints accessible at viewer privilege level. "
            "Viewer can read raw entry/exit counts, zone definitions, schedule config. "
            "No operator/admin gate on live count data endpoints."
        ),
        "prerequisite": "Viewer-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-OE-06",
        "severity": "HIGH",
        "title": "Hardcoded FTP developer credential: ftp://root:pass@192.168.0.90:21",
        "detail": (
            "Binary string: ftp://root:pass@192.168.0.90:21 "
            "Left in production binary by Cognimatics developers. "
            "If coredump/debug path is reachable (OE-09 or direct FTP path): "
            "camera attempts to connect to 192.168.0.90 with root:pass credentials. "
            "Internal Cognimatics dev network address (likely unreachable from internet, "
            "but reachable on camera LAN if IP conflicts)."
        ),
        "credential": "ftp://root:pass@192.168.0.90:21",
        "prerequisite": "Camera reachable to 192.168.0.90 on same network",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-OE-07",
        "severity": "HIGH",
        "title": "OccCoCounterAddress SSRF — attacker-controlled outbound connection",
        "detail": (
            "OccCoCounterAddress axparameter holds the remote counter address. "
            "If admin sets OccCoCounterAddress to attacker-controlled host: "
            "camera makes outbound TCP connection to arbitrary address. "
            "SSRF within camera network from camera source IP -> internal host pivoting."
        ),
        "param": "OccCoCounterAddress",
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-OE-08",
        "severity": "HIGH",
        "title": "privacy.sh mount --bind as root — filesystem mount primitive",
        "detail": (
            "privacy.sh uses 'mount --bind' as root to set up privacy masking. "
            "APPUSR=root enables arbitrary bind mount. "
            "Attacker with code execution in tvpc context (post-tarslip OE-01): "
            "bind-mount attacker-controlled directory over /etc or /usr "
            "-> permanent rootkit via overlay filesystem on camera."
        ),
        "prerequisite": "Code execution in occupancy estimator process (post OE-01)",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-OE-09",
        "severity": "MEDIUM",
        "title": "SFTP exfiltration to upload.cognimatics.com",
        "detail": (
            "Binary strings reference SFTP upload to upload.cognimatics.com. "
            "Coredumps and debug logs may be exfiltrated to Cognimatics servers. "
            "SFTP key or password for upload.cognimatics.com in binary or config. "
            "Sensitive camera data (counts, calibration, serial) transmitted to "
            "third-party server without customer consent documentation."
        ),
        "host": "upload.cognimatics.com",
        "protocol": "SFTP",
        "prerequisite": "Normal operation (no exploit required)",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-OE-10",
        "severity": "MEDIUM",
        "title": "connection_key.json admin endpoint — secret key file exposure",
        "detail": (
            "connection_key.json endpoint accessible to admin-level users. "
            "File contains key material used for camera-to-server connection authentication. "
            "Key extraction enables: impersonation of camera to Cognimatics backend, "
            "or session token replay if key is used for JWT/HMAC signing."
        ),
        "endpoint": "connection_key.json",
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
]
