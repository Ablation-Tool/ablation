"""
AXIS Speed Monitor (speedmonitor) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Speed Monitor (speedmonitor), appId 413872
Version: 1.1.7  Arch: ARM32 armhf stripped
CGI: administrator /control.cgi, /statistics.cgi (both admin-only)

Radar scene analytics: processes radar-tracked vehicle speed data.
SQLite3 Track database for speed/timestamp persistence.
Bundled: libgstreamer-1.0.so.0.2408.0, libprotobuf.so.26.0.2, libssl.so.3,
         libcrypto.so.3, libxml2.so.2.13.4, libcurl.so.4.8.0, libsqlite3.so.0.8.6
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-SPM"
LABEL = "speedmonitor: radar track dump, malformed protobuf, libxml2 XXE, bundled CVEs"

SQLITE_QUERIES = [
    "SELECT MIN(start_timestamp), MAX(start_timestamp) FROM Track",
    "INSERT INTO Track (...)",
    "DELETE FROM Track WHERE start_timestamp <= ?  (parameterized)",
    "SELECT * FROM Track  (unbounded dump at admin level)",
]

FINDINGS = [
    {
        "id": "AXIS-SPM-01",
        "severity": "MEDIUM",
        "title": "Full radar track data dump via statistics.cgi (admin)",
        "detail": (
            "SELECT * FROM Track via admin-only statistics.cgi. "
            "Track schema: start_timestamp, speed, object attributes from radarscene.proto. "
            "Unbounded SELECT * dump: full vehicle speed/time tracking history accessible "
            "to any admin-level user without filtering. "
            "Potentially hours or days of vehicle speed+timestamp data."
        ),
        "cgi": "/statistics.cgi (admin)",
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-SPM-02",
        "severity": "MEDIUM",
        "title": "Malformed protobuf from radar device -> crash",
        "detail": (
            "libprotobuf.so.26 (bundled) deserializes radarscene.proto from IPC provider. "
            "'Got invalid serialized scene size %d from provider' confirms size check present, "
            "but protobuf parsing after size check may still crash on malformed fields. "
            "If connected radar device is attacker-controlled: send crafted protobuf "
            "-> speedmonitor crash or heap corruption."
        ),
        "lib": "libprotobuf.so.26.0.2 (bundled)",
        "prerequisite": "Control of connected radar device (physical or network access to radar sensor)",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-SPM-03",
        "severity": "LOW",
        "title": "libxml2 metadata XXE / injection via radar XML stream",
        "detail": (
            "'Received non-wellformed metadata document from radar!' "
            "confirms libxml2.so.2.13.4 (bundled) parses radar metadata XML. "
            "If radar metadata XML from connected radar device is attacker-influenced: "
            "libxml2 XXE or injection. "
            "libxml2 2.13.4: audit NVD for post-2.13.4 CVEs applicable to this version."
        ),
        "lib": "libxml2.so.2.13.4 (bundled)",
        "prerequisite": "Control of connected radar metadata stream",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-SPM-04",
        "severity": "MEDIUM",
        "title": "Bundled lib CVE exposure: libssl.so.3 + libxml2.so.2.13.4 not firmware-updated",
        "detail": (
            "speedmonitor bundles its own copies of libssl.so.3 and libxml2.so.2.13.4. "
            "Bundled libs not updated by camera firmware upgrades. "
            "Any CVEs discovered in libssl/OpenSSL 3.x and libxml2 after shipment "
            "remain in speedmonitor regardless of firmware patch level. "
            "Audit NVD for OpenSSL 3.x and libxml2 2.13.4 CVEs post-release."
        ),
        "bundled_libs": ["libssl.so.3", "libcrypto.so.3", "libxml2.so.2.13.4"],
        "prerequisite": "Applicable exploit for specific bundled lib CVE",
        "status": "UNPATCHED",
        "cve": None,
    },
]
