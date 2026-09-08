"""
AXIS Sensor Metrics Dashboard (metricdashboard) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Sensor Metrics Dashboard (metricdashboard), appId 413965
Version: 4.4.0 (aarch64 ELF stripped PIE)
Arch: aarch64 (target arches: aarch64 + armv7hf from source tarball)

Camera-mounted ICS/SCADA bridge: Modbus TCP/RTU + NMEA GPS bridge on Axis cameras.
Ships: libmodbus 3.1.11 (CVE-2019-14462, CVE-2019-14463), libnmea (snapshot).
Serial device: /dev/ttyPCC1 (RS-485 bus on ARTPEC cameras).
CGI: administrator-only /app-settings.cgi and /data-source.cgi (both fastCGI).

libmodbus 3.1.11 is the admin-configured Modbus CLIENT: if admin sets Modbus
server IP to attacker-controlled host, attacker's Modbus server can send crafted
response -> CVE-2019-14463 heap corruption on camera (SMD-1 chains here).
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-SMD"
LABEL = "metricdashboard: Modbus SSRF, NMEA GPS spoof, RS-485 bus acquisition"

FINDINGS = [
    {
        "id": "AXIS-SMD-01",
        "severity": "HIGH",
        "title": "Modbus TCP SSRF — camera pivots to internal OT/ICS network",
        "detail": (
            "Administrator can configure Modbus device IP and register set via /data-source.cgi. "
            "metricdashboard connects as Modbus client (libmodbus 3.1.11) to configured IP:502. "
            "If attacker controls admin session: point Modbus client at internal OT/ICS device "
            "-> camera makes Modbus TCP/502 connections to internal PLCs/controllers otherwise "
            "unreachable from attacker (SSRF via Modbus). "
            "Attacker can also configure external Modbus server -> camera exfiltrates "
            "ICS sensor readings to attacker-controlled endpoint."
        ),
        "cgi": "/data-source.cgi (admin)",
        "protocol": "Modbus TCP port 502",
        "libs": ["libmodbus 3.1.11 (CVE-2019-14462, CVE-2019-14463)"],
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-SMD-02",
        "severity": "MEDIUM",
        "title": "NMEA GPS spoofing via RS-485 bus injection",
        "detail": (
            "DataProducer NMEA class parses NMEA 0183 sentences from /dev/ttyPCC1 (RS-485). "
            "GPS coordinates overlaid on camera video stream. "
            "Physical access to RS-485 wiring or bridge device on same bus: inject forged "
            "$GPRMC/$GPGGA sentences -> camera displays attacker-controlled GPS coordinates "
            "on video overlay -> location falsification in evidence/security recordings. "
            "libnmea nmea_scanf() uses memcpy(parg_target, beg_tok, width) with width from "
            "format parser; miscalculated width = stack overflow in sentence parse handler."
        ),
        "protocol": "NMEA 0183 (RS-485)",
        "prerequisite": "Physical access to RS-485 wiring or co-resident device on same bus",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-SMD-03",
        "severity": "MEDIUM",
        "title": "VAPIX service account credential exposed in error log",
        "detail": (
            "'Failed to retrieve VAPIX credentials' — app fetches VAPIX service account token "
            "from com.axis.HTTPConf1.VAPIXServiceAccounts1 to call dynamicoverlay.cgi. "
            "Credential path or token included in error log output. "
            "If logging to syslog or /tmp file: token readable by co-resident ACAP "
            "or via /tmp read via backup/tarslip chain."
        ),
        "prerequisite": "Read access to syslog or /tmp log (local ACAP or backup chain)",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-SMD-04",
        "severity": "LOW",
        "title": "RS-485 bus exclusive lock DoS via forced ACAP crash",
        "detail": (
            "'Failed to acquire serial bus for %s' — app acquires exclusive RS-485 bus access. "
            "DataProducerModbusSerial connects to sensors on camera RS-485 (/dev/ttyPCC1). "
            "If metricdashboard crashes or is SIGKILL'd, serial bus may remain locked, "
            "DoS'ing other ACAP apps that need RS-485 access."
        ),
        "prerequisite": "Ability to crash or kill metricdashboard process",
        "status": "UNPATCHED",
        "cve": None,
    },
]

LIBMODBUS_CVES = {
    "CVE-2019-14462": {
        "description": "OOB read in receive_msg(): response length > allowed max not fully checked before memcpy",
        "affects": "libmodbus 3.1.11 and prior 3.1.x",
        "impact_in_context": "Camera as Modbus CLIENT: malformed response from admin-configured server -> crash",
    },
    "CVE-2019-14463": {
        "description": "OOB write in modbus_reply(): unsigned comparison of response_length allows crafted Modbus server response to write outside buffer; heap corruption",
        "affects": "libmodbus 3.1.11 and prior 3.1.x",
        "impact_in_context": (
            "Camera is a Modbus CLIENT: if admin-configured Modbus server sends crafted response, "
            "metricdashboard crashes or achieves RCE as ACAP user. "
            "SMD-01 SSRF chains here: attacker controls Modbus server -> sends malformed response -> RCE on camera."
        ),
    },
}
