"""
AXIS Barcode Reader (BarcodeReader) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Barcode Reader (BarcodeReader), appId 413766
Versions: 1.3.2 (ARM32 armhf SHA e1a4ee, aarch64 SHA ba161d) — both stripped
Arch: ARM32 EABI5 armv7hf + aarch64 (functionally identical)

Critical: Barcode value mapped to NBIX Token in D-Bus call
axtid:IndicateRemoteActivities — no server-side crypto validation visible in binary.
Craft a barcode value matching a valid NBIX token -> door unlock without badge.

ignoreCert="1" default in param.conf: all libcurl calls skip TLS cert validation.
VAPIX service account token fetched from com.axis.HTTPConf1.VAPIXServiceAccounts1
and used for loopback HTTP to http://127.0.0.12/%s.
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-BR"
LABEL = "BarcodeReader NBIX token spoof + TLS disabled by default"

NBIX_DBUS_CALLS = [
    '{"axtdc:GetDoorList":{}}',
    '{"axtid:GetIdPointList":{}}',
    '{"axtid:GetIdPointConfigurationList":{}}',
    '{"axtid:IndicateRemoteActivities":{"Token":"%s","Description":"%s","Activities":[...]}}',
]

BARCODE_FORMAT_CODES = [
    '706', '71D', '770', '779', '7E6', '976', '7DF',
    '9C1', '95A', '9CA', '980', 'A25', 'A66.2',
]

FINDINGS = [
    {
        "id": "AXIS-BR-01",
        "severity": "CRITICAL",
        "title": "Physical access bypass via barcode token spoofing",
        "detail": (
            "BarcodeReader scans barcode value and maps it to Token string "
            "in axtid:IndicateRemoteActivities D-Bus call: "
            "{\"axtid:IndicateRemoteActivities\":{\"Token\":\"%s\",\"Description\":\"%s\",\"Activities\":[...]}}. "
            "No server-side crypto validation visible in binary — trust based on barcode value only. "
            "Craft a barcode value (QR code, 1D barcode) that matches a valid NBIX token pattern "
            "-> scanner presents it to the D-Bus door controller -> physical access granted. "
            "18 AIM symbology ID codes whitelisted (706/71D/770/779/7E6/976/7DF/9C1/95A.x/9CA.x/980/A25.x/A66.2). "
            "No token entropy/length enforcement visible. NBIX token patterns discoverable via "
            "GetIdPointConfigurationList D-Bus enumeration."
        ),
        "dbus_target": "com.axis.axtid (Axis Door Controller extension)",
        "prerequisite": "Physical access to barcode scanner camera field of view",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-BR-02",
        "severity": "HIGH",
        "title": "ignoreCert=1 default — TLS disabled on all libcurl calls",
        "detail": (
            "param.conf default: ignoreCert=\"1\" (type hidden:int:min=0;max=1). "
            "When ignoreCert=1, TLS certificate validation is suppressed on ALL libcurl calls. "
            "Combined with barcode reader PACS/NBIX communication: MITM between "
            "barcode reader and PACS backend intercepts and modifies access control decisions. "
            "Default-on means all out-of-box deployments have TLS verification disabled."
        ),
        "default_value": "ignoreCert=1 (TLS disabled)",
        "prerequisite": "Network position between camera and PACS/NBIX server",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-BR-03",
        "severity": "MEDIUM",
        "title": "PacsConfig JSON injection via operator axparameter write",
        "detail": (
            "PacsConfig and PacsConfigv1 axparameters store PACS configuration as raw JSON strings. "
            "Content not validated in binary — no schema enforcement visible. "
            "Operator-level write to PacsConfig/PacsConfigv1 injects malformed or attacker-controlled "
            "JSON into PACS door controller integration. Effect on door control behavior depends "
            "on how the camera firmware processes PacsConfig."
        ),
        "params": ["PacsConfig: {} (JSON string)", "PacsConfigv1: {} (JSON string)"],
        "prerequisite": "Operator-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-BR-04",
        "severity": "MEDIUM",
        "title": "VAPIX service account token leak via D-Bus sniff",
        "detail": (
            "BarcodeReader fetches a VAPIX service account token from "
            "com.axis.HTTPConf1.VAPIXServiceAccounts1 D-Bus interface. "
            "Token used for loopback VAPIX calls to http://127.0.0.12/%s. "
            "If the D-Bus session bus is accessible to another co-resident ACAP, "
            "the token is sniffable in transit or via /proc/<pid>/mem. "
            "VAPIX service account grants camera API access."
        ),
        "prerequisite": "Another ACAP installed on the same camera with D-Bus session access",
        "status": "UNPATCHED",
        "cve": None,
    },
]
