"""
AXIS License Plate Verifier (fflprapp) — additional findings (LPV-3 to LPV-7)
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS License Plate Verifier (fflprapp), appId 333330
Versions: 3.0.10 and 3.0.13 (aarch64 ELF stripped, ARTPEC-8)
Arch: aarch64 ELF stripped

Covers: plaintext creds, TFLite model swap, list poisoning,
        cloud cred exposure, tarslip via restorecfg.cgi.

LPV-1 (SQL injection) and LPV-2 (shell injection) are in axis_lpv_sqli.py and
axis_lpv_shell_inject.py respectively.
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-LPV-REMAINING"
LABEL = "fflprapp: plaintext creds, model swap, list poisoning, cloud creds, tarslip"

FINDINGS = [
    {
        "id": "AXIS-LPV-03",
        "severity": "HIGH",
        "title": "Plaintext camera credentials in SQLite CAMERA_BWLIST",
        "detail": (
            "LPR database at /usr/local/packages/fflprapp/localdata/cfg/*.db contains tables: "
            "CAMERA_BWLIST(CAMERA_NAME, CAMERA_IP, CAMERA_LOGIN, CAMERA_PASSWORD, CAMERA_SYNC) "
            "and CAMERA_MASTER_BWLIST (same schema). "
            "Camera credentials for synchronized LPR nodes stored plaintext in SQLite. "
            "Any process with read access to the package directory reads all sync credentials. "
            "Lateral movement: credentials grant VAPIX access to all synchronized cameras."
        ),
        "path": "/usr/local/packages/fflprapp/localdata/cfg/*.db",
        "schema": "CAMERA_BWLIST(CAMERA_NAME, CAMERA_IP, CAMERA_LOGIN, CAMERA_PASSWORD)",
        "prerequisite": "Read access to /usr/local/packages/fflprapp/ (viewer CGI or backup chain)",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-LPV-04",
        "severity": "MEDIUM",
        "title": "TFLite model substitution — no integrity check on ML models",
        "detail": (
            "fflprapp loads 11 TFLite model files via liblarod.so.1 (ARTPEC ML accelerator). "
            "Primary: onnx_model_full_integer_quant.tflite (6.8MB, OCR model). "
            "Also: Multi_detector_step1/2.tflite, LP_type_*.tflite, color_resnet_relu.tflite, Symbol.tflite. "
            "No hash or signature verification on model files visible in binary strings. "
            "Replace onnx_model_full_integer_quant.tflite with adversarial model "
            "-> suppress plate reads, spoof plate values, or cause ML inference crash."
        ),
        "path": "/usr/local/packages/fflprapp/models/*.tflite",
        "prerequisite": "Write access to package models dir (ACAP reinstall or filesystem access)",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-LPV-05",
        "severity": "HIGH",
        "title": "Access list poisoning via list_mgmt.cgi (operator)",
        "detail": (
            "Operator-level CGIs control vehicle access lists: "
            "list_mgmt.cgi, allow_list.cgi, block_list.cgi, custom_list.cgi. "
            "EventAllowList/EventBlockList/EventCustomList events flow to 2N intercom, "
            "GSC3574, A91xx IPC, heartbeat cloud integrations. "
            "Poisoning: suppress EventBlockList entries -> denied vehicles pass gates. "
            "Inject EventAllowList entries -> unauthorized vehicles are allowed. "
            "No cryptographic signing on list modifications."
        ),
        "cgi": "list_mgmt.cgi, allow_list.cgi, block_list.cgi, custom_list.cgi (operator)",
        "integrations": ["2N intercom", "GSC3574 (Grandstream)", "A91xx Dahua IPC", "A1601/A1001 Axis door controllers"],
        "prerequisite": "Operator-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-LPV-06",
        "severity": "MEDIUM",
        "title": "Cloud integration credential exposure via test.cgi (operator)",
        "detail": (
            "Multiple cloud credential sets stored in axparameter: "
            "cloud_config: {user, password, http_auth_type, proxy_user, proxy_password, cloud_url}, "
            "hb_config: {user, password, http_auth_type}, "
            "a91xx_config: {ipc_login, ipc_password, a91xx_url}, "
            "gsc_config: {user, password}. "
            "Readable via test.cgi (operator) and config_json_o.cgi (operator). "
            "Attacker with operator auth reads all cloud/integration credentials in one request."
        ),
        "params": [
            "cloud_config/user, cloud_config/password",
            "a91xx_config/ipc_login, a91xx_config/ipc_password",
            "gsc_config/user, gsc_config/password",
            "hb_config/user, hb_config/password",
        ],
        "cgi": "test.cgi (operator), config_json_o.cgi (operator)",
        "prerequisite": "Operator-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-LPV-07",
        "severity": "HIGH",
        "title": "Tarslip via restorecfg.cgi (admin) — arbitrary file write as sdk user",
        "detail": (
            "Admin-level restorecfg.cgi extracts uploaded backup archive with: "
            "tar zxvf /tmp/backup.zip -C /tmp/ "
            "No path traversal sanitization. APPUSR=sdk; sdk has write access to "
            "/usr/local/packages/fflprapp/. "
            "Craft backup.zip with entries like: "
            "../../usr/local/packages/fflprapp/models/onnx_model_full_integer_quant.tflite "
            "-> write arbitrary file outside /tmp/ to any sdk-writable path. "
            "Chain: overwrite TFLite model + adversarial ML model -> suppress plate reads. "
            "Or: overwrite fflprapp config -> disable allow/block list enforcement."
        ),
        "cgi": "restorecfg.cgi (admin)",
        "appusr": "sdk",
        "exploit_outline": (
            "import tarfile, io; payload=b''; t=tarfile.open('b.tar.gz','w:gz'); "
            "ti=tarfile.TarInfo('../../usr/local/packages/fflprapp/models/Symbol.tflite'); "
            "ti.size=len(payload); t.addfile(ti, io.BytesIO(payload)); t.close(); "
            "POST b.tar.gz to restorecfg.cgi"
        ),
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
]
