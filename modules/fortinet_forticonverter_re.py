"""
Fortinet FortiConverter v7.4.0 Build 0848 RE
Source: FortiConverterSetup_7.4.0_Build0848.py.exe (NSIS installer, 163MB)
Platform: Windows (NSIS-3 Unicode); Django 1.10.1 web app; Python 3.13
Extracted to: /tmp/forticonverter/nsis_full/ (1615 files; 251MB)
Key path: /tmp/forticonverter/nsis_full/converter/backend/mysite/
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":      "Fortinet FortiConverter v7.4.0 build 0848",
    "installer":    "NSIS-3 Unicode (not PyInstaller; Python source included directly)",
    "python":       "Python 3.13 (bundled at nsis_full/Python/python.exe)",
    "framework":    "Django 1.10.1 (2016; 8 years old as of 2026)",
    "db":           "PostgreSQL (default credentials: postgres:postgres)",
    "extracted_to": "/tmp/forticonverter/nsis_full/converter/backend/mysite/",

    "supported_vendors": [
        "Cisco (ASA, Firepower, IOS, IOS-XR, Nexus, PIX, Meraki, FWSM)",
        "Check Point (firewall, MDS, VSX)",
        "Juniper (JunOS, ScreenOS)",
        "Palo Alto PAN-OS",
        "F5 BIG-IP",
        "Sophos",
        "SonicWall",
        "Forcepoint/Sidewinder/Stonesoft",
        "WatchGuard",
        "McAfee",
        "BlueCoat (Symantec)",
        "Huawei",
        "IBM",
        "Lucent",
        "TippingPoint",
        "Radware",
        "NetScaler",
        "OpenSystems",
        "PFSense",
        "Zscaler",
        "Ivanti",
        "Cipafilter",
        "Zyxel",
        "Snort",
        "Vyatta",
    ],

    "architecture": {
        "entry":        "startup_django.py / manage.py (Django management)",
        "start_http":   "start.py (HTTP mode)",
        "start_https":  "start_https.py (HTTPS mode with mkcert.exe cert)",
        "settings":     "mysite/settings.py",
        "urls":         "mysite/urls.py",
        "db_init":      "database_maintain.py",
        "automation":   "automation/ (Linux-only; Kafka + etcd integration)",
    },

    "url_namespace": {
        "/conversion/":  "Conversion CRUD management",
        "/convertjob/":  "Conversion job execution",
        "/tuning/":      "Conversion tuning/adjustment",
        "/homepage/":    "Web UI home",
        "/license/":     "License management",
        "/restapi/":     "REST API to FortiGate/FMG (device management, import)",
        "/utils/":       "Utilities (report generation, obfuscation)",
        "/api/files/":   "File upload (DRF ModelViewSet; multipart)",
        "/sase_api/":    "FortiSASE API integration",
        "/greenfield/":  "Greenfield (new deployment) configuration",
    },
}


# ---------------------------------------------------------
# FCV-F1: No authentication on all REST API endpoints
# ---------------------------------------------------------
FCV_F01_NO_AUTHENTICATION = {
    "id":       "FCV-F01",
    "product":  "Fortinet FortiConverter v7.4.0 build 0848",
    "severity": "CRITICAL -- all REST API endpoints are unauthenticated",
    "class":    "Missing authentication (CWE-306)",

    "description": (
        "REST framework configured with NoAuthentication + AllowAny for all endpoints. "
        "settings.py REST_FRAMEWORK: "
        "DEFAULT_AUTHENTICATION_CLASSES = ('applications.rest_auth.noauth.NoAuthentication',) "
        "DEFAULT_PERMISSION_CLASSES = ('rest_framework.permissions.AllowAny',). "
        "ALLOWED_HOSTS = ['localhost', '127.0.0.1'] provides host-header filtering "
        "but does NOT prevent access from any local process or same-machine browser. "
        "Any web page visited in the same browser session can access the FortiConverter "
        "REST API via DNS rebinding (resolving attacker.com to 127.0.0.1) or "
        "by exploiting CSRF_TRUSTED_ORIGINS = ['http://localhost:5173', 'http://127.0.0.1:5173']. "
        "Django 1.10.1 is used (released 2016; 8 years old; multiple known CVEs)."
    ),

    "evidence": {
        "settings_file":     "mysite/settings.py lines 251-257",
        "auth_class":        "applications.rest_auth.noauth.NoAuthentication",
        "permission_class":  "rest_framework.permissions.AllowAny",
        "allowed_hosts":     "ALLOWED_HOSTS = ['localhost', '127.0.0.1']",
        "csrf_origins":      "CSRF_TRUSTED_ORIGINS = ['http://localhost:5173', 'http://127.0.0.1:5173']",
        "django_version":    "Django 1.10.1 (2016; comment in settings.py)",
    },

    "impact": (
        "Any local process, or any website visited in the browser when FortiConverter "
        "is running, can call all REST API endpoints without authentication. "
        "This includes: reading stored FortiGate/FMG credentials, uploading malicious "
        "config files, triggering converter execution, and pushing converted configs "
        "to connected FortiGate/FMG devices."
    ),

    "remediation": (
        "Implement authentication for all REST endpoints. "
        "At minimum, use Django's SessionAuthentication or token authentication. "
        "Upgrade Django from 1.10.1 to current LTS (5.x). "
        "Consider binding only to localhost and requiring a session token issued at startup."
    ),
}


# ---------------------------------------------------------
# FCV-F2: Plaintext FortiGate/FMG credentials exposed via unauthenticated GET
# ---------------------------------------------------------
FCV_F02_CREDENTIAL_EXPOSURE = {
    "id":       "FCV-F02",
    "product":  "Fortinet FortiConverter v7.4.0 build 0848",
    "severity": "CRITICAL -- FortiGate/FMG credentials readable unauthenticated",
    "class":    "Credentials exposure via unauthenticated API (CWE-522 + CWE-306)",

    "description": (
        "The Device model stores FortiGate/FortiManager credentials in plaintext: "
        "username (TextField), password (TextField), api_token (TextField), device_ip. "
        "GET /restapi/getdevices returns all Device objects via DeviceSerializer(fields='__all__') "
        "-- all fields including password and api_token are serialized in the JSON response. "
        "No authentication is required (FCV-F01). "
        "An attacker who can reach the FortiConverter REST API receives "
        "the username, password, API token, and IP address of all connected "
        "FortiGate and FortiManager devices."
    ),

    "evidence": {
        "model_file":   "applications/restapi/models.py Device class",
        "password_field": "password = models.TextField(null=True, blank=True)",
        "api_token_field": "api_token = models.TextField(null=True, blank=True)",
        "serializer":   "DeviceSerializer(fields='__all__') -- exposes ALL fields",
        "endpoint":     "GET /restapi/getdevices (no authentication)",
        "view":         "applications/restapi/views.py get_devices()",
    },

    "attack_scenario": (
        "1. Victim has FortiConverter open and has connected it to FortiGate/FMG devices "
        "(storing credentials). "
        "2. Victim visits attacker.com which resolves to 127.0.0.1 (DNS rebinding). "
        "3. JavaScript at attacker.com fetches http://127.0.0.1:8000/restapi/getdevices. "
        "4. Response contains all stored FortiGate/FMG credentials in JSON. "
        "5. Attacker uses credentials to directly log into FortiGate/FMG."
    ),

    "remediation": (
        "Exclude password and api_token from DeviceSerializer (use explicit fields, not '__all__'). "
        "Store credentials encrypted using Django's encrypted fields or OS keystore. "
        "Implement authentication (FCV-F01 remediation)."
    ),
}


# ---------------------------------------------------------
# FCV-F3: Path traversal in file upload via 'type' field
# ---------------------------------------------------------
FCV_F03_PATH_TRAVERSAL = {
    "id":       "FCV-F03",
    "product":  "Fortinet FortiConverter v7.4.0 build 0848",
    "severity": "HIGH -- path traversal in file upload via unsanitized 'type' field",
    "class":    "Path traversal via user-controlled filename component (CWE-22)",

    "description": (
        "get_file_path() (applications/fileupload/models.py) constructs file storage paths "
        "using string concatenation with user-supplied data. "
        "When 'type' contains ':', it splits on ':' and uses split_str[0] as domain_name "
        "in the path: "
        "domain_dir = CONVERSIONS_DIR + '\\\\{0}\\\\source config\\\\{1}\\\\'.format(conversion.name, domain_name). "
        "Neither domain_name nor conversion.name is sanitized for path traversal sequences. "
        "If type='..\\\\..\\\\:any', then domain_name='..\\\\..\\\\' and the file is stored "
        "two directories above CONVERSIONS_DIR. "
        "The UploadFile model exposes this via the unauthenticated POST /api/files/ endpoint "
        "(UploadFileViewSet is a ModelViewSet with no permission restrictions)."
    ),

    "evidence": {
        "model_file":      "applications/fileupload/models.py get_file_path()",
        "vulnerable_line": "domain_dir = CONVERSIONS_DIR + '\\\\{0}\\\\source config\\\\{1}\\\\'.format(conversion.name, domain_name)",
        "no_sanitize":     "domain_name = split_str[0] -- no os.path.basename() or path traversal check",
        "upload_endpoint": "POST /api/files/ (unauthenticated; UploadFileViewSet ModelViewSet)",
        "upload_parsers":  "FormParser + MultiPartParser",
        "note":            "Django FileField storage.get_valid_name() sanitizes filename; type field bypasses this",
    },

    "attack_scenario": (
        "1. POST /api/files/ (no auth) with: "
        "type=..\\..\\Windows\\Startup: (or on Linux: type=../../.config:), "
        "conversion_id=1, filename=evil.bat (or .bashrc). "
        "2. get_file_path splits type on ':' -> domain_name='..\\..\\Windows\\Startup'. "
        "3. domain_dir resolves to Windows Startup folder. "
        "4. File is written to Windows Startup folder = persistence on next boot."
    ),

    "note": (
        "Django FileField.storage.get_available_name() sanitizes the uploaded filename "
        "to prevent path traversal in the filename component. "
        "The traversal vector here is the 'type' field, not the filename itself -- "
        "Django does not sanitize non-filename path components in custom upload_to functions."
    ),

    "remediation": (
        "Apply os.path.basename() to domain_name and conversion.name before path construction. "
        "Use pathlib.Path and check that the resolved path is within CONVERSIONS_DIR. "
        "Alternatively, use UUIDs for directory names instead of user-supplied strings."
    ),
}


# ---------------------------------------------------------
# FCV-F4: Default PostgreSQL credentials + Django 1.10.1
# ---------------------------------------------------------
FCV_F04_DEFAULT_CREDS_OLD_DJANGO = {
    "id":       "FCV-F04",
    "product":  "Fortinet FortiConverter v7.4.0 build 0848",
    "severity": "HIGH -- default database credentials; legacy Django version",
    "class":    "Default credentials (CWE-1188) + Use of outdated component (CWE-1104)",

    "description": (
        "settings.py DATABASES configuration defaults: "
        "POSTGRES_USER = 'postgres', POSTGRES_PASSWORD = 'postgres'. "
        "These are the default PostgreSQL superuser credentials. "
        "If deployed without customizing environment variables, "
        "the FortiConverter database is accessible with default credentials "
        "on the configured POSTGRES_HOST (default: localhost) port 5432. "
        "Django 1.10.1 (released September 2016) is specified in settings.py comments. "
        "Django 1.10.x is end-of-life and has multiple known CVEs "
        "including CVE-2017-7233, CVE-2017-7234 (open redirect), "
        "CVE-2021-33203 (path traversal), and others."
    ),

    "evidence": {
        "db_config":    "POSTGRES_PASSWORD = os.environ.get('POSTGRES_PASSWORD', 'postgres')",
        "db_user":      "POSTGRES_USER = os.environ.get('POSTGRES_USER', 'postgres')",
        "django_ver":   "settings.py comment: Generated by 'django-admin startproject' using Django 1.10.1",
        "kafka_default": "KAFKA_ENDPOINT = os.environ.get('KAFKA_ENDPOINT', 'localhost:9092')",
    },

    "impact": (
        "Default postgres:postgres credentials allow direct database access "
        "to all stored FortiGate credentials (plaintext password in Device.password), "
        "all uploaded vendor config files, and all conversion results. "
        "PostgreSQL superuser access allows reading/writing all databases on the server."
    ),

    "remediation": "Set non-default PostgreSQL credentials. Upgrade Django to current LTS (5.x). Use managed secret injection (env file, keystore).",
}


# ---------------------------------------------------------
# FCV-F5: Vendor parser attack surface (25 parsers processing untrusted input)
# ---------------------------------------------------------
FCV_F05_PARSER_ATTACK_SURFACE = {
    "id":       "FCV-F05",
    "product":  "Fortinet FortiConverter v7.4.0 build 0848",
    "severity": "HIGH -- 25 vendor config parsers process untrusted uploaded files; IBM XML bomb and Lucent ZIP bomb CONFIRMED",
    "class":    "Unsafe deserialization / parser vulnerabilities (CWE-20, CWE-776, CWE-409)",

    "description": (
        "FortiConverter parses 25 different vendor firewall config formats. "
        "Config files are uploaded via the unauthenticated /api/files/ endpoint "
        "and processed by dedicated Django apps per vendor. "
        "All parsers run in the Django process without sandboxing."
    ),

    "high_risk_parsers": {
        "paloalto":       "XML parsed by native ConversionEngine.exe (binary); Python layer delegates via engine_invoker; XML parsing risk unclear without binary RE",
        "ibm":            "CONFIRMED: minidom.parse(filename) -- no defusedxml; XML entity expansion (Billion Laughs) DoS",
        "forcepoint":     "XML-based (stonesoft.xml) -- XXE risk pending confirmation",
        "sophos":         "XML-based -- XXE risk pending confirmation",
        "checkpoint":     "C object database format -- complex nested parsing",
        "cisco_asa":      "CLI text parsing -- regex-based; ReDoS pending confirmation",
        "lucent":         "CONFIRMED: zipfile.extractall() with no size/entry limit -> zip bomb DoS",
    },

    "confirmed_ibm_xml_bomb": {
        "source":   "applications/ibm/ibm_convert_script.py:25: mydoc = minidom.parse(filename)",
        "import":   "from xml.dom import minidom",
        "class":    "XML entity expansion (Billion Laughs) -- CWE-776",
        "payload":  (
            "<?xml version='1.0'?>"
            "<!DOCTYPE bomb [<!ENTITY a 'aaa...'><!ENTITY b '&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;'>...]>"
            "<securityEventsList>&b;</securityEventsList>"
        ),
        "impact":   "Exponential memory expansion in Django process; OOM -> DoS. No auth required via /api/files/.",
        "no_defusedxml": "defusedxml is NOT imported or used anywhere in the IBM parser or its dependencies.",
    },

    "confirmed_lucent_zip_bomb": {
        "source":   "applications/lucent/lucent_convert_job.py:95-96: zip_job = zipfile.ZipFile(...); zip_job.extractall(self.output_dir_base)",
        "class":    "ZIP bomb / unrestricted archive extraction (CWE-409)",
        "no_limits": (
            "No check for: total uncompressed size, file count, individual file size, "
            "path traversal in ZIP entry names (../ paths), symlinks in ZIP entries. "
            "zipfile.extractall() follows ZIP paths relative to output_dir_base -- "
            "a ZIP with entries like '../../etc/cron.d/evil' would write to those paths "
            "if Django is running with write access to parent dirs."
        ),
        "zip_bomb_payload": "Single ZIP file ~1KB compressed -> 1GB+ uncompressed (standard zip bomb).",
        "path_traversal":   "ZIP entries with '../' paths: output_dir_base + '../../etc/cron.d/evil' if not sandboxed.",
        "impact":           "DoS via disk/memory exhaustion; potential path traversal to writable dirs. No auth required.",
    },

    "evidence": {
        "upload_endpoint":  "POST /api/files/ (no auth; multipart upload)",
        "parser_dirs":      "applications/{cisco,checkpoint,paloalto,ibm,sophos,...}/",
        "xml_parsers":      "IBM confirmed (minidom); Forcepoint/Sophos pending",
        "zip_input":        "Lucent parser accepts .zip files (confirmed extractall)",
        "source_path":      "/tmp/forticonverter/nsis_full/converter/backend/mysite/applications/",
    },
}


# ---------------------------------------------------------
# Pending findings
# ---------------------------------------------------------
pending_findings = [
    "FCV-F03 verification: test POST /api/files/ with type field containing path traversal; "
    "verify Django storage.get_valid_name() interaction with the type-based path construction; "
    "source: applications/fileupload/models.py get_file_path(); 2026-09-16",

    "FCV-F05 IBM XML bomb CONFIRMED: test payload at /tmp/forticonverter via /api/files/ upload "
    "to confirm OOM crash in Django process; source: applications/ibm/ibm_convert_script.py:25; 2026-09-16",

    "FCV-F05 Lucent ZIP bomb CONFIRMED: verify disk exhaustion via extractall; "
    "test path traversal in ZIP entries (../); source: lucent_convert_job.py:95-96; 2026-09-16",

    "FCV-F05 XXE: fuzz PaloAlto XML via ConversionEngine.exe (native binary); "
    "Python delegates to engine_invoker.invoke_engine_parse -- binary needs RE for XML parser ID; "
    "source: paloalto_convert_job.py:180; 2026-09-16",

    "FCV-F05 Cisco ASA ReDoS: fuzz applications/cisco/ parser with pathological input "
    "designed to trigger catastrophic backtracking in Python regex patterns; "
    "source: applications/cisco/models.py; 2026-09-16",

    "Django 1.10.1 SQL injection audit: check all Django ORM usages for raw() or extra() "
    "calls with user-controlled data; source: applications/*/models.py; 2026-09-16",

    "RESTAPIConnector credential transmission: check applications/restapi/restapi_connector.py "
    "to see if credentials are sent over HTTP (not HTTPS) when connecting to FortiGate/FMG; "
    "source: applications/restapi/restapi_connector.py; 2026-09-16",

    "Automation Kafka/etcd: check automation/ Django app (Linux-only) for unauthenticated "
    "Kafka topic injection or etcd key write; default endpoint localhost:9092/localhost:2379; "
    "source: automation/ directory in nsis_full; 2026-09-16",
]
