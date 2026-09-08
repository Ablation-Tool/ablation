"""
AXIS StoreDataManager (Cognimatics TrueView DataManager) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS StoreDataManager v1.6.10
Package: AXIS_StoreDataManager_1_06_10.deb
Type: Debian server-side app (NOT a camera EAP)
Stack: PHP5 / MySQL 5.0+ / Zend Framework / Apache2
Extracted: /tmp/axis_sdm_re/usr/share/cognimatics/datamanager/

Auth: HTTP Digest (RFC 2069) against MySQL users table.
  digest_helper_password: HA1 = MD5(user:realm:pass), realm = APPLICATION_REALM
  nonce: uniqid() (microsecond timestamp, predictable)
  No CSRF protection on any state-changing POST

Obfuscation: application/abc.php injects cm_decrypt2/cm_decrypt_binary2 via
5+ layers eval(base64_decode(hex(...))) at runtime (~331KB blob).

Protocol v4 (decodeVersion4): ##-delimited fields, field[1] = plaintext camera password.
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-SDM"
LABEL = "StoreDataManager: hardcoded backdoor, static salt, SQL injection, debug artifact"

STATIC_SALT = "qvUReYOddaOWw7qkb6QfHAd3kgUAo6"
REALM = "TrueView Web Report"
BACKDOOR_EMAIL = "support@cognimatics.com"
BACKDOOR_PASS = "pass123"
BACKDOOR_DIGEST_HA1 = "f66742c7d3869b5c57fa0cfa3c2b0f25"

FINDINGS = [
    {
        "id": "AXIS-SDM-01",
        "severity": "CRITICAL",
        "title": "Hardcoded backdoor account: support@cognimatics.com:pass123 (admin)",
        "detail": (
            "maintenance/admin/supportUser.php creates support@cognimatics.com with ACL role = "
            "first role (admin-equivalent) on any installation. "
            "Password hash: MD5(STATIC_SALT + 'pass123' + dynamicSalt). "
            "HTTP Digest HA1: MD5('support@cognimatics.com:TrueView Web Report:pass123') = "
            "f66742c7d3869b5c57fa0cfa3c2b0f25. "
            "Present in all installations; no configuration required by installer."
        ),
        "credential": f"{BACKDOOR_EMAIL}:{BACKDOOR_PASS}",
        "digest_ha1": BACKDOOR_DIGEST_HA1,
        "file": "maintenance/admin/supportUser.php",
        "prerequisite": "Network access to SDM web interface",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-SDM-02",
        "severity": "CRITICAL",
        "title": "Static salt qvUReYOddaOWw7qkb6QfHAd3kgUAo6 — all password hashes pre-crackable",
        "detail": (
            "STATIC_SALT = 'qvUReYOddaOWw7qkb6QfHAd3kgUAo6' hardcoded in "
            "datamanager_installation/public/installation/index.php:22 with comment \"DON'T CHANGE\". "
            "Login SQL: MD5(CONCAT('qvUReYOddaOWw7qkb6QfHAd3kgUAo6', ?, password_salt)) "
            "where second factor is user-specific. "
            "Known static salt enables precomputed rainbow tables against all password hashes. "
            "MigrateCompany.php:423: migrated users get MD5(STATIC_SALT + '' + dynamicSalt) "
            "= empty password after migration."
        ),
        "static_salt": STATIC_SALT,
        "file": "datamanager_installation/public/installation/index.php:22",
        "prerequisite": "Read access to MySQL database OR HTTP Digest nonce brute-force (uniqid = microsecond timestamp)",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-SDM-03",
        "severity": "HIGH",
        "title": "SQL injection in camera name search: UPPER(camera.name) LIKE UPPER('%$word%')",
        "detail": (
            "Cameras.php:503 camera name search: "
            "UPPER(camera.name) LIKE UPPER('%$word%') "
            "$word comes from space-split of user-supplied search string. "
            "No PDO binding; raw string interpolation into Zend_Db_Select::where(). "
            "Zend_Db_Select::where() passes string verbatim to MySQL when not parameterized. "
            "Endpoint accessible to authenticated users (role unclear from source)."
        ),
        "file": "application/modules/core/models/Cameras.php:503",
        "pattern": "UPPER(camera.name) LIKE UPPER('%$word%')",
        "prerequisite": "Authenticated session (standard user or above)",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-SDM-04",
        "severity": "MEDIUM",
        "title": "/tmp/decrypted_json debug artifact written on every API call",
        "detail": (
            "Abstract.php:23: decryptAndDecodeJSON() calls fopen/fputs/fclose "
            "to write decrypted payload to /tmp/decrypted_json unconditionally on every call. "
            "All decrypted camera data (protocol v4 ##-delimited: camera name, serial, "
            "count data) written to local filesystem. "
            "Any local process with /tmp read access recovers full surveillance metadata stream."
        ),
        "file": "application/modules/core/controllers/Abstract.php:23",
        "debug_path": "/tmp/decrypted_json",
        "prerequisite": "Local filesystem read access to /tmp (post-RCE or server-side file read)",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-SDM-05",
        "severity": "MEDIUM",
        "title": "Camera password in plaintext in protocol v4 push field[1]",
        "detail": (
            "Protocol v4 (decodeVersion4): ##-delimited fields. "
            "[0]=username [1]=password [2]=version [3]=cameraName [4]=serial "
            "[5]=cnttime [6]=nbrOfTypes ... "
            "Camera plaintext password embedded in field[1] of EVERY data push from cameras. "
            "Attacker who can MitM camera-to-SDM traffic or read the debug artifact "
            "recovers all camera credentials passively."
        ),
        "field_layout": "[0]=username [1]=password [2]=version [3]=cameraName [4]=serial",
        "prerequisite": "Network position on camera-to-SDM path or /tmp/decrypted_json read (SDM-04)",
        "status": "UNPATCHED",
        "cve": None,
    },
]
