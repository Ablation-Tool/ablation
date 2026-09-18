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
]
