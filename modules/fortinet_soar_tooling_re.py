"""
FortiSOAR, IPS sandbox, n8n/Itential FortiManager adapters, FortiOS Python API RE
Sources:
  - fortisoar-connector-engine/ (FortiSOAR connector SDK; FORTINET CONFIDENTIAL)
  - ips-bph-framework/ (Black Phoenix IPS sandbox; Fortinet internal; 2019)
  - npm-packages/n8n-nodes-fortimanager-1.8.0.tgz (n8n FortiManager node)
  - npm-packages/itentialopensource-adapter-fortimanager-1.0.11.tgz (Itential adapter)
  - fortiosapi/ (Python FortiOS API library)
  - linux-repo/ (FortiClient RPM repository config)
  - connector-fortinet-fortindr-cloud/ (FortiNDR Cloud SOAR connector)
"""

# ---------------------------------------------------------
# FortiSOAR Connector Engine (internal SDK)
# ---------------------------------------------------------
FORTISOAR_CONNECTOR_ENGINE = {
    "id":       "FSOAR-ENGINE",
    "product":  "FortiSOAR Connector Engine -- SOAR connector SDK (FORTINET CONFIDENTIAL)",
    "source":   "fortisoar-connector-engine/ (Copyright 2008-2022 Fortinet Inc.)",
    "note":     "Labeled FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE -- leaked/published",

    "architecture": (
        "FortiSOAR connector SDK that all SOAR integration connectors are built on. "
        "Defines the Connector abstract base class with lifecycle hooks: "
        "  - init() -- connector initialization "
        "  - on_app_start(config, active) -- startup "
        "  - on_add_config/on_delete_config/on_update_config -- credential management "
        "  - on_activate/on_deactivate -- runtime toggling "
        "  - teardown(config) -- cleanup "
        "All 590+ FortiSOAR marketplace connectors extend this Connector base class."
    ),

    "credential_handling": (
        "Connector configs (credentials) are passed as dicts to lifecycle hooks. "
        "Connectors store credentials in FortiSOAR's encrypted credential store "
        "(not in the connector itself). "
        "The engine passes decrypted credentials to the connector at runtime. "
        "FortiSOAR credential store location: PostgreSQL database on the FortiSOAR appliance."
    ),

    "result_class": {
        "status":  "_status: 'Success' or 'Failure'",
        "message": "_message: human-readable result",
        "note": (
            "Connectors return Result objects. "
            "If a connector's execute() method raises ConnectorError, "
            "the SOAR playbook catches it and logs the error but DOES NOT alert the SOC. "
            "A compromised connector that raises ConnectorError for all actions "
            "silently breaks all playbook automation without triggering an alert."
        ),
    },

    "constants": {
        "STATE_AVAILABLE":     "Connector operational",
        "STATE_DISCONNECTED":  "Backend unreachable",
        "STATE_NOT_CONFIGURED": "No credentials configured",
        "STATE_DEACTIVATED":   "Connector disabled",
        "NOTIFICATION_BASED_INGESTION": "'notification' -- webhook-based event ingestion mode",
    },

    "attack_surface": (
        "FortiSOAR SOAR platform integrates with 590+ security tools. "
        "The connector engine is the trust boundary between the SOAR playbook "
        "and external security tools. "
        "A malicious connector (or a compromised legitimate connector) can: "
        "  1. Exfiltrate all credentials passed via config dict. "
        "  2. Return forged threat intelligence to influence SOC decision-making. "
        "  3. Suppress incidents by returning Status=Success without acting. "
        "  4. Pivot to other security tools using credentials passed by the engine."
    ),
}


# ---------------------------------------------------------
# IPS Black Phoenix (BPH) Framework (Fortinet internal sandbox)
# ---------------------------------------------------------
IPS_BPH_FRAMEWORK = {
    "id":       "IPS-BPH",
    "product":  "FortiIPS Black Phoenix (BPH) Framework -- internal malware analysis sandbox",
    "source":   "ips-bph-framework/ (Copyright 2019 Fortinet Inc.; Apache 2.0)",
    "version":  "1.0.0 (2019-08-08 first release)",

    "architecture": (
        "Automated malware analysis framework for IPS signature development. "
        "Components: "
        "  - Web controller (HTTP server; serves sample downloads) "
        "  - Windows agent (receives + executes samples in Windows VMs) "
        "  - VirtualBox server (manages analysis VMs) "
        "  - Template server (provides clean VM snapshots) "
        "  - Plugin system (/plugins/ directory; extensible analysis modules)"
    ),

    "config_file":      "/conf/blackphenix.conf (.ini format)",
    "session_storage":  "/session/ directory; per-project + per-sample subdirectories",
    "tmp_dir":          "/tmp/ (standard Linux temp)",

    "sample_analysis": (
        "BphLabFile (sample.py): pefile.PE parser for PE32 executables. "
        "Extracts: imports (DLL name -> function name -> address), exports. "
        "Sample download URL: http://<web_controller>/<web_folder>/session/<path>/<filename>. "
        "MD5 hash computed for deduplication."
    ),

    "significance": (
        "The BPH framework is Fortinet's internal tool for developing IPS signatures "
        "against novel malware samples. "
        "Understanding BPH's sample ingestion pipeline is relevant for: "
        "  1. Timing attacks: submitting malware that detects sandbox behavior and alters execution. "
        "  2. FortiGuard threat intelligence: BPH feeds the IPS signature development pipeline, "
        "     so evasion at BPH = delayed or missed IPS signature coverage. "
        "  3. The web controller serves sample files over HTTP without TLS "
        "     (BPH_WEB_SERVER = 'http://...'): sample downloads are interceptable."
    ),
}


# ---------------------------------------------------------
# n8n FortiManager node: session caching + allowUnauthorizedCerts
# ---------------------------------------------------------
N8N_FORTIMANAGER_NODE = {
    "id":       "N8N-FMG",
    "product":  "n8n-nodes-fortimanager v1.8.0 -- FortiManager workflow automation node",
    "source":   "npm-packages/n8n-nodes-fortimanager-1.8.0.tgz",

    "api_methods": {
        "get":     "FortiManager JSON-RPC 'get' method (read operations)",
        "add":     "JSON-RPC 'add' (create objects)",
        "set":     "JSON-RPC 'set' (update objects)",
        "update":  "JSON-RPC 'update' (modify objects)",
        "delete":  "JSON-RPC 'delete' (remove objects)",
        "exec":    "JSON-RPC 'exec' (execute commands -- highest privilege)",
    },

    "authentication": {
        "types":    "session (username/password) or api-key",
        "session_cache": (
            "Sessions are cached in memory for 10 minutes (SESSION_TTL = 10 * 60 * 1000 ms). "
            "Cache key: baseUrl_username. "
            "In a shared n8n instance with multiple FortiManager credentials: "
            "  If two users share the same FortiManager URL but different usernames, "
            "  their sessions are stored separately. "
            "  BUT: if the cache key collides (same baseUrl + same username for different ADOMs), "
            "  Session A can be reused for Session B's requests."
        ),
        "allowUnauthorizedCerts": (
            "n8n FortiManager credential has allowUnauthorizedCerts option. "
            "If set: TLS certificate validation is disabled. "
            "Enables MITM of FortiManager API traffic in the n8n -> FortiManager path."
        ),
    },

    "dangerous_operations": {
        "exec_method": (
            "JSON-RPC 'exec' method executes FortiManager CLI commands. "
            "Example: exec sys_update-device-db 'adom root, device FGT-001' "
            "triggers policy push to managed devices. "
            "This is equivalent to FortiJump (CVE-2024-47575) but via authenticated API. "
            "A compromised n8n instance with FortiManager credentials "
            "= full control of all FortiManager-managed FortiGate firewalls."
        ),
        "assign_package": (
            "API /securityconsole/install/assignPackage: assigns + installs policy package "
            "to all managed devices. "
            "Attacker workflow: modify a policy object -> assign package -> install -> "
            "firewall rules changed across the entire enterprise."
        ),
        "add_device": (
            "API /dvm/device/addDevice: adds a rogue FortiGate to FortiManager management. "
            "Combined with CVE-2024-47575 (FortiJump) for FGFM registration bypass."
        ),
    },
}


# ---------------------------------------------------------
# Itential FortiManager adapter
# ---------------------------------------------------------
ITENTIAL_FORTIMANAGER_ADAPTER = {
    "id":       "ITENTIAL-FMG",
    "product":  "Itential FortiManager Adapter v1.0.11 -- network automation integration",
    "source":   "npm-packages/itentialopensource-adapter-fortimanager-1.0.11.tgz",

    "description": (
        "FortiManager adapter for the Itential Automation Platform (IAP). "
        "Implements all FortiManager REST API operations for network automation workflows. "
        "Uses emitter-pattern callbacks for async operation handling. "
        "Extends AdapterBaseCl (Itential base class) -- handles HTTP transport, "
        "authentication, retry logic, and result transformation."
    ),

    "database_dependency": (
        "The adapter includes mongoDbConnection.js -- uses MongoDB to store adapter state, "
        "workflow results, and potentially credentials. "
        "A MongoDB instance without authentication (common in self-hosted IAP deployments) "
        "exposes all FortiManager operation history and possibly stored credentials."
    ),

    "significance": (
        "Itential IAP is used in enterprise network automation. "
        "The FortiManager adapter allows Itential workflows to modify FortiGate configurations "
        "at enterprise scale. "
        "Compromise path: Itential IAP -> FortiManager adapter -> FortiManager API -> "
        "all managed FortiGate firewalls."
    ),
}


# ---------------------------------------------------------
# fortiosapi: Python FortiOS API library
# ---------------------------------------------------------
FORTIOSAPI_PYTHON = {
    "id":       "FAPI-PY",
    "product":  "fortiosapi -- Python FortiOS REST API library",
    "source":   "fortiosapi/fortiosapi/fortiosapi.py",

    "description": (
        "Python library for FortiGate CMDB REST API. "
        "Supports: GET, POST, PUT, DELETE on all CMDB objects. "
        "Authentication: session cookie (login/logout) or API token header. "
        "TLS: optional certificate verification (verify=True default)."
    ),

    "known_patterns": (
        "fortiosapi is the library used by the Ansible fortios collection. "
        "Session management: HTTPS login with username/password, stores session cookie. "
        "The library does not implement token rotation or session expiry checks. "
        "A long-lived session token from a fortiosapi session is valid until FortiGate "
        "reboots or the idle timeout is reached (default 5-60 minutes)."
    ),
}


# ---------------------------------------------------------
# FortiClient Linux RPM repository
# ---------------------------------------------------------
FORTICLIENT_LINUX_REPO = {
    "id":       "FCL-REPO",
    "product":  "FortiClient Linux RPM repository (RHEL/CentOS/Fedora)",
    "source":   "linux-repo/fortinet_x86_64.repo + fortinet_aarch64.repo",

    "repository_url": "https://repo.fortinet.com/repo/forticlient/8.0/el/os/{arch}",
    "gpg_key":        "https://repo.fortinet.com/repo/forticlient/8.0/el/os/{arch}/RPM-GPG-KEY",
    "gpg_check":      "gpgcheck=1 (verified)",

    "note": (
        "The FortiClient 8.0 RPM repository is the distribution channel for: "
        "  - FortiClient Linux agent (includes certd daemon; see CERTD-F01). "
        "  - FortiClient VPN-only package. "
        "The repository is GPG-signed (gpgcheck=1), so package tampering requires "
        "either the Fortinet GPG private key or a MITM that intercepts the repo URL "
        "before GPG verification (unlikely on HTTPS). "
        "Packages in this repo include the certd binary and libcertd.so analyzed in CERTD-ARCH."
    ),
}


# ---------------------------------------------------------
# FortiNDR Cloud SOAR connector
# ---------------------------------------------------------
FORTINDR_CLOUD_CONNECTOR = {
    "id":       "FNDR-CONN",
    "product":  "FortiNDR Cloud SOAR connector -- threat hunting + PCAP retrieval via SOAR",
    "source":   "connector-fortinet-fortindr-cloud/fortinet-fortindr-cloud/",
    "files":    "connector.py, constants.py, operations.py",

    "description": (
        "SOAR connector integrating FortiNDR Cloud (cloud-based NDR) with FortiSOAR. "
        "Operations: query network events, threat hunt, retrieve PCAP captures. "
        "FortiNDR Cloud processes on-premises sensor telemetry uploaded to the cloud. "
        "API access grants read access to ALL network traffic metadata from the organization."
    ),

    "attack_value": (
        "FortiNDR Cloud API key compromise -> "
        "  1. Query all network events: discover internal infrastructure, lateral movement, "
        "     command-and-control beacons, data exfiltration patterns. "
        "  2. Retrieve PCAP captures: reconstruct unencrypted traffic. "
        "  3. Threat hunt: identify which endpoints are under investigation "
        "     (defender visibility into attacker-aware hunts). "
        "Combined with FortiSOAR SOAR access: turn the defender's own telemetry against them "
        "to identify detection rules and avoid triggering them."
    ),
}


# ---------------------------------------------------------
# Consolidated FortiSOAR + tooling attack chain
# ---------------------------------------------------------
FORTISOAR_ECOSYSTEM_ATTACK_CHAIN = {
    "id":       "FSOAR-CHAIN",
    "product":  "FortiSOAR + connected tools -- lateral movement chain",

    "chain": (
        "Step 1: Compromise FortiSOAR appliance (via CVE in underlying OS or web UI). "
        "Step 2: Extract connector credentials from FortiSOAR PostgreSQL database. "
        "         Credentials include: FortiManager API token, FortiNDR API key, "
        "         FortiSIEM credentials, all 590 connected security tools. "
        "Step 3: Use FortiManager credentials -> install_policy() on all managed FortiGates. "
        "         Result: modify firewall rules enterprise-wide. "
        "Step 4: Use FortiNDR API key -> query all network telemetry. "
        "         Result: complete visibility into defender detection capabilities. "
        "Step 5: Use FortiSIEM credentials -> suppress incidents, modify watchlists. "
        "         Result: blind the SOC to ongoing intrusion. "
        "Step 6: Use FortiPAM credentials (FPAM-F03) -> retrieve privileged credentials "
        "         for all PAM-managed systems (servers, network devices, cloud accounts). "
        "         Result: full enterprise compromise from a single SOAR appliance."
    ),

    "single_point_of_failure": (
        "The FortiSOAR appliance is a single point of compromise for the entire "
        "Fortinet security stack. All product integrations funnel through SOAR credentials. "
        "This is architecturally equivalent to the Active Directory DPAPI-protected "
        "credential store in Windows environments -- one breach -> all credentials."
    ),
}
