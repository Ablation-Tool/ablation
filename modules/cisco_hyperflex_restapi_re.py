"""
Cisco HyperFlex StorFS REST API (stctlVM WAR deployments, HyperFlex 5.5.2b) — RE Module
Sources:
  wars/ — ROOT, iscsi, dataprotection, hxupgrade, securityservice, slservice,
           backupservice, supportservice WAR deployments
  storfs-restapi/auth-war/ — HyperFlex AAA (aaa/v1) authentication WAR

Platform: Springpath / Cisco HyperFlex storage controller VM (stctlVM)
Port:     443 (HTTPS, management interface)
"""

FIRMWARE = {
    "targets": [
        {
            "name": "Cisco HyperFlex StorFS REST API (stctlVM)",
            "version": "5.5.2b-43453",
            "vendor": "Springpath Inc / Cisco",
            "war_deployments": [
                "ROOT",          # management web app; port 443 base context
                "iscsi",         # iSCSI target/LUN management  /v1/*
                "dataprotection",# data protection, DR              /v1/*
                "hxupgrade",     # firmware/HX upgrade               /v1/*
                "securityservice",# DARE encryption, secure-boot     /v1/*
                "slservice",     # smart licensing + features        /v1/*
                "backupservice", # backup/restore                    /v1/*
                "supportservice",# support bundles, STIG             /v1/*
            ],
        },
    ],
    "auth_model": "stSSOProvider via HxAAAConfig.json; JWT tokens; /aaa/v1/auth endpoint",
    "findings": ["HXAPI-F1", "HXAPI-F2", "HXAPI-F3"],
}

# ─────────────────────────────────────────────────────────
# HXAPI-F1: /st-support/* and /storfs-support/* in ROOT war
#           have ZERO auth filter-mappings — unauthenticated diagnostic dump
# ─────────────────────────────────────────────────────────
HXAPI_F1 = {
    "id":       "HXAPI-F1",
    "title":    "ROOT web.xml registers StorvisorSupportBundle (/st-support/*) and "
                "StorfsSupportBundle (/storfs-support/*) servlets with no auth filter-mappings "
                "— unauthenticated diagnostic data collection on port 443",
    "status":   "CONFIRMED — extracted from wars/ROOT/WEB-INF/web.xml; grep count = 2 (servlet-mapping only, zero filter-mapping hits)",
    "severity": "HIGH",

    "source_file":   "wars/ROOT/WEB-INF/web.xml",
    "unprotected_servlets": {
        "/st-support/*": {
            "class": "com.storvisor.sysmgmt.service.StorvisorSupportBundle",
            "description": "Springpath Support Bundle aggregation — full cluster diagnostic data",
        },
        "/storfs-support/*": {
            "class": "com.storvisor.sysmgmt.service.StorfsSupportBundle",
            "description": "Springpath StorFS Support Bundle Extended — storage subsystem diagnostic data",
        },
    },

    "protected_comparators": {
        "/rest/*":           "AuditFilter + SPPrivilegedAuth + SessionAuth + SPBasicAuth + SPAuth",
        "/internalsupport/*": "AuditFilter + SPPrivilegedAuth + SessionAuth + SPBasicAuth + SPAuth",
        "/upload/*":         "AuditFilter + SPPrivilegedAuth + SessionAuth + KerberosAuth + SPBasicAuth + SPAuth",
        "/st-support/*":     "NONE — zero filter-mappings",
        "/storfs-support/*": "NONE — zero filter-mappings",
    },

    "description": (
        "The HyperFlex stctlVM (storage controller VM) runs a Tomcat container on port 443 "
        "serving the ROOT web application. The ROOT web.xml registers all auth filters "
        "(SPPrivilegedAuth, SessionAuth, SPBasicAuth, SPAuth) but maps them only to "
        "/rest/*, /internalsupport/*, and /upload/*. The servlets "
        "StorvisorSupportBundle (mounted at /st-support/*) and StorfsSupportBundle "
        "(mounted at /storfs-support/*) are never covered by any filter-mapping. "
        "An unauthenticated HTTP client reachable on port 443 can invoke these endpoints "
        "and receive cluster diagnostic bundles without credentials."
    ),

    "exposed_data": (
        "Support bundles typically aggregate: cluster configuration (network, storage, ZK "
        "connection string), system logs (which may contain credentials, tokens, or ZK paths), "
        "node inventory, service state, and SpringPath internal debug output. "
        "The StorfsSupportBundle class specifically captures StorFS (the distributed filesystem) "
        "internals, which include ZooKeeper state, volume metadata, and replication status."
    ),

    "attack_vector": "Network → HTTPS port 443 → GET/POST /st-support/ or /storfs-support/",
    "auth_required": False,
}

# ─────────────────────────────────────────────────────────
# HXAPI-F2: 18-day access token lifetime — default for all HyperFlex API tokens
# ─────────────────────────────────────────────────────────
HXAPI_F2 = {
    "id":       "HXAPI-F2",
    "title":    "HyperFlex AAA issues access tokens with 18-day default lifetime "
                "(defaultTokenLifeTime=1555200000 ms) — stolen token persists 18 days",
    "status":   "CONFIRMED — extracted from wars/ROOT/WEB-INF/classes/resources/HxAAAConfig.json and aaaExt.json Swagger spec",
    "severity": "MEDIUM",

    "config_file": "wars/ROOT/WEB-INF/classes/resources/HxAAAConfig.json",
    "config_value": '"defaultTokenLifeTime": "1555200000"',
    "decoded_lifetime": "1555200 seconds = 18 days",
    "swagger_confirmation": (
        "aaaExt.json: 'Access Tokens issued are valid for 18 days (1555200 second).'"
    ),

    "additional_token_limits": {
        "max_unrevoked_per_user":      8,
        "max_unrevoked_system_wide":   16,
        "auto_revoke_on_overflow":     "oldest token revoked when user exceeds 8",
        "brute_force_lockout":         "10 consecutive failures → 120s lockout",
        "rate_limit_auth":             "5 successful /auth calls per 15 minutes",
    },

    "description": (
        "Every API token issued by the HyperFlex AAA is valid for 18 days. "
        "An attacker who captures a valid token (via TLS inspection, log exposure, "
        "credential theft, or XSS in the management UI) retains full API access for 18 days "
        "without re-authenticating. Admin-level tokens enable cluster shutdown "
        "(POST /rest/cluster/shutdown), iSCSI LUN manipulation, encryption key operations, "
        "and support bundle downloads."
    ),
}

# ─────────────────────────────────────────────────────────
# HXAPI-F3: auditHttpVerbsToSkip = "GET" — read-only reconnaissance leaves no audit trail
# ─────────────────────────────────────────────────────────
HXAPI_F3 = {
    "id":       "HXAPI-F3",
    "title":    "HxAAAConfig auditHttpVerbsToSkip='GET' — all read-only REST API calls "
                "are excluded from audit logs across every HyperFlex WAR deployment",
    "status":   "CONFIRMED — extracted from HxAAAConfig.json in all 6 WAR deployments",
    "severity": "MEDIUM",

    "config_key":   "auditHttpVerbsToSkip",
    "config_value": '"GET"',
    "affected_wars": [
        "ROOT", "dataprotection", "slservice", "backupservice",
        "supportservice", "iscsi"
    ],

    "unlogged_get_operations": [
        "GET /rest/cluster/savings",
        "GET /rest/summary",
        "GET /rest/datastores (enumerate all datastores)",
        "GET /rest/virtplatform/vms (enumerate all VMs)",
        "GET /rest/network/* (network configuration)",
        "GET /clusters/{cuuid}/targets (iSCSI target enumeration)",
        "GET /clusters/{cuuid}/luns (LUN enumeration)",
        "GET /v1/callhome, /v1/remotesupport (support config)",
        "GET /v1/software-encryption/dare/overview (encryption key state)",
        "GET /slapi/features (feature flags and license state)",
    ],

    "description": (
        "AuditFilterImpl reads auditHttpVerbsToSkip from HxAAAConfig.json and skips "
        "audit-log writes for any HTTP verb in that list. With 'GET' excluded, an "
        "attacker who holds a valid token can enumerate the entire cluster — VM inventory, "
        "datastore layout, network config, iSCSI targets, encryption state, and license "
        "features — and the activity generates no audit events. Post-incident forensics "
        "cannot reconstruct what was read."
    ),
}

FINDINGS = [HXAPI_F1, HXAPI_F2, HXAPI_F3]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:12s}] {f['id']}: {f['title'][:80]}")
