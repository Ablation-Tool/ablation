"""
RE Module: Cisco HyperFlex StorFS - storfs-core 5.5.2b + storfs-restapi 6.0.2b
storfs-core:    storfs-core_5.5.2b-43453_x86_64.deb  (28MB, BUILD_DATE=20250428)
storfs-restapi: storfs-restapi_6.0.2b-44423_amd64.deb (81MB, 11 Tomcat WAR services)
Platform: Cisco HyperFlex HCI storage controller (SpringPath / StorVisor)

Findings: 6F [0C+3H+2M+1L]
"""

FINDINGS = [
    {
        "id": "STORFS-F1",
        "title": "LD_LIBRARY_PATH set to '/root' in storfs.py before exec of 18MB storage daemon",
        "severity": "HIGH",
        "component": "storfs-core/opt/springpath/storfs-core/storfs.py (line 31)",
        "evidence": [
            "os.environ['LD_LIBRARY_PATH'] = '/root'",
            "BINFILE = '/opt/springpath/storfs-core/storfs'",
            "os.execvp(pg, (pg,) + tuple(pgargs))  # line 1730",
        ],
        "detail": (
            "storfs.py is the Python wrapper for the 18MB storfs storage daemon. At module "
            "scope (line 31), before any command-line parsing or tunes loading, it sets "
            "LD_LIBRARY_PATH to '/root'. This environment variable is inherited across the "
            "os.execvp() call at line 1730 that replaces the Python process with the storfs "
            "binary. The dynamic linker resolves shared library names against directories in "
            "LD_LIBRARY_PATH before the standard search paths; any .so file placed in /root "
            "matching a library name used by the storfs binary will be loaded into the storfs "
            "process address space. storfs is the HyperFlex cluster storage daemon: it manages "
            "all data I/O for the HCI cluster and runs with elevated privileges. "
            "Setting LD_LIBRARY_PATH to a user home directory instead of a controlled path "
            "(e.g., /opt/springpath/lib) is non-standard and creates a persistent .so injection "
            "surface. An attacker who gains file-write access to /root -- via the unauthenticated "
            "ZooKeeper write surface (F2), via an exploited HyperFlex REST service, or via any "
            "prior access that allows writing to the root home directory -- can place a malicious "
            "shared object in /root that is loaded on the next storfs restart. "
            "The library is loaded unconditionally on every storfs daemon start; no additional "
            "privileges are required beyond write access to /root."
        ),
        "impact": (
            "Persistent code execution in the storfs storage daemon process on every restart. "
            "storfs controls all HyperFlex cluster data paths. Library injection survives "
            "process restart until /root is cleared."
        ),
        "remediation": (
            "Remove the LD_LIBRARY_PATH assignment from storfs.py. If additional shared "
            "libraries are required at runtime, place them in a fixed, controlled directory "
            "under /opt/springpath/ and set LD_LIBRARY_PATH to that path. Do not use any "
            "user home directory as a library search path for a privileged daemon."
        ),
        "references": [
            "storfs.py line 31: os.environ['LD_LIBRARY_PATH'] = '/root'",
            "storfs binary: /opt/springpath/storfs-core/storfs (18MB)",
        ],
    },
    {
        "id": "STORFS-F2",
        "title": "ZooKeeper KazooClient instantiated without authentication; useZKAuth absent from all shipped tunes",
        "severity": "HIGH",
        "component": "storfs-core/opt/springpath/storfs-core/zkclient.py + default.tunes",
        "evidence": [
            "self.zkClient = KazooClient(hosts=self.host, max_retries=5)",
            "# no add_auth() call, no sasl_options, no auth_data in KazooClient()",
            "# default.tunes [storfsoptional] section lists useZKAuth but never assigns it a value",
            "# cip-monitor.conf: if [ \"x$useZKAuth\" = \"xtrue\" ]; then ARGS=\"${ARGS} -A ...\"; fi",
            "# sysmtool CLI: enablezkauth command (post-install opt-in, not a default)",
        ],
        "detail": (
            "zkclient.py creates a KazooClient with hosts and max_retries only. No auth_data, "
            "no sasl_options, and no add_auth() call are present. The client connects to "
            "ZooKeeper at localhost:2181 (read from /etc/springpath/storfs.cfg zkConnectString, "
            "defaulting to localhost:2181 if absent). ZooKeeper authentication is controlled "
            "by the useZKAuth tunable. In default.tunes, useZKAuth appears in the "
            "[storfsoptional] section, which means it is passed to the storfs daemon only if "
            "its value is populated. No shipped tunes file (default.tunes, encryption.tunes, "
            "afa.tunes, lff.tunes, hyperv.tunes, vdi_*.tunes, vsi_*.tunes) assigns useZKAuth "
            "a value. The cip-monitor.conf Upstart script gate "
            "(if [ \"x$useZKAuth\" = \"xtrue\" ]) never evaluates to true in a default "
            "deployment. sysmtool exposes an enablezkauth command (StPlatform.enableZKAuth "
            "Thrift RPC via StPlatformClient::enableZKAuth), confirming ZK auth is a "
            "post-install administrative opt-in, not a default. "
            "Any local process on the HyperFlex storage VM with network access to localhost:2181 "
            "can connect to ZooKeeper and perform arbitrary reads and writes against cluster "
            "state znodes without credentials. The ZK ensemble stores cluster topology, node "
            "membership, configuration, and replication state."
        ),
        "impact": (
            "Any local process on the HyperFlex storage VM can read and write ZooKeeper "
            "cluster state without authentication. Cluster topology manipulation, node "
            "eviction, and configuration poisoning available to any process with loopback "
            "access. Ships disabled in all 5.5.2b deployments until operator runs "
            "sysmtool enablezkauth."
        ),
        "remediation": (
            "Set useZKAuth=true in the default tunes configuration distributed with the "
            "package so ZK authentication is enabled at installation. Update zkclient.py "
            "to pass the cluster UUID credentials to KazooClient (add_auth scheme and "
            "credential). Update cip-monitor.conf and repl-cip-monitor.conf to always "
            "pass -A rather than gating on useZKAuth."
        ),
        "references": [
            "zkclient.py: KazooClient(hosts=self.host, max_retries=5)",
            "default.tunes [storfsoptional]: useZKAuth (no assigned value)",
            "cip-monitor.conf: if [ \"x$useZKAuth\" = \"xtrue\" ]",
            "sysmtool: enablezkauth command (StPlatform.enableZKAuth Thrift RPC)",
        ],
    },
    {
        "id": "STORFS-F3",
        "title": "invSecEncSystem=true ships as default in encryption.tunes; storage encryption disabled at installation",
        "severity": "HIGH",
        "component": "storfs-core/opt/springpath/storfs-core/encryption.tunes + encrypt/libcrypt_disabled.so",
        "evidence": [
            "# encryption.tunes (shipped file, unmodified):",
            "invSecEncSystem=true",
            "# directory listing: encrypt/libcrypt_disabled.so present",
            "# build-manifest.txt BUILD_DATE=20250428 BUILD_RELEASE=5.5.2b",
        ],
        "detail": (
            "The shipped encryption.tunes file contains a single line: invSecEncSystem=true. "
            "This tunable controls the HyperFlex StorFS encryption subsystem. When set to "
            "true, StorFS loads the disabled-encryption library (encrypt/libcrypt_disabled.so) "
            "rather than the active encryption library. The presence of libcrypt_disabled.so "
            "in the package confirms this is the intended shipping path: a dedicated "
            "'no-op' encryption library is provided for use when invSecEncSystem=true. "
            "No other value is set in encryption.tunes; invSecEncSystem=true is the entire "
            "file content. HyperFlex is an HCI platform deployed in enterprise and healthcare "
            "environments where data-at-rest encryption is a compliance requirement "
            "(HIPAA, PCI-DSS). StorFS 5.5.2b ships with encryption turned off, meaning "
            "any HyperFlex cluster deployed at release without explicit post-install "
            "encryption configuration has no data-at-rest protection. The disabled state "
            "is not surfaced as a warning during installation or in default dashboards."
        ),
        "impact": (
            "Data-at-rest encryption disabled on all HyperFlex clusters running "
            "storfs-core 5.5.2b as shipped. Physical disk removal provides unencrypted "
            "data access. Compliance posture for HIPAA/PCI-DSS deployments is broken "
            "unless encryption is explicitly enabled post-install."
        ),
        "remediation": (
            "Change the shipped default to invSecEncSystem=false so encryption is active "
            "at installation. If hardware lacks SED (self-encrypting drive) support, "
            "document clearly that encryption requires an explicit configuration step "
            "and surface the disabled state as a prominent cluster health warning."
        ),
        "references": [
            "encryption.tunes: invSecEncSystem=true (full file content)",
            "encrypt/libcrypt_disabled.so (disabled-encryption library)",
            "storfs-core_5.5.2b-43453 BUILD_DATE=20250428",
        ],
    },
    {
        "id": "STORFS-F4",
        "title": "barredUsers list inconsistent across 11 WAR services: diag user blocked in 3, allowed in 8",
        "severity": "MEDIUM",
        "component": "storfs-restapi 6.0.2b: all WAR application.conf files",
        "evidence": [
            # WARs that bar diag
            'auth-1.0.0.war application.conf:       barredUsers = ["root", "local/root", "diag", "local/diag"]',
            'coreapi-1.0.0.war application.conf:    barredUsers = ["root", "local/root", "diag", "local/diag"]',
            'iscsi-1.0.0.war application.conf:      barredUsers = ["root", "local/root", "diag", "local/diag"]',
            # WARs that do NOT bar diag
            'encryption-1.0.0.war application.conf: barredUsers = ["root", "local/root"]',
            'hxupgrade-1.0.0.war application.conf:  barredUsers = ["root", "local/root"]',
            'dataprotection-1.0.0.war application.conf: barredUsers = ["root", "local/root"]',
            'backupservice-1.0.0.war application.conf:  barredUsers = ["root", "local/root"]',
            'securityservice-1.0.0.war application.conf: barredUsers = ["root", "local/root"]',
            'supportservice-1.0.0.war application.conf:  barredUsers = ["root", "local/root"]',
            'slservice-1.0.0.war application.conf:   barredUsers = ["root", "local/root"]',
            'ROOT-1.0.0.war application.conf:        barredUsers = ["root", "local/root"]',
        ],
        "detail": (
            "The barredUsers configuration controls which local HyperFlex accounts are "
            "prohibited from authenticating to each REST API service. The diag user is a "
            "HyperFlex diagnostic/support account present on all controller VMs. "
            "auth.war, coreapi.war, and iscsi.war include both 'diag' and 'local/diag' "
            "in their barredUsers list. The remaining eight WAR services "
            "(encryption, hxupgrade, dataprotection, backupservice, securityservice, "
            "supportservice, slservice, ROOT) do not include diag or local/diag in their "
            "barredUsers list. "
            "The barredUsers check in each WAR is independent and evaluated after JWT "
            "token validation. If a valid session token for the diag user is obtained "
            "through any path not governed by auth.war's barredUsers check -- including "
            "service account tokens, legacy tokens issued before a barredUsers update, "
            "or any auth bypass -- the eight unguarded WAR services will accept the diag "
            "token. The encryption.war and hxupgrade.war exposure is the most significant: "
            "encryption.war manages disk encryption key policy and SED configuration; "
            "hxupgrade.war manages firmware upgrade operations for the HCI cluster."
        ),
        "impact": (
            "diag user tokens accepted by encryption, hxupgrade, dataprotection, "
            "backupservice, securityservice, supportservice, slservice, and ROOT REST "
            "API endpoints. Missing defense-in-depth layer; auth.war barredUsers check "
            "is the only enforcement point for diag. Affects storfs-restapi 6.0.2b "
            "across all 11 deployed WAR contexts."
        ),
        "remediation": (
            "Add 'diag' and 'local/diag' to the barredUsers list in all 11 WAR "
            "application.conf files. Implement a shared security policy configuration "
            "that is applied uniformly at deployment time rather than per-WAR "
            "application.conf files that can drift."
        ),
        "references": [
            "storfs-restapi 6.0.2b: 11 WAR application.conf files",
            "barredUsers: inconsistent inclusion of diag/local/diag across WARs",
        ],
    },
    {
        "id": "STORFS-F5",
        "title": "hxSvcHttpEnabled=true and hyperVSvcHttpEnabled=true in all WAR configs; cleartext HTTP service active by default",
        "severity": "MEDIUM",
        "component": "storfs-restapi 6.0.2b: all WAR WEB-INF/classes/application.conf",
        "evidence": [
            "hxSvcHttpEnabled=true",
            "hyperVSvcHttpEnabled=true",
            "# both flags appear in every extracted WAR application.conf",
            "# spauthenticate.conf: HxPamLoginModule required service=nginx",
        ],
        "detail": (
            "All 11 storfs-restapi WAR services (auth, coreapi, encryption, hxupgrade, "
            "dataprotection, backupservice, securityservice, supportservice, slservice, "
            "iscsi, ROOT) carry hxSvcHttpEnabled=true and hyperVSvcHttpEnabled=true in "
            "their shipped application.conf. These flags enable the cleartext HTTP "
            "listener for both the base HyperFlex service and the Hyper-V integration "
            "service path. Tomcat10 on the HyperFlex controller VM will accept REST API "
            "requests over unencrypted HTTP. "
            "Authentication credentials (username and password submitted to /aaa/v1/auth) "
            "and session tokens returned in responses are transmitted in cleartext over "
            "the HyperFlex management network when clients use the HTTP endpoint. "
            "Additionally, spauthenticate.conf configures JAAS PAM authentication with "
            "'service=nginx', coupling HyperFlex REST authentication to the nginx PAM "
            "configuration file (/etc/pam.d/nginx) rather than a dedicated HyperFlex "
            "PAM service. Any change to the nginx PAM policy on the controller VM "
            "directly affects HyperFlex REST authentication behavior."
        ),
        "impact": (
            "Cleartext credential and token transmission on the management network when "
            "HTTP endpoint is used. PAM configuration coupling to nginx means nginx PAM "
            "policy changes affect HyperFlex REST auth. Both conditions ship as defaults "
            "in storfs-restapi 6.0.2b."
        ),
        "remediation": (
            "Set hxSvcHttpEnabled=false and hyperVSvcHttpEnabled=false in all WAR configs "
            "to disable the HTTP listener. Require TLS for all REST API traffic. "
            "Create a dedicated /etc/pam.d/hyperflex PAM configuration and update "
            "spauthenticate.conf to use service=hyperflex."
        ),
        "references": [
            "application.conf (all WARs): hxSvcHttpEnabled=true, hyperVSvcHttpEnabled=true",
            "encryption-war WEB-INF/classes/resources/spauthenticate.conf: service=nginx",
        ],
    },
    {
        "id": "STORFS-F6",
        "title": "defaultTokenLifeTime=1555200000ms (18 days) across all storfs-restapi WAR services",
        "severity": "LOW",
        "component": "storfs-restapi 6.0.2b: all WAR WEB-INF/classes/application.conf",
        "evidence": [
            "defaultTokenLifeTime = 1555200000",
            "# 1555200000 ms = 1555200 sec = 432 hours = 18 days",
            "defaultIdleTimeout = 1800000",
            "# idle timeout: 1800000 ms = 30 minutes",
            "maxFailedLogins = 10",
            "rateLimitAuthMaxAuthenticationsAllowedInWindow = 5",
            "rateLimitAuthWindowSizeInMins = 15",
        ],
        "detail": (
            "All storfs-restapi 6.0.2b WAR services configure defaultTokenLifeTime at "
            "1555200000 milliseconds, equal to 18 days. A session token obtained via "
            "/aaa/v1/auth or /aaa/v1/serviceauth remains valid for 18 calendar days "
            "without reauthorization. The idle timeout is 30 minutes "
            "(defaultIdleTimeout=1800000ms), but the absolute token expiry is 18 days. "
            "An active connection resets the idle clock; a token used once per 29 minutes "
            "remains valid indefinitely within the 18-day window. "
            "Rate limiting is set to 5 authentication attempts per 15-minute window "
            "(20/hour), with lockout for 120 seconds after 10 failed logins. The 18-day "
            "token lifetime extends any session compromise window substantially and means "
            "that token revocation (via /aaa/v1/revoke) is the only mechanism to "
            "invalidate a stolen token before expiry."
        ),
        "impact": (
            "Stolen or leaked session token remains valid for up to 18 days. Token "
            "disclosure via the HTTP service (F5) combined with the 18-day lifetime "
            "gives a large exploitation window. Affects all 11 WAR services in "
            "storfs-restapi 6.0.2b."
        ),
        "remediation": (
            "Reduce defaultTokenLifeTime to 8 hours (28800000ms) or less for "
            "interactive sessions. Implement refresh token rotation rather than "
            "long-lived absolute tokens. Document the /aaa/v1/revoke endpoint as "
            "the mandatory response to any suspected token compromise."
        ),
        "references": [
            "application.conf (all WARs): defaultTokenLifeTime = 1555200000",
            "auth.war: /aaa/v1/revoke endpoint",
        ],
    },
]


def run():
    for f in FINDINGS:
        sev = f["severity"]
        print(f"[{sev}] {f['id']}: {f['title']}")
        for e in f["evidence"]:
            print(f"    {e!r}")
        print()


if __name__ == "__main__":
    run()
