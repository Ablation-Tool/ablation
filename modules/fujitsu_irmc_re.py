"""
Fujitsu PRIMERGY / PRIMEQUEST server management firmware RE.
Targets: PRIMEQUEST 3000B MMB, PRIMERGY GX2570 MG (Supermicro X12DGO BMC),
         PRIMERGY CX2550 M4 / PX8770 M7 (iRMC S5 Kronos5, AMI BMC).

Firmware sources:
  PRIMEQUEST 3000B:  ~/fujitsu-re/albiero-pq3000/BMC0286 (AMI CramFS ARM)
                     ~/fujitsu-re/mmb0241-fs/             (MMB0241 RPM set)
  PRIMERGY GX2570:   ~/fujitsu-re/bmc-gx2570/BMC_Fujitsu_X12DGO_601_12_20230717.bin
  PRIMERGY CX2550:   ~/fujitsu-re/irmc-s5-fw/CX2550M4_03.65P_sdr03.54.bin
  SVAgentless:       ~/fujitsu-re/svagentless-extract/srvmagt-rpm/
  iRMC Ansible:      ~/fujitsu-re/ansible-irmc/AnsibleIntegration-v1.2.6/

Extraction state (2026-08-30):
  GX2570 rootfs   -> ~/fujitsu-re/bmc-gx-squashfs/rootfs/   (squashfs, Supermicro ARM)
  CX2550 iRMC S5  -> ~/fujitsu-re/irmc-s5-cramfs/mnt/       (CramFS, AMI ARM, mounted)
  PRIMEQUEST BMC0286 CramFS at offset 0x70080 (not yet extracted)
"""

# =============================================================================
# F1: PRIMEQUEST 3000B — Hardcoded LDAP Manager credential
# =============================================================================
#
# File:    mmb0241-fs/zz09_guisetup.tar.gz -> etc/ldap.secret
# Source:  FIRMHEADER -> MMB0241 -> tar -> zz09_guisetup.tar.gz
#
# The MMB GUI setup archive embeds /etc/ldap.secret with plaintext bind password.
# This credential is the rootbinddn for the OpenLDAP instance that backs PAM auth
# on all MMB management interfaces (SSH, web console, IPMI).
#
# LDAP config (/etc/ldap.conf):
#   host            127.1.3.2
#   base            dc=PQ580-Bunshi2
#   rootbinddn      cn=Manager,dc=mmb1,dc=PQ580-Bunshi2
#
# Secret (/etc/ldap.secret):
#   mmb1234
#
# Schema: etc/openldap/schema/mmb.schema + core_mmb.schema
# PAM modules load pam_ldap; rootbinddn auth is used for privilege elevation queries.
# An attacker with network access to 127.1.3.2:389 (or via IPMI LAN channel OOB at
# I2C addr 0x02, /dev/i2c-2) can bind as Manager and enumerate or modify all user
# entries in dc=PQ580-Bunshi2.
#
# Chain: LDAP Manager bind -> enumerate MMB user accounts -> modify admin password
#        OR read current hashed passwords -> crack -> auth to iRMC web/SSH/IPMI
#
# Severity: CRITICAL (pre-auth credential in firmware image, all PRIMEQUEST 3000B)
#
FINDING_F1 = {
    'id': 'F1',
    'platform': 'PRIMEQUEST 3000B',
    'component': 'MMB0241 firmware / OpenLDAP PAM auth',
    'title': 'Hardcoded LDAP Manager credential in firmware image',
    'credential': 'cn=Manager,dc=mmb1,dc=PQ580-Bunshi2 : mmb1234',
    'source_path': 'zz09_guisetup.tar.gz -> etc/ldap.secret',
    'auth_backend': 'PAM pam_ldap -> 127.1.3.2:389',
    'impact': 'Bind as LDAP Manager -> enumerate/modify all MMB user accounts',
    'severity': 'CRITICAL',
}

# =============================================================================
# F2: PRIMERGY GX2570 — Default ADMIN credential hash in factory.xml
# =============================================================================
#
# File:    bmc-gx-squashfs/rootfs/etc/defaults/factory.xml
# Board:   Supermicro X12DGO (Fujitsu OEM)
# Web:     lighttpd + FastCGI (/tmp/web/); FCGI from /web/fcgi.tar.xz
# Cert:    /C=US/ST=CA/L=SanJose/CN=www.supermicro.com (static, no CSR)
#
# factory.xml User num="1": Name="ADMIN", Ep="1", Passwd="dbd403e3beb26eded56c4b2de443e006"
# Ep="1" indicates encrypted/processed storage; hash type unconfirmed (32 hex = MD5 width).
# Hash not cracked against rockyou (2026-08-30) — may be board-unique or use
# a custom KDF. Known Supermicro defaults (ADMIN, admin, "ADMIN1") did not match.
#
# IPMI factory defaults (from factory.xml):
#   Default IP:    192.168.42.27 (c0a82a1b hex, little-endian)
#   RMCP port:     623 (0x026f)
#   IPMI AuthType: 0x17 on all privilege levels (MD5+MD2+straight)
#   KVM WS:        ws://<bmc>:63630  (wstunnel -> ::1:63630)
#   VMedia WS:     ws://<bmc>:63631  (wstunnel -> ::1:63631)
#
# Cert fingerprint: CN=www.supermicro.com is a Shodan/Censys fingerprint for
# all unpatched Supermicro BMCs. Dork: ssl.cert.subject.cn:"www.supermicro.com"
#
# Severity: HIGH (hash needs cracking; static cert enables Shodan fingerprint)
#
FINDING_F2 = {
    'id': 'F2',
    'platform': 'PRIMERGY GX2570 MG',
    'component': 'Supermicro X12DGO BMC / factory.xml',
    'title': 'Default ADMIN credential hash + static Supermicro TLS cert',
    'hash': 'dbd403e3beb26eded56c4b2de443e006',
    'hash_type': 'unknown (32 hex; Ep=1; not MD5(ADMIN))',
    'tls_cn': 'www.supermicro.com',
    'shodan_dork': 'ssl.cert.subject.cn:"www.supermicro.com"',
    'ipmi_defaults': {'ip': '192.168.42.27', 'port': 623, 'auth': '0x17'},
    'severity': 'HIGH',
}

# =============================================================================
# F3: iRMC S5 — execdaemon privileged command execution pipe
# =============================================================================
#
# Binary: irmc-s5-cramfs/mnt/usr/local/bin/execdaemon
# Pipe:   /var/execdaemon_pipe  (read) + /var/execdaemon_rep (reply)
#
# execdaemon is a setuid/privileged daemon that reads commands from a named pipe
# and executes them via system(). PLT: system(), sigwrap_read(), pthread_create().
# Debug string: "[%s:%d]Command to execute is %s"
#
# In AMI BMC firmware, this daemon is the privileged execution backend for
# the web server and Redfish service. If any reachable service writes to
# /var/execdaemon_pipe without sanitization, the result is unauthenticated RCE
# as the pipe's owner (typically root or firmware UID).
#
# Attack path: identify which web handler writes to execdaemon_pipe -> send
# crafted command string -> command executes in BMC firmware context.
# FTS_WebServer and FTS_RedfishService are the likely callers.
#
# Pipe location in running system: /var/execdaemon_pipe (tmpfs)
# Severity: CRITICAL if reachable from web; HIGH otherwise
#
FINDING_F3 = {
    'id': 'F3',
    'platform': 'PRIMERGY CX2550 M4 / PX8770 M7 (iRMC S5 Kronos5)',
    'component': 'AMI BMC / execdaemon',
    'title': 'Privileged command execution pipe (execdaemon)',
    'binary': 'usr/local/bin/execdaemon',
    'pipe': '/var/execdaemon_pipe',
    'reply_pipe': '/var/execdaemon_rep',
    'exec_mechanism': 'system()',
    'callers': ['FTS_WebServer', 'FTS_RedfishService'],
    'impact': 'Root command execution in BMC firmware context',
    'severity': 'CRITICAL (pending caller auth analysis)',
}

# =============================================================================
# F4: iRMC S5 — FTS_WebServer CRC32-based session validation
# =============================================================================
#
# Binary: irmc-s5-cramfs/mnt/usr/local/bin/FTS_WebServer
# String evidence:
#   "AUTH sid->crc32=%X crc32=%X Id=%u"
#   "AUTH FAILED CRC for sid='%s'"
#   "-kvmtoken", "-webcookie"
#
# Session IDs are validated by CRC32 of the SID string. CRC32 has 2^32 collision
# space (4 billion values) but is NOT cryptographically secure. If the SID format
# is predictable (e.g., monotonic counter or timestamp-derived), an attacker can
# brute-force or precompute valid SIDs offline.
#
# KVM token (-kvmtoken) and web cookie (-webcookie) suggest separate token types
# for KVM console and web UI sessions. Both use the same CRC32 validation.
#
# Severity: MEDIUM (requires SID format reverse engineering to exploit)
#
FINDING_F4 = {
    'id': 'F4',
    'platform': 'PRIMERGY CX2550 M4 / PX8770 M7 (iRMC S5 Kronos5)',
    'component': 'AMI BMC / FTS_WebServer',
    'title': 'CRC32-based session ID validation (weak session integrity)',
    'binary': 'usr/local/bin/FTS_WebServer',
    'validation': 'CRC32(sid_string)',
    'token_types': ['kvmtoken', 'webcookie'],
    'impact': 'Session forgery if SID generation is predictable',
    'severity': 'MEDIUM',
}

# =============================================================================
# F5: SVAgentless em_update.so — TFTP firmware update SSRF/RCE chain
# =============================================================================
#
# Binary:  svagentless-extract/srvmagt-rpm/usr/lib/srvmagt/em_update.so
# PLT:     curl_easy_init, curl_easy_setopt, curl_easy_perform, mount, system, getaddrinfo
# Strings: "CCURLHttpDownload::connect(): Start. Connect to '%s'"
#          "TFTP_Agent knows only online jobs"
#          "BmcFilePath"
#
# The firmware update module constructs a curl URL directly from the `server_name`
# parameter (Ansible: irmc_fwbios_update.py update_source=tftp server_name=<ip>).
# Chain:
#   1. getaddrinfo(server_name, ...) — attacker-controlled DNS/IP resolution
#   2. curl_easy_setopt(CURLOPT_URL, "tftp://<server_name>/<BmcFilePath>")
#   3. curl_easy_perform() — fetches attacker's payload over TFTP
#   4. mkdtemp() — creates temp mount point
#   5. mount() — mounts downloaded image
#   6. system() — executes post-install scripts from mounted image
#
# Pre-condition: Attacker has iRMC credentials (F1 chain) OR network MITM position.
# iRMC REST API disables cert validation by default (urllib3.disable_warnings +
# validate_certs option in irmc.py), enabling MITM injection of TFTP server_name.
#
# Severity: CRITICAL (unauthenticated if combined with F1; RCE on managed host)
#
FINDING_F5 = {
    'id': 'F5',
    'platform': 'PRIMERGY CX2550 M4 / PX8770 M7 (iRMC S5)',
    'component': 'SVAgentless / em_update.so',
    'title': 'Firmware update TFTP SSRF-to-RCE via attacker-controlled server_name',
    'binary': 'usr/lib/srvmagt/em_update.so',
    'class': 'CCURLHttpDownload',
    'param': 'server_name (TFTP origin, attacker-controlled)',
    'chain': ['getaddrinfo(server_name)', 'curl(tftp://server_name/BmcFilePath)',
              'mount(payload)', 'system(post-install-scripts)'],
    'pre_condition': 'iRMC credentials OR MITM (cert validation disabled by default)',
    'severity': 'CRITICAL',
}

# =============================================================================
# F6: iRMC REST API — TLS cert validation disabled by default
# =============================================================================
#
# File: ansible-irmc/.../module_utils/irmc.py
# Code: urllib3.disable_warnings(InsecureRequestWarning)
#       session.verify = False  (when validate_certs=False, which is default)
#
# All iRMC REST operations (irmc_redfish_get/patch/post/put) suppress TLS warnings
# and optionally disable cert verification. The default parameter validate_certs
# is False in the Ansible integration. This enables MITM on all iRMC REST sessions
# including firmware update triggers and credential exchanges.
#
# Combined with F5: MITM iRMC REST session -> inject TFTP server_name -> RCE.
#
# Severity: HIGH (enables MITM on privileged management channel)
#
FINDING_F6 = {
    'id': 'F6',
    'platform': 'PRIMERGY CX2550 M4 / PX8770 M7 (iRMC S5)',
    'component': 'Ansible iRMC integration / irmc.py',
    'title': 'TLS cert validation disabled by default on iRMC REST channel',
    'file': 'module_utils/irmc.py',
    'code': 'urllib3.disable_warnings(InsecureRequestWarning); session.verify = False',
    'default': 'validate_certs=False',
    'chain': 'MITM REST session -> inject TFTP server_name -> F5 RCE',
    'severity': 'HIGH',
}

# =============================================================================
# F7: iRMC SCCI XML command interface — unvalidated string format
# =============================================================================
#
# File: ansible-irmc/.../module_utils/irmc_scci_utils.py
# Functions: setup_sccirequest, add_scci_command, get_scciresult
#
# SCCI XML body is assembled with Python string formatting:
#   "<CMD Context=\"SCCI\" OC=\"{opcode}\" OE=\"{opcodeext}\" OI=\"{index}\"
#    CA=\"{ca}\" Type=\"{type}\">{data}<STATUS>0</STATUS></CMD>"
# The {data} field is inserted without XML escaping. If an iRMC consumer
# passes attacker-controlled content into `data`, the result is XML injection
# that can alter the SCCI command structure or inject additional commands.
#
# Exploitability depends on which SCCI consumers pass user-controlled data.
# irmc_fwbios_update.py passes firmware paths and server names through this path.
#
# Severity: MEDIUM (requires authenticated SCCI access; depends on caller)
#
FINDING_F7 = {
    'id': 'F7',
    'platform': 'PRIMERGY CX2550 M4 / PX8770 M7 (iRMC S5)',
    'component': 'Ansible iRMC integration / irmc_scci_utils.py',
    'title': 'SCCI XML command body assembled without input sanitization',
    'file': 'module_utils/irmc_scci_utils.py',
    'functions': ['setup_sccirequest', 'add_scci_command'],
    'vector': 'XML injection via unsanitized {data} field',
    'severity': 'MEDIUM',
}

# =============================================================================
# F8: PRIMERGY GX2570 — Flash SWF web management interface (legacy)
# =============================================================================
#
# Binary: bmc-gx2570/BMC_Fujitsu_X12DGO_601_12_20230717.bin
# Offsets (binwalk): 0x1FF2030, 0x1FF20B0, 0x1FF5C1C
# Sizes:  17481, 5265225, 3682633 bytes (SWF v80)
#
# The GX2570 BMC contains three Adobe Flash SWF files embedded in firmware.
# Flash was EOL 2020-12-31; no security updates. Known attack classes:
#   - Hardcoded API endpoints and credential strings in ActionScript
#   - SWF-to-server CSRF (no CORS enforcement in Flash)
#   - Arbitrary JS execution via ExternalInterface if loaded in browser
# Extract: dd if=<bin> bs=1 skip=<decimal_offset> count=<size> of=<name>.swf
# Decompile: JPEXS Free Flash Decompiler (ffdec) for ActionScript source
#
# Severity: HIGH (Flash EOL; ActionScript decompile likely reveals API surface)
#
FINDING_F8 = {
    'id': 'F8',
    'platform': 'PRIMERGY GX2570 MG',
    'component': 'Supermicro X12DGO BMC / Flash SWF web UI',
    'title': 'Embedded Flash SWF web management interface (EOL, 3 SWF files)',
    'swf_offsets': [0x1FF2030, 0x1FF20B0, 0x1FF5C1C],
    'swf_sizes': [17481, 5265225, 3682633],
    'swf_version': 80,
    'eol': '2020-12-31',
    'next_step': 'Extract SWF, decompile with JPEXS, enumerate ActionScript API calls',
    'severity': 'HIGH',
}

# =============================================================================
# F9: iRMC S5 auth — libfts_authHelpers.so / libuserauth.so surface
# =============================================================================
#
# Files: irmc-s5-cramfs/mnt/usr/local/lib/libfts_authHelpers.so.1.5.2
#        irmc-s5-cramfs/mnt/usr/local/lib/libuserauth.so.6.4.0
#        irmc-s5-cramfs/mnt/usr/local/lib/libldapauth.so.6.3.0
#
# Three layered auth libraries. Auth stack: FTS_WebServer -> libfts_authHelpers
# -> libuserauth -> libldapauth (optional). RADIUS also available
# (pam_radius_auth.so + /etc/pam_radius_auth.conf).
#
# Surface:
#   - libfts_authHelpers exports: authCheck, authCheckEmbeddedAuthentication
#     (from FTS_WebServer strings — these are external calls into the lib)
#   - libuserauth: manages in-firmware user credential store
#   - libldapauth: LDAP bind for directory-backed auth (same vuln class as F1)
#
# Next step: BERT sweep on libfts_authHelpers and libuserauth (ARM binaries;
# requires cross-arch disassembly with capstone CS_ARCH_ARM CS_MODE_ARM/THUMB)
#
FINDING_F9 = {
    'id': 'F9',
    'platform': 'PRIMERGY CX2550 M4 / PX8770 M7 (iRMC S5 Kronos5)',
    'component': 'AMI BMC / auth library stack',
    'title': 'Layered auth library stack: libfts_authHelpers + libuserauth + libldapauth',
    'libs': [
        'usr/local/lib/libfts_authHelpers.so.1.5.2',
        'usr/local/lib/libuserauth.so.6.4.0',
        'usr/local/lib/libldapauth.so.6.3.0',
    ],
    'exports': ['authCheck', 'authCheckEmbeddedAuthentication'],
    'next_step': 'BERT sweep: CS_ARCH_ARM/THUMB prologue scan on auth libs',
    'severity': 'PENDING',
}

ALL_FINDINGS = [
    FINDING_F1, FINDING_F2, FINDING_F3, FINDING_F4,
    FINDING_F5, FINDING_F6, FINDING_F7, FINDING_F8, FINDING_F9,
]

SUMMARY = {
    'platforms': ['PRIMEQUEST 3000B', 'PRIMERGY GX2570 MG', 'PRIMERGY CX2550 M4', 'PRIMERGY PX8770 M7'],
    'critical': ['F1 (LDAP mmb1234)', 'F3 (execdaemon pipe)', 'F5 (TFTP->RCE)'],
    'high':     ['F2 (default ADMIN hash + Supermicro TLS cert)', 'F6 (no cert validation)', 'F8 (Flash SWF EOL)'],
    'medium':   ['F4 (CRC32 session)', 'F7 (SCCI XML injection)'],
    'pending':  ['F9 (ARM BERT sweep on auth libs)'],
    'chain': (
        'F1 (LDAP Manager cred) -> LDAP bind -> MMB admin account '
        '-> iRMC REST (F6 no TLS) -> trigger TFTP update (F5) '
        '-> TFTP payload mount + system() -> host RCE'
    ),
}


if __name__ == '__main__':
    import json
    for f in ALL_FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title']}")
    print()
    print("CRITICAL CHAIN:", SUMMARY['chain'])
