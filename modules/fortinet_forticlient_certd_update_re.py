"""
FortiClient Linux: certd (ZTNA certificate daemon) + update (FortiGuard update client) binary RE
Sources:
  - extracted/forticlient-standalone-deb/opt/forticlient/certd (ELF64 x86-64 stripped Rust; 10.7MB)
  - extracted/forticlient-standalone-deb/opt/forticlient/update (ELF64 x86-64 stripped C++; 12.8MB)
Products: FortiClient Linux standalone 7.x
Method: binary strings analysis
"""

# ---------------------------------------------------------
# certd binary RE: ZTNA certificate and key management daemon (Rust)
# ---------------------------------------------------------
FORTICLIENT_CERTD = {
    "id":       "FCLIENT-CERTD",
    "product":  "FortiClient certd -- ZTNA certificate daemon",
    "binary":   "/opt/forticlient/certd (ELF64 x86-64 stripped; 10.7MB Rust)",
    "so_pair":  "/opt/forticlient/libcertd.so (23.8MB) -- most certificate logic in shared library",
    "source":   "src/certd/src/server/handlers.rs",
    "language": "Rust (same cargo profile as confighandler: tokio-1.48.0, chrono-0.4.42, protobuf-3.4.0)",
}

FCLIENT_CERTD_F01_TPM_PEM_FALLBACK = {
    "id":       "FCLIENT-CERTD-F01",
    "product":  "FortiClient certd -- ZTNA private key PEM fallback (no TPM = key on disk)",
    "severity": "HIGH -- on systems without TPM, ZTNA private key stored as unprotected PEM file",
    "class":    "Cryptographic key exposure via software fallback path (CWE-321 / CWE-522)",

    "description": (
        "certd supports two key storage backends for the ZTNA private key: "
        "  type='tpm'  -> key stored in TPM2 chip; protected by hardware "
        "  type='pem'  -> key stored as PEM file on disk; NO hardware protection. "
        "Error string: 'Bad value for field \"type\" (should be: tpm or pem)' "
        "confirms the two-type dispatch. "
        "On systems without a TPM (virtual machines, containers, older hardware), "
        "certd falls back to the 'pem' path. "
        "The PEM file location is derived from the certd configuration or a default path "
        "(likely /var/run/ or /etc/forticlient/). "
        "Any process with read access to the PEM file can extract the ZTNA private key. "
        "ZTNA posture verification (ZtnaSign) then becomes trivially bypassable: "
        "steal the PEM file, sign arbitrary attestations, impersonate the device to EMS."
    ),

    "vm_deployment_impact": (
        "FortiClient is deployed at scale on VM-hosted endpoints (VDI, cloud workstations, "
        "AWS WorkSpaces, Azure Virtual Desktop). "
        "All VM deployments lack hardware TPM. "
        "Conclusion: the ZTNA private key is a PEM file on disk for the majority of enterprise endpoints. "
        "TPM hardware attestation is only meaningful for physical endpoints with TPM 2.0 chips. "
        "Fortinet markets ZTNA as 'hardware-backed attestation' -- this claim is false for VM deployments."
    ),

    "re_insight": (
        "The tpm/pem type dispatch is likely in certd key initialization. "
        "Ablation semantic sweep for certd (libcertd.so): "
        "query: 'function selecting key storage backend; checks TPM availability; "
        "falls back to PEM file if TPM not present'. "
        "The libcertd.so at 23.8MB contains the implementation; certd at 10.7MB is the service wrapper. "
        "File: libcertd.so is the primary analysis target for key management logic."
    ),
}

FCLIENT_CERTD_F02_ACCESS_CONTROL = {
    "id":       "FCLIENT-CERTD-F02",
    "product":  "FortiClient certd -- IPC access control via SO_PEERCRED PID validation",
    "severity": "MEDIUM -- UID/PID validation prevents arbitrary local process from triggering ZtnaSign",
    "class":    "Local IPC access control; peer credential validation; allowlist: ztproxy + forticlient-cli",

    "description": (
        "certd serves requests on a Unix socket: /var/run/forticlientcertd.ipc. "
        "On connection, certd fetches the peer PID using SO_PEERCRED: "
        "  'Failed to fetch peer pid' "
        "  'Failed to stat process dir: ' (reads /proc/<pid>/... to validate caller) "
        "Allowed callers: ztproxy, forticlient-cli (strings adjacent in binary). "
        "Rejected operations with specific error messages: "
        "  'Rejecting GenCSR request from' "
        "  'Rejecting ZtnaSign request from' "
        "  'Rejecting UploadCert request from' "
        "  'Rejecting export_key request from UID: permission denied'. "
        "The access control is PID-based: certd checks /proc/<pid>/exe or /proc/<pid>/status "
        "to verify the calling process is ztproxy or forticlient-cli. "
        "TOCTOU race: between SO_PEERCRED (gets PID) and reading /proc/<pid>/exe, "
        "a fast PID reuse attack could forge the identity of an authorized caller."
    ),

    "pid_reuse_attack": (
        "Linux PID namespace: PIDs are 32-bit integers that wrap around after pid_max (default 32768). "
        "Attack sequence: "
        "1. Wait for ztproxy or forticlient-cli to exit (or force a crash). "
        "2. Rapidly fork() processes to exhaust PIDs until the target PID is reused by an attacker-controlled process. "
        "3. The attacker process connects to /var/run/forticlientcertd.ipc. "
        "4. certd calls SO_PEERCRED -> gets the attacker's PID (same as the former ztproxy PID). "
        "5. certd reads /proc/<pid>/exe -> still reads ztproxy binary path (zombie window or race). "
        "Result: certd grants ZtnaSign to the attacker process. "
        "This is a theoretical race; practicality depends on certd's TOCTOU window size."
    ),

    "socket_path": "/var/run/forticlientcertd.ipc (regular filesystem socket; permissions likely 0660 forticlient group)",

    "re_insight": (
        "The PID-to-binary-path validation in /proc/ is a common Linux pattern. "
        "The TOCTOU race is documented (CVE-2019-5736 for runc exploited the same pattern). "
        "For certd specifically: the window is narrow because certd reads /proc/<pid>/... "
        "immediately after SO_PEERCRED without any delay. "
        "More accessible: check whether the forticlient group membership is too broad -- "
        "if any non-privileged process can join the forticlient group, it can connect to the socket "
        "and the PID race becomes moot."
    ),
}

FCLIENT_CERTD_F03_TPM_ATTESTATION = {
    "id":       "FCLIENT-CERTD-F03",
    "product":  "FortiClient certd -- TPM 2.0 attestation key architecture",
    "severity": "INFORMATIONAL -- architecture detail; no bypass (when hardware TPM present)",
    "class":    "TPM 2.0 attestation; persistent key handle; AIK certificate; tpmrm0 resource manager",

    "description": (
        "certd uses TPM 2.0 for ZTNA key operations: "
        "  /dev/tpm0 -- direct TPM device (kernel driver) "
        "  /dev/tpmrm0 -- TPM resource manager (kernel 4.12+; multiplexed; preferred) "
        "  '/proc/tpm is not available' -- fallback check if neither device exists. "
        "TPM operation types: "
        "  ATTEST_CERTIFY -- TPM2_Certify: certifies that a key is resident in the TPM "
        "  ATTEST_COMMAND_AUDIT -- TPM2_GetCommandAuditDigest: audit trail of TPM commands "
        "  ATTEST_CREATION -- TPM2_CertifyCreation: certifies a newly created key. "
        "Key handle: 'An existing persistent primary (handle %x) key will be used.' "
        "  The persistent primary key handle (e.g., 0x81010001) is pre-provisioned. "
        "AIK: 'Attestation Identity Key Certificate' "
        "  The AIK is used to certify other keys; the AIK certificate proves the AIK is TPM-resident. "
        "TPM session management: "
        "  'Failed to close session:', 'Invalid session handle:', 'Invalid object handle:' "
        "  cmp_TPM2B_AUTH, cmp_TPM2B_DIGEST, cmp_TPM2B_NAME -- TPM2B structure validation. "
        "'Bad magic in tpms_attest' -- validates the TPMS_ATTEST magic number (0xFF544347) before parsing."
    ),

    "re_insight": (
        "The persistent primary key handle is deterministic and known (0x81010001 is the standard EK handle). "
        "If the handle number is hardcoded in certd, an attacker who can read the TPM NVRAM "
        "or intercept /dev/tpmrm0 ioctl calls could potentially replay or forge attestation structures. "
        "Ablation sweep for libcertd.so: "
        "query: 'function calling Tspi_TPM_ActivateIdentity or TPM2_Certify; "
        "passes persistent key handle; validates TPMS_ATTEST structure'."
    ),
}

FCLIENT_CERTD_ZTNA_CHAIN = {
    "id":       "FCLIENT-CERTD-ZTNA-CHAIN",
    "product":  "FortiClient certd -- complete ZTNA attestation IPC chain",

    "chain": (
        "1. EMS sends ZTNA posture check request to FortiClient (via TCP 8013 to epctrl). "
        "2. epctrl passes request to confighandler via System V shared memory (Shm::epctrl_auth_saml). "
        "3. confighandler sends ZtnaSign request to certd via /var/run/forticlientcertd.ipc. "
        "4. certd validates caller PID (SO_PEERCRED -> /proc/<pid>/exe). "
        "5a. (TPM path): certd sends TPM2_Sign to /dev/tpmrm0 with persistent key handle. "
        "5b. (PEM path on VMs): certd reads ZTNA private key PEM from disk and signs with ring/OpenSSL. "
        "6. certd returns Sign response (Protobuf tpm::response::Sign) to confighandler. "
        "7. confighandler includes signature in X-FCCK-TAG message sent by epctrl to EMS."
    ),

    "bypass_options": {
        "vm_pem_key": "FCLIENT-CERTD-F01: extract ZTNA private key PEM from disk on VM endpoint",
        "pid_race":   "FCLIENT-CERTD-F02: race SO_PEERCRED PID validation (theoretical, narrow window)",
        "ems_sqli":   "CVE-2023-48788: compromise EMS server (SYSTEM); ZTNA attestation is moot if relying party is compromised",
        "ems_spoof":  "FCLIENT-EPCTRL-PROTO: forge X-FCCK-TAG with any content; EMS validates on its end",
    },
}


# ---------------------------------------------------------
# update binary RE: FortiGuard update client (C++)
# ---------------------------------------------------------
FORTICLIENT_UPDATE = {
    "id":       "FCLIENT-UPDATE",
    "product":  "FortiClient update -- FortiGuard distribution network client",
    "binary":   "/opt/forticlient/update (ELF64 x86-64 stripped C++; 12.8MB)",
    "language": "C++ (demangled symbols; OpenSSL 3.5.5 bundled from /home/devops/code/.build/)",
    "source": [
        "/home/devops/code/src/update/src/downloader.cpp",
        "/home/devops/code/src/update/src/legacy_downloader.cpp",
        "/home/devops/code/src/update/src/tls_downloader.cpp",
        "/home/devops/code/src/update/src/component/av.cpp",
        "/home/devops/code/src/update/src/component/fdni.cpp",
        "/home/devops/code/src/update/src/component/icdb.cpp",
        "/home/devops/code/src/update/src/component/isdb.cpp",
        "/home/devops/code/src/update/src/component/sandbox.cpp",
        "/home/devops/code/src/update/src/component/vuln.cpp",
    ],
}

FCLIENT_UPDATE_F01_SIGNATURE_TOCTOU = {
    "id":       "FCLIENT-UPDATE-F01",
    "product":  "FortiClient update -- DownloadSignature separate from package (TOCTOU window)",
    "severity": "MEDIUM -- MITM between package download and signature verification = unsigned install",
    "class":    "TOCTOU between package download and signature verification (CWE-367)",

    "description": (
        "The update binary has distinct function/class names: "
        "  'Added component to download: (%s) %s [%s]' -- package added to download queue "
        "  'DownloadSignature' -- separate class/function for signature file download "
        "  'Failed to verify and install patched ISDB file' -- verification after download. "
        "The standard update flow: "
        "  1. Download package file (ISDB tar, AV signature, sandbox signature). "
        "  2. Download signature file (DownloadSignature). "
        "  3. Verify signature against package. "
        "  4. Install. "
        "TOCTOU window: between step 2 (signature file download) and step 3 (verify): "
        "  an attacker with write access to the temporary directory can swap the package file "
        "  for a malicious one AFTER the signature was verified against the original. "
        "MITM attack: if FDS communication is not certificate-pinned, "
        "  an attacker can serve a malicious package + valid signature for a different (older) package "
        "  (downgrade) or substitute the package file after serving a legitimate signature. "
        "CVE-2021-44168 context: Fortinet patched a path traversal in the update mechanism; "
        "  the TOCTOU pattern is structurally similar to that class of vulnerability."
    ),

    "cve_2021_44168": (
        "CVE-2021-44168: FortiClient allows download of a specially crafted update package "
        "that writes arbitrary files on the client. "
        "The path traversal was in the extraction of the update tar archive: "
        "  '/../' string present in update binary -- path validation code. "
        "  'cannot canonicalize', 'cannot make canonical path' -- realpath() checks that fail silently. "
        "  'InstallTar' -- tar extraction class. "
        "Pattern: if the tar archive contains paths like '../../etc/cron.d/malicious', "
        "and the canonicalization check fails without blocking, "
        "the extracted file is written outside the intended installation directory."
    ),

    "re_insight": (
        "The `/../` string appears adjacent to SQLite header in the binary -- "
        "possibly a constant used in path validation (strip ../ sequences). "
        "The error strings 'cannot canonicalize' and 'cannot make canonical path' "
        "are from a realpath()-based check. If realpath() fails (e.g., intermediate directory does not exist), "
        "the check returns an error but the extraction may continue. "
        "Ablation semantic sweep for update binary: "
        "query: 'function extracting tar archive; calls realpath or canonicalize on entry path; "
        "returns error if path contains directory traversal; continues extraction despite error'. "
        "Note: this binary is C++; BERT semantic encoding will work but symbol demangling aids analysis."
    ),
}

FCLIENT_UPDATE_F02_LEGACY_DOWNLOADER = {
    "id":       "FCLIENT-UPDATE-F02",
    "product":  "FortiClient update -- LegacyDownloader FDS protocol fallback",
    "severity": "MEDIUM -- downgrade to legacy FDS may skip TLS certificate verification",
    "class":    "Protocol downgrade to legacy FDS; TLSDownloader vs LegacyDownloader path split",

    "description": (
        "update binary has three downloader implementations: "
        "  N6update10DownloaderE -- base downloader "
        "  N6update13TLSDownloaderE -- TLS-secured downloader (tls_downloader.cpp) "
        "  N6update16LegacyDownloaderE -- legacy protocol downloader (legacy_downloader.cpp). "
        "Error string: 'Legacy FDS detected' -- the binary actively detects legacy FDS servers "
        "and switches to LegacyDownloader. "
        "Error string: 'Failed to connect to proxy, failing over to FDN' -- proxy failure triggers FDN fallback. "
        "Attack surface: "
        "  1. An attacker on the network can present a legacy FDS server. "
        "  2. update binary detects it and switches to LegacyDownloader. "
        "  3. LegacyDownloader likely skips TLS or uses weaker authentication. "
        "  4. Attacker serves malicious package via the legacy protocol. "
        "The FDNI (FortiGuard Distribution Network Information) provides the server list: "
        "  'Got FDNI server entry: %s:%s (tz: %d)' -- hostname + port + timezone "
        "  An attacker who can poison FDNI (DNS, BGP, or via the FDS server list injection) "
        "  can inject a legacy FDS server into the rotation."
    ),

    "re_insight": (
        "The legacy FDS protocol predates TLS-mandatory; it may use HTTP or an older custom protocol. "
        "Ablation semantic sweep for legacy_downloader.cpp code section: "
        "query: 'function connecting to FDS server using non-TLS transport; "
        "sends version request; receives package download URL'. "
        "If legacy_downloader.cpp uses plain HTTP, the entire MITM chain becomes trivial: "
        "DNS spoofing -> FortiClient connects to attacker FDS -> legacy protocol -> "
        "malicious ISDB/AV package served -> InstallTar extracts to arbitrary path."
    ),
}

FCLIENT_UPDATE_COMPONENTS = {
    "id":       "FCLIENT-UPDATE-ARCH",
    "product":  "FortiClient update -- component types and update architecture",

    "component_types": {
        "FDNI":     "FortiGuard Distribution Network Information; provides FDS server list",
        "ISDB":     "Internet Services Database; app identification; delta patching (Applied ISDB patch N of M)",
        "ISDBDelta":"ISDB delta patch; partial update to avoid full ISDB download",
        "AV":       "Antivirus signature (main + extended); copied to client directory",
        "Sandbox":  "FortiSandbox integration signature; cloud sandbox configuration",
        "ICDB":     "Internet Certificate Database (likely) -- certificate database updates",
        "Vuln":     "Vulnerability scan engine (VulnEngine); N6update9component10VulnEngineE",
        "FECT":     "FortiClient Extension Component Table; ComponentImplINS0_4FECTEEE",
    },

    "update_flow": (
        "1. certd+epctrl start, endpoint registered with EMS. "
        "2. fctsched (scheduler) triggers update at scheduled interval. "
        "3. update binary contacts FDNI server to get current FDS server list. "
        "4. update connects to FDS server (TLSDownloader or LegacyDownloader). "
        "5. update compares local component versions with FDS metadata. "
        "6. update downloads changed components (DownloadSignature per component). "
        "7. update verifies package signature, installs via InstallTar. "
        "8. ISDB: delta patches applied (Applied ISDB patch N of M)."
    ),

    "install_json": (
        "install.json -- installation manifest; likely lists target paths for each component. "
        "If install.json is read from the downloaded package (not bundled in binary), "
        "it is an attacker-controlled input that determines write paths. "
        "Path traversal in install.json would bypass any tar-level path check."
    ),
}
