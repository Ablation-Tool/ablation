"""
FortiClient Windows standalone RE (forticlient_standalone_win64.exe)
Version: 7.4.7 (2026-05-01 build timestamps)
Structure: ZIP -> FortiClientStandalone.msi (Compound) -> multiple .cab files
Method: 7z extract + strings analysis on PE32+/Go binaries and kernel driver
"""

# ---------------------------------------------------------
# Windows architecture
# ---------------------------------------------------------
WIN_ARCH = {
    "id":       "WIN-ARCH",
    "product":  "FortiClient Windows standalone 7.4.7 (x64)",

    "installer_structure": {
        "format":   "ZIP -> FortiClientStandalone.msi (MSI/Compound OLE)",
        "cabs": {
            "common.cab":   "122MB; main binaries (Electron GUI, FortiTray, FortiTcs, crypto, etc.)",
            "VPN.cab":      "3.3MB; VPN binaries (ipsec.exe, xmlvpn.dll, IPS signature database)",
            "x64.cab":      "65KB; kernel driver (fortitransctrl.sys)",
            "PAM.cab":      "1.3MB; Privileged Access Management",
            "Core.cab":     "18MB; core service",
        },
    },

    "key_binaries": {
        "File_FortiClient.exe":     "162MB Electron/Chromium GUI; PE32+ (x64)",
        "File_FortiTray.exe":       "3.1MB Windows tray daemon; PE32+ (C/C++); named pipe IPC",
        "File_FortiTcs.exe":        "12.6MB service controller; Go binary; token impersonation",
        "File_FortiElevate.exe":    "97KB privilege elevation helper; PE32+ (C++); asInvoker manifest",
        "File_ipsec.exe":           "5.8MB IPsec/IKE daemon; Go binary; VPN.cab",
        "File_FortiAuth.exe":       "196KB .NET (Mono) assembly; Azure/SAML authentication",
        "File_AzureToken2.exe":     "29KB Azure AD token acquisition; PE32",
        "File_xmlvpn.dll":          "877KB VPN XML config parser; TinyXML (PE32+)",
        "File_xmlztna.dll":         "507KB ZTNA XML parser; TinyXML (PE32+)",
        "File_nanomsg.dll":         "254KB NNG/nanomsg IPC; Windows named pipe backend",
        "File_sslvpnlib.dll":       "1.7MB SSL VPN library",
        "File_FCCryptDLL.dll":      "631KB cryptographic library",
        "File_fortivna.dll":        "241KB FortiVNA (Virtual Network Adapter) library",
        "File_FortiHealth.dll":     "857KB health/compliance checking",
        "fortitransctrl.sys":       "134KB Windows kernel driver; WFP callout + NDIS; x64.cab",
    },

    "ipc_architecture": {
        "protocol":         "Named pipes (Windows) replaces Unix domain sockets (Linux)",
        "known_pipes": {
            "\\\\pipe\\\\NsloCollectorServiceSecurePipe": "NSLO collector service (audit logging)",
            "FortiVPN pipe":    "PIPEMSG_VPN_START / PIPEMSG_VPN_STOP messages from FortiTray",
            "fortitray pipe":   "FortiTcs sends auth messages to FortiTray: 'failed to write to fortitray'",
        },
        "nanomsg": "nanomsg.dll implements NNG; same IPC bus architecture as Linux (ipc:// scheme on Windows)",
    },

    "kernel_driver": {
        "name":     "fortitransctrl.sys (\\Device\\FortitransCtrlDrv, \\??\\FortitransCtrlDrv)",
        "type":     "WFP (Windows Filtering Platform) callout driver + NDIS",
        "callouts": [
            "FortiTransCtrl auth connect callout (ALE auth connect layer)",
            "FortiTransCtrl auth recv-accept callout",
            "FortitransCtrl bind redirect callout (FWPS_LAYER_ALE_BIND_REDIRECT_V4)",
            "FortiTransCtrl connection redirect callout",
            "FortiTransCtrl datagram data callout (v4/v6)",
            "FortiTransCtrl stream data callout/filter (v4/v6)",
            "FortiTransCtrl subLayer",
        ],
        "ioctl_commands": [
            "CONNFORWARD_IOCTL_CMD_FQDN_REAL_IP -- set FQDN-to-IP mapping in kernel",
            "CONNFORWARD_IOCTL_CMD_APPEND_REDIRECT_IP -- add IP redirect rule in kernel",
        ],
        "creation":     "IoCreateDeviceSecure SDDL CONFIRMED: D:P(A;;GA;;;SY)(A;;GA;;;BA) -- SYSTEM and Administrators only; no world access",
        "pool_alloc":   "ExAllocatePoolWithTag (deprecated in Win11 22H2; should be ExAllocatePool2)",
        "packet_inject": ["FwpsInjectTransportReceiveAsync", "FwpsInjectNetworkSendAsync"],
    },
}


# ---------------------------------------------------------
# WIN-F01: Kernel driver IOCTL with unconfirmed device ACL
# ---------------------------------------------------------
WIN_F01_DRIVER_IOCTL = {
    "id":       "WIN-F01",
    "product":  "FortiClient Windows -- fortitransctrl.sys WFP callout driver; IOCTL interface with unconfirmed device SDDL; FQDN/IP redirect manipulation from kernel",
    "severity": "MEDIUM -- device SDDL confirmed D:P(A;;GA;;;SY)(A;;GA;;;BA): SYSTEM+Admins only; unprivileged IOCTL ruled out; ExAllocatePoolWithTag (deprecated NX) and post-exploitation IOCTL abuse remain",
    "class":    "Kernel IOCTL access control + kernel-level MITM (CWE-284, CWE-749)",

    "evidence": [
        "fortitransctrl.sys strings: 'CONNFORWARD_IOCTL_CMD_FQDN_REAL_IP error!'",
        "fortitransctrl.sys strings: 'CONNFORWARD_IOCTL_CMD_APPEND_REDIRECT_IP error!'",
        "fortitransctrl.sys: IoCreateDeviceSecure -- SDDL not confirmed; requires runtime check",
        "fortitransctrl.sys: FWPS_LAYER_ALE_BIND_REDIRECT_V4 callout = kernel socket bind intercept",
        "fortitransctrl.sys: FwpsInjectTransportReceiveAsync + FwpsInjectNetworkSendAsync = packet injection",
        "fortitransctrl.sys: ExAllocatePoolWithTag (deprecated; missing ExAllocatePool2 NX bit)",
    ],

    "attack_surface": {
        "ioctl_unprivileged": (
            "RULED OUT: SDDL D:P(A;;GA;;;SY)(A;;GA;;;BA) blocks all non-admin access. "
            "Standard user processes cannot open \\\\Device\\\\FortitransCtrlDrv. "
            "---\n"
            "If IoCreateDeviceSecure uses a permissive SDDL (e.g., world-readable/writable), "
            "any local process can open \\\\Device\\\\FortitransCtrlDrv and issue IOCTLs. "
            "CONNFORWARD_IOCTL_CMD_FQDN_REAL_IP: attacker sets forged FQDN-to-IP mappings "
            "in the kernel filter table -> kernel-level DNS hijacking bypassing all userspace DNS. "
            "CONNFORWARD_IOCTL_CMD_APPEND_REDIRECT_IP: attacker adds IP redirect rules -> "
            "kernel-level traffic MITM for any IP (bypasses Windows Firewall + HTTPS cert checks "
            "only at kernel packet level, not at TLS layer). "
            "Fleet impact: if FortiClient is managed by EMS and EMS is compromised, "
            "the attacker can push IOCTL commands to fortitransctrl.sys on all enrolled endpoints "
            "via the FortiTcs/FortiTray service chain."
        ),
        "pool_overflow": (
            "ExAllocatePoolWithTag without NX flag (should be ExAllocatePool2 POOL_FLAG_NON_PAGED_EXECUTE). "
            "If IOCTL input length for FQDN strings is not bounded before pool allocation, "
            "kernel NonPagedPool overflow -> BSOD or kernel code execution. "
            "The FQDN data comes from userspace IOCTL -> attacker-controlled."
        ),
        "bind_redirect": (
            "FortitransCtrl bind redirect callout intercepts ALL socket bind() calls at "
            "FWPS_LAYER_ALE_BIND_REDIRECT_V4. If attacker controls the IOCTL to configure "
            "redirect rules, they can transparently redirect any process's network connections "
            "at the kernel layer -- invisible to all userspace monitoring."
        ),
    },

    "verification_needed": (
        "Confirm device SDDL: use sc.exe sdshow FortitransCtrlDrv or "
        "NtOpenFile/ZwOpenFile from low-privilege process to check accessibility. "
        "Confirm IOCTL input validation: specifically length bounds on FQDN string parameter."
    ),

    "see_also": [
        "WIN-F03: TinyXML in xmlztna.dll processes network-sourced XML at userspace level",
        "IKED-F01: Linux iked fragment reassembly; ipsec.exe (Go binary in VPN.cab) is the Windows equivalent",
    ],
}


# ---------------------------------------------------------
# WIN-F02: Named pipe ACL -- PIPEMSG injection
# ---------------------------------------------------------
WIN_F02_PIPE_ACL = {
    "id":       "WIN-F02",
    "product":  "FortiClient Windows -- FortiTray and FortiVPN communicate via named pipes; pipe ACL not confirmed; PIPEMSG injection may enable VPN state manipulation",
    "severity": "HIGH if pipe is world-accessible; MEDIUM otherwise (VPN start/stop from unprivileged process)",
    "class":    "Named pipe access control (CWE-284, CWE-732)",

    "evidence": [
        "FortiTray.exe strings: 'post_pipemsg_to_fortivpn(PIPEMSG_VPN_STOP) returned %d'",
        "FortiTray.exe strings: 'post_pipemsg_to_fortivpn(PIPEMSG_VPN_START) returned %d'",
        "FortiTray.exe strings: 'ignore request from pid=%d state=%d app=%d of pipe=%ws'",
        "FortiTray.exe strings: '\\\\pipe\\\\NsloCollectorServiceSecurePipe'",
        "FortiTray.exe strings: 'ConnectNamedPipe' + 'CreateNamedPipeW'",
    ],

    "mechanism": (
        "FortiTray sends PIPEMSG_VPN_START and PIPEMSG_VPN_STOP messages to the FortiVPN daemon "
        "via named pipes. The log message 'ignore request from pid=%d state=%d app=%d of pipe=%ws' "
        "shows there IS a caller check, but it only ignores (not refuses) unauthorized callers. "
        "The named pipe ACL (set at CreateNamedPipeW) determines who can connect. "
        "If the pipe DACL allows low-privilege users: "
        "  1. Local process opens the named pipe "
        "  2. Sends PIPEMSG_VPN_STOP -> disconnects the VPN tunnel (DoS) "
        "  3. Sends PIPEMSG_VPN_START with modified tunnel parameters -> connects to attacker's VPN endpoint "
        "Verification: use accesschk.exe to check pipe DACL; replicate PIPEMSG format from protocol RE."
    ),

    "nslo_pipe": (
        "\\\\pipe\\\\NsloCollectorServiceSecurePipe -- 'Secure' in the name is advisory, not guaranteed. "
        "This pipe handles audit/logging collection. If world-accessible, attacker can forge "
        "compliance/audit log entries via the pipe, poisoning the audit trail."
    ),
}


# ---------------------------------------------------------
# WIN-F03: TinyXML in VPN and ZTNA XML parsers
# ---------------------------------------------------------
WIN_F03_TINYXML = {
    "id":       "WIN-F03",
    "product":  "FortiClient Windows -- xmlvpn.dll and xmlztna.dll use TinyXML for VPN/ZTNA configuration parsing; TinyXML has multiple buffer overflow CVEs",
    "severity": "HIGH -- VPN/ZTNA config comes from FortiGate/EMS; malformed XML -> potential buffer overflow in DLL context",
    "class":    "Vulnerable XML library with network-reachable attack surface (CWE-787, CWE-611)",

    "evidence": [
        "xmlztna.dll strings: '.?AVTiXmlText@@', '.?AVTiXmlAttribute@@', '.?AVTiXmlNode@@', '.?AVTiXmlDocument@@'",
        "xmlztna.dll strings: 'ExportToXml', 'ImportFromXml'",
        "xmlvpn.dll (VPN.cab): same TinyXML class references expected",
        "TinyXML 1.x/2.x has CVE-2021-42260 (heap buffer overflow), CVE-2023-34194, and others",
    ],

    "mechanism": (
        "xmlztna.dll parses ZTNA configuration XML received from the FortiGate or EMS server. "
        "xmlvpn.dll parses VPN profile XML. "
        "TinyXML's TiXmlDocument::Parse() has had multiple CVEs: "
        "  - CVE-2021-42260: heap buffer overflow in TiXmlBase::GetChar "
        "  - Integer overflow in element/attribute length handling "
        "If Fortinet uses an unpatched TinyXML version, a rogue FortiGate/EMS can send "
        "malformed XML to exploit the parser. "
        "Attack: rogue FortiGate sends oversized XML attribute -> TinyXML heap overflow "
        "-> code execution in the FortiClient VPN service process context (admin/SYSTEM)."
    ),

    "see_also": [
        "IKED-F04/F05: IKED SAML/EAP-TTLS parsing on Linux; same rogue FortiGate attack vector",
        "WIN-F01: kernel driver affected by same rogue FortiGate origin",
    ],
}


# ---------------------------------------------------------
# WIN-F04: FortiElevate.exe -- asInvoker + ShellExecuteEx UAC bypass surface
# ---------------------------------------------------------
WIN_F04_FORTIELEVATE = {
    "id":       "WIN-F04",
    "product":  "FortiClient Windows -- FortiElevate.exe uses asInvoker manifest + ShellExecuteExW; privilege elevation pattern requires analysis of what it elevates and with what parameters",
    "severity": "MEDIUM -- context-dependent; FortiElevate is called from the Electron GUI with -noschedulercheck arg",
    "class":    "Privilege elevation component requiring parameter validation (CWE-250)",

    "evidence": [
        "FortiElevate.exe strings: 'requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"' (does NOT self-elevate)",
        "FortiElevate.exe strings: 'ShellExecuteExW' (delegates elevation via runas verb)",
        "FortiElevate.exe strings: 'service_is_running', 'service_start', 'sec_get_elevation_type'",
        "FortiElevate.exe strings: 'CommandLineToArgvW' (parses -noschedulercheck arg from Linux GUI source reference)",
        "Linux GUI main.js line ~272846: n(5317).execFile('./FortiElevate.exe', ['-noschedulercheck'], callback)",
        "Source path: C:\\279\\2902741\\FortiClientHS\\service\\FCCryptdAPI\\FCCryptdAPI.cpp",
    ],

    "mechanism": (
        "FortiElevate.exe is a 97KB C++ binary with asInvoker manifest (does not self-elevate via UAC). "
        "It uses ShellExecuteExW to launch something with elevated privileges. "
        "The Electron GUI calls FortiElevate.exe with -noschedulercheck flag. "
        "Key questions (require disassembly to answer definitively): "
        "  1. Does FortiElevate.exe call ShellExecuteEx with runas verb on a hardcoded binary, "
        "     or does it accept the target binary path from command-line arguments? "
        "  2. If the target path is user-controllable, GUI XSS (GUI-F01/F02 equivalent on Windows) "
        "     could call FortiElevate.exe with a malicious target -> UAC dialog for attacker-chosen binary. "
        "  3. The -noschedulercheck flag bypasses a Windows Task Scheduler check (prevents scheduled task "
        "     recreation interference), suggesting FortiElevate creates or manages scheduled tasks."
    ),

    "attack_surface": (
        "If the Electron GUI on Windows exposes the same api.sudoer/ipc.invoke preload as Linux: "
        "  - elevateGUI() IPC handler calls FortiElevate.exe (same code path, cross-platform) "
        "  - GUI XSS -> window.forticlient.elevateGUI() -> FortiElevate.exe "
        "  - Result depends on what FortiElevate.exe elevates and whether target is hardcoded."
    ),
}


# ---------------------------------------------------------
# WIN-F05: Token impersonation in FortiTcs.exe (Go service controller)
# ---------------------------------------------------------
WIN_F05_TOKEN_IMPERSONATION = {
    "id":       "WIN-F05",
    "product":  "FortiClient Windows -- FortiTcs.exe (Go service controller) calls ImpersonateSelf + DuplicateTokenEx + AdjustTokenPrivileges; SetSecurityDescriptorDacl modifies DACLs",
    "severity": "HIGH -- improper use of token impersonation or DACL modification = local privilege escalation",
    "class":    "Token impersonation and privilege manipulation (CWE-269, CWE-732)",

    "evidence": [
        "FortiTcs.exe strings: 'ImpersonateSelf' (impersonates current thread's token)",
        "FortiTcs.exe strings: 'DuplicateTokenEx' (duplicates access token for privilege changes)",
        "FortiTcs.exe strings: 'AdjustTokenPrivileges' (enables/disables token privileges)",
        "FortiTcs.exe strings: 'AdjustTokenGroups' (modifies group membership in token)",
        "FortiTcs.exe strings: 'IsTokenRestricted' (checks for restricted token)",
        "FortiTcs.exe strings: 'SetSecurityDescriptorDacl' (modifies DACL on objects)",
        "FortiTcs.exe strings: 'SetNamedSecurityInfoW' (sets security on named objects)",
        "FortiTcs.exe strings: 'GetNamedSecurityInfoW' (reads security from named objects)",
        "FortiTcs.exe Go symbol: 'fortinet.com/fct/common.RevertImpersonateUser'",
        "FortiTcs.exe Go symbol: 'main.SetSecurityDescriptorDacl' (main package DACL setter)",
    ],

    "mechanism": (
        "FortiTcs.exe (the main FortiClient Windows service controller, a Go binary) "
        "implements token impersonation via ImpersonateSelf + DuplicateTokenEx to run "
        "privileged operations in a user context. "
        "The Go symbol 'fortinet.com/fct/common.RevertImpersonateUser' is the cleanup path "
        "after impersonation -- if this is not called in all error paths, token leaks occur. "
        "main.SetSecurityDescriptorDacl modifies DACLs on objects. "
        "If SetNamedSecurityInfoW is called on kernel objects (pipes, events, mutexes) "
        "with insufficient restrictions, a low-privilege process gains write access. "
        "Attack vectors: "
        "  1. Token leak: if RevertImpersonateUser is skipped on error paths, "
        "     a subsequent call to OpenThreadToken retrieves elevated token from an elevated thread. "
        "  2. DACL loosening: if main.SetSecurityDescriptorDacl sets world-writable DACLs on "
        "     kernel objects, local escalation via those objects. "
        "  3. AdjustTokenPrivileges enabling SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege "
        "     on a token that's then accessible to low-privilege code."
    ),

    "ztna_functions": {
        "RequestAzureTokenFromFortiTray":   "FortiTcs requests Azure AD tokens via FortiTray IPC",
        "IsCurrentUserInAzureDomain":       "Azure AD membership check (potential TOCTOU)",
        "GetTokenFromCurrentUser":          "extracts token from current user context",
        "AzureToken2.exe":                  "29KB Azure token helper; spawned as subprocess",
    },
}


# ---------------------------------------------------------
# WIN-F06: IPS signature database extracted from tar at runtime
# ---------------------------------------------------------
WIN_F06_ISDB_EXTRACT = {
    "id":       "WIN-F06",
    "product":  "FortiClient Windows -- isdb.tar (IPS signature database) extracted at runtime; binary replacement race similar to FORTITRAY-F01",
    "severity": "MEDIUM -- requires write access to VPN installation directory; code execution in IPS engine context",
    "class":    "Insecure runtime archive extraction (CWE-494); same pattern as FORTITRAY-F01 and MACOS-F04",

    "evidence": [
        "VPN.cab contents: 'File_isdb.tar' (4.1MB), 'File_isdb_app.txt', 'File_isdb_map.dat', 'File_vsdb.json'",
        "isdb.tar extracted at runtime and parsed by libips.dylib equivalent on Windows",
    ],

    "mechanism": (
        "The IPS signature database (isdb.tar) is installed in the FortiClient directory "
        "and extracted at runtime. If the installation directory has incorrect permissions, "
        "a local attacker replaces isdb.tar with one containing a malicious binary or "
        "signature file that triggers a parser vulnerability in the IPS engine when processed."
    ),
}


# ---------------------------------------------------------
# WIN-F07: ipsec.exe IKEv2 fragment reassembly (Windows iked)
# ---------------------------------------------------------
WIN_F07_IPSEC_FRAG = {
    "id":       "WIN-F07",
    "product":  "FortiClient Windows -- ipsec.exe (C/C++ iked, 5.8MB, VPN.cab); IKEv2 RFC7383 fragment reassembly (ikev2_frags_reassemble); same class as IKED-F01 on Linux",
    "severity": "HIGH -- network-reachable; rogue FortiGate can send crafted IKEv2 fragments; pre-auth if IKE_SA_INIT phase is targeted",
    "class":    "IKE fragment reassembly attack surface (CWE-120, CWE-400)",

    "evidence": [
        "ipsec.exe strings: 'ikev2_frags_reassemble' (RFC7383 fragment reassembly function)",
        "ipsec.exe strings: '%s: Total Fragments too big %u' (fragment count guard present)",
        "ipsec.exe strings: 'N_FRAGMENTATION_SUPPORTED' (IKEv2 fragmentation negotiated)",
        "ipsec.exe strings: 'ikev2_send_encrypted_fragments' (fragment sending path)",
        "ipsec.exe strings: 'ikev2_getimsgdata: length too small for sh' (length check -- if not exhaustive, bypass possible)",
        "Source: ..\\..\\iked\\config.c, ..\\..\\iked\\ca.c (same C codebase as Linux iked)",
        "Build: C:\\6627\\2443094\\FortiClientHS\\ (matches Linux build tree prefix)",
        "Protobuf 31.1: C:\\6627\\2443094\\libraries\\src\\protobuf\\ (IKE config serialization)",
    ],

    "mechanism": (
        "ipsec.exe is the Windows port of the same iked C codebase running on Linux FortiClient. "
        "ikev2_frags_reassemble accumulates IKEv2 Encrypted Fragment payloads (RFC7383) into a buffer. "
        "The 'Total Fragments too big' guard checks fragment COUNT but may not bound the "
        "TOTAL REASSEMBLED SIZE independently -- if per-fragment size * count overflows "
        "the reassembly buffer allocation size, heap overflow results. "
        "Pre-auth: IKE_SA_INIT uses fragments BEFORE the IKE_AUTH exchange completes. "
        "EAP-TTLS phase also present: 'EAP-TTLS: too short Phase 2 request (len=%lu)' "
        "and 'EAP-TTLS: Phase 2 MSCHAPV2 Request' -- EAP tunnel carries MSCHAPv2 challenges "
        "from the FortiGate without certificate-pinned validation of EAP server identity "
        "(same IKED-F04/F05 pattern on Windows)."
    ),

    "eap_attack_surface": {
        "eap_ttls_mschapv2": (
            "FortiClient connects to FortiGate's EAP-TTLS server; inside the TLS tunnel, "
            "MSCHAPv2 challenges from the FortiGate are processed. "
            "If FortiClient does not pin the EAP server certificate against the gateway's "
            "configured identity, a rogue FortiGate (or MITM) sends crafted MSCHAPv2 challenges "
            "-> NTLM hash capture (MS-CHAPv2 DES) without user awareness."
        ),
        "protobuf": (
            "Protobuf 31.1 used for IKE config/state messages. "
            "Protobuf parse_context.h included from C:\\6627\\2443094\\libraries\\src\\protobuf\\. "
            "Attacker-controlled IKE config from EMS/FortiGate -> protobuf deserialization path "
            "-> CVE-2022-1941 class (proto3 required fields / arena corruption)."
        ),
    },

    "see_also": [
        "IKED-F01: Linux iked fragment reassembly (same C source)",
        "IKED-F04/F05: EAP-TTLS credential exposure (same attack surface, Windows ipsec.exe)",
    ],
}


# ---------------------------------------------------------
# WIN-F08: xmlvpn.dll TinyXML + TinyXPath double-parser; FortiGate XML arrives here
# ---------------------------------------------------------
WIN_F08_XMLVPN_TINYXML = {
    "id":       "WIN-F08",
    "product":  "FortiClient Windows -- xmlvpn.dll uses TinyXML + TinyXPath (877KB, VPN.cab); FortiGate VPN profile XML processed at connection setup",
    "severity": "HIGH -- rogue FortiGate sends malformed XML config; dual parser (TinyXML + TinyXPath) means two separate exploit surfaces",
    "class":    "Vulnerable XML/XPath library (CWE-787, CWE-611); same class as WIN-F03 (xmlztna.dll) but VPN path",

    "evidence": [
        "xmlvpn.dll RTTI: '.?AVTiXmlDocument@@', '.?AVTiXmlElement@@', '.?AVTiXmlBase@@'",
        "xmlvpn.dll RTTI: '.?AVxpath_processor@TinyXPath@@', '.?AVsyntax_overflow@TinyXPath@@'",
        "xmlvpn.dll RTTI: '.?AVtoken_list@TinyXPath@@', '.?AVbyte_stream@TinyXPath@@'",
        "xmlvpn.dll XPath paths: '/forticlient_configuration/vpn/ipsecvpn/connections/connection/ike_settings/fgt'",
        "xmlvpn.dll XPath paths: '/forticlient_configuration/vpn/sslvpn/connections/connection'",
        "xmlvpn.dll source: C:\\279\\2902741\\FortiClientHS\\service\\xmlvpn\\x64\\Release\\xmlvpn.pdb",
        "xmlvpn.dll exports: ExportToXml, ImportFromXml, VpnLockDown_Get/SetDeadLockedFlag, VpnLockDown_Get/SetTempLockedFlag",
    ],

    "mechanism": (
        "xmlvpn.dll parses FortiGate-supplied VPN connection profiles via TinyXML. "
        "XPath queries extract IKE settings and connection parameters. "
        "TinyXPath 'syntax_overflow' exception class reveals the XPath evaluator uses a fixed-size "
        "token/expression stack -- a deeply nested XPath expression from FortiGate overflows it. "
        "Attack: rogue FortiGate returns a 'VPN profile' XML with: "
        "  1. Oversized element content -> TinyXML heap overflow (CVE-2021-42260 class) "
        "  2. Deeply nested XPath -> TinyXPath syntax_overflow -> C++ exception with "
        "     potential use-after-free in the exception handler path "
        "  3. XML entity expansion (XXE) if external entity processing not disabled "
        "Both ExportToXml and ImportFromXml are DLL exports -- xmlvpn.dll is the serialization "
        "boundary between FortiGate-controlled config and the local VPN service."
    ),

    "note": (
        "VpnLockDown_GetDeadLockedFlag and VpnLockDown_SetTempLockedFlag suggest VPN lockdown "
        "mode (block all non-VPN traffic) is controlled via this DLL. An attacker who corrupts "
        "the VPN config via xmlvpn.dll may also affect the lockdown state."
    ),
}


# ---------------------------------------------------------
# WIN-F09: FCAuth.exe credential dialog -- named pipe with same PID-based ignore pattern
# ---------------------------------------------------------
WIN_F09_FCAUTH_PIPE = {
    "id":       "WIN-F09",
    "product":  "FortiClient Windows -- FCAuth.exe (credential dialog, VPN.cab); named pipe with PID-based 'ignore' (not deny); same class as WIN-F02 (FortiTray pipe)",
    "severity": "MEDIUM -- if pipe is world-accessible, attacker can inject into authentication dialog flow or suppress credential prompts",
    "class":    "Named pipe access control (CWE-284); credential dialog spoofing",

    "evidence": [
        "FCAuth.exe strings: 'ignore request from pid=%d state=%d app=%d of pipe=%ws'",
        "FCAuth.exe strings: 'GetNamedPipeClientProcessId', 'GetNamedPipeClientSessionId'",
        "FCAuth.exe strings: 'PIPEMSG: Peercheck pipe=%ws pid=%d, session=%d, app=%ws'",
        "FCAuth.exe strings: 'Credential Dialog Xaml Host' (Windows Xaml credential UI)",
        "FCAuth.exe strings: 'HandlePipeMsg', 'MsgPipe_PostMessage_UE'",
        "FCAuth.exe source: C:\\279\\2902741\\FortiClientHS\\service\\AuthDaemon\\x64\\Release\\fcauth.pdb",
    ],

    "mechanism": (
        "FCAuth.exe hosts the Windows credential dialog (Xaml-based) for VPN authentication. "
        "It communicates with the VPN service via a named pipe using the same 'ignore request from pid' "
        "pattern as FortiTray -- unauthorized callers are ignored, not rejected. "
        "If the pipe DACL allows low-privilege write: "
        "  1. Attacker process opens FCAuth pipe "
        "  2. Sends PIPEMSG to trigger credential dialog display -> phishing (attacker-controlled "
        "     credential dialog appearing at arbitrary times) "
        "  3. Sends PIPEMSG to suppress credential dialog -> credential collection bypass "
        "WTSQueryUserToken in the import list: FCAuth.exe queries user session tokens, "
        "meaning it runs as SYSTEM and impersonates the user for credential operations."
    ),
}


# ---------------------------------------------------------
# WIN-F10: FCConfig2.exe -- Rust WebSocket+OIDC server on 127.0.0.1:8011; JWT 'none' alg attack surface
# ---------------------------------------------------------
WIN_F10_FCCONFIG2_JWT = {
    "id":       "WIN-F10",
    "product":  "FortiClient Windows -- FCConfig2.exe (Rust/Tokio WebSocket+OIDC config daemon); binds 127.0.0.1:8011; JWT 'none' algorithm in signing algorithm list; local OIDC provider with potential token forgery",
    "severity": "HIGH -- local WebSocket config endpoint on 127.0.0.1:8011 accessible to all local processes; JWT 'none' alg MITIGATED (openidconnect Rust crate hard-rejects it); residual: token theft via OIDC redirect race or WebSocket pre-auth info disclosure",
    "class":    "Local WebSocket config endpoint access control (CWE-284); OIDC redirect port race (CWE-362)",

    "evidence": [
        "FCConfig2.exe (11MB Rust binary) strings: '127.0.0.1:8011' (WebSocket bind address)",
        "FCConfig2.exe strings: 'websocket upgrade complete', 'sec-websocket-key', 'sec-websocket-version'",
        "FCConfig2.exe strings: 'forticlient::standalone::http::server::OidcRedirectListener::run'",
        "FCConfig2.exe strings: 'confighandler_rust::webserver::routes::websock::command::Command::send_to_clients'",
        "FCConfig2.exe strings: 'Websocket msg:' + 'handle_message' (WebSocket message dispatch)",
        "FCConfig2.exe strings: 'CoreJwsSigningAlgorithmHS256HS384HS512RS256RS384RS512ES256ES384ES512PS256PS384PS512EdDSA' -- none present in algorithm enumeration",
        "FCConfig2.exe strings: 'sh_token', 'id_token', 'nonce mi', 'bad sign' (JWT token handling)",
        "FCConfig2.exe strings: 'struct JsonWebKeySet', 'jwks_uri' (full OIDC discovery document support)",
        "FCConfig2.exe source: C:\\279\\2902741\\ForticlientNG\\Apps\\confighandler-rust\\src\\webserver\\routes\\websock\\command\\license.rs",
        "FCConfig2.exe source: C:\\279\\2902741\\ForticlientNG\\Base\\forticlient\\src\\standalone\\http\\server.rs (OIDC redirect listener)",
    ],

    "mechanism": (
        "FCConfig2.exe is a Rust/Tokio+Warp HTTP+WebSocket server providing: "
        "  1. WebSocket IPC for config commands (the Electron GUI connects here as the 'confighandler') "
        "  2. OIDC redirect listener for Azure/SAML auth callbacks "
        "  3. JWT-protected config API using 'sh_token' (shared token) "
        "The JWT signing algorithm list includes 'none' in the algorithm enum. "
        "If the JWT library accepts a token with header alg:none, an attacker can: "
        "  1. Connect to ws://127.0.0.1:8011 from any local process "
        "  2. Forge a JWT with alg:none and any sh_token claim "
        "  3. Issue config commands as an authenticated Fabric Agent client "
        "  -> arbitrary config read/write including VPN credentials, compliance policy bypass. "
        "The OIDC redirect listener (port may be 127.0.0.1:34254) "
        "could also be interceptable by a local process registering a race on the port."
    ),

    "attack_surface": {
        "jwt_none_alg": (
            "MITIGATED: FCConfig2.exe uses openidconnect Rust crate "
            "(C:\\279\\2902741\\ForticlientNG\\vendor\\openidconnect\\src\\verification\\mod.rs). "
            "The crate hard-rejects alg:none in verification::mod.rs -- 'noneunrecognized JSON Web Algorithm' "
            "is an error variant, not an accepted algorithm. Algorithm confusion attack is blocked."
        ),
        "websocket_unauthenticated": (
            "If WebSocket endpoint at ws://127.0.0.1:8011 serves any commands before JWT "
            "auth validation (e.g., version info, license query, public OIDC discovery), "
            "information disclosure before any auth is required."
        ),
        "oidc_redirect_race": (
            "OidcRedirectListener binds a local port to receive the OAuth callback. "
            "If the port is dynamic and written to a shared file (same service_port pattern "
            "as Linux GUI-F06), attacker writes a rogue port -> OIDC redirect goes to attacker "
            "-> intercepts Azure AD id_token."
        ),
    },

    "see_also": [
        "GUI-F06: Linux service_port injection (same class -- local port file written for IPC)",
        "WIN-F05: FortiTcs.exe token manipulation -- combined with FCConfig2 JWT forgery = full config+service control",
    ],
}


# ---------------------------------------------------------
# WIN-F11: sslvpnlib.dll -- cert validation bypass via user dialog + shared memory credential exposure
# ---------------------------------------------------------
WIN_F11_SSLVPN = {
    "id":       "WIN-F11",
    "product":  "FortiClient Windows -- sslvpnlib.dll (1.7MB SSL-VPN library); user-bypassable server cert validation; FortiVpnDll2.dll VPN state shared memory with GR ACE for unknown SID",
    "severity": "HIGH -- MITM credential capture via cert dialog bypass; potential credential read from shared memory",
    "class":    "Trust-on-first-use cert validation (CWE-297) + shared memory access control (CWE-732)",

    "evidence": [
        "sslvpnlib.dll strings: 'IsSslvpnStrictServerCertValidationEnabled' (non-strict mode implies bypass path)",
        "sslvpnlib.dll strings: 'User doesn\\'t want to proceed connection with invalid certificate'",
        "sslvpnlib.dll strings: 'ShowServerCerttificateWarningMessage' (dialog shown, not blocked)",
        "sslvpnlib.dll strings: 'CSslvpnBase::GetServerCertFingerprint' (fingerprint pinning available but not default)",
        "sslvpnlib.dll strings: '\\\\pipe\\\\FortiSslvpnNamedPipe' (named pipe for SSL-VPN daemon IPC)",
        "FortiVpnDll2.dll strings: SDDL 'D:(A;;GAFA;;;' + '(A;;GA;;;' + '(A;;GR;;;' -- three ACEs, third has GR (read) for unknown SID",
        "FortiVpnDll2.dll strings: 'VpnConnInfo_GetUsername', 'VpnConnInfo_GetRemoteGateway', 'VpnConnInfo_GetCommandline'",
        "FortiVpnDll2.dll strings: 'Clear string [%s] in VpnConnParam shared memory in session %lu'",
    ],

    "cert_bypass": (
        "sslvpnlib.dll uses WinHTTP for SSL-VPN HTTPS connections. "
        "Non-strict mode allows the user to click through a certificate warning dialog "
        "and connect to an invalid server. "
        "A rogue FortiGate with a self-signed cert: "
        "  1. User sees ShowServerCerttificateWarningMessage dialog "
        "  2. If user proceeds: SSL-VPN credentials sent to attacker's endpoint "
        "  3. Fingerprint pinning only works if previously stored."
    ),

    "shared_mem_credential": (
        "FortiVpnDll2.dll stores VPN connection parameters including VpnConnInfo_GetUsername "
        "in a shared memory section. SDDL third ACE has GR (read-only) for dynamically computed SID. "
        "If that SID = BU (Built-in Users) or WD (Everyone): any local process maps the section "
        "and reads VPN session parameters including username and connection metadata. "
        "Verification: OpenFileMappingW test from low-priv process."
    ),
}


# ---------------------------------------------------------
# WIN-F12: FortiAuth.exe WebView2 SAML -- JsonDeserializeHtml from rogue FortiGate
# ---------------------------------------------------------
WIN_F12_FORTIAUTH_SAML = {
    "id":       "WIN-F12",
    "product":  "FortiClient Windows -- FortiAuth.exe (.NET 4.7.2 + WebView2); SAML response deserialized via JsonDeserializeHtml; SAMLResponse content from FortiGate-controlled page",
    "severity": "HIGH -- rogue FortiGate controls WebView2 page content; malformed JSON in SAML response -> deserialization in .NET 4.7.2 context",
    "class":    "Attacker-controlled JSON deserialization via browser SAML flow (CWE-502)",

    "evidence": [
        "FortiAuth.exe strings: 'CoreWebView2_DocumentTitleChanged', 'WebViewAuth_CoreWebView2InitializationCompleted'",
        "FortiAuth.exe strings: 'GetSamlResponseAndRelayState', 'SAMLResponse', 'SamlZtnaResponse', 'SamlIpsecVpnResponse'",
        "FortiAuth.exe strings: 'JsonDeserializeHtml' (custom function deserializing JSON from HTML)",
        "FortiAuth.exe strings: 'Deserialize', 'GetMd5Hash', 'HashAlgorithm'",
        "FortiAuth.exe strings: 'FormSamlAuth', 'FormSamlAuth2', 'ShowWebBrowserAuth'",
        "FortiAuth.exe config: .NET Framework 4.7.2 (System.Runtime.CompilerServices.Unsafe 6.0.0.0)",
    ],

    "mechanism": (
        "FortiAuth.exe shows a WebView2 browser window for SAML authentication. "
        "WebView2 navigates to the FortiGate SAML endpoint. "
        "FortiGate (or rogue FortiGate) controls the HTML/JSON returned. "
        "FortiAuth.exe calls JsonDeserializeHtml on the page content to extract the SAMLResponse. "
        "If JsonDeserializeHtml uses Newtonsoft.Json with TypeNameHandling.All or BinaryFormatter, "
        "a rogue FortiGate's SAML page can embed a .NET gadget chain in the JSON -> "
        "code execution in the FortiAuth.exe process context."
    ),
}


# ---------------------------------------------------------
# Cross-version driver analysis: 7.2.3 vs 7.4.7
# ---------------------------------------------------------
WIN_DRIVER_CROSSVER = {
    "id":       "WIN-CROSSVER",
    "product":  "FortiClient Windows driver suite -- 7.2.3 vs 7.4.7 cross-version comparison",

    "fortitransctrl_changes": {
        "7.2.3_size":   "109KB (FortiTransCtrl.pdb: C:\\jenkins\\FCT0\\GIT_CLONE_PARENT\\FortiClientDriver\\2019-x64-Win10Release\\)",
        "7.4.7_size":   "134KB (+23% code growth)",
        "added_in_7.4.7": [
            "AleAuthConnectRegisterCallouts / AleAuthRecvAcceptRegisterCallouts (new auth callout layer)",
            "BindRedirectClassify (new bind redirect logic -- caller classification)",
            "ConnectionRedirectClassify (new connection redirect classification)",
            "ConnectionRedirectRegisterCallouts_v4/v6 (explicit v4/v6 separation)",
            "AppendIpForwardEntryToTunnel (new tunnel routing API)",
            "apply NonExemptPorts (port exemption management)",
            "Protocol-specific allow rules: DNS, DHCP, mDNS, LLMNR, STUN/TURN/ICE, SSDP, NetBIOS-NS, WSD, WS-Discovery",
            "Block IPV6 mDNS query: remoteIp=0x%08x remotePort=%d (explicit IPv6 mDNS filtering)",
            "All Tunnel: this flow was blocked (new ZTNA all-tunnel mode enforcement)",
        ],
        "removed_in_7.4.7": [
            "Generic 'allow port %d for inbound traffic' (replaced by protocol-specific rules)",
        ],
        "significance": (
            "The 23% code growth in fortitransctrl.sys from 7.2.3 to 7.4.7 introduces "
            "significantly more protocol-specific classification logic. Each new callout "
            "(BindRedirectClassify, ConnectionRedirectClassify) is a potential parsing "
            "path for attacker-controlled network data. The STUN/TURN/ICE allow rule is "
            "interesting: WebRTC traffic is specifically exempted from tunnel enforcement, "
            "which could allow covert channel exfiltration through a STUN endpoint."
        ),
    },

    "drivers_present_in_7.2.3_not_7.4.7_standalone": {
        "FortiShield.sys": {
            "size":     "132KB PE32+ native",
            "purpose":  "Self-protection minifilter driver; protects FortiClient files and processes",
            "sddl":     "D:P(A;;GA;;;SY)(A;;GA;;;BA) -- confirmed; same as fortitransctrl.sys",
            "port":     "FltBuildDefaultSecurityDescriptor (default -- Admins+SYSTEM only)",
            "bypass_list": (
                "FortiShield maintains a bypass PID list ('add bypass pid %ld'). "
                "Log: '%d trying to access %d with %x, bypass' / 'deny'. "
                "PIDs on the bypass list can access protected paths without restriction. "
                "List management requires Admins (port ACL). "
                "Bypass is also automatic for SYSTEM-level processes: "
                "'local system %d trying to access %d with %x, bypass'."
            ),
            "source":   "C:\\jenkins\\FCT0\\GIT_CLONE_PARENT\\FortiClientDriver\\2019-x64-Win10Release\\FortiShield.pdb",
        },
        "fortips_ndis6_3.sys": {
            "size":     "199KB PE32+ native NDIS 6.3 filter driver",
            "purpose":  "Kernel-mode IPS engine; processes all inbound/outbound network packets",
            "apis":     ["NdisAllocateMemoryWithTagPriority", "NdisAllocateNetBuffer", "NdisGetDataBuffer", "NdisAllocateMdl"],
            "esp_handlers": ["__esp_input", "__esp_input6", "__esp_output", "__esp_output6"],
            "attack_surface": (
                "fortips_ndis6_3.sys processes inbound packet data at the NDIS filter layer. "
                "The IPS signature parser (isdb.tar rules at userspace, kernel pattern match here) "
                "receives attacker-controlled packet payloads. "
                "Warning: 'esp_output not big enough (must expand)' suggests dynamic buffer expansion "
                "for ESP packet processing -- if the expansion lacks an upper bound, "
                "NdisAllocateMemory can fail and an unhandled failure path causes kernel panic. "
                "The isdb.tar replacement race (WIN-F06) that injects malformed IPS rules "
                "would cause this kernel driver to process attacker-crafted patterns."
            ),
            "source":   "C:\\jenkins\\FCT0\\GIT_CLONE_PARENT\\FortiClientDriver\\2019-x64-Win10Release\\fortips.pdb",
        },
        "fortimon3.sys": "85KB process activity monitor kernel driver",
        "fortisniff2.sys": "134KB network packet capture kernel driver",
        "FortiAptFilter.sys": "78KB APT detection kernel filter",
        "FortiDeviceGuard.sys": "51KB Credential Guard integration driver",
        "fortielam.sys": "21KB Early Launch Anti-Malware driver",
        "fortiwf2.sys": "65KB Windows Firewall integration",
        "ftsvnic.sys": "76KB FortiClient virtual NIC driver",
        "note": (
            "The full EPP (endpoint protection) suite adds 7+ kernel drivers on top of "
            "the VPN-only standalone. Each kernel driver is a privilege escalation surface "
            "with 0-privilege-needed execution if any kernel vuln is present. "
            "The standalone package omits FortiShield (self-protection) -- "
            "meaning the standalone installation is more vulnerable to tampering "
            "but has less kernel attack surface."
        ),
    },

    "fortips_semantic_sweep": {
        "binary":   "/tmp/fc723_driver/File_fortips_ndis6_3.sys",
        "method":   "ablation semantic sweep; sentence-transformers/all-MiniLM-L6-v2; 607 functions; x64 prologues",
        "note":     "Low scores (0.17-0.37) due to stripped kernel driver with minimal strings -- typical for kernel code",
        "clusters": {
            "buffer_overflow_candidate": {
                "va":   "0x14000cdec",
                "score": 0.375,
                "calls": ["0x14000db50", "0x140016e78"],
                "profile": "Tops buffer_overflow, ndis_recv_undercheck, AND esp_ipsec_overflow queries -- cross-profile concentration",
                "priority": "HIGH for manual disassembly",
            },
            "esp_handler_cluster": {
                "shared_callee": "0x14001b570 (called by 0x14001cfce, 0x14001d0db, 0x14001cea8, 0x14001cfa7, 0x14001cfa7)",
                "profile": "ESP overflow query; 'esp_output not big enough' string belongs to this call graph",
                "priority": "HIGH for manual disassembly -- 0x14001b570 is the ESP buffer management function",
            },
            "integer_overflow_candidate": {
                "va":   "0x14000baca",
                "calls": ["0x14000bc00"],
                "note": "Calls same target twice in sequence; possible loop over variable-length field",
            },
        },
        "manual_verification": {
            "0x14000cdec": "FLOW TRACKER ALLOCATOR -- pool tag SASS (0x46415353), size 0x88; linked list walk + conditional alloc; NOT a buffer overflow. False positive from semantic sweep.",
            "0x14001b570": "NDIS BUFFER COPY HELPER -- NdisAllocateNetBuffer + RtlCopyMemory chain. All callers use HARDCODED size constants (0x254, 0x54, 0x478, 0xa0 etc.) via dispatch table; NOT packet-field-derived. No vulnerability confirmed.",
            "0x14001cfce": "IKE MESSAGE DISPATCH TABLE -- sub ecx,1/3/5 stepping through message types; each branch calls 0x14001b570 with a fixed struct size. Correct handling.",
        },
        "conclusion": "No kernel vulnerability confirmed in fortips_ndis6_3.sys from semantic sweep + manual disassembly of top candidates. Fixed-size NDIS copies with hardcoded bounds. 'esp_output not big enough' warning is in userspace ipsec.exe, not this driver.",
        "next_step": "Manual disassembly of 0x14000cdec and 0x14001b570 COMPLETE -- no finding. Consider deeper analysis of NdisAllocateMemoryWithTagPriority callers for dynamic-length allocation paths.",
    },

    "fortips_743_new_ioctls": {
        "binary":   "fortips_ndis6_3.sys 7.4.3 (220KB, +21KB vs 7.2.3)",
        "sddl":     "D:P(A;;GA;;;SY)(A;;GA;;;BA) confirmed -- Admins only; no new privilege surface",
        "new_features_7.4.3": [
            "IOCTL_FORTIPS_ENABLE (new IOCTL command)",
            "IOCTL_START_IPSEC_OVER_TCP_SERVICE (new IOCTL -- enables IPsec-over-TCP tunnel mode)",
            "IOCTL_STOP_IPSEC_OVER_TCP_SERVICE (new IOCTL)",
            "IPS_CMD_SET_CONFIG with gIpsecIkeFloatPort and gIpsecTunnelMode (new config surface)",
            "shared memory IPC added (failed to create share memory / de-initialize share memory / MmMapLockedPagesSpecifyCache)",
            "'critical error in copy from user space' -- new userspace-to-kernel copy path; if bounds not checked, kernel write primitive",
            "DHCP option stripping: 'remove option 121 len=%d' / 'remove option 249 len=%d' (VPN bypass protection)",
            "got input dhcp packet %d on phy adapter (DHCP packet processing in kernel)",
        ],
        "note": (
            "The shared memory IPC and critical-copy-from-user-space added in 7.4.3 are "
            "new kernel attack surface. Admin-only IOCTL gate means they require admin access, "
            "but the shared memory path (MmMapLockedPagesSpecifyCache + IoAllocateMdl) deserves "
            "deeper analysis for ProbeForRead/ProbeForWrite usage before the copy."
        ),
    },
}


# ---------------------------------------------------------
# WIN-F13: TinyXML pervasive usage across all config DLLs
# ---------------------------------------------------------
WIN_F13_TINYXML_PERVASIVE = {
    "id":       "WIN-F13",
    "product":  "FortiClient Windows -- TinyXML used in ALL config serialization DLLs; 4 confirmed instances covering VPN, ZTNA, PAM, and system compliance",
    "severity": "HIGH -- network-reachable via rogue FortiGate/EMS; same vulnerability class amplified across all config areas",
    "class":    "Vulnerable XML library across multiple trust boundaries (CWE-787, CWE-611)",

    "instances": {
        "xmlvpn.dll":    "VPN profile config (FortiGate IKE settings) -- TinyXML + TinyXPath (WIN-F08)",
        "xmlztna.dll":   "ZTNA config (FortiGate/EMS) -- TinyXML + TinyXPath (WIN-F03)",
        "xmlsystem.dll": "System/compliance config (EMS) -- TinyXML + IsComponentInstalled",
        "xmlpam.dll":    "PAM (Privileged Access Management) config -- TinyXML",
        "xmlfssoma.dll": "FSSOMA agent config -- TinyXML (likely, same naming pattern)",
    },

    "significance": (
        "Fortinet uses a single TinyXML library across all feature-area config DLLs. "
        "A single vulnerability in TinyXML (e.g., CVE-2021-42260 class heap overflow) "
        "is exploitable via 5+ different attack surfaces: "
        "  - VPN config from FortiGate (IPsec, SSL-VPN) "
        "  - ZTNA rules from EMS/FortiGate "
        "  - System compliance config from EMS "
        "  - PAM config from EMS "
        "  - FSSOMA agent config "
        "A single TinyXML patch applies across all; a single TinyXML vuln affects all. "
        "This is a systemic dependency risk -- the XML parser is the single point of failure "
        "for the entire EMS-managed config attack surface."
    ),
}


# ---------------------------------------------------------
# WIN-F14: update_task.exe -- requireAdministrator + temp file TOCTOU race
# ---------------------------------------------------------
WIN_F14_UPDATE_TOCTOU = {
    "id":       "WIN-F14",
    "product":  "FortiClient Windows -- update_task.exe (requireAdministrator manifest); software update downloads to temp file then verifies; TOCTOU race between temp write and verify/install",
    "severity": "MEDIUM -- requires local write access to temp directory; escalates to admin code execution when update runs",
    "class":    "Update handler TOCTOU race (CWE-367, CWE-379)",

    "evidence": [
        "update_task.exe manifest: requestedExecutionLevel level='requireAdministrator' (UAC prompt on launch)",
        "update_task.dll strings: 'GetTempPath failed, error=%lu' + 'GetTempFileName failed, error=%lu'",
        "update_task.dll strings: 'Failed to remove temp folder, ret=%d, err=%d, %ws'",
        "update_task.dll strings: 'combined CRCs: stored = 0x%08x, computed = 0x%08x' (CRC verification after download)",
        "update_task.dll strings: 'process_certverify_result' + 'failed to verify object, ret=%d, cate=%d'",
        "update_task.dll strings: '%ws(), uploading softinvent to FDS is enabled' (FortiGuard update server contact)",
        "update_task.dll source: C:\\279\\2902741\\FortiClientHS\\service\\update_task",
    ],

    "mechanism": (
        "update_task.exe triggers a UAC elevation prompt (requireAdministrator). "
        "Post-elevation, update_task.dll contacts FortiGuard Distribution Server (FDS) "
        "and downloads update packages to a temp directory (GetTempPath + GetTempFileName). "
        "The update is verified via CRC checksum and certificate check (process_certverify_result). "
        "TOCTOU race: the download and verification use a temp file path; "
        "if the temp directory allows low-privilege write (standard %LOCALAPPDATA%\\Temp behavior), "
        "a local attacker can: "
        "  1. Monitor for temp file creation during update "
        "  2. Swap the temp file AFTER verification passes but BEFORE the install move "
        "  3. The admin-privileged installer executes the swapped payload "
        "The CRC check uses stored CRC from the download metadata -- if the swap happens "
        "before the second CRC check, the race window is the install stage."
    ),
}


# ---------------------------------------------------------
# WIN-F15: AzureToken2.exe -- EMS-controlled OAuth client_id injection
# ---------------------------------------------------------
WIN_F15_AZURE_TOKEN = {
    "id":       "WIN-F15",
    "product":  "FortiClient Windows -- AzureToken2.exe (.NET 4.8.1 MSAL); receives client_id and tenant_name as command-line args from FortiTcs.exe; EMS-controlled values allow arbitrary OAuth app impersonation",
    "severity": "HIGH -- if EMS is compromised, attacker controls client_id -> Azure AD tokens acquired for arbitrary registered applications",
    "class":    "OAuth client_id injection via EMS config (CWE-441, CWE-346)",

    "evidence": [
        "AzureToken2.exe strings: 'client_id', 'tenant_name' (command-line argument names)",
        "AzureToken2.exe strings: 'AcquireTokenInteractive', 'AcquireTokenSilent' (MSAL token acquisition)",
        "AzureToken2.exe strings: 'LaunchFortiClientWithAzureToken', 'AquireAzureToken' (main flow)",
        "AzureToken2.exe strings: 'WithDefaultRedirectUri' (OAuth redirect)",
        "AzureToken2.exe manifest: asInvoker (no elevation -- runs as user)",
        "AzureToken2.exe source: C:\\279\\2902741\\FortiClientHS\\service\\AzureToken\\obj\\Release\\AzureToken2.pdb",
        "AzureToken2.exe: .NET Framework 4.8.1 MSAL client",
        "FortiTcs.exe strings (WIN-F05): 'RequestAzureTokenFromFortiTray' -- FortiTcs requests tokens",
    ],

    "mechanism": (
        "AzureToken2.exe is a .NET MSAL client that acquires Azure AD access tokens. "
        "It receives client_id (the Azure AD application ID) and tenant_name as command-line arguments. "
        "FortiTcs.exe spawns AzureToken2.exe with values sourced from EMS configuration. "
        "If EMS is compromised or a rogue FortiGate sends malicious EMS config: "
        "  1. Attacker sets client_id to their own registered Azure AD application ID "
        "  2. AzureToken2.exe shows a legitimate Azure AD login dialog to the user "
        "  3. User authenticates (they see a normal Microsoft login page) "
        "  4. Access token is issued for the attacker's app with the user's identity "
        "  -> silent exfiltration of Azure AD session with permissions matching the fake app's scopes. "
        "MSAL's AcquireTokenInteractive shows the user the OAUTH consent screen for the attacker's app -- "
        "if scopes are broad (e.g., User.Read.All, Mail.Read), the attack yields full AD access."
    ),
}


# ---------------------------------------------------------
# WIN-F16: FortiSSLVPNdaemon.exe -- Mongoose web server + CGI + TinyXML; FortiGate XML fetch
# ---------------------------------------------------------
WIN_F16_SSLVPN_DAEMON = {
    "id":       "WIN-F16",
    "product":  "FortiClient Windows -- FortiSSLVPNdaemon.exe (present 7.2.9 and 7.4.3; removed 7.4.7); embeds Mongoose mini web server with CGI support; fetches FortiGate-controlled XML at /remote/fortisslvpn_xml; TinyXML compiled in",
    "severity": "HIGH -- network-controlled XML from FortiGate parsed by TinyXML; CGI root potentially writable",
    "class":    "Embedded web server + XML injection (CWE-787 via TinyXML; CWE-78 via CGI path)",

    "versions": {
        "7.2.9":  "FortiSSLVPNdaemon.exe 836KB (VPN.cab); Mongoose-based; TinyXML RTTI confirmed; fetches /remote/fortisslvpn_xml",
        "7.4.3":  "FortiSSLVPNdaemon.exe 1.6MB (VPN.cab); DTLS support added; still TinyXML; still fetches /remote/fortisslvpn_xml",
        "7.4.7":  "Removed; replaced by sslvpnlib.dll (library-only architecture; no embedded server)",
    },

    "evidence": [
        "FortiSSLVPNdaemon.exe strings (7.2.9+7.4.3): 'GET /remote/fortisslvpn_xml', 'GetAndDoXmlConfig', '[DoXmlConfigEx]: Xml='",
        "TinyXML RTTI (both versions): .?AVTiXmlDocument@@, .?AVTiXmlElement@@, .?AVTiXmlText@@ (full set)",
        "Mongoose web server: 'mg_vsnprintf', 'truncating vsnprintf buffer', '**.cgi$|**.pl$|**.php$'",
        "CGI support: 'SCRIPT_NAME=%s', 'GATEWAY_INTERFACE=CGI/1.1', 'Error: CGI program...'",
        "SSL cert verification: 'SSL_CTX_set_cert_verify_callback', 'CListener: RequestHandle copying fingerprint: %s'",
        "Named pipe: '\\\\.\\\\.pipe\\\\FortiSslvpnNamedPipe'",
        "7.4.3 pdb: C:\\279\\2693219\\FortiClientHS\\sslvpn\\FortiSSLVPNd\\x64\\Release\\FortiSSLVPNdaemon.pdb",
        "7.2.9 pdb: C:\\GitLab-Runner\\builds\\temp\\FortiClientHS\\sslvpn\\FortiSSLVPNd\\",
    ],

    "attack_surface": (
        "FortiSSLVPNdaemon.exe embeds a Mongoose HTTP server with full CGI script execution support. "
        "Attack paths: "
        "  1. XML injection: daemon fetches /remote/fortisslvpn_xml from FortiGate over established tunnel; "
        "     rogue FortiGate can send crafted XML -> TinyXML parses attacker-controlled content "
        "     (same class as CVE-2021-42260 + xmlvpn.dll chain in WIN-F08). "
        "  2. CGI execution: if document_root is writable by non-admin process, "
        "     an attacker who can write to that path gets code execution in the daemon's security context. "
        "  3. The CGI patterns (**.cgi, **.pl, **.php) suggest broad CGI extension matching -- "
        "     any file with those extensions in document_root is executed as CGI subprocess. "
        "Removed in 7.4.7 -- this attack surface is present in any 7.2.x or 7.4.3 deployment."
    ),
}


# ---------------------------------------------------------
# WIN-F17: ipsec_proxy.dll -- Asio-based IPsec-over-TCP proxy (7.4.3 new)
# ---------------------------------------------------------
WIN_F17_IPSEC_PROXY = {
    "id":       "WIN-F17",
    "product":  "FortiClient Windows -- ipsec_proxy.dll (7.4.3 new, VPN.cab); Boost.Asio-based UDP-to-TCP proxy for IPsec-over-TCP service; pairs with IOCTL_START_IPSEC_OVER_TCP_SERVICE in fortips_ndis6_3.sys",
    "severity": "MEDIUM -- new IPC layer between userspace IKE and kernel driver; packet injection surface if proxy_write_tcp_packet lacks validation",
    "class":    "New userspace-kernel IPC proxy layer (CWE-20 potential at packet write boundary)",

    "versions": {
        "7.2.9":  "absent",
        "7.4.3":  "ipsec_proxy.dll 192KB (VPN.cab); Asio IOCP; exports start/stop/write",
        "7.4.7":  "present (in VPN.cab as part of full 7.4.7 package)",
    },

    "evidence": [
        "ipsec_proxy.dll strings: 'start_ipsec_proxy', 'stop_ipsec_proxy', 'proxy_write_tcp_packet', 'proxy_get_tcp_local_port'",
        "ipsec_proxy.dll strings: 'ike packet', 'UDP Server failed create listen socket'",
        "ipsec_proxy.dll RTTI: Boost.Asio win_iocp_socket_service for both UDP and TCP transports",
        "ipsec_proxy.dll pdb: C:\\279\\2693219\\FortiClientHS\\x64\\Release\\ipsec_proxy.pdb",
        "Pairs with: fortips_ndis6_3.sys 7.4.3 IOCTL_START_IPSEC_OVER_TCP_SERVICE (WIN-CROSSVER)",
    ],

    "mechanism": (
        "ipsec_proxy.dll is a new UDP-to-TCP proxy library added in 7.4.3, paired with the "
        "new IPsec-over-TCP IOCTLs in the fortips_ndis6_3.sys kernel driver. "
        "It listens on a UDP socket for IKE packets from ipsec.exe and proxies them "
        "over TCP to a FortiGate endpoint (for NAT traversal where UDP 500/4500 are blocked). "
        "proxy_write_tcp_packet takes an IKE packet and writes it to the TCP connection -- "
        "if the length/content of the IKE packet from a rogue FortiGate is not validated "
        "before the write, this is a potential buffer boundary issue in the proxy layer. "
        "The proxy runs in userspace, so no kernel memory risk; process memory corruption only."
    ),
}


# ---------------------------------------------------------
# WIN-CROSSVER-2: 3-version cross-version analysis (7.2.9 / 7.4.3 / 7.4.7)
# ---------------------------------------------------------
WIN_CROSSVER2 = {
    "id":       "WIN-CROSSVER-2",
    "product":  "FortiClient Windows -- cross-version binary progression 7.2.9 to 7.4.7 (VPN + Core installers)",
    "method":   "MSI/CAB extraction + 7z listing + strings comparison across three versions",

    "installer_cabs": {
        "7.2.9_vpn_143MB": "VPN.cab + common.cab + x64.cab + fcresc.cab + FSSOMA.cab",
        "7.4.3_vpn_208MB": "VPN.cab + common.cab + Core.cab + x64.cab + fcresc.cab + FSSOMA.cab",
        "7.4.7_standalone_169MB": "common.cab (122MB) + VPN.cab (3.3MB) + x64.cab (65KB) + PAM.cab (1.3MB) + Core.cab (18MB)",
    },

    "sslvpn_daemon_timeline": {
        "7.2.9": "FortiSSLVPNdaemon.exe 836KB + FortiSSLVPNsys.exe 146KB + pppop_ndis6_0.sys (PPP-over-NDIS)",
        "7.4.3": "FortiSSLVPNdaemon.exe 1.6MB (grew -- DTLS added) + FortiSSLVPNsys.exe 144KB; pppop removed",
        "7.4.7": "FortiSSLVPNdaemon.exe REMOVED; replaced by sslvpnlib.dll 1.75MB (library-only)",
    },

    "ipsec_timeline": {
        "7.2.9": "ipsec.exe 926KB (FortiIKE -- C/C++ IKE daemon; no protobuf; build=GitLab-Runner)",
        "7.4.3": "ipsec.exe 1.0MB + ipsec_proxy.dll 192KB (new Asio IPsec-over-TCP proxy)",
        "7.4.7": "ipsec.exe 5.8MB (massive growth -- protobuf 31.1 IKE config serialization added)",
    },

    "config_server_timeline": {
        "7.2.9": "FCConfig.exe (C++) -- no Rust OIDC server",
        "7.4.3": "FCConfig.exe 694KB (C++) -- no Rust OIDC server",
        "7.4.7": "FCConfig2.exe (Rust/Warp/Tokio; 127.0.0.1:8011 OIDC server) NEW",
    },

    "azure_token_timeline": {
        "7.2.9": "AzureToken.exe 27KB (.NET 4.x MSAL; single binary; pdb=GitLab-Runner)",
        "7.4.3": "AzureToken2.exe 28KB (renamed; AzureToken.exe = 24-byte stub placeholder)",
        "7.4.7": "AzureToken2.exe (same class; source path C:\\279\\2902741\\...)",
    },

    "fortitcs_timeline": {
        "7.2.9": "absent",
        "7.4.3": "absent",
        "7.4.7": "FortiTcs.exe (Go binary; token impersonation -- WIN-F05) NEW",
    },

    "xml_dlls_timeline": {
        "7.2.9_msi_binary_resources": [
            "xmlae.dll", "xmlav.dll", "xmlcloudscan.dll", "xmlesnac.dll",
            "xmlfssoma.dll", "xmlfw.dll", "xmlpam.dll", "xmlsandbox.dll",
            "xmlsystem.dll", "xmlusbmon.dll", "xmlvpn.dll", "xmlvuln.dll",
            "xmlwanopt.dll", "xmlwf.dll", "xmlztna.dll",
        ],
        "note": (
            "7.2.9 MSI embeds 15 xml*.dll setup-time binaries confirming full-product TinyXML "
            "pervasiveness (extends WIN-F13 count to 15+ XML DLLs + FortiSSLVPNdaemon.exe = 16+ TinyXML instances). "
            "7.4.7 standalone (VPN+ZTNA subset) only ships 4."
        ),
    },

    "driver_sizes": {
        "fortitransctrl.sys": {"7.2.3": "109KB", "7.4.3": "117KB", "7.4.7": "131KB"},
        "fortips_ndis6_3.sys": {"7.2.3": "199KB", "7.4.3": "225KB", "7.4.7": "confirmed present"},
        "FortiFilter_ndis6_3.sys": {"7.4.3": "39KB (NDIS packet filter -- new confirmed)"},
        "ftsvnic.sys": {"7.4.3": "85KB (SSL VPN virtual NIC adapter)"},
        "ftvnic_ndis6_3.sys": {"7.4.3": "52KB (VPN NIC NDIS driver)"},
        "pppop_ndis6_0.sys": {"7.2.9": "54KB (PPP over NDIS)", "7.4.3": "removed"},
    },
}
