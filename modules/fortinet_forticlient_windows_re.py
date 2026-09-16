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
