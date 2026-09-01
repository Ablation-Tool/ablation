"""
Cisco IP Phone 7945/7965 SCCP firmware reverse engineering module.
Firmware: SCCP 9.4.2SR1-1 (cmterm-7945_7965-sccp.9-4-2SR1-1.zip)
Platform: MIPS big-endian, Beamish CVM (J2ME CDC), Linux
Container: CNU_File_Archive_3.0 (variable-length Cisco sig block)
Key findings: SSLStreamConnection.class identical to SIP (PHN-F06/F07 by identity);
              DSP binary PHN-F08/F09 candidates; secReq_srtpFipsTest SCCP-unique IPC;
              SDES-SRTP confirmed (no DTLS strings in DSP binary).
"""

FIRMWARE = {
    "model":     "Cisco IP Phone 7945/7965 SCCP",
    "version":   "9.4.2SR1-1",
    "arch":      "MIPS big-endian",
    "platform":  "Beamish CVM (J2ME CDC VM)",
    "container": "CNU_File_Archive_3.0 (Cisco proprietary archive)",
    "protocol":  "SCCP (Skinny Client Control Protocol)",
    "cvm_binary": "beamishcvmsccp.cnu (gzip at 0x457, 5.4MB decompressed)",
    "jar_binary": "jar45sccp.9-4-2ES9.sbn (dual-ZIP: zip1=resources, zip2=1007 class files)",
    "dsp_binary": "dsp45.9-4-2ES9.sbn (364,207 bytes — MediaTermination / PSYL DSP process)",
    "apps_binary": "apps45.9-4-2ES9.sbn (MIPS ELF bundle, 61 objects)",
}

# ---- JAR structure: dual-ZIP (same as SIP) ----

JAR_STRUCTURE = {
    "zip1_eocd_offset": 0x831e8,
    "zip1_entries": None,
    "zip2_eocd_offset": 0x1a31c9,
    "zip2_entries": 1007,
    "zip2_content": "Java class library (CDC Foundation + Cisco additions)",
    "extraction": "Exact slice: data[0x831fe:0x1a31c9+22] to isolate ZIP2",
    "note": "Dual-ZIP structure identical to SIP jar45sip.sbn pattern",
}

# ---- SSLStreamConnection.class: IDENTICAL to SIP ----

PHN_F06_F07_SCCP_CONFIRMATION = {
    "class": "com.sun.cdc.io.j2me.ssl.SSLStreamConnection",
    "sha256": "291db3749603a3f04f781d7293e23b1deeb1fc6376ea10eec3f3f7a3d1fb3cfe",
    "identical_to_sip": True,
    "findings_confirmed": ["PHN-F06", "PHN-F07"],
    "phn_f06": "getTrustedCertStore() guaranteed null return — Class.forName('com.sun.cdc.io.j2me.ssl') always throws ClassNotFoundException",
    "phn_f07": "lockTrustedCertStore() null-guard logic inversion — trustedCertStoreLocked never set when store is null",
    "implication": "PHN-F06/F07 Java CertStore bypass applies to SCCP by byte-for-byte identity",
}

# ---- CVM secd-proxy: new SCCP IPC call ----

SCCP_CVM_DELTA = {
    "binary": "beamishcvmsccp.cnu (5.4MB vs SIP cvm45sip.sbn 6.8MB)",
    "secd_proxy_confirmed": True,
    "shared_with_sip": ["/tmp/sslAppSrvrSock", "** no secd?! no SSL/TLS proxy srvr sock",
                        "Entering StcpOpenActiveSSL", "StcpActiveSSLConnectionStatus: SUCCESS"],
    "sccp_unique_ipc": {
        "secReq_srtpFipsTest": (
            "SCCP CVM makes secReq_srtpFipsTest IPC call to secd — absent in SIP CVM. "
            "Invokes FIPS SRTP self-test via secd before SRTP session setup. "
            "If this test can be forced to fail, FIPS SRTP mode is disabled. "
            "Attack: trigger test failure → SRTP falls to non-FIPS path → weaker key material."
        ),
    },
    "cvm_size_delta_note": (
        "SCCP CVM is 1.4MB smaller than SIP CVM. "
        "SIP CVM includes SIP-specific session management and offer/answer logic. "
        "SCCP CVM uses simpler call control (CUCM sends codec parameters directly)."
    ),
}

# ---- DSP binary: MediaTermination process ----

DSP_BINARY_ANALYSIS = {
    "file":    "dsp45.9-4-2ES9.sbn",
    "size":    364207,
    "magic":   "DEADBEEF at offset 0x428",
    "version": "8.3(14.15)PSYL - enable audio output at teh end",
    "platform_codename": "PSYL — Cisco DSP platform identifier for 7945/7965 family",
    "process_type": "MediaTermination — handles RTP send/recv and DSP codec control",
    "ipc_sockets": [
        "/usr/localsocketMT (MediaTermination IPC)",
        "/usr/localsocketRTP_SOCKS (RTP socket IPC)",
        "/usr/FileDspstart (DSP initialization file trigger)",
    ],
    "srtp_mode": "SDES-SRTP confirmed — aes-ecb, sha1, aes_icm key material; NO DTLS strings",
    "srtp_strings": [
        "srtp_create()", "srtp_unprotect()", "srtp_protect()",
        "aes-ecb", "sha1", "aes_icm",
        "key_limit exceeded",
        "packet index limit reached",
    ],
    "no_dtls": (
        "Absence of DTLS strings ('dtls', 'DTLS', 'ClientHello', 'ServerHello' in DSP context) "
        "confirms 7945/7965 SCCP uses SDES-SRTP (key in SDP offer/answer), not DTLS-SRTP. "
        "DTLS is SIP-standard for RFC 5764 but Cisco 7945/7965 predate this."
    ),
}

# ---- PHN-F08 candidate: DSP_STATE_READY BYPASSED ----

PHN_F08_DSP_BYPASS_CANDIDATE = {
    "id":     "PHN-F08",
    "status": "CANDIDATE — not confirmed exploitable",
    "title":  "DSP init BYPASSED state skips security checks",
    "binary": "dsp45.9-4-2ES9.sbn (MediaTermination process)",
    "string": "DSP INIT-*** DSP_STATE_READY***  BYPASSED **********************",
    "mechanism": (
        "DSP initialization has an explicit BYPASSED state distinct from normal DSP_STATE_READY. "
        "The BYPASSED state in DSP init implies security or FIPS checks are skipped. "
        "Trigger condition unknown from static analysis — requires runtime DSP IPC analysis. "
        "Possible triggers: hardware self-test failure, debug mode flag, or IPC command injection."
    ),
    "impact_if_confirmed": (
        "DSP in BYPASSED state may accept non-FIPS SRTP key material or disable key usage limits. "
        "SRTP key material from SDP would not be validated against FIPS constraints. "
        "This would allow replay attacks or key reuse beyond the RFC-defined packet limit."
    ),
    "next_step": "Runtime IPC fuzzing via /usr/localsocketMT to trigger BYPASSED state",
}

# ---- PHN-F09 candidate: FIPS SRTP bypass test ----

PHN_F09_FIPS_BYPASS_CANDIDATE = {
    "id":     "PHN-F09",
    "status": "CANDIDATE — not confirmed exploitable",
    "title":  "DSP FIPS SRTP bypass test failure disables FIPS SRTP path",
    "binary": "dsp45.9-4-2ES9.sbn",
    "strings": [
        "RTP TX: sRTP memcmp bypass test failed!",
        "FIPS SRTP bypass test passed",
        "Table Substitution %s, checksum is disabled, actual checksum = %d",
    ],
    "mechanism": (
        "'FIPS SRTP bypass test' is a self-test that verifies the SRTP path correctly "
        "bypasses non-FIPS-compliant key operations. "
        "'memcmp bypass test' verifies constant-time comparison for SRTP keys. "
        "If 'RTP TX: sRTP memcmp bypass test failed!', FIPS SRTP path is disabled. "
        "'Table Substitution checksum is disabled' — substitution table integrity check can be turned off."
    ),
    "fips_downgrade_scenario": (
        "Attacker sends SRTP packet that triggers memcmp timing failure → "
        "FIPS SRTP disabled for session → non-FIPS SRTP with weaker guarantees. "
        "Timing the memcmp via network: speculative; requires controlled environment to confirm."
    ),
}

# ---- 7945/7965 SCCP vs SIP: key deltas ----

SCCP_vs_SIP_7965_DELTA = {
    "identical": [
        "SSLStreamConnection.class (SHA256 291db374...) — PHN-F06/F07 by identity",
        "secd IPC architecture (/tmp/sslAppSrvrSock)",
        "Beamish CVM platform (J2ME CDC)",
        "SDES-SRTP (no DTLS-SRTP)",
        "CTL/ITL trust framework (apps45.sbn MIPS code)",
        "PHN-F02/F04 analogues (TOFU, TVS-absent)",
    ],
    "sccp_additions": [
        "secReq_srtpFipsTest IPC call in SCCP CVM",
        "DSP binary PSYL platform (shared with SCCP — SIP DSP also PSYL; both SDES-SRTP)",
        "PHN-F08/F09 candidates in DSP binary",
    ],
    "sccp_removals": [
        "SIP CVM -1.4MB (SCCP simpler call control — no SDP offer/answer in CVM)",
    ],
    "assessment": (
        "7945/7965 SCCP and SIP share the same Java SSL layer and secd architecture. "
        "PHN-F06/F07 Java CertStore bypasses apply identically. "
        "The primary attack surface difference is secReq_srtpFipsTest in SCCP CVM "
        "and the DSP PHN-F08/F09 candidates."
    ),
}

# ---- 7970/7971 SCCP coverage ----

COVERAGE_7970_SCCP = {
    "note": (
        "7970/7971 SCCP architecture is identical Beamish CVM to 7945/7965. "
        "PHN-F06/F07 apply by platform identity. "
        "7970 SCCP not separately verified — assumed same findings as 7965 SCCP."
    ),
}

# ---- 7945/7965 SCCP CVM vs SIP CVM full comparison ----

CVM_SCCP_vs_SIP_COMPARISON = {
    "cvm_sccp": {
        "file":    "cvm45sccp.9-4-2ES9.sbn",
        "sha256":  "a13eb1c354b17506a17f8f08c86971990062a31f3a888a9342155be9172f2c1d",
        "size_compressed": 2219236,
        "size_decompressed": 5426292,
    },
    "cvm_sip": {
        "file":    "cvm45sip.9-4-2ES9.sbn",
        "sha256":  "b71f79c1d845e4e0158f13fd7c16fab10d00173ad1a1977fb4fe50790309d220",
        "size_compressed": 2691040,
        "size_decompressed": 6805740,
    },
    "size_delta":   1379448,
    "delta_reason": (
        "SIP CVM includes SIP/SDP protocol stack, H.264 video codec support, "
        "additional media handling layers. SCCP CVM has only SCCP call control."
    ),
    "secd_ipc_diff": {
        "absent_in_sccp": ["secReq_getRand (sec_req_api_rand.c not compiled in)"],
        "present_in_both": (
            "All other 32 secReq_* IPC calls identical: AddEntity, Auth_N_Decr, "
            "cancelCapf, clearCapf, CTLdelete, CTLupdate, DelEntity, fipsTest, "
            "getCapf, getCapfStatus, getCertInfo, getCTLInfo, getCTLItem, getITLItem, "
            "getProxySock, getSrvCertAttr, getTvsServer, initClient, initiateCapf, "
            "Listen, LookupSrvr, secFileOp, setCapf, setEMCCStatus, setMode, "
            "setTvsServer, setVPNCertificates, srtpFipsTest, startCapf, "
            "VerifyMIDlet, vfyVPNCertificates"
        ),
    },
    "rand_bytes_note": (
        "RAND_BYTES IPC message exists in SCCP CVM but secReq_getRand() wrapper is absent. "
        "Implication: SCCP CVM PRNG request path uses a different call site — "
        "possibly inline RAND_BYTES message construction rather than the wrapper. "
        "sec_req_api_rand.c was excluded from the SCCP CVM build."
    ),
}

SCCP_XML_DTLS_DOWNGRADE = {
    "finding_id": "PHN-F12",
    "title": "7945/7965 SCCP: hasDtls/hasSsl flags in XmlCallManagersObject — XML config DTLS downgrade",
    "class": "cip.xml.XmlCallManagersObject (CVM-native, not in JAR)",
    "methods": ["getHasDtls()", "getHasSsl()"],
    "absent_in_sip_cvm": True,

    "mechanism": (
        "SCCP CVM parses the TFTP-provisioned CallManager XML (typically SEPDefault.cnf.xml "
        "or device-specific XML from CUCM). The XmlCallManagersObject has native methods "
        "getHasDtls() and getHasSsl() that expose DTLS/SSL availability flags from this XML. "
        "A malicious TFTP server (reachable via DHCP option 150 redirect, per PHN-F02 chain) "
        "can provision XML with hasDtls=false and hasSsl=false, potentially causing the phone "
        "to connect to CUCM without DTLS/TLS signaling encryption."
    ),

    "dtls_context": (
        "DTLS strings in SCCP CVM are all VPN-path (AnyConnect). SCCP signaling uses TLS "
        "(getHasSsl flag). The getHasDtls flag may govern VPN DTLS transport. "
        "Either path: attacker-provisioned XML can disable the relevant encrypted channel."
    ),

    "chain": (
        "PHN-F02 TOFU → DHCP 150 redirect → malicious ITLFile.tlv (trust anchor) AND "
        "malicious SEPDefault.cnf.xml (hasSsl=false) → phone connects on unencrypted SCCP → "
        "full signaling plaintext"
    ),

    "status": "CANDIDATE — requires live 7945/7965 SCCP test to confirm flag behavior",
    "severity": "HIGH if confirmed — TLS signaling disabled via XML provisioning",
}

DSP_SCCP_IDENTITY = {
    "note": "dsp45.9-4-2ES9.sbn SIP vs SCCP: only Cisco TLV sig block differs (0x7d-0x17c, 255 bytes). Payload after sig: IDENTICAL (sha256 fefb9b57...). PHN-F08/F09 candidates apply equally to SCCP.",
    "apps45_note": "apps45.9-4-2ES9.sbn SIP vs SCCP: IDENTICAL payload from sig boundary. All MIPS native binaries shared across SIP and SCCP 9.4.2SR1-1.",
}
