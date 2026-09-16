"""
FortiClient EMS + FortiMail + FortiManager RCE (Rapid7 MSF modules) RE
Sources:
  - msf-modules/forticlient_ems_sqli.rb (CVE-2023-48788)
  - msf-modules/fortimail_login_bypass.rb (CVE-2020-9294)
  - msf-modules/fortimanager_rce_47575.rb (CVE-2024-47575, Rapid7 MSF)
Products: FortiClient EMS, FortiMail, FortiManager
"""

# ---------------------------------------------------------
# CVE-2023-48788: FortiClient EMS SQL injection via FCTUID parameter
# ---------------------------------------------------------
CVE_2023_48788 = {
    "cve":      "CVE-2023-48788",
    "product":  "Fortinet FortiClient EMS (Endpoint Management Server) -- FcmDaemon.exe",
    "cvss":     "9.8 (Critical) -- CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "class":    "SQL injection in MSG_HEADER FCTUID parameter -> xp_cmdshell -> SYSTEM RCE",
    "endpoint": "TCP/TLS port 8013 (FortiClient EMS management service FcmDaemon.exe)",
    "source":   "msf-modules/forticlient_ems_sqli.rb",
}

CVE_2023_48788_MECHANICS = {
    "architecture": (
        "FcmDaemon.exe: main service; listens on TCP 8013; communicates with enrolled FortiClient agents. "
        "FCTDas.exe: translation service; receives messages from FcmDaemon and sends to SQL Server (MSSQL). "
        "FCTUID: unique endpoint identifier in MSG_HEADER; passed to SQL queries without sanitization."
    ),

    "injection_point": {
        "protocol":  "Custom TCP framing on port 8013; message format: MSG_HEADER: FCTUID={value}\\n...",
        "parameter": "FCTUID in MSG_HEADER",
        "injection": "Stacked SQL injection (semicolon-separated statements)",
    },

    "sqli_payload_v7_0": (
        "xp_cmdshell delivery for 7.0.x (uppercase safe): "
        "sqli = \"'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; "
        "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; "
        "EXEC xp_cmdshell 'POWERSHELL.EXE -COMMAND \\\"\\\"Add-Type -AssemblyName System.Web; "
        "CMD.EXE /C ([SYSTEM.WEB.HTTPUTILITY]::URLDECODE(\\\"\\\"\\\"{hex_url_encoded_payload}\\\"\\\"\\\")); --' "
        "Note: EMS converts injected SQL to UPPERCASE; PowerShell cmdlets are case-insensitive. "
        "URL-encoding via System.Web.HttpUtility::UrlDecode bypasses the case constraint for the payload."
    ),

    "sqli_payload_v7_2": (
        "Hex encoding for 7.2.x ('=' is a bad char): "
        "sqli = \"'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; "
        "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; "
        "DECLARE @SQL VARCHAR({len}) = CONVERT(VARCHAR(MAX), 0X{hex_payload}); exec xp_cmdshell @sql; --' "
        "CONVERT(VARCHAR(MAX), 0x{hex}) embeds the payload as hex literal without '=' sign. "
        "DECLARE @SQL and exec xp_cmdshell execute the decoded payload."
    ),

    "execution_context": "NT AUTHORITY\\SYSTEM (FcmDaemon.exe runs as SYSTEM on Windows)",

    "re_insight": (
        "FortiClient EMS is a Windows application (FcmDaemon.exe) that processes "
        "client registration messages and passes parameters directly to MSSQL. "
        "The FCTUID field is a UUID-like identifier -- FortiClient agents send this as their device ID. "
        "No validation or parameterization of the FCTUID before SQL inclusion. "
        "The two-service architecture (FcmDaemon -> FCTDas -> MSSQL) distributes the trust: "
        "FcmDaemon trusts the FortiClient protocol; FCTDas trusts FcmDaemon's output. "
        "Attack surface: any host that can connect to TCP 8013 can inject SQL, "
        "even without a valid FortiClient installation -- just send the MSG_HEADER format."
    ),
}


# ---------------------------------------------------------
# CVE-2020-9294: FortiMail unauthenticated login bypass (version detection)
# ---------------------------------------------------------
CVE_2020_9294 = {
    "cve":      "CVE-2020-9294",
    "product":  "Fortinet FortiMail -- web admin interface (/admin/AdminLogin.html)",
    "cvss":     "9.8 (Critical) -- CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "class":    "Unauthenticated admin login bypass; bypasses credential check",
    "endpoint": "HTTPS /admin/AdminLogin.html (FortiMail admin panel)",
    "source":   "msf-modules/fortimail_login_bypass.rb",
}

CVE_2020_9294_MECHANICS = {
    "version_fingerprint": (
        "FortiMail includes a versioned JS file: fml-admin-login-{build}.js. "
        "Vulnerable builds (extracted from MSF module): "
        "  build 140-160 (FortiMail 5.x range), "
        "  build 730-745 (FortiMail 6.x range), "
        "  build 250-263 (FortiMail transitional). "
        "Additional check: response body includes 'newpassword' (field name). "
        "The MSF module is a scanner only -- the actual bypass mechanism is not shown in the module. "
        "CVE-2020-9294 is documented as an authentication bypass via a specially crafted HTTP request."
    ),

    "re_insight": (
        "FortiMail is a Java/web application for email security. "
        "The bypass likely involves a session token, cookie, or request parameter "
        "that FortiMail accepts as pre-authenticated without validation. "
        "Pattern matches CVE-2022-40684 (FortiOS) and CVE-2024-55591 (FortiOS) -- "
        "Fortinet repeatedly ships authentication shortcuts that become bypasses. "
        "The version detection via JS build number is a fingerprinting primitive "
        "applicable to any Fortinet web product that embeds build numbers in JS filenames."
    ),
}


# ---------------------------------------------------------
# CVE-2024-47575 MSF module (Rapid7): FortiManager FGFM cert bypass details
# ---------------------------------------------------------
CVE_2024_47575_MSF_DETAIL = {
    "cve":      "CVE-2024-47575",
    "product":  "Fortinet FortiManager -- FGFM protocol (fdssvrd)",
    "source":   "msf-modules/fortimanager_rce_47575.rb (Rapid7 MSF module)",
    "note":     "Extends the watchTowr analysis (CVE-2024-47575 in fortinet_cve_poc_re.py)",
}

CVE_2024_47575_MSF_MECHANICS = {
    "certificate_requirements": (
        "The MSF module provides a bundled fake client certificate as the default. "
        "OptPath 'ClientCert': optional; if not provided, the module uses get_client_cert(). "
        "The certificate CN field contains the device serial number. "
        "Serial number format detection by platform: "
        "  'FMG-VM...' -> FortiManager VM "
        "  'FGT-VM...' -> FortiGate VM "
        "  Default fallback: 'FMG-VM0000000000'. "
        "This confirms: fdssvrd does NOT validate the TLS client certificate against Fortinet's CA. "
        "Any X.509 cert is accepted -- the 'fortinet-signed' requirement was either absent or bypassable."
    ),

    "target_detection": (
        "check() method: connects to FGFM port; reads peer TLS certificate. "
        "Validates target is FortiManager by checking: "
        "  cert.subject O = 'Fortinet' AND "
        "  cert.subject CN starts with FortiManager serial prefix. "
        "This works because FortiManager serves its own TLS certificate in the FGFM handshake. "
        "Fingerprinting primitive: any target with O=Fortinet and FortiManager CN is a FortiManager."
    ),

    "platform_serial_mapping": (
        "The MSF module tries to match serial number prefix to platform type: "
        "  FMG-VMXXXXXXX -> FortiManager VM "
        "  FGT-VMXXXXXXX -> FortiGate VM (for cloud-managed device impersonation). "
        "The platform field in the FGFM 'get auth' message must match the serial prefix. "
        "Mismatch between serial and platform may cause fdssvrd to reject the connection."
    ),

    "re_insight": (
        "The Rapid7 MSF module's bundled client certificate is a Fortinet-format cert "
        "with a valid-looking CN but not signed by Fortinet's CA. "
        "fdssvrd accepts it -- the CA check is the missing piece. "
        "Ablation semantic sweep for SSL_CTX_set_verify() and related cert verification calls in fdssvrd "
        "reveals: "
        "(1) Whether SSL_VERIFY_PEER is set (i.e., client cert requested), "
        "(2) Whether SSL_CTX_set_verify_depth() is called, "
        "(3) Whether a verify callback is registered that checks the CA chain. "
        "If SSL_VERIFY_NONE or if the verify callback returns 1 unconditionally, "
        "that is the bypass point."
    ),
}


# ---------------------------------------------------------
# FortiClient EMS architecture -- broader RE context
# ---------------------------------------------------------
FORTICLIENT_EMS_ARCHITECTURE = {
    "id":       "FCEMS-ARCH",
    "product":  "FortiClient EMS (Windows application)",
    "description": "Endpoint management server for FortiClient agents",

    "key_processes": {
        "FcmDaemon.exe":  "Main management daemon; listens on TCP 8013; receives FortiClient registrations",
        "FCTDas.exe":     "Database translation service; receives from FcmDaemon; queries MSSQL",
        "FortiClientEMS": "Web UI (IIS); admin management interface on HTTPS 443",
    },

    "protocol_format": {
        "transport": "TCP/TLS on port 8013",
        "message_format": "MSG_HEADER: KEY=VALUE\\nKEY=VALUE\\n...\\n\\n",
        "auth_fields": "FCTUID=<uuid>; FCTVER=<version>; PEER_IP=<ip>; COM_SN=<serial>",
    },

    "re_insight": (
        "The MSG_HEADER protocol is plaintext key-value pairs over TLS. "
        "No HMAC, no nonce, no authentication of the message sender beyond TLS itself. "
        "The FortiClient agent authenticates only via its FCTUID (UUID) -- "
        "no client certificate for the FortiClient protocol. "
        "An attacker impersonating a FortiClient agent can inject SQL via FCTUID "
        "without requiring a valid client certificate. "
        "The protocol is undocumented; the MSF module reverse-engineered the message format "
        "from FcmDaemon network captures."
    ),
}
