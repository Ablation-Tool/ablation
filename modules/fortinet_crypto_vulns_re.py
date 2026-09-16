"""
FortiOS/FortiManager hardcoded crypto keys + format string + buffer overflow RE
Sources:
  - cve-pocs-extra/cve-2019-6693/fortigate-decrypt.py (CVE-2019-6693)
  - cve-pocs-extra/CVE-2020-9289/cve-2020-9289.py (CVE-2020-9289)
  - cve-pocs-extra/CVE-2024-23113/POC-CVE-2024-23113.py (CVE-2024-23113)
  - cve-pocs-extra/CVE-2025-32756-POC/fortinet_cve_2025_32756_poc.py (CVE-2025-32756)
Products: FortiOS, FortiManager, FortiVoice, FortiMail, FortiNDR, FortiRecorder
"""

# ---------------------------------------------------------
# CVE-2019-6693: FortiOS hardcoded AES key for config backup encryption
# ---------------------------------------------------------
CVE_2019_6693 = {
    "cve":      "CVE-2019-6693",
    "product":  "Fortinet FortiOS -- configuration backup encryption",
    "cvss":     "6.5 (Medium) -- CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "class":    "Hardcoded AES-128-CBC key in FortiOS config backup; all non-admin passwords decryptable",
    "source":   "cve-pocs-extra/cve-2019-6693/fortigate-decrypt.py",
}

CVE_2019_6693_MECHANICS = {
    "encryption_scheme": {
        "algorithm": "AES-128-CBC",
        "key":       "Mary had a littl",
        "key_note":  "'Mary had a littl' is the first 16 bytes of 'Mary had a little lamb'; hardcoded in FortiOS binary",
        "iv_derivation": (
            "data = base64.b64decode(encrypted_password). "
            "iv = data[0:4] + b'\\x00' * 12. "
            "Only the first 4 bytes of the stored data are used as IV; padded with 12 null bytes to fill 16-byte IV. "
            "ciphertext = data[4:]."
        ),
        "plaintext": "User password or HA password in cleartext after decryption",
    },

    "config_locations": {
        "user_password": "config system local-user; edit <user>; set passwd ENC <base64_ciphertext>",
        "ha_password":   "config system ha; set password ENC <base64_ciphertext>",
        "format":        "'set passwd ENC ' followed by base64(iv[0:4] + AES_CBC_encrypt(key, iv, plaintext))",
    },

    "re_insight": (
        "CVE-2019-6693 and CVE-2020-9289 are variants of the same issue: "
        "Fortinet uses a hardcoded symmetric key for config file encryption. "
        "'Mary had a littl' is deliberately truncated at 16 chars -- it is the AES-128 key. "
        "The same key is used in FortiOS, FortiManager, FortiProxy, and others. "
        "This key was previously documented in BOLDMOVE RE (BM-F01): "
        "'cmdb AES-128 Mary had a littl key' in the threat intel module. "
        "With this key, anyone with access to a FortiOS configuration backup "
        "(either from CVE-2018-13379 path traversal or any backup file) can decrypt "
        "all user passwords, HA passwords, and VPN credentials."
    ),

    "scope_of_exposure": (
        "Affects ALL products using the FortiOS cmdb configuration format. "
        "Same key, different IV handling in FortiManager (CVE-2020-9289). "
        "The Belsen Group 2025 leak (87k+ config dumps from CVE-2022-40684) "
        "makes this key immediately actionable against leaked config files."
    ),
}


# ---------------------------------------------------------
# CVE-2020-9289: FortiManager hardcoded AES key (same key, different IV)
# ---------------------------------------------------------
CVE_2020_9289 = {
    "cve":      "CVE-2020-9289",
    "product":  "Fortinet FortiManager -- configuration secret encryption",
    "cvss":     "7.5 (High)",
    "class":    "Hardcoded AES-128-CBC key (same as CVE-2019-6693); full 16-byte IV",
    "source":   "cve-pocs-extra/CVE-2020-9289/cve-2020-9289.py",
}

CVE_2020_9289_MECHANICS = {
    "difference_from_6693": (
        "Key: same 'Mary had a littl'. "
        "IV difference: data[0:16] (full 16 bytes used as IV, not 4-byte + nulls). "
        "Ciphertext: data[16:]. "
        "Padding issue: if ciphertext length is not a multiple of 16, "
        "null bytes are appended; the last block is discarded from plaintext. "
        "This 'junk stripping' (pt[:-16] when elen != 0) is a quirk of the FortiManager cipher usage -- "
        "the last 16 bytes of ciphertext are padding/junk appended during encryption."
    ),

    "products_affected": "FortiManager + any product that uses the FortiOS cmdb ENC format with 16-byte IV",

    "re_insight": (
        "Two CVEs, same key, two different IV schemes. "
        "This implies two different code paths for encryption in FortiOS vs FortiManager -- "
        "both use AES-128-CBC with the hardcoded key, but one stores 4-byte IV prefix, "
        "the other stores the full 16-byte IV. "
        "Ablation sweep target: find AES_CBC_encrypt / aes_init calls in cmdbsrv and fmgd binaries. "
        "The key literal 'Mary had a littl' or its hash equivalent should be findable "
        "via semantic search: 'function initializing AES with constant key for config encryption'."
    ),
}


# ---------------------------------------------------------
# Hardcoded key cross-product systemic summary
# ---------------------------------------------------------
FORTINET_HARDCODED_AES_SYSTEMIC = {
    "id":       "FCRYPTO-AES-SYSTEMIC",
    "product":  "Fortinet (FortiOS + FortiManager + FortiProxy + FortiAnalyzer)",
    "severity": "CRITICAL -- hardcoded AES key decrypts all ENC-prefixed secrets from config files",

    "key_usage_map": {
        "FortiOS backup (.conf file)":       "AES-128-CBC, key='Mary had a littl', IV=data[0:4]+12 nulls",
        "FortiManager config secrets":       "AES-128-CBC, key='Mary had a littl', IV=data[0:16]",
        "FortiOS firmware image (BOLDMOVE)": "AES-128-CBC same key (BM-F01 reference)",
    },

    "attack_surface": (
        "1. CVE-2018-13379 path traversal -> /dev/cmdb/sslvpn_websession (plaintext VPN creds). "
        "2. CVE-2022-40684 auth bypass -> GET /api/v2/cmdb/ -> full config download including ENC passwords. "
        "3. Belsen 2025 config dump (87k devices, Jan 2025). "
        "4. Any legitimate FortiOS backup file (restore UI, TFTP backup). "
        "Any of the above + 'Mary had a littl' AES-128-CBC decryption = full credential recovery."
    ),
}


# ---------------------------------------------------------
# CVE-2024-23113: FortiOS format string on FGFM port 541
# ---------------------------------------------------------
CVE_2024_23113 = {
    "cve":      "CVE-2024-23113",
    "product":  "Fortinet FortiOS -- fgfmsd service port 541 (FortiManager protocol)",
    "cvss":     "9.8 (Critical) -- CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "class":    "Unauthenticated format string vulnerability in fgfmsd; %n write primitive",
    "endpoint": "TLS TCP/541 (FGFM FortiManager management protocol)",
    "source":   "cve-pocs-extra/CVE-2024-23113/POC-CVE-2024-23113.py",
}

CVE_2024_23113_MECHANICS = {
    "fgfm_protocol_detail": {
        "transport": "TLS/TCP port 541",
        "framing":   "4-byte flags (LE int32) + 4-byte packet_length (LE int32) + payload",
        "initial_handshake": (
            "Server sends initial frame on connect. "
            "Client reads: pkt_flags = unpack('i', data[:4])[0]; "
            "pkt_len = unpack('i', data[4:8])[0] - 2; "
            "payload = recv(pkt_len - 8). "
            "Then client sends auth response."
        ),
    },

    "format_string_payload": {
        "request": "reply 200\\r\\nrequest=auth\\r\\nauthip=%n\\r\\n\\r\\n\\x00",
        "packet_code": "0x0001e034 = 122932 (auth response command code)",
        "packet": (
            "packet = 0x0001e034.to_bytes(4, 'little') "
            "+ (len(payload) + 8).to_bytes(4, 'big') "
            "+ format_string_payload"
        ),
    },

    "vulnerability_detection": (
        "Vulnerable: connection is aborted with TLS alert after sending the %n payload. "
        "  ssl.SSLError containing 'tlsv1 alert' or 'unexpected message'. "
        "Patched: server returns a response (200 HTTP-like status). "
        "The TLS abort indicates the server crashed or entered an invalid state "
        "from processing the %n format specifier (writing to memory)."
    ),

    "format_string_class": (
        "'authip=%n' -- the authip field value is passed to a printf-family function "
        "without a format string argument. "
        "%n writes the count of bytes written so far to the pointer argument. "
        "Without a corresponding pointer argument on the stack, "
        "this is a write to an arbitrary stack address -- exploitable for RCE. "
        "The FortiOS fgfmsd binary processes FGFM protocol messages using "
        "string-format functions inherited from the FortiOS common library. "
        "Same code path as CVE-2024-47575 (FortiJump) -- different field, same service."
    ),

    "re_insight": (
        "Port 541 (fgfmsd) is now documented with two critical vulnerabilities: "
        "CVE-2024-47575 (FortiJump): no cert validation -> arbitrary device registration -> backtick RCE. "
        "CVE-2024-23113: format string in authip field -> %n write primitive -> RCE pre-auth. "
        "Both are unauthenticated and target the same service. "
        "Port 541 should be treated as a critical attack surface equivalent to SSL VPN port 443. "
        "Ablation semantic sweep: find all printf/sprintf/fprintf calls in fgfmsd "
        "where format string contains user-controlled input (authip, request= fields). "
        "Key ablation query: 'printf with external format string argument; no format validation'."
    ),
}


# ---------------------------------------------------------
# CVE-2025-32756: FortiOS stack buffer overflow via enc= on /remote/hostcheck_validate
# ---------------------------------------------------------
CVE_2025_32756 = {
    "cve":      "CVE-2025-32756",
    "product":  "Fortinet FortiVoice / FortiMail / FortiNDR / FortiRecorder -- sslvpnd hostcheck",
    "cvss":     "9.6 (Critical) -- CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "class":    "Stack-based buffer overflow in hostcheck_validate endpoint; encrypted overflow via MD5 keystream",
    "endpoint": "HTTPS POST /remote/hostcheck_validate (enc= parameter)",
    "source":   "cve-pocs-extra/CVE-2025-32756-POC/fortinet_cve_2025_32756_poc.py",
}

CVE_2025_32756_MECHANICS = {
    "affected_products": (
        "FortiVoice, FortiMail, FortiNDR, FortiRecorder (NOT FortiOS itself in the original advisory). "
        "Note: same /remote/hostcheck_validate endpoint as CVE-2024-21762 (FortiOS sslvpnd). "
        "These products share sslvpnd code from FortiOS -- the overflow is in the shared library."
    ),

    "encryption_scheme": (
        "The enc= parameter is a custom encrypted value. "
        "Key derivation: GET /remote/info -> extract 'salt' from response. "
        "PoC hardcodes salt='e0b638ac'. "
        "Initial state: MD5(salt + seed + 'GCC is the GNU Compiler Collection.'). "
        "Keystream: iterative MD5 chaining: current = MD5(current_hex); keystream += current. "
        "Payload assembly: seed + enc_length_hex + encrypted_data_hex. "
        "XOR of desired_length with keystream bytes to produce enc_length. "
        "XOR of data bytes with keystream to produce encrypted_data."
    ),

    "overflow_trigger": (
        "Two requests to /remote/hostcheck_validate: "
        "Request 1: enc= with overflow_length=4999. "
        "Request 2: enc= with overflow_length=5000. "
        "The 'encrypted' length field, when decrypted by the server, "
        "specifies how many bytes to copy into a stack buffer. "
        "Length > stack buffer size -> overflow. "
        "The 5000-byte length triggers the overflow while 4999 sets up state. "
        "String 'GCC is the GNU Compiler Collection.' in the key derivation is a "
        "deliberate Fortinet constant embedded in the hostcheck protocol -- "
        "another hardcoded constant enabling the PoC without requiring MITM."
    ),

    "salt_acquisition": (
        "GET /remote/info returns device salt (no auth). "
        "Salt is used to bind the encryption to the device session. "
        "The PoC treats this as a soft check -- hardcoded example salt works for demonstration."
    ),

    "re_insight": (
        "CVE-2025-32756 targets the same /remote/hostcheck_validate endpoint as CVE-2024-21762. "
        "CVE-2024-21762 affected FortiOS sslvpnd; CVE-2025-32756 affects FortiVoice/FortiMail/etc. "
        "These products include the same sslvpnd code without the 2024-21762 patch. "
        "The 'GCC is the GNU Compiler Collection.' string in the key derivation is notable: "
        "it is a garbage string deliberately chosen by Fortinet as a protocol salt. "
        "Finding this string in binary search will locate the hostcheck_validate handler. "
        "The MD5-chaining keystream is findable via semantic sweep: "
        "'function that derives keystream from hash of hash of salt+seed+constant'. "
        "Once the handler is found, memcpy/strcpy with the decrypted length is the overflow site."
    ),
}


# ---------------------------------------------------------
# Systemic: FortiOS sslvpnd hostcheck endpoint vulnerability family
# ---------------------------------------------------------
HOSTCHECK_ENDPOINT_SYSTEMIC = {
    "id":       "FHOSTCHECK-SYSTEMIC",
    "product":  "Fortinet (FortiOS, FortiVoice, FortiMail, FortiNDR, FortiRecorder) -- /remote/hostcheck_validate",
    "severity": "CRITICAL -- pre-auth RCE across multiple products via shared sslvpnd code",

    "cve_timeline": {
        "CVE-2022-42475": "Heap overflow; /remote/error endpoint; 173096 bytes; ASLR base hardcoded",
        "CVE-2023-27997": "Identical to CVE-2022-42475 PoC (same gadgets, same base)",
        "CVE-2024-21762": "Stack overflow at /remote/hostcheck_validate; enc= param; two-request pattern",
        "CVE-2025-32756": "CVE-2024-21762 same endpoint; FortiVoice/FortiMail/FortiNDR/FortiRecorder unpatched",
    },

    "pattern": (
        "The /remote/* endpoints are served by sslvpnd (SSL VPN daemon). "
        "sslvpnd is compiled from a common codebase shared across FortiOS and satellite products. "
        "Patches applied to FortiOS sslvpnd are NOT automatically applied to satellite products. "
        "Result: a family of related products repeatedly receives the same vulnerability "
        "months or years after FortiOS patches. "
        "Ablation target: cross-version sslvpnd binary comparison using semantic homolog tracking "
        "to identify which CVE-2024-21762 patch functions exist in FortiVoice/FortiMail sslvpnd builds."
    ),
}
