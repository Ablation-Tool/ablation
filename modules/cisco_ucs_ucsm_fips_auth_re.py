"""
Cisco UCSM 6.0(2b) FIPS Module and Authentication Library RE
Source: ucs-manager-k9.6.0.2b.bin (inside ucs-6400-k9-bundle-infra.6.0.2b.A.bin)
Components analyzed (from sam_plugin_main inner3 tar):
  ./usr/lib/cfom.so           (711068 bytes, ELF 32-bit i386, stripped)
  ./isan/apache/modules/libhttpauth.a  (122466 bytes, ar archive: Auth.o, SessionCache.o,
                                        LogoutDelayTimer.o, WsChannelInitTimer.o)
  ./isan/apache/modules/mod_security2.so  (752120 bytes, ELF 32-bit i386, with debug_info)

cfom.so: Cisco FIPS Object Module v7.2a - custom OpenSSL ENGINE providing FIPS 140-2
validated cryptographic operations (AES, SHA, RSA, ECDSA, DH, DSA, DRBG).
Exports ENGINE_load_cfom, bind_engine, FINGERPRINT_premain, FIPS_cfom_get_load_permission,
and ~600 FIPS-wrapped crypto primitives.

libhttpauth.a: Static library linked into mod_nuova.so implementing UCSM HTTP authentication.
Source path: /ucsm/perfocarta/sam/src/http/apache/auth/Auth.cc
Auth.o: login/logout/refresh/token flows, session creation, privilege assignment.
SessionCache.o: in-memory session store keyed by cookie string.

mod_security2.so: Standard ModSecurity 2.x WAF module with debug symbols present.

5 findings: 0C/1H/2M/2L
Cumulative: 657 [55C+212H+206M+184L]
"""

# ============================================================
# CFOM.SO ARCHITECTURE
# ============================================================

CFOM_ARCHITECTURE = {
    "identity": "Cisco FIPS Object Module v7.2a (CiscoSSL FOM 7.2a)",
    "elf": "ELF 32-bit i386, dynamically linked, stripped",
    "build_id": "sha1=0018ade3be7e2c547f0b92e158e9bc3210c75c96",
    "dependencies": ["libcrypto.so.1.1", "libdl.so.2", "libpthread.so.0", "libc.so.6"],
    "key_exports": [
        "ENGINE_load_cfom",
        "bind_engine",
        "FINGERPRINT_premain",
        "FIPS_cfom_get_load_permission",
        "cfom_bind_ciphers",
        "cfom_digests",
        "cfom_dh_init",
        "cfom_dsa_init",
        "cfom_rsa_init",
        "cfom_ec_key_meth_init",
        "cfom_ecdsa_sign",
        "cfom_ecdsa_verify",
    ],
    "key_imports": [
        "getenv (PLT index 28, VA 0x101f0)",
        "FIPS_cfom_get_load_permission (PLT index 81)",
        "FIPS_check_selftest_run (PLT index 4)",
        "ENGINE_set_FIPS (PLT index 110, requires OpenSSL 1.1.1b)",
    ],
    "sections": {
        ".text":    "VA 0x10980, size 0x64dfb (413KB)",
        ".rodata":  "VA 0x76000, size 0xb226 (45KB)",
        ".data":    "VA 0xad260, size 0x11a8",
        ".ctors":   "VA 0xab408 (constructor called at library load)",
    },
    "post_state_vars": {
        "post_initialized": ".bss + 0x294 (relative to GOT 0xad000)",
        "post_ok":          ".bss + 0x1460 (relative to GOT 0xad000)",
    },
    "fips_source_files": [
        "fips_post.c", "aes_wrap.c", "bn_add.c", "bn_blind.c", "bn_ctx.c",
        "bn_div.c", "bn_exp.c", "bn_exp2.c", "bn_gcd.c", "bn_lib.c",
        "bn_mont.c", "bn_rand.c", "hmac.c", "ecdsa_sign.c", "dh_check.c",
    ],
}

# ============================================================
# LIBHTTPAUTH.A ARCHITECTURE
# ============================================================

LIBHTTPAUTH_ARCHITECTURE = {
    "ar_members": ["Auth.o", "SessionCache.o", "LogoutDelayTimer.o", "WsChannelInitTimer.o"],
    "source_path": "/ucsm/perfocarta/sam/src/http/apache/auth/Auth.cc",
    "compiler": "GCC 5.2.0",
    "auth_flows": [
        "processLoginMe        - password-based login, returns cookie + session_id",
        "processTokenLoginMe   - token-based login (alternate auth path)",
        "processTokenRefreshMe - refresh token session",
        "processRefreshMe      - refresh cookie session",
        "processLogoutMe       - standard logout (delayed or immediate)",
        "changeSelfPasswordMe  - self-service password change",
        "processKillSessionMe  - admin-initiated session kill",
        "processClearSessionMe - clear session cache",
        "invokeCheckAuthToken  - validate compute auth token",
        "generateIMXMLCookie   - cookie generation using /dev/urandom",
    ],
    "session_limits": {
        "source":         "DME (Device Management Engine) query at each login",
        "per_user_limit": "Maximum sessions reached for user %s",
        "total_limit":    "Maximum http user sessions %d",
        "on_dme_down":    "Failed to get SessionLimits, DME is down. (SessionCache.o)",
    },
    "privilege_format": "64-bit bitmask (uint64, logged as %llx)",
    "random_source":    "/dev/urandom",
    "session_key_type": "string cookie (inserted into SessionCache keyed by cookie value)",
}

# ============================================================
# FINDINGS
# ============================================================

FINDINGS = {

    "F1": {
        "id":       "F1",
        "title":    "FIPS POST Bypass via CISCOSSL_FOM_DIAG=SKIP_POST",
        "severity": "HIGH",
        "component": "cfom.so",
        "what": (
            "cfom.so (Cisco FIPS Object Module v7.2a) contains a single getenv() call "
            "at VA 0x11d09. It calls getenv(\"CISCOSSL_FOM_DIAG\") and compares the result "
            "against the literal string \"SKIP_POST\" using repz cmpsb with ecx=9. When "
            "the comparison succeeds, execution jumps to VA 0x11d70, which sets "
            "post_initialized=1 and post_ok=0 and returns success immediately, skipping "
            "the entire FIPS Power-On Self Test."
        ),
        "disassembly": {
            "0x11d02": "lea -0x2cd56(%ebx),%eax  ; eax = 0x802aa -> 'CISCOSSL_FOM_DIAG'",
            "0x11d08": "push %eax",
            "0x11d09": "call 0x101f0             ; getenv@plt",
            "0x11d11": "test %eax,%eax",
            "0x11d13": "je 0x11d26              ; NULL return -> run POST normally",
            "0x11d15": "lea -0x2cd44(%ebx),%edi  ; edi = 0x802bc -> 'SKIP_POST'",
            "0x11d1b": "mov $0x9,%ecx",
            "0x11d20": "mov %eax,%esi",
            "0x11d22": "repz cmpsb              ; compare 9 bytes",
            "0x11d24": "je 0x11d70              ; match -> skip POST",
            "0x11d70": "movl $0x1,0x294(%ebx)   ; post_initialized = 1",
            "0x11d7c": "movl $0x0,0x1460(%ebx)  ; post_ok = 0",
            "0x11d88": "add $0x1c,%esp",
            "0x11d8b": "mov $0x1,%eax           ; return 1 (success)",
            "0x11d94": "ret",
        },
        "why_it_matters": (
            "The FIPS POST verifies the integrity of all cryptographic algorithm implementations "
            "including DRBG, AES, SHA, RSA, ECDSA, and DH. Skipping it means a modified cfom.so "
            "with weakened DRBG output, backdoored RSA key generation, or disabled entropy checks "
            "will load without any self-test failure. Combined with the bind-mount path "
            "(stop-ucsm-container.sh copies from /bootflash), an attacker who writes a modified "
            "cfom.so to /bootflash/ucsm-container/ and sets CISCOSSL_FOM_DIAG=SKIP_POST in the "
            "container startup environment gets persistent crypto-layer compromise with no POST alert."
        ),
        "how_to_trigger": (
            "Set CISCOSSL_FOM_DIAG=SKIP_POST in the LXC container environment before UCSM starts. "
            "In start-ucsm-container.sh, the container is launched via 'virsh -c lxc:/// start'; "
            "environment variables can be injected via the container XML config in /var/lib/libvirt/. "
            "With write access to /bootflash (bind-mounted into container), the startup script can "
            "be modified to export CISCOSSL_FOM_DIAG=SKIP_POST before virsh start."
        ),
        "remediation": (
            "Remove the CISCOSSL_FOM_DIAG/SKIP_POST code path from cfom.so. The FIPS 140-2 "
            "standard does not permit conditional POST bypass. The current implementation is "
            "non-compliant if the bypass path can be triggered in a production configuration. "
            "If the bypass is required for testing, it must be gated on a compile-time flag "
            "that is not present in production builds."
        ),
        "references": [
            "FIPS 140-2 Section 4.9: Power-Up Self-Tests are mandatory and shall not be bypassable",
            "NIST SP 800-131A: Algorithm transition requirements",
            "cfom.so VA 0x11cf0-0x11d94 (POST initialization function)",
        ],
    },

    "F2": {
        "id":       "F2",
        "title":    "X-Forwarded-For Trusted from HA Fabric Interconnect IP",
        "severity": "MEDIUM",
        "component": "libhttpauth.a (Auth.o)",
        "what": (
            "Auth.cc accepts and trusts the X-Forwarded-For header without modification when "
            "the connecting source IP matches the Fabric Interconnect's HA management interface IP. "
            "The trust decision is logged as 'HA IP Match. Source IP: %s, Trusted FI Mgmt IP: %s' "
            "followed by 'Trusting X-Forwarded-For from local FI. Using client IP: %s'. "
            "The FI management IP is retrieved via 'Found a Fabric Interconnect MgmtIf.' "
            "(a DME object lookup)."
        ),
        "why_it_matters": (
            "If an attacker can send HTTP requests to the UCSM Apache instance from the FI's "
            "HA management IP (e.g., the FI itself is compromised, or an SSRF originates from "
            "the FI's management-plane IP), they can set X-Forwarded-For to any IP address. "
            "Any IP-based access control, rate limiting by client IP, or audit logging that "
            "relies on the client IP would then reflect the forged X-Forwarded-For value. "
            "In dual-FI setups, the secondary FI's management IP would also be trusted, "
            "doubling the attack surface."
        ),
        "trust_condition": {
            "trigger":        "Source IP == FI MgmtIf HA IP (resolved via DME)",
            "trusted_header": "X-Forwarded-For",
            "result":         "Apache sees client IP as X-Forwarded-For value, not real source IP",
            "log_strings": [
                "Found a Fabric Interconnect MgmtIf.",
                "HA IP Match. Source IP: %s, Trusted FI Mgmt IP: %s",
                "Trusting X-Forwarded-For from local FI. Using client IP: %s",
            ],
        },
        "remediation": (
            "Only trust X-Forwarded-For headers from hosts that cannot inject them in the first place. "
            "The HA link between FIs is a dedicated channel and should not carry client-controlled "
            "HTTP headers through to the management API. If FI-to-FI proxy is required, validate "
            "the entire HTTPS chain and sign the forwarded IP claim, rather than trusting a header."
        ),
        "references": [
            "Auth.cc string literal: 'Trusting X-Forwarded-For from local FI'",
            "Auth.cc string literal: 'HA IP Match. Source IP: %s, Trusted FI Mgmt IP: %s'",
        ],
    },

    "F3": {
        "id":       "F3",
        "title":    "MOD_NUOVA_REFRESH_INTERVAL Environment Variable Controls Session Refresh",
        "severity": "MEDIUM",
        "component": "libhttpauth.a (Auth.o)",
        "what": (
            "Auth.cc reads the environment variable MOD_NUOVA_REFRESH_INTERVAL and uses it "
            "to set the session refresh interval, logging 'refresh interval set to %d'. "
            "The variable is undocumented. Setting it to 0 would disable periodic session "
            "refresh checking; setting it to a large value would extend the effective session "
            "lifetime beyond the configured timeout. The variable sits next to the HTTPD_TEST_SECURITY "
            "string (found in mod_nuova.so) in the same diagnostic env-var pattern."
        ),
        "why_it_matters": (
            "If set in the UCSM container environment, MOD_NUOVA_REFRESH_INTERVAL=0 or a very "
            "large value would cause existing authenticated sessions to persist indefinitely "
            "after logout or timeout, or prevent session token rotation. In combination with "
            "session hijacking (cookie theft), this extends the exploit window. As with "
            "HTTPD_TEST_SECURITY, this env var can be injected via modification of the "
            "container startup environment (bind-mount path to /bootflash)."
        ),
        "evidence": [
            "Auth.o string literal: 'MOD_NUOVA_REFRESH_INTERVAL'",
            "Auth.o string literal: 'refresh interval set to %d'",
            "Pattern: same diagnostic env-var pattern as HTTPD_TEST_SECURITY in mod_nuova.so",
        ],
        "remediation": (
            "Remove MOD_NUOVA_REFRESH_INTERVAL from production builds. Session refresh intervals "
            "must be fixed at the code level or derived from UCSM policy configuration, not "
            "from environment variables that can be set by anyone with container startup access."
        ),
    },

    "F4": {
        "id":       "F4",
        "title":    "Session Cookie Entropy Debug Logging",
        "severity": "LOW",
        "component": "libhttpauth.a (Auth.o)",
        "what": (
            "Auth.cc logs the raw byte count and the actual random value used for session cookie "
            "generation: 'reading %d bytes from /dev/urandom, random %d' and "
            "'setting random, addr %p, value %d'. If UCSM diagnostic logging is active "
            "(e.g., triggered by CISCOSSL_FOM_DIAG or another diagnostic flag), the numeric "
            "seed value used to generate session cookies is written to the UCSM log. "
            "The log destination depends on DME_ERROR configuration."
        ),
        "why_it_matters": (
            "An attacker with read access to the UCSM diagnostic log (e.g., via the "
            "/anonymous directory exposed by httpd.conf or via authenticated log access) "
            "could observe the random value used during cookie generation. If the cookie "
            "is derived directly from this value, live session cookies could be forged. "
            "This is conditional on debug logging being enabled."
        ),
        "evidence": [
            "Auth.o string: 'reading %d bytes from /dev/urandom, random %d'",
            "Auth.o string: 'setting random, addr %p, value %d'",
        ],
        "remediation": (
            "Remove entropy debug logging from production builds. Never log cryptographic "
            "material or values derived from the random seed, regardless of log level."
        ),
    },

    "F5": {
        "id":       "F5",
        "title":    "Source Tree Path Disclosure in Auth.cc Error Strings",
        "severity": "LOW",
        "component": "libhttpauth.a (Auth.o)",
        "what": (
            "Auth.cc embeds the full internal source path in runtime error strings that are "
            "reachable via the UCSM management API: "
            "'DME_ERROR: /ucsm/perfocarta/sam/src/http/apache/auth/Auth.cc: failed to get current time' "
            "and 'DME_ERROR: /ucsm/perfocarta/sam/src/http/apache/auth/Auth.cc: snprintf failed'. "
            "These strings are linked into the production libhttpauth.a and therefore into mod_nuova.so."
        ),
        "why_it_matters": (
            "Reveals the internal UCSM codename ('perfocarta') and source tree layout. "
            "Confirms that the SAM (Service Abstraction Manager) HTTP authentication component "
            "source lives at /ucsm/perfocarta/sam/src/http/apache/auth/. "
            "DME_ERROR messages could be surfaced to API clients in error responses."
        ),
        "internal_path": "/ucsm/perfocarta/sam/src/http/apache/auth/Auth.cc",
        "remediation": "Strip full source paths from production error strings; use error codes only.",
    },

}

# ============================================================
# MODULE SUMMARY
# ============================================================

MODULE_SUMMARY = {
    "module": "cisco_ucs_ucsm_fips_auth_re",
    "firmware": "ucs-6400-k9-bundle-infra.6.0.2b.A.bin",
    "components": {
        "cfom.so":           "Cisco FIPS Object Module v7.2a, 711KB, ELF i386, stripped",
        "libhttpauth.a":     "HTTP auth static library, 122KB, 4 .o files (Auth.o, SessionCache.o, ...)",
        "mod_security2.so":  "ModSecurity 2.x, 752KB, with debug symbols",
    },
    "finding_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 2},
    "cumulative_counts": {"CRITICAL": 55, "HIGH": 212, "MEDIUM": 206, "LOW": 184},
    "cumulative_total": 657,
}

if __name__ == "__main__":
    import json
    print(json.dumps(MODULE_SUMMARY, indent=2))
    for fid, f in FINDINGS.items():
        print(f"\n[{f['severity']}] {f['id']}: {f['title']}")
        print(f"  Component: {f['component']}")
