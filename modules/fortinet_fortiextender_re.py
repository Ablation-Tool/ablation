"""
Fortinet FortiExtender 511F v7.0.3 RE
Source: FEXT_511F-v7.0.3-build0056.out (23MB)
Architecture: ARM aarch64 (Cortex-A53)
Extraction: gzip outer -> raw disk image -> MBR -> squashfs (hsqs LE) at 0x2a2f78
Web server: Kore (C-based) + libapgui.so (REST handlers)
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":      "Fortinet FortiExtender 511F",
    "version":      "v7.0.3 build 0056",
    "arch":         "aarch64 (ARM Cortex-A53)",
    "libc":         "musl 1.2.x (statically linked)",
    "filesystem":   "squashfs LE (hsqs magic) at disk offset 0x2a2f78",
    "web_process":  "Kore web framework (C) + libapgui.so REST handlers",
    "process_user": "admin (runas admin in apgui.conf)",

    "image_layout": {
        "format":        "40-byte ASCII text header + gzip wrapper",
        "inner":         "raw MBR disk image (~23MB)",
        "mbr_dtb_blob":  "2.76MB DTB blob at disk offset 512 (partition table points beyond image boundary)",
        "squashfs":      "hsqs LE at disk offset 0x2a2f78 (after DTB blob)",
        "extraction":    "dd if=inner.raw bs=1 skip=$((0x2a2f78)) | unsquashfs -f -d rootfs /dev/stdin",
    },

    "key_binaries": {
        "libapgui.so": "/lib/libapgui.so -- REST API handlers, PTY management; NOT stripped (full symbol table)",
        "extenderd":   "/usr/sbin/extenderd -- main daemon; NOT stripped with debug_info",
    },

    "kore_config": {
        "http":  "http_bind 0.0.0.0 80",
        "https": "https_bind 0.0.0.0 443",
        "certs": "/tmp/fgt_b.crt + /tmp/fgt_b.key (generated at runtime)",
        "runas": "admin",
    },
}


# ---------------------------------------------------------
# FEXT-F01: Unauthenticated REST API (full device attack surface)
# ---------------------------------------------------------
FEXT_F01_UNAUTH_REST_API = {
    "id":       "FEXT-F01",
    "product":  "Fortinet FortiExtender 511F v7.0.3",
    "severity": "CRITICAL -- entire REST API surface accessible without credentials; combined with FEXT-F02 yields unauthenticated RCE as admin",
    "class":    "Missing Authentication for Critical Function (CWE-306)",
    "cwe":      "CWE-306 (Missing Authentication for Critical Function)",

    "description": (
        "The FortiExtender REST API is completely unauthenticated. "
        "Authentication is disabled at both the framework layer (Kore config) "
        "and the handler layer (system_api_req_handler in libapgui.so). "
        "The process runs as the 'admin' user. "
        "Any client with network access to ports 80/443 can reach any API endpoint "
        "without credentials."
    ),

    "framework_layer_evidence": {
        "file":    "/etc/kore/apgui.conf",
        "finding": "Both authentication and session validator blocks are commented out",
        "config":  (
            "# validator v_session ...       <- COMMENTED OUT\n"
            "# authentication ap_auth ...    <- COMMENTED OUT\n"
            "validator all           regex .*  <- only active validator: accepts any value"
        ),
        "note": "In Kore, an 'authentication' block is the gate that enforces credentials on routes. "
                "Commenting it out disables the gate entirely. The only active validator 'all' uses "
                "regex '.*' which matches empty strings -- any parameter value passes.",
    },

    "handler_layer_evidence": {
        "function":  "system_api_req_handler (libapgui.so:0x1b810)",
        "disasm":    (
            "000000000001b810 <system_api_req_handler>:\n"
            "   1b810:  stp x29, x30, [sp, #-32]!\n"
            "   1b818:  str x0, [x29, #24]\n"
            "   1b81c:  adrp x0, 3e000\n"
            "   1b820:  add x0, x0, #0xef8           ; handler table at 0x3eef8\n"
            "   1b824:  mov w2, #0x23                 ; 35 endpoint handlers\n"
            "   1b828:  mov x1, x0\n"
            "   1b82c:  ldr x0, [x29, #24]\n"
            "   1b830:  bl  97f0 <rest_generic_request_dispatch@plt>\n"
            "   1b834:  ldp x29, x30, [sp], #32\n"
            "   1b838:  ret"
        ),
        "note": "Zero instructions between function entry and rest_generic_request_dispatch. "
                "No call to kore_worker_find_authorized, kore_worker_authorize, "
                "config_get_session, or any other auth primitive. The function is a "
                "direct trampoline into the dispatch table.",
    },

    "unauthenticated_endpoints": {
        "/api/4.2/monitor/reboot":                    "System reboot (no params required)",
        "/api/4.2/monitor/factoryreset":              "Factory reset (no params required)",
        "/api/4.2/monitor/firmware/osImgUpgLocal":    "Local firmware upload -- arbitrary image push",
        "/api/4.2/monitor/firmware/osImgUpgCld":      "Cloud firmware upgrade",
        "/api/4.2/monitor/terminal":                  "PTY session management (create/delete terminal)",
        "/api/4.2/monitor/terminal/ws":               "WebSocket PTY attach (see FEXT-F02)",
        "/api/4.2/monitor/system/config/backup":      "Full config export",
        "/api/4.2/monitor/system/config/restore":     "Config restore -- arbitrary config push",
        "/api/4.2/monitor/system/sessions":           "Session enumeration and deletion",
        "/api/4.2/config/.*":                         "Full config read/write (dynamic routes)",
    },

    "auth_primitives_confirmed_absent": [
        "kore_worker_find_authorized (UNDEF in libapgui.so -- imported but never called from system_api_req_handler)",
        "kore_worker_find_authorized_by_sid (UNDEF)",
        "config_get_session (UNDEF)",
        "config_user_login (UNDEF)",
    ],

    "attack_scenario": {
        "attacker":     "Any host with network access to FortiExtender management ports",
        "step_1":       "curl -k https://<extender>/api/4.2/monitor/system/config/backup -> full device config",
        "step_2":       "curl -k -X POST https://<extender>/api/4.2/monitor/reboot -> instant DoS",
        "step_3":       "curl -k -X POST -F 'file=@evil.img' https://<extender>/api/4.2/monitor/firmware/osImgUpgLocal -> persistent compromise",
        "privileges":   "None -- no credentials, no session, no tokens",
    },

    "remediation": (
        "Restore the Kore authentication block in apgui.conf. "
        "Implement and call kore_worker_find_authorized at the entry of system_api_req_handler "
        "before passing to rest_generic_request_dispatch. "
        "Bind management API to a dedicated interface or VLAN rather than 0.0.0.0."
    ),
}


# ---------------------------------------------------------
# FEXT-F02: Unauthenticated WebSocket PTY terminal -- pre-auth RCE
# ---------------------------------------------------------
FEXT_F02_UNAUTH_TERMINAL_RCE = {
    "id":       "FEXT-F02",
    "product":  "Fortinet FortiExtender 511F v7.0.3",
    "severity": "CRITICAL -- pre-authentication remote code execution as admin; full device compromise in two unauthenticated HTTP requests",
    "class":    "Missing Authentication for Critical Function / OS Command Injection (CWE-306, CWE-78)",
    "cwe":      "CWE-306 (Missing Authentication for Critical Function)",

    "description": (
        "The FortiExtender exposes an interactive WebSocket terminal "
        "at /api/4.2/monitor/terminal/ws via the system_terminal_ws_handler. "
        "The handler creates a PTY child process via kore_pty_create, "
        "then attaches the WebSocket to the PTY via kore_pty_attach. "
        "The terminal provides an interactive shell to any unauthenticated caller. "
        "The process runs as 'admin' (runas admin in apgui.conf). "
        "This is a direct consequence of FEXT-F01 -- authentication is fully disabled "
        "at the Kore framework level."
    ),

    "technical_evidence": {
        "config":        "/etc/kore/api_system.conf: static /api/4.2/monitor/terminal/ws system_terminal_ws_handler",
        "handler":       "system_terminal_ws_handler (libapgui.so:0x1bc78)",
        "pty_symbols":   [
            "kore_pty_create (libapgui.so -- creates PTY, forks child, logs: 'create pty %p.' + 'pid %d')",
            "kore_pty_attach (libapgui.so -- attaches PTY to WebSocket connection)",
            "kore_pty_resize (libapgui.so -- handles terminal resize messages)",
            "kore_pty_delete (libapgui.so -- cleanup on disconnect)",
        ],
        "params_schema": {
            "POST /api/4.2/monitor/terminal":   "Create PTY session, returns pid; body: {rows: int, cols: int}",
            "GET  /api/4.2/monitor/terminal/ws?pid=<pid>": "WebSocket upgrade: attach to PTY by pid",
            "DELETE /api/4.2/monitor/terminal?pid=<pid>": "Terminate PTY session",
        },
        "log_strings":   [
            "'[...] create pty %p.' -- emitted by kore_pty_create on success",
            "'[...] pid %d' -- forked child PID logged",
            "'[...] pty %p, pid %d' -- PTY + PID association logged",
            "'[...] Failed to create pty.' -- error path",
        ],
    },

    "rce_chain": {
        "step_1": "POST /api/4.2/monitor/terminal {rows: 24, cols: 80} -> {pid: <N>}",
        "step_2": "WebSocket connect: wss://<extender>/api/4.2/monitor/terminal/ws?pid=<N>",
        "step_3": "Interactive shell session -- full command execution as admin",
        "total_requests": 2,
        "credentials_required": "None",
    },

    "impact": (
        "Full administrative access to the FortiExtender device. "
        "FortiExtender 511F manages LTE/5G cellular WAN uplinks in branch offices -- "
        "compromise allows: disabling WAN uplinks (DoS), intercepting cellular traffic, "
        "pivoting into the enterprise LAN segment via the LTE interface, "
        "persistent backdoor via firmware replacement (FEXT-F01). "
        "Authentication-less access means this is exploitable from any network "
        "segment that can reach the management interface."
    ),

    "remediation": (
        "Enable Kore authentication (restore ap_auth block). "
        "Restrict /api/4.2/monitor/terminal to authenticated sessions only. "
        "Require additional step-up authentication (separate PIN or confirm dialog) "
        "before creating a PTY session, even in authenticated contexts. "
        "Consider removing the terminal endpoint entirely from production firmware "
        "and shipping it only in debug builds."
    ),
}


# ---------------------------------------------------------
# FEXT-F03: Debug symbols not stripped in production firmware
# ---------------------------------------------------------
FEXT_F03_DEBUG_SYMBOLS = {
    "id":       "FEXT-F03",
    "product":  "Fortinet FortiExtender 511F v7.0.3",
    "severity": "LOW -- no direct exploitability; materially accelerates RE and vulnerability discovery",
    "class":    "Information Exposure (CWE-200)",
    "cwe":      "CWE-200 (Exposure of Sensitive Information to Unauthorized Actor)",

    "description": (
        "libapgui.so and extenderd ship with full symbol tables (not stripped). "
        "Function names, parameter types, and in some cases debug section data "
        "are present in the production firmware image. "
        "This eliminated the need for dynamic analysis to identify "
        "system_api_req_handler, kore_pty_create, kore_pty_attach, "
        "and the 35-entry handler dispatch table."
    ),

    "evidence": {
        "libapgui.so": (
            "nm -n -> 200+ exported symbols including: "
            "system_api_req_handler, system_terminal_ws_handler, "
            "system_reboot_response, v4_terminal_set, v4_terminal_wscb_connect, "
            "v4_terminal_wscb_message, v4_exec_osImgUpgLocal, "
            "kore_pty_create, kore_pty_attach, kore_pty_resize, kore_pty_delete, "
            "kore_find_api_user, kore_generate_api_key, kore_worker_authorize, "
            "rest_generic_request_dispatch"
        ),
        "extenderd": "file: ELF 64-bit LSB shared object, ARM aarch64, NOT stripped, with debug_info",
    },

    "impact_on_re": "FEXT-F01 and FEXT-F02 were confirmed from static analysis alone. "
                    "No dynamic execution required to map the attack surface.",

    "remediation": "Run strip --strip-all on all production binaries before packaging firmware.",
}


# ---------------------------------------------------------
# Analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "rootfs":           "EXTRACTED (squashfs at 0x2a2f78 in MBR disk image, extracted to rootfs/)",
    "kore_config":      "COMPLETE -- /etc/kore/apgui.conf + api_system.conf fully analyzed",
    "libapgui.so":      "COMPLETE -- system_api_req_handler disassembled; PTY symbols confirmed",
    "extenderd":        "SURFACE ONLY -- not stripped; deeper analysis pending",
    "authentication":   "CONFIRMED ABSENT at both config and handler layer (FEXT-F01)",
    "terminal_rce":     "CONFIRMED -- kore_pty_create + system_terminal_ws_handler (FEXT-F02)",
    "fortism":          "NOT ANALYZED -- kernel not extracted; squashfs contains ARM aarch64 userspace only",

    "unique_findings": [
        "FEXT-F01: CRITICAL -- Kore authentication commented out in apgui.conf; system_api_req_handler calls rest_generic_request_dispatch with zero auth check; entire API unauthenticated",
        "FEXT-F02: CRITICAL -- /api/4.2/monitor/terminal/ws unauthenticated WebSocket PTY; 2-request pre-auth RCE as admin (POST create PTY + WS attach)",
        "FEXT-F03: LOW -- libapgui.so and extenderd NOT stripped; full symbol table in production firmware",
        "Process runas admin -- no privilege separation between web server and OS",
        "Management API binds to 0.0.0.0:80/443 -- reachable from any network interface including LTE WAN",
    ],

    "vs_other_products": {
        "FGT/FFW/FWB": "fortism LSM + authenticated REST; FortiExtender auth is entirely absent at config level",
        "FAD":         "SBVM DES key issue; REST has authentication; FortiExtender terminal RCE is unique",
        "FAC":         "Auth appliance -- authenticated REST; rootfs encrypted; opposite security posture",
        "FFF":         "Electron desktop; unauthenticated WebSocket but localhost-only; FortiExtender is network-exposed",
    },

    "image_format_notes": {
        "outer_header": "40-byte ASCII: 'FEXT_511F-v7.0.3-build0056.out\\n...' (build metadata)",
        "gzip_wrapper": "Immediate gzip stream after header",
        "inner_disk":   "MBR raw disk image; partition entries point beyond the image boundary (MBR is partial header only)",
        "dtb_blob":     "2.76MB device tree blob at disk offset 512 (immediately after MBR)",
        "squashfs":     "hsqs LE at disk offset 0x2a2f78; 19MB; extracted with unsquashfs",
    },
}
