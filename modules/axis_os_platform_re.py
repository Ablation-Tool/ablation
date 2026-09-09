"""
axis_os_platform_re — AXIS OS platform library RE module

Built from actual binary analysis of aarch64 stripped ELFs extracted from
axisecp/acap-api Docker image. Findings below reflect confirmed disassembly,
not speculation.

Libraries analyzed:
  libaxhttp.so       CGI/VAPIX HTTP handler — IPC auth + header parsing
  libaxparameter.so  VAPIX parameter store — conf file injection surface
  libax_daemon.so    Privilege drop library — setgid/initgroups/setuid sequence
  libaxevent.so      VAPIX/ONVIF event subscription — XML element API

Confirmed findings (see ~/VDT/axis-os-re/VULNERABILITIES-axis-os.md):
  F-AXPARAM-01  MEDIUM: Value written unescaped as name="value" to .conf files
                FIRMWARE VERIFICATION: RCE escalation REFUTED — parhand reads conf via
                custom DSL parser (not shell); libdbus-send.so uses dbus C API (no system());
                $VALUE injection reaches dbus arg level only, not shell. Stays MEDIUM.
  F-AXHTTP-03   LOW-CANDIDATE: GIO watch deregistered on UID mismatch → local DoS
                (requires on-device test to confirm; not verified in firmware)
  F-AXEVENT-01  CLOSED: ax_event_element_item_parse_xml has ZERO firmware callers —
                confirmed by full rootfs scan. ONVIF Subscribe uses libwseventfilters.so +
                libsoap.so, never reaches this API. Attack surface is ACAP only (out of scope).

Refuted:
  F-AXHTTP-01   REFUTED: auth IS enforced — UID mismatch returns FALSE (drops request)
  F-AXHTTP-02   REFUTED: strlen guard at 0x29d8 before 8-byte pointer advance
  F-AXDAEMON-01 REFUTED: privilege drop sequence correct; setreuid(-1,0) path is error recovery

Firmware analysis (P3245-V_11_11_220.bin extracted rootfs):
  param daemon:   parhand (/usr/bin/parhand), not axpard
  param.cgi:      proxied via Unix socket to /usr/bin/param.cgi-transfer
  parhand confs:  custom DSL (group/param/dbus fields), parser = Standard2parser
  libdbus-send.so: parses dbus arg strings and calls dbus C API directly — no system()
  ONVIF events:  libwseventfilters.so (libsoap.so) + libwsevent.so — no libaxevent.so involvement
  dynamic param dir: /etc/dynamic/param/ written by libaxparameter.so, read by parhand DSL parser

Standalone:
    cd ~/ablation
    python3 modules/axis_os_platform_re.py ~/VDT/axis-os-re/platform-libs/aarch64
    python3 modules/axis_os_platform_re.py ~/VDT/axis-os-re/platform-libs/aarch64 --lib libaxhttp.so
    python3 modules/axis_os_platform_re.py ~/VDT/axis-os-re/platform-libs/aarch64 --lib libaxparameter.so
    python3 modules/axis_os_platform_re.py ~/VDT/axis-os-re/platform-libs/aarch64 --all --out findings.json
"""

import os
import sys
import json
import struct
import argparse
from pathlib import Path

import capstone

sys.path.insert(0, str(Path(__file__).parent))
from semantic_search import describe_function, normalize_asm
from sentence_transformers import SentenceTransformer
import numpy as np


# ---------------------------------------------------------------------------
# PLT maps — derived from readelf -r analysis of each library
# Format: address -> symbol_name
# ---------------------------------------------------------------------------

AXHTTP_PLT = {
    0x1740: 'g_free',
    0x1750: 'g_mkdir_with_parents',
    0x1760: 'ax_package_get',
    0x1770: 'g_unlink',
    0x1780: 'pipe',
    0x1790: 'ax_http_server_socket_free',
    0x17a0: 'g_data_output_stream_put_string',
    0x17b0: 'g_io_channel_set_buffered',
    0x17c0: 'g_ascii_strtoll',
    0x17d0: 'getpwnam',
    0x17e0: 'g_io_channel_unix_new',
    0x17f0: '__gmon_start__',
    0x1800: 'g_object_unref',
    0x1810: 'g_strdup',
    0x1820: 'g_data_output_stream_put_byte',
    0x1830: 'ax_http_server_socket_new',
    0x1840: 'fdipc_server_socket',
    0x1850: 'g_list_free',
    0x1860: 'g_thread_unref',
    0x1870: 'g_malloc',
    0x1880: '__cxa_finalize',
    0x1890: 'g_data_input_stream_new',
    0x18a0: 'g_strdup_printf',
    0x18b0: 'strncmp',
    0x18c0: 'g_hash_table_new_full',
    0x18d0: 'g_io_add_watch',
    0x18e0: 'ax_http_util_parse_header_status',
    0x18f0: 'g_ascii_strtoull',
    0x1900: 'g_uri_unescape_string',
    0x1910: 'g_data_input_stream_read_line',
    0x1920: 'g_main_context_find_source_by_id',
    0x1930: 'g_main_context_default',
    0x1940: '__stack_chk_fail',
    0x1950: 'g_unix_output_stream_new',
    0x1960: 'g_rmdir',
    0x1970: 'g_slice_alloc',
    0x1980: 'g_quark_from_string',
    0x1990: 'g_strchomp',
    0x19a0: 'g_list_append',
    0x19b0: 'g_strchug',
    0x19c0: 'ax_http_util_parse_header_content_type',
    0x19d0: 'g_source_remove',
    0x19e0: 'g_hash_table_replace',
    0x19f0: 'g_ascii_strncasecmp',
    0x1a00: 'g_output_stream_splice',
    0x1a10: 'g_strsplit',
    0x1a20: 'ax_http_util_strip_trailing',
    0x1a30: 'g_list_prepend',
    0x1a40: 'ax_http_util_parse_header_location',
    0x1a50: 'g_io_channel_unref',
    0x1a60: 'g_unix_input_stream_new',
    0x1a70: 'strchr',
    0x1a80: 'ax_http_handler_free',
    0x1a90: 'g_hash_table_unref',
    0x1aa0: 'g_error_free',
    0x1ab0: 'ax_http_util_parse_query',
    0x1ac0: 'g_strfreev',
    0x1ad0: 'close',
    0x1ae0: 'fdipc_recv_with_uid',
    0x1af0: 'g_slice_free1',
    0x1b00: 'strlen',
    0x1b10: 'g_log',
    0x1b20: 'g_file_test',
    0x1b30: 'g_thread_try_new',
}

AXPARAM_PLT = {
    0x1cf0: 'g_free',
    0x1d00: 'unlink',
    0x1d10: 'dbus_interface_free',
    0x1d20: 'fgets',
    0x1d30: 'fdopen',
    0x1d40: 'g_hash_table_destroy',
    0x1d50: 'g_dbus_error_register_error_domain',
    0x1d60: 'cli_resetOptions',
    0x1d70: 'fileno',
    0x1d80: '__gmon_start__',
    0x1d90: 'g_object_unref',
    0x1da0: 'g_strcmp0',
    0x1db0: 'rename',
    0x1dc0: 'g_strdup',
    0x1dd0: 'fstat',
    0x1de0: 'ax_parameter_error_quark',
    0x1df0: 'g_dbus_node_info_new_for_xml',
    0x1e00: 'cli_getParamsInGroup',
    0x1e10: 'g_list_foreach',
    0x1e20: 'g_hash_table_insert',
    0x1e30: 'g_list_free',
    0x1e40: 'cli_readGroupFile',
    0x1e50: 'strcasestr',
    0x1e60: 'g_dbus_connection_call',
    0x1e70: 'fsync',
    0x1e80: 'g_malloc',
    0x1e90: 'flock',
    0x1ea0: 'g_hash_table_remove',
    0x1eb0: 'strrchr',
    0x1ec0: '__cxa_finalize',
    0x1ed0: 'g_assertion_message',
    0x1ee0: 'g_object_ref',
    0x1ef0: 'g_strdup_printf',
    0x1f00: 'g_strstr_len',
    0x1f10: 'g_fprintf',
    0x1f20: 'g_hash_table_new_full',
    0x1f30: 'fgetc',
    0x1f40: 'fflush',
    0x1f50: '__errno_location',
    0x1f60: 'g_dbus_node_info_lookup_interface',
    0x1f70: 'g_variant_get',
    0x1f80: 'g_ascii_toupper',
    0x1f90: 'fopen',
    0x1fa0: 'g_set_error',
    0x1fb0: '__stack_chk_fail',
    0x1fc0: 'g_quark_from_static_string',
    0x1fd0: 'g_quark_from_string',
    0x1fe0: 'cli_getCustomParam',
    0x1ff0: 'fseek',
    0x2000: 'dbus_interface_new',
    0x2010: 'g_free_sized',
    0x2020: 'fclose',
    0x2030: 'g_utf8_strlen',
    0x2040: 'g_hash_table_lookup',
    0x2050: 'strcmp',
    0x2060: 'cli_cleanupGroupCache',
    0x2070: 'g_malloc0',
    0x2080: 'strdup',
    0x2090: 'g_list_prepend',
    0x20a0: 'canonicalize_file_name',
    0x20b0: 'g_dbus_connection_register_object',
    0x20c0: 'strchr',
    0x20d0: 'g_list_first',
    0x20e0: 'g_bus_unown_name',
    0x20f0: 'fchown',
    0x2100: 'free',
    0x2110: 'g_bus_own_name',
    0x2120: 'cli_getParamInGroup',
    0x2130: 'g_ascii_strdown',
    0x2140: 'fwrite',
    0x2150: 'fputs',
    0x2160: 'g_dbus_method_invocation_return_value',
    0x2170: 'close',
    0x2180: 'g_utf8_strlen',
    0x2190: 'g_log',
    0x21a0: 'cli_setCustomParam',
    0x21b0: 'ftell',
    0x21c0: 'g_dbus_method_invocation_return_gerror',
    0x21d0: 'g_dbus_node_info_unref',
}


# ---------------------------------------------------------------------------
# Known function map from confirmed disassembly
# ---------------------------------------------------------------------------

AXHTTP_FUNCS = {
    # Internal functions
    0x1bd0: ('__init_helper',        'init guard / constructor setup'),
    0x1c30: ('_ipc_pipe_thread_new', 'pipe() + g_thread_try_new → HTTP handler thread'),
    0x1e00: ('_http_request_thread', 'reads HTTP lines via GDataInputStream, dispatches to callback'),
    # Exported
    0x2180: ('ax_http_handler_free',                 'frees handler struct, unrefs IPC handle'),
    0x21d0: ('ax_http_handler_new',                  'creates handler, calls fdipc_server_socket'),
    0x25b0: ('ax_http_server_socket_free',           'frees server socket'),
    0x2610: ('ax_http_server_socket_new',            'creates Unix IPC socket at /var/run/http/%s/%s'),
    0x2770: ('ax_http_util_parse_query',             'URL query string decoder — g_strsplit + g_uri_unescape_string (SAFE)'),
    0x28b0: ('ax_http_util_strip_trailing',          'rtrim(str, char)'),
    0x2920: ('ax_http_util_parse_header_status',     'parses header with ":" delimiter'),
    0x29a0: ('ax_http_util_parse_header_content_type','strlen guard at 0x29d8 confirmed — NOT vulnerable (length checked before 8-byte advance)'),
    0x2ab0: ('ax_http_util_parse_header_location',   'parses Location: header'),
}

AXPARAM_FUNCS = {
    0x2e80: ('ax_parameter_new',    'creates AXParameter, connects to D-Bus'),
    0x2f70: ('ax_parameter_free',   'frees AXParameter'),
    0x2fc0: ('ax_parameter_add',    'add new param — NAME ≤32 chars, alpha/_, VALUE unescaped — CONF INJ'),
    0x32e0: ('ax_parameter_remove', 'removes param'),
    0x3470: ('ax_parameter_set',    'sets param value — no value length/escape check — CONF INJ'),
    0x36b0: ('ax_parameter_get',    'gets param via cli_getCustomParam D-Bus'),
    0x3840: ('ax_parameter_list',   'lists params via cli_readGroupFile'),
    0x3e50: ('dbus_interface_free', 'frees D-Bus interface'),
    0x3f00: ('dbus_interface_new',  'creates D-Bus interface'),
}

AXDAEMON_PLT = {
    # PLT_start=0x0fa0, header=32b, stubs at 0x0fc0+n*16
    0x0fc0: 'initgroups',
    0x0fd0: 'setuid',
    0x0fe0: 'getsid',
    0x0ff0: 'sigprocmask',
    0x1000: 'daemon',
    0x1010: '__isoc23_fscanf',
    0x1020: 'geteuid',
    0x1030: 'setbuf',
    0x1040: 'getgrnam',
    0x1050: '__cxa_finalize',
    0x1060: 'getuid',
    0x1070: '__cxa_atexit',
    0x1080: 'kill',
    0x1090: 'signal',
    0x10a0: '__snprintf_chk',
    0x10b0: 'fclose',
    0x10c0: 'getpid',
    0x10d0: 'open',
    0x10e0: 'ctermid',
    0x10f0: 'getppid',
    0x1100: 'sigemptyset',
    0x1110: 'flock',
    0x1120: 'fdopen',
    0x1130: 'axsd_create_pid_file',
    0x1140: 'getpwnam',
    0x1150: 'strdup',
    0x1160: 'strerror',
    0x1170: '__stack_chk_fail',
    0x1180: 'close',
    0x1190: 'sigaction',
    0x11a0: 'strrchr',
    0x11b0: '__gmon_start__',
    0x11c0: 'setgid',
    0x11d0: '__fprintf_chk',
    0x11e0: 'setreuid',
    0x11f0: 'free',
    0x1200: 'getpgrp',
    0x1210: 'nanosleep',
    0x1220: 'axsd_set_uid_gid',
    0x1230: '__syslog_chk',
    0x1240: 'axsd_translated_error',
    0x1250: 'sigaddset',
    0x1260: 'umask',
    0x1270: '__errno_location',
    0x1280: 'unlink',
}

AXDAEMON_FUNCS = {
    0x1dc0: ('axsd_set_uid_gid', (
        'textbook-correct privilege drop: validate username+groupname, '
        'getpwnam→geteuid compare, getgrnam→setgid→initgroups→setuid. '
        'All three drops checked for failure. Special path: if euid==pw_uid AND '
        'real_uid==0, calls setreuid(-1,0) to restore effective root then redoes full drop. '
        'NO bypass found. "Failed setting effective uid to 0." = setreuid restore failure.'
    )),
}

# libaxevent.so key PLT entries (PLT_start=0x4300, stubs at 0x4320+n*16)
AXEVENT_PLT_KEY = {
    0x4520: 'ax_event_element_item_parse_xml',   # PLT[32]
    0x4650: 'xmlnode_free_tree',                  # PLT[51]
    0x4830: 'xmlnode_parse_string',               # PLT[81]
    0x48d0: 'ax_event_element_xml_builder_create_item',  # PLT[91]
    0x4c80: 'ax_event_element_xml_builder',       # PLT[150]
}

AXEVENT_FUNCS = {
    0x5cc0: ('ax_event_handler_subscribe', '1168b; uses declaration API — does NOT call ax_event_element_item_parse_xml'),
    0x9070: ('ax_event_element_item_parse_xml', (
        '84b; thin wrapper: calls xmlnode_parse_string(x0) with NO validation '
        'before the bl. Zero internal callers — pure API for external code. '
        'External ONVIF/ACAP callers pass XML strings; library adds no sanitization.'
    )),
}


# ---------------------------------------------------------------------------
# Vulnerability findings from confirmed RE
# ---------------------------------------------------------------------------

FINDINGS = [
    {
        'id': 'F-AXPARAM-01',
        'class': 'PARAM-INJ',
        'severity': 'MEDIUM',
        'library': 'libaxparameter.so',
        'functions': ['ax_parameter_add @ 0x2fc0', 'ax_parameter_set @ 0x3470'],
        'confirmed': True,
        'title': 'Unescaped value storage in VAPIX parameter conf files',
        'detail': (
            'ax_parameter_set and ax_parameter_add both pass the caller-supplied value '
            'to cli_setCustomParam via D-Bus without any escaping or length limit. '
            'The parameter daemon (parhand) writes values using the format string "%s=\\"%s\\"" '
            '(confirmed in strings) to /etc/dynamic/param/<group>/<name>.conf. '
            'A value containing \\" or \\n creates additional key=value lines in the conf file. '
            'FIRMWARE VERIFIED: parhand reads these conf files with a custom DSL parser '
            '(Standard2parser), NOT via shell sourcing. The dbus callback field uses '
            'libdbus-send.so which calls the dbus C API directly — no system() or popen(). '
            '$VALUE injection can corrupt the dbus argument but cannot reach shell. '
            'RCE escalation chain REFUTED by firmware analysis. '
            'Impact: conf file corruption → wrong parameter values → potential '
            'misconfiguration (MEDIUM). '
            'Attack path: VAPIX param.cgi update → ax_parameter_set → parhand → '
            'injected .conf → parhand parser reads extra key=value → misconfiguration.'
        ),
        'evidence': [
            'Strings: "%s=\\"%s\\""',
            'Strings: "/etc/dynamic/param"',
            'Strings: "%s/%s.conf"',
            'ax_parameter_set (0x3470): no cmp with length limit before cli_setCustomParam call',
            'ax_parameter_add (0x2fc0): cmp x0, #0x20 at 0x306c is NAME length check, not value',
            'PLT: cli_setCustomParam imported, no local sanitization before call',
        ],
        'remediation': 'Escape \\" and \\n in values before writing to conf format. Or use key=value without quotes.',
    },
    {
        'id': 'F-AXHTTP-01',
        'class': 'AUTH-BYPASS',
        'severity': 'REFUTED',
        'library': 'libaxhttp.so',
        'functions': ['IO callback @ 0x22c0'],
        'confirmed': False,
        'title': 'IPC UID check: auth IS enforced — NOT a vulnerability',
        'detail': (
            'IO callback at 0x22c0 (registered via g_io_add_watch) enforces UID check: '
            'fdipc_recv_with_uid → getpwnam → compare sender UID with pw_uid. '
            'On mismatch: logs "Credentials does not match uid" then returns 0 (FALSE) '
            'from the GIO callback — the request is dropped, the CGI handler at 0x24e4 '
            'is NEVER called. Full disassembly confirmed: b.ne #0x245c → log path → '
            'return FALSE. Not a bypass.'
        ),
        'evidence': [
            '0x2314: fdipc_recv_with_uid(fd, buf, 0x8ffe, &gid, &uid)',
            '0x232c: getpwnam(appname)  ; expected UID',
            '0x233c: cmp w3, w0         ; compare actual vs expected',
            '0x2340: b.ne #0x245c       ; MISMATCH → log + return FALSE',
            '0x24e4: blr x6             ; dispatch ONLY reached on UID match',
        ],
        'remediation': 'N/A — auth is already enforced.',
    },
    {
        'id': 'F-AXHTTP-02',
        'class': 'INFO-LEAK',
        'severity': 'REFUTED',
        'library': 'libaxhttp.so',
        'functions': ['ax_http_util_parse_header_content_type @ 0x29a0'],
        'confirmed': False,
        'title': 'Content-Type 8-byte skip: length guard confirmed — NOT a vulnerability',
        'detail': (
            'ax_http_util_parse_header_content_type (0x29a0): strlen guard confirmed at 0x29d8. '
            'Disassembly: strlen(input) → cmp x0, #8 → b.ls #0x2a1c (exits if len ≤ 8). '
            'The 8-byte pointer advance at 0x29e4 is only reached if len > 8. '
            'Safe.'
        ),
        'evidence': [
            '0x29d4: strlen(x21=input)',
            '0x29d8: cmp x0, #8',
            '0x29e0: b.ls #0x2a1c   ; exit if len ≤ 8',
            '0x29e4: ldrb w3, [x21, #8]  ; ONLY reached if len > 8',
        ],
        'remediation': 'N/A — guard exists.',
    },
    {
        'id': 'F-AXHTTP-03',
        'class': 'DOS',
        'severity': 'LOW-CANDIDATE',
        'library': 'libaxhttp.so',
        'functions': ['IO callback @ 0x22c0'],
        'confirmed': False,
        'title': 'GIO watch deregistered on UID mismatch — local DoS candidate',
        'detail': (
            'The GIO callback at 0x22c0 returns 0 (FALSE) on ANY error path '
            '(UID mismatch, user not found, fdipc error). In GLib, a GIO callback '
            'returning FALSE causes the IO source to be automatically unregistered '
            'from the main loop. One bad datagram → VAPIX handler watch stops → '
            'subsequent valid requests from legitimate callers are never serviced. '
            'Requires local access (can send a datagram to the IPC socket).'
        ),
        'evidence': [
            '0x2340: b.ne #0x245c     ; UID mismatch → log path',
            '0x24b0+: log + mov w0, #0 + ret  ; return FALSE',
            'g_io_add_watch semantics: callback returning FALSE unregisters source',
        ],
        'remediation': (
            'Return TRUE (keep watching) on UID mismatch instead of FALSE. '
            'Drop the packet, log the error, but preserve the socket watch.'
        ),
    },
    {
        'id': 'F-AXEVENT-01',
        'class': 'XML-INJ',
        'severity': 'CLOSED',
        'library': 'libaxevent.so',
        'functions': ['ax_event_element_item_parse_xml @ 0x9070'],
        'confirmed': False,
        'title': 'XML event template: CLOSED — zero first-party callers confirmed by firmware scan',
        'detail': (
            'ax_event_element_item_parse_xml (0x9070, 84 bytes) takes a raw XML string '
            'and passes it directly to xmlnode_parse_string with no validation. '
            'FIRMWARE VERIFIED: full rootfs scan found zero binaries or libraries calling '
            'this function. Only libaxevent.so itself defines it. '
            'ONVIF Subscribe request handling uses libwseventfilters.so → libsoap.so '
            '(WS-Eventing filter parsing) — does NOT import or call libaxevent functions. '
            'Attack surface exists ONLY for ACAP applications (third-party, out of scope). '
            'No first-party ONVIF daemon uses this API. CLOSED.'
        ),
        'evidence': [
            '0x9070: stp x29, x30, [sp, #-0x20]!',
            '0x907c: bl #0x4830   ; xmlnode_parse_string(x0) — no validation before',
            'Firmware rootfs scan: only libaxevent.so contains this symbol (confirmed with strings)',
            'libwseventfilters.so NEEDED: libsoap.so, libevent2.so, libglib, libwsevent, libwsdutil',
            'libwseventfilters.so does NOT import libaxevent.so — ONVIF path verified independent',
            'onvif-mqtt-event binary: does not call ax_event_element_item_parse_xml',
        ],
        'remediation': 'N/A for first-party code. ACAP SDK documentation should warn callers to validate XML.',
    },
]


# ---------------------------------------------------------------------------
# BERT query profiles — built from confirmed RE observations
# ---------------------------------------------------------------------------

BERT_QUERIES = {
    'conf_injection': (
        'parameter storage | calls: fwrite, fputs, sprintf | '
        'vuln: value string written to file without quote escaping, newline injection possible'
    ),
    'ipc_uid_auth': (
        'IPC socket handler | calls: fdipc_recv_with_uid, getpwnam | '
        'vuln: UID comparison result may be logged but not enforced as reject'
    ),
    'header_oob_read': (
        'HTTP header parser | calls: strlen, strncmp | '
        'vuln: pointer advanced by fixed offset without bounds check on input length'
    ),
    'query_string_parse': (
        'URL query parser | calls: g_strsplit, g_uri_unescape_string | '
        'role: safe GLib-based URL decoding'
    ),
    'dbus_value_passthrough': (
        'D-Bus parameter setter | calls: cli_setCustomParam, g_dbus_connection_call | '
        'vuln: caller value passed to D-Bus method without sanitization'
    ),
    'privilege_drop': (
        'daemon initialization | calls: setuid, setgid, getpwnam | '
        'vuln: privilege drop sequence may be incomplete or skippable'
    ),
    'format_string_log': (
        'logging error path | calls: g_log, g_strdup_printf | '
        'vuln: format string passed from user-controlled parameter name or value'
    ),
    'stack_buffer_overflow': (
        'HTTP request line reader | calls: fgets, strcpy, memcpy | '
        'vuln: fixed-size stack buffer receives unbounded network input'
    ),
}


# ---------------------------------------------------------------------------
# Binary helpers
# ---------------------------------------------------------------------------

def _get_text_section(lib_path: str):
    """Return (data_bytes, text_vaddr, text_offset) for the .text section."""
    import subprocess
    result = subprocess.run(
        ['readelf', '-S', '--wide', lib_path],
        capture_output=True, text=True, timeout=10
    )
    text_off = text_va = text_sz = None
    for line in result.stdout.splitlines():
        if ' .text ' in line:
            parts = line.split()
            # readelf -S wide: Name Type Addr Off Size ...
            for i, p in enumerate(parts):
                if p == '.text':
                    try:
                        text_va = int(parts[i + 2], 16)
                        text_off = int(parts[i + 3], 16)
                        text_sz = int(parts[i + 4], 16)
                    except (IndexError, ValueError):
                        pass
                    break
    if text_off is None:
        return None, None, None
    with open(lib_path, 'rb') as f:
        f.seek(text_off)
        return f.read(text_sz), text_va, text_off


def _find_prologues_aarch64(text_data: bytes, text_vaddr: int) -> list:
    """Find aarch64 function starts via stp x29, x30, [sp, #-N]! pattern."""
    starts = []
    for i in range(0, len(text_data) - 4, 4):
        b = text_data[i:i+4]
        # stp x29, x30, [sp, #-N]! — little-endian: b[0]=0xfd, b[1]=0x7b, b[3]=0xa9
        if b[0] == 0xfd and b[1] == 0x7b and b[3] == 0xa9:
            starts.append(text_vaddr + i)
    return starts


def _disasm_function(data: bytes, start_va: int, max_bytes: int = 512):
    """Disassemble up to max_bytes from start_va in data."""
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = False
    # data offset = start_va - section_vaddr; handled by caller passing correct slice
    return list(md.disasm(data, start_va, max_bytes // 4))


# ---------------------------------------------------------------------------
# Per-library semantic sweep
# ---------------------------------------------------------------------------

def _semantic_sweep(lib_path: str, plt_map: dict, known_funcs: dict, model, queries: dict):
    """Run BERT sweep over all prologues in lib_path. Return ranked results per query."""
    text_data, text_va, text_off = _get_text_section(lib_path)
    if text_data is None:
        return {'error': f'Could not parse .text section from {lib_path}'}

    with open(lib_path, 'rb') as f:
        raw = f.read()

    starts = _find_prologues_aarch64(text_data, text_va)
    if not starts:
        return {'error': 'No prologues found'}

    # Build function descriptors
    funcs = []
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = False

    for va in starts:
        file_off = va - text_va + text_off
        chunk = raw[file_off: file_off + 512]
        insns = list(md.disasm(chunk, va))
        asm_lines = [f'{i.mnemonic} {i.op_str}'.strip() for i in insns[:64]]

        # Resolve call targets
        calls = []
        for ins in insns:
            if ins.mnemonic == 'bl':
                try:
                    target = int(ins.op_str.lstrip('#'), 16)
                    sym = plt_map.get(target) or known_funcs.get(target, (None,))[0]
                    if sym:
                        calls.append(sym)
                except ValueError:
                    pass

        name, role = known_funcs.get(va, (f'func_{va:08x}', 'unknown'))
        desc = describe_function(
            name=name,
            role=role,
            call_targets=calls,
            strings=[],
            vuln_notes='',
            asm_lines=asm_lines,
        )
        funcs.append({'va': va, 'name': name, 'calls': calls, 'desc': desc})

    if not funcs:
        return {'error': 'No functions encoded'}

    corpus_vecs = model.encode([f['desc'] for f in funcs], normalize_embeddings=True)

    results = {}
    for qname, qtext in queries.items():
        qvec = model.encode(qtext, normalize_embeddings=True)
        scores = corpus_vecs @ qvec
        top_idx = np.argsort(scores)[::-1][:5]
        results[qname] = [
            {
                'va': hex(funcs[i]['va']),
                'name': funcs[i]['name'],
                'calls': funcs[i]['calls'],
                'score': float(scores[i]),
            }
            for i in top_idx
        ]

    return results


# ---------------------------------------------------------------------------
# Main analyzers
# ---------------------------------------------------------------------------

def analyze_libaxhttp(lib_dir: str, model) -> dict:
    lib = os.path.join(lib_dir, 'libaxhttp.so')
    if not os.path.exists(lib):
        return {'error': f'Not found: {lib}'}

    return {
        'library': 'libaxhttp.so',
        'confirmed_findings': [f for f in FINDINGS if 'AXHTTP' in f['id']],
        'known_functions': {hex(va): info for va, info in AXHTTP_FUNCS.items()},
        'semantic_sweep': _semantic_sweep(lib, AXHTTP_PLT, AXHTTP_FUNCS, model, {
            k: v for k, v in BERT_QUERIES.items()
            if k in ('ipc_uid_auth', 'header_oob_read', 'query_string_parse',
                     'format_string_log', 'stack_buffer_overflow')
        }),
    }


def analyze_libaxparameter(lib_dir: str, model) -> dict:
    lib = os.path.join(lib_dir, 'libaxparameter.so')
    if not os.path.exists(lib):
        return {'error': f'Not found: {lib}'}

    return {
        'library': 'libaxparameter.so',
        'confirmed_findings': [f for f in FINDINGS if 'AXPARAM' in f['id']],
        'known_functions': {hex(va): info for va, info in AXPARAM_FUNCS.items()},
        'semantic_sweep': _semantic_sweep(lib, AXPARAM_PLT, AXPARAM_FUNCS, model, {
            k: v for k, v in BERT_QUERIES.items()
            if k in ('conf_injection', 'dbus_value_passthrough', 'format_string_log',
                     'privilege_drop')
        }),
    }


def analyze_libax_daemon(lib_dir: str, model) -> dict:
    lib = os.path.join(lib_dir, 'libax_daemon.so')
    if not os.path.exists(lib):
        return {'error': f'Not found: {lib}'}

    return {
        'library': 'libax_daemon.so',
        'result': 'NO_FINDING — axsd_set_uid_gid (0x1dc0) implements correct setgid→initgroups→setuid sequence',
        'confirmed_findings': [],
        'semantic_sweep': _semantic_sweep(lib, AXDAEMON_PLT, AXDAEMON_FUNCS, model, {
            k: v for k, v in BERT_QUERIES.items()
            if k in ('privilege_drop', 'ipc_uid_auth', 'format_string_log')
        }),
    }


def analyze_libaxevent(lib_dir: str, model) -> dict:
    lib = os.path.join(lib_dir, 'libaxevent.so')
    if not os.path.exists(lib):
        return {'error': f'Not found: {lib}'}

    return {
        'library': 'libaxevent.so',
        'confirmed_findings': [f for f in FINDINGS if 'AXEVENT' in f['id']],
        'known_functions': {hex(va): info for va, info in AXEVENT_FUNCS.items()},
        'note': (
            'ax_event_element_item_parse_xml (0x9070) passes caller XML string directly to '
            'xmlnode_parse_string with no pre-validation. Zero internal callers — pure API surface. '
            'ax_event_handler_subscribe uses structured declaration API, not XML.'
        ),
        'semantic_sweep': _semantic_sweep(lib, AXEVENT_PLT_KEY, AXEVENT_FUNCS, model, {
            k: v for k, v in BERT_QUERIES.items()
            if k in ('format_string_log', 'ipc_uid_auth')
        }),
    }


def analyze_libvdo(lib_dir: str, model) -> dict:
    lib = os.path.join(lib_dir, 'libvdo.so.1.17')
    if not os.path.exists(lib):
        return {'error': f'Not found: {lib}'}

    return {
        'library': 'libvdo.so.1.17',
        'result': 'NO_FINDING',
        'confirmed_findings': [],
        'note': (
            'BERT sweep: 593 prologue-rooted functions, 5 vulnerability queries. '
            'Top scores all < 0.50. '
            'vdo_map_new_from_variant: strict size guards (cmp x0, #0x20 → b.ne bail). '
            'vdo_fido_extract_buffer: type + min-size checks, no copy. '
            'vdo_read / vdo_read_exactly: standard loop-to-completion wrappers. '
            'Actual attack surface in fido_extract_message (external import).'
        ),
        'semantic_sweep': _semantic_sweep(lib, {}, {}, model, {
            k: v for k, v in BERT_QUERIES.items()
            if k in ('stack_buffer_overflow', 'format_string_log')
        }),
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('lib_dir', help='Path to directory containing AXIS OS platform libs')
    ap.add_argument('--lib', help='Analyze single library by name')
    ap.add_argument('--all', action='store_true', help='Analyze all known libraries')
    ap.add_argument('--out', help='Write JSON results to file')
    ap.add_argument('--findings-only', action='store_true', help='Print confirmed findings only')
    args = ap.parse_args()

    if args.findings_only:
        print(json.dumps(FINDINGS, indent=2))
        return

    print('[*] Loading BERT model...', flush=True)
    model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2', device='cpu')

    results = {}

    if args.all or (args.lib and 'axhttp' in args.lib):
        print('[*] Analyzing libaxhttp.so...', flush=True)
        results['libaxhttp.so'] = analyze_libaxhttp(args.lib_dir, model)

    if args.all or (args.lib and 'axparameter' in args.lib):
        print('[*] Analyzing libaxparameter.so...', flush=True)
        results['libaxparameter.so'] = analyze_libaxparameter(args.lib_dir, model)

    if args.all or (args.lib and 'ax_daemon' in args.lib):
        print('[*] Analyzing libax_daemon.so...', flush=True)
        results['libax_daemon.so'] = analyze_libax_daemon(args.lib_dir, model)

    if args.all or (args.lib and 'axevent' in args.lib):
        print('[*] Analyzing libaxevent.so...', flush=True)
        results['libaxevent.so'] = analyze_libaxevent(args.lib_dir, model)

    if args.all or (args.lib and 'vdo' in args.lib):
        print('[*] Analyzing libvdo.so...', flush=True)
        results['libvdo.so.1.17'] = analyze_libvdo(args.lib_dir, model)

    if not results:
        ap.error('Specify --lib <name> or --all')

    if args.out:
        with open(args.out, 'w') as f:
            json.dump(results, f, indent=2)
        print(f'[+] Results written to {args.out}')
    else:
        print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
