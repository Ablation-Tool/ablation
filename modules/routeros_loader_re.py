"""
RouterOS 7.24.2 — /nova/bin/loader RE module
Binary: loader (84KB, x86-32 ELF stripped, dynamically linked)
SHA path: ~/mikrotik-re/bins/loader

Role: Nova bus supervisor and module launcher. Forks child daemons,
PTRACE_ATTACHes for crash monitoring, re-execs failed daemons, enforces
nv::policies on incoming Nova bus messages.

PLT imports (security-relevant):
  strcpy@plt         : 0x804c320  — 1 call site (sockaddr_un, CLEAN)
  execl@plt          : 0x804c890  — 2 call sites
  ptrace@plt         : 0x804cc70  — 5 call sites (supervisor pattern)
  nv::findFile       : 0x804c2c0  — used before dynamic execl
  nv::policies::is_allowed   : 0x804c8d0
  nv::policies::add_policy   : 0x804c500
  nv::getMainPartSize        : 0x804cb50  (embedded symbol)
  bind@plt           : 0x804c560  — after strcpy/sockaddr_un setup
  waitpid@plt        : 0x804c5f0  — supervisor child wait
  nanosleep@plt      : 0x804ca60  — sleep between ptrace retries

Nova path strings:
  /nova/bin/           — module prefix (hardcoded in findFile path build)
  /rw/logs/critical_program_crash
  /rw/logs/prev.catlog

Policy IDs registered (add_policy at 0x8053f24+):
  0x1, 0x2, 0x40 — base management channels
  0xfe0002, 0xfe0003, 0xfe0004, 0xfe0005, 0xfe0006 — maintenance ops (0xfe prefix = system-level)
  0x400, 0x401 — additional privileged channels
  All with permission mask 0x80000000

ptrace request codes observed:
  0x10 (16) = PTRACE_ATTACH   — attach to child daemon for monitoring
  0x07 (7)  = PTRACE_CONT     — resume child after signal delivery

No stack canary (__stack_chk_fail absent from PLT)

----- FINDINGS SUMMARY -----
MTIK-LOAD-F01 MEDIUM 5.5  Dynamic execl via nv::findFile — Nova-influenced module path
MTIK-LOAD-F02 MEDIUM 5.3  Policy bypass: nv::policies::is_allowed has no cryptographic binding
MTIK-LOAD-F03 LOW    3.7  ptrace supervisor — race window between fork and PTRACE_ATTACH
MTIK-LOAD-F04 INFO   0.0  strcpy at 0x8053d1f — rodata source, sockaddr_un path — CLEAN
MTIK-LOAD-F05 INFO   0.0  execl at 0x8056f94 — all rodata args — CLEAN
"""

# ---------------------------------------------------------------------------
# Call site analysis
# ---------------------------------------------------------------------------

EXECL_SITES = [
    {
        'va':      0x8050a93,
        'risk':    'CANDIDATE',
        'path_source': 'nv::findFile result at 0x8050a73; input built via string::append from Nova config',
        'execl_args':  'execl(path, path, NULL) — argv[0] = argv[1] = result of findFile',
        'prefix_enforced': '/nova/bin/ (hardcoded in path build before findFile call)',
        'detail': (
            'The path passed to execl is the result of nv::findFile, which resolves a module name '
            'to a full filesystem path. The name component is built via string::append from '
            'Nova-sourced config data. Because findFile prepends /nova/bin/, the exec is '
            'constrained to existing binaries in that directory. The squashfs mount of /nova/bin/ '
            'is read-only in normal operation, limiting practical exploitation to: '
            '(a) a writable /nova/bin/ (e.g., squashfs remount, developer mode), or '
            '(b) a Nova message that redirects findFile to resolve outside /nova/bin/ via '
            'a malformed path component (path traversal in the name string).'
        ),
    },
    {
        'va':      0x8056f94,
        'risk':    'CLEAN',
        'path_source': 'push $0x805aba6 — rodata literal',
        'execl_args':  'execl(path, path, path, NULL) — all rodata',
        'context': 'Bootstrap re-exec after close(3..0x400) fd cleanup loop',
    },
]

STRCPY_SITES = [
    {
        'va':      0x8053d1f,
        'risk':    'CLEAN',
        'dest':    'lea -0x1016(%ebp) — sockaddr_un.sun_path (2 bytes after sa_family at -0x1018)',
        'source':  'push $0x805b174 — rodata literal (same string used in unlink() just before)',
        'context': 'Unix domain socket bind — Nova IPC socket setup: unlink, bind, listen',
        'frame_depth': '> 0x1018 bytes',
    },
]

PTRACE_SITES = [
    {
        'va':      0x80557be,
        'request': 0x10,
        'request_name': 'PTRACE_ATTACH',
        'pid_arg': '%edi (child pid)',
        'detail':  'Supervisor: attach to child daemon after fork/exec; enables crash signal capture',
    },
    {
        'va':      0x80557f2,
        'request': 0x07,
        'request_name': 'PTRACE_CONT',
        'pid_arg': '%edi',
        'sig_arg': '%eax (signal from waitpid status)',
        'detail':  'Supervisor: resume child after signal processing',
    },
    {
        'va':      0x80558cf,
        'request': 'unknown',
        'detail':  'Additional ptrace operation in supervisor loop',
    },
    {
        'va':      0x8055921,
        'request': 'unknown',
        'detail':  'Additional ptrace operation in supervisor loop',
    },
    {
        'va':      0x805594f,
        'request': 'unknown',
        'detail':  'Additional ptrace operation in supervisor loop',
    },
]

POLICY_REGISTRATION = {
    'add_policy_va':   0x804c500,
    'is_allowed_va':   0x804c8d0,
    'registration_fn': 0x8053f24,
    'permission_mask': 0x80000000,
    'policy_entries': [
        {'msg_type': 0x00000001, 'mask': 0x80000000},
        {'msg_type': 0x00000002, 'mask': 0x40},
        {'msg_type': 0x00fe0002, 'mask': 0x80000000},
        {'msg_type': 0x00fe0004, 'mask': 0x80000000},
        {'msg_type': 0x00fe0003, 'mask': 0x80000000},
        {'msg_type': 0x00fe0005, 'mask': 0x80000000},
        {'msg_type': 0x00fe0006, 'mask': 0x80000000},
        {'msg_type': 0x00000400, 'mask': 0x80000000},
        {'msg_type': 0x00000401, 'mask': 0x80000000},
    ],
    'note': 'is_allowed enforces these at runtime; bypass requires spoofed message type IDs from any authorized Nova socket',
}

SUPERVISOR_LOOP = {
    'description': (
        'loader forks child daemons and PTRACE_ATTACHes (request=0x10) to monitor them. '
        'After SIGSTOP acknowledgement, it resumes with PTRACE_CONT (request=0x7) passing '
        'the original signal. waitpid status parsing at 0x80557cb: '
        '  WIFEXITED → log crash to /rw/logs/critical_program_crash; restart '
        '  WIFSIGNALED(19/SIGSTOP) → benign, continue '
        'The supervisory attach happens in a nanosleep retry loop (0x80557a9), meaning '
        'there is a window between fork() and PTRACE_ATTACH during which the child runs '
        'unmonitored and could race to SIGKILL itself or its parent.'
    ),
    'restart_log': '/rw/logs/critical_program_crash',
    'catlog':      '/rw/logs/prev.catlog',
}

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

FINDINGS = [
    {
        'id':             'MTIK-LOAD-F01',
        'severity':       'MEDIUM',
        'cvss':           5.5,
        'title':          'Dynamic execl via nv::findFile — Nova-influenced module path (0x8050a93)',
        'detail': (
            'The loader calls execl with a path resolved by nv::findFile, where the filename '
            'component is assembled via string::append from Nova configuration data. '
            'The base prefix /nova/bin/ is prepended before findFile resolution, constraining '
            'exec targets to that directory. In normal operation /nova/bin/ is read-only (squashfs). '
            'Two attack paths remain: '
            '(1) If a Nova message can inject a path traversal component (e.g., "../../../tmp/evil") '
            'into the name string before append, findFile might resolve outside /nova/bin/. '
            '(2) In developer mode or after a squashfs remount, /nova/bin/ becomes writable; '
            'a controlled module name then directly controls the exec target. '
            'No sanitization of the module name string (e.g., path component stripping, '
            'canonicalization) was observed before the findFile call.'
        ),
        'evidence': {
            'execl_va':      '0x8050a93',
            'findfile_va':   '0x8050a73',
            'findfile_sym':  'nv::findFile(string const&, bool)',
            'prefix':        '/nova/bin/',
            'path_build_va': '0x8050a64',
        },
        'recommendation': (
            'Sanitize module name strings at the Nova message consumption point: '
            'reject any name containing "/" or "..". '
            'Add an absolute-path canonicalization check after findFile returns: '
            'confirm the resolved path starts with /nova/bin/ before execl. '
            'Enforce /nova/bin/ mount as read-only at the kernel/initramfs level.'
        ),
        'status': 'UNCONFIRMED — requires trace of Nova message name string input',
        'cve': None,
    },
    {
        'id':             'MTIK-LOAD-F02',
        'severity':       'MEDIUM',
        'cvss':           5.3,
        'title':          'nv::policies::is_allowed — policy enforcement without cryptographic binding',
        'detail': (
            'The loader registers 9 Nova bus policies at startup (0x8053f24+) then calls '
            'nv::policies::is_allowed(message) to gate privileged operations (module load, '
            'policy change, maintenance ops in 0xfe0000 range). '
            'Policy enforcement relies on message type IDs and source socket identity, but '
            'Nova bus has no inter-daemon authentication (confirmed in MTIK-NOVA-F03: libumsg.so). '
            'Any daemon registered on the Nova bus can send a message with type ID 0x1 or 0x2 '
            '(the two lowest-ID policies; 0x2 has permission mask 0x40 suggesting a less-privileged '
            'channel). The 0xfe00xx maintenance messages require mask 0x80000000, which may be '
            'restricted to a specific socket identity — but without HMAC or signing on messages, '
            'a compromised daemon at any permission level can spoof the message type field.'
        ),
        'evidence': {
            'is_allowed_va': '0x804c8d0',
            'add_policy_va': '0x804c500',
            'policy_ids':    [0x1, 0x2, 0xfe0002, 0xfe0003, 0xfe0004, 0xfe0005, 0xfe0006, 0x400, 0x401],
            'nova_auth':     'NONE (confirmed MTIK-NOVA-F03)',
        },
        'recommendation': (
            'Nova bus policy enforcement needs a cryptographic layer: '
            'sign privileged messages at the source daemon (e.g., HMAC with a per-boot secret), '
            'verify at is_allowed time. '
            'Short-term: restrict loader socket (AF_UNIX path at /rw/... or /nova/...) to root-owned, '
            'mode 0600, so only processes running as root can connect.'
        ),
        'status': 'CONFIRMED (architectural) — no crypto in Nova bus message format',
        'cve': None,
    },
    {
        'id':             'MTIK-LOAD-F03',
        'severity':       'LOW',
        'cvss':           3.7,
        'title':          'ptrace supervisor race — window between fork() and PTRACE_ATTACH',
        'detail': (
            'The supervisor loop forks a child daemon, then calls PTRACE_ATTACH (0x10) after '
            'a nanosleep retry at 0x80557a9. There is a race window between fork() and the attach: '
            'the child process runs without ptrace supervision during this window. '
            'If a child daemon receives SIGKILL during this window (e.g., from an OOM killer), '
            'the loader\'s waitpid at 0x8056fba will observe the killed child without ptrace data '
            'and may incorrectly log it as a crash without the crash context. '
            'More concerning: if an attacker can trigger a controlled child crash during this window '
            '(e.g., via a Nova message that causes the child to abort), the crash handler at '
            '/rw/logs/critical_program_crash logs the event before restart — creating a log injection '
            'primitive if the crash message includes attacker-controlled strings.'
        ),
        'evidence': {
            'ptrace_attach_va': '0x80557be',
            'nanosleep_va':     '0x80557a9',
            'waitpid_va':       '0x8056fba',
            'crash_log':        '/rw/logs/critical_program_crash',
        },
        'recommendation': (
            'Use PTRACE_SEIZE (request=0x4206) + PTRACE_INTERRUPT instead of PTRACE_ATTACH '
            'to avoid the SIGSTOP race. '
            'Alternatively, use PR_SET_CHILD_SUBREAPER + clone(CLONE_PTRACE) at fork time. '
            'Sanitize module name/crash context before writing to /rw/logs/.'
        ),
        'status': 'UNCONFIRMED — timing-dependent; requires controlled environment',
        'cve': None,
    },
    {
        'id':             'MTIK-LOAD-F04',
        'severity':       'INFO',
        'cvss':           0.0,
        'title':          'strcpy at 0x8053d1f — rodata source, sockaddr_un.sun_path — CLEAN',
        'detail': (
            'strcpy(sun_path, $0x805b174): source is a rodata literal (confirmed by immediate push). '
            'Destination is sockaddr_un.sun_path at -0x1016(%ebp), 2 bytes after sa_family. '
            'Same rodata address used in unlink() call immediately before the bind. '
            'CLEAN — no user-controlled data in source.'
        ),
        'evidence': {
            'va':     '0x8053d1f',
            'source': 'push $0x805b174 (rodata)',
            'dest':   'lea -0x1016(%ebp) = sockaddr_un.sun_path',
            'bind_va': '0x8053d36',
        },
        'recommendation': 'No action required.',
        'status': 'CLEAN',
        'cve': None,
    },
    {
        'id':             'MTIK-LOAD-F05',
        'severity':       'INFO',
        'cvss':           0.0,
        'title':          'execl at 0x8056f94 — all rodata args, bootstrap re-exec — CLEAN',
        'detail': (
            'execl(0x805aba6, 0x805aba6, 0x805aba3, 0x805ab8e, 0) — all four arguments are '
            'rodata immediates. Context: close(3..0x400) fd cleanup loop followed by execl. '
            'This is the bootstrap re-exec path where loader restarts itself with a clean '
            'file descriptor table. CLEAN — no attacker influence.'
        ),
        'evidence': {
            'va':     '0x8056f94',
            'arg1':   'push $0x805aba6 (rodata)',
            'close_loop': 'close(fd) for fd in range(3, 0x400)',
        },
        'recommendation': 'No action required.',
        'status': 'CLEAN',
        'cve': None,
    },
]
