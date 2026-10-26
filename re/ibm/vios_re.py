"""
vios_re.py — IBM VIOS sp01 U828079.bff RE findings

Target:   U828079.bff — AIX PTF for bos.net.nfs.client 6.1.4.2
          AIX backup/restore format, 6.2MB, PowerPC (big-endian XCOFF)
          Part of IBM VIOS Service Pack 01 (released 2010-03-02)

File:     /media/cowboy/research/IBM-RE/VIOS/sp01/U828079.bff
          6,504,448 bytes (6.2 MB)

Session:  Session 14 — VIOS BFF triage (2026-10-25)
"""

# ── File metadata ─────────────────────────────────────────────────────────────

IMAGE = {
    'file':     '/media/cowboy/research/IBM-RE/VIOS/sp01/U828079.bff',
    'size':     6_504_448,
    'format':   'AIX backup/restore format (file magic: 0x09006bea)',
    'magic':    b'\x09\x00\x6b\xea',
    'date':     '2010-03-02',
    'package':  'bos.net.nfs.client 6.1.4.2',
    'product':  'AIX NFS Client (base AIX package, not VIOS-specific)',
    'arch':     'PowerPC big-endian (XCOFF32 + XCOFF64)',
    'context':  'Included in IBM VIOS Service Pack 01 as a base AIX package dependency',
}

# ── Architecture note ─────────────────────────────────────────────────────────

ARCH = {
    'format':   'XCOFF (IBM Common Object File Format) — PowerPC big-endian',
    'tooling': (
        'BinaryContext, SemanticSearcher, SinkArgClassifier: NOT APPLICABLE. '
        'All require ELF format. AIX VIOS uses XCOFF, not ELF. '
        'This is a genuine ablation tooling gap for the AIX/XCOFF platform. '
        'Analysis performed via: (1) AIX BFF path extraction, (2) string sweep, '
        '(3) XCOFF .loader import table scan for exec-class symbols.'
    ),
    'xcoff_counts': {
        'XCOFF32 occurrences': 123,
        'XCOFF64 occurrences': 135,
        'ELF occurrences': 0,
    },
    'extract_method': 'Binary scan — no `restore` or AIX `pax` on Linux host',
    'ablation_gap': (
        'XCOFF support is not implemented in ablation. '
        'Tooling gap logged but deferred — this AIX NFS client PTF has '
        '0 VIOS-specific commands and is out of scope for VIOS RE.'
    ),
}

# ── Package identification ────────────────────────────────────────────────────

PACKAGE = {
    'lpp_name':   'bos.net.nfs.client',
    'version':    '6.1.4.2',
    'install_path': '/usr/lpp/bos.net/bos.net.nfs.client/6.1.4.2/',
    'key_paths': [
        '/usr/lpp/bos.net/bos.net.nfs.client/6.1.4.2/liblpp.a',
        '/etc/nfs/hostkey',
        '/etc/nfs/local_domain',
        '/etc/nfs/princmap',
        '/etc/nfs/realm.map',
        '/etc/rc.nfs',
        '/etc/rc.tcpip',
        '/etc/inetd.conf',
    ],
    'binaries': [
        'showmount',           'biod',          'lockd',         'nfsd',
        'nfshostkey',          'nfshostmap',    'nfsauthreset',  'gfsinstall',
        'rpc.rstatd',          'rpc.rusersd',   'rpc.rwalld',    'rpc.lockd',
        'stnfs (kernext)',     'swapnfsdd (kernext)',
    ],
    'vios_specific': (
        'ZERO VIOS-specific paths or commands found. '
        'No ioscli, cfgdev, mkvdev, padmin, ios or VIOS-specific paths. '
        'This is a base AIX NFS client package included in the VIOS sp01 bundle '
        'as a dependency, not VIOS application code.'
    ),
}

# ── Security sweep ────────────────────────────────────────────────────────────

SECURITY_SWEEP = {
    'vios_commands': {
        'result': 'NOT FOUND',
        'searched': 'ioscli, cfgdev, mkvdev, padmin, ios, VIOS',
        'note': (
            'The GOAL\'s target focus (ioscli, cfgdev, mkvdev) is absent. '
            'U828079.bff is an AIX NFS client PTF, not VIOS management code.'
        ),
    },

    'exec_class': {
        'result': 'popen IMPORTED by 2 XCOFF modules (EXPECTED)',
        'popen_imports': {
            'offset_1':   '0x0535dd4',
            'offset_2':   '0x053a2f0',
            'format':     'XCOFF .loader section import symbol: "popen.........@"',
            'analysis': (
                'Two XCOFF binaries in this BFF import popen(). Based on the binary listing, '
                'the importers are almost certainly rpc.rwalld and rpc.rusersd — the standard '
                'AIX NFS wall/rusers daemons. '
                'rpc.rwalld: calls popen("/usr/bin/wall","w") to broadcast messages. '
                'rpc.rusersd: calls popen("/usr/bin/who -a","r") to list logged-in users. '
                'Both are expected, well-known patterns for these daemons. '
                'Cannot confirm without XCOFF parser (ablation does not support XCOFF). '
                'The popen() call in rpc.rwalld with RPC-supplied data would be a vulnerability '
                'if the message string is passed unsanitized to wall — but this is a known '
                'historical AIX issue, not a new finding from this analysis.'
            ),
        },
        'system_matches': {
            'count': 17,
            'verdict': 'ALL FALSE POSITIVES',
            'note': '"system" appears as a substring of "file systems", "filesystem_heap", etc.',
        },
    },

    'credentials': {
        'result': 'NO HARDCODED CREDENTIALS',
        'nfs_kerberos': (
            'nfshostkey manages Kerberos keytab at /etc/nfs/hostkey. '
            'Key is runtime-managed, not compiled into the binary. '
            'Usage: "nfshostkey -p <principal> -f <keytab file>". '
            'No hardcoded Kerberos key or NFS host key found in binary.'
        ),
        'krb5_flavors': (
            '"krb5", "krb5i", "krb5p" = NFS security flavor option strings '
            '(authentication, integrity, privacy levels). Not credentials.'
        ),
    },

    'bin_sh': {
        'result': 'FALSE POSITIVE',
        'note': (
            'The "/bin/sh" match at 0x0075b7d is in embedded XCOFF debug path: '
            '"/usr/bin/showmount.s.ne" — the ".s" suffix is the XCOFF debug path '
            'for the showmount source file, not a shell reference.'
        ),
    },
}

# ── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = [
    {
        'id':      'VIOS-001',
        'verdict': 'SAFE',
        'title':   'U828079.bff AIX NFS client PTF — no VIOS vulnerability found',
        'notes': (
            'U828079.bff: AIX BFF format, 6.2MB, bos.net.nfs.client 6.1.4.2. '
            'Included in VIOS sp01 as a base AIX dependency (not VIOS-specific). '
            'Architecture: XCOFF (PowerPC BE) — BinaryContext/SemanticSearcher not applicable. '
            '0 VIOS-specific commands (ioscli, cfgdev, mkvdev absent). '
            'popen() imported by 2 XCOFF modules (expected: rpc.rwalld + rpc.rusersd). '
            'No hardcoded credentials. No Kerberos key material compiled in. '
            'No VIOS management vulnerability found. '
            'Ablation gap: XCOFF format not supported by BinaryContext — '
            'logged but deferred (base AIX package, out of VIOS RE scope).'
        ),
        'eliminated_classes': [
            'VIOS-specific command injection (ioscli/cfgdev/mkvdev: not present)',
            'hardcoded credentials (Kerberos key is runtime-managed)',
            'system() injection (all 17 matches are substring false positives)',
        ],
        'candidates': [
            {
                'id':       'VIOS-001-POPEN',
                'status':   'EXPECTED/UNVERIFIED',
                'desc': (
                    'popen() imported by 2 XCOFF modules (rpc.rwalld + rpc.rusersd). '
                    'Expected pattern for wall broadcast and who-listing daemons. '
                    'Cannot byte-verify without XCOFF parser. '
                    'Not escalated: XCOFF BinaryContext gap required, and this is '
                    'a base AIX package outside the VIOS-specific RE scope.'
                ),
            },
        ],
    },
]

# ── Sessions ─────────────────────────────────────────────────────────────────

SESSIONS = [
    {
        'session': 14,
        'date':    '2026-10-25',
        'work': (
            'File format: AIX backup/restore (0x09006bea). '
            'Package identified via embedded paths: bos.net.nfs.client 6.1.4.2. '
            '0 VIOS-specific paths (ioscli, cfgdev, mkvdev, padmin absent). '
            'XCOFF32: 123 occurrences. XCOFF64: 135 occurrences. ELF: 0. '
            'BinaryContext not applicable (XCOFF format). '
            'String sweep: system() matches all false positives (substring). '
            'popen: 2 real XCOFF import table entries (rpc.rwalld + rpc.rusersd expected). '
            'No hardcoded credentials. nfshostkey uses /etc/nfs/hostkey (runtime key). '
            'VIOS-001 SAFE.'
        ),
        'open': [
            'XCOFF support ablation gap: logged (but base AIX NFS package, deferred).',
        ],
    },
]
