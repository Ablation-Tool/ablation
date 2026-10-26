"""
tws_osf1_re.py — IBM Tivoli Workload Scheduler 8.3.0 FP08 OSF/1 (Tru64) Alpha RE findings

Target:   OSF_8.3.0-TIV-TWS-FP0008.TAR
          IBM TWS 8.3.0 Fix Pack 08 installer for Compaq Tru64 UNIX (OSF/1)
          Alpha AXP architecture, PTF U831581

File:     /media/cowboy/research/IBM-RE/TWS-ExoticPlatforms/8.3.0-FP0008/OSF_8.3.0-TIV-TWS-FP0008.TAR
          64MB, 174 files extracted

Session:  Session 14 — TWS OSF/1 Tru64 Alpha triage (2026-10-25)
"""

# ── Archive metadata ──────────────────────────────────────────────────────────

IMAGE = {
    'file':     '/media/cowboy/research/IBM-RE/TWS-ExoticPlatforms/8.3.0-FP0008/OSF_8.3.0-TIV-TWS-FP0008.TAR',
    'size_mb':  64,
    'files':    174,
    'product':  'IBM Tivoli Workload Scheduler (TWS) 8.3.0 Fix Pack 08 — PTF U831581',
    'purpose':  'Migration/upgrade installer for Compaq Tru64 UNIX (OSF/1, DEC Alpha AXP)',
    'arch':     'DEC Alpha AXP, ECOFF (COFF format alpha demand paged executable), Tru64 UNIX',
    'os':       'Compaq Tru64 UNIX / OSF/1',
    'format':   'COFF alpha demand paged dynamically linked not stripped — version 3.13-14',
}

# ── Cross-reference to tws_irix_re ───────────────────────────────────────────

CROSS_REF = {
    'irix_parallel': (
        'OSF/1 and IRIX tarballs contain the same 5 installer utilities compiled from '
        'the same IBM TWS source tree (src/setup/backup.c, src/setup/components.c). '
        'Source paths match (seen in MIPS IRIX debug info). '
        'Exec-class sink analysis is identical between platforms — same conclusion applies.'
    ),
    'vs_dxexec': (
        'These Alpha binaries use Tru64 ECOFF dynamic linking format. '
        'AlphaEcoffScanner (built for dxexec Alpha AXP) returns 0 findings — '
        'OSF/1 Tru64 ECOFF dynamic linking tables differ from dxexec\'s format. '
        'This is an ablation tooling gap for Tru64 ECOFF (see TOOLING_GAP below). '
        'String sweep confirmed exec-class imports identical to IRIX binaries.'
    ),
}

# ── Architecture / tooling ────────────────────────────────────────────────────

ARCH = {
    'format':   'DEC Alpha AXP ECOFF (Tru64 UNIX / OSF/1)',
    'tooling': (
        'AlphaEcoffScanner (from insn_alpha.py): loaded OK but returned 0 findings. '
        'AlphaEcoffScanner uses .dynsym/.dynstr/.got/.hash ELF-style sections. '
        'Tru64 ECOFF uses different dynamic linking format (not ELF PLT/GOT). '
        'dxexec (also Alpha COFF) produced findings because it uses a different '
        'dynamic linking layout — possibly a hybrid or older COFF+ELF format. '
        'BinaryContext not applicable (ECOFF, not ELF). '
        'Analysis: string sweep confirming exec-class imports from libc dynamic symbol table.'
    ),
}

TOOLING_GAP = {
    'gap':    'Tru64 ECOFF dynamic linking / AlphaEcoffScanner PLT scan',
    'desc': (
        'AlphaEcoffScanner._resolve_exec_sinks() parses ELF section headers (.dynsym, '
        '.dynstr, .got, .hash). Tru64 ECOFF uses different dynamic linking tables: '
        '  - .rdata section contains the dynamic link info (not .dynstr) '
        '  - Import table format differs from ELF PLT stubs '
        'dxexec may have ELF-style sections embedded (unusual) or be a different '
        'variant. Fix: add Tru64 ECOFF .rdata dynamic link table parser to '
        'AlphaEcoffScanner (or a separate EcoffTru64Scanner class).'
    ),
    'severity': 'LOW (all 5 TWS OSF/1 binaries are small installer utilities; '
                'string sweep sufficient to confirm exec-class sink picture)',
}

# ── Binary inventory ──────────────────────────────────────────────────────────

BINARIES = {
    'instmecho': {
        'path':  'bin/instmecho',
        'size':  154240,
        'strip': False,
        'exec_imports': [],
        'verdict': 'SAFE (0 exec-class imports)',
    },
    'TWScomponents': {
        'path':  'ACTIONTOOLS/TWScomponents',
        'size':  28784,
        'strip': False,
        'exec_imports': ['execl', 'system', 'fork'],
        'key_strings': [
            'TWScomponents, fork ucomp',
            'TWScomponents, execl ucomp',
            '/bin/ucomp',
        ],
        'verdict': 'SAFE (execl to hardcoded IBM binary; same pattern as IRIX version)',
    },
    'TWSconfig': {
        'path':  'ACTIONTOOLS/TWSconfig',
        'size':  29232,
        'strip': False,
        'exec_imports': ['system'],
        'verdict': 'SAFE (system(cp-p); admin-only installer; same as IRIX)',
    },
    'TWSbackup': {
        'path':  'ACTIONTOOLS/TWSbackup',
        'size':  28688,
        'strip': False,
        'exec_imports': ['system'],
        'verdict': 'SAFE (system(cp-p argv); admin-only installer; same as IRIX)',
    },
    'TWSupdate_file': {
        'path':  'ACTIONTOOLS/TWSupdate_file',
        'size':  29472,
        'strip': False,
        'exec_imports': [],
        'note':  '"#System error <%x>" is error string, not system() import — false positive',
        'verdict': 'SAFE (0 exec-class imports)',
    },
}

# ── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = [
    {
        'id':      'TWSOSF1-001',
        'verdict': 'SAFE',
        'title':   'TWS 8.3.0 FP08 OSF/1 Tru64 installer — no security vulnerability',
        'notes': (
            '5 DEC Alpha AXP ECOFF binaries. Same IBM TWS installer utilities as IRIX target '
            '(re/ibm/tws_irix_re.py) compiled for Tru64 UNIX. Same exec-class sink pattern. '
            'All one-shot installer/migration utilities — 0 daemons, 0 setuid, 0 network. '
            'AlphaEcoffScanner returned 0 findings (Tru64 ECOFF format vs ELF expectation); '
            'string sweep confirmed exec-class imports (execl, system, fork). '
            'Tru64 ECOFF gap documented (different dynamic linking format than ELF). '
            'No new findings vs IRIX triage — identical source code, different target platform.'
        ),
        'eliminated_classes': [
            'exec-class sinks with attacker-controlled input (same analysis as TWSIRIX-001)',
            'setuid privilege escalation (no setuid in installer archive)',
            'network-facing attack surface (no daemons)',
            'hardcoded credentials (none found)',
        ],
    },
]

# ── Sessions ─────────────────────────────────────────────────────────────────

SESSIONS = [
    {
        'session': 14,
        'date':    '2026-10-25',
        'work': (
            'Extracted OSF_8.3.0-TIV-TWS-FP0008.TAR (64MB, 174 files). '
            'Identified 5 DEC Alpha AXP ECOFF binaries (all not stripped, version 3.13-14). '
            'AlphaEcoffScanner: 0 findings (Tru64 ECOFF dynamic linking != ELF format). '
            'String sweep: identical exec-class pattern to IRIX parallel (same source tree). '
            'Tru64 ECOFF dynamic linking gap documented. '
            'TWSOSF1-001 SAFE. FORGE PASS (data-only module).'
        ),
    },
]
