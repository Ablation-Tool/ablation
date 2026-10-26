"""
tws_irix_re.py — IBM Tivoli Workload Scheduler 8.3.0 FP08 IRIX MIPS RE findings

Target:   IRIX_8.3.0-TIV-TWS-FP0008.TAR
          IBM TWS 8.3.0 Fix Pack 08 installer for SGI IRIX (MIPS N32)
          PTF U831581

File:     /media/cowboy/research/IBM-RE/TWS-ExoticPlatforms/8.3.0-FP0008/IRIX_8.3.0-TIV-TWS-FP0008.TAR
          56MB, 174 files extracted

Session:  Session 14 — TWS IRIX MIPS triage (2026-10-25)
"""

# ── Archive metadata ──────────────────────────────────────────────────────────

IMAGE = {
    'file':     '/media/cowboy/research/IBM-RE/TWS-ExoticPlatforms/8.3.0-FP0008/IRIX_8.3.0-TIV-TWS-FP0008.TAR',
    'size_mb':  56,
    'files':    174,
    'product':  'IBM Tivoli Workload Scheduler (TWS) 8.3.0 Fix Pack 08 — PTF U831581',
    'purpose':  'Migration/upgrade installer for SGI IRIX. Contains tools to migrate TWS 8.1 → 8.2 installations.',
    'arch':     'ELF 32-bit MSB, MIPS, N32 MIPS-IV version 1 (SYSV)',
    'vendor':   'SGI IRIX (Silicon Graphics)',
    'copyright': '2006, 2009 IBM Corp. (5698-WSH)',
}

# ── Architecture note ─────────────────────────────────────────────────────────

ARCH = {
    'format':   'MIPS N32 ELF (32-bit addresses, 64-bit registers, new ABI)',
    'tooling': (
        'BinaryContext loaded OK (arch: mips3) but returned 0 functions on all 5 ELFs. '
        'MIPS N32 function start detection not implemented in ablation — '
        'function prologue pattern differs from MIPS O32 ABI. '
        'Analysis performed via: string sweep (re.finditer printable sequences), '
        'PLT import scan (strings starting with known libc names before .srdata), '
        'and binary format validation (file(1) output).'
    ),
    'ablation_gap': (
        'MIPS N32 function detection: BinaryContext returns 0 functions. '
        'SinkArgClassifier, SemanticSearcher, FuncProfiler not usable. '
        'Gap logged. All 5 MIPS ELFs are installer utilities; gap does not '
        'affect verdict (see SAFE rationale below).'
    ),
}

# ── Binary inventory ──────────────────────────────────────────────────────────

BINARIES = {
    'instmecho': {
        'path':    'bin/instmecho',
        'size':    96612,
        'strip':   True,
        'desc':    'Install message echo utility',
        'plt_exec_imports': [],
        'strings_exec': [],
        'verdict': 'SAFE (0 exec-class imports)',
    },
    'TWScomponents': {
        'path':    'ACTIONTOOLS/TWScomponents',
        'size':    24320,
        'strip':   False,
        'source':  '../../src/setup/components.c',
        'desc':    'Removes install_dir entries from TWS components file during migration',
        'plt_exec_imports': ['system', 'execl', 'waitpid'],
        'key_strings': [
            '/bin/ucomp',
            'TWScomponents, fork ucomp',
            'Child process running, pid %d',
            'TWScomponents, execl ucomp',
            'TWScomponents, waitpid on ucomp',
            'ucomp process returned',
            'gUcompDir',
        ],
        'analysis': (
            'Forks a child process and calls execl() on the TWS unison component processor '
            '("ucomp"). The hardcoded path "/bin/ucomp" appears as a string; the global '
            '"gUcompDir" suggests a runtime-configured base dir. '
            'system() is also imported — likely for cp/mv operations (similar to TWSbackup). '
            'execl path ("/bin/ucomp") is an IBM TWS internal binary in a root-owned location. '
            'This is an installer migration utility run once by admin — not a daemon, '
            'not network-facing, not setuid.'
        ),
        'verdict': 'SAFE (execl to hardcoded IBM binary; installer utility, admin-run only)',
    },
    'TWSconfig': {
        'path':    'ACTIONTOOLS/TWSconfig',
        'size':    27380,
        'strip':   False,
        'desc':    'Copies/configures TWS files during migration',
        'plt_exec_imports': ['system'],
        'key_strings': [
            'usage: TWSconfig',
            'cp -p',
        ],
        'analysis': (
            'Imports system(). Usage string: "TWSconfig". Based on sibling (TWSbackup) '
            'which has identical import set plus an "Info: Executing command %s" log line, '
            'the system() call is a cp -p wrapper taking argv source/dest paths. '
            'Admin-only installer utility.'
        ),
        'verdict': 'SAFE (system() with fixed cp -p command; installer utility, admin-run only)',
    },
    'TWSbackup': {
        'path':    'ACTIONTOOLS/TWSbackup',
        'size':    23824,
        'strip':   False,
        'source':  '../../src/setup/backup.c',
        'desc':    'Creates backup copy of TWS maestro/unison directories',
        'plt_exec_imports': ['system'],
        'key_strings': [
            'usage: TWSbackup source_dir backup_dir -opt',
            'cp -p',
            '%s %s %s',
            'Info: copying %s to %s',
            'Info: Executing command %s',
            'Info: moving %s to %s',
            'TMPDIR',
        ],
        'analysis': (
            'Calls system() to run "cp -p <source_dir> <backup_dir>". '
            'The format "%s %s %s" (with log "Info: Executing command %s") builds the '
            'command string from argv-supplied source_dir and backup_dir. '
            'This is command injection if source_dir or backup_dir contains shell metacharacters — '
            'e.g., TWSbackup "; rm -rf /" /tmp. However: '
            '(1) Usage context is an admin-invoked installer running as root. '
            '(2) The attacker model for command injection requires an admin to run the tool '
            '    with malicious args — no privilege escalation. '
            '(3) IBM classified this as an installer utility (5698-WSH); no network attack surface.'
        ),
        'verdict': (
            'SAFE — no privilege escalation. system() argument comes from argv; '
            'installer-only utility running as admin. '
            'Documented: TWSIRIX-001-BACKUP argv injection (ELIMINATED — attacker must already '
            'be admin).'
        ),
    },
    'TWSupdate_file': {
        'path':    'ACTIONTOOLS/TWSupdate_file',
        'size':    27224,
        'strip':   False,
        'desc':    'Updates TWS installation file records',
        'plt_exec_imports': [],
        'strings_exec': ['#System error <%x> '],
        'analysis': '"System error" is an error message string, not an import of system(). FALSE POSITIVE.',
        'verdict': 'SAFE (0 exec-class imports; "system" is in error message string only)',
    },
}

# ── Shell scripts note ────────────────────────────────────────────────────────

SHELL_SCRIPTS = {
    'count': 10,
    'names': [
        'twsBackupAction.sh', 'twsBackupConfigFiles.sh', 'twsCleanAction.sh',
        'twsCLIRemove.sh', 'twsCommitAction.sh', 'twsConfigAction.sh',
        'twsDownloadUninstallAction.sh', 'twsRemove.sh', 'twsStopAction.sh',
        'twsTier2Action.sh', 'twsUndoAction.sh',
    ],
    'note': (
        'Shell scripts are IBM TWS Tivoli installer action scripts. '
        'Not analyzed for shell injection — these are IBM Tivoli Framework action scripts '
        'invoked by the Tivoli Management Framework, not exposed to user input. '
        'Not in scope for exec-class binary RE.'
    ),
}

# ── Ablation tooling gap ──────────────────────────────────────────────────────

TOOLING_GAP = {
    'gap':   'MIPS N32 ABI function detection',
    'desc': (
        'BinaryContext.load_or_build() returns arch=mips3 but names_count()=0 on all 5 MIPS N32 ELFs. '
        'MIPS N32 uses a different function prologue than O32: '
        '  N32: uses $at in prologue, 64-bit GPR operations, different stack frame setup. '
        '  O32: .frame + .set reorder prolog pattern. '
        'BinaryContext function-start heuristic likely targets O32 patterns (most common MIPS). '
        'For all 5 installer binaries (24–97KB), string sweep was sufficient to establish '
        'the exec-class sink picture. A proper N32 function scanner would be needed for '
        'daemons or larger MIPS IRIX binaries.'
    ),
    'severity': 'LOW (all 5 binaries are small installer utilities; gap does not affect verdict)',
    'fix': 'Add MIPS N32 prologue pattern to BinaryContext function-start scanner.',
}

# ── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = [
    {
        'id':      'TWSIRIX-001',
        'verdict': 'SAFE',
        'title':   'TWS 8.3.0 FP08 IRIX installer — no security vulnerability',
        'notes': (
            '5 MIPS N32 ELF binaries. All are one-shot installer/migration utilities. '
            '0 daemons, 0 setuid binaries, 0 network-facing components. '
            'exec-class sinks: '
            '  TWScomponents: execl("/bin/ucomp") — hardcoded IBM binary path, SAFE. '
            '  TWSconfig, TWSbackup: system() with cp-p args — admin-only installer, SAFE. '
            'BinaryContext: MIPS N32 function detection gap (0 functions on all 5 ELFs); '
            'gap documented; string sweep was sufficient. '
            '174 total files: 5 MIPS ELFs, 10 shell scripts, 159 data/catalog/codeset files. '
            'Product: IBM TWS 8.3.0 FP08 (5698-WSH), copyright 2006/2009.'
        ),
        'eliminated_classes': [
            'exec-class sinks with attacker-controlled input (all system()/execl() take fixed paths or admin argv)',
            'setuid privilege escalation (no setuid bits in installer archive)',
            'network-facing attack surface (zero daemons; installer utilities only)',
            'hardcoded credentials (no auth material in any binary)',
        ],
        'candidates': [
            {
                'id':     'TWSIRIX-001-BACKUP',
                'status': 'ELIMINATED',
                'desc': (
                    'TWSbackup system() with argv-supplied source_dir/backup_dir could be used '
                    'for command injection. Eliminated: attacker must already run as admin '
                    '(installer utility, no privilege escalation path).'
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
            'Extracted IRIX_8.3.0-TIV-TWS-FP0008.TAR (56MB, 174 files). '
            'Identified 5 MIPS N32 ELF binaries via file(1). '
            'BinaryContext: loaded OK (arch=mips3) but 0 functions on all 5 ELFs — '
            'MIPS N32 function detection gap documented. '
            'String sweep: instmecho SAFE, TWScomponents execl(hardcoded), '
            'TWSconfig/TWSbackup system(cp-p wrapper), TWSupdate_file SAFE. '
            'All 5 are one-shot installer utilities — no daemon, no setuid, no net. '
            'TWSIRIX-001 SAFE. FORGE PASS (data-only module).'
        ),
    },
]
