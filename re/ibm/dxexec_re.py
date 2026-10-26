"""
dxexec_re.py — IBM DataExplorer dxexec RE findings

Target:   dxexec
          DEC Alpha AXP ECOFF, OSF/1 3.11-4
          IBM DataExplorer 3.1.4 (1997)
          6MB stripped executable (no symbols)
          47 886 BSR + 11 435 JSR call sites

Binary:   /media/cowboy/research/IBM-RE/dxexec
          (tmp analysis copy: /tmp/dxexec)

Tool:     AlphaEcoffScanner (ablation.analyzers.insn_alpha)
          Custom module written to fill Alpha ECOFF architecture gap.
          BinaryContext returns arch=x86_64, func_starts=0 on this binary.

Session:  Session 13 — dxexec exec-class sweep (2026-10-25)
"""

# ── Binary structure confirmed ────────────────────────────────────────────────

BINARY_FACTS = {
    'magic':       0x0183,                    # OSF/1 Alpha ECOFF
    'gp_value':    0x1400FC380,
    'entry':       0x120035a90,
    'text_va':     0x120034a30,
    'text_size':   0x4d1900,                  # 5MB
    'text_rawptr': 0x34a30,
    'got_va':      0x1400f4390,
    'got_entries': 4276,
    'dynsym_n':    3103,                      # .hash nchain = 3103; 24-byte Elf64_Sym
    'bsr_total':   47886,
    'jsr_total':   11435,
    'version':     'OSF/1 3.11-4',
    'description': 'IBM DataExplorer 3.1.4 — scientific data visualization',
}

# ── Triage results ────────────────────────────────────────────────────────────

TRIAGE_RESULTS = {
    'remaining': [],   # all exec-class findings triage complete

    # Exec-class functions are STATICALLY LINKED (libc compiled in).
    # They appear in .dynsym as EXPORTED symbols for other DX modules to call.
    # GOT[N] = actual function VA within .text (confirmed via GOT[2921]=0x1202e9550 etc.)
    'exec_class_functions': {
        'system':  {'dynsym_idx': 2921, 'va': 0x1202e9550},
        'execve':  {'dynsym_idx': 2982, 'va': 0x12031f810},
        'popen':   {'dynsym_idx': 2986, 'va': 0x12031f9d0},
        'execlp':  {'dynsym_idx': 3005, 'va': 0x120321860},
    },
}

# ── Findings ──────────────────────────────────────────────────────────────────

FINDINGS = [

    # ── DX-001 ────────────────────────────────────────────────────────────────
    {
        'id':          'DX-001',
        'verdict':     'CANDIDATE MEDIUM',
        'title':       'system() call in DataExplorer application code',
        'function_va': 0x12028d76c,
        'callee_va':   0x1202e9550,   # system()
        'sink':        'system',
        'byte_verify': True,
        'bytes':       b'\x78\x6f\x41\xd3',   # BSR insn word 0xd3416f78 at file_off 0x28bd3c
        'notes': (
            'BSR from 0x12028d76c to system() at 0x1202e9550 (offset in function '
            'containing lda $27, -9384($gp) four instructions prior — standard Alpha '
            'ABI: load callee PV into $27 before BSR). '
            'The function at this VA is in a region 5.8MB into .text — not in the '
            'exec-family libc block (which starts at 0x12031E000+). '
            'This is application-level code calling system(). '
            'Argument construction requires manual trace (what goes into $a0 before BSR). '
            'CANDIDATE pending argument taint analysis.'
        ),
    },

    # ── DX-002 ────────────────────────────────────────────────────────────────
    {
        'id':          'DX-002',
        'verdict':     'ELIMINATED — libc chain call',
        'title':       'execve() callers at 3 sites — all libc-internal wrappers',
        'callers': [
            {'va': 0x12031e128, 'dist_from_execve': 5864},
            {'va': 0x12031ec2c, 'dist_from_execve': 3044},
            {'va': 0x12031fa5c, 'dist_from_execve': 588},
        ],
        'callee_va':  0x12031f810,   # execve()
        'sink':       'execve',
        'notes': (
            'All three BSR callers are within 6KB of execve() at 0x12031f810. '
            'This is the exec-family function cluster in the statically-linked libc: '
            'execl/execle/execv/execvp chain-call execve() internally. '
            'None of these sites are reachable from external (network-facing) input '
            'without first calling one of the exec-family wrappers. '
            'Eliminated as libc-internal implementation artifacts.'
        ),
    },

    # ── DX-003 ────────────────────────────────────────────────────────────────
    {
        'id':          'DX-003',
        'verdict':     'ELIMINATED — libc chain call',
        'title':       'execlp() caller at 1 site — libc wrapper',
        'function_va': 0x12032180c,
        'callee_va':   0x120321860,   # execlp()
        'sink':        'execlp',
        'notes': (
            'BSR at 0x12032180c to execlp() at 0x120321860 (distance: 84 bytes). '
            'Immediately adjacent functions in the exec-family libc block. '
            'Eliminated as libc-internal chain call.'
        ),
    },

    # ── DX-004 ────────────────────────────────────────────────────────────────
    {
        'id':          'DX-004',
        'verdict':     'SAFE — no internal callers',
        'title':       'popen() exported but not called internally',
        'callee_va':   0x12031f9d0,   # popen()
        'sink':        'popen',
        'notes': (
            'popen() is present at 0x12031f9d0 (exported via dynsym[2986]). '
            'Zero BSR callers found in .text. Zero JSR-through-GOT callers found '
            '(scan for ldq $27, -8864($gp) + JSR found no matches). '
            'popen() is exported for use by other DataExplorer shared modules (dx.so etc.) '
            'but is not invoked within dxexec itself. '
            'Marked SAFE for this binary; note for TWS OSF/1 cross-reference (target 20).'
        ),
    },
]

# ── Sessions ──────────────────────────────────────────────────────────────────

SESSIONS = [
    {
        'session': 13,
        'date':    '2026-10-25',
        'work': (
            'Wrote insn_alpha.py (AlphaEcoffScanner) to fill Alpha ECOFF architecture gap. '
            'Confirmed 24-byte OSF/1 Alpha FILHDR (64-bit symptr), 80-byte AOUTHDR, '
            '64-byte section headers. Confirmed Elf64_Sym (24-byte) layout for .dynsym '
            'via .hash nchain=3103 and dynsym.size=0x122f0. '
            'Confirmed GOT[N]=dynsym[N] mapping. '
            'Found 5 exec-class call sites: 1 system (CANDIDATE), '
            '3 execve (ELIMINATED libc chain), 1 execlp (ELIMINATED libc chain), '
            '0 popen (SAFE). '
            'Byte-verified system() caller at 0x12028d76c: bytes d3 41 6f 78, '
            'BSR opcode 0x34, target 0x1202e9550 confirmed. '
            'FORGE gate: PASS. pytest: 1904 passed.'
        ),
        'open': ['DX-001 argument taint trace pending (requires manual WindowAnalyzer on 0x12028d76c)'],
    },
]
