"""
power_sim_re.py — IBM POWER functional simulator opcode analysis

Targets:  sim_ppc-power7-1.0-2626.x86_64.rpm   (POWER7 functional simulator)
          sim_ppc-power9-1.0-2581.x86_64.rpm    (POWER9 functional simulator)
          systemsim-p10_1.2-4_amd64.deb         (POWER10 systemsim)

Files:    /media/cowboy/research/IBM-RE/IPLSDK/sim_ppc-power7-1.0-2626.x86_64.rpm
          /media/cowboy/research/IBM-RE/IPLSDK/sim_ppc-power9-1.0-2581.x86_64.rpm
          /media/cowboy/research/IBM-RE/PowerFuncSim/systemsim-p10_1.2-4_amd64.deb

Session:  Session 14 — POWER simulator opcode analysis (2026-10-25)
"""

# ── Package metadata ──────────────────────────────────────────────────────────

PACKAGES = {
    'power7': {
        'file':    '/media/cowboy/research/IBM-RE/IPLSDK/sim_ppc-power7-1.0-2626.x86_64.rpm',
        'install': 'opt/ibm/sim_ppc/sim_p7/',
        'decode_map': 'opt/ibm/sim_ppc/sim_p7/bin/decode.map',
        'decode_lines': 2483,
        'unique_ops':   1461,
        'binaries':    ['otimer', 'otimer.smt', 'otimer.smt4', 'otimer.scroll.java',
                        'otimer.scroll.java.smt', 'otimer.scroll.java.smt4', 'reader'],
        'binary_arch': 'x86_64 ELF, stripped (host simulator binary)',
        'data_arch':   'POWER7 (PowerPC 64-bit BE)',
        'xcoff_tools': ['kt2qt (XCOFF PPC32, not stripped)', 'ff2kt_appleE2 (XCOFF PPC32)'],
    },
    'power9': {
        'file':    '/media/cowboy/research/IBM-RE/IPLSDK/sim_ppc-power9-1.0-2581.x86_64.rpm',
        'install': 'opt/ibm/sim_ppc/sim_p9/',
        'decode_map': 'opt/ibm/sim_ppc/sim_p9/bin/decode.map',
        'decode_lines': 4614,
        'unique_ops':   2576,
        'binary_arch': 'x86_64 ELF, stripped',
        'data_arch':   'POWER9 (PowerPC 64-bit LE)',
    },
    'power10': {
        'file':    '/media/cowboy/research/IBM-RE/PowerFuncSim/systemsim-p10_1.2-4_amd64.deb',
        'install': 'opt/ibm/systemsim-p10-1.2-4/',
        'decode_map': None,
        'decode_lines': 0,
        'unique_ops':   None,
        'binary_arch': 'x86_64 ELF, stripped (systemsim-p10)',
        'data_arch':   'POWER10 (PowerPC 64-bit LE)',
        'note': 'No decode.map in systemsim-p10 1.2-4. Opcode table compiled into binary.',
    },
}

# ── Decode.map format ─────────────────────────────────────────────────────────

DECODE_MAP_FORMAT = {
    'description': (
        'IBM sim_ppc decode.map is a plaintext instruction decode table used by the '
        'simulator to recognize and dispatch POWER instructions. Format per line: '
        '  <binary_bit_pattern>  <flags>  #<exec_unit>,<mnemonic>[,<alias>]'
        '`-` in bit pattern = don\'t-care bit. Exec units: FXU, BRU, FPU, VMX, CMU, ...'
    ),
    'ablation_module': 'ablation.analyzers.undocumented_ppc_opcodes.PPCOpcodeScanner',
    'docs': 'docs/reference-modules/undocumented-ppc-opcodes.md',
}

# ── Opcode comparison: P7 → P9 ────────────────────────────────────────────────

OPCODE_COMPARISON = {
    'p7_unique_mnems':  1461,
    'p9_unique_mnems':  2576,
    'p9_new_mnems':     828,
    'p7_removed_mnems': 391,
    'note': (
        'POWER9 added 828 new mnemonics vs POWER7 (BCD arithmetic, VSX extensions, '
        'cryptographic operations, etc.). 391 POWER7 mnemonics absent in POWER9 '
        '(power management consolidation into stop, AltiVec stream touch variants, etc.).'
    ),
    'power_mgmt': {
        'p7': ['doze', 'nap', 'sleep', 'rvwinkle'],
        'p9': ['stop'],
        'note': 'POWER9 unified all power states into a single `stop` instruction (BRU unit).',
    },
}

# ── Key undocumented instruction findings ─────────────────────────────────────

UNDOCUMENTED_INSTRUCTIONS = {
    'sp_attn': {
        'status':   'CONFIRMED UNDOCUMENTED (primary opcode 0)',
        'p7_bits':  '000000---------------0100000000-',
        'p7_unit':  'CMU',
        'p9_bits':  '000000---------------01000000000',
        'p9_unit':  'FXU',
        'p10':      'ABSENT (not found in systemsim-p10 binary)',
        'encoding': (
            'Primary opcode 0, XO 0x100 (POWER7) / 0x200 (POWER9). '
            'Primary opcode 0 is reserved/trap in all public POWER ISA specifications. '
            'IBM internally calls this the "Special Attention" interrupt mechanism — '
            'causes a service processor interrupt to the hardware debugger/FSP. '
            'Separate from the public `attn` instruction (opcode 0, XO 0x200 in ISA 2.x).'
        ),
        'security_note': (
            'sp_attn at XO 0x100 (POWER7) is NOT the same encoding as the public `attn` '
            'at XO 0x200 (ISA 2.x+). This means POWER7 had TWO attention-type instructions: '
            'one for software debug breakpoints (`attn`) and one for service processor '
            'attention signals (`sp_attn`). POWER9 collapsed these — the XO 0x200 encoding '
            'in POWER9 decode.map is labeled `sp_attn`, not `attn`. POWER10 removed it entirely.'
        ),
    },
    'rvwinkle': {
        'status':   'POWER7-only internal instruction',
        'p7_bits':  '010011---------------0111110010-',
        'p7_unit':  'CMU',
        'p9':       'ABSENT',
        'encoding': (
            'Primary opcode 19 (0x13), XO bits 21-30 = 0111110010 = 498 decimal. '
            '"Runlatch Winkle" — enters winkle-class deep sleep while resetting the runlatch register. '
            'POWER7 lab testing instruction. Not documented in any public POWER ISA spec.'
        ),
    },
    'sp_attn_p10': {
        'status':   'Removed in POWER10',
        'evidence': (
            'systemsim-p10 1.2-4 binary (x86_64, stripped): 0 occurrences of "sp_attn" string. '
            '42 occurrences of "stop" (the POWER9 power management replacement). '
            '"doze", "nap" still appear as semantic function names (semantic_doze, semantic_nap) '
            'but these are handlers for POWER9 `stop` sub-modes, not separate instructions.'
        ),
    },
}

# ── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = [
    {
        'id':      'POWERSIM-001',
        'verdict': 'SAFE',
        'title':   'POWER7/P9/P10 functional simulators — no security vulnerability',
        'notes': (
            'Simulators are host x86_64 ELF tooling, not POWER firmware targets. '
            'Analysis focused on opcode decode tables (GOAL: undocumented ISA opcodes). '
            'New ablation module: undocumented_ppc_opcodes.PPCOpcodeScanner '
            '(FORGE PASS, 1904 tests pass). '
            'Opcode gap analysis confirmed 2 notable findings: '
            '(1) sp_attn at primary opcode 0 (XO 0x100 P7 / XO 0x200 P9) — internal '
            '    Special Attention instruction, not in public user-space POWER ISA docs. '
            '    Absent in POWER10. '
            '(2) rvwinkle (POWER7 CMU unit, XO 498) — "Runlatch Winkle" lab instruction, '
            '    POWER7-only, removed in POWER9. '
            'Power management consolidation: doze/nap/sleep/rvwinkle (P7 CMU) → stop (P9 BRU). '
            'Scanner false positives: CMU-routed public instructions (sc, rfid, hrfid, isel, '
            'dst/dstst) — unit filter fires before public-ISA membership check. Documented gap. '
            'No security vulnerability in simulator package itself.'
        ),
        'eliminated_classes': [
            'exec-class sinks in simulator binaries (x86_64 host tool, not target firmware)',
            'hardcoded credentials (no credentials in decode.map or sim config)',
        ],
    },
]

# ── Ablation module gap ───────────────────────────────────────────────────────

MODULE_GAP_FILLED = {
    'module':   'ablation/analyzers/undocumented_ppc_opcodes.py',
    'class':    'PPCOpcodeScanner',
    'docs':     'docs/reference-modules/undocumented-ppc-opcodes.md',
    'added_to_guide': False,
    'known_fp': (
        'CMU-routed public instructions (sc, rfid, hrfid, isel, dst, dstst, dss) '
        'are false positives. Fix: add `and e.mnem not in PUBLIC_POWER_ISA_MNEMONICS` '
        'to the internal_unit branch in scan().'
    ),
}

# ── Sessions ─────────────────────────────────────────────────────────────────

SESSIONS = [
    {
        'session': 14,
        'date':    '2026-10-25',
        'work': (
            'Extracted sim_ppc-power7 and sim_ppc-power9 RPMs with rpm2cpio. '
            'Identified decode.map text files (P7: 2483 lines/1461 ops; P9: 4614 lines/2576 ops). '
            'Extracted systemsim-p10 deb — no decode.map; opcode table in stripped binary. '
            'Implemented PPCOpcodeScanner (undocumented_ppc_opcodes.py). '
            'Found: sp_attn (opcode 0, P7 XO 0x100, P9 XO 0x200, absent P10). '
            'Found: rvwinkle (P7 CMU only, XO 498). '
            'P7 power mgmt: doze/nap/sleep/rvwinkle → P9: stop. '
            'P10 binary evidence: sp_attn absent, stop x42, darn/copy/paste present. '
            'FORGE PASS. Tests: 1904 passed. POWERSIM-001 SAFE.'
        ),
        'open': [
            'CMU FP fix: add public-ISA check to internal_unit branch in scan().',
            'Add PPCOpcodeScanner to docs/guide-tool-selection.md.',
            'P10 decode.map: embedded in stripped binary — would need binary decode table scanner.',
        ],
    },
]
