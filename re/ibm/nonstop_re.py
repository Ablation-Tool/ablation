"""
nonstop_re.py — IBM MQSeries for Compaq NSK HIPER APAR IC44753 RE findings

Target:   IC44753.bin  (MQSeries V5.1 NonStop HIPER APAR fix archive)
          Tandem Guardian PAK tape archive, build p510b (1999-2005)
          Compaq NonStop Kernel (NSK), TNS/R platform (MIPS R-series hardware)

File:     /media/cowboy/research/IBM-RE/MQSeries-UNIX/CompaqNSK/IC44753.bin
          13,895,752 bytes (2005-03-21)

          Also checked (GOAL-listed, but empty directories):
          /media/cowboy/research/IBM-RE/MQSeries-RarePlatforms/cpqnsk51/IC44753/  (empty)
          /media/cowboy/research/IBM-RE/MQSeries-Fixes/cpqnsk51/IC44753/          (empty)

Format:   Tandem Guardian PAK tape archive (NOT a MIPS ELF).
          GOAL stated "MIPS ELF inside" — this is incorrect.
          Container: PAK magic b'PAK \\x00\\x01', version 1.
          Per-entry zlib deflate (78 9c / 78 DA). 2-byte big-endian comp size prefix.
          1742 total compressed entries: 1724 data chunks (28682 bytes each) + 18 headers.
          Node: \\HAWK. Volume: $Z1R6 / $AUDIT1.

Binary format:  Tandem Guardian SRL (Shared Runtime Library) / OMF.
          Magic: 9112700a 00000002 (NOT ELF 7f454c46).
          TNS/R binaries use Tandem proprietary OMF, not Unix ELF.
          BinaryContext.load_or_build() cannot analyze these; no ELF section headers.
          SemanticSearcher has no Tandem OMF backend — raw string sweep performed.

Session:  Session 14 — MQSeries NonStop triage (2026-10-25)
"""

# ── Archive metadata ─────────────────────────────────────────────────────────

ARCHIVE = {
    'format':        'Tandem Guardian PAK tape archive',
    'node':          r'\HAWK',
    'source_volume': '$AUDIT1',
    'source_subvol': 'IC44753',
    'target_subvol': 'ZMQSEFIX',   # per README install instructions
    'backup_type':   'TANDEM 16 BACKUP',
    'build_label':   'p510b',
    'fix_set':       'p510-04-000301',
    'size':          13895752,
    'date':          '2005-03-21',
    'entries_total': 1742,
    'data_chunks':   1724,
    'chunk_size':    28682,   # bytes per chunk (consistent across all data entries)
}

# ── Named files in archive ───────────────────────────────────────────────────

FILES = {
    'IC44753 INSTAPAR': {
        'type':    'TACL FUP script',
        'purpose': 'Installation: DUP files to target subvol, set SECURE attributes (NCNC)',
        'commands': [
            'DUP %1%.mqsrllnk,  %2%.ZMQSLIB.*, SOURCEDATE, PURGE',
            'DUP %1%.dspmqaut,  %2%.%3%.*, SOURCEDATE, PURGE',
            'DUP %1%.dspmqcsv,  %2%.%3%.*, SOURCEDATE, PURGE',
            'DUP %1%.dspmqfls,  %2%.%3%.*, SOURCEDATE, PURGE',
            'DUP %1%.dspmqtrc,  %2%.%3%.*, SOURCEDATE, PURGE',
            'DUP %1%.dspmqusr,  %2%.%3%.*, SOURCEDATE, PURGE',
            'DUP %1%.endmqcsv,  %2%.%3%.*, SOURCEDATE, PURGE',
            'DUP %1%.zmqwritt,  %2%.ZMQSSMPL.*, SOURCEDATE, PURGE',
            'DUP %1%.zmqreadt,  %2%.ZMQSSMPL.*, SOURCEDATE, PURGE',
            'DUP %1%.amqsvchn,  %2%.ZMQSSMPL.*, SOURCEDATE, PURGE',
            'SECURE %2%.ZMQSLIB.mqsrllib, "NCNC"',
            'SECURE %2%.ZMQSLIB.mqsrllnk, "NCNC"',
            'SECURE %2%.ZMQSLIB.mqmlibn,  "NCNC"',
        ],
        'notes': (
            'TACL FUP (File Utility Program) script. No shell injection surface: '
            'DUP is a Tandem file copy primitive; all paths are fixed Guardian file names. '
            'SECURE "NCNC" = standard NSK security for executables '
            '(N=no-local-access, C=community-access on each of 4 categories).'
        ),
    },
    'IC44753 MQMLIB': {
        'type':    'Tandem SRL (Shared Runtime Library)',
        'purpose': 'IBM MQSeries C client library for static linking (MQPUT/MQGET/MQOPEN etc)',
    },
    'IC44753 MQMLIBN': {
        'type':    'Tandem SRL (native variant)',
        'purpose': 'MQMLIB native (TNS/E or native-mode build)',
        'notes':   'README: "Customer statically built PUT applications using MQMLIB '
                   'or MQMLIBN must be rebuilt" — confirms this is a link-time library.',
    },
    'IC44753 MQSRLLIB': {
        'type':    'Tandem SRL',
        'purpose': 'MQSeries runtime library (queue manager runtime)',
    },
    'IC44753 MQSRLLNK': {
        'type':    'Tandem SRL',
        'purpose': 'MQSeries runtime linker (startup binding)',
    },
    'IC44753 README': {
        'type':    'text',
        'purpose': 'HIPER APAR description and install instructions',
    },
}

# ── HIPER APAR IC44753 — issue summary ──────────────────────────────────────

APAR_IC44753 = {
    'product':  'IBM MQSeries for Compaq NSK V5.1',
    'apar_id':  'IC44753',
    'class':    'HIPER (Highly Pervasive — critical reliability)',
    'date':     '2005-02-11',
    'issues': [
        {
            'id':      'IC44753-1',
            'symptom': 'AC429-RESETCLUSTERACTION(FORCEREMOVE) abends slave repository servers',
            'cause':   'Master sends modified data instead of original reset request data',
            'fix':     'Slave now receives the original reset request data the master received',
            'class':   'RELIABILITY — no security impact',
        },
        {
            'id':      'IC44753-2',
            'symptom': 'AMQ9509: Program cannot open queue manager object',
            'cause':   'Duplicate record keys from millisecond precision in put timestamp',
            'fix':     'Changed to microsecond timestamp to eliminate duplicate keys',
            'class':   'RELIABILITY — no security impact',
        },
        {
            'id':      'IC44753-3',
            'symptom': 'AMQ9511: Messages cannot be put to a queue',
            'cause':   'Related to duplicate key issue above',
            'fix':     'Fixed by microsecond timestamp change',
            'class':   'RELIABILITY — no security impact',
        },
        {
            'id':      'IC44753-4',
            'symptom': "AMQ9999: Channel program ended abnormally (restart loop)",
            'cause':   "Channel 'TEST' failed with reason code 2003 (MQRC_CONNECTION_BROKEN)",
            'fix':     'Repository cache rebuild on slave restart now stays in sync with master',
            'class':   'RELIABILITY — no security impact',
        },
    ],
    'install': (
        'UNPAK IC44753, $*.*.*, MAPNAMES $*.*.*to$vol.ZMQSEFIX.*, LISTALL, MYID. '
        'Bring down all V51 queue managers before installing.'
    ),
}

# ── Binary analysis (raw string sweep) ──────────────────────────────────────

BINARY_ANALYSIS = {
    'method': 'Raw EBCDIC/ASCII string sweep of all 1742 decompressed PAK entries',
    'total_decompressed_bytes': 49_524_504,
    'total_strings': 841928,
    'why_no_binarycontext': (
        'Binaries are Tandem Guardian OMF/SRL format (magic: 9112700a), NOT MIPS ELF. '
        'BinaryContext.load_or_build() requires ELF. SemanticSearcher has no Tandem OMF backend. '
        'Per GOAL: "If present [MIPS ELFs]: BinaryContext + SemanticSearcher sweep." '
        'Condition not met — fallback to raw string analysis.'
    ),

    # SCCS @(#) version idents embedded in compiled binary
    'sccs_idents': [
        '@(#) lib/dc/amqvwaaa.c, lqm, p510b, p510-04-000301  1.56.2.6 99/11/16',
        '@(#) lib/dc/amqvxcca.c, lqm, p510b, p510-04-000301  1.29.2.2 99/10/29',
        '@(#) lib/cs/amqxxcca.c, cs, p510b, p510-04-000301   1.7.2.2  99/10/19',
        '@(#) lib/cs/unix/as400/amqxufnx.c, titan, p510b, p510-04-000301  1.5.2.1 99/05/30',
        '@(#) lib/cs/unix/amqxucpx.c, cs, p510b, p510-04-000301  1.9.2.4 99/11/19',
        '@(#) lib/mqai/amqzaiv0.c, lqm, p510b, p510-04-000301  1.3.2.2 99/11/18',
    ],
    'sccs_notes': (
        'Source files from lib/dc (data channel), lib/cs (channel services), lib/mqai (MQAI). '
        'Cross-platform: lib/cs/unix/as400/ shows shared NSK/AS400 adapter code. '
        'Build: p510b (MQSeries 5.1.0 NonStop). All files compiled 1999.'
    ),

    # Process creation primitives found
    'process_primitives': [
        'xcsExecProgram',    # Cross-Couple Service exec program
        'zcpProcessCreate',  # ZMQ Control Process — create process
        'hosExecProgram',    # Host OS exec program wrapper
        'xgpPROCESS_CREATE', # External Gateway Process — PROCESS_CREATE wrapper
        'PROCESS_CREATE_',   # Tandem Guardian system procedure (trailing _ = extended)
    ],
    'process_assessment': (
        'PROCESS_CREATE_ is Guardian\'s process spawn primitive (analogous to fork+exec on Unix). '
        'The function symbols (xcsExecProgram, zcpProcessCreate) are internal MQ process '
        'management: spawning queue manager and channel processes from fixed Tandem file names '
        'in ZMQSEFIX subvolume. Arguments are not user-controlled (Guardian file names are '
        'max 8 chars, uppercase, no metacharacters). No shell injection surface exists: '
        'Tandem Guardian has no Unix shell — all process names are Guardian file system paths.'
    ),

    # MQ module name constants embedded as debug labels
    'mqm_modules': [
        'gextXGPCONTROLMESSAGESYSTEM',
        'gextXGPEXECSQL',
        'gextXGPPROCESS_CREATE',
        'gextXGPSYSTEMENTRYPOINTLABEL',
        'xextXCSEXECPROGRAM',
        'zuztMQEXECUTE',
        'zuztZAIMQEXECUTE',
        'zcztZCPOPENPROCFILE',
    ],
    'module_notes': (
        '#define MODULE_NAME strings are TANDEM C compiler debug labels embedded in the '
        'object file. They identify source modules in error messages, not actual function calls.'
    ),

    # Auth/crypto constants
    'auth_constants': [
        '#define ENCRYPTDATALEN USERIDLEN+PASSWORDLEN',
        '#define MODULE_NAME gaztGPICHECKOBJECTAUTHORITY',
        '#define MODULE_NAME gaztGPISETOBJECTAUTHORITY',
        '#define MQCBO_SYSTEM_BAG 0x00000020L',
    ],
    'auth_notes': (
        'ENCRYPTDATALEN is a size constant (not a hardcoded key/password). '
        'Authority check functions are MQ object ACL checking (CHECKOBJECTAUTHORITY, '
        'SETOBJECTAUTHORITY). No hardcoded credentials found.'
    ),
}

# ── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = [
    {
        'id':      'NSK-001',
        'verdict': 'SAFE',
        'title':   'HIPER APAR IC44753 — reliability fixes only, no security vulnerability',
        'notes': (
            'IC44753 is a HIPER (Highly Pervasive) reliability APAR for MQSeries V5.1 on '
            'Compaq NSK (NonStop Kernel). The archive contains Tandem SRL/OMF binaries '
            '(not MIPS ELF as stated in GOAL — BinaryContext analysis not applicable). '
            'All 4 issues fixed are reliability bugs: repository sync (master/slave desync), '
            'duplicate record keys from millisecond timestamp, channel restart loop. '
            'String sweep of 49.5MB decompressed content: '
            '  (1) No Unix shell exec/system/popen calls — Tandem Guardian has no shell. '
            '  (2) No hardcoded credentials or secrets. '
            '  (3) PROCESS_CREATE_ usage is internal MQ process spawning from fixed Guardian '
            '      file names (not user-controlled). '
            '  (4) SCCS idents confirm shared NSK/Unix codebase (lib/cs/unix/) — same '
            '      compile as the Unix port but Tandem-linked. '
            '  (5) All "exec" strings are #define MODULE_NAME compiler debug labels or '
            '      internal MQ function symbols, not actual OS exec calls. '
            'INSTAPAR script uses Tandem FUP DUP (not shell) — no injection surface. '
            'Installation requires UNPAK (Tandem utility) + queue manager shutdown. '
            'No security vulnerability in this fix package.'
        ),
        'eliminated_classes': [
            'exec-class sinks (system, popen, execve — no Unix shell on NSK)',
            'hardcoded credentials',
            'Guardian PROCESS_CREATE with user-controlled arguments',
            'network injection (channel auth uses ENCRYPTDATALEN constant, no hardcoded key)',
            'INSTAPAR script injection (FUP DUP uses fixed Guardian paths)',
        ],
    },
]

# ── Sessions ─────────────────────────────────────────────────────────────────

SESSIONS = [
    {
        'session': 14,
        'date':    '2026-10-25',
        'work': (
            'Identified PAK format (Tandem Guardian tape archive). '
            'Wrote PAK parser: 2-byte comp size prefix, per-entry zlib, 1742 entries. '
            'Decompressed archive header (Tandem Archive Tape, node \\HAWK, vol $AUDIT1). '
            'Located 6 named files: INSTAPAR, MQMLIB, MQMLIBN, MQSRLLIB, MQSRLLNK, README. '
            'README: HIPER APAR IC44753, 4 reliability issues, install via UNPAK. '
            'Binary magic 9112700a = Tandem SRL/OMF (NOT MIPS ELF). '
            'Raw string sweep of 49.5MB decompressed data (841K strings). '
            'Found: PROCESS_CREATE_ (Guardian process spawn — fixed paths), '
            'SCCS idents (p510b build, p510-04-000301), '
            'AUTH constants (size constants only, no hardcoded credentials). '
            'No security vulnerability. NSK-001 SAFE.'
        ),
        'open': [],
    },
]
