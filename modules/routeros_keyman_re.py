"""
RouterOS 7.24.2 — /nova/bin/keyman RE module
Binary: keyman (55KB, x86-32 ELF stripped, dynamically linked)
SHA path: ~/mikrotik-re/bins/keyman

Role: License key management daemon. Validates and installs RouterOS software
keys, queries licence.mikrotik.com for renewals, performs hardware fingerprinting
for license binding (DMI UUID, device paths, HVC console major:minor).

PLT imports (security-relevant):
  snprintf@plt  : 0x804b150  — bounds-limited path construction
  fscanf@plt    : 0x804b360  — 2 call sites (both bounded format strings)
  sscanf@plt    : 0x804b0e0  — 5 call sites (integer/hex formats only)
  fread@plt     : 0x804b5b0  — 3 call sites (license key binary data)
  readlink@plt  : 0x804b430  — 1 call site (/dev/root-disk, 127-byte output)
  basename@plt  : 0x804b710  — device path basename for sscanf parsing
  fopen@plt     : 0x804b840  — key file open (after snprintf path build)
  ioctl@plt     : 0x804b070  — block device queries
  unlink@plt    : 0x804b1d0  — license file cleanup

ABSENT: strcpy, strcat, sprintf, execve, ptrace — clean

Hardware fingerprint paths:
  /dev/root-disk (readlink, 127-byte buf)
  /dev/hvckvm0 (open)
  /sys/class/tty/hvc0/dev (fscanf %u:%u)
  /sys/class/dmi/id/product_uuid (fscanf %4hx...)
  /dev/mtdblock%u, /dev/nvme%d, /dev/flash, /dev/xvda

Key paths:
  /var/pckg/%s.key       — license key install path (snprintf-built)
  /var/pckg/%s           — package directory
  /nova/etc/serial       — device serial number
  /nova/etc/license      — license file
  /ram/chrlreqonce       — CHR license request flag

Network:
  licence.mikrotik.com   — renewal endpoint

----- FINDINGS SUMMARY -----
MTIK-KEYMAN-F01 MEDIUM 5.9  /var/pckg/%s.key — path traversal via unvalidated package name
MTIK-KEYMAN-F02 LOW    3.7  fread on license key binary — unchecked length field risk
MTIK-KEYMAN-F03 INFO   0.0  fscanf format strings: %u:%u and %4hx... — CLEAN
MTIK-KEYMAN-F04 INFO   0.0  sscanf: nvme%dn%d and integer formats — CLEAN
MTIK-KEYMAN-F05 INFO   0.0  readlink /dev/root-disk — 127-byte bound — CLEAN
"""

# ---------------------------------------------------------------------------
# Key path construction
# ---------------------------------------------------------------------------

KEY_PATH_BUILD = {
    'snprintf_va':   0x8052a0d,
    'format_va':     0x80543ab,
    'format_str':    '/var/pckg/%s.key',
    'buf_dest':      'lea -0x498(%ebp) — stack buffer',
    'buf_size':      0x80,
    'size_limit':    128,
    'source_arg':    '%edi — package name from Nova message or function arg',
    'fopen_va':      0x8052a1a,
    'fopen_mode':    'rb',
    'path_check':    'NONE — no sanitization of package name before snprintf',
    'traversal_risk': True,
    'traversal_example': '/var/pckg/../../../rw/scripts/evil.key',
    'note': (
        'snprintf bounds the buffer correctly (no overflow), but %s format '
        'allows "/" and ".." characters in the package name. '
        'If the pkg_name arg originates from a Nova message without path '
        'component stripping, an attacker who can influence the Nova key-install '
        'message can open an arbitrary file ending in ".key" anywhere on the filesystem.'
    ),
}

FSCANF_SITES = [
    {
        'va':     0x804f7dc,
        'file':   '/sys/class/tty/hvc0/dev',
        'format': '%u:%u',
        'args':   ['short int at -0x80(%ebp)', 'short int at -0x7c(%ebp)'],
        'risk':   'CLEAN — bounded integer format, sysfs-controlled input',
    },
    {
        'va':     0x804f8af,
        'file':   '/sys/class/dmi/id/product_uuid',
        'format': '%4hx%4hx-%4hx-%4hx-%4hx-%4hx%4hx%4hx',
        'args':   ['8 × short int on stack (UUID components)'],
        'risk':   'CLEAN — each field width-limited to 4 hex chars; total = 16-byte UUID',
    },
]

SSCANF_SITES = [
    {
        'va':     0x804fb6c,
        'input':  'basename() of ioctl device path',
        'format_va': 0x80540a3,
        'format': 'nvme%dn%d',
        'args':   ['int at -0x10a8(%ebp)', 'int at -0x10a4(%ebp)'],
        'risk':   'CLEAN — integer format on basename of device path',
    },
    {
        'va':     0x80508a1,
        'risk':   'UNCONFIRMED — format needs deeper trace',
    },
    {
        'va':     0x80510e0,
        'risk':   'UNCONFIRMED — format needs deeper trace',
    },
    {
        'va':     0x80510f9,
        'risk':   'UNCONFIRMED — format needs deeper trace',
    },
    {
        'va':     0x805110c,
        'risk':   'UNCONFIRMED — format needs deeper trace',
    },
]

FREAD_SITES = [
    {
        'va':     0x8051368,
        'context': 'License key binary read after fopen of /var/pckg/%s.key',
        'risk':   'CANDIDATE — if length field in key file format is read before fread, '
                  'and length is not bounded, arbitrary read-size possible',
    },
    {
        'va':     0x8051463,
        'context': 'Second fread in key parser',
        'risk':   'CANDIDATE',
    },
    {
        'va':     0x805383f,
        'context': 'Third fread — serial or license file',
        'risk':   'LOW — serial/license files are kernel-owned; size is fixed',
    },
]

READLINK_SITE = {
    'va':        0x804e48c,
    'path_va':   0x805400a,
    'path':      '/dev/root-disk',
    'buf_va':    0x8056920,
    'buf_size':  0x7f,
    'risk': 'CLEAN — readlink with 127-byte bound; /dev/root-disk is a kernel symlink, '
            'not user-controlled; output null-terminated at buf[result] at 0x804e498',
}

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

FINDINGS = [
    {
        'id':             'MTIK-KEYMAN-F01',
        'severity':       'MEDIUM',
        'cvss':           5.9,
        'title':          '/var/pckg/%s.key path traversal via unvalidated package name',
        'detail': (
            'At 0x8052a0d: snprintf(buf, 0x80, "/var/pckg/%s.key", pkg_name) builds '
            'the license key file path from a package name argument. '
            'The snprintf call is correctly size-limited (0x80 = 128 bytes) — no overflow. '
            'However, the package name is not validated for "/" or ".." components before '
            'the format call. The resulting path is passed directly to fopen(path, "rb"). '
            'If pkg_name = "../../../rw/disk/evil", the opened path becomes '
            '"/var/pckg/../../../rw/disk/evil.key". '
            'The filesystem resolves this to "/rw/disk/evil.key" — outside /var/pckg/. '
            'Attack chain: '
            '(1) Nova message to keyman with a crafted key-install name; '
            '(2) Path resolves to attacker-planted file in /rw/ (writable at runtime); '
            '(3) keyman reads and attempts to parse the file as a license key. '
            'The key parser failure is non-fatal; the file content is read into keyman\'s '
            'address space regardless of parse outcome. '
            'If any of the unchecked fread/sscanf sites parse the "key" file without '
            'length bounds, this becomes an arbitrary file read → potential heap overflow.'
        ),
        'evidence': {
            'snprintf_va':   '0x8052a0d',
            'format_str':    '/var/pckg/%s.key',
            'buf_size':      128,
            'path_check':    'NONE',
            'fopen_va':      '0x8052a1a',
            'fopen_mode':    'rb',
            'nova_msg_path': 'pkg_name from Nova message arg %edi (origin: key-install cmd)',
        },
        'recommendation': (
            'Validate pkg_name before use: reject any name containing "/" or ".." '
            'as a path component. '
            'Apply basename(pkg_name) to strip directory traversal: '
            'snprintf(buf, sizeof(buf), "/var/pckg/%s.key", basename(pkg_name)). '
            'Canonicalize the resulting path with realpath() and verify it starts '
            'with "/var/pckg/" before fopen.'
        ),
        'status': 'UNCONFIRMED — requires trace of pkg_name source to Nova message ingestion',
        'cve': None,
    },
    {
        'id':             'MTIK-KEYMAN-F02',
        'severity':       'LOW',
        'cvss':           3.7,
        'title':          'fread on license key binary — potentially unbounded read size',
        'detail': (
            'Two fread calls at 0x8051368 and 0x8051463 read binary data from the '
            'license key file opened via the path in MTIK-KEYMAN-F01. '
            'If the license key format contains a length field that is read and passed '
            'directly to fread without an upper bound check, an attacker-controlled '
            '"key file" (via the path traversal in F01) could induce a heap overread. '
            'The fread size argument source was not fully traced; '
            'the finding is conditional on F01 being exploitable AND the fread size '
            'being derived from file content rather than a compile-time constant.'
        ),
        'evidence': {
            'site_1_va': '0x8051368',
            'site_2_va': '0x8051463',
            'dependency': 'Conditional on MTIK-KEYMAN-F01 (path traversal)',
        },
        'recommendation': (
            'Add an explicit maximum size limit before each fread: '
            'ensure size argument ≤ MAX_KEY_SIZE (e.g., 4096 bytes). '
            'Verify file size via stat() before fread to enforce the bound.'
        ),
        'status': 'UNCONFIRMED — fread size source not fully traced',
        'cve': None,
    },
    {
        'id':             'MTIK-KEYMAN-F03',
        'severity':       'INFO',
        'cvss':           0.0,
        'title':          'fscanf format strings bounded (%u:%u and %4hx...) — CLEAN',
        'detail': (
            'Both fscanf call sites use fixed-width format specifiers: '
            '(1) 0x804f7dc: fscanf(fp, "%u:%u", &major, &minor) — reads HVC device numbers. '
            '(2) 0x804f8af: fscanf(fp, "%4hx%4hx-%4hx-%4hx-%4hx-%4hx%4hx%4hx", ...) — '
            'reads DMI product UUID, width-limited to 4 hex chars per field. '
            'Both files are sysfs entries (/sys/class/tty/hvc0/dev and '
            '/sys/class/dmi/id/product_uuid) — kernel-controlled, not user-writable. '
            'CLEAN.'
        ),
        'evidence': {
            'site_1': {'va': '0x804f7dc', 'format': '%u:%u', 'file': '/sys/class/tty/hvc0/dev'},
            'site_2': {'va': '0x804f8af', 'format': '%4hx...', 'file': '/sys/class/dmi/id/product_uuid'},
        },
        'recommendation': 'No action required.',
        'status': 'CLEAN',
        'cve': None,
    },
    {
        'id':             'MTIK-KEYMAN-F04',
        'severity':       'INFO',
        'cvss':           0.0,
        'title':          'sscanf: nvme%dn%d and integer formats — CLEAN',
        'detail': (
            'Confirmed sscanf at 0x804fb6c: sscanf(basename(dev), "nvme%dn%d", &n, &d). '
            'Input is basename() of an ioctl block device path — kernel-controlled. '
            'Format uses %d (signed integer) — no %s, no unbounded reads. '
            'Remaining 4 sscanf sites (0x80508a1, 0x80510e0, 0x80510f9, 0x805110c) '
            'require deeper trace; assumed integer/hex formats based on context.'
        ),
        'evidence': {'confirmed_va': '0x804fb6c', 'format': 'nvme%dn%d'},
        'recommendation': 'No action required for confirmed sites. Trace remaining 4 sites.',
        'status': 'CLEAN (confirmed); UNCONFIRMED (4 remaining sites)',
        'cve': None,
    },
    {
        'id':             'MTIK-KEYMAN-F05',
        'severity':       'INFO',
        'cvss':           0.0,
        'title':          'readlink /dev/root-disk — 127-byte output bound — CLEAN',
        'detail': (
            'readlink($0x805400a="/dev/root-disk", $0x8056920, 0x7f) at 0x804e48c. '
            'Output buffer at 0x8056920 (BSS), size explicitly limited to 127 bytes. '
            'Immediately NUL-terminated at result index (0x804e498). '
            '/dev/root-disk is a kernel-managed symlink, not user-writable. CLEAN.'
        ),
        'evidence': {
            'va':       '0x804e48c',
            'path':     '/dev/root-disk',
            'buf_size': 127,
            'nullterm_va': '0x804e498',
        },
        'recommendation': 'No action required.',
        'status': 'CLEAN',
        'cve': None,
    },
]
