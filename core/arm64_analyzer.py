#!/usr/bin/env python3
"""
ARM64 Binary Analyzer
Synthesized from:
  ARM 64-Bit Assembly Language (9780128192221) — ch 9-10 (SIMD/NEON, calling conv)
  Foundations of ARM64 Linux Debugging (9781484290828) — ch 10-13 (frames, params)
  Practical Reverse Engineering (9781118787397) — ch 2 (ARM calling conv, BL/BLX)
  Practical Binary Analysis (9781492071204) — ch 2, 7 (GOT/PLT, binary structure)

Covers: AAPCS64 calling convention, function boundary detection, PAC patterns,
        ADRP+ADD string reference resolution, Darwin+Linux syscall detection,
        Swift ABI markers, ObjC msgSend, CFString refs, NEON/SIMD detection,
        stdlib function signature matching, indirect branch target analysis,
        frameless leaf function detection, dead code stripping artifacts.

Key ARM64/Darwin facts encoded here:
  - Function prologue: STP X29, X30, [SP, #-N]! then MOV X29, SP
  - Leaf (frameless): SUB SP, SP, #N only (no STP X29/X30, no outgoing calls)
  - Calling convention: X0-X7 args, X0 return, X19-X28+X29+X30 callee-saved
  - Darwin syscall: X16 = number, SVC #0x80 (NOT SVC #0 like Linux)
  - Linux syscall:  X8  = number, SVC #0
  - PAC: PACIASP/AUTIASP/PACIBSP/AUTIBSP on Apple Silicon
  - ADRP+ADD/LDR: PC-relative addressing for strings and data refs
  - NEON/Advanced SIMD: V0-V31 registers, LD1/ST1 families, UMULL/PMULL
  - Swift: self in X20, error in X21, thick fn ptr = (fn_ptr, context_ptr)
  - ObjC msgSend: BL/BLR to _objc_msgSend; X0=self, X1=SEL
  - Dead code: unreachable basic blocks after unconditional branches/returns
"""

import struct
from pathlib import Path

try:
    from capstone import Cs, CS_MODE_ARM, CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET
    # capstone 6.x renamed CS_ARCH_ARM64 -> CS_ARCH_AARCH64
    try:
        from capstone import CS_ARCH_ARM64
    except ImportError:
        from capstone import CS_ARCH_AARCH64 as CS_ARCH_ARM64
    from capstone.arm64_const import (
        ARM64_REG_X29, ARM64_REG_X30, ARM64_REG_SP,
        ARM64_REG_X8, ARM64_REG_X16, ARM64_REG_X20, ARM64_REG_X21,
        ARM64_REG_XZR, ARM64_REG_WZR,
        ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM,
    )
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    ARM64_REG_X29 = ARM64_REG_X30 = ARM64_REG_SP = None
    ARM64_REG_X8 = ARM64_REG_X16 = ARM64_REG_X20 = ARM64_REG_X21 = None
    ARM64_REG_XZR = ARM64_REG_WZR = None
    ARM64_OP_REG = ARM64_OP_IMM = ARM64_OP_MEM = None


# ── AAPCS64 register names ────────────────────────────────────────────────────
ARG_REGS     = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7']
RETURN_REG   = 'x0'
CALLEE_SAVED = ['x19', 'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26',
                'x27', 'x28', 'x29', 'x30']
FRAME_PTR    = 'x29'
LINK_REG     = 'x30'  # return address register

# Swift-specific register conventions (ARM64 calling convention extension)
SWIFT_SELF_REG  = 'x20'   # 'self' parameter in Swift methods
SWIFT_ERROR_REG = 'x21'   # indirect error return (pointer to Error?)
SWIFT_CONTEXT   = 'x22'   # context pointer for closures/coroutines

# Darwin (macOS) syscall interface — DIFFERS from Linux (x8 / SVC #0)
DARWIN_SYSCALL_REG  = 'x16'    # syscall number register
DARWIN_SVC_IMM      = 0x80     # SVC #0x80 on Darwin (Linux uses SVC #0)
LINUX_SYSCALL_REG   = 'x8'     # Linux ARM64 syscall number register
LINUX_SVC_IMM       = 0        # SVC #0 on Linux

# ── Darwin BSD syscall table (XNU BSD layer, arm64) ──────────────────────────
# Source: xnu bsd/kern/syscalls.master; negative = Mach trap
DARWIN_SYSCALLS = {
    # Core I/O
    1:   'exit',           2:   'fork',           3:   'read',
    4:   'write',          5:   'open',            6:   'close',
    7:   'wait4',          9:   'link',            10:  'unlink',
    12:  'chdir',          13:  'fchdir',          14:  'mknod',
    15:  'chmod',          16:  'chown',           18:  'getfsstat',
    20:  'getpid',         23:  'setuid',          24:  'getuid',
    25:  'geteuid',        26:  'ptrace',          27:  'recvmsg',
    28:  'sendmsg',        29:  'recvfrom',        30:  'accept',
    31:  'getpeername',    32:  'getsockname',     33:  'access',
    34:  'chflags',        35:  'fchflags',        36:  'sync',
    37:  'kill',           39:  'getppid',         41:  'dup',
    42:  'pipe',           43:  'getegid',         46:  'sigaction',
    47:  'getgid',         48:  'sigprocmask',     49:  'getlogin',
    50:  'setlogin',       51:  'acct',            53:  'sigaltstack',
    54:  'ioctl',          55:  'reboot',          56:  'revoke',
    57:  'symlink',        58:  'readlink',        59:  'execve',
    60:  'umask',          61:  'chroot',          65:  'msync',
    66:  'vfork',          73:  'munmap',          74:  'mprotect',
    75:  'madvise',        78:  'mincore',         79:  'getgroups',
    80:  'setgroups',      81:  'getpgrp',         82:  'setpgid',
    83:  'setitimer',      85:  'swapon',          86:  'getitimer',
    89:  'getdtablesize',  90:  'dup2',            92:  'fcntl',
    93:  'select',         95:  'fsync',           96:  'setpriority',
    97:  'socket',         98:  'connect',         100: 'getpriority',
    104: 'bind',           105: 'setsockopt',      106: 'listen',
    111: 'sigsuspend',     116: 'gettimeofday',    117: 'getrusage',
    118: 'getsockopt',     120: 'readv',           121: 'writev',
    122: 'settimeofday',   123: 'fchown',          124: 'fchmod',
    126: 'setreuid',       127: 'setregid',        128: 'rename',
    131: 'flock',         132: 'mkfifo',           133: 'sendto',
    134: 'shutdown',       135: 'socketpair',      136: 'mkdir',
    137: 'rmdir',          138: 'utimes',          139: 'futimes',
    140: 'adjtime',        147: 'setsid',          148: 'getpgid',
    149: 'setprivexec',    150: 'pread',           151: 'pwrite',
    153: 'statfs',         154: 'fstatfs',         155: 'unmount',
    157: 'statfs64',       158: 'fstatfs64',       159: 'getfh',
    165: 'quotactl',       167: 'mount',           169: 'csops',
    170: 'csops_audittoken',
    173: 'waitid',         177: 'add_profil',      178: 'kdebug_typefilter',
    179: 'kdebug_trace_string',
    180: 'kdebug_trace64', 181: 'kdebug_trace',    182: 'setgid',
    183: 'setegid',        184: 'seteuid',         185: 'sigreturn',
    187: 'fdatasync',      188: 'stat',            189: 'fstat',
    190: 'lstat',          191: 'pathconf',        192: 'fpathconf',
    194: 'getrlimit',      195: 'setrlimit',       196: 'getdirentries',
    197: 'mmap',           199: 'lseek',           200: 'truncate',
    201: 'ftruncate',      202: '__sysctl',        203: 'mlock',
    204: 'munlock',        205: 'undelete',
    # Networking extras
    266: 'kqueue',         267: 'kevent',          268: 'lchown',
    274: 'bsdthread_create',
    281: 'pread64',        282: 'pwrite64',        285: 'sendfile',
    286: 'stat64',         287: 'fstat64',         288: 'lstat64',
    289: 'stat64_extended',290: 'lstat64_extended',291: 'fstat64_extended',
    292: 'getdirentries64',293: 'statfs64_d',      294: 'fstatfs64_d',
    303: 'pthread_sigmask',304: 'sigwait',         305: 'disable_threadsignal',
    306: 'pthread_markcancel',307: 'pthread_canceled',308: 'semwait_signal',
    316: 'posix_spawn',    317: 'nfsclnt',         318: 'fhopen',
    320: 'minherit',       324: 'mlockall',        325: 'munlockall',
    326: 'issetugid',      327: 'pthread_kill',    334: 'sigaction_nocancel',
    336: 'read_nocancel',  337: 'write_nocancel',  338: 'open_nocancel',
    339: 'close_nocancel', 340: 'wait4_nocancel',  341: 'recvmsg_nocancel',
    342: 'sendmsg_nocancel',343: 'recvfrom_nocancel',344: 'accept_nocancel',
    345: 'msync_nocancel', 346: 'fcntl_nocancel',  347: 'select_nocancel',
    348: 'fsync_nocancel', 349: 'connect_nocancel',351: 'sendto_nocancel',
    352: 'recv_nocancel',  353: 'recvfrom_nocancel2',354: 'sendmsg_nocancel2',
    360: 'openat',         361: 'openat_nocancel', 362: 'renameat',
    363: 'faccessat',      364: 'fchmodat',        365: 'fchownat',
    366: 'fstatat',        367: 'linkat',          368: 'unlinkat',
    369: 'readlinkat',     370: 'symlinkat',       371: 'mkdirat',
    373: 'getattrlistat',  374: 'proc_trace_log',  375: 'bsdthread_ctl',
    376: 'openbyid_np',    377: 'recvmsg_x',       378: 'sendmsg_x',
    380: 'thread_selfusage',381: 'csrctl',         382: 'guarded_open_np',
    383: 'guarded_close_np',384: 'guarded_kqueue_np',385: 'change_fdguard_np',
    386: 'usrctl',         387: 'proc_rlimit_control',388: 'connectat',
    389: 'connectitx',     390: 'bindat',          391: 'disconnectx',
    392: 'peeloff',        393: 'socket_delegate', 394: 'telemetry',
    395: 'proc_uuid_policy',396: 'memorystatus_get_level',
    397: 'system_override', 398: 'vfs_purge',      399: 'sfi_ctl',
    400: 'sfi_pidctl',     401: 'coalition',       402: 'coalition_info',
    403: 'necp_match_policy',
    # Mach traps (negative numbers)
    -10:  'mach_msg_trap',
    -26:  'mach_reply_port',
    -27:  'thread_self_trap',
    -28:  'task_self_trap',
    -29:  'host_self_trap',
    -31:  'mach_msg_overwrite_trap',
    -36:  'semaphore_signal_trap',
    -37:  'semaphore_signal_all_trap',
    -38:  'semaphore_signal_thread_trap',
    -39:  'semaphore_wait_trap',
    -40:  'semaphore_wait_signal_trap',
    -41:  'semaphore_timedwait_trap',
    -42:  'semaphore_timedwait_signal_trap',
    -44:  '_task_name_for_pid',
    -45:  'task_name_for_pid',
    -46:  'pid_for_task',
    -48:  'macx_swapon',
    -49:  'macx_swapoff',
    -51:  'macx_triggers',
    -52:  'macx_backing_store_suspend',
    -53:  'macx_backing_store_recovery',
    -58:  'pfz_exit',
    -59:  'swtch_pri',
    -60:  'swtch',
    -61:  'thread_switch',
    -62:  'clock_sleep_trap',
    -89:  'mach_timebase_info_trap',
    -90:  'mach_wait_until_trap',
    -91:  'mk_timer_create_trap',
    -92:  'mk_timer_destroy_trap',
    -93:  'mk_timer_arm_trap',
    -94:  'mk_timer_cancel_trap',
    -95:  'mk_timer_arm_leeway_trap',
    -96:  'debug_control_port_for_pid',
}

# ── Linux ARM64 syscall table (kernel >=5.x, arch/arm64) ─────────────────────
# Source: kernel/include/uapi/asm-generic/unistd.h (aarch64 uses generic table)
LINUX_SYSCALLS = {
    0:   'io_setup',        1:   'io_destroy',      2:   'io_submit',
    3:   'io_cancel',       4:   'io_getevents',     5:   'setxattr',
    6:   'lsetxattr',       7:   'fsetxattr',        8:   'getxattr',
    9:   'lgetxattr',       10:  'fgetxattr',        11:  'listxattr',
    12:  'llistxattr',      13:  'flistxattr',       14:  'removexattr',
    15:  'lremovexattr',    16:  'fremovexattr',     17:  'getcwd',
    18:  'lookup_dcookie',  19:  'eventfd2',         20:  'epoll_create1',
    21:  'epoll_ctl',       22:  'epoll_pwait',      23:  'dup',
    24:  'dup3',            25:  'fcntl',            26:  'inotify_init1',
    27:  'inotify_add_watch',28: 'inotify_rm_watch', 29:  'ioctl',
    30:  'ioprio_set',      31:  'ioprio_get',       32:  'flock',
    33:  'mknodat',         34:  'mkdirat',          35:  'unlinkat',
    36:  'symlinkat',       37:  'linkat',           38:  'renameat',
    39:  'umount2',         40:  'mount',            41:  'pivot_root',
    42:  'nfsservctl',      43:  'statfs',           44:  'fstatfs',
    45:  'truncate',        46:  'ftruncate',        47:  'fallocate',
    48:  'faccessat',       49:  'chdir',            50:  'fchdir',
    51:  'chroot',          52:  'fchmod',           53:  'fchmodat',
    54:  'fchownat',        55:  'fchown',           56:  'openat',
    57:  'close',           58:  'vhangup',          59:  'pipe2',
    60:  'quotactl',        61:  'getdents64',       62:  'lseek',
    63:  'read',            64:  'write',            65:  'readv',
    66:  'writev',          67:  'pread64',          68:  'pwrite64',
    69:  'preadv',          70:  'pwritev',          71:  'sendfile',
    72:  'pselect6',        73:  'ppoll',            74:  'signalfd4',
    75:  'vmsplice',        76:  'splice',           77:  'tee',
    78:  'readlinkat',      79:  'fstatat',          80:  'fstat',
    81:  'sync',            82:  'fsync',            83:  'fdatasync',
    84:  'sync_file_range', 85:  'timerfd_create',   86:  'timerfd_settime',
    87:  'timerfd_gettime', 88:  'utimensat',        89:  'acct',
    90:  'capget',          91:  'capset',           92:  'personality',
    93:  'exit',            94:  'exit_group',       95:  'waitid',
    96:  'set_tid_address', 97:  'unshare',          98:  'futex',
    99:  'set_robust_list', 100: 'get_robust_list',  101: 'nanosleep',
    102: 'getitimer',       103: 'setitimer',        104: 'kexec_load',
    105: 'init_module',     106: 'delete_module',    107: 'timer_create',
    108: 'timer_gettime',   109: 'timer_getoverrun', 110: 'timer_settime',
    111: 'timer_delete',    112: 'clock_settime',    113: 'clock_gettime',
    114: 'clock_getres',    115: 'clock_nanosleep',  116: 'syslog',
    117: 'ptrace',          118: 'sched_setparam',   119: 'sched_setscheduler',
    120: 'sched_getscheduler',121:'sched_getparam',  122: 'sched_setaffinity',
    123: 'sched_getaffinity',124: 'sched_yield',     125: 'sched_get_priority_max',
    126: 'sched_get_priority_min',127:'sched_rr_get_interval',
    128: 'restart_syscall', 129: 'kill',             130: 'tkill',
    131: 'tgkill',          132: 'sigaltstack',      133: 'rt_sigsuspend',
    134: 'rt_sigaction',    135: 'rt_sigprocmask',   136: 'rt_sigpending',
    137: 'rt_sigtimedwait', 138: 'rt_sigqueueinfo',  139: 'rt_sigreturn',
    140: 'setpriority',     141: 'getpriority',      142: 'reboot',
    143: 'setregid',        144: 'setgid',           145: 'setreuid',
    146: 'setuid',          147: 'setresuid',        148: 'getresuid',
    149: 'setresgid',       150: 'getresgid',        151: 'setfsuid',
    152: 'setfsgid',        153: 'times',            154: 'setpgid',
    155: 'getpgid',         156: 'getsid',           157: 'setsid',
    158: 'getgroups',       159: 'setgroups',        160: 'uname',
    161: 'sethostname',     162: 'setdomainname',    163: 'getrlimit',
    164: 'setrlimit',       165: 'getrusage',        166: 'umask',
    167: 'prctl',           168: 'getcpu',           169: 'gettimeofday',
    170: 'settimeofday',    171: 'adjtimex',         172: 'getpid',
    173: 'getppid',         174: 'getuid',           175: 'geteuid',
    176: 'getgid',          177: 'getegid',          178: 'gettid',
    179: 'sysinfo',         180: 'mq_open',          181: 'mq_unlink',
    182: 'mq_timedsend',    183: 'mq_timedreceive',  184: 'mq_notify',
    185: 'mq_getsetattr',   186: 'msgget',           187: 'msgctl',
    188: 'msgrcv',          189: 'msgsnd',           190: 'semget',
    191: 'semctl',          192: 'semtimedop',       193: 'semop',
    194: 'shmget',          195: 'shmctl',           196: 'shmat',
    197: 'shmdt',           198: 'socket',           199: 'socketpair',
    200: 'bind',            201: 'listen',           202: 'accept',
    203: 'connect',         204: 'getsockname',      205: 'getpeername',
    206: 'sendto',          207: 'recvfrom',         208: 'setsockopt',
    209: 'getsockopt',      210: 'shutdown',         211: 'sendmsg',
    212: 'recvmsg',         213: 'readahead',        214: 'brk',
    215: 'munmap',          216: 'mremap',           217: 'add_key',
    218: 'request_key',     219: 'keyctl',           220: 'clone',
    221: 'execve',          222: 'mmap',             223: 'fadvise64',
    224: 'swapon',          225: 'swapoff',          226: 'mprotect',
    227: 'msync',           228: 'mlock',            229: 'munlock',
    230: 'mlockall',        231: 'munlockall',       232: 'mincore',
    233: 'madvise',         234: 'remap_file_pages', 235: 'mbind',
    236: 'get_mempolicy',   237: 'set_mempolicy',    238: 'migrate_pages',
    239: 'move_pages',      240: 'rt_tgsigqueueinfo',241: 'perf_event_open',
    242: 'accept4',         243: 'recvmmsg',         244: 'arch_specific_syscall',
    258: 'wait4',           259: 'prlimit64',        260: 'fanotify_init',
    261: 'fanotify_mark',   262: 'name_to_handle_at',263: 'open_by_handle_at',
    264: 'clock_adjtime',   265: 'syncfs',           266: 'setns',
    267: 'sendmmsg',        268: 'process_vm_readv', 269: 'process_vm_writev',
    270: 'kcmp',            271: 'finit_module',     272: 'sched_setattr',
    273: 'sched_getattr',   274: 'renameat2',        275: 'seccomp',
    276: 'getrandom',       277: 'memfd_create',     278: 'bpf',
    279: 'execveat',        280: 'userfaultfd',      281: 'membarrier',
    282: 'mlock2',          283: 'copy_file_range',  284: 'preadv2',
    285: 'pwritev2',        286: 'pkey_mprotect',    287: 'pkey_alloc',
    288: 'pkey_free',       289: 'statx',            290: 'io_pgetevents',
    291: 'rseq',            292: 'kexec_file_load',
    # io_uring (5.1+)
    425: 'io_uring_setup',  426: 'io_uring_enter',   427: 'io_uring_register',
    428: 'open_tree',       429: 'move_mount',       430: 'fsopen',
    431: 'fsconfig',        432: 'fsmount',          433: 'fspick',
    434: 'pidfd_open',      435: 'clone3',           436: 'close_range',
    437: 'openat2',         438: 'pidfd_getfd',      439: 'faccessat2',
    440: 'process_madvise', 441: 'epoll_pwait2',     442: 'mount_setattr',
    443: 'quotactl_fd',     444: 'landlock_create_ruleset',
    445: 'landlock_add_rule',446: 'landlock_restrict_self',
    447: 'memfd_secret',    448: 'process_mrelease', 449: 'futex_waitv',
    450: 'set_mempolicy_home_node',
}

# PAC instructions (ARMv8.3-A, always active on Apple Silicon)
PAC_MNEMONICS = {
    'paciasp',  # Sign X30 with SP, key A — most common in Apple binaries
    'pacibsp',  # Sign X30 with SP, key B
    'paciza',   # Sign Xn with zero, key A
    'autiasp',  # Authenticate X30 with SP, key A
    'autibsp',  # Authenticate X30 with SP, key B
    'autiza',
    'retaa',    # AUTIA + RET combined
    'retab',    # AUTIB + RET combined
    'xpaclri',  # Strip PAC from X30
    'xpaci',    # Strip PAC from Xn
    'blraaz',   # BLR with authenticate
}

# ── NEON/Advanced SIMD instruction families ───────────────────────────────────
# Source: ARM 64-Bit Assembly Language ch.10 "Advanced SIMD instructions"
# These are the AArch64 mnemonic prefixes/names for NEON operations.
# V0-V31 are 128-bit registers; accessed as Bn/Hn/Sn/Dn/Qn (scalar views)
# or Vn.T (vector views: 16b, 8b, 8h, 4h, 4s, 2s, 2d, 1d).

# Load/store: LD1/LD2/LD3/LD4 and ST1/ST2/ST3/ST4 replace the legacy
# VLD1/VST1 mnemonics in AArch64 (the Vx prefix is AArch32/NEON32 only).
NEON_LOAD_STORE = {
    'ld1', 'ld2', 'ld3', 'ld4',          # load N-element structures
    'ld1r', 'ld2r', 'ld3r', 'ld4r',      # load+replicate
    'st1', 'st2', 'st3', 'st4',          # store N-element structures
}

# Multiply family: crypto (pmull), widening (umull/smull), saturating
NEON_MUL = {
    'mul',                                # vector multiply
    'mla', 'mls',                         # multiply-accumulate / subtract
    'umull', 'smull',                     # unsigned/signed multiply long
    'umull2', 'smull2',                   # upper half sources
    'umlal', 'smlal',                     # multiply-accumulate long
    'umlal2', 'smlal2',
    'pmull', 'pmull2',                    # polynomial multiply long (GCM/AES)
    'sqrdmulh', 'sqdmulh',               # saturating doubling multiply high
    'sqdmull', 'sqdmull2',
    'fmul', 'fmla', 'fmls',              # float multiply / accumulate
    'fmulx',                              # float multiply extended
}

# Arithmetic / comparison / shift
NEON_ARITH = {
    'add', 'sub', 'abs', 'neg',
    'addp', 'addv', 'saddlv', 'uaddlv',
    'fadd', 'fsub', 'fabs', 'fneg',
    'fmax', 'fmin', 'fmaxp', 'fminp',
    'fmaxnm', 'fminnm', 'fmaxnmp', 'fminnmp',
    'cmgt', 'cmge', 'cmeq', 'cmle', 'cmlt', 'cmtst',
    'fcmgt', 'fcmge', 'fcmeq', 'fcmle', 'fcmlt',
    'sshl', 'ushl', 'sshr', 'ushr',
    'srshl', 'urshl', 'srshr', 'urshr',
    'sri', 'sli',
}

# Crypto extensions (AES, SHA1, SHA2, SHA512, SHA3, SM3, SM4)
NEON_CRYPTO = {
    'aese', 'aesd', 'aesmc', 'aesimc',  # AES rounds
    'sha1c', 'sha1p', 'sha1m', 'sha1su0', 'sha1su1', 'sha1h',
    'sha256h', 'sha256h2', 'sha256su0', 'sha256su1',
    'sha512h', 'sha512h2', 'sha512su0', 'sha512su1',
    'sm3tt1a', 'sm3tt1b', 'sm3tt2a', 'sm3tt2b', 'sm3ss1', 'sm3partw1', 'sm3partw2',
    'sm4e', 'sm4ekey',
    'rax1', 'eor3', 'xar', 'bcax',       # SHA3 extensions
}

# Data movement / conversion
NEON_MOV = {
    'dup', 'ext', 'ins', 'trn1', 'trn2', 'uzp1', 'uzp2', 'zip1', 'zip2',
    'rev16', 'rev32', 'rev64',
    'tbl', 'tbx',                         # table lookup (common in crypto S-boxes)
    'fmov',                               # FP/vector move
    'fcvt', 'fcvtl', 'fcvtn', 'fcvtxn',  # convert FP formats
    'scvtf', 'ucvtf',                     # int -> float
    'fcvtzs', 'fcvtzu',                   # float -> int (truncate to zero)
    'sqxtn', 'uqxtn', 'sqxtun',          # saturating narrow
    'xtn', 'xtn2',                        # narrow (no saturation)
    'sxtl', 'uxtl', 'sxtl2', 'uxtl2',   # extend (long)
}

# Full set for membership testing
NEON_ALL = NEON_LOAD_STORE | NEON_MUL | NEON_ARITH | NEON_CRYPTO | NEON_MOV

# Vector register prefixes (capstone uses v0..v31 for 128-bit view)
VECTOR_REGS = {f'v{i}' for i in range(32)}

# ── Stdlib function signature patterns ───────────────────────────────────────
# Each entry is a tuple of (mnemonic_sequence, optional_operand_hints, label)
# These are common compiler-generated sequences that identify known functions.
# Source: ARM 64-Bit Assembly Language ch.10, Foundations ARM64 ch.11-13,
#         Practical Reverse Engineering ch.2 (inline memcpy via LDM/STM)

STDLIB_PATTERNS = [
    # strlen: loop on LDRB, compare 0, increment pointer, branch-back
    # Modern: ADRP+ADD to string, then loop CBZ/CBNZ
    {
        'label': 'strlen_candidate',
        'sequence': ['ldrb', 'cbz'],          # load byte, test zero
        'note': 'byte-at-a-time strlen loop',
    },
    # memset: typical compiler expansion uses STP of zero pairs across loop
    {
        'label': 'memset_candidate',
        'sequence': ['stp', 'stp'],           # paired zero stores
        'note': 'paired-store memset expansion',
    },
    # memcpy (scalar): LDP + STP in a loop (Practical RE ch.2: LDM/STM inline)
    {
        'label': 'memcpy_scalar_candidate',
        'sequence': ['ldp', 'stp'],           # load pair, store pair
        'note': 'LDP+STP memcpy (scalar path)',
    },
    # memcpy (NEON): LD1+ST1 loop — used for large copies
    {
        'label': 'memcpy_neon_candidate',
        'sequence': ['ld1', 'st1'],           # NEON load/store
        'note': 'LD1+ST1 memcpy (NEON path)',
    },
    # malloc stub: BL to plt stub; X0 = size in; X0 = ptr out
    {
        'label': 'malloc_call_candidate',
        'sequence': ['bl'],                   # needs target resolution
        'note': 'BL to potential malloc/calloc/realloc',
    },
    # free stub: BL; X0 = ptr
    {
        'label': 'free_call_candidate',
        'sequence': ['bl'],                   # needs target resolution
        'note': 'BL to potential free/cfrelease',
    },
    # memmove: similar to memcpy but with direction check first
    {
        'label': 'memmove_candidate',
        'sequence': ['cmp', 'b.lo'],          # direction check
        'note': 'direction-sensitive memmove',
    },
]

# ObjC runtime function names (called via BL/BLR in Apple binaries)
# Source: Mac OS X and iOS Internals / Practical RE ch.2 bridging notes
OBJC_RUNTIME_FUNCS = {
    '_objc_msgSend',
    '_objc_msgSendSuper',
    '_objc_msgSendSuper2',
    '_objc_msgSend_fpret',    # float-return variant
    '_objc_msgSend_stret',    # struct-return variant (stack pointer in X8)
    '_objc_retain',
    '_objc_release',
    '_objc_autorelease',
    '_objc_retainAutorelease',
    '_objc_autoreleaseReturnValue',
    '_objc_retainAutoreleaseReturnValue',
    '_objc_storeStrong',
    '_objc_storeWeak',
    '_objc_loadWeakRetained',
    '_objc_copyWeak',
    '_objc_destroyWeak',
    '_objc_allocWithZone',
    '_objc_alloc',
    '_objc_alloc_init',
    '_swift_bridgeObjectRetain',
    '_swift_bridgeObjectRelease',
}


class ARM64Analyzer:
    """ARM64 binary analysis: function boundaries, CFG, NEON, stdlib, ObjC, syscalls."""

    def __init__(self, code: bytes, base_addr: int = 0):
        self.code = code
        self.base_addr = base_addr
        self.md = None
        self._insns = None  # cached full disassembly

        if HAS_CAPSTONE:
            self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            self.md.detail = True

    def _disasm_all(self):
        """Cache full disassembly of the code buffer."""
        if self._insns is None and self.md:
            self._insns = list(self.md.disasm(self.code, self.base_addr))
        return self._insns or []

    # ── Function boundary detection ───────────────────────────────────────────

    def find_functions(self) -> list:
        """Detect function entry points using prologue patterns and BL targets.

        Strategy:
        1. Scan for STP X29, X30, [SP, #-N]! followed by MOV X29, SP
        2. Detect frameless leaf functions: SUB SP, SP, #N only
        3. Collect all BL (direct call) targets
        4. Merge, deduplicate, sort
        """
        prologues      = self._find_prologue_starts()
        leaf_starts    = self._find_leaf_function_starts()
        bl_targets     = self._collect_bl_targets()

        all_starts = sorted(set(prologues) | set(leaf_starts) | set(bl_targets))
        return all_starts

    def _find_prologue_starts(self) -> list:
        """Find STP X29, X30, [SP, #-N]! prologue entries (frame-bearing functions)."""
        if not self.md:
            return self._find_prologues_bitwise()

        starts = []
        insns = self._disasm_all()

        for i, insn in enumerate(insns):
            if insn.mnemonic == 'stp' and insn.mnemonic:
                ops = insn.operands
                if (len(ops) >= 3 and
                        ops[0].type == ARM64_OP_REG and ops[0].reg == ARM64_REG_X29 and
                        ops[1].type == ARM64_OP_REG and ops[1].reg == ARM64_REG_X30 and
                        ops[2].type == ARM64_OP_MEM and ops[2].mem.base == ARM64_REG_SP and
                        ops[2].mem.disp < 0):
                    starts.append(insn.address)

            # PACIASP/PACIBSP often immediately precede the STP in Apple binaries
            # and can serve as the real entry point.
            if insn.mnemonic in ('paciasp', 'pacibsp'):
                # Check that the next instruction is STP X29/X30
                if i + 1 < len(insns):
                    nxt = insns[i + 1]
                    if nxt.mnemonic == 'stp':
                        ops = nxt.operands
                        if (len(ops) >= 3 and
                                ops[0].type == ARM64_OP_REG and
                                ops[0].reg == ARM64_REG_X29 and
                                ops[1].type == ARM64_OP_REG and
                                ops[1].reg == ARM64_REG_X30):
                            starts.append(insn.address)

        return starts

    def _find_leaf_function_starts(self) -> list:
        """Find frameless leaf functions: SUB SP, SP, #N without STP X29/X30.

        Leaf functions make no outgoing calls, so they need not save LR (X30).
        The compiler still allocates a stack frame via SUB SP, SP, #N for local
        storage. These are common in hot-path math, crypto, and NEON routines.

        Per Foundations of ARM64 Linux Debugging ch.10: the simplest leaf has
        only SUB SP/ADD SP with no STP at all (pure register-only leafs produce
        zero stack frame).
        """
        if not self.md:
            return []

        starts = []
        insns  = self._disasm_all()
        # Build set of addresses that are already known frame-bearing prologues
        # so we don't double-count.
        known = set()
        for insn in insns:
            if (insn.mnemonic == 'stp' and
                    insn.operands and len(insn.operands) >= 3 and
                    insn.operands[0].type == ARM64_OP_REG and
                    insn.operands[0].reg == ARM64_REG_X29):
                known.add(insn.address)

        for i, insn in enumerate(insns):
            # Skip if this address is covered by a frame-bearing prologue already
            if insn.address in known:
                continue

            if insn.mnemonic == 'sub':
                ops = insn.operands
                if (len(ops) >= 3 and
                        ops[0].type == ARM64_OP_REG and ops[0].reg == ARM64_REG_SP and
                        ops[1].type == ARM64_OP_REG and ops[1].reg == ARM64_REG_SP and
                        ops[2].type == ARM64_OP_IMM):
                    # Confirm prior instruction is not ADD SP (that is epilogue)
                    if i > 0 and insns[i - 1].mnemonic == 'add':
                        prior_ops = insns[i - 1].operands
                        if (prior_ops and len(prior_ops) >= 2 and
                                prior_ops[0].type == ARM64_OP_REG and
                                prior_ops[0].reg == ARM64_REG_SP):
                            continue  # epilogue of prior function
                    starts.append(insn.address)

        return starts

    def _find_prologues_bitwise(self) -> list:
        """Fallback: find STP X29, X30, [SP, #-N]! via bitmask (no capstone)."""
        starts = []
        # ARM64 STP pre-index encoding (A64 ISA):
        # [31:30]=10, [29:27]=101, [26]=0, [25:23]=011, [22]=0
        # [14:10]=Rt2=30=0x1E, [9:5]=Rn=SP=31=0x1F, [4:0]=Rt=29=0x1D
        # Loose mask: just verify Rt=29(x29), Rt2=30(x30), Rn=31(sp)
        LOOSE_MASK  = 0xFF8003FF
        LOOSE_VALUE = 0xA98003FD  # bits[9:0]=0x3FD=29|31<<5; bits[14:10]=30

        for i in range(0, len(self.code) - 4, 4):
            word = struct.unpack_from('<I', self.code, i)[0]
            if (word & LOOSE_MASK) == LOOSE_VALUE and (word >> 30) == 2:
                starts.append(self.base_addr + i)

        return starts

    def _collect_bl_targets(self) -> list:
        """Collect all BL (direct call) target addresses."""
        if not self.md:
            return []

        targets = []
        for insn in self._disasm_all():
            if insn.mnemonic == 'bl':
                ops = insn.operands
                if ops and ops[0].type == ARM64_OP_IMM:
                    targets.append(ops[0].imm)

        return targets

    # ── String reference resolution (ADRP + ADD/LDR) ─────────────────────────

    def find_string_refs(self) -> list:
        """Find ADRP+ADD pairs that reference string constants.

        ADRP sets a register to the 4KB-aligned page containing the target.
        ADD then adds the page offset to get the final address.
        Together they implement PC-relative addressing for ±4GB range.
        """
        if not self.md:
            return []

        refs = []
        insns = self._disasm_all()

        for i in range(len(insns) - 1):
            curr = insns[i]
            nxt  = insns[i + 1]

            if curr.mnemonic != 'adrp':
                continue

            curr_ops = curr.operands
            nxt_ops  = nxt.operands

            if not curr_ops or curr_ops[0].type != ARM64_OP_REG:
                continue

            adrp_dst_reg = curr_ops[0].reg
            adrp_page    = curr_ops[1].imm if len(curr_ops) > 1 else 0

            if nxt.mnemonic == 'add' and nxt_ops and len(nxt_ops) >= 3:
                if (nxt_ops[0].type == ARM64_OP_REG and
                        nxt_ops[1].type == ARM64_OP_REG and
                        nxt_ops[1].reg == adrp_dst_reg and
                        nxt_ops[2].type == ARM64_OP_IMM):
                    offset = nxt_ops[2].imm
                    target = adrp_page + offset
                    refs.append({
                        'insn_addr':   curr.address,
                        'target_addr': target,
                        'type':        'adrp+add',
                        'dst_reg':     curr_ops[0].reg,
                    })

            elif nxt.mnemonic == 'ldr' and nxt_ops and len(nxt_ops) >= 2:
                if (nxt_ops[1].type == ARM64_OP_MEM and
                        nxt_ops[1].mem.base == adrp_dst_reg):
                    offset = nxt_ops[1].mem.disp
                    target = adrp_page + offset
                    refs.append({
                        'insn_addr':   curr.address,
                        'target_addr': target,
                        'type':        'adrp+ldr (GOT)',
                        'dst_reg':     curr_ops[0].reg,
                    })

        return refs

    # ── CFString detection ────────────────────────────────────────────────────

    def detect_cfstring_refs(self, cfstring_section_range: tuple = None) -> list:
        """Detect CFString references via ADRP+ADD pattern pointing to __cstring.

        In Apple binaries, CFStringRef objects live in __DATA,__cfstring and
        point to character data in __TEXT,__cstring. The compiler emits
        ADRP + ADD (or ADRP + LDR for indirect) to reference them.

        cfstring_section_range: optional (start_addr, end_addr) of __cstring
        section to validate targets against. If not provided, all ADRP+ADD
        refs are returned as CFString candidates (lower confidence).
        """
        if not self.md:
            return []

        raw_refs = self.find_string_refs()
        candidates = []

        for ref in raw_refs:
            target = ref['target_addr']
            is_in_range = True

            if cfstring_section_range:
                lo, hi = cfstring_section_range
                is_in_range = lo <= target < hi

            if is_in_range:
                candidates.append({
                    'insn_addr':   ref['insn_addr'],
                    'target_addr': target,
                    'type':        'cfstring_candidate',
                    'ref_type':    ref['type'],
                    'confidence':  'high' if cfstring_section_range else 'low',
                })

        return candidates

    # ── ObjC msgSend detection ────────────────────────────────────────────────

    def detect_objc_msgsend(self, symbol_map: dict = None) -> list:
        """Detect ObjC runtime dispatch calls (objc_msgSend and variants).

        Two detection modes:
        1. Symbol-map mode: caller provides {addr: name} from dyld info / symbol
           table; we look up BL/BLR targets in that map.
        2. Heuristic mode (no symbol map): look for BLR Xn where Xn was loaded
           by ADRP+LDR (GOT pattern) — typical compiler output for msgSend stubs.

        ABI: X0 = receiver (id), X1 = selector (SEL), X2.. = args.
             objc_msgSend_stret has X8 = struct-return pointer (like AAPCS64
             indirect result extension used by Swift as well).

        Returns list of {addr, target_type, receiver_reg, selector_reg, variant}.
        """
        if not self.md:
            return []

        results = []
        insns   = self._disasm_all()
        sym     = symbol_map or {}

        for i, insn in enumerate(insns):
            if insn.mnemonic not in ('bl', 'blr', 'blraaz', 'blrabz'):
                continue

            ops = insn.operands

            # Direct BL to known ObjC runtime symbol
            if insn.mnemonic == 'bl' and ops and ops[0].type == ARM64_OP_IMM:
                target_addr = ops[0].imm
                name = sym.get(target_addr, '')
                if name in OBJC_RUNTIME_FUNCS or '_objc_' in name or '_swift_bridge' in name:
                    results.append({
                        'addr':           insn.address,
                        'target_addr':    target_addr,
                        'target_name':    name,
                        'target_type':    'direct_bl',
                        'receiver_reg':   'x0',
                        'selector_reg':   'x1',
                        'variant':        _classify_msgsend_variant(name),
                    })

            # Indirect BLR Xn — heuristic: preceded by LDR from GOT (ADRP+LDR)
            elif insn.mnemonic in ('blr', 'blraaz', 'blrabz') and ops:
                if ops[0].type == ARM64_OP_REG:
                    blr_reg = ops[0].reg
                    # Walk back up to 8 instructions looking for the load
                    for j in range(max(0, i - 8), i):
                        prev = insns[j]
                        if (prev.mnemonic == 'ldr' and
                                prev.operands and len(prev.operands) >= 2):
                            dst_op = prev.operands[0]
                            if (dst_op.type == ARM64_OP_REG and
                                    dst_op.reg == blr_reg):
                                # This LDR loads the function pointer into blr_reg
                                load_addr = None
                                if (prev.operands[1].type == ARM64_OP_MEM):
                                    base_r = prev.operands[1].mem.base
                                    disp   = prev.operands[1].mem.disp
                                    # Resolve ADRP base from earlier ADRP
                                    adrp_page = _resolve_adrp_page(insns, j, base_r)
                                    if adrp_page is not None:
                                        load_addr = adrp_page + disp
                                target_name = sym.get(load_addr, '') if load_addr else ''
                                results.append({
                                    'addr':        insn.address,
                                    'got_entry':   hex(load_addr) if load_addr else 'unknown',
                                    'target_name': target_name or 'unknown_indirect',
                                    'target_type': 'indirect_blr_got',
                                    'blr_reg':     f'x{blr_reg - 1}' if blr_reg else '?',
                                    'receiver_reg': 'x0',
                                    'selector_reg': 'x1',
                                    'variant':     _classify_msgsend_variant(target_name),
                                })
                                break

        return results

    # ── Control flow graph ────────────────────────────────────────────────────

    def build_cfg(self, start_addr: int, max_insns: int = 500) -> dict:
        """Build basic-block CFG for a function starting at start_addr."""
        if not self.md:
            return {}

        blocks = {}
        worklist = [start_addr]
        visited = set()

        insns_by_addr = {i.address: i for i in self._disasm_all()}

        while worklist:
            addr = worklist.pop()
            if addr in visited:
                continue
            visited.add(addr)

            block = {'start': addr, 'insns': [], 'succs': []}
            cur = addr

            for _ in range(max_insns):
                insn = insns_by_addr.get(cur)
                if not insn:
                    break

                block['insns'].append({
                    'addr': insn.address,
                    'mnem': insn.mnemonic,
                    'ops':  insn.op_str,
                })
                cur = insn.address + insn.size

                # Block terminators
                if insn.mnemonic == 'ret' or insn.mnemonic in ('retaa', 'retab'):
                    block['type'] = 'return'
                    break

                if insn.mnemonic in ('b',):
                    ops = insn.operands
                    if ops and ops[0].type == ARM64_OP_IMM:
                        target = ops[0].imm
                        block['succs'].append(target)
                        if target not in visited:
                            worklist.append(target)
                    block['type'] = 'unconditional_branch'
                    break

                if insn.mnemonic.startswith('b.'):
                    ops = insn.operands
                    if ops and ops[0].type == ARM64_OP_IMM:
                        taken = ops[0].imm
                        fallthrough = insn.address + insn.size
                        block['succs'].extend([taken, fallthrough])
                        worklist.extend([t for t in [taken, fallthrough]
                                         if t not in visited])
                    block['type'] = 'conditional_branch'
                    break

                if insn.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
                    ops = insn.operands
                    if ops and ops[-1].type == ARM64_OP_IMM:
                        taken = ops[-1].imm
                        fallthrough = insn.address + insn.size
                        block['succs'].extend([taken, fallthrough])
                        worklist.extend([t for t in [taken, fallthrough]
                                         if t not in visited])
                    block['type'] = 'compare_branch'
                    break

                if insn.mnemonic in ('br', 'blr', 'braaz', 'brabz'):
                    block['type'] = 'indirect_branch'
                    break

            block.setdefault('type', 'sequential')
            block['end'] = cur
            blocks[addr] = block

        return {'entry': start_addr, 'blocks': blocks, 'block_count': len(blocks)}

    # ── Indirect branch target analysis ──────────────────────────────────────

    def analyze_indirect_branches(self) -> list:
        """Analyze BLR Xn calls and attempt to resolve the target register's value.

        Approach: lightweight register-value propagation within the same basic
        block. Walk backward from each BLR, tracking the last MOV/LDR/MOVZ
        that wrote to the target register.

        Sources:
          - ADRP+ADD  => absolute target in code segment (direct fn pointer)
          - ADRP+LDR  => GOT entry (shared library function)
          - MOV Xn, Xm => alias of another register (chain one level)
          - MOVZ/MOVK  => immediate value (function pointer constant)

        Returns list of dicts with 'addr', 'reg', 'resolved_target', 'method'.
        """
        if not self.md:
            return []

        results  = []
        insns    = self._disasm_all()

        for i, insn in enumerate(insns):
            if insn.mnemonic not in ('blr', 'br', 'blraaz', 'blrabz', 'braaz', 'brabz'):
                continue

            ops = insn.operands
            if not ops or ops[0].type != ARM64_OP_REG:
                continue

            target_reg = ops[0].reg
            resolved   = _propagate_register(insns, i, target_reg, depth=10)

            results.append({
                'addr':             insn.address,
                'mnemonic':         insn.mnemonic,
                'reg':              _reg_name(target_reg),
                'resolved_target':  resolved.get('value'),
                'resolution_method': resolved.get('method', 'unresolved'),
                'resolution_insn':  resolved.get('insn_addr'),
                'got_entry':        resolved.get('got_entry'),
            })

        return results

    # ── NEON/SIMD detection ───────────────────────────────────────────────────

    def detect_neon(self) -> dict:
        """Detect NEON/Advanced SIMD instruction usage.

        Categories:
          - load_store: LD1/ST1 families (memcpy, media pipeline)
          - multiply:   UMULL/PMULL/FMLA (crypto, DSP, ML)
          - arithmetic: FADD/FSUB/FMAX/CMGT etc.
          - crypto:     AES*/SHA*/SM3/SM4 (hardware-accelerated crypto)
          - movement:   DUP/EXT/TBL (shuffle, broadcast)

        High PMULL density => GCM-mode AES or polynomial hashing.
        AES* family => hardware AES rounds (common in TLS, disk encryption).
        FMLA/FMUL density => ML inference kernel or signal processing.
        """
        if not self.md:
            return {'has_neon': False}

        counts = {
            'load_store': 0, 'multiply': 0, 'arithmetic': 0,
            'crypto': 0, 'movement': 0, 'total': 0,
        }
        sites = []

        for insn in self._disasm_all():
            mnem = insn.mnemonic

            # Capstone uses e.g. "ld1" but also "ld1  {v0.16b}" — split suffix
            base_mnem = mnem.split('.')[0].lower()

            if base_mnem in NEON_LOAD_STORE:
                counts['load_store'] += 1
                counts['total'] += 1
            elif base_mnem in NEON_MUL:
                counts['multiply'] += 1
                counts['total'] += 1
            elif base_mnem in NEON_ARITH:
                counts['arithmetic'] += 1
                counts['total'] += 1
            elif base_mnem in NEON_CRYPTO:
                counts['crypto'] += 1
                counts['total'] += 1
            elif base_mnem in NEON_MOV:
                counts['movement'] += 1
                counts['total'] += 1
            else:
                continue

            if len(sites) < 30:
                sites.append({
                    'addr': insn.address,
                    'mnem': mnem,
                    'ops':  insn.op_str,
                    'category': _neon_category(base_mnem),
                })

        has_neon = counts['total'] > 0
        interpretation = _interpret_neon_usage(counts)

        return {
            'has_neon':       has_neon,
            'counts':         counts,
            'sites':          sites,
            'interpretation': interpretation,
        }

    # ── Stdlib function signature matching ───────────────────────────────────

    def match_stdlib_signatures(self) -> list:
        """Identify common stdlib function patterns by instruction sequence.

        Approach: sliding window over the disassembly, matching 2-5 instruction
        mnemonic sequences. Returns candidate sites with function boundary context.

        These are heuristics — they identify *candidate* regions, not confirmed
        matches. Cross-reference against symbol names and call targets to confirm.
        """
        if not self.md:
            return []

        insns   = self._disasm_all()
        matches = []

        for i in range(len(insns) - 1):
            window = [ins.mnemonic for ins in insns[i:i + 5]]

            # strlen: LDRB + CBZ/CBNZ loop
            if (window[0] == 'ldrb' and
                    len(window) > 1 and window[1] in ('cbz', 'cbnz')):
                matches.append({
                    'addr':  insns[i].address,
                    'label': 'strlen_candidate',
                    'note':  'byte-load + zero-test (strlen loop)',
                    'confidence': 'medium',
                })

            # memset: STP + STP back-to-back (zeroing)
            if window[0] == 'stp' and len(window) > 1 and window[1] == 'stp':
                if True:
                    ops = insns[i].operands
                    # Check if first two operands are XZR (zero reg, reg id 31 in GP)
                    if (ops and len(ops) >= 2 and
                            ops[0].type == ARM64_OP_REG and
                            ops[1].type == ARM64_OP_REG and
                            _is_zero_reg(ops[0].reg) and _is_zero_reg(ops[1].reg)):
                        matches.append({
                            'addr':  insns[i].address,
                            'label': 'memset_zero_candidate',
                            'note':  'STP XZR,XZR — bulk zeroing (memset/bzero)',
                            'confidence': 'high',
                        })

            # memcpy scalar: LDP immediately before STP in sequence
            if window[0] == 'ldp' and len(window) > 1 and window[1] == 'stp':
                matches.append({
                    'addr':  insns[i].address,
                    'label': 'memcpy_scalar_candidate',
                    'note':  'LDP+STP pair (scalar memcpy)',
                    'confidence': 'medium',
                })

            # memcpy NEON: LD1 + ST1
            if window[0] == 'ld1' and len(window) > 1 and window[1] == 'st1':
                matches.append({
                    'addr':  insns[i].address,
                    'label': 'memcpy_neon_candidate',
                    'note':  'LD1+ST1 (NEON memcpy path)',
                    'confidence': 'high',
                })

            # memmove direction check: CMP + B.LO / B.HS
            if window[0] == 'cmp' and len(window) > 1 and window[1] in ('b.lo', 'b.hs', 'b.cc', 'b.cs'):
                matches.append({
                    'addr':  insns[i].address,
                    'label': 'memmove_candidate',
                    'note':  'CMP + conditional branch (memmove direction)',
                    'confidence': 'low',
                })

        # Deduplicate by address
        seen = set()
        deduped = []
        for m in matches:
            k = (m['addr'], m['label'])
            if k not in seen:
                seen.add(k)
                deduped.append(m)

        return deduped

    # ── PAC detection ──────────────────────────────────────────────────────────

    def detect_pac(self) -> dict:
        """Detect Pointer Authentication Code usage in the binary."""
        if not self.md:
            return {'has_pac': False}

        pac_sites = []
        for insn in self._disasm_all():
            if insn.mnemonic in PAC_MNEMONICS:
                pac_sites.append({
                    'addr':  insn.address,
                    'insn':  insn.mnemonic,
                    'bytes': insn.bytes.hex(),
                })

        return {
            'has_pac':        bool(pac_sites),
            'pac_count':      len(pac_sites),
            'pac_sites':      pac_sites[:20],
            'pac_types':      list({p['insn'] for p in pac_sites}),
            'interpretation': (
                'Binary uses Apple PAC hardening. PACIASP/AUTIASP protect return '
                'addresses. Exploitation requires bypassing PAC or using a gadget '
                'that signs attacker pointers.'
                if pac_sites else 'No PAC instructions found.'
            ),
        }

    # ── Darwin syscall detection ───────────────────────────────────────────────

    def find_syscalls(self, platform: str = 'darwin') -> list:
        """Find syscall sequences for Darwin (X16+SVC#0x80) or Linux (X8+SVC#0).

        Darwin:
          MOV/MOVZ X16, #N   ; syscall number in X16
          SVC #0x80          ; BSD layer call (Mach traps use negative numbers)

        Linux ARM64:
          MOV/MOVZ X8, #N    ; syscall number in X8
          SVC #0             ; kernel entry

        Negative Darwin syscall numbers are Mach traps (e.g., mach_msg).
        """
        if not self.md:
            return []

        syscalls  = []
        insns     = self._disasm_all()
        table     = DARWIN_SYSCALLS if platform == 'darwin' else LINUX_SYSCALLS
        svc_imm   = DARWIN_SVC_IMM  if platform == 'darwin' else LINUX_SVC_IMM

        # Register to watch for syscall number (X16 Darwin, X8 Linux)
        syscall_reg_str = DARWIN_SYSCALL_REG if platform == 'darwin' else LINUX_SYSCALL_REG
        # Map name to capstone const
        syscall_reg_id  = ARM64_REG_X16 if platform == 'darwin' else ARM64_REG_X8

        for i in range(len(insns) - 1):
            insn = insns[i]
            nxt  = insns[i + 1]

            if insn.mnemonic not in ('mov', 'movz', 'movk'):
                continue

            ops = insn.operands
            if not ops or len(ops) < 2:
                continue

            if (ops[0].type == ARM64_OP_REG and ops[0].reg == syscall_reg_id and
                    ops[1].type == ARM64_OP_IMM):
                syscall_num = ops[1].imm
                # MOVK can OR in upper bits — treat as raw; negative via sign ext
                # For Darwin Mach traps the number is passed as negative (e.g., -10)
                if nxt.mnemonic == 'svc':
                    svc_ops = nxt.operands
                    if svc_ops and svc_ops[0].type == ARM64_OP_IMM and svc_ops[0].imm == svc_imm:
                        syscalls.append({
                            'addr':          insn.address,
                            'number':        syscall_num,
                            'name':          table.get(syscall_num,
                                             table.get(-syscall_num,
                                             f'syscall_{syscall_num}')),
                            'platform':      platform,
                            'is_mach_trap':  syscall_num < 0 and platform == 'darwin',
                        })

        return syscalls

    def find_all_syscalls(self) -> dict:
        """Find both Darwin and Linux syscall sequences in the binary."""
        return {
            'darwin': self.find_syscalls('darwin'),
            'linux':  self.find_syscalls('linux'),
        }

    # ── Dead code stripping artifact detection ────────────────────────────────

    def detect_dead_code(self) -> list:
        """Find unreachable basic blocks — artifacts of dead code stripping.

        After linker dead-strip and compiler DCE, unreachable blocks manifest as:
        1. Instructions following an unconditional RET/B with no incoming edges
           (no BL target, no conditional branch target pointing here).
        2. UDF (undefined instruction, encoding 0x00000000) sequences — the
           compiler/linker fills stripped regions with UDF #0.
        3. NOP sleds following a terminator with no label.
        4. Trap sequences: BRK #0xF000 (Apple) or HLT #0 padding.

        Returns list of {start_addr, length, kind} for suspected dead regions.
        """
        if not self.md:
            return []

        insns        = self._disasm_all()
        n            = len(insns)
        if n == 0:
            return []

        # Build set of all addresses that are branch/call targets
        target_addrs = set()
        for insn in insns:
            if insn.mnemonic in ('bl', 'b', 'blr', 'br',
                                                  'cbz', 'cbnz', 'tbz', 'tbnz'):
                ops = insn.operands
                if ops:
                    for op in ops:
                        if op.type == ARM64_OP_IMM:
                            target_addrs.add(op.imm)
            if insn.mnemonic.startswith('b.'):
                ops = insn.operands
                if ops and ops[0].type == ARM64_OP_IMM:
                    target_addrs.add(ops[0].imm)

        dead_regions = []
        i = 0

        while i < n:
            insn = insns[i]
            mnem = insn.mnemonic

            # After a terminating instruction (ret/b/retaa), check if next
            # instruction has no incoming edge (not a branch target).
            is_terminator = (
                mnem in ('ret', 'retaa', 'retab', 'b') or
                (mnem == 'br')
            )

            if is_terminator and i + 1 < n:
                nxt = insns[i + 1]
                if nxt.address not in target_addrs:
                    # Scan forward to find end of unreachable block
                    region_start = nxt.address
                    j = i + 1
                    while j < n:
                        candidate = insns[j]
                        # Stop if this address is a known target
                        if candidate.address in target_addrs:
                            break
                        # Stop at another terminator that looks like a new function
                        if candidate.mnemonic in ('paciasp', 'pacibsp'):
                            break
                        j += 1

                    region_len = insns[j - 1].address + insns[j - 1].size - region_start
                    if region_len > 0:
                        dead_regions.append({
                            'start_addr': region_start,
                            'length':     region_len,
                            'kind':       'unreachable_after_terminator',
                            'insn_count': j - (i + 1),
                        })
                    i = j
                    continue

            # UDF #0 (encoding = 0x00000000) block — linker padding
            if mnem == 'udf' and insn.bytes == b'\x00\x00\x00\x00':
                region_start = insn.address
                j = i
                while j < n and insns[j].mnemonic == 'udf' and insns[j].bytes == b'\x00\x00\x00\x00':
                    j += 1
                region_len = j * 4  # each udf is 4 bytes
                dead_regions.append({
                    'start_addr': region_start,
                    'length':     (j - i) * 4,
                    'kind':       'udf_zero_padding',
                    'insn_count': j - i,
                })
                i = j
                continue

            # BRK #0xF000 (Apple trap padding, e.g., end of stripped functions)
            if mnem == 'brk':
                ops = insn.operands
                if ops and ops[0].type == ARM64_OP_IMM and ops[0].imm in (0xF000, 0xC471):
                    region_start = insn.address
                    j = i
                    while j < n and insns[j].mnemonic == 'brk':
                        j += 1
                    dead_regions.append({
                        'start_addr': region_start,
                        'length':     (j - i) * 4,
                        'kind':       'brk_trap_padding',
                        'insn_count': j - i,
                    })
                    i = j
                    continue

            i += 1

        return dead_regions

    # ── Swift ABI marker detection ────────────────────────────────────────────

    def detect_swift_abi(self) -> dict:
        """Detect Swift ABI patterns: X20 self, X21 error, thick function pointers."""
        if not self.md:
            return {}

        x20_uses = 0
        x21_uses = 0

        for insn in self._disasm_all():
            if True:
                ops = insn.operands
                for op in ops:
                    if op.type == ARM64_OP_REG:
                        if op.reg == ARM64_REG_X20:
                            x20_uses += 1
                        elif op.reg == ARM64_REG_X21:
                            x21_uses += 1

        is_swift_binary = x20_uses > 10 and x21_uses > 5

        return {
            'likely_swift':   is_swift_binary,
            'x20_uses':       x20_uses,
            'x21_uses':       x21_uses,
            'interpretation': (
                'Heavy X20/X21 usage consistent with Swift ABI '
                '(X20=self, X21=error pointer). Apply Swift demangling to symbols.'
                if is_swift_binary else
                'X20/X21 usage does not strongly indicate Swift.'
            ),
        }

    # ── Callee-saved register frame analysis ──────────────────────────────────

    def analyze_function_frame(self, func_addr: int) -> dict:
        """Analyze a function's prologue/epilogue to map its stack frame."""
        if not self.md:
            return {}

        insns = self._disasm_all()
        insns_by_addr = {i.address: i for i in insns}

        saved_regs = []
        frame_size = 0
        has_pac    = False
        is_leaf    = True  # assume leaf until we see STP X29/X30

        cur = func_addr
        for _ in range(30):
            insn = insns_by_addr.get(cur)
            if not insn:
                break

            mnem = insn.mnemonic
            ops  = insn.operands

            if mnem in ('paciasp', 'pacibsp'):
                has_pac = True

            if mnem == 'stp' and len(ops) >= 3:
                r1 = ops[0].reg if ops[0].type == ARM64_OP_REG else None
                r2 = ops[1].reg if ops[1].type == ARM64_OP_REG else None
                if ops[2].type == ARM64_OP_MEM:
                    disp = ops[2].mem.disp
                    saved_regs.append((r1, r2, disp))
                    if (ops[2].mem.base == ARM64_REG_SP and disp < 0 and
                            r1 == ARM64_REG_X29 and r2 == ARM64_REG_X30):
                        frame_size = max(frame_size, abs(disp))
                        is_leaf = False

            if mnem == 'sub' and len(ops) >= 3:
                if (ops[0].type == ARM64_OP_REG and ops[0].reg == ARM64_REG_SP and
                        ops[1].type == ARM64_OP_REG and ops[1].reg == ARM64_REG_SP and
                        ops[2].type == ARM64_OP_IMM):
                    frame_size = max(frame_size, ops[2].imm)

            if mnem == 'mov':
                if (len(ops) >= 2 and
                        ops[0].type == ARM64_OP_REG and ops[0].reg == ARM64_REG_X29 and
                        ops[1].type == ARM64_OP_REG and ops[1].reg == ARM64_REG_SP):
                    break

            cur += insn.size

        return {
            'frame_size': frame_size,
            'has_pac':    has_pac,
            'saved_regs': saved_regs,
            'is_leaf':    is_leaf,
        }

    # ── Swift name demangling ─────────────────────────────────────────────────

    @staticmethod
    def demangle_swift(symbol: str) -> str:
        """Demangle a Swift symbol using the swift-demangle tool (if available)."""
        import subprocess
        if not symbol.startswith(('$s', '_T', '$S')):
            return symbol
        try:
            result = subprocess.run(
                ['swift-demangle', symbol],
                capture_output=True, text=True, timeout=3,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return ARM64Analyzer._minimal_swift_demangle(symbol)

    @staticmethod
    def _minimal_swift_demangle(symbol: str) -> str:
        """Minimal Swift demangling without the swift-demangle binary."""
        import re

        s = symbol
        if s.startswith(('$s', '$S')):
            s = s[2:]

        parts = []
        i = 0
        while i < len(s):
            m = re.match(r'(\d+)', s[i:])
            if m:
                length = int(m.group(1))
                i += len(m.group(1))
                if i + length <= len(s):
                    parts.append(s[i:i + length])
                    i += length
                else:
                    break
            else:
                i += 1

        if parts:
            return '.'.join(parts)
        return symbol

    @staticmethod
    def is_swift_symbol(name: str) -> bool:
        """Check if a symbol name uses Swift mangling convention."""
        return name.startswith(('$s', '$S', '_T', '_T0'))

    # ── Full analysis report ──────────────────────────────────────────────────

    def analyze(self, max_funcs: int = 100, platform: str = 'darwin') -> dict:
        """Run full ARM64 analysis pipeline."""
        result = {
            'arch':      'arm64',
            'base_addr': hex(self.base_addr),
            'code_size': len(self.code),
            'platform':  platform,
        }

        if not HAS_CAPSTONE:
            result['error'] = 'capstone not available; install with: pip install capstone'
            return result

        # Functions (frame-bearing + leaf)
        func_addrs = self.find_functions()[:max_funcs]
        result['function_count'] = len(func_addrs)
        result['function_addrs'] = [hex(a) for a in func_addrs[:20]]

        # String refs
        refs = self.find_string_refs()
        result['string_ref_count'] = len(refs)
        result['string_refs']      = refs[:20]

        # CFString candidates
        result['cfstring_candidates'] = self.detect_cfstring_refs()[:10]

        # PAC
        result['pac'] = self.detect_pac()

        # Syscalls (platform-specific + both)
        all_syscalls = self.find_all_syscalls()
        result['syscalls'] = all_syscalls
        result['syscall_count'] = (len(all_syscalls['darwin']) +
                                   len(all_syscalls['linux']))

        # Swift ABI
        result['swift_abi'] = self.detect_swift_abi()

        # NEON/SIMD
        result['neon'] = self.detect_neon()

        # Stdlib signatures
        result['stdlib_matches'] = self.match_stdlib_signatures()[:30]

        # Indirect branches
        result['indirect_branches'] = self.analyze_indirect_branches()[:30]

        # ObjC msgSend (heuristic without symbol map)
        result['objc_msgsend'] = self.detect_objc_msgsend()[:20]

        # Dead code
        result['dead_code_regions'] = self.detect_dead_code()[:20]

        return result


# ── Module-level helpers ──────────────────────────────────────────────────────

def _neon_category(mnem: str) -> str:
    if mnem in NEON_LOAD_STORE:  return 'load_store'
    if mnem in NEON_MUL:         return 'multiply'
    if mnem in NEON_ARITH:       return 'arithmetic'
    if mnem in NEON_CRYPTO:      return 'crypto'
    if mnem in NEON_MOV:         return 'movement'
    return 'unknown'


def _interpret_neon_usage(counts: dict) -> str:
    total = counts['total']
    if total == 0:
        return 'No NEON/SIMD instructions found.'
    parts = []
    if counts['crypto'] > 5:
        parts.append('hardware crypto (AES/SHA/PMULL) — TLS, disk encryption likely')
    if counts['multiply'] > 20 and counts['load_store'] > 10:
        parts.append('high FMLA/LD1 density — ML inference kernel or DSP')
    if counts['load_store'] > 30:
        parts.append('bulk LD1/ST1 — optimized memcpy or media codec')
    if not parts:
        parts.append(f'{total} NEON instructions — general vectorisation')
    return '; '.join(parts)


def _propagate_register(insns, blr_idx: int, target_reg: int, depth: int) -> dict:
    """Walk backward from blr_idx tracking writes to target_reg."""
    result = {'method': 'unresolved'}

    for j in range(blr_idx - 1, max(-1, blr_idx - depth - 1), -1):
        prev = insns[j]
        if not prev.operands:
            continue
        dst_op = prev.operands[0]
        if dst_op.type != ARM64_OP_REG or dst_op.reg != target_reg:
            continue

        mnem = prev.mnemonic
        ops  = prev.operands

        # ADRP+ADD => code-segment function pointer
        if mnem == 'add' and len(ops) >= 3 and ops[2].type == ARM64_OP_IMM:
            page = _resolve_adrp_page(insns, j, ops[1].reg)
            if page is not None:
                return {
                    'method':    'adrp+add (code ptr)',
                    'value':     hex(page + ops[2].imm),
                    'insn_addr': prev.address,
                }

        # ADRP+LDR => GOT slot
        if mnem == 'ldr' and len(ops) >= 2 and ops[1].type == ARM64_OP_MEM:
            base_r = ops[1].mem.base
            disp   = ops[1].mem.disp
            page   = _resolve_adrp_page(insns, j, base_r)
            if page is not None:
                got_addr = page + disp
                return {
                    'method':    'adrp+ldr (GOT)',
                    'got_entry': hex(got_addr),
                    'value':     None,  # need symbol map to resolve
                    'insn_addr': prev.address,
                }

        # MOV Xn, Xm => alias; recurse one level
        if mnem == 'mov' and len(ops) >= 2 and ops[1].type == ARM64_OP_REG:
            return _propagate_register(insns, j, ops[1].reg, depth - 1)

        # MOVZ / MOVK with immediate
        if mnem in ('movz', 'movk') and len(ops) >= 2 and ops[1].type == ARM64_OP_IMM:
            return {
                'method':    'movz/movk immediate',
                'value':     hex(ops[1].imm),
                'insn_addr': prev.address,
            }

        # Any other write to target_reg stops the search
        break

    return result


def _resolve_adrp_page(insns, from_idx: int, base_reg: int):
    """Find the ADRP that last wrote to base_reg before from_idx."""
    if not HAS_CAPSTONE or ARM64_OP_REG is None:
        return None
    for j in range(from_idx - 1, max(-1, from_idx - 12), -1):
        prev = insns[j]
        if prev.mnemonic != "adrp" or not prev.operands:
            continue
        ops = prev.operands
        if (ops[0].type == ARM64_OP_REG and ops[0].reg == base_reg and
                len(ops) >= 2 and ops[1].type == ARM64_OP_IMM):
            return ops[1].imm
    return None


def _build_reg_map():
    """Build reg_id -> name map from capstone constants at module load time."""
    if not HAS_CAPSTONE:
        return {}
    try:
        from capstone.arm64_const import (
            ARM64_REG_X0, ARM64_REG_X1, ARM64_REG_X2, ARM64_REG_X3,
            ARM64_REG_X4, ARM64_REG_X5, ARM64_REG_X6, ARM64_REG_X7,
            ARM64_REG_X8, ARM64_REG_X9, ARM64_REG_X10, ARM64_REG_X11,
            ARM64_REG_X12, ARM64_REG_X13, ARM64_REG_X14, ARM64_REG_X15,
            ARM64_REG_X16, ARM64_REG_X17, ARM64_REG_X18, ARM64_REG_X19,
            ARM64_REG_X20, ARM64_REG_X21, ARM64_REG_X22, ARM64_REG_X23,
            ARM64_REG_X24, ARM64_REG_X25, ARM64_REG_X26, ARM64_REG_X27,
            ARM64_REG_X28, ARM64_REG_X29, ARM64_REG_X30,
        )
        return {
            ARM64_REG_X0: 'x0',   ARM64_REG_X1: 'x1',   ARM64_REG_X2: 'x2',
            ARM64_REG_X3: 'x3',   ARM64_REG_X4: 'x4',   ARM64_REG_X5: 'x5',
            ARM64_REG_X6: 'x6',   ARM64_REG_X7: 'x7',   ARM64_REG_X8: 'x8',
            ARM64_REG_X9: 'x9',   ARM64_REG_X10: 'x10', ARM64_REG_X11: 'x11',
            ARM64_REG_X12: 'x12', ARM64_REG_X13: 'x13', ARM64_REG_X14: 'x14',
            ARM64_REG_X15: 'x15', ARM64_REG_X16: 'x16', ARM64_REG_X17: 'x17',
            ARM64_REG_X18: 'x18', ARM64_REG_X19: 'x19', ARM64_REG_X20: 'x20',
            ARM64_REG_X21: 'x21', ARM64_REG_X22: 'x22', ARM64_REG_X23: 'x23',
            ARM64_REG_X24: 'x24', ARM64_REG_X25: 'x25', ARM64_REG_X26: 'x26',
            ARM64_REG_X27: 'x27', ARM64_REG_X28: 'x28',
            ARM64_REG_X29: 'x29', ARM64_REG_X30: 'x30',
        }
    except ImportError:
        return {}

_REG_MAP = _build_reg_map()


def _reg_name(reg_id: int) -> str:
    """Convert capstone ARM64 register id to human-readable name."""
    return _REG_MAP.get(reg_id, f'reg_{reg_id}')


def _is_zero_reg(reg_id: int) -> bool:
    """True if reg_id is XZR or WZR (the ARM64 zero register, always reads 0).

    XZR/WZR share encoding 31 with SP in instructions, but capstone assigns
    them distinct IDs so they can be distinguished from SP in memory operands.
    Writes to XZR are discarded; reads return 0 — used for bulk zeroing.
    """
    if not HAS_CAPSTONE or ARM64_REG_XZR is None:
        return False
    return reg_id in (ARM64_REG_XZR, ARM64_REG_WZR)


def _classify_msgsend_variant(name: str) -> str:
    """Return the ObjC msgSend variant for a symbol name."""
    if '_stret' in name:    return 'struct_return'   # struct in memory, X8=ptr
    if '_fpret' in name:    return 'float_return'    # float/double return
    if 'Super' in name:     return 'super_send'
    if '_retain' in name:   return 'retain'
    if '_release' in name:  return 'release'
    if '_msgSend' in name:  return 'standard'
    return 'unknown'


# ── Public API ────────────────────────────────────────────────────────────────

def analyze_arm64_binary(filepath: str, platform: str = 'auto') -> dict:
    """Analyze an ARM64 binary file."""
    data = Path(filepath).read_bytes()

    base = 0
    detected_platform = platform

    if data[:4] in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe'):  # Mach-O magic
        base = 0x100000000  # Standard macOS arm64 PIE load address
        if platform == 'auto':
            detected_platform = 'darwin'
    elif data[:4] == b'\x7fELF':
        if platform == 'auto':
            detected_platform = 'linux'

    analyzer = ARM64Analyzer(data, base_addr=base)
    return analyzer.analyze(platform=detected_platform)


if __name__ == '__main__':
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: arm64_analyzer.py <binary> [base_addr_hex] [darwin|linux]")
        sys.exit(1)

    fpath    = sys.argv[1]
    base     = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0
    platform = sys.argv[3] if len(sys.argv) > 3 else 'auto'

    data = Path(fpath).read_bytes()
    ana  = ARM64Analyzer(data, base_addr=base)
    result = ana.analyze(platform=platform)
    print(json.dumps(result, indent=2, default=str))
