"""
syscall_loongarch64.py: LoongArch64 Linux syscall ABI classification.

ABI (lp64, Linux asm-generic unistd.h):
  $a7: syscall number  (loaded before syscall instruction)
  $a0–$a5: arguments   (up to 6)
  $a0: return value    (negative = -errno)

Syscall numbers match the asm-generic/unistd.h table used by all
LoongArch Linux builds (kernel 5.x+). LoongArch does NOT have a
custom syscall table — it uses the generic ABI directly.

Source: linux/arch/loongarch/include/uapi/asm/unistd.h
        linux/include/uapi/asm-generic/unistd.h (6.6 kernel)
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

# ---------------------------------------------------------------------------
# Syscall number -> name (asm-generic/unistd.h, Linux 6.6)
# ---------------------------------------------------------------------------

SYSCALL_TABLE: Dict[int, str] = {
    0:   "io_setup",
    1:   "io_destroy",
    2:   "io_submit",
    3:   "io_cancel",
    4:   "io_getevents",
    5:   "setxattr",
    6:   "lsetxattr",
    7:   "fsetxattr",
    8:   "getxattr",
    9:   "lgetxattr",
    10:  "fgetxattr",
    11:  "listxattr",
    12:  "llistxattr",
    13:  "flistxattr",
    14:  "removexattr",
    15:  "lremovexattr",
    16:  "fremovexattr",
    17:  "getcwd",
    18:  "lookup_dcookie",
    19:  "eventfd2",
    20:  "epoll_create1",
    21:  "epoll_ctl",
    22:  "epoll_pwait",
    23:  "dup",
    24:  "dup3",
    25:  "fcntl",
    26:  "inotify_init1",
    27:  "inotify_add_watch",
    28:  "inotify_rm_watch",
    29:  "ioctl",
    30:  "ioprio_set",
    31:  "ioprio_get",
    32:  "flock",
    33:  "mknodat",
    34:  "mkdirat",
    35:  "unlinkat",
    36:  "symlinkat",
    37:  "linkat",
    38:  "renameat",
    39:  "umount2",
    40:  "mount",
    41:  "pivot_root",
    42:  "nfsservctl",
    43:  "statfs",
    44:  "fstatfs",
    45:  "truncate",
    46:  "ftruncate",
    47:  "fallocate",
    48:  "faccessat",
    49:  "chdir",
    50:  "fchdir",
    51:  "chroot",
    52:  "fchmod",
    53:  "fchmodat",
    54:  "fchownat",
    55:  "fchown",
    56:  "openat",
    57:  "close",
    58:  "vhangup",
    59:  "pipe2",
    60:  "quotactl",
    61:  "getdents64",
    62:  "lseek",
    63:  "read",
    64:  "write",
    65:  "readv",
    66:  "writev",
    67:  "pread64",
    68:  "pwrite64",
    69:  "preadv",
    70:  "pwritev",
    71:  "sendfile",
    72:  "pselect6",
    73:  "ppoll",
    74:  "signalfd4",
    75:  "vmsplice",
    76:  "splice",
    77:  "tee",
    78:  "readlinkat",
    79:  "newfstatat",
    80:  "fstat",
    81:  "sync",
    82:  "fsync",
    83:  "fdatasync",
    84:  "sync_file_range",
    85:  "timerfd_create",
    86:  "timerfd_settime",
    87:  "timerfd_gettime",
    88:  "utimensat",
    89:  "acct",
    90:  "capget",
    91:  "capset",
    92:  "personality",
    93:  "exit",
    94:  "exit_group",
    95:  "waitid",
    96:  "set_tid_address",
    97:  "unshare",
    98:  "futex",
    99:  "set_robust_list",
    100: "get_robust_list",
    101: "nanosleep",
    102: "getitimer",
    103: "setitimer",
    104: "kexec_load",
    105: "init_module",
    106: "delete_module",
    107: "timer_create",
    108: "timer_gettime",
    109: "timer_getoverrun",
    110: "timer_settime",
    111: "timer_delete",
    112: "clock_settime",
    113: "clock_gettime",
    114: "clock_getres",
    115: "clock_nanosleep",
    116: "syslog",
    117: "ptrace",
    118: "sched_setparam",
    119: "sched_setscheduler",
    120: "sched_getscheduler",
    121: "sched_getparam",
    122: "sched_setaffinity",
    123: "sched_getaffinity",
    124: "sched_yield",
    125: "sched_get_priority_max",
    126: "sched_get_priority_min",
    127: "sched_rr_get_interval",
    128: "restart_syscall",
    129: "kill",
    130: "tkill",
    131: "tgkill",
    132: "sigaltstack",
    133: "rt_sigsuspend",
    134: "rt_sigaction",
    135: "rt_sigprocmask",
    136: "rt_sigpending",
    137: "rt_sigtimedwait",
    138: "rt_sigqueueinfo",
    139: "rt_sigreturn",
    140: "setpriority",
    141: "getpriority",
    142: "reboot",
    143: "setregid",
    144: "setgid",
    145: "setreuid",
    146: "setuid",
    147: "setresuid",
    148: "getresuid",
    149: "setresgid",
    150: "getresgid",
    151: "setfsuid",
    152: "setfsgid",
    153: "times",
    154: "setpgid",
    155: "getpgid",
    156: "getsid",
    157: "setsid",
    158: "getgroups",
    159: "setgroups",
    160: "newuname",
    161: "sethostname",
    162: "setdomainname",
    163: "getrlimit",
    164: "setrlimit",
    165: "getrusage",
    166: "umask",
    167: "prctl",
    168: "getcpu",
    169: "gettimeofday",
    170: "settimeofday",
    171: "adjtimex",
    172: "getpid",
    173: "getppid",
    174: "getuid",
    175: "geteuid",
    176: "getgid",
    177: "getegid",
    178: "gettid",
    179: "sysinfo",
    180: "mq_open",
    181: "mq_unlink",
    182: "mq_timedsend",
    183: "mq_timedreceive",
    184: "mq_notify",
    185: "mq_getsetattr",
    186: "msgget",
    187: "msgctl",
    188: "msgrcv",
    189: "msgsnd",
    190: "semget",
    191: "semctl",
    192: "semtimedop",
    193: "semop",
    194: "shmget",
    195: "shmctl",
    196: "shmat",
    197: "shmdt",
    198: "socket",
    199: "socketpair",
    200: "bind",
    201: "listen",
    202: "accept",
    203: "connect",
    204: "getsockname",
    205: "getpeername",
    206: "sendto",
    207: "recvfrom",
    208: "setsockopt",
    209: "getsockopt",
    210: "shutdown",
    211: "sendmsg",
    212: "recvmsg",
    213: "readahead",
    214: "brk",
    215: "munmap",
    216: "mremap",
    217: "add_key",
    218: "request_key",
    219: "keyctl",
    220: "clone",
    221: "execve",
    222: "mmap",
    223: "fadvise64",
    224: "swapon",
    225: "swapoff",
    226: "mprotect",
    227: "msync",
    228: "mlock",
    229: "munlock",
    230: "mlockall",
    231: "munlockall",
    232: "mincore",
    233: "madvise",
    234: "remap_file_pages",
    235: "mbind",
    236: "get_mempolicy",
    237: "set_mempolicy",
    238: "migrate_pages",
    239: "move_pages",
    240: "rt_tgsigqueueinfo",
    241: "perf_event_open",
    242: "accept4",
    243: "recvmmsg",
    244: "arch_specific_syscall",
    258: "riscv_flush_icache",  # LoongArch may map this differently; placeholder
    260: "wait4",
    261: "prlimit64",
    262: "fanotify_init",
    263: "fanotify_mark",
    264: "name_to_handle_at",
    265: "open_by_handle_at",
    266: "clock_adjtime",
    267: "syncfs",
    268: "setns",
    269: "sendmmsg",
    270: "process_vm_readv",
    271: "process_vm_writev",
    272: "kcmp",
    273: "finit_module",
    274: "sched_setattr",
    275: "sched_getattr",
    276: "renameat2",
    277: "seccomp",
    278: "getrandom",
    279: "memfd_create",
    280: "bpf",
    281: "execveat",
    282: "userfaultfd",
    283: "membarrier",
    284: "mlock2",
    285: "copy_file_range",
    286: "preadv2",
    287: "pwritev2",
    288: "pkey_mprotect",
    289: "pkey_alloc",
    290: "pkey_free",
    291: "statx",
    292: "io_pgetevents",
    293: "rseq",
    294: "kexec_file_load",
    424: "pidfd_send_signal",
    425: "io_uring_setup",
    426: "io_uring_enter",
    427: "io_uring_register",
    428: "open_tree",
    429: "move_mount",
    430: "fsopen",
    431: "fsconfig",
    432: "fsmount",
    433: "fspick",
    434: "pidfd_open",
    435: "clone3",
    436: "close_range",
    437: "openat2",
    438: "pidfd_getfd",
    439: "faccessat2",
    440: "process_madvise",
    441: "epoll_pwait2",
    442: "mount_setattr",
    443: "quotactl_fd",
    444: "landlock_create_ruleset",
    445: "landlock_add_rule",
    446: "landlock_restrict_self",
    448: "process_mrelease",
    449: "futex_waitv",
    450: "set_mempolicy_home_node",
    451: "cachestat",
    452: "fchmodat2",
    453: "map_shadow_stack",
    454: "futex_wake",
    455: "futex_wait",
    456: "futex_requeue",
    457: "statmount",
    458: "listmount",
    459: "lsm_get_self_attr",
    460: "lsm_set_self_attr",
    461: "lsm_list_modules",
}

# ---------------------------------------------------------------------------
# Security classification
# ---------------------------------------------------------------------------

# Syscalls that introduce attacker-controlled data into $a0 on return.
# label: the taint source label applied to the return value.
SYSCALL_SOURCES: Dict[str, str] = {
    "read":         "syscall:read",
    "pread64":      "syscall:pread64",
    "readv":        "syscall:read",
    "preadv":       "syscall:read",
    "preadv2":      "syscall:read",
    "recvfrom":     "syscall:network",
    "recvmsg":      "syscall:network",
    "recvmmsg":     "syscall:network",
    "getdents64":   "syscall:fs",
    "getxattr":     "syscall:fs",
    "fgetxattr":    "syscall:fs",
    "lgetxattr":    "syscall:fs",
    "readlinkat":   "syscall:fs",
    "getcwd":       "syscall:fs",
    "getsockopt":   "syscall:network",
    "getpeername":  "syscall:network",
    "getsockname":  "syscall:network",
    "process_vm_readv": "syscall:process_mem",
    "getrandom":    "syscall:rng",
}

# Syscalls that consume user-controlled data in $a0–$a5 as a dangerous sink.
# value: severity string
SYSCALL_SINKS: Dict[str, str] = {
    "execve":    "CRITICAL",
    "execveat":  "CRITICAL",
    "write":     "HIGH",
    "writev":    "HIGH",
    "pwrite64":  "HIGH",
    "sendto":    "HIGH",
    "sendmsg":   "HIGH",
    "sendmmsg":  "HIGH",
    "mmap":      "HIGH",
    "mprotect":  "HIGH",
    "ptrace":    "CRITICAL",
    "process_vm_writev": "CRITICAL",
    "bpf":       "CRITICAL",
    "clone":     "HIGH",
    "clone3":    "HIGH",
    "kexec_load": "CRITICAL",
    "kexec_file_load": "CRITICAL",
    "init_module": "CRITICAL",
    "finit_module": "CRITICAL",
    "delete_module": "HIGH",
}

# Syscalls that escalate privileges (always CRITICAL).
SYSCALL_ESCALATION: frozenset = frozenset({
    "setuid", "setgid", "setresuid", "setresgid",
    "setreuid", "setregid", "setfsuid", "setfsgid",
    "setgroups", "capset", "prctl",
})

# Kernel-space function sources (used in kernel modules).
# copy_from_user reads from user memory -> kernel buffer.
KERNEL_SOURCES: frozenset = frozenset({
    "copy_from_user", "__copy_from_user",
    "__copy_from_user_inatomic", "get_user", "__get_user",
    "strncpy_from_user", "strnlen_user",
    "nla_get_string", "nla_data",
    "nlmsg_data", "__nlmsg_put",
    "skb_get_data", "skb_pull_data",
    "memdup_user", "__memdup_user",
    "vmalloc_user", "kzalloc_user",
})

# Kernel-space function sinks.
KERNEL_SINKS: frozenset = frozenset({
    "copy_to_user", "__copy_to_user", "put_user", "__put_user",
    "call_usermodehelper", "call_usermodehelper_exec",
    "kernel_execve",
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "strcpy", "strcat", "memcpy",
    "kmalloc", "kzalloc", "vmalloc",  # size-controlled allocation
})

# Kernel privilege-escalation primitives (always CRITICAL in kernel context).
KERNEL_ESCALATION: frozenset = frozenset({
    "commit_creds",
    "prepare_kernel_cred",
    "set_current_cred",
    "override_creds",
    "__sys_setuid",
    "security_setuid",
})

# ---------------------------------------------------------------------------
# Classification API
# ---------------------------------------------------------------------------

def classify_syscall(num: int) -> Optional[Tuple[str, str]]:
    """
    Classify a syscall number.

    Returns (name, kind) where kind is one of:
      "source"     — introduces attacker-controlled data
      "sink"       — consumes data as a dangerous operation
      "escalation" — privilege escalation
    Returns None if unknown or unclassified.
    """
    name = SYSCALL_TABLE.get(num)
    if name is None:
        return None
    if name in SYSCALL_ESCALATION:
        return (name, "escalation")
    if name in SYSCALL_SINKS:
        return (name, "sink")
    if name in SYSCALL_SOURCES:
        return (name, "source")
    return None


def syscall_label(num: int) -> str:
    """Return the taint label for a source syscall number."""
    name = SYSCALL_TABLE.get(num, f"syscall_{num}")
    return SYSCALL_SOURCES.get(name, f"syscall:{name}")


def syscall_severity(num: int) -> str:
    """Return severity for a sink/escalation syscall number."""
    name = SYSCALL_TABLE.get(num, "")
    if name in SYSCALL_ESCALATION:
        return "CRITICAL"
    return SYSCALL_SINKS.get(name, "HIGH")
