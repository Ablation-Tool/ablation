"""
TencentOS / OpenCloudOS netatop Kernel Module RE
Source: /media/cowboy/research/tencentos-kernel/opencloudos-5.4.119/kernel/tkernel/netatop/netatop.c
Module version: netatopversion.h -> "0.7"
Analysis date: 2026-09-04

netatop is a GPL kernel module originally by Gerlof Langeveld (gerlof.langeveld@atoptool.nl)
included in Tencent's OpenCloudOS/TencentLinux TK4 (5.4.119) kernel.

Purpose: per-task (thread-group / thread) network accounting via netfilter hooks.
Interface: getsockopt() on IPPROTO_IP socket with 5 command codes.
  NETATOP_PROBE            — probe module presence
  NETATOP_FORCE_GC         — trigger garbage collection
  NETATOP_EMPTY_EXIT       — block until exitlist empty
  NETATOP_GETCNT_EXIT      — consume one exited-process record
  NETATOP_GETCNT_TGID/PID  — read live process/thread network counters
Access gate: CAP_NET_ADMIN required (getsockopt handler L1518).
  Containers with NET_ADMIN capability (docker run --cap-add=NET_ADMIN) can reach this.

Architecture:
  sockinfo structs — per-socket, keyed by (proto, local/remote addr/port)
    kmem_cache: sicache; SILIMIT = 4MB total
    chained in shash[SBUCKS=1024] — per-bucket spinlock shash[i].lock
    refs: sip->tgp = *taskinfo (thread group), sip->thp = *taskinfo (thread)

  taskinfo structs — per-process / per-thread
    kmem_cache: ticache; TILIMIT = 2MB total
    chained in thash[TBUCKS=1024] — per-bucket spinlock thash[i].lock
    state: CHECKED / INDELETE / FINISHED
    exitlist: singly-linked list; exithead/exittail; exitlock spinlock; nre counter

  Garbage collector: mutex gclock; max 2 cycles/sec
    gctaskexit() -> clears stale FINISHED entries (15-second timeout)
    gcsockinfo()  -> validates socket liveness
    gctaskinfo()  -> moves exited tasks to exitlist

  Wakeup queues:
    exitlist_filled — woken by move_taskinfo() when task moves to exitlist
    exitlist_empty  — woken by gctaskexit() when nre drops to 0 (L1039)

Analysis method: source code audit (netatop.c + netatop.h + netatopversion.h); 1793 lines.
"""

SOURCE_FILE = (
    "/media/cowboy/research/tencentos-kernel/opencloudos-5.4.119/"
    "kernel/tkernel/netatop/netatop.c"
)

IOCTL_INTERFACE = {
    "NETATOP_PROBE":       {"cmd": "getsockopt via IPPROTO_IP", "privilege": "CAP_NET_ADMIN"},
    "NETATOP_FORCE_GC":    {"cmd": "trigger GC", "privilege": "CAP_NET_ADMIN"},
    "NETATOP_EMPTY_EXIT":  {"cmd": "block until exitlist empty", "privilege": "CAP_NET_ADMIN"},
    "NETATOP_GETCNT_EXIT": {"cmd": "consume one exited-process record", "privilege": "CAP_NET_ADMIN"},
    "NETATOP_GETCNT_TGID": {"cmd": "read tgid counters", "privilege": "CAP_NET_ADMIN"},
    "NETATOP_GETCNT_PID":  {"cmd": "read thread counters", "privilege": "CAP_NET_ADMIN"},
}

FINDINGS = {
    "NETATOP-F01": {
        "title": (
            "Missing exitlist_empty Wake After GETCNT_EXIT Consumes Last Exit Entry; "
            "NETATOP_EMPTY_EXIT Waiters Block Up to 15 Seconds Post-Consumption"
        ),
        "severity": "LOW",
        "cvss": "2.3",
        "cvss_vector": "AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L",
        "cwe": "CWE-362",
        "component": "netatop.c:1572 (nre-- in NETATOP_GETCNT_EXIT without exitlist_empty wake)",
        "description": (
            "The NETATOP_GETCNT_EXIT getsockopt handler consumes one taskinfo entry from "
            "the exitlist and decrements nre at L1572. If nre drops to 0 after this decrement, "
            "no wake_up_interruptible(&exitlist_empty) is called. "
            "\n"
            "Waiters blocked in NETATOP_EMPTY_EXIT (which waits on `exitlist_empty` until "
            "nre == 0) are not notified when GETCNT_EXIT drains the list. They remain blocked "
            "for up to 15 seconds, until the knetatop GC thread cycles and gctaskexit() "
            "reaches its nre == 0 check (L1037-1039) and issues the wake. "
            "\n"
            "The compensating wake at L1540-1541 fires on entry to GETCNT_EXIT when the "
            "lockless nre read happens to observe nre == 0. This cannot wake EMPTY_EXIT "
            "waiters who started waiting AFTER the last entry was consumed. "
            "\n"
            "Required context: gctaskexit() does issue the wake at L1039, but only when "
            "the GC runs (maximum 2 cycles/sec, period ~15 seconds for the knetatop thread). "
            "The correct fix: add if (nre == 0) wake_up_interruptible(&exitlist_empty) "
            "immediately after L1572 while still holding exitlock."
        ),
        "reproduce": (
            "1. Open CAP_NET_ADMIN socket, issue NETATOP_EMPTY_EXIT to block Thread A "
            "   (nre > 0 from prior process exits). "
            "2. Issue NETATOP_GETCNT_EXIT from Thread B to consume the last exit entry. "
            "3. Thread A remains blocked for up to 15 seconds despite nre == 0. "
            "4. Thread A unblocks only on next knetatop GC cycle."
        ),
        "chain": (
            "CAP_NET_ADMIN process issues GETCNT_EXIT draining all exits → "
            "EMPTY_EXIT monitor misses the signal → monitoring loop stalls for 15s → "
            "per-process exit accounting data silently delayed"
        ),
        "line_refs": {
            "nre_decrement_no_wake": "L1572 (nre--; spin_unlock)",
            "compensating_lockless_wake": "L1540-1541 (if (nre == 0) wake_up_interruptible(&exitlist_empty))",
            "correct_gc_wake": "L1037-1039 (gctaskexit only)",
            "waiter_location": "L1533-1536 (wait_event_interruptible(exitlist_empty, nre == 0))",
        },
        "fix": "After L1572 (nre--), while still holding exitlock: if (nre == 0) wake_up_interruptible(&exitlist_empty);",
        "access_constraint": "CAP_NET_ADMIN required (getsockopt handler L1518)",
    },
    "NETATOP-F02": {
        "title": (
            "Lockless nre Read in GETCNT_EXIT Before Acquiring exitlock; "
            "Spurious exitlist_empty Wake May Fire on Stale Counter"
        ),
        "severity": "LOW",
        "cvss": "1.9",
        "cvss_vector": "AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:L",
        "cwe": "CWE-362",
        "component": "netatop.c:1540 (if (nre == 0) before spin_lock_irqsave(&exitlock))",
        "description": (
            "At L1540 in the NETATOP_GETCNT_EXIT case, `nre` is read without holding `exitlock`. "
            "The `nre` counter is exclusively protected by `exitlock` in all other paths "
            "(move_taskinfo L1427, gctaskexit L1029, the while-loop at L1555 re-checks under lock). "
            "\n"
            "On x86, single-word reads are naturally atomic, so no torn value is possible. "
            "On other architectures with weaker memory ordering, a stale nre value is visible. "
            "\n"
            "When this lockless read observes nre == 0, wake_up_interruptible(&exitlist_empty) "
            "fires at L1541. If the actual protected nre is 1 (read was stale), "
            "any NETATOP_EMPTY_EXIT waiters wake and re-check their condition "
            "(wait_event_interruptible uses the condition expression under lock) — they would "
            "immediately re-block if nre > 0. This is a spurious wakeup, handled correctly "
            "by the wait_event_interruptible pattern, but is a logic error. "
            "\n"
            "On x86 in practice: TOCTOU window between nre check (L1540) and exitlock "
            "acquisition (L1549) — nre could change value from the time of the check."
        ),
        "line_refs": {
            "lockless_read": "L1540 (if (nre == 0) — no exitlock held)",
            "exitlock_acquire": "L1549 (spin_lock_irqsave(&exitlock, tflags))",
            "correct_protected_reads": "L1555 (while (nre == 0) — under exitlock)",
        },
        "fix": "Remove the L1540-1541 early-exit wake or move it inside the exitlock critical section.",
        "access_constraint": "CAP_NET_ADMIN required",
    },
    "NETATOP-F03": {
        "title": (
            "netatop getsockopt Interface Reachable via Container CAP_NET_ADMIN; "
            "All Five Commands (Including Forced GC, Process Exit Data, Task Counter Reads) "
            "Accessible to Container with NET_ADMIN Capability"
        ),
        "severity": "MEDIUM",
        "cvss": "5.5",
        "cvss_vector": "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-732",
        "component": "netatop.c:1518 (CAP_NET_ADMIN check; container NET_ADMIN passes)",
        "description": (
            "The netatop getsockopt interface is gated on CAP_NET_ADMIN (L1518). "
            "In container environments, a container granted CAP_NET_ADMIN (docker run "
            "--cap-add=NET_ADMIN, or a Kubernetes pod with securityContext.capabilities: "
            "[NET_ADMIN]) can invoke all netatop commands, including: "
            "\n"
            "NETATOP_GETCNT_TGID/PID: read per-process network byte/packet counters for ANY "
            "process on the host by pid/tgid — bypasses cgroup network isolation. "
            "This leaks host process traffic data to a container process. "
            "\n"
            "NETATOP_GETCNT_EXIT: read process name (command), start time, and network "
            "counters for recently-exited processes across the ENTIRE host. "
            "A container can enumerate host process lifecycle events (process names, timing). "
            "\n"
            "NETATOP_FORCE_GC: force kernel memory cleanup, potentially disrupting host "
            "monitoring tools that read netatop data (atop). "
            "\n"
            "The module does not apply any namespace or cgroup filtering — all taskinfos "
            "are keyed by host pid/tgid. Container processes with NET_ADMIN see the "
            "full host process namespace through this interface."
        ),
        "chain": (
            "Container with CAP_NET_ADMIN (common in CI/CD, network-function containers) → "
            "NETATOP_GETCNT_EXIT iterates recently-exited host processes → "
            "host process names + network counters leaked to container → "
            "NETATOP_GETCNT_TGID enumerates live host process traffic → "
            "combined: container escapes into host process monitoring visibility"
        ),
        "remediation": (
            "Add pid_namespace check: if (!task_active_pid_ns(current)->parent) return -EPERM. "
            "Or add user_ns check to restrict to the initial user namespace. "
            "Alternatively, add config option to disable netatop at build time for "
            "container-hosting workloads."
        ),
        "access_constraint": "CAP_NET_ADMIN in any namespace; containers commonly granted this",
    },
}


SOURCE_ANALYSIS = {
    "getsockopt_entry": {"line": 1507, "note": "entry point for all netatop commands"},
    "cap_check":        {"line": 1518, "note": "!capable(CAP_NET_ADMIN) → -EPERM"},
    "getcnt_exit_entry":{"line": 1539, "note": "NETATOP_GETCNT_EXIT case start"},
    "lockless_nre_check":{"line": 1540, "note": "if (nre == 0) — no exitlock (F02)"},
    "spurious_wake":    {"line": 1541, "note": "wake_up_interruptible(&exitlist_empty) — spurious (F02)"},
    "exitlock_acquire": {"line": 1549, "note": "spin_lock_irqsave(&exitlock) — lock acquired here"},
    "nre_decrement":    {"line": 1572, "note": "nre-- after consuming exit entry — no wake after (F01)"},
    "missing_wake":     {"line": 1572, "note": "should call wake_up_interruptible(&exitlist_empty) if nre==0"},
    "move_taskinfo":    {"line": 1397, "note": "correct wake: L1429 wakes exitlist_filled"},
    "gctaskexit_wake":  {"line": 1039, "note": "correct wake: L1039 wakes exitlist_empty — only in GC"},
    "comlen":           {"line": 145, "note": "command[COMLEN=16] == TASK_COMM_LEN; strncpy safe at L971"},
}


def get_findings():
    return FINDINGS


if __name__ == "__main__":
    import json
    print(json.dumps({
        "module": "netatop.c v0.7",
        "source": SOURCE_FILE,
        "lines": 1793,
        "interface": "getsockopt IPPROTO_IP",
        "access_gate": "CAP_NET_ADMIN",
        "findings": [
            {"id": k, "severity": v["severity"], "title": v["title"][:80]}
            for k, v in FINDINGS.items()
        ],
    }, indent=2))
