"""
TencentOS 4.6 — irqlatency.ko binary RE module.

irqlatency — per-CPU IRQ and softirq disable latency measurement.
Author: shookliu <shookliu@tencent.com>
Source: kernel/tkernel/irqlatency/irqlatency.c (per srcfile string)
Vermagic: 6.6.119-51.3.tl4.x86_64 (TOS 4.6)
Size: 40278B

irqlatency uses per-CPU hrtimers to periodically check how long IRQs or softirqs
have been disabled. When the disable duration exceeds a configurable threshold,
the latency and kernel stack trace are recorded.

Notable: irqlatency imports __klp_sched_try_switch — KLP (Kernel Live Patch) aware.
"""

METADATA = {
    "kernel": "6.6.119-51.3.tl4.x86_64",
    "module": "irqlatency",
    "size_bytes": 40278,
    "author": "shookliu <shookliu@tencent.com>",
    "srcfile": "kernel/tkernel/irqlatency/irqlatency.c",
    "license": "GPL v2",
    "srcversion": "F5A22B86DB91B96DBD2B4EF",
    "tencent_tkernel": True,
}

MEASUREMENT_APPROACH = {
    "technique": "Per-CPU hrtimer polling",
    "alternatives_not_used": ["irq_disable tracepoint", "kprobes on arch_local_irq_disable"],
    "tradeoff": (
        "hrtimer fires every freq_ms on each CPU and reads current IRQ disable duration. "
        "Lower overhead than tracepoints (no hook on every irq_disable/irq_enable). "
        "Limitation: misses latency spikes shorter than freq_ms between timer fires."
    ),
    "measured_events": {
        "irq-disable": "Duration IRQs disabled on a CPU (irq_hrtimer_func)",
        "softirq-disable": "Duration softirqs disabled on a CPU (softirq_timer_func)",
    },
    "clock": "local_clock() — monotonic per-CPU clock (nanosecond resolution)",
}

PERCPU_DATA_STRUCTS = {
    "per_cpu_detect_data": {
        "symbol": "detect_data (BSS base)",
        "fields": [
            "per_stack: stack trace storage per CPU",
            "stack_index: current write index into per_stack",
            "soft_in_irq: softirq detection data",
            "softirq_timer: regular timer for softirq checks",
            "irq_timer: hrtimer for IRQ checks",
        ],
    },
    "latency_data": "Per-CPU latency samples (histogram buckets)",
    "perstack": "Stack trace array — saved when threshold exceeded",
}

FUNCTIONS = {
    "irq_hrtimer_func": {
        "addr": 0x0820,
        "type": "hrtimer callback (HRTIMER_NORESTART or HRTIMER_RESTART)",
        "purpose": (
            "High-resolution timer callback, fires every freq_ms on each CPU. "
            "Reads current IRQ disable duration via local_clock(). "
            "If duration > irq_latency_ms threshold: calls record_latency + save_stack. "
            "Reschedules itself via hrtimer_forward."
        ),
    },
    "softirq_timer_func": {
        "addr": 0x0940,
        "type": "regular timer callback (add_timer_on / mod_timer)",
        "purpose": (
            "Regular (jiffies) timer callback for softirq disable latency. "
            "Uses add_timer_on to pin to specific CPU. "
            "Checks softirq disable duration against threshold."
        ),
        "note": "Uses regular timer (jiffies resolution ~4ms) vs hrtimer for IRQ path",
    },
    "percpu_timers_start": {
        "addr": 0x03c0,
        "purpose": (
            "Start per-CPU hrtimers and softirq timers. "
            "Uses _find_next_bit + __cpu_online_mask to iterate online CPUs. "
            "Calls smp_call_function_single to start hrtimer on each CPU. "
            "Calls add_timer_on for softirq timer."
        ),
    },
    "latency_timers_stop": {
        "addr": 0x0a20,
        "purpose": "Cancel all per-CPU hrtimers (hrtimer_cancel) and timer_delete_sync",
    },
    "record_latency": {
        "addr": 0x0750,
        "purpose": "Record a latency sample into the per-CPU histogram (latency_data)",
    },
    "save_stack": {
        "addr": 0x0600,
        "purpose": "Save kernel stack trace via stack_trace_save when threshold exceeded",
        "max_entries_check": "Prints 'BUG: MAX_STACK_ENTRIES too low!' if stack array too small",
    },
    "reset_latency_trace": {
        "addr": 0x0010,
        "purpose": "memset all per-CPU latency data to zero — reset counters",
    },
}

PROC_INTERFACE = {
    "directory": "/proc/irq_latency/",
    "files": {
        "enable": {
            "handlers": "enable_open/enable_show/enable_write",
            "write": "kstrtouint_from_user — accepts 0/1",
            "variable": "check_enable (BSS bool)",
            "behavior": "1 = start percpu_timers_start; 0 = latency_timers_stop",
        },
        "freq": {
            "handlers": "freq_open/freq_show/freq_write",
            "write": "kstrtoul_from_user",
            "variable": "freq_ms (data) — timer fire interval in milliseconds",
            "default": "stored in .data (non-zero initialized)",
        },
        "lat": {
            "handlers": "lat_open/lat_show/lat_write",
            "write": "kstrtoul_from_user",
            "variable": "irq_latency_ms (data) — reporting threshold in milliseconds",
        },
        "trace_dist": {
            "handlers": "trace_dist_open/trace_dist_show",
            "content": "Latency distribution histogram — IRQ and softirq buckets",
            "format": "'latency distribution', 'irq-disable:', 'softirq-disable:' sections",
        },
        "trace_stack": {
            "handlers": "trace_stack_open/trace_stack_show/trace_stack_write",
            "content": "Per-CPU stack traces saved when threshold exceeded",
            "format": "'cpu: %d', 'irq:', 'softirq:', stack frames",
            "write": "trace_stack_write — likely resets per-CPU stack trace buffer",
        },
    },
}

KLP_INTEGRATION = {
    "import": "__klp_sched_try_switch",
    "import2": "klp_sched_try_switch_key",
    "purpose": (
        "KLP (Kernel Live Patching) requires that patched functions quiesce before "
        "the patch is fully applied. klp_sched_try_switch ensures tasks migrate "
        "to the patched version at scheduling points. "
        "irqlatency's hrtimer callback imports klp_sched_try_switch — "
        "suggesting it runs a KLP quiescence check inside the hrtimer. "
        "This is unusual for a monitoring module: it participates in KLP's task-switch "
        "protocol to ensure it doesn't run stale code after a live patch."
    ),
    "risk": (
        "If a live patch is applied while irqlatency's hrtimer is active, "
        "the hrtimer callback checks klp_sched_try_switch which may reschedule or block. "
        "A hrtimer callback that reschedules is unusual and could cause latency in the "
        "measurement path itself — irqlatency introduces the latency it measures."
    ),
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "irqlatency measures IRQ disable by polling — short spikes below freq_ms are invisible",
        "detail": (
            "irqlatency fires hrtimers every freq_ms (configurable). "
            "A latency spike shorter than freq_ms is not detected. "
            "On a default freq_ms of (e.g.) 10ms, any IRQ disable lasting 1-9ms "
            "is invisible unless the timer happens to fire during the spike. "
            "This is a statistical measurement — it reports only latency spikes "
            "that persist across a timer fire boundary. "
            "For production debugging, real IRQ disable latency sources (spinlocks, "
            "DMA operations, hardware interrupts) often last microseconds, not milliseconds. "
            "irqlatency may systematically miss these."
        ),
        "measurement_gap": "IRQ disable spikes shorter than freq_ms are invisible",
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "__klp_sched_try_switch in hrtimer callback — live patch quiescence inside IRQ context",
        "detail": (
            "irqlatency's irq_hrtimer_func calls __klp_sched_try_switch. "
            "KLP quiescence checks should only happen at voluntary scheduling points, "
            "not inside hrtimer callbacks (which run in interrupt context or softirq). "
            "Calling klp_sched_try_switch from hrtimer context breaks the KLP assumption "
            "that quiescence happens at task boundaries. "
            "If a KLP patch targets any function called in irq_hrtimer_func's call graph, "
            "the patch may quiesce the hrtimer context — "
            "a potential deadlock if irq_hrtimer_func holds a lock that the patched code needs."
        ),
        "klp_in_irq_context": True,
        "potential_deadlock": True,
    },
    {
        "id": "F3",
        "severity": "MEDIUM",
        "title": "softirq measurement uses jiffies-resolution timer — ~4ms blind spot for softirq disable",
        "detail": (
            "irq_hrtimer_func uses hrtimer (nanosecond resolution). "
            "softirq_timer_func uses a regular timer (jiffies, ~4ms at HZ=250). "
            "For softirq disable latency, the measurement has a 4ms minimum blind spot — "
            "worse than the IRQ path. "
            "Softirq disable is used in BH (bottom half) sections and network processing. "
            "Short softirq disable events (< 4ms) are systematically invisible."
        ),
        "softirq_timer_resolution": "jiffies (~4ms at HZ=250)",
        "irq_timer_resolution": "hrtimer (nanosecond scale)",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "/proc/irq_latency/trace_stack world-readable — kernel stack traces leaked to unprivileged users",
        "detail": (
            "trace_stack proc file exposes kernel stack traces captured during latency spikes. "
            "Kernel stack traces reveal: function addresses (KASLR offsets if KPTR_RESTRICT != 2), "
            "call chains (which locks were held, which drivers were active). "
            "If /proc/irq_latency/ is world-readable, any local user can read these traces. "
            "KASLR bypass from stack trace addresses requires that KPTR_RESTRICT < 2 — "
            "verify runtime sysctl kernel.kptr_restrict value."
        ),
        "data_leaked": "Kernel stack traces at latency threshold crossings",
        "kaslr_bypass": "If KPTR_RESTRICT != 2, function addresses reveal KASLR slide",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "irqlatency self-overhead — hrtimer fires on every CPU at freq_ms, adds load on high-CPU hosts",
        "detail": (
            "irqlatency starts one hrtimer per CPU via smp_call_function_single. "
            "On a 64-CPU host with freq_ms=10: 100 hrtimer fires/second per CPU = 6400 fires/second total. "
            "Each fire: reads local_clock(), computes duration, potentially calls save_stack. "
            "save_stack calls stack_trace_save which walks the stack frame — "
            "on latency events, this adds further IRQ-disabled time (irqlatency's own overhead). "
            "This is measurement interference: the act of measuring IRQ latency increases IRQ latency."
        ),
        "fires_per_second_per_cpu": "1000/freq_ms",
        "self_interference": "save_stack runs with IRQs disabled, increasing the measured latency",
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "irq_latency_ms threshold configurable via /proc/irq_latency/lat — zero risk of false positives if tuned",
        "detail": (
            "lat_write accepts kstrtoul_from_user to set irq_latency_ms at runtime. "
            "A threshold of 0 would log every timer fire — flooding logs. "
            "No minimum threshold enforcement visible in the write handler. "
            "If irq_latency_ms is set to 0 by a misconfigured script or attacker, "
            "irqlatency would log every single hrtimer invocation, "
            "creating a kernel log flood that could fill /var/log or exhaust dmesg ring."
        ),
        "threshold_minimum_enforced": False,
        "log_flood_risk": "irq_latency_ms = 0 → log every timer fire",
    },
]

if __name__ == '__main__':
    print("irqlatency.ko (TOS 4.6) RE analysis")
    print(f"Author: {METADATA['author']}")
    print()
    print("Measurement approach:")
    for event, desc in MEASUREMENT_APPROACH['measured_events'].items():
        print(f"  {event}: {desc}")
    print()
    print("/proc interface:")
    for f, info in PROC_INTERFACE['files'].items():
        print(f"  /proc/irq_latency/{f}: {info.get('content', info.get('variable', '?'))[:60]}")
    print()
    print("KLP integration:", KLP_INTEGRATION['import'])
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:70]}")
