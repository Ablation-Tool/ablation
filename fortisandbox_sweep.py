"""
FortiSandbox binary semantic sweep — FSA 5.0.5 build0141
Targets: sandbox-scan-main, merged_daemon, sfmpd, system-cli, system-admin,
         sandbox-scan-filter, sandbox-scan-rtap, inline_block
"""

import sys, os, json, numpy as np
sys.path.insert(0, os.path.dirname(__file__))
from fortinet_sweep import sweep, VULN_PROFILES

FSA_ROOT = os.path.expanduser("~/ablation/fortisandbox-work/extract/rootfs")

TARGETS = [
    ("sandbox-scan-main",   "FSA sandbox scan engine (main)"),
    ("merged_daemon",       "FSA merged daemon"),
    ("sfmpd",               "FSA management protocol daemon"),
    ("system-cli",          "FSA system CLI"),
    ("system-admin",        "FSA system admin daemon"),
    ("sandbox-scan-filter", "FSA sandbox scan filter"),
    ("sandbox-scan-rtap",   "FSA sandbox scan rtap"),
    ("inline_block",        "FSA inline block daemon"),
]

FSA_VULN_PROFILES = VULN_PROFILES + [
    ("vm_escape_syscall",
     "HYPERVISOR_GUEST | role=vm_control | calls: ioctl open prctl seccomp | "
     "vuln: ioctl or syscall with attacker-controlled arguments that could escape sandbox or VM isolation"),

    ("file_analysis_overflow",
     "FILE_PARSER | role=sample_analysis | calls: memcpy memmove realloc fread | "
     "vuln: file format parser reads length field from sample and copies without upper bound check; heap overflow"),

    ("verdict_spoof",
     "VERDICT_ENGINE | role=verdict_write | calls: sqlite3_exec fwrite fprintf | "
     "vuln: verdict result written to DB or log with attacker-controlled content without sanitization"),

    ("ipc_msg_overflow",
     "IPC_HANDLER | role=message_receive | calls: recv recvmsg read | "
     "vuln: IPC message length field from peer trusted without validation; buffer overflow in handler"),
]


def run_all(output_file: str = None):
    all_results = {}
    for binary_name, label in TARGETS:
        path = os.path.join(FSA_ROOT, "bin", binary_name)
        if not os.path.exists(path):
            print(f"[SKIP] {binary_name} not found at {path}")
            continue
        results, metas, descs, corpus_vecs, model = sweep(path, label)
        all_results[binary_name] = {
            "label": label,
            "n_functions": len(metas),
            "hits": results,
        }

    if output_file:
        with open(output_file, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\nResults written to {output_file}")

    return all_results


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/fsa_sweep_results.json"
    run_all(out)
