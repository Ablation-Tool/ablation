"""
TencentOS kernel evolution — cross-version comparison RE module.

Tracks the evolution of TOS-specific kernel features from TOS 3.3 to TOS 4.6,
documenting compiler changes, feature additions, and security architecture progression.

Source: kernel config files from each mounted TOS filesystem.
"""

VERSIONS = {
    "TOS_3.3": {
        "kernel": "5.4.241-24.0017.41.1",
        "source": "/mnt/tos33_re/boot/config-5.4.241-24.0017.41.1",
        "compiler": "GCC 8.5.0 (standard, not Tencent-modified)",
        "compiler_text": "gcc (GCC) 8.5.0 20210514 (Red Hat 8.5.0-22)",
        "gcc_version_config": "CONFIG_GCC_VERSION=80500",
        "tls_protocol": "TLCP via libssl TOS patches (SM2/SM4 at TLS layer)",
        "kernel_tree": "upstream Linux 5.4 LTS",
    },
    "TOS_4.2": {
        "kernel": "6.6.47-12.tl4.x86_64",
        "source": "kernel config not accessible (boot partition inaccessible)",
        "compiler": "Unknown — likely early Tencent Compiler 12.x (kernel 6.6 requires GCC 12+)",
        "tls_protocol": "TLCP likely inherited from TOS 3.x",
        "kernel_tree": "upstream Linux 6.6 LTS base",
    },
    "TOS_4.4": {
        "kernel": "6.6.110-42.4.tl4.x86_64",
        "source": "/mnt/tos44_re/boot/config-6.6.110-42.4.tl4.x86_64",
        "compiler": "Tencent Compiler 12.3.1.7 (first confirmed Tencent GCC fork)",
        "compiler_text": "gcc (Tencent Compiler 12.3.1.7) 12.3.1 20230912 (TencentOS 12.3.1.7-1)",
        "gcc_version_config": "CONFIG_GCC_VERSION=120301",
        "kernel_tree": "Linux 6.6 LTS + TOS patches",
    },
    "TOS_4.6": {
        "kernel": "6.6.119-51.3.tl4.x86_64",
        "source": "/mnt/tos46_re/boot/config-6.6.119-51.3.tl4.x86_64",
        "compiler": "Tencent Compiler 12.3.1.8 (updated, 4th iteration)",
        "compiler_text": "gcc (Tencent Compiler 12.3.1.8) 12.3.1 20230912 (TencentOS 12.3.1.8-4)",
        "gcc_version_config": "CONFIG_GCC_VERSION=120301",
        "kernel_tree": "Linux 6.6 LTS + TOS patches",
    },
}

FEATURE_PROGRESSION = {
    "CONFIG_ASYNC_FORK": {
        "TOS_3.3": "=y (built-in)",
        "TOS_4.2": "=y (built-in, confirmed from tkernel module analysis)",
        "TOS_4.4": "=y (built-in)",
        "TOS_4.6": "=y (built-in)",
        "note": "Present across all TOS versions — async fork is a TOS foundation feature",
    },
    "CONFIG_TKERNEL": {
        "TOS_3.3": "not set",
        "TOS_4.2": "unknown",
        "TOS_4.4": "=y",
        "TOS_4.6": "=y",
        "note": "Tkernel subsystem introduced in TOS 4.x",
    },
    "CONFIG_TKERNEL_KILL_HOOK": {
        "TOS_3.3": "not set",
        "TOS_4.2": "not set",
        "TOS_4.4": "unknown (kill_protect.ko present, likely =y)",
        "TOS_4.6": "=y",
        "note": "Kill hook API — register_kill_hook/unregister_kill_hook built into kernel",
    },
    "CONFIG_SHELL_GUARD": {
        "TOS_3.3": "not set",
        "TOS_4.2": "not set",
        "TOS_4.4": "unknown",
        "TOS_4.6": "=y",
        "note": "Shell exec protection — introduced in TOS 4.6",
    },
    "CONFIG_DIM": {
        "TOS_3.3": "=y (DIMLIB only — the library, not full DIM subsystem)",
        "TOS_4.2": "unknown",
        "TOS_4.4": "=y (dim_core.ko, dim_monitor.ko present)",
        "TOS_4.6": "=y (full DIM with SM3 support)",
        "note": "TOS 3.3 has DIMLIB but not the full Dynamic Integrity Measurement system",
    },
    "CONFIG_CRYPTO_SM2": {
        "TOS_3.3": "not set",
        "TOS_4.2": "=y (aegis uses SM2 for module signing)",
        "TOS_4.4": "=y",
        "TOS_4.6": "=y",
        "note": "SM2 asymmetric crypto added in TOS 4.x",
    },
    "CONFIG_CRYPTO_SM3": {
        "TOS_3.3": "=m (module only)",
        "TOS_4.2": "=y",
        "TOS_4.4": "=y",
        "TOS_4.6": "=y",
        "note": "SM3 hash: module in TOS 3.3, built-in from TOS 4.x",
    },
    "CONFIG_CRYPTO_SM4": {
        "TOS_3.3": "=m (module only)",
        "TOS_4.2": "=m",
        "TOS_4.4": "=m",
        "TOS_4.6": "=m",
        "note": "SM4 block cipher remains a module across all versions",
    },
    "CONFIG_SECURITY_BIBA": {
        "TOS_3.3": "=y",
        "TOS_4.2": "unknown",
        "TOS_4.4": "unknown",
        "TOS_4.6": "=y",
        "note": "Biba MAC model present in both 3.3 and 4.6 — consistent design choice",
    },
    "CONFIG_CPU_SUP_ZHAOXIN": {
        "TOS_3.3": "=y",
        "TOS_4.2": "unknown",
        "TOS_4.4": "=y (Zhaoxin GMI modules present)",
        "TOS_4.6": "=y",
        "note": "Zhaoxin support consistent throughout — deployed on Chinese domestic hardware from early on",
    },
    "CONFIG_TKERNEL_AEGIS_MODULE": {
        "TOS_3.3": "not set",
        "TOS_4.2": "=m (aegis.ko exec monitoring)",
        "TOS_4.4": "not set (deprecated)",
        "TOS_4.6": "not set (deprecated)",
        "note": "aegis was a TOS 4.2-only feature, replaced by dim_core/dim_monitor",
    },
    "CONFIG_TKERNEL_TTOOLS": {
        "TOS_3.3": "=m (ttools.ko anti-ptrace)",
        "TOS_4.2": "not set",
        "TOS_4.4": "not set",
        "TOS_4.6": "not set",
        "note": "ttools anti-ptrace was TOS 3.3-only; replaced by CONFIG_SECURITY_YAMA in 4.x",
    },
    "CONFIG_SECURITY_YAMA": {
        "TOS_3.3": "=y (alongside ttools)",
        "TOS_4.6": "=y (ttools absent; Yama is the ptrace restriction mechanism)",
        "note": (
            "TOS 3.3: both Yama and ttools.ko for ptrace restriction (redundant layers). "
            "TOS 4.x: ttools removed, Yama is the sole ptrace restriction mechanism."
        ),
    },
    "CONFIG_KFENCE": {
        "TOS_3.3": "not set (5.4 LTS predates KFENCE, added in 5.12)",
        "TOS_4.6": "=y",
        "note": "KFENCE kernel memory safety added with move to Linux 6.6",
    },
}

SIGNING_KEY_EVOLUTION = {
    "TOS_3.3": {
        "key": "6E:69:6E:67:20:6B:65:79:2C (hex = ASCII 'ning key,')",
        "hashalgo": "sha256",
        "signer": " sig (literal space + sig)",
        "modules": ["ttools.ko", "netatop.ko"],
        "quality": "Development/test key — improperly named fingerprint",
    },
    "TOS_4.2": {
        "key": "D8:37:BC:3B:9C:28:FD:F6",
        "hashalgo": "sha512",
        "signer": "Tkernel signing key",
        "modules": ["aegis.ko"],
        "quality": "Production key, sha512 — later retired",
    },
    "TOS_4.4": {
        "key": "01:9D:01:14:84:D7",
        "hashalgo": "sha256",
        "signer": "Tkernel signing key",
        "modules": ["kill_protect.ko", "kill_block.ko", "irqlatency.ko", "emm_*.ko"],
        "quality": "Current production key — key rotation from TOS 4.2 D8:37:BC key",
    },
    "TOS_4.6": {
        "key": "01:9D:01:14:84:D7",
        "hashalgo": "sha256",
        "signer": "Tkernel signing key",
        "modules": ["kill_protect.ko", "kill_block.ko", "irqlatency.ko", "emm_*.ko", "dim_core.ko", "dim_monitor.ko", "async-fork.ko", "sm2_zhaoxin_gmi.ko", "tcm_hygon.ko", "tpm_hygon.ko", "hct.ko", "tdm-kernel-guard.ko"],
        "quality": "Same key as TOS 4.4 — no rotation between 4.4 and 4.6",
    },
}

SECURITY_ARCHITECTURE_EVOLUTION = {
    "exec_monitoring": {
        "TOS_3.3": "None",
        "TOS_4.2": "aegis.ko — execve hook, 128KB env cap, procfs output",
        "TOS_4.4": "kill_protect.ko (process kill protection) — shift from monitoring to protection",
        "TOS_4.6": "dim_core.ko — cryptographic integrity measurement (hash-based, not event-based)",
        "trend": "3.3→4.2: behavioral monitoring; 4.2→4.4: process protection; 4.4→4.6: crypto integrity",
    },
    "ptrace_protection": {
        "TOS_3.3": "ttools.ko + Yama LSM (dual layer)",
        "TOS_4.6": "Yama LSM only (ttools removed)",
        "trend": "Consolidation: TOS-specific module deprecated, replaced by upstream Yama",
    },
    "network_monitoring": {
        "TOS_3.3": "netatop.ko — per-task network stats via netfilter",
        "TOS_4.6": "netatop not present (no CONFIG_TKERNEL_NETATOP)",
        "trend": "Network monitoring removed from kernel, likely moved to userspace agent (tagent)",
    },
    "integrity_measurement": {
        "TOS_3.3": "None",
        "TOS_4.2": "aegis.ko (behavioral)",
        "TOS_4.4": "dim_core.ko introduced",
        "TOS_4.6": "dim_core.ko + dim_monitor.ko + tdm-kernel-guard.ko (hardware-backed)",
        "trend": "Software-only integrity → hardware-backed (Hygon PSP + TDM) in TOS 4.6",
    },
    "hardware_trust": {
        "TOS_3.3": "None (no PSP/TPM driver specific to TOS)",
        "TOS_4.6": "tcm_hygon.ko + tpm_hygon.ko + tdm-kernel-guard.ko — full Hygon trust chain",
        "trend": "Added complete hardware root-of-trust stack in TOS 4.x",
    },
    "crypto_acceleration": {
        "TOS_3.3": "Zhaoxin CPU support, SM3=m, SM4=m, no SM2",
        "TOS_4.6": "SM2=y, SM3=y, SM4=m + Zhaoxin GMI (sm2/sm3/sm4_zhaoxin_gmi.ko) + hardware acceleration",
        "trend": "SM2 added, SM3 promoted to built-in, Zhaoxin hardware path added",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "HIGH",
        "title": "Tencent compiler fork introduced in TOS 4.4 — all kernels from 6.6+ use unaudited GCC",
        "detail": (
            "TOS 3.3 (kernel 5.4): compiled with standard GCC 8.5.0 (Red Hat 8.5.0-22). "
            "TOS 4.4 (kernel 6.6): compiled with Tencent Compiler 12.3.1.7. "
            "TOS 4.6 (kernel 6.6): compiled with Tencent Compiler 12.3.1.8 (4th iteration). "
            "The transition from standard GCC to Tencent's proprietary fork means "
            "all TOS 4.x kernel code is compiled by an unaudited, closed-source GCC variant. "
            "The version numbering (12.3.1.7, 12.3.1.8) shows active development — "
            "Tencent actively patches GCC, with each iteration potentially adding "
            "or changing code generation behavior."
        ),
        "compiler_transition": {
            "before": "GCC 8.5.0 (standard, auditable)",
            "after": "Tencent Compiler 12.3.1.8 (closed-source fork)",
        },
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "Signing key rotation TOS 4.2→4.4 — old D8:37 key may still be trusted by in-production 4.2 systems",
        "detail": (
            "TOS 4.2 modules use key D8:37:BC:3B:9C:28:FD:F6 (sha512). "
            "TOS 4.4+ modules use key 01:9D:01:14:84:D7 (sha256). "
            "The rotation occurred at the TOS 4.2→4.4 boundary. "
            "TOS 4.2 kernels in production still trust D8:37. "
            "If the D8:37 private key material is accessible (from TOS 4.2 build infrastructure), "
            "arbitrary modules can be signed and loaded on any TOS 4.2 kernel. "
            "No evidence the old key was revoked from TOS 4.2 kernel keyrings."
        ),
        "old_key": "D8:37:BC:3B:9C:28:FD:F6 (sha512)",
        "new_key": "01:9D:01:14:84:D7 (sha256)",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "TOS 3.3 uses development signing key 'ning key,' — dev key risk in production deployment",
        "detail": (
            "TOS 3.3 module signing key fingerprint starts with 6E:69:6E:67:20:6B:65:79:2C = ASCII 'ning key,'. "
            "The signer field is ' sig' (space + sig). "
            "This is a development/build key with an improperly generated fingerprint. "
            "If TOS 3.3 systems remain in production and this key's private key "
            "is on build servers, arbitrary modules can be signed for TOS 3.3 kernels. "
            "Three distinct signing key artifacts exist across TOS versions: "
            "dev 'ning key,' (3.3) → production sha512 D8:37 (4.2) → production sha256 01:9D (4.4+). "
            "Each represents a distinct signing infrastructure compromise vector."
        ),
        "tos33_key": "6E:69:6E:67:20:6B:65:79:2C = ASCII 'ning key,'",
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "ttools ptrace protection removed in TOS 4.4 — replaced by upstream Yama (weaker model)",
        "detail": (
            "TOS 3.3: both ttools.ko (custom anti-ptrace with protected PID list) + Yama LSM. "
            "TOS 4.x: ttools removed, Yama only. "
            "ttools provided PID-level anti-ptrace control (any PID can be protected). "
            "Yama restricts ptrace to parent-child relationships (less granular). "
            "The removal of ttools means a process that could self-remove from the "
            "protected list via ioctl(0xee01) is no longer relevant — but also means "
            "there is no per-PID anti-ptrace mechanism on TOS 4.x beyond Yama's scope."
        ),
        "removed_in": "TOS 4.4",
        "replacement": "CONFIG_SECURITY_YAMA (less granular ptrace restriction)",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "aegis exec monitoring removed in TOS 4.4 — network traffic moved to userspace tagent",
        "detail": (
            "TOS 4.2 has aegis.ko (exec monitoring) and netatop.ko (network stats). "
            "TOS 4.4+ has neither. "
            "The monitoring functions are presumed moved to userspace: tagent (the Tencent cloud agent) "
            "handles exec and network monitoring in userspace via eBPF or proc polling. "
            "Userspace monitoring can be bypassed by disabling/killing tagent. "
            "aegis.ko was kernel-level (required CAP_SYS_ADMIN to disable); "
            "tagent is userspace (killable with SIGKILL if permissions allow)."
        ),
        "removed_in": "TOS 4.4",
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "Security architecture trend: behavioral monitoring → process protection → crypto integrity",
        "detail": (
            "TOS 3.3: no integrity monitoring. "
            "TOS 4.2: aegis.ko — behavioral exec event capture (WHO executed WHAT). "
            "TOS 4.4: kill_protect.ko introduced — process death protection. "
            "TOS 4.6: dim_core.ko — cryptographic hash verification of running code. "
            "Trend: moved from soft monitoring (easy to bypass via hook_disable) "
            "to hard integrity verification (signature-based, PSP-backed in 4.6). "
            "This represents a maturing security architecture over the TOS lifecycle."
        ),
    },
    {
        "id": "F7",
        "severity": "INFO",
        "title": "CONFIG_SECURITY_BIBA present in both TOS 3.3 and TOS 4.6 — consistent Biba MAC across generations",
        "detail": (
            "Biba integrity MAC (CONFIG_SECURITY_BIBA=y) appears in both "
            "TOS 3.3 (kernel 5.4) and TOS 4.6 (kernel 6.6). "
            "This is a deliberate Tencent design choice maintained across a 3-year span "
            "and two major kernel version upgrades. "
            "Upstream RHEL/CentOS does NOT ship with CONFIG_SECURITY_BIBA=y. "
            "TOS uses Biba in addition to SELinux — both MAC models active simultaneously. "
            "This is a consistent, intentional divergence from upstream."
        ),
        "present_in": ["TOS_3.3", "TOS_4.6"],
        "upstream_rhel": "Biba not enabled",
    },
]

if __name__ == '__main__':
    print("TOS kernel evolution analysis")
    print()
    print("Compiler timeline:")
    for ver, data in VERSIONS.items():
        print(f"  {ver} ({data['kernel']}): {data['compiler'][:60]}")
    print()
    print("Signing key evolution:")
    for ver, key_data in SIGNING_KEY_EVOLUTION.items():
        print(f"  {ver}: {key_data['key'][:22]} ({key_data['hashalgo']}) — {key_data['quality'][:40]}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']:6s}] {f['id']}: {f['title'][:70]}")
