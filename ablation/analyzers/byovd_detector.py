"""
BYOVD (Bring Your Own Vulnerable Driver) detector.

BYOVD attacks use legitimate (often signed) kernel drivers that expose dangerous
primitives via an IOCTL interface. The attacker loads the signed driver (bypassing
driver signing enforcement) and calls its IOCTLs to invoke the underlying primitive.

Attack chain structure (from PRE ch3 walk-through analysis):
  1. Signed driver loads without test-signing requirement
  2. User opens device handle via \\DosDevices\\ symbolic link
  3. User calls DeviceIoControl with crafted IOCTL input
  4. Driver IOCTL handler invokes dangerous kernel primitive with user data:
       -- MmMapIoSpace(user_pa, size) -> map arbitrary physical page
       -- MDL chain -> writable mapping of kernel .text / SSDT
       -- WRMSR(0xC0000082, user_va) -> replace syscall handler
       -- CR0 WP-disable + SSDT patch -> hook system calls

Sources:
  - Practical Reverse Engineering (Dang/Gazet/Bachaalany) ch3: IRP/IOCTL dispatch,
    MmMapIoSpace + MDL kernel-write primitive, MSR_LSTAR sequences, CR0 WP-disable,
    KeServiceDescriptorTable access, SSDT hook rootkit walk-through
  - Rootkits: Subverting the Windows Kernel (Hoglund/Butler) ch3/ch4:
    MDL arbitrary write, SSDT hook, pool shellcode

Usage:
    from ablation.analyzers.byovd_detector import BYOVDDetector
    det = BYOVDDetector.from_path('/path/to/driver.sys')
    report = det.analyze()
    print(report.fmt())

    # CLI:  ablation byovd driver.sys
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ablation.analyzers.kernel_driver_analyzer import (
    KernelDriverAnalyzer,
    KernelDriverReport,
)


# ---------------------------------------------------------------------------
# Attack path
# ---------------------------------------------------------------------------

@dataclass
class AttackPath:
    """A confirmed or likely BYOVD attack primitive in this driver."""
    name: str           # e.g. 'PHYS_MEM_ARBITRARY_RW'
    severity: str       # CRITICAL / HIGH / MEDIUM
    description: str    # one-line description of the primitive
    evidence: list      # list[str] -- what signals were found
    cve_examples: list  # list[str] -- known CVEs using this pattern

    def fmt(self) -> str:
        lines = [f"  [{self.severity:<8}] {self.name}"]
        lines.append(f"             {self.description}")
        for ev in self.evidence:
            lines.append(f"             + {ev}")
        if self.cve_examples:
            lines.append(f"             CVEs: {', '.join(self.cve_examples)}")
        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# BYOVD report
# ---------------------------------------------------------------------------

_VERDICT_LABELS = {
    'BYOVD_CONFIRMED': 'Driver exposes dangerous primitive + IOCTL interface; ready-to-use BYOVD weapon',
    'BYOVD_LIKELY':    'High-confidence combination of dangerous imports and IOCTL surface',
    'BYOVD_POSSIBLE':  'Dangerous primitives present; IOCTL exposure unconfirmed or weaker signal',
    'CLEAN':           'No BYOVD-relevant primitive combination detected',
}


@dataclass
class BYOVDReport:
    path: str
    verdict: str        # BYOVD_CONFIRMED / BYOVD_LIKELY / BYOVD_POSSIBLE / CLEAN
    risk_score: int     # 0-100
    is_signed: bool
    has_ioctl: bool
    attack_paths: list = field(default_factory=list)
    driver_report: Optional[KernelDriverReport] = None

    def fmt(self) -> str:
        lines = ['=' * 72]
        lines.append(f"BYOVD ANALYSIS: {Path(self.path).name}")
        lines.append('=' * 72)
        lines.append(f"Verdict:     {self.verdict}")
        lines.append(f"Risk score:  {self.risk_score}/100")
        lines.append(f"Signed:      {'YES' if self.is_signed else 'NO'}")
        lines.append(f"IOCTL:       {'YES' if self.has_ioctl else 'NO'}")
        lines.append(f"Note:        {_VERDICT_LABELS.get(self.verdict, '')}")

        if self.attack_paths:
            lines.append(f"\nAttack paths ({len(self.attack_paths)}):")
            for ap in self.attack_paths:
                lines.append(ap.fmt())

        if self.driver_report and self.driver_report.ioctl_codes:
            neither = [ic for ic in self.driver_report.ioctl_codes if ic.is_neither()]
            lines.append(
                f"\nIOCTL surface: {len(self.driver_report.ioctl_codes)} codes, "
                f"{len(neither)} METHOD_NEITHER (raw user ptr)"
            )
            for ic in self.driver_report.ioctl_codes:
                lines.append(f"  {ic.fmt()}")

        return '\n'.join(lines)

    def summary(self) -> dict:
        return {
            'verdict':       self.verdict,
            'risk_score':    self.risk_score,
            'is_signed':     self.is_signed,
            'has_ioctl':     self.has_ioctl,
            'attack_paths':  len(self.attack_paths),
            'path_names':    [ap.name for ap in self.attack_paths],
        }


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class BYOVDDetector:
    """
    BYOVD risk assessment for Windows kernel drivers.

    Wraps KernelDriverAnalyzer and applies BYOVD-specific scoring.  Each
    attack path requires both a dangerous primitive AND an IOCTL surface
    through which user mode can reach it.

    Scoring:
      - Each confirmed attack path contributes to a 0-100 risk score
      - Signed drivers score higher (signed = loads without test-signing)
      - METHOD_NEITHER IOCTLs score higher (raw user ptr, no validation)
      - Multiple attack paths compound the score
      - BYOVD_CONFIRMED >= 65, BYOVD_LIKELY >= 35, BYOVD_POSSIBLE >= 15
    """

    def __init__(self, data: bytes, path: str = '<unknown>'):
        self._kda = KernelDriverAnalyzer(data, path)
        self.path = path

    @classmethod
    def from_path(cls, path: str) -> 'BYOVDDetector':
        with open(path, 'rb') as fh:
            data = fh.read()
        return cls(data, path)

    def analyze(self) -> BYOVDReport:
        dr = self._kda.analyze()

        # Flatten signal sets for O(1) lookup
        imports_flat: set = {f.api for f in dr.kernel_api_findings}
        patterns: set = {p.pattern for p in dr.dangerous_patterns}
        has_ioctl = (
            any(mf.index == 0x0e for mf in dr.major_functions)
            or bool(dr.ioctl_codes)
        )

        attack_paths = []
        score = 0

        # ----------------------------------------------------------------
        # 1. Physical memory arbitrary read/write
        #
        # Primitive: MmMapIoSpace(PhysicalAddress, NumberOfBytes, CacheType)
        # Source: PRE ch3 -- "BYOVD patterns: MmMapIoSpace with user-controlled
        # physical address, arbitrary read/write via IOCTL"
        #
        # Chain: user supplies physical address via IOCTL buffer -> driver calls
        # MmMapIoSpace(user_pa, ...) -> kernel VA mapping of arbitrary physical page
        # -> driver reads/writes through that VA -> attacker reads kernel objects
        # or patches code/data at any physical address.
        # ----------------------------------------------------------------
        phys_ev = []
        if 'MmMapIoSpace' in imports_flat:
            phys_ev.append('imports MmMapIoSpace (map arbitrary physical page by PA)')
        if 'MmMapIoSpaceEx' in imports_flat:
            phys_ev.append('imports MmMapIoSpaceEx (extended phys-page mapping)')
        if 'MmCopyMemory' in imports_flat:
            phys_ev.append('imports MmCopyMemory (copy from/to physical or virtual address)')
        if 'MmGetPhysicalAddress' in imports_flat:
            phys_ev.append('imports MmGetPhysicalAddress (PA of any kernel VA = step 1 of PA chain)')

        if phys_ev and has_ioctl:
            is_crit = any('MmMapIoSpace' in e or 'MmCopyMemory' in e for e in phys_ev)
            attack_paths.append(AttackPath(
                name='PHYS_MEM_ARBITRARY_RW',
                severity='CRITICAL' if is_crit else 'HIGH',
                description='Physical memory r/w via IOCTL with user-supplied physical address',
                evidence=phys_ev,
                cve_examples=[
                    'CVE-2021-21551 (Dell DBUtil -- phys-write -> SYSTEM)',
                    'CVE-2018-19320 (Gigabyte -- MmMapIoSpace exposed)',
                    'CVE-2019-18845 (EVGA Precision -- MmMapIoSpace via IOCTL)',
                ],
            ))
            score += 40 if is_crit else 20

        # ----------------------------------------------------------------
        # 2. MDL-based kernel write primitive
        #
        # Source: PRE ch3 walk-through (Sample A MapMdl function):
        #   IoAllocateMdl(KiServiceTable, nsyscalls*4, ...) -> MDL describing kernel .text
        #   MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess) -> lock pages
        #   MmMapLockedPagesSpecifyCache(mdl, KernelMode, ...) -> get writable kernel VA
        #   Write through new VA -> patches SSDT or any kernel .text region
        #
        # This is the canonical kernel-write primitive that bypasses WP bit without
        # touching CR0 -- MDL lock elevates page to writable regardless of PTE bits.
        # ----------------------------------------------------------------
        mdl_ev = []
        if 'IoAllocateMdl' in imports_flat:
            mdl_ev.append('imports IoAllocateMdl (allocate MDL for any VA)')
        if 'MmProbeAndLockPages' in imports_flat:
            mdl_ev.append('imports MmProbeAndLockPages (lock pages IoWriteAccess)')
        if 'MmMapLockedPagesSpecifyCache' in imports_flat:
            mdl_ev.append('imports MmMapLockedPagesSpecifyCache (writable kernel VA mapping)')
        if 'MmGetSystemAddressForMdlSafe' in imports_flat:
            mdl_ev.append('imports MmGetSystemAddressForMdlSafe (system-space VA from MDL)')
        if 'MmMapLockedPagesWithReservedMapping' in imports_flat:
            mdl_ev.append('imports MmMapLockedPagesWithReservedMapping')
        if 'MmBuildMdlForNonPagedPool' in imports_flat:
            mdl_ev.append('imports MmBuildMdlForNonPagedPool (MDL for non-paged pool page)')

        if len(mdl_ev) >= 2 and has_ioctl:
            attack_paths.append(AttackPath(
                name='MDL_KERNEL_WRITE',
                severity='CRITICAL',
                description='MDL-based writable kernel mapping; can patch SSDT or kernel .text',
                evidence=mdl_ev,
                cve_examples=[
                    'PRE ch3 Sample A: MapMdl(KiServiceTable) SSDT overwrite via IOCTL',
                ],
            ))
            score += 35

        # ----------------------------------------------------------------
        # 3. MSR_LSTAR manipulation
        #
        # Source: PRE ch3 summary -- "MSR_LSTAR (0xC0000082): RDMSR = KASLR defeat,
        # WRMSR = syscall hijack"
        # B9 82 00 00 C0 = MOV ECX, 0xC0000082; RDMSR reads KiSystemCall64 VA;
        # WRMSR replaces the syscall handler.
        # ----------------------------------------------------------------
        msr_ev = []
        if 'MSR_LSTAR_ACCESS' in patterns:
            msr_ev.append('MOV ECX, 0xC0000082 sequence (LSTAR index load)')
        if 'WRMSR' in patterns:
            msr_ev.append('WRMSR instruction (arbitrary MSR write)')
        if 'RDMSR' in patterns:
            msr_ev.append('RDMSR instruction (arbitrary MSR read = KASLR defeat risk)')

        if msr_ev:
            has_write = 'WRMSR instruction (arbitrary MSR write)' in msr_ev
            attack_paths.append(AttackPath(
                name='MSR_LSTAR_MANIPULATION',
                severity='CRITICAL' if has_write else 'HIGH',
                description=(
                    'WRMSR(LSTAR) replaces syscall handler (ring-0 takeover)'
                    if has_write else
                    'RDMSR(LSTAR) reads KiSystemCall64 VA (KASLR defeat)'
                ),
                evidence=msr_ev,
                cve_examples=[
                    'CVE-2015-2291 (IQVW64 Intel NIC driver -- RDMSR/WRMSR exposed)',
                ],
            ))
            score += 40 if has_write else 20

        # ----------------------------------------------------------------
        # 4. SSDT hook via CR0 WP-disable
        #
        # Source: PRE ch3 "Miscellaneous System Mechanisms" + Sample A walk-through:
        #   PUSH EAX; MOV EAX, CR0; AND EAX, 0FFFEFFFFh; MOV CR0, EAX  (WP bit 16 = 0)
        #   Write to KiServiceTable[n] = hook system call n
        #   MOV CR0, saved_cr0 (restore WP)
        # ----------------------------------------------------------------
        ssdt_ev = []
        if 'SSDT_HOOK_CR0_SEQUENCE' in patterns:
            ssdt_ev.append('CR0 WP-disable read-modify-write sequence (canonical SSDT hook)')
        if 'MOV_CR0' in patterns:
            ssdt_ev.append('MOV CR0 write (CR0 manipulation)')
        if any(f.api == 'KeServiceDescriptorTable' for f in dr.kernel_api_findings):
            ssdt_ev.append('imports KeServiceDescriptorTable (IAT SSDT reference -- x86 only)')
        if 'KSERVDESCRIPTORTABLE_WIDE' in patterns:
            ssdt_ev.append('L"KeServiceDescriptorTable" wide string (MmGetSystemRoutineAddress lookup -- x64)')
        if any(f.api == 'MmGetSystemRoutineAddress' for f in dr.kernel_api_findings):
            ssdt_ev.append('imports MmGetSystemRoutineAddress (dynamic kernel symbol resolution)')

        if ssdt_ev:
            is_full_chain = 'SSDT_HOOK_CR0_SEQUENCE' in patterns
            attack_paths.append(AttackPath(
                name='SSDT_HOOK',
                severity='CRITICAL' if is_full_chain else 'HIGH',
                description='System call table hook: CR0 WP-disable + KiServiceTable overwrite',
                evidence=ssdt_ev,
                cve_examples=[],
            ))
            score += 35 if is_full_chain else 15

        # ----------------------------------------------------------------
        # 5. Token stealing / DKOM privilege escalation
        #
        # Source: PRE ch3 -- PsInitialSystemProcess = EPROCESS of System process (pid 4).
        # Chain: PsLookupProcessByProcessId(pid) -> PEPROCESS of target process
        #        KeStackAttachProcess(target_eprocess) -> attach to target VA space
        #        Copy token at EPROCESS+0x4b8 from System to target
        # ----------------------------------------------------------------
        token_ev = []
        if any(f.api == 'PsInitialSystemProcess' for f in dr.kernel_api_findings):
            token_ev.append('imports PsInitialSystemProcess (pointer to System EPROCESS)')
        if any(f.api == 'PsLookupProcessByProcessId' for f in dr.kernel_api_findings):
            token_ev.append('imports PsLookupProcessByProcessId (EPROCESS from PID)')
        if any(f.api == 'KeStackAttachProcess' for f in dr.kernel_api_findings):
            token_ev.append('imports KeStackAttachProcess (arbitrary process VA space attach)')

        if token_ev and has_ioctl:
            attack_paths.append(AttackPath(
                name='TOKEN_STEALING_LPE',
                severity='HIGH',
                description='Token stealing LPE: copies System token to target via EPROCESS DKOM',
                evidence=token_ev,
                cve_examples=[
                    'Common LPE pattern in DKOM rootkits; many BYOVD chains end here',
                ],
            ))
            score += 25

        # ----------------------------------------------------------------
        # 6. SMEP bypass via CR4
        #
        # Source: PRE ch3 -- CR4 bit 20 = SMEP (Supervisor Mode Execution Prevention).
        # Combined CR4 sequence: MOV RAX, CR4; AND RAX, ~SMEP; MOV CR4, RAX
        # Disables supervisor-mode execution prevention -> kernel can JMP to user-mode pages.
        # Classic exploit chain: write shellcode to user heap -> SMEP bypass -> ret2user.
        # ----------------------------------------------------------------
        smep_ev = []
        if 'SMEP_DISABLE_CR4_SEQUENCE' in patterns:
            smep_ev.append('CR4 SMEP-disable read-modify-write sequence')
        if 'MOV_CR4' in patterns:
            smep_ev.append('MOV CR4 write (CR4 modification)')

        if smep_ev:
            attack_paths.append(AttackPath(
                name='SMEP_BYPASS',
                severity='CRITICAL',
                description='CR4 SMEP-disable; kernel can execute user-mode pages after bypass',
                evidence=smep_ev,
                cve_examples=[],
            ))
            score += 30 if 'CR4 SMEP-disable read-modify-write sequence' in smep_ev else 10

        # ----------------------------------------------------------------
        # 7. Kernel APC code injection
        #
        # Source: PRE ch3 -- KeInitializeApc/KeInsertQueueApc chain:
        # KeInsertQueueApc queues a kernel-mode APC to an arbitrary thread.
        # Combined with ZwAllocateVirtualMemory to allocate RWX shellcode page.
        # Rootkits inject code into arbitrary processes by queueing user-mode APCs.
        # ----------------------------------------------------------------
        apc_ev = []
        if any(f.api == 'KeInitializeApc' for f in dr.kernel_api_findings):
            apc_ev.append('imports KeInitializeApc (APC init)')
        if any(f.api == 'KeInsertQueueApc' for f in dr.kernel_api_findings):
            apc_ev.append('imports KeInsertQueueApc (queue APC to arbitrary thread)')
        if any(f.api == 'ZwAllocateVirtualMemory' for f in dr.kernel_api_findings):
            apc_ev.append('imports ZwAllocateVirtualMemory (allocate RWX pages in target process)')

        if len(apc_ev) >= 2 and has_ioctl:
            attack_paths.append(AttackPath(
                name='APC_KERNEL_INJECTION',
                severity='HIGH',
                description='Kernel APC injection: queue user-mode APC to thread in target process',
                evidence=apc_ev,
                cve_examples=[],
            ))
            score += 20

        # ----------------------------------------------------------------
        # 8. Kernel memory arbitrary write via virtual memory APIs
        #
        # ZwWriteVirtualMemory / NtProtectVirtualMemory from kernel mode bypasses
        # all userland checks and can write to any process VA or make kernel pages RWX.
        # ----------------------------------------------------------------
        vmem_ev = []
        if any(f.api in ('ZwWriteVirtualMemory',) for f in dr.kernel_api_findings):
            vmem_ev.append('imports ZwWriteVirtualMemory (write to any process VA from kernel)')
        if any(f.api in ('ZwProtectVirtualMemory', 'NtProtectVirtualMemory')
               for f in dr.kernel_api_findings):
            vmem_ev.append('imports ZwProtectVirtualMemory / NtProtectVirtualMemory (make pages RWX)')

        if vmem_ev and has_ioctl:
            attack_paths.append(AttackPath(
                name='VIRTUAL_MEM_WRITE',
                severity='HIGH',
                description='Kernel-mode virtual memory write to arbitrary process VA space',
                evidence=vmem_ev,
                cve_examples=[],
            ))
            score += 20

        # ----------------------------------------------------------------
        # Score adjustments
        # ----------------------------------------------------------------

        # Signed bonus: signed driver loads on production systems without test-signing.
        # The entire BYOVD threat model depends on signing bypass.
        if dr.is_signed and attack_paths:
            score += 10

        # METHOD_NEITHER IOCTLs: raw user pointer passes directly to driver.
        # No kernel copy, no probe -- easiest attack surface.
        neither_count = sum(1 for ic in dr.ioctl_codes if ic.is_neither())
        score += min(neither_count * 5, 15)

        score = min(score, 100)

        # ----------------------------------------------------------------
        # Verdict
        # ----------------------------------------------------------------
        if score >= 65:
            verdict = 'BYOVD_CONFIRMED'
        elif score >= 35:
            verdict = 'BYOVD_LIKELY'
        elif score >= 15:
            verdict = 'BYOVD_POSSIBLE'
        else:
            verdict = 'CLEAN'

        return BYOVDReport(
            path=self.path,
            verdict=verdict,
            risk_score=score,
            is_signed=dr.is_signed,
            has_ioctl=has_ioctl,
            attack_paths=attack_paths,
            driver_report=dr,
        )


def analyze_byovd(path: str) -> BYOVDReport:
    """One-call shortcut. Returns BYOVDReport."""
    return BYOVDDetector.from_path(path).analyze()


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <driver.sys>')
        sys.exit(1)

    report = analyze_byovd(sys.argv[1])
    print(report.fmt())
    print()
    import json
    print(json.dumps(report.summary(), indent=2))
