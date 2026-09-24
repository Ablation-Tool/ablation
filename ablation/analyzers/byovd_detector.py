"""
byovd_detector.py -- Bring Your Own Vulnerable Driver (BYOVD) capability detector.

BYOVD is a technique where attackers load a legitimate, Authenticode-signed kernel
driver that contains dangerous capabilities -- physical memory R/W, process/token
manipulation, or direct kernel object manipulation -- and exploit those capabilities
to bypass EDR controls, disable kernel-level security, or escalate to kernel-mode
execution.

Detection strategy:
  Stage 1: Static signature -- identify dangerous capability imports
  Stage 2: IOCTL surface scan -- find IOCTLs that accept physical addresses or
           process handles, and trace them to the dangerous APIs
  Stage 3: String evidence -- device path names, known vulnerable driver strings,
           \Device\PhysicalMemory access, direct object manager paths

BYOVD capability classes:
  PHYS_MEM_RW:    MmMapIoSpace / HalTranslateBusAddress -- map physical memory
                  from user-controlled address -> arbitrary kernel R/W
  PROCESS_KILL:   ZwTerminateProcess with elevated privilege -- kill EDR processes
  TOKEN_STEAL:    PsInitialSystemProcess + token copy pattern -- privilege escalation
  PTE_MANIP:      MmGetPhysicalAddress + direct PTE write via MmMapIoSpace
  DRIVER_LOAD:    ZwLoadDriver / IoCreateDriver -- load additional kernel modules
  CALLBACK_REMOVE:PsRemoveLoadImageNotifyRoutine / PsRemoveCreateThreadNotifyRoutine
                  -- blind EDR callbacks
  MSR_WRITE:      WRMSR (0x30) via IOCTL passthrough -- modify LSTAR/STAR/SYSENTER
  DKOM:           ObReferenceObjectByHandle + direct _EPROCESS manipulation

Grounded in:
  - Practical Reverse Engineering (Dang et al.) Ch 3: Windows Kernel
  - Rootkits: Subverting the Windows Kernel (Hoglund/Butler)
  - Windows Internals Part 1 (Yosifovich/Russinovich) Ch 5-6
  - https://www.loldrivers.io/ (BYOVD known-vulnerable driver database)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import lief

try:
    import capstone
    from capstone.x86_const import (
        X86_OP_REG, X86_OP_IMM, X86_OP_MEM,
        X86_INS_MOV, X86_INS_CALL, X86_INS_RET, X86_INS_RETF, X86_INS_RETFQ,
        X86_INS_WRMSR, X86_INS_RDMSR,
        X86_INS_IN, X86_INS_OUT,
    )
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False

try:
    from ablation.analyzers.kernel_driver_analyzer import (
        KernelDriverAnalyzer, KernelDriverReport,
    )
    _HAS_KDA = True
except ImportError:
    _HAS_KDA = False


# ── API classification ────────────────────────────────────────────────────────

CAPABILITY_MAP: Dict[str, str] = {
    # Physical memory mapping
    "MmMapIoSpace":                    "PHYS_MEM_RW",
    "MmMapIoSpaceEx":                  "PHYS_MEM_RW",
    "MmUnmapIoSpace":                  "PHYS_MEM_RW",
    "HalTranslateBusAddress":          "PHYS_MEM_RW",
    "MmGetPhysicalAddress":            "PHYS_MEM_RW",
    "MmAllocateMappingAddress":        "PHYS_MEM_RW",
    "MmMapLockedPagesSpecifyCache":    "PHYS_MEM_RW",
    # Process termination
    "ZwTerminateProcess":              "PROCESS_KILL",
    "NtTerminateProcess":              "PROCESS_KILL",
    # Token manipulation
    "PsInitialSystemProcess":          "TOKEN_STEAL",
    "PsLookupProcessByProcessId":      "TOKEN_STEAL",
    "SeQueryInformationToken":         "TOKEN_STEAL",
    # Virtual memory manipulation
    "ZwWriteVirtualMemory":            "MEM_WRITE",
    "ZwReadVirtualMemory":             "MEM_READ",
    "ZwAllocateVirtualMemory":         "MEM_ALLOC",
    "ZwProtectVirtualMemory":          "MEM_WRITE",
    # Driver / module load
    "ZwLoadDriver":                    "DRIVER_LOAD",
    "ZwUnloadDriver":                  "DRIVER_LOAD",
    "IoCreateDriver":                  "DRIVER_LOAD",
    # EDR callback removal
    "PsRemoveLoadImageNotifyRoutine":  "CALLBACK_REMOVE",
    "PsRemoveCreateThreadNotifyRoutine": "CALLBACK_REMOVE",
    "CmUnRegisterCallback":            "CALLBACK_REMOVE",
    "ObUnRegisterCallbacks":           "CALLBACK_REMOVE",
    # DKOM / object manipulation
    "ObReferenceObjectByHandle":       "DKOM",
    "ObOpenObjectByPointer":           "DKOM",
    "ObDereferenceObject":             "DKOM",
    "KeStackAttachProcess":            "DKOM",
    "KeUnstackDetachProcess":          "DKOM",
    # APC injection (code exec in another process)
    "KeInitializeApc":                 "APC_INJECT",
    "KeInsertQueueApc":                "APC_INJECT",
}

# Capability class risk levels
CAPABILITY_RISK: Dict[str, str] = {
    "PHYS_MEM_RW":      "CRITICAL",
    "TOKEN_STEAL":      "CRITICAL",
    "DKOM":             "CRITICAL",
    "APC_INJECT":       "CRITICAL",
    "DRIVER_LOAD":      "HIGH",
    "CALLBACK_REMOVE":  "HIGH",
    "PROCESS_KILL":     "HIGH",
    "MEM_WRITE":        "HIGH",
    "MEM_READ":         "MEDIUM",
    "MEM_ALLOC":        "MEDIUM",
    "MSR_WRITE":        "CRITICAL",
}

# Suspicious device path strings that indicate BYOVD-style device exposure
_BYOVD_STRINGS: List[str] = [
    "\\Device\\PhysicalMemory",
    "PhysicalMemory",
    "\\BaseNamedObjects\\",
    "GIO",          # Giga I/O
    "MHYPROT",      # miHoYo anti-cheat (known BYOVD)
    "dbutil",       # Dell BIOS driver (known BYOVD)
    "AsrDrv",       # ASRock driver (known BYOVD)
    "PROCEXP",      # Process Explorer (known BYOVD)
]

# Known vulnerable driver fingerprints (PDB path fragments)
_KNOWN_BYOVD_PDB: List[str] = [
    "mhyprot",    # Genshin Impact anti-cheat
    "dbutil",     # Dell BIOS utility
    "AsrDrv",     # ASRock extreme tuner
    "PROCEXP",    # Sysinternals Process Explorer
    "iqvw64e",    # Intel Network Adapter
    "speedfan",   # SpeedFan temperature monitor
    "cpuz",       # CPU-Z
    "aswArPot",   # Avast anti-rootkit
    "NDISUIO",    # NDIS user I/O driver
    "RTCore64",   # MSI Afterburner
]


@dataclass
class ByovdCapability:
    """One detected BYOVD capability in a driver."""
    api_name: str
    capability_class: str
    risk: str
    evidence: str         # how it was detected
    file_offset: int = 0

    def fmt(self) -> str:
        risk_tag = {
            "CRITICAL": "[CRIT] ",
            "HIGH":     "[HIGH] ",
            "MEDIUM":   "[MED]  ",
        }.get(self.risk, "[?]    ")
        return f"{risk_tag} {self.capability_class}: {self.api_name} -- {self.evidence}"


@dataclass
class ByovdMsrAccess:
    """Detected RDMSR/WRMSR instruction that could be used to modify kernel control registers."""
    kind: str     # "RDMSR" | "WRMSR"
    offset: int   # file offset
    description: str

    def fmt(self) -> str:
        tag = "[CRIT] " if self.kind == "WRMSR" else "[HIGH] "
        return f"{tag} MSR_ACCESS ({self.kind}) @ +0x{self.offset:x}: {self.description}"


@dataclass
class ByovdReport:
    """Full BYOVD capability report for a driver."""
    binary_path: str
    driver_type: str
    is_signed: bool
    pdb_path: Optional[str]
    capabilities: List[ByovdCapability] = field(default_factory=list)
    msr_accesses: List[ByovdMsrAccess] = field(default_factory=list)
    byovd_strings: List[str] = field(default_factory=list)
    known_byovd_match: Optional[str] = None

    @property
    def is_byovd_capable(self) -> bool:
        critical = [c for c in self.capabilities if c.risk == "CRITICAL"]
        return bool(critical) or bool(self.msr_accesses) or self.known_byovd_match is not None

    @property
    def risk_level(self) -> str:
        if self.known_byovd_match:
            return "CRITICAL"
        if any(c.risk == "CRITICAL" for c in self.capabilities):
            return "CRITICAL"
        if any(c.risk == "HIGH" for c in self.capabilities):
            return "HIGH"
        return "MEDIUM"

    def summary(self) -> Dict:
        cap_classes = list({c.capability_class for c in self.capabilities})
        return {
            "binary":            self.binary_path,
            "is_byovd_capable":  self.is_byovd_capable,
            "risk_level":        self.risk_level,
            "capabilities":      cap_classes,
            "msr_accesses":      len(self.msr_accesses),
            "known_byovd_match": self.known_byovd_match,
            "is_signed":         self.is_signed,
            "pdb_path":          self.pdb_path,
        }

    def fmt(self) -> str:
        lines = [
            f"[byovd_detector] {self.binary_path}",
            f"  risk={self.risk_level}  byovd_capable={self.is_byovd_capable}",
            f"  signed={self.is_signed}  driver_type={self.driver_type}",
            f"  pdb_path={self.pdb_path or 'N/A'}",
        ]

        if self.known_byovd_match:
            lines.append(f"  *** KNOWN BYOVD MATCH: {self.known_byovd_match} ***")

        if self.byovd_strings:
            lines.append(f"  Suspicious strings ({len(self.byovd_strings)}):")
            for s in self.byovd_strings[:8]:
                lines.append(f"    {s!r}")

        if self.msr_accesses:
            lines.append(f"  MSR accesses ({len(self.msr_accesses)}):")
            for m in self.msr_accesses:
                lines.append(f"    {m.fmt()}")

        if self.capabilities:
            lines.append(f"  Capabilities ({len(self.capabilities)}):")
            seen_classes: Set[str] = set()
            for c in sorted(self.capabilities, key=lambda x: (x.risk != "CRITICAL", x.capability_class)):
                if c.capability_class not in seen_classes:
                    lines.append(f"    {c.fmt()}")
                    seen_classes.add(c.capability_class)

        if not self.is_byovd_capable:
            lines.append("  No BYOVD capabilities detected.")

        return "\n".join(lines)


class ByovdDetector:
    """
    Detect Bring Your Own Vulnerable Driver (BYOVD) capabilities in a .sys file.

    Usage:
        detector = ByovdDetector('/path/to/driver.sys')
        report = detector.detect()
        print(report.fmt())

        if report.is_byovd_capable:
            print("BYOVD-capable driver detected!")
            for cap in report.capabilities:
                print(f"  {cap.capability_class}: {cap.api_name}")

    From an existing KernelDriverReport:
        kda_report = KernelDriverAnalyzer.from_path('/path/driver.sys').analyze()
        detector = ByovdDetector('/path/driver.sys', kda_report=kda_report)
        report = detector.detect()
    """

    def __init__(
        self,
        driver_path: str,
        kda_report: Optional["KernelDriverReport"] = None,
    ):
        self.driver_path = driver_path
        self._kda_report = kda_report
        self._data = Path(driver_path).read_bytes()
        self._pe = lief.parse(driver_path)

        if _HAS_CAPSTONE:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            md.detail = True
            self._md = md
        else:
            self._md = None

    @classmethod
    def from_path(cls, driver_path: str) -> "ByovdDetector":
        return cls(driver_path)

    def _get_imports(self) -> Dict[str, int]:
        """Returns {import_name: IAT_address}."""
        imports: Dict[str, int] = {}
        if not self._pe:
            return imports
        try:
            for imp in self._pe.imports:
                for entry in imp.entries:
                    if entry.name and entry.iat_address:
                        imports[entry.name] = entry.iat_address
        except Exception:
            pass
        return imports

    def _scan_for_byovd_strings(self) -> List[str]:
        """Find BYOVD-relevant strings in the binary."""
        found = []
        data = self._data
        for needle in _BYOVD_STRINGS:
            # Check both ASCII and UTF-16LE
            if needle.encode("ascii") in data:
                found.append(needle)
            elif needle.encode("utf-16-le") in data:
                found.append(f"{needle} (UTF-16LE)")
        return found

    def _check_known_byovd_pdb(self, pdb_path: Optional[str]) -> Optional[str]:
        if not pdb_path:
            return None
        pdb_lower = pdb_path.lower()
        for fragment in _KNOWN_BYOVD_PDB:
            if fragment.lower() in pdb_lower:
                return fragment
        return None

    def _scan_msr_accesses(self) -> List[ByovdMsrAccess]:
        """Scan binary for RDMSR/WRMSR instructions."""
        if not self._md:
            return []

        accesses: List[ByovdMsrAccess] = []
        if not self._pe:
            return accesses

        try:
            for sec in self._pe.sections:
                if not (sec.characteristics & 0x20):  # IMAGE_SCN_CNT_CODE
                    continue
                sec_va = sec.virtual_address
                try:
                    image_base = self._pe.optional_header.imagebase
                    sec_va += image_base
                except Exception:
                    pass
                sec_data = bytes(sec.content)
                if not sec_data:
                    continue

                for insn in self._md.disasm(sec_data, sec_va):
                    if insn.id == X86_INS_WRMSR:
                        accesses.append(ByovdMsrAccess(
                            kind="WRMSR",
                            offset=insn.address,
                            description=(
                                "WRMSR writes to MSR register. "
                                "BYOVD pattern: IOCTL passes ECX=0xC0000082 (LSTAR) + "
                                "EDX:EAX = attacker shellcode VA -> syscall hijack."
                            ),
                        ))
                    elif insn.id == X86_INS_RDMSR:
                        accesses.append(ByovdMsrAccess(
                            kind="RDMSR",
                            offset=insn.address,
                            description=(
                                "RDMSR reads from MSR register. "
                                "BYOVD pattern: IOCTL with ECX=0xC0000082 (LSTAR) "
                                "reads syscall handler VA -> KASLR defeat."
                            ),
                        ))
        except Exception:
            pass

        return accesses

    def detect(self) -> ByovdReport:
        """Run full BYOVD detection on the driver."""
        # Parse with KernelDriverAnalyzer if not pre-supplied
        if self._kda_report is None and _HAS_KDA:
            try:
                kda = KernelDriverAnalyzer.from_path(self.driver_path)
                self._kda_report = kda.analyze()
            except Exception:
                pass

        driver_type = "unknown"
        is_signed = False
        pdb_path: Optional[str] = None

        if self._kda_report is not None:
            driver_type = self._kda_report.driver_type
            is_signed = self._kda_report.is_signed
            pdb_path = self._kda_report.pdb_path

        # Stage 1: import-based capability detection
        imports = self._get_imports()
        capabilities: List[ByovdCapability] = []

        for api_name, iat_va in imports.items():
            cap_class = CAPABILITY_MAP.get(api_name)
            if cap_class:
                risk = CAPABILITY_RISK.get(cap_class, "MEDIUM")
                capabilities.append(ByovdCapability(
                    api_name=api_name,
                    capability_class=cap_class,
                    risk=risk,
                    evidence=f"IAT import at 0x{iat_va:x}",
                    file_offset=iat_va,
                ))

        # Also check KDA API findings if available
        if self._kda_report is not None:
            for finding in self._kda_report.kernel_api_findings:
                cap_class = CAPABILITY_MAP.get(finding.api)
                if cap_class and not any(c.api_name == finding.api for c in capabilities):
                    risk = CAPABILITY_RISK.get(cap_class, "MEDIUM")
                    capabilities.append(ByovdCapability(
                        api_name=finding.api,
                        capability_class=cap_class,
                        risk=risk,
                        evidence=f"Found in binary (risk_class={finding.category})",
                    ))

        # Stage 2: dangerous pattern flags from KDA
        if self._kda_report is not None:
            for dp in self._kda_report.dangerous_patterns:
                if "WRMSR" in dp.pattern or "MSR_LSTAR" in dp.pattern:
                    # Already caught by _scan_msr_accesses; skip duplicate
                    pass
                if "MmMapIoSpace" in dp.description and not any(
                    c.api_name == "MmMapIoSpace" for c in capabilities
                ):
                    capabilities.append(ByovdCapability(
                        api_name="MmMapIoSpace",
                        capability_class="PHYS_MEM_RW",
                        risk="CRITICAL",
                        evidence=f"Dangerous pattern: {dp.description[:80]}",
                        file_offset=dp.offset,
                    ))

        # Stage 3: string evidence
        byovd_strings = self._scan_for_byovd_strings()

        # Stage 4: MSR instruction scan
        msr_accesses = self._scan_msr_accesses()
        # Add MSR_WRITE capability if WRMSR found
        if any(m.kind == "WRMSR" for m in msr_accesses):
            capabilities.append(ByovdCapability(
                api_name="WRMSR",
                capability_class="MSR_WRITE",
                risk="CRITICAL",
                evidence="WRMSR instruction in executable code",
            ))
        if any(m.kind == "RDMSR" for m in msr_accesses):
            if not any(c.api_name == "RDMSR" for c in capabilities):
                capabilities.append(ByovdCapability(
                    api_name="RDMSR",
                    capability_class="MSR_WRITE",
                    risk="HIGH",
                    evidence="RDMSR instruction (KASLR defeat potential)",
                ))

        # Stage 5: known BYOVD match
        known_match = self._check_known_byovd_pdb(pdb_path)
        if not known_match:
            # Also check device name strings
            for s in byovd_strings:
                for fragment in _KNOWN_BYOVD_PDB:
                    if fragment.lower() in s.lower():
                        known_match = fragment
                        break

        return ByovdReport(
            binary_path=self.driver_path,
            driver_type=driver_type,
            is_signed=is_signed,
            pdb_path=pdb_path,
            capabilities=capabilities,
            msr_accesses=msr_accesses,
            byovd_strings=byovd_strings,
            known_byovd_match=known_match,
        )


def screen_directory(dir_path: str) -> List[ByovdReport]:
    """
    Screen all .sys files in a directory for BYOVD capabilities.

    Returns reports sorted by risk level (CRITICAL first).
    """
    import os
    reports = []
    for fname in os.listdir(dir_path):
        if fname.lower().endswith(".sys"):
            fpath = os.path.join(dir_path, fname)
            try:
                detector = ByovdDetector(fpath)
                report = detector.detect()
                if report.is_byovd_capable:
                    reports.append(report)
            except Exception:
                continue

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    return sorted(reports, key=lambda r: order.get(r.risk_level, 99))


# CLI compatibility alias: `det.analyze()` same as `det.detect()`
ByovdDetector.analyze = ByovdDetector.detect  # type: ignore[attr-defined]

# CLI import alias: `from ablation.analyzers.byovd_detector import BYOVDDetector`
BYOVDDetector = ByovdDetector
