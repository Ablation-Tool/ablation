"""
TI Neural Network Compiler (NNC) inference artifact scanner.

Detects TVM-generated `tvmgen_*` symbols in ARM ELF firmware compiled by the TI
NNC (ti_mcu_nnc, v2.x).  The NNC is built on Apache TVM and produces libraries for
TI MCU targets: F28P55x (C28x), MSPM0 (Cortex-M0+), CC2745/AM13x (Cortex-M33),
CC1352 (Cortex-M4), AM26x (Cortex-R5), F29H85x (C29x).

Security surface:
    NNC-generated headers declare normalization arrays as __attribute__((weak)):
        extern const float tvmgen_default_bias_data[]  __attribute__((weak));
        extern const float tvmgen_default_scale_data[] __attribute__((weak));
        extern const int32_t tvmgen_default_shift_data[] __attribute__((weak));
    Any object linked after mod.a that provides a strong symbol of the same name
    silently overrides the normalization parameters, changing the float->int8
    quantization boundary without any compile-time or run-time warning.

Finding classes:
    TINCC-001  HIGH    Weak normalization symbol override risk
    TINCC-002  MEDIUM  NPU async completion flag — ordering hazard
    TINCC-003  MEDIUM  Multi-model NPU contention (sequential enforcement required)
    TINCC-004  INFO    Skip-normalize mode active — manual normalization required

C28x (F28P55x) note:
    cl2000 emits COFF, not ELF.  This scanner requires ELF.  C28x firmware is
    not supported until Gap 1 (C28x ISA decoder with COFF loader) ships.

Usage::

    from ablation.analyzers.ti_nnc_scanner import TiNNCScanner

    scanner = TiNNCScanner.from_path('/path/to/firmware.elf')
    result  = scanner.scan()
    print(TiNNCScanner.report(result))
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import lief
    _LIEF_OK = True
except ImportError:
    _LIEF_OK = False


# ---------------------------------------------------------------------------
# NNC symbol name patterns
# ---------------------------------------------------------------------------

# Matches:  tvmgen_<name>_run
_RE_RUN        = re.compile(r'^tvmgen_([a-zA-Z0-9_]+)_run$')
# Matches:  tvmgen_<name>_finished   (volatile int32_t — NPU HW mode only)
_RE_FINISHED   = re.compile(r'^tvmgen_([a-zA-Z0-9_]+)_finished$')
# Matches:  tvmgen_<name>_bias_data / scale_data / shift_data  (NPU-QAT norm)
_RE_NPU_NORM   = re.compile(
    r'^tvmgen_([a-zA-Z0-9_]+)_(bias_data|scale_data|shift_data)$'
)
# Matches:  tvmgen_<name>_input_reciprocal_scale_data / input_zero_point_data
#           tvmgen_<name>_output_scale_data / output_zero_point_data  (CPU QDQ)
_RE_QDQ_NORM   = re.compile(
    r'^tvmgen_([a-zA-Z0-9_]+)_'
    r'(input_reciprocal_scale_data|input_zero_point_data|'
    r'output_scale_data|output_zero_point_data)$'
)

# Normalization symbol suffixes that are __attribute__((weak)) per NNC spec
_WEAK_NORM_SUFFIXES = frozenset({
    'bias_data',
    'scale_data',
    'shift_data',
    'input_reciprocal_scale_data',
    'input_zero_point_data',
    'output_scale_data',
    'output_zero_point_data',
})

# Symbol names that indicate hardware NPU mode
_NPU_INIT_NAMES = frozenset({'TI_NPU_init', '_TI_NPU_init'})


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class NormSymbol:
    """A normalization parameter symbol extracted from the ELF symbol table."""
    symbol_name: str
    suffix: str              # 'bias_data' | 'scale_data' | 'shift_data' | ...
    binding: str             # 'WEAK' | 'GLOBAL' | 'LOCAL' | 'OTHER'
    va: int
    size: int                # bytes; 0 if unknown
    values: Optional[List[float]] = None  # extracted from .rodata if reachable


@dataclass
class TiNNCModule:
    """One compiled TVM model (one tvmc compile invocation → one mod.a)."""
    name: str                           # e.g. 'default', 'a', 'b'
    run_va: int                         # tvmgen_<name>_run VA
    execution_mode: str                 # 'npu_hw' | 'npu_soft' | 'unknown'
    has_finished_flag: bool             # tvmgen_<name>_finished present
    norm_symbols: List[NormSymbol]      # all normalization symbols found
    weak_norm_symbols: List[str]        # subset with WEAK binding


@dataclass
class TiNNCScanFinding:
    finding_id: str          # e.g. 'TINCC-001'
    severity: str            # 'HIGH' | 'MEDIUM' | 'INFO'
    title: str
    description: str
    module_name: str
    va: int
    symbol: Optional[str] = None


@dataclass
class TiNNCScanResult:
    modules: List[TiNNCModule] = field(default_factory=list)
    findings: List[TiNNCScanFinding] = field(default_factory=list)
    binary_path: str = ''
    has_npu_init: bool = False


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class TiNNCScanner:
    """
    Scans ARM ELF firmware for TI NNC inference artifacts.

    Operates entirely from the ELF symbol table — no disassembly required.
    The primary security finding (TINCC-001 weak-symbol override) is fully
    deterministic from symbol binding metadata.
    """

    def __init__(self, path: str | Path) -> None:
        if not _LIEF_OK:
            raise ImportError(
                'lief is required: pip install lief>=0.14.0'
            )
        self._path = str(path)

    @classmethod
    def from_path(cls, path: str | Path) -> 'TiNNCScanner':
        return cls(path)

    # ------------------------------------------------------------------

    def scan(self) -> TiNNCScanResult:
        result = TiNNCScanResult(binary_path=self._path)

        binary = lief.parse(self._path)
        if binary is None:
            return result

        if not isinstance(binary, lief.ELF.Binary):
            return result

        syms = list(binary.symbols)
        if not syms:
            syms = list(binary.dynamic_symbols)

        # Collect all tvmgen symbols indexed by model name
        run_syms: Dict[str, Tuple[int, lief.ELF.Symbol]] = {}
        finished_syms: Set[str] = set()
        norm_by_model: Dict[str, List[NormSymbol]] = {}

        has_npu_init = False

        for sym in syms:
            name = sym.name
            if not name:
                continue

            if name in _NPU_INIT_NAMES:
                has_npu_init = True
                continue

            m = _RE_RUN.match(name)
            if m:
                model = m.group(1)
                run_syms[model] = (sym.value, sym)
                continue

            m = _RE_FINISHED.match(name)
            if m:
                finished_syms.add(m.group(1))
                continue

            m = _RE_NPU_NORM.match(name)
            if not m:
                m = _RE_QDQ_NORM.match(name)
            if m:
                model = m.group(1)
                suffix = m.group(2)
                binding_str = self._binding_str(sym)
                ns = NormSymbol(
                    symbol_name=name,
                    suffix=suffix,
                    binding=binding_str,
                    va=sym.value,
                    size=sym.size,
                    values=self._extract_floats(binary, sym)
                        if suffix not in ('shift_data', 'input_zero_point_data',
                                          'output_zero_point_data')
                        else self._extract_int32s(binary, sym),
                )
                norm_by_model.setdefault(model, []).append(ns)

        result.has_npu_init = has_npu_init

        # Build TiNNCModule for each run symbol found
        for model_name, (run_va, _) in run_syms.items():
            norms = norm_by_model.get(model_name, [])
            weak_norms = [
                ns.symbol_name for ns in norms
                if ns.binding == 'WEAK'
            ]
            mode = self._infer_mode(model_name, finished_syms, has_npu_init)
            mod = TiNNCModule(
                name=model_name,
                run_va=run_va,
                execution_mode=mode,
                has_finished_flag=model_name in finished_syms,
                norm_symbols=norms,
                weak_norm_symbols=weak_norms,
            )
            result.modules.append(mod)

        result.modules.sort(key=lambda m: m.run_va)

        # Generate findings
        result.findings.extend(self._generate_findings(result))
        return result

    # ------------------------------------------------------------------
    # Finding generation
    # ------------------------------------------------------------------

    def _generate_findings(
        self, result: TiNNCScanResult
    ) -> List[TiNNCScanFinding]:
        findings: List[TiNNCScanFinding] = []
        npu_hw_models = [m for m in result.modules if m.execution_mode == 'npu_hw']

        for mod in result.modules:
            # TINCC-001: weak normalization symbol override
            for sym_name in mod.weak_norm_symbols:
                findings.append(TiNNCScanFinding(
                    finding_id='TINCC-001',
                    severity='HIGH',
                    title='Weak normalization symbol override risk',
                    description=(
                        f'{sym_name} is declared __attribute__((weak)) by the NNC. '
                        'Any object file or shared library linked after mod.a that '
                        'provides a strong symbol of the same name silently overrides '
                        'the normalization parameters, changing the float->int8 '
                        'quantization boundary without warning. Confirmed NNC behavior '
                        'per user guide §3.1.1.'
                    ),
                    module_name=mod.name,
                    va=next(
                        (ns.va for ns in mod.norm_symbols
                         if ns.symbol_name == sym_name), 0
                    ),
                    symbol=sym_name,
                ))

            # TINCC-002: NPU async ordering hazard
            if mod.execution_mode == 'npu_hw' and mod.has_finished_flag:
                findings.append(TiNNCScanFinding(
                    finding_id='TINCC-002',
                    severity='MEDIUM',
                    title='NPU async completion flag — ordering hazard',
                    description=(
                        f'tvmgen_{mod.name}_finished is a volatile int32_t polled '
                        'by the host to detect NPU completion. The NNC spec requires '
                        'the application to spin on this flag before reading outputs '
                        'or before calling a second NPU model. Missing or reordered '
                        'polls read stale output tensors from the previous inference. '
                        'Confirm the caller polls the flag on every inference path.'
                    ),
                    module_name=mod.name,
                    va=mod.run_va,
                    symbol=f'tvmgen_{mod.name}_finished',
                ))

            # TINCC-004: skip-normalize detected
            if mod.norm_symbols:
                findings.append(TiNNCScanFinding(
                    finding_id='TINCC-004',
                    severity='INFO',
                    title='Skip-normalize mode active — manual normalization required',
                    description=(
                        f'Model "{mod.name}" was compiled with skip_normalize=true: '
                        'normalization symbols are present, meaning the model library '
                        'expects pre-quantized int8 input. The caller must apply: '
                        'input_int = clip(((int32_t)((input_float + bias) * scale)) >> shift, '
                        'min, max) before calling tvmgen_{mod.name}_run(). '
                        'If the caller passes raw float data the NPU receives out-of-range '
                        'integers, producing incorrect inference results.'
                    ),
                    module_name=mod.name,
                    va=mod.run_va,
                ))

        # TINCC-003: multi-model NPU contention
        if len(npu_hw_models) > 1:
            names = ', '.join(m.name for m in npu_hw_models)
            findings.append(TiNNCScanFinding(
                finding_id='TINCC-003',
                severity='MEDIUM',
                title='Multi-model NPU contention — sequential enforcement required',
                description=(
                    f'Models [{names}] all target the hardware NPU accelerator. '
                    'The NNC specification prohibits concurrent NPU execution: '
                    'the application must poll tvmgen_X_finished before invoking '
                    'tvmgen_Y_run(). If this ordering is not enforced, NPU microcode '
                    'state is corrupted and inference results from both models are '
                    'invalid. Verify the call sequence against NNC user guide §7.2.2.2.'
                ),
                module_name=npu_hw_models[0].name,
                va=npu_hw_models[0].run_va,
            ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _binding_str(sym: 'lief.ELF.Symbol') -> str:
        try:
            b = sym.binding
            if b == lief.ELF.Symbol.BINDING.WEAK:
                return 'WEAK'
            if b == lief.ELF.Symbol.BINDING.GLOBAL:
                return 'GLOBAL'
            if b == lief.ELF.Symbol.BINDING.LOCAL:
                return 'LOCAL'
        except Exception:
            pass
        return 'OTHER'

    @staticmethod
    def _infer_mode(
        model_name: str,
        finished_syms: Set[str],
        has_npu_init: bool,
    ) -> str:
        if model_name in finished_syms:
            return 'npu_hw'
        if has_npu_init:
            return 'npu_hw'
        return 'npu_soft'

    @staticmethod
    def _extract_floats(
        binary: 'lief.ELF.Binary', sym: 'lief.ELF.Symbol'
    ) -> Optional[List[float]]:
        """Read float32 array from .rodata at sym.value."""
        va = sym.value
        size = sym.size
        if not va or not size or size < 4:
            return None
        try:
            content = bytes(binary.get_content_from_virtual_address(va, size))
            if len(content) < size:
                return None
            count = size // 4
            return list(struct.unpack(f'<{count}f', content[:count * 4]))
        except Exception:
            return None

    @staticmethod
    def _extract_int32s(
        binary: 'lief.ELF.Binary', sym: 'lief.ELF.Symbol'
    ) -> Optional[List[int]]:
        """Read int32 array from .rodata at sym.value."""
        va = sym.value
        size = sym.size
        if not va or not size or size < 4:
            return None
        try:
            content = bytes(binary.get_content_from_virtual_address(va, size))
            if len(content) < size:
                return None
            count = size // 4
            return list(struct.unpack(f'<{count}i', content[:count * 4]))
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    @staticmethod
    def report(result: TiNNCScanResult) -> str:
        lines: List[str] = []
        lines.append(f'TI NNC Scanner — {result.binary_path}')
        lines.append(f'  Models found : {len(result.modules)}')
        lines.append(f'  NPU init     : {"yes" if result.has_npu_init else "no"}')
        lines.append('')

        for mod in result.modules:
            lines.append(
                f'  [{mod.name}]  run=0x{mod.run_va:08x}  '
                f'mode={mod.execution_mode}  '
                f'finished_flag={"yes" if mod.has_finished_flag else "no"}'
            )
            for ns in mod.norm_symbols:
                vals = ''
                if ns.values is not None:
                    vals = '  values=' + repr(ns.values[:4]) + (
                        '...' if len(ns.values) > 4 else ''
                    )
                lines.append(
                    f'    {ns.binding:6s}  0x{ns.va:08x}  {ns.symbol_name}{vals}'
                )
        if result.modules:
            lines.append('')

        if not result.findings:
            lines.append('  No findings.')
            return '\n'.join(lines)

        sev_order = {'HIGH': 0, 'MEDIUM': 1, 'INFO': 2}
        for f in sorted(result.findings, key=lambda x: sev_order.get(x.severity, 9)):
            lines.append(f'  [{f.severity}] {f.finding_id}: {f.title}')
            lines.append(f'    module={f.module_name}  va=0x{f.va:08x}')
            if f.symbol:
                lines.append(f'    symbol={f.symbol}')
            for chunk in _wrap(f.description, 72):
                lines.append(f'    {chunk}')
            lines.append('')

        return '\n'.join(lines)


def _wrap(text: str, width: int) -> List[str]:
    """Naive word-wrap for report output."""
    words = text.split()
    lines: List[str] = []
    current = ''
    for w in words:
        if current and len(current) + 1 + len(w) > width:
            lines.append(current)
            current = w
        else:
            current = (current + ' ' + w).lstrip()
    if current:
        lines.append(current)
    return lines
