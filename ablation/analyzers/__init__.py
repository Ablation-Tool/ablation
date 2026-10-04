from .semantic_search import SemanticSearcher, describe_function, normalize_asm, WhiteningTransform
from .taint_tracker_arm32 import ARM32TaintTracker, TaintFinding32, TaintState32
from .intoverflow_scanner_arm32 import ARM32IntOverflowScanner, IntOverflowFinding32
from .arm32_reg_annotator import ARM32RegAnnotator
from .taint_tracker_arm64 import ARM64TaintTracker, TaintFindingARM64
from .arm64_fgets_fd_discriminator import ARM64FgetsFdDiscriminator, FgetsClassifiedFinding
from .version_delta import VersionTracker, diff_functions
from .func_id_db import FuncDB
from .go_pclntab import GoFuncTable
from .go_string_resolver import GoStringResolver, build_resolver_from_elf
from .go_subprocess_scanner import GoSubprocessScanner, scan_binary, SubprocessSite
from .finding_registry import FindingRegistry
from .xref_graph import XRefGraph
from .taint_tracker_x86 import TaintTracker, TaintFinding, TaintState, InterproceduralPath
from .cfg_builder import CFGBuilder, CFG, BasicBlock
from .bss_taint_tracker import BssTaintTracker, BSSSymbol, Function as BssFunction, BasicBlock as BssBasicBlock, build_function as bss_build_function
from .window_analyzer import WindowAnalyzer
from .binary_context import BinaryContext
from .lib_graph import LibGraph, LibCaller
from .reg_annotator import RegAnnotator, RegVal, CallSite, AnnotationResult
from .func_profiler import FuncProfiler, FuncProfile, ProfiledCall
from .pattern_library import PatternLibrary, Pattern, SweepResult
from .ipreg_annotator import IPRegAnnotator, IPChain, ChainResult, ChainCallSite
from .opseq import OpSeqEncoder, CAT_INDEX, CAT_NAMES, NUM_CATS, seq_to_str, seq_histogram, mnemonic_to_cat
from .matrix_profile_diff import MatrixProfileDiff, DiffResult, ChangeRegion
from .dtw_matcher import DTWMatcher, HomologMatch, SimilarityReport, dtw_distance, dtw_similarity
from .sax_index import SAXIndex, SAXMatch, IndexEntry, encode_sax, sax_mindist
from .subsequence_searcher import SubsequenceSearcher, PatternMatch, parse_pattern
from .taint_tracker_mips64 import MIPS64TaintTracker, TaintFinding64, InterproceduralPath64
from .nanomips_decoder import NanoMIPSDecoder, NanoMIPSDisasm, NanoFrame
from .taint_tracker_nanomips import NanoMIPSTaintTracker, NanoMIPSTaintFinding, NanoMIPSInterproceduralPath
from .taint_tracker_ppc32 import PPC32TaintTracker, TaintFindingPPC32
from .ppc32_plt_tracer import PPC32PLTTracer, PPC32ELF, PLTCallSite, batch_sweep as ppc32_batch_sweep, batch_scan as ppc32_batch_scan
from .taint_tracker_ppc64 import PPC64TaintTracker, TaintFindingPPC64
from .arc_decoder import ARCDecoder, ARCDisasm, ARCFrame
from .taint_tracker_arc import ARCTaintTracker, TaintFindingARC
from .taint_tracker_riscv32 import RISCV32TaintTracker, TaintFindingRISCV32
from .taint_tracker_riscv64 import RISCV64TaintTracker, TaintFindingRISCV64
from .v850_decoder import V850Decoder, V850Disasm, V850Frame
from .taint_tracker_v850 import V850TaintTracker, TaintFindingV850
from .loongarch_decoder import LoongArchDecoder, LoongArchFrame
from .loongarch_decoder_v2 import (
    LoongArchDecoderV2, LoongArchFrameV2, LoongArchDisasmV2,
    KASAN_SYMBOL_PREFIXES, KCOV_SYMBOL_PREFIXES,
)
from .loongarch64_max_not_min_scanner import LA64MaxNotMinScanner, LA64MaxNotMinFinding
from .la64_heap_vuln_scanner import LA64HeapVulnScanner, LA64HeapVulnFinding
from .taint_tracker_loongarch64 import (
    LoongArch64TaintTracker, TaintFindingLA64,
    _ESCALATION_NAMES as LOONGARCH_ESCALATION_NAMES,
)
from .syscall_loongarch64 import (
    SYSCALL_TABLE as LOONGARCH_SYSCALL_TABLE,
    classify_syscall as loongarch_classify_syscall,
)
from .dwarf_loongarch64 import (
    extract_eh_frame_starts,
    extract_debug_funcs,
    extract_btf_funcs,
)
from .beam_context import (
    BeamContext, BeamExport, BeamImport, BeamAstFunction,
    BeamDiffEntry,
    sweep_beam_dir, fmt_sweep,
    sweep_beam_diff, fmt_sweep_diff,
    SEVERITY_DISPATCH, SEVERITY_NETWORK, SEVERITY_INFO,
    SEVERITY_CODE_EVAL, SEVERITY_CODE_EXEC,
)
# ── Source Code Auditor ───────────────────────────────────────────────────────
# Audit any large codebase for security vulnerabilities.
# Entry point: SourceAuditCompressor (source_audit_compressor.py)
# Full pipeline: SourceContext -> SourceAuditCompressor -> SourceEntryClassifier
#                -> SourceSinkScanner -> SourceIsolationChecker -> SourceTaintTracker
from .source_ingestion import SourceContext
from .source_entry_classifier import SourceEntryClassifier, RouteClassification, AUTH_NONE, AUTH_API_KEY, AUTH_SESSION, AUTH_INTERNAL, AUTH_ADMIN
from .source_sink_scanner import SourceSinkScanner, SinkHit
from .source_arch_risk import SourceArchRiskScanner, ArchRiskFinding
from .source_audit_compressor import SourceAuditCompressor, FileProfile, ProfileBucket
from .source_isolation_checker import SourceIsolationChecker, IsolationFinding
from .source_taint_tracker import SourceTaintTracker, TaintPath, TaintHop, CallGraph
from .sink_arg_classifier import (
    SinkArgClassifier, SinkClassification,
    RODATA_CONST, SNPRINTF_RODATA, ARG_PROPAGATED, UNKNOWN as SINK_UNKNOWN,
    _count_plt_callers, batch_plt_intersect,
)
from .sanitizer_detector import SanitizerDetector, SanitizerProfile, SHELL_METACHARACTERS
from .fork_exec_classifier import (
    ForkExecClassifier, ForkCallerResult,
    WORKER, EXEC_AFTER_FORK, EXIT_IN_CHILD, UNKNOWN as FORK_UNKNOWN,
)
from .vendor_profile import VendorProfile
from .dex_analyzer import DexAnalyzer, DexFinding
from .jni_bridge_scanner import JniBridgeScanner, JniBridgeFinding
from .binder_scanner import BinderScanner, BinderFinding
from .dex_disasm import DEXDisasm, DEXInstruction, decode_code_item
from .dex_lifter import DEXLifter, RegVal
from .binary_lifter import BinaryLifter, NativeVal
from .hypothesis_models import (
    ConfidenceState, EvidenceRelation, EVIDENCE_FAMILIES, HYPOTHESIS_KINDS,
    HypothesisRecord, EvidenceRecord, ProbeRecord, HypothesisSession,
)
from .evidence_scorer import EvidenceScorer, score_report
from .probe_ranker import ProbeRanker, probe_kinds
from .hypothesis_engine import HypothesisEngine
from .probe_adapters import (
    ProbeAdapter,
    DisassemblyAdapter, CFGAdapter, XRefAdapter,
    LifterAdapter, SemanticAdapter, VersionAdapter,
    TaintAdapter, ManualAdapter,
    execute_probe, available_kinds,
)
from .dynamic_sandbox import DynamicSandbox, DynamicProbeAdapter, SandboxResult, LeafFunctionChecker
from .engine_pattern_library import (
    EnginePatternLibrary, EngineSignature, EngineLabel,
    ENGINES, CATEGORIES,
)
from .safecode import SAFECODE, SafecodeReport, SafecodeFinding
from .lsb_stego_extractor import (
    LSBStegoReader, LagrangeKeyExtractor, BmpKeyExtractor,
    StegoKeyResult, CoordPair,
)
from .crypto_pattern_detector import (
    HashAlgoDiscriminator, HashAlgoMatch, ConstMatch,
    CustomCBCDetector, CBCPattern,
)
from .abc_parser import (
    ABCParser, ABCHeader, ABCIndexHeader,
    MethodInfo, CodeItem, FieldInfo, ClassInfo,
)
from .abc_disasm import ARKDisasm, ARKInstruction
from .abc_decompiler import ABCDecompiler

__all__ = [
    "SemanticSearcher", "describe_function", "normalize_asm", "WhiteningTransform",
    "ARM32TaintTracker", "TaintFinding32", "TaintState32",
    "ARM32IntOverflowScanner", "IntOverflowFinding32",
    "ARM32RegAnnotator",
    "ARM64TaintTracker", "TaintFindingARM64",
    "ARM64FgetsFdDiscriminator", "FgetsClassifiedFinding",
    "VersionTracker", "diff_functions",
    "FuncDB",
    "GoFuncTable",
    "GoStringResolver", "build_resolver_from_elf",
    "GoSubprocessScanner", "scan_binary", "SubprocessSite",
    "FindingRegistry",
    "XRefGraph",
    "TaintTracker", "TaintFinding", "TaintState", "InterproceduralPath",
    "CFGBuilder", "CFG", "BasicBlock",
    "BssTaintTracker", "BSSSymbol", "BssFunction", "BssBasicBlock", "bss_build_function",
    "WindowAnalyzer",
    "BinaryContext",
    "LibGraph", "LibCaller",
    "RegAnnotator", "RegVal", "CallSite", "AnnotationResult",
    "FuncProfiler", "FuncProfile", "ProfiledCall",
    "PatternLibrary", "Pattern", "SweepResult",
    "IPRegAnnotator", "IPChain", "ChainResult", "ChainCallSite",
    "OpSeqEncoder", "CAT_INDEX", "CAT_NAMES", "NUM_CATS", "seq_to_str", "seq_histogram", "mnemonic_to_cat",
    "MatrixProfileDiff", "DiffResult", "ChangeRegion",
    "DTWMatcher", "HomologMatch", "SimilarityReport", "dtw_distance", "dtw_similarity",
    "SAXIndex", "SAXMatch", "IndexEntry", "encode_sax", "sax_mindist",
    "SubsequenceSearcher", "PatternMatch", "parse_pattern",
    "MIPS64TaintTracker", "TaintFinding64", "InterproceduralPath64",
    "NanoMIPSDecoder", "NanoMIPSDisasm", "NanoFrame",
    "NanoMIPSTaintTracker", "NanoMIPSTaintFinding", "NanoMIPSInterproceduralPath",
    "PPC32TaintTracker", "TaintFindingPPC32",
    "PPC32PLTTracer", "PPC32ELF", "PLTCallSite", "ppc32_batch_sweep", "ppc32_batch_scan",
    "PPC64TaintTracker", "TaintFindingPPC64",
    "ARCDecoder", "ARCDisasm", "ARCFrame",
    "ARCTaintTracker", "TaintFindingARC",
    "RISCV32TaintTracker", "TaintFindingRISCV32",
    "RISCV64TaintTracker", "TaintFindingRISCV64",
    "V850Decoder", "V850Disasm", "V850Frame",
    "V850TaintTracker", "TaintFindingV850",
    "LoongArchDecoder", "LoongArchFrame",
    "LoongArchDecoderV2", "LoongArchFrameV2", "LoongArchDisasmV2",
    "KASAN_SYMBOL_PREFIXES", "KCOV_SYMBOL_PREFIXES",
    "LA64MaxNotMinScanner", "LA64MaxNotMinFinding",
    "LA64HeapVulnScanner", "LA64HeapVulnFinding",
    "LoongArch64TaintTracker", "TaintFindingLA64",
    "LOONGARCH_ESCALATION_NAMES",
    "LOONGARCH_SYSCALL_TABLE", "loongarch_classify_syscall",
    "extract_eh_frame_starts", "extract_debug_funcs", "extract_btf_funcs",
    "BeamContext", "BeamExport", "BeamImport", "BeamAstFunction", "BeamDiffEntry",
    "sweep_beam_dir", "fmt_sweep", "sweep_beam_diff", "fmt_sweep_diff",
    "SEVERITY_DISPATCH", "SEVERITY_NETWORK", "SEVERITY_INFO",
    "SEVERITY_CODE_EVAL", "SEVERITY_CODE_EXEC",
    "SourceContext",
    "SourceEntryClassifier", "RouteClassification",
    "AUTH_NONE", "AUTH_API_KEY", "AUTH_SESSION", "AUTH_INTERNAL", "AUTH_ADMIN",
    "SourceSinkScanner", "SinkHit",
    "SourceArchRiskScanner", "ArchRiskFinding",
    "SourceAuditCompressor", "FileProfile", "ProfileBucket",
    "SourceIsolationChecker", "IsolationFinding",
    "SourceTaintTracker", "TaintPath", "TaintHop", "CallGraph",
    "SinkArgClassifier", "SinkClassification",
    "RODATA_CONST", "SNPRINTF_RODATA", "ARG_PROPAGATED", "SINK_UNKNOWN",
    "_count_plt_callers", "batch_plt_intersect",
    "SanitizerDetector", "SanitizerProfile", "SHELL_METACHARACTERS",
    "ForkExecClassifier", "ForkCallerResult",
    "WORKER", "EXEC_AFTER_FORK", "EXIT_IN_CHILD", "FORK_UNKNOWN",
    "VendorProfile",
    # ── Android / DEX / JNI / Binder ───────────────────────────────────────
    "DexAnalyzer", "DexFinding",
    "JniBridgeScanner", "JniBridgeFinding",
    "BinderScanner", "BinderFinding",
    "DEXDisasm", "DEXInstruction", "decode_code_item",
    "DEXLifter", "RegVal",
    "BinaryLifter", "NativeVal",
    # ── Active Hypothesis Engine ────────────────────────────────────────────────
    "ConfidenceState", "EvidenceRelation", "EVIDENCE_FAMILIES", "HYPOTHESIS_KINDS",
    "HypothesisRecord", "EvidenceRecord", "ProbeRecord", "HypothesisSession",
    "EvidenceScorer", "score_report",
    "ProbeRanker", "probe_kinds",
    "HypothesisEngine",
    # ── Probe Adapters (Milestone 3 — auto-execution) ───────────────────────────
    "ProbeAdapter",
    "DisassemblyAdapter", "CFGAdapter", "XRefAdapter",
    "LifterAdapter", "SemanticAdapter", "VersionAdapter",
    "TaintAdapter", "ManualAdapter",
    "execute_probe", "available_kinds",
    # ── Dynamic Sandbox (Phase 3 — Unicorn leaf-function execution) ────────────
    "DynamicSandbox", "DynamicProbeAdapter", "SandboxResult", "LeafFunctionChecker",
    # ── Engine Pattern Library (PC game engine-stripping) ──────────────────────
    "EnginePatternLibrary", "EngineSignature", "EngineLabel", "ENGINES", "CATEGORIES",
    # ── Steganography / secret-sharing key extraction ───────────────────────
    "LSBStegoReader", "LagrangeKeyExtractor", "BmpKeyExtractor",
    "StegoKeyResult", "CoordPair",
    # ── Crypto pattern recognition (binary / disassembly) ───────────────────
    "HashAlgoDiscriminator", "HashAlgoMatch", "ConstMatch",
    "CustomCBCDetector", "CBCPattern",
    # ── SAFECODE ─────────────────────────────────────────────────────────────
    "SAFECODE", "SafecodeReport", "SafecodeFinding",
    # ── HarmonyOS / ArkTS ────────────────────────────────────────────────────
    "ABCParser", "ABCHeader", "ABCIndexHeader",
    "MethodInfo", "CodeItem", "FieldInfo", "ClassInfo",
    "ARKDisasm", "ARKInstruction",
    "ABCDecompiler",
]
