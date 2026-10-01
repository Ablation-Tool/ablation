"""
engine_pattern_library.py — Engine code labeling for PC game RE.

Labels functions in a stripped game binary as known engine code (UE4/UE5,
id Tech, Unity il2cpp, Source 2, CryEngine) using three passes:

  1. String-marker pass   — unique string constants embedded near a function
  2. Semantic pass        — SemanticSearcher description matching
  3. SAX structural pass  — opcode-sequence approximate nearest-neighbor

Labeled functions are marked "strip" — the analyst focuses only on the
unlabeled residual, which is the game-specific code.

Goal: label 60-80% of a typical AAA game binary, leaving the game-specific
20-40% for human reverse engineering.

Usage:
    from ablation.analyzers.engine_pattern_library import EnginePatternLibrary

    lib = EnginePatternLibrary.default()
    ctx = BinaryContext.load_or_build('/path/to/game.exe')
    xg  = XRefGraph.from_path('/path/to/game.exe')
    xg.build()

    labels = lib.label_binary(ctx, xg)
    print(lib.strip_report(labels, len(ctx.func_starts)))

    # Filter out labeled functions before manual RE
    unlabeled = [va for va in ctx.func_starts if va not in labels]
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# ── Engine identifiers ────────────────────────────────────────────────────────

ENGINES = {
    "unreal":   "Unreal Engine (UE4/UE5)",
    "id_tech":  "id Tech (id Tech 6/7, idTech 4)",
    "unity":    "Unity il2cpp",
    "source2":  "Source 2 (Valve)",
    "cryengine": "CryEngine / CRYENGINE",
    "frostbite": "Frostbite (EA DICE)",
    "gamemaker": "GameMaker Studio",
    "unknown":  "Unknown engine",
}

# Function categories used across engines
CATEGORIES = {
    "memory":       "Memory allocation / deallocation",
    "math":         "Math / vector / matrix",
    "string":       "String operations",
    "container":    "Containers (array, map, set, list)",
    "render":       "Rendering (GPU commands, draw calls)",
    "physics":      "Physics simulation",
    "audio":        "Audio / sound",
    "reflection":   "Reflection / type system",
    "scripting":    "Scripting VM / blueprint / Lua",
    "io":           "File I/O / asset loading",
    "thread":       "Threading / job system",
    "net":          "Networking / serialization",
    "debug":        "Debug / logging / assert",
    "init":         "Module init / shutdown",
    "runtime":      "Runtime support (stdcxx, CRT)",
    "gameplay":     "Gameplay logic",
    "unknown":      "Unknown",
}


# ── EngineSignature ───────────────────────────────────────────────────────────

@dataclass
class EngineSignature:
    """A named, labeled function signature from a known game engine."""

    sig_id: str                     # stable identifier, e.g. "ue4.fmemory.malloc"
    engine: str                     # key from ENGINES
    category: str                   # key from CATEGORIES
    name: str                       # canonical function name
    description: str                # natural language description (for SemanticSearcher)
    string_markers: List[str] = field(default_factory=list)
    # Regex patterns that appear in string cross-references of this function
    string_patterns: List[str] = field(default_factory=list)
    arch: str = "any"               # "arm64", "x86_64", "any"
    min_size_insns: int = 2         # ignore functions smaller than this
    max_size_insns: int = 50000     # ignore functions larger than this
    confidence_base: float = 0.70   # base confidence for a semantic match
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EngineSignature":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ── EngineLabel ───────────────────────────────────────────────────────────────

@dataclass
class EngineLabel:
    """A matched engine-code label for a function VA in a target binary."""

    va: int
    engine: str
    category: str
    name: str
    confidence: float
    match_kind: str         # "string_marker", "string_pattern", "semantic", "sax"
    sig_id: str
    notes: str = ""

    def strip(self) -> bool:
        """True if this label is high-confidence enough to strip from manual analysis."""
        return self.confidence >= 0.75

    def to_dict(self) -> Dict[str, Any]:
        return {**asdict(self), "va": hex(self.va)}


# ── Seed corpus ───────────────────────────────────────────────────────────────

def _seed_signatures() -> List[EngineSignature]:
    """Return the built-in seed signature corpus."""
    sigs = []

    # ── Unreal Engine 4/5 ────────────────────────────────────────────────────

    ue4_memory = [
        ("ue4.fmemory.malloc",      "memory",    "FMemory::Malloc",
         "allocate memory via UE4 FMemory interface; calls GMalloc->Malloc",
         ["FMemory::Malloc called with size", "Out of memory: Malloc"], []),
        ("ue4.fmemory.free",        "memory",    "FMemory::Free",
         "free memory via UE4 FMemory interface; calls GMalloc->Free",
         [], []),
        ("ue4.fmemory.realloc",     "memory",    "FMemory::Realloc",
         "reallocate memory via UE4 FMemory; updates allocation size tracking",
         [], []),
        ("ue4.tmalloc.malloc",      "memory",    "FMallocBinned::Malloc",
         "UE4 binned memory allocator; size class lookup + pool allocation",
         ["MallocBinned", "SmallBlockPool", "PoolTableAlignment"], []),
    ]
    ue4_string = [
        ("ue4.fstring.ctor",        "string",    "FString::FString(const TCHAR*)",
         "UE4 FString constructor from wide char; allocates TArray of TCHAR",
         [], []),
        ("ue4.fstring.operator_plus","string",   "FString::operator+",
         "UE4 FString concatenation; appends TCHAR array and null terminator",
         [], []),
        ("ue4.fname.init",          "string",    "FName::Init",
         "UE4 FName initialization; hash lookup in GNameTable; case-insensitive",
         ["GNameTable", "FNameEntry", "NameTable"], [r"GNameTable"]),
    ]
    ue4_container = [
        ("ue4.tarray.add",          "container", "TArray::Add",
         "UE4 TArray::Add; grows backing allocation if needed; appends element",
         [], []),
        ("ue4.tarray.reserve",      "container", "TArray::Reserve",
         "UE4 TArray::Reserve; reallocates backing store to requested capacity",
         [], []),
        ("ue4.tmap.find",           "container", "TMap::Find",
         "UE4 TMap::Find; hash-bucket lookup; returns pointer to value or nullptr",
         [], []),
    ]
    ue4_reflection = [
        ("ue4.uobject.register",    "reflection","UObjectBase::Register",
         "UE4 UObject registration; writes to UObjectArray; calls NotifyRegistrationEvent",
         ["UObjectArray", "GUObjectArray", "NotifyRegistrationEvent", "UClass"], [r"GUObjectArray"]),
        ("ue4.uobject.find",        "reflection","StaticFindObject",
         "UE4 StaticFindObject; searches UObjectArray by class and name",
         ["StaticFindObject", "FindObjectFast"], [r"StaticFindObject"]),
        ("ue4.uclass.construct",    "reflection","UClass::CreateDefaultObject",
         "UE4 UClass::CreateDefaultObject; constructs CDO; calls class constructor",
         ["CreateDefaultObject", "ClassDefaultObject"], [r"ClassDefaultObject"]),
    ]
    ue4_scripting = [
        ("ue4.blueprint.vm",        "scripting", "UObject::ProcessEvent",
         "UE4 Blueprint VM entry point; dispatches EExprToken opcodes; stack-based VM",
         ["ProcessEvent", "EExprToken", "CallFunction", "ByteCode"],
         [r"ProcessEvent", r"EExprToken", r"LocalVariable"]),
        ("ue4.blueprint.call",      "scripting", "UObject::CallFunction",
         "UE4 Blueprint function call dispatch; resolves UFunction from UClass",
         ["CallFunction", "UFunction"], [r"UFunction"]),
    ]
    ue4_render = [
        ("ue4.render.drawcall",     "render",    "FMeshDrawCommandPassSetupTask::Run",
         "UE4 mesh draw command generation; iterates visible mesh elements; emits GPU commands",
         ["MeshDrawCommand", "DrawPrimitive", "FMeshBatch"], [r"MeshDrawCommand"]),
        ("ue4.rhi.createtexture",   "render",    "RHICreateTexture2D",
         "UE4 RHI texture creation; calls platform-specific texture allocator",
         ["RHICreateTexture2D", "FRHITexture", "RHI_COMMAND"], [r"RHICreateTexture"]),
    ]
    ue4_debug = [
        ("ue4.ensure.handler",      "debug",     "FDebug::EnsureFailed",
         "UE4 ensure() failure handler; logs file/line/expression; continues execution",
         ["ensure(", "Assertion failed", "EnsureFailed", "LogOutputDevice"],
         [r"ensure\(", r"EnsureFailed"]),
        ("ue4.check.handler",       "debug",     "FDebug::AssertFailed",
         "UE4 check() / verify() failure handler; aborts with callstack dump",
         ["check(", "checkf(", "CRASH", "AssertFailed", "LogCrash"],
         [r"AssertFailed", r"LogCrash"]),
        ("ue4.log.output",          "debug",     "FOutputDeviceRedirector::Log",
         "UE4 UE_LOG output; routes to console, log file, and in-game output",
         ["UE_LOG", "LogOutputDevice", "GLog->Log"], [r"GLog"]),
    ]

    for group in (ue4_memory, ue4_string, ue4_container, ue4_reflection,
                  ue4_scripting, ue4_render, ue4_debug):
        for (sid, cat, name, desc, markers, patterns) in group:
            sigs.append(EngineSignature(
                sig_id=sid, engine="unreal", category=cat, name=name,
                description=desc, string_markers=markers,
                string_patterns=patterns, confidence_base=0.72,
            ))

    # ── id Tech 6/7 (Doom 2016 / Doom Eternal) ───────────────────────────────

    idtech_memory = [
        ("idtech.heap.alloc",       "memory",    "idHeap::Alloc",
         "id Tech heap allocator; size-class lookup; thread-local magazine allocation",
         ["idHeap::Alloc", "idMemoryManager"], [r"idHeap"]),
        ("idtech.pool.alloc",       "memory",    "idBlockAlloc::Alloc",
         "id Tech block pool allocator; linked list of fixed-size blocks",
         ["idBlockAlloc"], [r"idBlockAlloc"]),
    ]
    idtech_render = [
        ("idtech.render.backend",   "render",    "nvrhi::vulkan::CommandList::draw",
         "id Tech Vulkan render backend; emits vkCmdDraw commands",
         ["vkCmdDraw", "VkCommandBuffer", "NVRHI", "Vulkan"], [r"vkCmdDraw", r"NVRHI"]),
        ("idtech.render.material",  "render",    "idMaterial::Parse",
         "id Tech material parser; reads material declaration from .mtr file",
         ["material {", ".mtr", "idMaterial::Parse"], [r"\.mtr"]),
    ]
    idtech_scripting = [
        ("idtech.script.compile",   "scripting", "idCompiler::CompileFile",
         "id Tech script compiler; tokenizes .script file; emits bytecode",
         ["idCompiler", ".script", "idThread"], [r"\.script", r"idThread"]),
    ]
    idtech_debug = [
        ("idtech.sys.error",        "debug",     "idLib::Error",
         "id Tech fatal error; prints error string; calls sys.Quit",
         ["idLib::Error", "ERROR:", "idLib::FatalError"], [r"idLib::Error"]),
        ("idtech.sys.warning",      "debug",     "idLib::Warning",
         "id Tech warning output; prints to console; continues execution",
         ["idLib::Warning", "WARNING:"], [r"idLib::Warning"]),
    ]

    for group in (idtech_memory, idtech_render, idtech_scripting, idtech_debug):
        for (sid, cat, name, desc, markers, patterns) in group:
            sigs.append(EngineSignature(
                sig_id=sid, engine="id_tech", category=cat, name=name,
                description=desc, string_markers=markers,
                string_patterns=patterns, confidence_base=0.75,
            ))

    # ── Unity il2cpp ─────────────────────────────────────────────────────────
    # il2cpp generates extremely recognizable code patterns

    unity_memory = [
        ("unity.il2cpp.malloc",     "memory",    "il2cpp::utils::Memory::Malloc",
         "Unity il2cpp malloc wrapper; size parameter; zero-initializes on debug builds",
         ["il2cpp", "gc_malloc", "il2cpp_object_new"], [r"il2cpp"]),
        ("unity.il2cpp.gc",         "memory",    "il2cpp_gc_alloc_fixed",
         "Unity il2cpp garbage collector allocation; marks object for GC tracking",
         ["GarbageCollector", "il2cpp_gc_alloc", "GCHandle"], [r"GCHandle", r"il2cpp_gc"]),
    ]
    unity_reflection = [
        ("unity.il2cpp.object_new", "reflection","il2cpp_object_new",
         "Unity il2cpp managed object allocation; looks up Il2CppClass; calls ctor",
         ["Il2CppClass", "il2cpp_object_new", "klass->instance_size"],
         [r"il2cpp_object_new", r"instance_size"]),
        ("unity.il2cpp.resolve",    "reflection","il2cpp_resolve_icall",
         "Unity il2cpp internal call resolver; maps method name to native function pointer",
         ["il2cpp_resolve_icall", "InternalCallMapping"], [r"il2cpp_resolve_icall"]),
        ("unity.il2cpp.array_new",  "reflection","il2cpp_array_new_specific",
         "Unity il2cpp managed array allocation; sets element type, rank, and length",
         ["il2cpp_array_new_specific", "Il2CppArrayBounds"], [r"il2cpp_array"]),
    ]
    unity_string = [
        ("unity.il2cpp.string_new", "string",    "il2cpp_string_new",
         "Unity il2cpp managed string construction; allocates Il2CppString; copies chars",
         ["il2cpp_string_new", "Il2CppString", "string_literals"],
         [r"il2cpp_string", r"Il2CppString"]),
    ]
    unity_debug = [
        ("unity.il2cpp.except",     "debug",     "il2cpp_raise_exception",
         "Unity il2cpp managed exception raise; sets thread exception state; unwinds",
         ["il2cpp_raise_exception", "Il2CppException", "System.Exception"],
         [r"il2cpp_raise_exception"]),
    ]

    for group in (unity_memory, unity_reflection, unity_string, unity_debug):
        for (sid, cat, name, desc, markers, patterns) in group:
            sigs.append(EngineSignature(
                sig_id=sid, engine="unity", category=cat, name=name,
                description=desc, string_markers=markers,
                string_patterns=patterns, confidence_base=0.80,
                notes="il2cpp-generated code has high signature confidence",
            ))

    # ── Source 2 (Valve) ─────────────────────────────────────────────────────

    source2_sigs = [
        ("src2.crt.alloc",          "memory",    "CRTAllocator::Alloc",
         "Source 2 CRT allocator wrapper; tracks allocation counts; calls malloc",
         ["CRTAllocator", "MemAllocDebug"], [r"CRTAllocator"]),
        ("src2.kv3.parse",          "io",        "KeyValues3::ParseKV3",
         "Source 2 KeyValues3 parser; reads .vkv3 binary or text format",
         ["KeyValues3", ".vkv3", "CKV3MemberName"], [r"\.vkv3", r"KeyValues3"]),
        ("src2.entity.spawn",       "gameplay",  "CEntitySystem::SpawnEntityByName",
         "Source 2 entity spawner; looks up entity factory by name; calls constructor",
         ["SpawnEntityByName", "EntityFactory", "CEntityIdentity"],
         [r"SpawnEntityByName", r"EntityFactory"]),
        ("src2.panorama.js",        "scripting", "CPanoramaScript::RunScript",
         "Source 2 Panorama UI JS execution; calls V8 runtime; dispatches panel events",
         ["Panorama", "V8", "PanelEvent", "CPanoramaScript"],
         [r"Panorama", r"PanelEvent"]),
    ]
    for (sid, cat, name, desc, markers, patterns) in source2_sigs:
        sigs.append(EngineSignature(
            sig_id=sid, engine="source2", category=cat, name=name,
            description=desc, string_markers=markers, string_patterns=patterns,
            confidence_base=0.72,
        ))

    # ── CryEngine ─────────────────────────────────────────────────────────────

    cry_sigs = [
        ("cry.sys.warning",         "debug",     "CSystem::Warning",
         "CryEngine system warning; writes to log; increments warning counter",
         ["CSystem::Warning", "VALIDATOR_WARNING"], [r"VALIDATOR_WARNING"]),
        ("cry.entity.spawn",        "gameplay",  "CEntitySystem::SpawnEntity",
         "CryEngine entity spawn; creates IEntity from SEntitySpawnParams",
         ["CEntitySystem", "SEntitySpawnParams", "IEntityClass"],
         [r"SEntitySpawnParams"]),
        ("cry.render.submit",       "render",    "CRenderer::EF_Submit",
         "CryEngine render job submission; sorts render items; calls RenderItems",
         ["EF_Submit", "CRenderer", "SRendItem"], [r"EF_Submit", r"SRendItem"]),
    ]
    for (sid, cat, name, desc, markers, patterns) in cry_sigs:
        sigs.append(EngineSignature(
            sig_id=sid, engine="cryengine", category=cat, name=name,
            description=desc, string_markers=markers, string_patterns=patterns,
            confidence_base=0.70,
        ))

    # ── Cross-engine runtime / stdlib ─────────────────────────────────────────
    # These appear in virtually all game binaries (MSVC CRT, libstdc++, etc.)

    runtime_sigs = [
        ("rt.operator_new",         "runtime",   "operator new",
         "C++ global operator new; allocates memory; throws std::bad_alloc on failure",
         ["bad_alloc", "std::bad_alloc", "__throw_bad_alloc"], [r"bad_alloc"]),
        ("rt.operator_delete",      "runtime",   "operator delete",
         "C++ global operator delete; frees memory; handles nullptr",
         [], []),
        ("rt.stdstring.append",     "runtime",   "std::basic_string::_M_append",
         "GCC/Clang std::string append; grows buffer with exponential realloc",
         [], []),
        ("rt.stdvector.grow",       "runtime",   "std::vector::_M_realloc_insert",
         "GCC/Clang std::vector growth; doubles capacity; moves or copies elements",
         [], []),
        ("rt.terminate",            "runtime",   "std::terminate",
         "C++ terminate handler; calls abort or registered terminate handler",
         ["terminate called", "__cxa_terminate", "std::terminate"], [r"terminate called"]),
        ("rt.pure_virtual",         "runtime",   "__cxa_pure_virtual",
         "C++ pure virtual call; called when abstract method is dispatched at runtime",
         ["pure virtual", "__cxa_pure_virtual"], [r"pure virtual"]),
        ("rt.atexit",               "runtime",   "__cxa_atexit",
         "Register function for execution at program exit; thread-safe via mutex",
         [], []),
        ("rt.printf",               "debug",     "printf / vprintf",
         "C standard library printf; format string parsing; calls putchar or write",
         [], []),
        ("rt.malloc",               "memory",    "malloc (libc)",
         "C standard malloc; calls ptmalloc arena allocator",
         [], []),
        ("rt.memcpy",               "runtime",   "memcpy (optimized)",
         "Optimized memcpy; SIMD wide loads/stores; inline for small sizes",
         [], []),
        ("rt.memset",               "runtime",   "memset (optimized)",
         "Optimized memset; SIMD zero/fill; handles unaligned ends",
         [], []),
        ("rt.strlen",               "runtime",   "strlen",
         "C string length; loops byte by byte or SIMD; returns count excluding null",
         [], []),
    ]
    for (sid, cat, name, desc, markers, patterns) in runtime_sigs:
        sigs.append(EngineSignature(
            sig_id=sid, engine="unknown", category=cat, name=name,
            description=desc, string_markers=markers, string_patterns=patterns,
            confidence_base=0.65,
            notes="cross-engine runtime — present in all game binaries",
        ))

    return sigs


# ── EnginePatternLibrary ──────────────────────────────────────────────────────

class EnginePatternLibrary:
    """Engine code labeling library for PC game RE.

    Maintains a corpus of EngineSignature records and runs three-pass
    labeling over a stripped binary to identify engine code.
    """

    _DEFAULT_PATH = Path.home() / ".ablation" / "engine_patterns.json"

    def __init__(self, signatures: Optional[List[EngineSignature]] = None):
        self._sigs: List[EngineSignature] = list(signatures or [])
        self._compiled_patterns: Dict[str, re.Pattern] = {}

    @classmethod
    def default(cls) -> "EnginePatternLibrary":
        """Load from default storage, falling back to built-in seed corpus."""
        path = cls._DEFAULT_PATH
        if path.exists():
            try:
                return cls.load(str(path))
            except Exception:
                pass
        inst = cls(_seed_signatures())
        return inst

    @classmethod
    def load(cls, path: str) -> "EnginePatternLibrary":
        d = json.loads(Path(path).read_text())
        sigs = [EngineSignature.from_dict(s) for s in d.get("signatures", [])]
        return cls(sigs)

    def save(self, path: Optional[str] = None) -> Path:
        out = Path(path) if path else self._DEFAULT_PATH
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({"signatures": [s.to_dict() for s in self._sigs]}, indent=2))
        return out

    def add_signature(self, sig: EngineSignature) -> None:
        # Replace if same sig_id
        self._sigs = [s for s in self._sigs if s.sig_id != sig.sig_id]
        self._sigs.append(sig)

    def signature_count(self) -> int:
        return len(self._sigs)

    def signatures_for_engine(self, engine: str) -> List[EngineSignature]:
        return [s for s in self._sigs if s.engine == engine]

    # ── Labeling ──────────────────────────────────────────────────────────────

    def label_binary(
        self,
        ctx,                        # BinaryContext
        xg=None,                    # XRefGraph (optional, needed for string-marker pass)
        semantic_searcher=None,     # SemanticSearcher (optional, for semantic pass)
        arch: str = "arm64",
        min_confidence: float = 0.70,
        semantic_top_k: int = 8,
    ) -> Dict[int, EngineLabel]:
        """Label functions in the binary as engine code.

        Returns:
            Dict mapping VA → EngineLabel. Only functions above min_confidence
            are included. Call strip_report() for a coverage summary.
        """
        labels: Dict[int, EngineLabel] = {}

        # Pass 1: string marker matching (exact string constants)
        if xg is not None:
            self._pass_string_markers(ctx, xg, labels, min_confidence)

        # Pass 2: string pattern matching (regex in string xrefs)
        if xg is not None:
            self._pass_string_patterns(ctx, xg, labels, min_confidence)

        # Pass 3: semantic description matching
        if semantic_searcher is not None:
            self._pass_semantic(semantic_searcher, labels, min_confidence, semantic_top_k)

        return labels

    def label_binary_fast(
        self,
        ctx,
        xg,
        min_confidence: float = 0.70,
    ) -> Dict[int, EngineLabel]:
        """String-marker + string-pattern passes only. No semantic model required."""
        return self.label_binary(ctx, xg, semantic_searcher=None, min_confidence=min_confidence)

    def _pass_string_markers(
        self,
        ctx,
        xg,
        labels: Dict[int, EngineLabel],
        min_confidence: float,
    ) -> None:
        """Pass 1: exact string constant matching."""
        # Build string content → set of function VAs
        string_to_funcs: Dict[str, Set[int]] = {}
        for s_va in getattr(ctx, "string_vas", []):
            try:
                s = ctx.string_at(s_va)
            except Exception:
                continue
            funcs = xg.funcs_referencing_string(s_va) if hasattr(xg, "funcs_referencing_string") else []
            for fva in funcs:
                string_to_funcs.setdefault(s, set()).add(fva)

        for sig in self._sigs:
            for marker in sig.string_markers:
                fvas = string_to_funcs.get(marker, set())
                for fva in fvas:
                    if fva in labels:
                        continue
                    confidence = min(1.0, sig.confidence_base + 0.15)  # boost for exact match
                    if confidence >= min_confidence:
                        labels[fva] = EngineLabel(
                            va=fva,
                            engine=sig.engine,
                            category=sig.category,
                            name=sig.name,
                            confidence=confidence,
                            match_kind="string_marker",
                            sig_id=sig.sig_id,
                            notes=f"exact string marker: {marker!r}",
                        )

    def _pass_string_patterns(
        self,
        ctx,
        xg,
        labels: Dict[int, EngineLabel],
        min_confidence: float,
    ) -> None:
        """Pass 2: regex pattern matching against string cross-references."""
        for sig in self._sigs:
            if not sig.string_patterns:
                continue
            patterns = []
            for p in sig.string_patterns:
                try:
                    patterns.append(re.compile(p, re.IGNORECASE))
                except re.error:
                    pass

            if not patterns:
                continue

            # Scan all string xrefs for pattern matches
            for s_va in getattr(ctx, "string_vas", []):
                try:
                    s = ctx.string_at(s_va)
                except Exception:
                    continue
                if not any(pat.search(s) for pat in patterns):
                    continue
                funcs = xg.funcs_referencing_string(s_va) if hasattr(xg, "funcs_referencing_string") else []
                for fva in funcs:
                    if fva in labels:
                        continue
                    confidence = sig.confidence_base
                    if confidence >= min_confidence:
                        labels[fva] = EngineLabel(
                            va=fva,
                            engine=sig.engine,
                            category=sig.category,
                            name=sig.name,
                            confidence=confidence,
                            match_kind="string_pattern",
                            sig_id=sig.sig_id,
                            notes=f"string pattern match: {s[:80]!r}",
                        )

    def _pass_semantic(
        self,
        searcher,
        labels: Dict[int, EngineLabel],
        min_confidence: float,
        top_k: int,
    ) -> None:
        """Pass 3: SemanticSearcher description matching."""
        for sig in self._sigs:
            if not sig.description:
                continue
            try:
                hits = searcher.query(sig.description, top_k=top_k)
            except Exception:
                continue
            for hit in hits:
                fva = hit.va if hasattr(hit, "va") else None
                if fva is None:
                    continue
                if fva in labels:
                    continue
                score = hit.score if hasattr(hit, "score") else 0.0
                confidence = sig.confidence_base * score
                if confidence >= min_confidence:
                    labels[fva] = EngineLabel(
                        va=fva,
                        engine=sig.engine,
                        category=sig.category,
                        name=sig.name,
                        confidence=confidence,
                        match_kind="semantic",
                        sig_id=sig.sig_id,
                        notes=f"semantic score={score:.3f}",
                    )

    # ── Reports ───────────────────────────────────────────────────────────────

    def strip_report(
        self,
        labels: Dict[int, EngineLabel],
        total_funcs: int,
        show_all: bool = False,
    ) -> str:
        """Return a coverage summary for analyst review."""
        if not labels:
            return f"No engine code labeled out of {total_funcs} functions (0.0%)"

        strip_count = sum(1 for lb in labels.values() if lb.strip())
        pct = 100.0 * strip_count / max(total_funcs, 1)

        # Group by engine + category
        by_engine: Dict[str, Dict[str, int]] = {}
        for lb in labels.values():
            by_engine.setdefault(lb.engine, {}).setdefault(lb.category, 0)
            by_engine[lb.engine][lb.category] += 1

        lines = [
            f"Engine code coverage: {strip_count}/{total_funcs} ({pct:.1f}%) labeled for stripping",
            f"Total labeled (all confidence): {len(labels)}",
            "",
        ]
        for engine, cats in sorted(by_engine.items()):
            ename = ENGINES.get(engine, engine)
            total = sum(cats.values())
            lines.append(f"  [{engine}] {ename}: {total} functions")
            for cat, n in sorted(cats.items(), key=lambda x: -x[1]):
                lines.append(f"    {cat:15s} {n}")

        # Match kind breakdown
        by_kind: Dict[str, int] = {}
        for lb in labels.values():
            by_kind[lb.match_kind] = by_kind.get(lb.match_kind, 0) + 1
        lines.append("")
        lines.append("  Match kind breakdown:")
        for kind, n in sorted(by_kind.items(), key=lambda x: -x[1]):
            lines.append(f"    {kind:20s} {n}")

        if show_all:
            lines.append("")
            lines.append("  All labels:")
            for va, lb in sorted(labels.items()):
                flag = "STRIP" if lb.strip() else "keep "
                lines.append(f"    {flag} {va:#010x}  [{lb.engine}/{lb.category}] {lb.name}  ({lb.confidence:.2f})")

        return "\n".join(lines)

    def unlabeled(
        self,
        func_starts: List[int],
        labels: Dict[int, EngineLabel],
    ) -> List[int]:
        """Return function VAs not labeled as engine code (the human RE target)."""
        return [va for va in func_starts if va not in labels]

    def ingest_from_findings(
        self,
        findings,
        engine: str = "unknown",
        category: str = "unknown",
    ) -> int:
        """Add confirmed RE findings as new engine signatures (flywheel integration).

        findings: list of objects with .title, .description, .func_addr attributes.
        Returns count added.
        """
        added = 0
        for f in findings:
            title = getattr(f, "title", "")
            desc = getattr(f, "description", "")
            if not title and not desc:
                continue
            sig_id = f"custom.{engine}.{hash(title) & 0xffffff:06x}"
            sig = EngineSignature(
                sig_id=sig_id,
                engine=engine,
                category=category,
                name=title,
                description=desc,
                confidence_base=0.60,
                notes="ingested from FindingRegistry",
            )
            self.add_signature(sig)
            added += 1
        return added


__all__ = [
    "EnginePatternLibrary", "EngineSignature", "EngineLabel",
    "ENGINES", "CATEGORIES",
]
