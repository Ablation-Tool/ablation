"""
version_delta.py — Cross-version function tracking for ablation.

Tracks how a specific function (e.g., the RADIUS Class attribute handler in lina)
evolves across binary versions. Identifies homologs via a three-stage pipeline:

  Stage 1  Structural pre-filter   basic block count ±2, edge count ±30%
  Stage 2  Mnemonic 4-gram Jaccard sequence similarity, keeps top-10 candidates
  Stage 3  Semantic tiebreaker     SemanticSearcher when top-2 within 0.05

Patch localization via difflib.SequenceMatcher on normalized instruction lines
reveals the specific instructions that changed between versions.

Primary use case: track the RADIUS Class attr patch across all 17 lina versions
to confirm CVE-2022-0778 / RADIUS overflow remediation.
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Feature extraction
# ─────────────────────────────────────────────────────────────────────────────

_MNEMONIC_RE = re.compile(r'^\s*([a-z][a-z0-9_]{0,15})', re.IGNORECASE)
_ADDR_RE     = re.compile(r'\b0x[0-9a-fA-F]{4,}\b')
_IMM_RE      = re.compile(r'\b\d{4,}\b')
_REG_RE      = re.compile(
    r'\b('
    r'r(?:ax|bx|cx|dx|si|di|bp|sp|8|9|1[0-5])[lhwd]?|'
    r'e(?:ax|bx|cx|dx|si|di|bp|sp)|'
    r'[abcd][lhx]|sil|dil|bpl|spl|'
    r'[xyz]mm\d{1,2}|mm\d|st\d|'
    r'[xwb](?:\d{1,2}|zr|sp|lr|fp|pc)|'
    r'v\d{1,2}\.[248]?[BHSDQ]?|'
    r'r\d{1,2}'
    r')\b',
    re.IGNORECASE,
)


def _normalize_line(line: str) -> str:
    """Normalize one instruction line to a build-invariant form."""
    line = re.sub(r'^[0-9a-f]+:\s*(?:[0-9a-f]{2}\s+)*', '', line, flags=re.IGNORECASE)
    line = re.sub(r'[;#].*$', '', line)
    line = _ADDR_RE.sub('<A>', line)
    line = _IMM_RE.sub('<I>', line)
    line = _REG_RE.sub('<R>', line)
    return line.strip()


def _mnemonic(line: str) -> Optional[str]:
    m = _MNEMONIC_RE.match(line)
    return m.group(1).lower() if m else None


def _ngrams(seq: list[str], n: int = 4) -> frozenset[str]:
    return frozenset(' '.join(seq[i:i+n]) for i in range(len(seq) - n + 1))


def jaccard(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 1.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


@dataclass
class FuncFeatures:
    va:           int
    name:         str
    n_blocks:     int
    n_edges:      int
    n_instrs:     int
    mnemonics:    list[str]        # per-instruction, in order
    ngrams_4:     frozenset[str]
    norm_lines:   list[str]        # normalized instruction lines
    callees:      list[str]
    string_xrefs: list[str]

    @classmethod
    def from_angr(cls, proj, cfg, va: int, name: str = '') -> Optional['FuncFeatures']:
        """Extract features for the function at *va* using an already-built CFGFast."""
        try:
            func = cfg.kb.functions.get(va)
            if func is None:
                return None

            blocks     = list(func.blocks)
            n_blocks   = len(blocks)
            n_edges    = sum(len(list(func.graph.successors(b))) for b in blocks)
            mnemonics: list[str] = []
            norm_lines: list[str] = []

            for block in sorted(blocks, key=lambda b: b.addr):
                cs = block.disassembly
                if cs is None:
                    continue
                for insn in cs.insns:
                    raw  = f"{insn.mnemonic} {insn.op_str}".strip()
                    mn   = insn.mnemonic.lower()
                    mnemonics.append(mn)
                    norm = _normalize_line(raw)
                    if norm:
                        norm_lines.append(norm)

            callees = [
                (cfg.kb.functions.get(c.addr).name
                 if cfg.kb.functions.get(c.addr) else hex(c.addr))
                for c in func.callees
            ]
            string_xrefs: list[str] = []
            if hasattr(cfg, 'memory_data'):
                for ref in cfg.memory_data.values():
                    if ref.sort == 'string' and ref.content:
                        val = ref.content.decode(errors='replace').strip()
                        if val:
                            string_xrefs.append(val[:80])

            return cls(
                va=va,
                name=name or func.name or hex(va),
                n_blocks=n_blocks,
                n_edges=n_edges,
                n_instrs=len(mnemonics),
                mnemonics=mnemonics,
                ngrams_4=_ngrams(mnemonics, 4),
                norm_lines=norm_lines,
                callees=callees,
                string_xrefs=string_xrefs,
            )
        except Exception:
            return None

    @classmethod
    def from_disasm_lines(
        cls,
        va: int,
        name: str,
        asm_lines: list[str],
        callees: Optional[list[str]] = None,
        string_xrefs: Optional[list[str]] = None,
    ) -> 'FuncFeatures':
        """Build from raw disassembly text (e.g., capstone output)."""
        mnemonics  = [m for line in asm_lines if (m := _mnemonic(line))]
        norm_lines = [n for line in asm_lines if (n := _normalize_line(line))]
        return cls(
            va=va,
            name=name,
            n_blocks=0,
            n_edges=0,
            n_instrs=len(mnemonics),
            mnemonics=mnemonics,
            ngrams_4=_ngrams(mnemonics, 4),
            norm_lines=norm_lines,
            callees=callees or [],
            string_xrefs=string_xrefs or [],
        )


# ─────────────────────────────────────────────────────────────────────────────
# Patch localization
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PatchDelta:
    added:   list[str]
    removed: list[str]
    context: list[str]    # unchanged lines surrounding changes
    ratio:   float        # SequenceMatcher similarity (0–1, higher = more similar)

    @property
    def is_patched(self) -> bool:
        return bool(self.added or self.removed)

    def unified_diff(self, version_a: str = 'v_a', version_b: str = 'v_b') -> str:
        return '\n'.join(difflib.unified_diff(
            self.removed, self.added,
            fromfile=version_a, tofile=version_b,
            lineterm='',
        ))


def compute_patch_delta(features_a: FuncFeatures, features_b: FuncFeatures) -> PatchDelta:
    """Diff normalized instruction sequences to localize the patch."""
    sm = difflib.SequenceMatcher(None, features_a.norm_lines, features_b.norm_lines, autojunk=False)
    added   = []
    removed = []
    context = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            context.extend(features_a.norm_lines[i1:i2])
        elif tag in ('replace', 'delete'):
            removed.extend(features_a.norm_lines[i1:i2])
            if tag == 'replace':
                added.extend(features_b.norm_lines[j1:j2])
        elif tag == 'insert':
            added.extend(features_b.norm_lines[j1:j2])
    return PatchDelta(added=added, removed=removed, context=context, ratio=sm.ratio())


# ─────────────────────────────────────────────────────────────────────────────
# Homolog matching result
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HomologMatch:
    va:             int
    name:           str
    jaccard:        float
    semantic_score: float
    confidence:     str          # 'HIGH' | 'MEDIUM' | 'LOW'
    delta:          PatchDelta
    new_callees:    list[str]
    removed_callees: list[str]

    @property
    def callee_changed(self) -> bool:
        return bool(self.new_callees or self.removed_callees)


@dataclass
class DeltaReport:
    seed_binary:   str
    seed_va:       int
    seed_name:     str
    target_binary: str
    target_version: str
    match:         Optional[HomologMatch]

    def summary(self) -> str:
        if self.match is None:
            return f"{self.target_version}: NO MATCH"
        m = self.match
        patch = 'PATCHED' if m.delta.is_patched else 'UNCHANGED'
        callee = ''
        if m.new_callees:
            callee += f" +callees:{','.join(m.new_callees)}"
        if m.removed_callees:
            callee += f" -callees:{','.join(m.removed_callees)}"
        return (
            f"{self.target_version}: {m.name} @ {hex(m.va)}"
            f" jaccard={m.jaccard:.3f} sem={m.semantic_score:.3f}"
            f" [{m.confidence}] {patch}{callee}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Three-stage matching engine
# ─────────────────────────────────────────────────────────────────────────────

class FuncMatcher:
    """Match a seed function against a target binary's function set."""

    _BLOCK_TOLERANCE = 2       # ±N basic blocks for structural pre-filter
    _EDGE_RATIO_MAX  = 0.35    # max fractional edge-count difference
    _TOP_K           = 10      # candidates to keep after Jaccard ranking
    _SEM_TIE_THRESH  = 0.05    # Jaccard gap below which semantic is tiebreaker
    _SEM_JACCARD_MIN = 0.15    # Jaccard below this → semantic becomes primary signal

    def __init__(self, semantic_searcher=None):
        self._sem = semantic_searcher

    def _structural_candidates(
        self, seed: FuncFeatures, candidates: list[FuncFeatures]
    ) -> list[FuncFeatures]:
        """Stage 1: filter by basic-block and edge counts."""
        if seed.n_blocks == 0:
            return candidates  # no CFG data — skip filter
        out = []
        for c in candidates:
            if c.n_blocks == 0:
                out.append(c)
                continue
            block_ok = abs(c.n_blocks - seed.n_blocks) <= self._BLOCK_TOLERANCE
            if seed.n_edges > 0:
                edge_ratio = abs(c.n_edges - seed.n_edges) / max(seed.n_edges, 1)
                edge_ok = edge_ratio <= self._EDGE_RATIO_MAX
            else:
                edge_ok = True
            if block_ok and edge_ok:
                out.append(c)
        return out

    def _jaccard_rank(
        self, seed: FuncFeatures, candidates: list[FuncFeatures]
    ) -> list[tuple[float, FuncFeatures]]:
        """Stage 2: rank by mnemonic 4-gram Jaccard, return top-k."""
        scored = [(jaccard(seed.ngrams_4, c.ngrams_4), c) for c in candidates]
        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[:self._TOP_K]

    def _semantic_score(self, seed: FuncFeatures, candidate: FuncFeatures) -> float:
        """Stage 3: direct cosine similarity between seed and candidate embeddings.

        Does NOT use the func_id_db corpus — encodes both functions on the fly
        so cross-version homologs with different names are handled correctly.
        """
        if self._sem is None:
            return 0.0
        try:
            import numpy as np
            from modules.semantic_search import describe_function
            model = self._sem._get_model()
            seed_desc = describe_function(
                seed.name, 'UNKNOWN',
                seed.callees, seed.string_xrefs,
                asm_lines=seed.norm_lines[:30],
            )
            cand_desc = describe_function(
                candidate.name, 'UNKNOWN',
                candidate.callees, candidate.string_xrefs,
                asm_lines=candidate.norm_lines[:30],
            )
            vecs = model.encode(
                [seed_desc, cand_desc],
                normalize_embeddings=True,
                show_progress_bar=False,
            )
            return float(np.array(vecs[0]) @ np.array(vecs[1]))
        except Exception:
            return 0.0

    def find_homolog(
        self, seed: FuncFeatures, target_functions: list[FuncFeatures]
    ) -> Optional[HomologMatch]:
        """Three-stage pipeline: structural → Jaccard → semantic."""
        if not target_functions:
            return None

        # Stage 1
        struct_pass = self._structural_candidates(seed, target_functions)
        if not struct_pass:
            struct_pass = target_functions  # fallback to full set

        # Stage 2
        ranked = self._jaccard_rank(seed, struct_pass)
        if not ranked:
            return None

        best_score, best_func = ranked[0]

        # Stage 3 — semantic kicks in under two conditions:
        #   (a) tiebreak: top-2 Jaccard within _SEM_TIE_THRESH
        #   (b) primary:  best Jaccard below _SEM_JACCARD_MIN (cross-version divergence)
        sem_score = 0.0
        low_jaccard = best_score < self._SEM_JACCARD_MIN

        if self._sem is not None and (
            low_jaccard or
            (len(ranked) >= 2 and ranked[0][0] - ranked[1][0] < self._SEM_TIE_THRESH)
        ):
            if low_jaccard:
                # Score all top-K candidates; pick highest semantic match
                scored_sem = [
                    (self._semantic_score(seed, f), jac, f)
                    for jac, f in ranked
                ]
                scored_sem.sort(key=lambda x: x[0], reverse=True)
                sem_score, best_score, best_func = scored_sem[0]
            else:
                sem_a = self._semantic_score(seed, ranked[0][1])
                sem_b = self._semantic_score(seed, ranked[1][1])
                if sem_b > sem_a:
                    best_score, best_func = ranked[1]
                    sem_score = sem_b
                else:
                    sem_score = sem_a

        # Jaccard floor: semantic alone is insufficient for HIGH — too many generic
        # C patterns (alloc+copy+return) score 0.9+ cross-binary with no structural
        # overlap. Require _SEM_JACCARD_MIN structural corroboration for HIGH.
        jaccard_ok = best_score >= self._SEM_JACCARD_MIN
        confidence = (
            'HIGH'   if jaccard_ok and (sem_score >= 0.75 or best_score >= 0.70) else
            'MEDIUM' if sem_score >= 0.55 or best_score >= 0.45 else
            'LOW'
        )

        delta = compute_patch_delta(seed, best_func)
        new_callees     = [c for c in best_func.callees if c not in set(seed.callees)]
        removed_callees = [c for c in seed.callees     if c not in set(best_func.callees)]

        return HomologMatch(
            va=best_func.va,
            name=best_func.name,
            jaccard=best_score,
            semantic_score=sem_score,
            confidence=confidence,
            delta=delta,
            new_callees=new_callees,
            removed_callees=removed_callees,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Version tracker — orchestrates across a list of binaries
# ─────────────────────────────────────────────────────────────────────────────

class VersionTracker:
    """
    Track a seed function across multiple binary versions.

    Usage:
        tracker = VersionTracker(binaries={'9.14': '/path/lina-9.14', ...})
        reports = tracker.track(seed_binary='9.14', seed_va=0x4a1234)
        for r in reports:
            print(r.summary())
    """

    def __init__(
        self,
        binaries: dict[str, str],
        semantic_searcher=None,
        angr_load_options: Optional[dict] = None,
    ):
        self._binaries   = binaries          # {version_str: binary_path}
        self._matcher    = FuncMatcher(semantic_searcher)
        self._load_opts  = angr_load_options or {'auto_load_libs': False}
        self._cfg_cache: dict[str, object] = {}

    def _load_cfg(self, binary_path: str):
        """Load angr project and CFGFast, cached by path."""
        if binary_path in self._cfg_cache:
            return self._cfg_cache[binary_path]
        import angr
        proj = angr.Project(binary_path, load_options=self._load_opts, auto_load_libs=False)
        cfg  = proj.analyses.CFGFast(
            normalize=True,
            resolve_indirect_jumps=True,
            collect_data_references=True,
        )
        self._cfg_cache[binary_path] = (proj, cfg)
        return proj, cfg

    def _all_features(self, binary_path: str) -> list[FuncFeatures]:
        """Extract FuncFeatures for every function in a binary."""
        proj, cfg = self._load_cfg(binary_path)
        feats = []
        for va, func in cfg.kb.functions.items():
            if func.is_plt or func.is_simprocedure:
                continue
            f = FuncFeatures.from_angr(proj, cfg, va, func.name)
            if f and f.n_instrs >= 4:   # skip stub-size functions
                feats.append(f)
        return feats

    def _seed_features(self, seed_binary: str, seed_va: int, seed_name: str = '') -> Optional[FuncFeatures]:
        proj, cfg = self._load_cfg(seed_binary)
        func = cfg.kb.functions.get(seed_va)
        if func is None:
            # VA may be inside a function whose entry angr placed elsewhere —
            # use floor_func to find the nearest function whose start <= seed_va
            try:
                func = cfg.kb.functions.floor_func(seed_va)
            except Exception:
                pass
        if func is None:
            return None
        return FuncFeatures.from_angr(proj, cfg, func.addr, seed_name or func.name)

    def track(
        self,
        seed_binary: str,
        seed_va: int,
        seed_name: str = '',
        skip_versions: Optional[list[str]] = None,
    ) -> list[DeltaReport]:
        """
        Find homologs of seed_va across all registered binaries.

        Returns one DeltaReport per version, in version-registration order.
        """
        skip = set(skip_versions or [])
        seed_path = self._binaries.get(seed_binary)
        if seed_path is None:
            raise ValueError(f"seed binary '{seed_binary}' not in tracker")

        seed_feat = self._seed_features(seed_path, seed_va, seed_name)
        if seed_feat is None:
            raise ValueError(f"Function {hex(seed_va)} not found in {seed_path}")

        reports: list[DeltaReport] = []

        for version, binary_path in self._binaries.items():
            if version == seed_binary or version in skip:
                continue
            target_feats = self._all_features(binary_path)
            match = self._matcher.find_homolog(seed_feat, target_feats)
            reports.append(DeltaReport(
                seed_binary=seed_binary,
                seed_va=seed_va,
                seed_name=seed_feat.name,
                target_binary=binary_path,
                target_version=version,
                match=match,
            ))

        return reports


# ─────────────────────────────────────────────────────────────────────────────
# Standalone delta: compare two specific functions without a tracker
# ─────────────────────────────────────────────────────────────────────────────

def diff_functions(
    asm_a: list[str],
    name_a: str,
    asm_b: list[str],
    name_b: str,
    callees_a: Optional[list[str]] = None,
    callees_b: Optional[list[str]] = None,
    version_a: str = 'v_a',
    version_b: str = 'v_b',
) -> PatchDelta:
    """
    Quick diff between two functions given their disassembly text.

    No angr required — works on pre-extracted asm_lines from any disassembler.
    """
    fa = FuncFeatures.from_disasm_lines(0, name_a, asm_a, callees_a)
    fb = FuncFeatures.from_disasm_lines(0, name_b, asm_b, callees_b)
    return compute_patch_delta(fa, fb)


def jaccard_similarity(asm_a: list[str], asm_b: list[str]) -> float:
    """4-gram Jaccard similarity between two functions' mnemonic sequences."""
    mnemonics_a = [m for line in asm_a if (m := _mnemonic(line))]
    mnemonics_b = [m for line in asm_b if (m := _mnemonic(line))]
    return jaccard(_ngrams(mnemonics_a, 4), _ngrams(mnemonics_b, 4))
