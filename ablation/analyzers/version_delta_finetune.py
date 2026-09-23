"""
Cross-version binary function similarity fine-tuning.

Problem: MiniLM-L6-v2 collapses all stripped binary functions to the same
embedding neighborhood -- 0 orphans at threshold=0.65 even when 116% size
growth implies major new code. Root cause: opcode n-gram descriptions are
nearly identical across functions (push/sub/mov/call is universal).

Fix: self-supervised fine-tuning using structural Jaccard to generate
ground-truth homolog pairs. Bootstrap the semantic layer from the structural
layer that already works.

Pair generation strategy:
  anchor   = describe_function() text for function in version A
  positive = describe_function() text for best structural match in version B

Structural match = (instruction count within 20%) AND (call set Jaccard >= threshold).
Loss: MultipleNegativesRankingLoss -- every other sample in the batch acts
as a negative. Batch of 32 pairs provides 31 negatives per anchor automatically.
"""

import os
import random
import numpy as np
from typing import NamedTuple

from sentence_transformers import SentenceTransformer, InputExample, losses
from sentence_transformers.evaluation import EmbeddingSimilarityEvaluator
from torch.utils.data import DataLoader


class FunctionMeta(NamedTuple):
    va: int
    n_insns: int
    calls: list  # PLT-resolved call names (strings only, not addresses)
    desc: str    # describe_function() output


def _call_jaccard(calls_a: list, calls_b: list) -> float:
    """Jaccard similarity of PLT call sets (string names only)."""
    set_a = set(c for c in calls_a if not c.startswith("0x"))
    set_b = set(c for c in calls_b if not c.startswith("0x"))
    if not set_a and not set_b:
        return 0.0
    union = set_a | set_b
    if not union:
        return 0.0
    return len(set_a & set_b) / len(union)


def _size_bucket(n: int, bucket_size: int = 20) -> int:
    return n // bucket_size


def generate_structural_pairs(
    corpus_a: list,  # list of FunctionMeta for version A
    corpus_b: list,  # list of FunctionMeta for version B
    min_plt_calls: int = 1,
    min_jaccard: float = 0.4,
    max_pairs: int = 5000,
    seed: int = 42,
) -> tuple:
    """
    Returns (train_pairs, eval_pairs) where each element is a list of
    InputExample(texts=[anchor_desc, positive_desc]).

    Matching criteria:
    - Both functions have >= min_plt_calls PLT calls
    - Instruction count within 30% (within 15% for single-PLT-call functions)
    - Call set Jaccard >= min_jaccard

    Single-call functions use a tighter size constraint (±15%) to reduce
    false positives from generic single-import functions (e.g., malloc-only).
    """
    random.seed(seed)

    # Build lookup: bucket -> list of indices in corpus_b
    bucket_index: dict = {}
    for i, meta in enumerate(corpus_b):
        b = _size_bucket(meta.n_insns)
        for delta in (-1, 0, 1):
            bucket_index.setdefault(b + delta, []).append(i)

    pairs = []

    for meta_a in corpus_a:
        named_calls_a = [c for c in meta_a.calls if not c.startswith("0x")]
        n_named_a = len(named_calls_a)
        if n_named_a < min_plt_calls:
            continue

        # Tighter size window for single-call functions (less discriminative call set)
        sz_lo, sz_hi = (0.85, 1.15) if n_named_a == 1 else (0.70, 1.30)

        bucket_a = _size_bucket(meta_a.n_insns)
        candidates = bucket_index.get(bucket_a, [])

        best_j = -1.0
        best_idx = -1
        for idx in candidates:
            meta_b = corpus_b[idx]
            named_calls_b = [c for c in meta_b.calls if not c.startswith("0x")]
            if len(named_calls_b) < min_plt_calls:
                continue
            sz_ratio = meta_b.n_insns / max(meta_a.n_insns, 1)
            if sz_ratio < sz_lo or sz_ratio > sz_hi:
                continue
            j = _call_jaccard(meta_a.calls, meta_b.calls)
            if j > best_j:
                best_j = j
                best_idx = idx

        if best_j >= min_jaccard and best_idx >= 0:
            pairs.append(InputExample(
                texts=[meta_a.desc, corpus_b[best_idx].desc],
                label=float(best_j),
            ))

        if len(pairs) >= max_pairs:
            break

    random.shuffle(pairs)
    split = int(len(pairs) * 0.85)
    train_pairs = pairs[:split]
    eval_pairs = pairs[split:]

    print(f"[finetune] {len(pairs)} structural pairs generated "
          f"({len(train_pairs)} train, {len(eval_pairs)} eval)")
    print(f"[finetune] Jaccard distribution: "
          f"min={min(p.label for p in pairs):.3f} "
          f"mean={sum(p.label for p in pairs)/len(pairs):.3f} "
          f"max={max(p.label for p in pairs):.3f}")

    return train_pairs, eval_pairs


def finetune_model(
    train_pairs: list,
    eval_pairs: list,
    base_model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
    output_path: str = None,
    epochs: int = 4,
    batch_size: int = 16,
    warmup_frac: float = 0.1,
    device: str = "cpu",
) -> SentenceTransformer:
    """
    Fine-tune base_model on train_pairs with MultipleNegativesRankingLoss.
    Evaluates on eval_pairs after each epoch. Returns fine-tuned model.
    """
    if output_path is None:
        output_path = os.path.expanduser("~/ablation/models/cross_version_v1")

    print(f"[finetune] Loading base model: {base_model_name}")
    model = SentenceTransformer(base_model_name, device=device)

    train_loader = DataLoader(train_pairs, shuffle=True, batch_size=batch_size)
    train_loss = losses.MultipleNegativesRankingLoss(model)

    # Build evaluator from eval pairs: cosine similarity against label
    eval_sentences1 = [p.texts[0] for p in eval_pairs]
    eval_sentences2 = [p.texts[1] for p in eval_pairs]
    eval_labels = [p.label for p in eval_pairs]

    evaluator = EmbeddingSimilarityEvaluator(
        eval_sentences1, eval_sentences2, eval_labels,
        name="cross_version_eval",
        show_progress_bar=False,
    )

    warmup_steps = int(len(train_loader) * epochs * warmup_frac)
    print(f"[finetune] Training: {epochs} epochs, batch={batch_size}, "
          f"warmup={warmup_steps} steps, output={output_path}")

    model.fit(
        train_objectives=[(train_loader, train_loss)],
        evaluator=evaluator,
        epochs=epochs,
        warmup_steps=warmup_steps,
        optimizer_params={"lr": 2e-5},
        output_path=output_path,
        save_best_model=True,
        show_progress_bar=True,
    )

    print(f"[finetune] Model saved to {output_path}")
    return model


def evaluate_separation(
    model: SentenceTransformer,
    homolog_pairs: list,   # list of (desc_a, desc_b) confirmed homologs
    nonhomolog_pairs: list,  # list of (desc_a, desc_b) confirmed non-homologs
    batch_size: int = 64,
) -> dict:
    """
    Measure how well the model separates homologs from non-homologs.
    Returns dict with mean_homolog_sim, mean_nonhomolog_sim, separation_ratio.
    """
    def sim(pairs):
        a = model.encode([p[0] for p in pairs], normalize_embeddings=True,
                         batch_size=batch_size, show_progress_bar=False)
        b = model.encode([p[1] for p in pairs], normalize_embeddings=True,
                         batch_size=batch_size, show_progress_bar=False)
        return float(np.mean(np.sum(a * b, axis=1)))

    mean_h = sim(homolog_pairs)
    mean_n = sim(nonhomolog_pairs)
    sep = mean_h / max(mean_n, 1e-6)

    return {
        "mean_homolog_sim": mean_h,
        "mean_nonhomolog_sim": mean_n,
        "separation_ratio": sep,
        "n_homolog": len(homolog_pairs),
        "n_nonhomolog": len(nonhomolog_pairs),
    }
