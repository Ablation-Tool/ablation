"""
Cross-version binary function similarity fine-tuning.

Problem: MiniLM-L6-v2 collapses all stripped binary functions to the same
embedding neighborhood: 0 orphans at threshold=0.65 even when 116% size
growth implies major new code. Root cause: opcode n-gram descriptions are
nearly identical across functions (push/sub/mov/call is universal).

Fix: self-supervised fine-tuning using structural Jaccard to generate
ground-truth homolog pairs. Bootstrap the semantic layer from the structural
layer that already works.

Pair generation strategy:
  anchor   = describe_function() text for function in version A
  positive = describe_function() text for best structural match in version B

Structural match = (instruction count within 20%) AND (call set Jaccard >= threshold).
Loss: MultipleNegativesRankingLoss: every other sample in the batch acts
as a negative. Batch of 32 pairs provides 31 negatives per anchor automatically.

ZIM-BERT distillation (zimbert_finetune):
  Extends fine-tuning with mpnet teacher knowledge.
  L_total = L_MNR + alpha*L_KL_output + beta*L_value
  L_KL_output: KL divergence on batch pairwise similarity distributions
  L_value: MSE on value projection vectors across corresponding layer pairs
  Layer mapping: teacher {0,2,4,6,8,10} → student {0,1,2,3,4,5}
"""

import os
import random
import numpy as np
from typing import NamedTuple

from sentence_transformers import SentenceTransformer, InputExample, losses
from sentence_transformers.evaluation import EmbeddingSimilarityEvaluator


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

    from torch.utils.data import DataLoader
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


# ── ZIM-BERT ────────────────────────────────────────────────────────────────
# Teacher-student distillation for binary similarity.
# Teacher: all-mpnet-base-v2 (12L, 768-dim)
# Student: all-MiniLM-L6-v2  (6L,  384-dim)
# Layer alignment: teacher layers [0,2,4,6,8,10] → student layers [0,1,2,3,4,5]
# ─────────────────────────────────────────────────────────────────────────────

_TEACHER_LAYERS = [0, 2, 4, 6, 8, 10]  # teacher layers to align with student


class _ValueHookCapture:
    """Registers forward hooks on nn.Linear value-projection modules.

    Handles both BERT (layer.attention.self.value) and
    MPNet (layer.attention.attn.v) attention layouts.
    """

    def __init__(self):
        self.captures: dict = {}
        self._handles: list = []

    def register(self, hf_model):
        for i, layer in enumerate(hf_model.encoder.layer):
            attn = layer.attention
            if hasattr(attn, 'attn') and hasattr(attn.attn, 'v'):
                # MPNet layout
                value_proj = attn.attn.v
            elif hasattr(attn, 'self') and hasattr(attn.self, 'value'):
                # BERT layout
                value_proj = attn.self.value
            else:
                raise RuntimeError(
                    f"Unknown attention layout at encoder.layer[{i}]: "
                    f"{type(attn).__name__}"
                )
            h = value_proj.register_forward_hook(self._make(i))
            self._handles.append(h)

    def _make(self, idx):
        def hook(_, __, output):
            self.captures[idx] = output  # [B, seq, hidden]
        return hook

    def remove(self):
        for h in self._handles:
            h.remove()
        self._handles.clear()
        self.captures.clear()


def _mean_pool(last_hidden_state, attention_mask):
    mask = attention_mask.unsqueeze(-1).float()
    return (last_hidden_state * mask).sum(1) / mask.sum(1).clamp(min=1e-9)


def _kl_output_loss(teacher_emb, student_emb_proj, temperature=0.05):
    """KL divergence on batch pairwise cosine similarity distributions."""
    import torch.nn.functional as F
    import torch
    t = F.normalize(teacher_emb, dim=-1)
    s = F.normalize(student_emb_proj, dim=-1)
    t_sim = torch.mm(t, t.T) / temperature
    s_sim = torch.mm(s, s.T) / temperature
    t_prob = F.softmax(t_sim, dim=-1)
    s_log = F.log_softmax(s_sim, dim=-1)
    return F.kl_div(s_log, t_prob, reduction='batchmean')


def _value_mse_loss(teacher_caps, student_caps, proj):
    """MSE between teacher and student value vectors, averaged over layer pairs."""
    import torch
    import torch.nn.functional as F
    total = torch.tensor(0.0, device=proj.weight.device)
    n = 0
    for s_idx, t_idx in enumerate(_TEACHER_LAYERS):
        if t_idx not in teacher_caps or s_idx not in student_caps:
            continue
        t_val = teacher_caps[t_idx]  # [B, seq, 768]
        s_val = proj(student_caps[s_idx])  # [B, seq, 768]
        total = total + F.mse_loss(s_val, t_val.detach())
        n += 1
    return total / max(n, 1)


def zimbert_finetune(
    train_pairs: list,
    eval_pairs: list,
    teacher_name: str = "sentence-transformers/all-mpnet-base-v2",
    student_name: str = "sentence-transformers/all-MiniLM-L6-v2",
    output_path: str = None,
    alpha: float = 10.0,
    beta: float = 0.5,
    epochs: int = 4,
    batch_size: int = 16,
    lr: float = 2e-5,
    device: str = "cpu",
) -> SentenceTransformer:
    """
    ZIM-BERT distillation fine-tuning.

    L_total = L_MNR + alpha*L_KL_output + beta*L_value

    Returns a SentenceTransformer saved to output_path.
    Call evaluate_separation() after to measure improvement over baseline.
    """
    try:
        import torch
        import torch.nn as nn
        import torch.nn.functional as F
        from transformers import AutoModel, AutoTokenizer
        from sentence_transformers.models import Transformer as STTransformer, Pooling as STPooling
        from torch.utils.data import DataLoader as _DataLoader
    except ImportError as e:
        raise ImportError(
            f"zimbert_finetune requires torch and transformers: {e}\n"
            "Install with: pip install torch transformers"
        ) from e

    if output_path is None:
        output_path = os.path.expanduser("~/ablation/models/zimbert_v1")

    dev = torch.device(device)

    print(f"[zimbert] Loading teacher: {teacher_name}")
    t_hf = AutoModel.from_pretrained(teacher_name).to(dev).eval()
    t_tok = AutoTokenizer.from_pretrained(teacher_name)
    t_dim = t_hf.config.hidden_size  # 768

    print(f"[zimbert] Loading student: {student_name}")
    s_hf = AutoModel.from_pretrained(student_name).to(dev).train()
    s_tok = AutoTokenizer.from_pretrained(student_name)
    s_dim = s_hf.config.hidden_size  # 384

    # Projection: student-dim → teacher-dim, used for both L_KL and L_value
    proj = nn.Linear(s_dim, t_dim, bias=False).to(dev)
    nn.init.xavier_uniform_(proj.weight)

    optimizer = torch.optim.AdamW(
        list(s_hf.parameters()) + list(proj.parameters()),
        lr=lr,
        weight_decay=0.01,
    )

    n_steps = len(train_pairs) // batch_size * epochs
    scheduler = torch.optim.lr_scheduler.LinearLR(
        optimizer, start_factor=0.1, end_factor=1.0,
        total_iters=max(1, int(n_steps * 0.1))
    )

    t_hooks = _ValueHookCapture()
    s_hooks = _ValueHookCapture()
    t_hooks.register(t_hf)
    s_hooks.register(s_hf)

    for epoch in range(epochs):
        random.shuffle(train_pairs)
        epoch_loss = 0.0
        n_batches = 0

        for i in range(0, len(train_pairs) - batch_size, batch_size):
            batch = train_pairs[i: i + batch_size]
            anchors  = [p.texts[0] for p in batch]
            positives = [p.texts[1] for p in batch]
            texts = anchors + positives

            t_enc = t_tok(texts, padding=True, truncation=True,
                          max_length=256, return_tensors='pt').to(dev)
            s_enc = s_tok(texts, padding=True, truncation=True,
                          max_length=256, return_tensors='pt').to(dev)

            with torch.no_grad():
                t_out = t_hf(**t_enc)
            t_emb = _mean_pool(t_out.last_hidden_state, t_enc['attention_mask'])
            t_val_caps = dict(t_hooks.captures)

            s_hooks.captures.clear()
            s_out = s_hf(**s_enc)
            s_emb = _mean_pool(s_out.last_hidden_state, s_enc['attention_mask'])
            s_val_caps = dict(s_hooks.captures)

            # MNR loss: anchor embeddings vs positive embeddings
            a_emb = F.normalize(s_emb[:batch_size], dim=-1)
            p_emb = F.normalize(s_emb[batch_size:], dim=-1)
            scores = torch.mm(a_emb, p_emb.T)
            labels = torch.arange(batch_size, device=dev)
            l_mnr = F.cross_entropy(scores * 20.0, labels)

            # KL output loss
            l_kl = _kl_output_loss(t_emb, proj(s_emb))

            # Value MSE loss
            l_val = _value_mse_loss(t_val_caps, s_val_caps, proj)

            loss = l_mnr + alpha * l_kl + beta * l_val

            optimizer.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(list(s_hf.parameters()) + list(proj.parameters()), 1.0)
            optimizer.step()
            scheduler.step()

            epoch_loss += loss.item()
            n_batches += 1

        avg = epoch_loss / max(n_batches, 1)
        print(f"[zimbert] epoch {epoch+1}/{epochs}  avg_loss={avg:.4f}")

    t_hooks.remove()
    s_hooks.remove()

    # Wrap trained HF model in SentenceTransformer and save
    print(f"[zimbert] Saving to {output_path}")
    final = SentenceTransformer(modules=[
        STTransformer(student_name),
        STPooling(s_dim, pooling_mode_mean_tokens=True),
    ], device=device)

    # Load fine-tuned weights into the wrapper
    final[0].auto_model.load_state_dict(s_hf.state_dict())
    final.save(output_path)
    print(f"[zimbert] Done.")
    return final
