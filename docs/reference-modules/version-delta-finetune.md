# Version Delta Fine-Tune

**File:** `modules/version_delta_finetune.py`

## Why this exists

Self-supervised fine-tuning of the MiniLM-L6-v2 embedding model using structural Jaccard similarity to generate ground-truth homolog pairs across firmware versions. Fixes the model collapse problem where opcode n-gram descriptions cluster identically regardless of function size changes. Bootstraps the semantic layer from the structural layer that already works.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. No file reads. No HTTP reads. No subprocess. No lief.parse(). Operates entirely on in-memory function description strings and numpy/torch tensors.

---

## How it works

`generate_structural_pairs()` computes call-set Jaccard similarity between all function pairs across two firmware versions, using instruction count proximity within 30%, or 15% for single-PLT-call functions as a pre-filter. Pairs above `min_jaccard` become positive training examples. The corpus is split 90/10 into `train_pairs` and `eval_pairs`. `finetune_model()` wraps the `sentence-transformers` `SentenceTransformer.fit()` training loop with `CosineSimilarityLoss`, checkpoints to `output_path`, and returns the fine-tuned model. The result is a model that clusters homolog function descriptions more tightly than the pretrained MiniLM-L6-v2 while maintaining discrimination between non-homologs.

---

## Usage

```python
from modules.version_delta_finetune import finetune_model

# train_pairs: list of (anchor_text, positive_text) function description pairs
# eval_pairs: list of (text_a, text_b, label) tuples
model = finetune_model(
    train_pairs=[("heap_alloc size check", "malloc with bounds"), ...],
    eval_pairs=[("recv handler", "network input", 1.0), ...],
    base_model_name="sentence-transformers/all-MiniLM-L6-v2",
    output_path="/tmp/ablation-finetuned",
    epochs=4,
)
```

---

## Example output

```
generate_structural_pairs  v1: 19842 funcs  v2: 20103 funcs
  candidate pairs  : 142830 (within 30% size + ≥1 PLT call)
  positive pairs   : 4821   (Jaccard ≥ 0.40)
  train/eval split : 4338 / 483

finetune_model  epochs=4  batch_size=32
  epoch 1/4  train_loss=0.423  eval_cosine=0.61
  epoch 2/4  train_loss=0.311  eval_cosine=0.74
  epoch 3/4  train_loss=0.248  eval_cosine=0.81
  epoch 4/4  train_loss=0.201  eval_cosine=0.85
  model saved → /tmp/ablation-finetuned
```

---

## False positives

**Model collapse with too few training pairs**: if the firmware versions are very similar minor patch, `generate_structural_pairs()` may produce fewer than ~1000 positive pairs, which is insufficient for meaningful fine-tuning. In this case the loss curve flattens after epoch 1 and `eval_cosine` does not improve past 0.65. Use the pretrained MiniLM instead; fine-tuning on fewer than 1000 pairs will overfit to the available data.

**False positive pairs from single-PLT-call functions**: wrapper functions around a single `malloc`, `free`, or `memcpy` call produce a very high Jaccard score against each other even when they implement different data structures. The 15% instruction count constraint mitigates this but does not eliminate it entirely. Review `eval_separation()` output after training to confirm the fine-tuned model actually separates non-homologs.

---

## Pipeline position

**Before this module:** Build function corpora for both versions with `CorpusBuilder.build()`, then extract `FunctionMeta` lists from the corpus DB (or construct them from `BinaryContext` data). `generate_structural_pairs()` takes these lists.

**After this module:** Pass the returned `SentenceTransformer` model to `SemanticSearcher(model=model)` instead of the default pretrained model. The fine-tuned model produces tighter clustering for the specific firmware family and improves semantic query precision on homolog matching tasks.

---

## Reading output

`finetune_modeltrain_pairs, eval_pairs, base_model_name, output_path, epochs, batch_size` returns a fine-tuned `SentenceTransformer` model (from the `sentence-transformers` package). The trained model is saved to `output_path` and returned directly for immediate use.

`generate_structural_pairscorpus_a, corpus_b, min_plt_calls, min_jaccard, max_pairs` returns `train_pairs, eval_pairs`: lists of `InputExample(texts=[anchor_desc, positive_desc])` used by `finetune_model()`.

---

## See also

- [BinaryContext](binary-context.md): session foundation for all analysis
- [SemanticSearch](semantic-search.md): function candidate identification
- [FindingRegistry](registry.md): persistent finding storage
