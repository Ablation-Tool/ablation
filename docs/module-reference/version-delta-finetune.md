# Version Delta Fine-Tune

**File:** `modules/version_delta_finetune.py`

## Why this exists

Self-supervised fine-tuning of the MiniLM-L6-v2 embedding model using structural Jaccard similarity to generate ground-truth homolog pairs across firmware versions. Fixes the model collapse problem where opcode n-gram descriptions cluster identically regardless of function size changes. Bootstraps the semantic layer from the structural layer that already works.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. No file reads. No HTTP reads. No subprocess. No lief.parse(). Operates entirely on in-memory function description strings and numpy/torch tensors.
