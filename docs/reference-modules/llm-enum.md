# LLM Enumeration

**File:** `modules/llm_enum.py`

## Why this exists

Exposed LLM inference endpoint enumeration: Ollama, LM Studio, LocalAI, HuggingFace TGI, OpenAI-compatible APIs, and agentic surfaces. Covers OWASP LLM01–LLM10: prompt injection probes, model enumeration, system prompt disclosure, excessive agency detection, and insecure plugin surface.

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. All HTTP response bodies read with inline caps: `resp.read(65536)` for model listings, `e.read(4096)` for error bodies. No file reads. No lief.parse().
