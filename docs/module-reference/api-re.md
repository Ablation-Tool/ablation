# API Reverse Engineering

**File:** `modules/api_re.py`

## Why this exists

Autonomous HTTP API discovery and attack surface mapping without source code. Combines path fuzzing, OpenAPI harvesting, parameter inference, and OWASP API Top 10 probing in a single analysis pass.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_HTTP_BYTES` | 4 MB | HTTP response body cap via streaming read |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. All HTTP response bodies read via a capped streaming helper that breaks at `_MAX_HTTP_BYTES=4MB`. No file reads. No lief.parse().
