"""
yt-dlp YouTube extraction layer RE
Target: yt-dlp (https://github.com/yt-dlp/yt-dlp)
Version audited: installed at /home/cowboy/security-tools/lib/python3.12/site-packages/yt_dlp/
Goal: understand extraction architecture to build a standalone YouTube downloader

RE STATUS: pass 1 COMPLETE — architecture mapped; building improved tool at ~/bin/ytget

Ablation gap logged: SourceSinkScanner has no patterns for Python subprocess.run()
without shell=True, urllib/requests HTTP client calls, or external process
dependency detection. These are the critical signals for CLI tool architecture
audit. New module needed: CliToolArchScanner.

Compressor result: all 34 YouTube extractor files -> profile 0 (no web-app signals).
Expected: yt-dlp is a CLI tool. Compressor is web-app oriented. Confirms the gap above.
"""

YTDLP_ROOT = "/home/cowboy/security-tools/lib/python3.12/site-packages/yt_dlp/"
EXTRACTOR_ROOT = YTDLP_ROOT + "extractor/youtube/"

# =============================================================================
# ARCHITECTURE MAP
# =============================================================================

ARCHITECTURE = {
    "innertube_api": {
        "endpoint": "https://www.youtube.com/youtubei/v1/player",
        "method": "POST",
        "body": {"context": "<client_context>", "videoId": "<id>"},
        "note": "Returns streamingData with adaptiveFormats (separate video/audio) and formats (muxed)",
    },

    "client_selection": {
        "default_clients": ("visionos", "web"),
        "default_jsless_clients": ("visionos",),
        "jsless_clients": ["android", "android_vr", "ios", "visionos"],
        "note": "REQUIRE_JS_PLAYER=False clients skip the JS player fetch entirely. "
                "android_vr broken since 2026-08-17. visionos currently works.",
    },

    "jsc_system": {
        "purpose": "Solve n-param (throttling) and sig (signature cipher) JS challenges",
        "challenge_types": {"N": "n-parameter deobfuscation", "SIG": "signature cipher"},
        "mechanism": "Fetches YouTube player JS, parses AST via meriyah, extracts solver "
                     "function, executes via subprocess (node/deno/bun/quickjs)",
        "key_file": "jsc/_builtin/vendor/yt.solver.core.js",
        "skip_condition": "REQUIRE_JS_PLAYER=False clients do not need JSC solving. "
                          "HLS/m3u8 manifest URLs from visionos do not carry n-param.",
    },

    "pot_system": {
        "purpose": "Proof-of-Origin Token — newer anti-bot layer beyond n/sig",
        "required_for": "Most web clients (GVS_PO_TOKEN_POLICY required=True for HTTPS/DASH)",
        "not_required": "android/ios with player_token, visionos (no POT policy set)",
        "note": "Separate plugin system mirroring jsc/ — provider/director/registry pattern",
    },

    "stream_url_flow": {
        "1_innertube_call": "POST /youtubei/v1/player -> streamingData.adaptiveFormats[]",
        "2_format_selection": "adaptiveFormats has separate video (mimeType video/*) and audio (audio/*)",
        "3_url_or_cipher": "Each format has either url (direct) or signatureCipher (needs sig solve)",
        "4_n_param": "url contains n= query param -> must be solved to avoid throttling (for web clients)",
        "5_hls_path": "visionos returns HLS manifest (hlsManifestUrl) -> no n-param needed",
    },

    "visionos_client_context": {
        "clientName": "VISIONOS",
        "clientVersion": "1.02",
        "INNERTUBE_CONTEXT_CLIENT_NAME": 255,
        "REQUIRE_JS_PLAYER": False,
        "no_pot_policy": True,
    },
}

# =============================================================================
# FINDINGS
# =============================================================================

FINDINGS = {
    "YTDLP-ARCH-SUBPROCESS-JSC": {
        "file": "extractor/youtube/jsc/_builtin/node.py",
        "line": 41,
        "severity": "ARCH",
        "status": "CONFIRMED",
        "summary": "JS challenge solving requires subprocess call to Node/Deno/Bun/QuickJS",
        "note": "yt-dlp spawns an external JS runtime process for every n/sig challenge. "
                "Avoidable by using REQUIRE_JS_PLAYER=False clients (visionos, ios, android). "
                "Pure Python n-param solving also possible via regex extraction from player JS.",
    },

    "YTDLP-ARCH-POT-EXTERNAL": {
        "file": "extractor/youtube/pot/_director.py",
        "line": 1,
        "severity": "ARCH",
        "status": "CONFIRMED",
        "summary": "PoT token required for all web clients; no built-in solver — requires plugin",
        "note": "The pot/ system has no built-in PoT generator. It expects external providers. "
                "This means web clients silently degrade without a PoT plugin. "
                "Avoidable: visionos and mobile clients have no PoT requirement.",
    },

    "YTDLP-ARCH-OVER-ABSTRACTION": {
        "file": "extractor/youtube/jsc/",
        "line": 0,
        "severity": "ARCH",
        "status": "CONFIRMED",
        "summary": "Provider/director/registry plugin pattern for JSC and PoT adds ~1500 LoC of indirection",
        "note": "The full provider plugin system is designed for external JSC/PoT providers. "
                "For a self-contained tool using only visionos, all of this is dead code.",
    },
}

# =============================================================================
# CLEAN
# =============================================================================

CLEAN = {
    "extractor/youtube/_video.py": "4592 lines; complex but no security sinks. Architecturally: "
        "orchestrates Innertube client calls, JSC/PoT director initialization, and format selection.",
    "extractor/youtube/_base.py": "1350 lines; defines INNERTUBE_CLIENTS dict and _call_api(). "
        "Key: _call_api posts to /youtubei/v1/{ep} with context+query JSON.",
    "extractor/youtube/jsc/": "Full JSC subsystem. No security issues; architectural sink is "
        "subprocess execution in node.py/deno.py/bun.py — by design, not a vulnerability.",
    "extractor/youtube/pot/": "Full PoT subsystem. No security issues; same provider/director pattern.",
    "extractor/youtube/jsc/_builtin/vendor/yt.solver.core.js": "AST-based solver using meriyah+astring. "
        "Parses player JS, extracts n/sig solver functions, executes them. Clean; works correctly.",
}
