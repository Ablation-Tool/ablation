#!/usr/bin/env python3
"""
dex_analyzer.py -- Security scanner for Android APKs using the ablation DEX/AXML parser.

Scans all classes*.dex files in an APK for:
  - Hardcoded secrets (API keys, tokens, credentials, cloud keys)
  - Dangerous API usage (exec, reflection, crypto, dynamic code loading)
  - Cleartext network endpoints (http:// URLs)
  - SQLCipher / encryption key material
  - Exported attack surface (unprotected components)
  - Dangerous permission combinations

No external dependencies. Requires ablation.core.apk_parser.

Usage:
    from ablation.analyzers.dex_analyzer import DexAnalyzer

    scanner = DexAnalyzer.from_path('/path/to/app.apk')
    findings = scanner.scan()
    print(DexAnalyzer.report(findings))
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple

from ablation.core.apk_parser import (
    APKParser, DEXFile, ManifestInfo, MethodRef,
)


# ── severity ──────────────────────────────────────────────────────────────────

CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"


# ── Finding dataclass ─────────────────────────────────────────────────────────

@dataclass
class DexFinding:
    severity: str
    category: str
    title: str
    detail: str
    source: str        # "dex:classes3.dex" / "manifest" / "native"
    evidence: str = "" # raw string / API call / component name that triggered

    def fmt(self) -> str:
        lines = [
            f"[{self.severity}] {self.category}: {self.title}",
            f"  source:   {self.source}",
            f"  detail:   {self.detail}",
        ]
        if self.evidence:
            # truncate long evidence lines
            ev = self.evidence[:200] + ("…" if len(self.evidence) > 200 else "")
            lines.append(f"  evidence: {ev}")
        return "\n".join(lines)


# ── Secret patterns ───────────────────────────────────────────────────────────

# Each entry: (category_label, regex_pattern)
# Patterns focus on high-entropy secrets and well-known vendor key formats.
_SECRET_PATTERNS: List[Tuple[str, re.Pattern]] = [
    # Generic high-entropy tokens / API keys
    ("aws_access_key",      re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key",      re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][A-Za-z0-9/+=]{40}['\"]")),
    ("google_api_key",      re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("firebase_url",        re.compile(r"https://[a-z0-9-]+\.firebaseio\.com")),
    ("firebase_key",        re.compile(r"(?i)firebase.{0,20}['\"][A-Za-z0-9\-_]{32,}['\"]")),
    ("tuya_app_key",        re.compile(r"(?i)(?:appKey|app_key|thingAppKey).{0,10}['\"][A-Za-z0-9]{16,32}['\"]")),
    ("tuya_app_secret",     re.compile(r"(?i)(?:appSecret|app_secret|thingSecret).{0,10}['\"][A-Za-z0-9]{32,64}['\"]")),
    ("jwt_bearer",          re.compile(r"eyJ[A-Za-z0-9+/]{20,}\.eyJ[A-Za-z0-9+/]{20,}\.[A-Za-z0-9+/\-_]+")),
    ("private_key_pem",     re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("generic_secret",      re.compile(r"(?i)(?:secret|password|passwd|api_key|apikey|access_token|auth_token).{0,5}[=:]\s*['\"][A-Za-z0-9+/=_\-]{16,}['\"]")),
    ("hex_key_32",          re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")),  # 32-byte hex key
    ("hex_key_16",          re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])")),  # 16-byte hex key
]

# ── Dangerous API patterns ────────────────────────────────────────────────────

# class_fragment -> (label, severity)
_DANGEROUS_CLASSES: Dict[str, Tuple[str, str]] = {
    "Ljava/lang/Runtime;"                       : ("exec/Runtime",        HIGH),
    "Ljava/lang/ProcessBuilder;"                : ("exec/ProcessBuilder",  HIGH),
    "Ldalvik/system/DexClassLoader;"            : ("dyn_load/DexClassLoader", HIGH),
    "Ldalvik/system/PathClassLoader;"           : ("dyn_load/PathClassLoader", MEDIUM),
    "Ldalvik/system/InMemoryDexClassLoader;"    : ("dyn_load/InMemoryDexClassLoader", CRITICAL),
    "Ljava/lang/reflect/Method;"                : ("reflection",          MEDIUM),
    "Ljava/lang/reflect/Field;"                 : ("reflection",          MEDIUM),
    "Ljavax/crypto/Cipher;"                     : ("crypto/Cipher",       INFO),
    "Ljavax/crypto/spec/SecretKeySpec;"         : ("crypto/SecretKeySpec", INFO),
    "Ljava/security/MessageDigest;"             : ("crypto/MessageDigest", INFO),
    "Lnet/sqlcipher/database/SQLiteDatabase;"   : ("sqlcipher/open",      INFO),
    "Landroid/webkit/WebView;"                  : ("webview",             MEDIUM),
    "Landroid/app/admin/DevicePolicyManager;"   : ("device_admin",        MEDIUM),
    "Landroid/telephony/SmsManager;"            : ("sms_send",            HIGH),
    "Landroid/accounts/AccountManager;"         : ("account_access",      MEDIUM),
    "Ljava/net/URL;"                            : ("network/URL",         INFO),
    "Lokhttp3/OkHttpClient;"                    : ("network/okhttp",      INFO),
    "Lretrofit2/Retrofit;"                      : ("network/retrofit",    INFO),
    "Lcom/squareup/okhttp3/OkHttpClient;"       : ("network/okhttp3",     INFO),
}

# method name -> (label, severity) for methods across any class
_DANGEROUS_METHODS: Dict[str, Tuple[str, str]] = {
    "exec"                  : ("exec/Runtime.exec",        HIGH),
    "loadDex"               : ("dyn_load",                 HIGH),
    "loadClass"             : ("dyn_load/loadClass",       MEDIUM),
    "invoke"                : ("reflection/invoke",        MEDIUM),
    "setJavaScriptEnabled"  : ("webview/js_enabled",       HIGH),
    "addJavascriptInterface": ("webview/js_bridge",        CRITICAL),
    "loadUrl"               : ("webview/loadUrl",          MEDIUM),
    "evaluateJavascript"    : ("webview/eval_js",          HIGH),
    "openOrCreateDatabase"  : ("sqlcipher/open",           INFO),
    "sendTextMessage"       : ("sms_send",                 HIGH),
    "setDeviceOwner"        : ("device_admin/owner",       HIGH),
    "wipeData"              : ("device_admin/wipe",        CRITICAL),
    "setPackagesSuspended"  : ("device_admin/suspend",     HIGH),
}

# ── Crypto misuse patterns ────────────────────────────────────────────────────

_WEAK_CRYPTO_STRINGS = [
    ("DES",         "weak_cipher/DES",       HIGH),
    ("DESede",      "weak_cipher/3DES",      MEDIUM),
    ("RC4",         "weak_cipher/RC4",       HIGH),
    ("ARC4",        "weak_cipher/RC4",       HIGH),
    ("MD5",         "weak_hash/MD5",         MEDIUM),
    ("SHA1",        "weak_hash/SHA1",        LOW),
    ("SHA-1",       "weak_hash/SHA1",        LOW),
    ("ECB",         "weak_mode/ECB",         HIGH),
    ("AES/ECB",     "weak_mode/AES-ECB",     HIGH),
    ("NoPadding",   "crypto/no_padding",     LOW),
    ("SSL",         "tls/ssl_ref",           INFO),
    ("SSLv3",       "tls/SSLv3",             CRITICAL),
    ("TLSv1\b",     "tls/TLSv1.0",          HIGH),
    ("TLSv1.1",     "tls/TLSv1.1",          HIGH),
]

_HARDCODED_IV = re.compile(
    r"(?i)(?:iv|initialization.vector|ivSpec).{0,5}=.{0,20}"
    r"(?:new byte\[|0x[0-9a-f]{2}|\\x[0-9a-f]{2}|00000000)"
)


# ── DexAnalyzer ───────────────────────────────────────────────────────────────

class DexAnalyzer:
    """
    Security scanner for Android APKs.

    Scans all DEX files and the manifest for security-relevant findings.
    Construction: DexAnalyzer.from_path(apk_path)
    Execution:    findings = scanner.scan()
    Display:      print(DexAnalyzer.report(findings))
    """

    def __init__(self, apk: APKParser) -> None:
        self._apk = apk
        self._manifest: Optional[ManifestInfo] = None

    @classmethod
    def from_path(cls, path: str | Path) -> "DexAnalyzer":
        return cls(APKParser.from_path(path))

    # ── top-level scan ────────────────────────────────────────────────────────

    def scan(self) -> List[DexFinding]:
        findings: List[DexFinding] = []

        self._manifest = self._apk.parse_manifest()
        findings.extend(self._scan_manifest(self._manifest))

        for dex in self._apk.iter_dex():
            findings.extend(self._scan_dex_strings(dex))
            findings.extend(self._scan_dex_apis(dex))

        findings.sort(key=lambda f: _SEVERITY_RANK.get(f.severity, 99))
        return findings

    # ── manifest scan ─────────────────────────────────────────────────────────

    def _scan_manifest(self, mf: ManifestInfo) -> List[DexFinding]:
        results: List[DexFinding] = []
        src = "manifest"

        # debuggable flag
        if mf.debuggable:
            results.append(DexFinding(
                severity="HIGH", category="manifest/debug",
                title="Application is debuggable",
                detail="android:debuggable=true allows ADB debugging on any device",
                source=src,
            ))

        # cleartext traffic
        if mf.uses_cleartext_traffic:
            results.append(DexFinding(
                severity="MEDIUM", category="manifest/cleartext",
                title="Cleartext HTTP traffic explicitly allowed",
                detail="android:usesCleartextTraffic=true; MITM attacks are possible",
                source=src,
            ))

        # backup
        if mf.allow_backup:
            results.append(DexFinding(
                severity="LOW", category="manifest/backup",
                title="Application data backup enabled",
                detail="android:allowBackup=true; app data extractable via adb backup on rooted devices",
                source=src,
            ))

        # dangerous permissions
        for p in mf.dangerous_permissions():
            results.append(DexFinding(
                severity="INFO", category="manifest/dangerous_permission",
                title=f"Dangerous permission: {p.split('.')[-1]}",
                detail=f"App requests {p}",
                source=src,
                evidence=p,
            ))

        # exported components without permission
        for comp in mf.exported_components():
            if comp.permission is None:
                sev = HIGH if comp.tag in ("activity", "service") else MEDIUM
                results.append(DexFinding(
                    severity=sev,
                    category=f"manifest/exported_{comp.tag}",
                    title=f"Exported {comp.tag} without permission guard: {comp.name.split('.')[-1]}",
                    detail=(
                        f"{comp.tag} '{comp.name}' is reachable from other apps "
                        f"(exported={'true' if comp.exported else 'implicit via intent-filter'}) "
                        f"with no android:permission restriction."
                    ),
                    source=src,
                    evidence=comp.name,
                ))

        # SMS receiver
        sms_actions = {"android.provider.Telephony.SMS_RECEIVED", "android.provider.Telephony.SMS_DELIVER"}
        for comp in mf.components:
            if set(comp.intent_filters) & sms_actions:
                results.append(DexFinding(
                    severity=HIGH,
                    category="manifest/sms_receiver",
                    title=f"SMS receiver registered: {comp.name.split('.')[-1]}",
                    detail=f"Component '{comp.name}' intercepts incoming SMS messages",
                    source=src,
                    evidence=comp.name,
                ))

        return results

    # ── string scan ───────────────────────────────────────────────────────────

    def _scan_dex_strings(self, dex: DEXFile) -> List[DexFinding]:
        results: List[DexFinding] = []
        src = f"dex:{dex.filename}"
        seen_secrets: Set[str] = set()
        seen_crypto: Set[str] = set()
        http_seen: Set[str] = set()

        for s in dex.iter_strings():
            if not s or len(s) < 4:
                continue

            # secret patterns
            for label, pat in _SECRET_PATTERNS:
                m = pat.search(s)
                if m and m.group() not in seen_secrets:
                    seen_secrets.add(m.group())
                    results.append(DexFinding(
                        severity=HIGH,
                        category=f"secrets/{label}",
                        title=f"Hardcoded {label.replace('_', ' ')}",
                        detail=f"Pattern '{label}' matched in string constant",
                        source=src,
                        evidence=s[:200],
                    ))

            # cleartext URLs
            if s.startswith("http://") and len(s) > 10:
                host = s.split("/")[2] if "/" in s[7:] else s[7:]
                if host not in http_seen:
                    http_seen.add(host)
                    results.append(DexFinding(
                        severity=LOW,
                        category="network/cleartext_url",
                        title="Cleartext HTTP URL in string constants",
                        detail=f"HTTP endpoint reference found: {host}",
                        source=src,
                        evidence=s[:200],
                    ))

            # weak crypto string refs
            for keyword, label, severity in _WEAK_CRYPTO_STRINGS:
                pat = re.compile(r'\b' + re.escape(keyword) + r'\b')
                if pat.search(s) and keyword not in seen_crypto:
                    seen_crypto.add(keyword)
                    results.append(DexFinding(
                        severity=severity,
                        category=f"crypto/{label}",
                        title=f"Weak crypto reference: {keyword}",
                        detail=f"String constant '{s[:80]}' references weak algorithm/mode '{keyword}'",
                        source=src,
                        evidence=s[:200],
                    ))

        return results

    # ── API call scan ─────────────────────────────────────────────────────────

    def _scan_dex_apis(self, dex: DEXFile) -> List[DexFinding]:
        results: List[DexFinding] = []
        src = f"dex:{dex.filename}"
        seen_class_apis: Set[str] = set()
        seen_method_apis: Set[str] = set()

        for mref in dex.iter_method_refs():
            # class-level check
            cls = mref.class_name
            if cls in _DANGEROUS_CLASSES:
                label, severity = _DANGEROUS_CLASSES[cls]
                key = f"{cls}:{label}"
                if key not in seen_class_apis:
                    seen_class_apis.add(key)
                    results.append(DexFinding(
                        severity=severity,
                        category=f"api/{label}",
                        title=f"Dangerous API class used: {label}",
                        detail=f"Reference to {cls}",
                        source=src,
                        evidence=str(mref),
                    ))

            # method-level check
            mn = mref.method_name
            if mn in _DANGEROUS_METHODS:
                label, severity = _DANGEROUS_METHODS[mn]
                key = f"{cls}::{mn}"
                if key not in seen_method_apis:
                    seen_method_apis.add(key)
                    results.append(DexFinding(
                        severity=severity,
                        category=f"api/{label}",
                        title=f"Dangerous method call: {mn}()",
                        detail=f"{cls}->{mn}",
                        source=src,
                        evidence=str(mref),
                    ))

        return results

    # ── report ────────────────────────────────────────────────────────────────

    @staticmethod
    def report(findings: List[DexFinding], max_info: int = 20) -> str:
        if not findings:
            return "DexAnalyzer: no findings."

        lines = [f"DexAnalyzer: {len(findings)} findings\n"]
        by_sev: Dict[str, List[DexFinding]] = {}
        for f in findings:
            by_sev.setdefault(f.severity, []).append(f)

        for sev in (CRITICAL, HIGH, MEDIUM, LOW, INFO):
            group = by_sev.get(sev, [])
            if not group:
                continue
            lines.append(f"── {sev} ({len(group)}) " + "─" * (40 - len(sev)))
            shown = group if sev != INFO else group[:max_info]
            for finding in shown:
                lines.append(finding.fmt())
                lines.append("")
            if sev == INFO and len(group) > max_info:
                lines.append(f"  ... {len(group) - max_info} more INFO findings omitted\n")

        return "\n".join(lines)


_SEVERITY_RANK = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}
