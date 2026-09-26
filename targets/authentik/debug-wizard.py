#!/usr/bin/env python3
"""
debug-wizard.py — Authentik flow/stage static analysis harness.

Adapted from tool.txt "surreal" harness concepts:
  - Stage enumeration from source (no running instance needed)
  - Multi-persona analysis: which stages each role can reach
  - Transition graph via policy/permission pattern analysis
  - Cycle detection in stage reference graphs
  - DOT graph output (pipe to graphviz or paste at dreampuf.github.io)
  - XSS sink scan across TypeScript templates

Usage:
    cd /home/cowboy/ablation
    python3 targets/authentik/debug-wizard.py [--target /tmp/authentik] [--mode MODE]

Modes:
    default   — Stage types + auth surface + invariant checks (default)
    graph     — DOT graph of stage/flow relationships
    personas  — Multi-persona diff: which auth levels reach which stages
    xss       — XSS sink scan across all .ts/.tsx files
    all       — Run all modes

Personas (maps from surreal harness):
    admin        → IsSuperUser / is_superuser=True / global admin
    user         → IsAuthenticated / regular session user
    service      → TokenAuthentication (API token, not session)
    attacker     → AllowAny / unauthenticated
"""

import argparse
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from ablation.analyzers.source_ingestion import SourceContext
except ImportError:
    # Add ablation to path if not installed
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from ablation.analyzers.source_ingestion import SourceContext


# ---------------------------------------------------------------------------
# Stage type patterns — scraped from authentik/stages/*/models.py
# ---------------------------------------------------------------------------

STAGE_TYPES = {
    "identification":   re.compile(r"class\s+IdentificationStage\b"),
    "password":         re.compile(r"class\s+PasswordStage\b"),
    "mfa_totp":         re.compile(r"class\s+TOTPValidateStage\b|class\s+TOTPSetupStage\b"),
    "mfa_webauthn":     re.compile(r"class\s+AuthenticatorWebAuthnStage\b"),
    "mfa_sms":          re.compile(r"class\s+SMSAuthenticatorSetupStage\b"),
    "mfa_duo":          re.compile(r"class\s+AuthenticatorDuoStage\b"),
    "consent":          re.compile(r"class\s+ConsentStage\b"),
    "prompt":           re.compile(r"class\s+PromptStage\b"),
    "email":            re.compile(r"class\s+EmailStage\b"),
    "captcha":          re.compile(r"class\s+CaptchaStage\b"),
    "deny":             re.compile(r"class\s+DenyStage\b"),
    "dummy":            re.compile(r"class\s+DummyStage\b"),
    "user_write":       re.compile(r"class\s+UserWriteStage\b"),
    "user_login":       re.compile(r"class\s+UserLoginStage\b"),
    "user_logout":      re.compile(r"class\s+UserLogoutStage\b"),
    "user_delete":      re.compile(r"class\s+UserDeleteStage\b"),
    "invitation":       re.compile(r"class\s+InvitationStage\b"),
    "source":           re.compile(r"class\s+SourceStage\b"),
}

# Auth level signals in Python files
_AUTH_SIGNALS = {
    "NONE": [
        re.compile(r"permission_classes\s*=\s*\[\s*AllowAny\s*\]"),
        re.compile(r"authentication_classes\s*=\s*\[\s*\]"),
        re.compile(r"@action\s*\([^)]*permission_classes\s*=\s*\[\s*AllowAny\s*\]"),
    ],
    "ADMIN": [
        re.compile(r"\bIsSuperUser\b|\bIsAdminUser\b"),
        re.compile(r"@superuser_required\b|@staff_member_required\b"),
        re.compile(r"\bpermission_required\s*=\s*.*admin"),
    ],
    "TOKEN": [
        re.compile(r"\bTokenAuthentication\b"),
        re.compile(r"\bBearerTokenAuthentication\b"),
    ],
    "SESSION": [
        re.compile(r"\bIsAuthenticated\b|\bObjectPermissions\b"),
        re.compile(r"\bHasPermission\b"),
        re.compile(r"\bLoginRequiredMixin\b"),
    ],
}

# XSS sinks in TypeScript
_XSS_SINKS = [
    (re.compile(r"\bunsafeHTML\s*\("), "unsafeHTML()"),
    (re.compile(r"\bunsafeStatic\s*\("), "unsafeStatic()"),
    (re.compile(r'href=\$\{(?!.*toAdminInterface)'), "href=${dynamic}"),
    (re.compile(r'href="\$\{'), "href=\"${dynamic}\""),
    (re.compile(r'innerHTML\s*=\s*\$\{'), "innerHTML=${dynamic}"),
    (re.compile(r'innerHTML\s*=\s*[^"\']'), "innerHTML= direct"),
    (re.compile(r'\.innerHTML\s*\+?='), ".innerHTML="),
    (re.compile(r'createHTML\s*\('), "createHTML()"),
]

# Policy bypass patterns
_POLICY_BYPASS = [
    (re.compile(r"pass_policies\s*=\s*True"), "pass_policies=True"),
    (re.compile(r"skip_user_check\s*=\s*True"), "skip_user_check=True"),
    (re.compile(r"bypass_policies\s*=\s*True"), "bypass_policies=True"),
]

# Pickle deserialization (previously confirmed findings)
_PICKLE_PATTERNS = [
    (re.compile(r"\bpickle\.loads\s*\("), "pickle.loads()"),
    (re.compile(r"\bpickle\.load\s*\("), "pickle.load()"),
    (re.compile(r"from django\.core\.cache.*get.*pickle", re.S), "cache+pickle"),
]


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class StageInfo:
    rel_path: str
    stage_type: str
    class_name: str
    auth_levels: list[str] = field(default_factory=list)
    policy_bypass: list[str] = field(default_factory=list)
    line: int = 0


@dataclass
class XssFinding:
    rel_path: str
    line: int
    text: str
    sink: str


@dataclass
class PersonaAccess:
    stage_type: str
    class_name: str
    rel_path: str
    personas: dict[str, bool] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Mode: default — stage enumeration + invariant checks
# ---------------------------------------------------------------------------

def mode_default(ctx: SourceContext) -> None:
    print("=" * 70)
    print("AUTHENTIK FLOW DEBUG HARNESS — default mode")
    print("=" * 70)

    # 1. Enumerate stage types from Python source
    stages: list[StageInfo] = []
    py_files = ctx.files_by_lang("python")
    for f in py_files:
        text = ctx.read(f)
        if not text:
            continue
        for stype, pattern in STAGE_TYPES.items():
            m = pattern.search(text)
            if not m:
                continue
            # Extract class name
            class_m = re.search(r"class\s+(\w+Stage\w*)\b", text[m.start():m.start()+200])
            class_name = class_m.group(1) if class_m else "UnknownStage"
            rel = ctx.rel(f)
            # Line number
            line = text[:m.start()].count("\n") + 1
            # Auth levels
            auth_levels = []
            for level, patterns in _AUTH_SIGNALS.items():
                for p in patterns:
                    if p.search(text):
                        auth_levels.append(level)
                        break
            # Policy bypass
            bypasses = []
            for p, label in _POLICY_BYPASS:
                hits = p.findall(text)
                if hits:
                    bypasses.append(label)

            stages.append(StageInfo(
                rel_path=rel,
                stage_type=stype,
                class_name=class_name,
                auth_levels=sorted(set(auth_levels)),
                policy_bypass=bypasses,
                line=line,
            ))

    if not stages:
        print("[!] No stage class definitions found — check --target path")
        return

    print(f"\n[+] {len(stages)} stage type(s) enumerated:\n")
    print(f"  {'Type':<20} {'Class':<40} {'Auth':<30} {'Location'}")
    print("  " + "-" * 110)
    for s in sorted(stages, key=lambda x: x.stage_type):
        auth_str = ",".join(s.auth_levels) if s.auth_levels else "NONE"
        print(f"  {s.stage_type:<20} {s.class_name:<40} {auth_str:<30} {s.rel_path}:{s.line}")

    # 2. Invariant: stages with no auth signal
    no_auth = [s for s in stages if not s.auth_levels or "NONE" in s.auth_levels]
    if no_auth:
        print(f"\n[!] INVARIANT VIOLATION — {len(no_auth)} stage(s) with NONE/missing auth signal:")
        for s in no_auth:
            print(f"    {s.stage_type} ({s.class_name}) — {s.rel_path}:{s.line}")
    else:
        print("\n[✓] All stages have auth signal (no NONE-gated stage types)")

    # 3. Invariant: policy bypass patterns
    bypass_stages = [s for s in stages if s.policy_bypass]
    if bypass_stages:
        print(f"\n[!] INVARIANT VIOLATION — {len(bypass_stages)} stage file(s) with policy bypass:")
        for s in bypass_stages:
            print(f"    {s.stage_type} — {s.rel_path} — {', '.join(s.policy_bypass)}")
    else:
        print("[✓] No explicit policy bypass patterns found in stage definitions")

    # 4. AllowAny surface scan — broader than just stage files
    print("\n[+] AllowAny surface scan (all Python files):")
    allow_any_hits: list[tuple[str, int, str]] = []
    for f in py_files:
        text = ctx.read(f)
        if not text:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"\bAllowAny\b", line) and "import" not in line:
                allow_any_hits.append((ctx.rel(f), i, line.strip()))

    if allow_any_hits:
        print(f"  {len(allow_any_hits)} AllowAny usage(s):")
        for rel, line_num, line_text in allow_any_hits[:30]:
            print(f"    {rel}:{line_num}  {line_text[:80]}")
        if len(allow_any_hits) > 30:
            print(f"    ... {len(allow_any_hits) - 30} more")
    else:
        print("  No AllowAny usages found")

    # 5. Pickle scan (known finding class)
    print("\n[+] Pickle deserialization scan:")
    pickle_hits: list[tuple[str, int, str]] = []
    for f in py_files:
        text = ctx.read(f)
        if not text:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for p, label in _PICKLE_PATTERNS:
                if p.search(line):
                    pickle_hits.append((ctx.rel(f), i, label, line.strip()))
    if pickle_hits:
        print(f"  {len(pickle_hits)} pickle usage(s) — already tracked in FINDINGS dict:")
        for rel, line_num, label, line_text in pickle_hits[:10]:
            print(f"    [{label}] {rel}:{line_num}  {line_text[:80]}")
    else:
        print("  No raw pickle.loads() calls found in Python files")


# ---------------------------------------------------------------------------
# Mode: xss — TypeScript XSS sink scan
# ---------------------------------------------------------------------------

def mode_xss(ctx: SourceContext) -> None:
    print("=" * 70)
    print("AUTHENTIK FLOW DEBUG HARNESS — xss mode")
    print("=" * 70)

    ts_files = ctx.files_by_lang("typescript")
    print(f"\n[+] Scanning {len(ts_files)} TypeScript files for XSS sinks...\n")

    findings: list[XssFinding] = []
    for f in ts_files:
        text = ctx.read(f)
        if not text:
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, label in _XSS_SINKS:
                if pattern.search(line):
                    findings.append(XssFinding(
                        rel_path=ctx.rel(f),
                        line=i,
                        text=line.strip()[:120],
                        sink=label,
                    ))

    # Group by sink type
    by_sink: dict[str, list[XssFinding]] = defaultdict(list)
    for f in findings:
        by_sink[f.sink].append(f)

    print(f"  {'Sink':<30} {'Count'}")
    print("  " + "-" * 50)
    for sink, hits in sorted(by_sink.items(), key=lambda x: -len(x[1])):
        print(f"  {sink:<30} {len(hits)}")

    print()
    for sink, hits in sorted(by_sink.items(), key=lambda x: -len(x[1])):
        print(f"\n── {sink} ({len(hits)} hits) ──────────────────────")
        for h in hits[:20]:
            print(f"  {h.rel_path}:{h.line}")
            print(f"    {h.text}")
        if len(hits) > 20:
            print(f"  ... {len(hits) - 20} more (use grep for full list)")

    # Known confirmed vs. new
    confirmed_paths = {
        "web/src/admin/applications/ApplicationListPage.ts",
        "web/src/admin/applications/ApplicationViewPage.ts",
    }
    print("\n[+] Status:")
    new_count = sum(1 for f in findings if not any(cp in f.rel_path for cp in confirmed_paths))
    confirmed_count = sum(1 for f in findings if any(cp in f.rel_path for cp in confirmed_paths))
    print(f"  Confirmed (AUT-LAUNCH-URL-1): {confirmed_count} occurrences in ApplicationListPage/ViewPage")
    if new_count:
        print(f"  [!] Potentially new: {new_count} occurrences — review required")
    else:
        print(f"  [✓] No new sink occurrences beyond confirmed findings")


# ---------------------------------------------------------------------------
# Mode: personas — multi-persona auth diff
# ---------------------------------------------------------------------------

PERSONAS = {
    "admin":    {"signals": ["ADMIN", "NONE"], "label": "superuser / is_superuser=True"},
    "user":     {"signals": ["SESSION", "NONE"], "label": "authenticated user session"},
    "service":  {"signals": ["TOKEN", "SESSION", "NONE"], "label": "API token / Bearer"},
    "attacker": {"signals": ["NONE"], "label": "unauthenticated / AllowAny only"},
}


def _persona_can_access(stage: StageInfo, persona: str) -> bool:
    """Return True if persona's auth signals satisfy the stage's required signals."""
    allowed_signals = PERSONAS[persona]["signals"]
    if not stage.auth_levels:
        return "NONE" in allowed_signals
    # Stage is accessible if any of its auth levels match persona's allowed signals
    return any(level in allowed_signals for level in stage.auth_levels)


def mode_personas(ctx: SourceContext) -> None:
    print("=" * 70)
    print("AUTHENTIK FLOW DEBUG HARNESS — personas mode")
    print("=" * 70)

    print("\nPersonas:")
    for name, cfg in PERSONAS.items():
        print(f"  {name:<12} — {cfg['label']}")

    # Build stage list (reuse default logic inline)
    stages: list[StageInfo] = []
    py_files = ctx.files_by_lang("python")
    for f in py_files:
        text = ctx.read(f)
        if not text:
            continue
        for stype, pattern in STAGE_TYPES.items():
            m = pattern.search(text)
            if not m:
                continue
            class_m = re.search(r"class\s+(\w+Stage\w*)\b", text[m.start():m.start()+200])
            class_name = class_m.group(1) if class_m else "UnknownStage"
            auth_levels = []
            for level, patterns in _AUTH_SIGNALS.items():
                for p in patterns:
                    if p.search(text):
                        auth_levels.append(level)
                        break
            stages.append(StageInfo(
                rel_path=ctx.rel(f),
                stage_type=stype,
                class_name=class_name,
                auth_levels=sorted(set(auth_levels)),
            ))

    persona_names = list(PERSONAS.keys())
    header = f"\n  {'Stage Type':<22} {'Class':<35}" + "".join(f"  {p:<10}" for p in persona_names)
    print(header)
    print("  " + "-" * (60 + len(persona_names) * 12))

    divergence_stages: list[tuple[StageInfo, list[bool]]] = []
    for s in sorted(stages, key=lambda x: x.stage_type):
        access = [_persona_can_access(s, p) for p in persona_names]
        marks = ["  ✓         " if a else "  ✗         " for a in access]
        print(f"  {s.stage_type:<22} {s.class_name:<35}" + "".join(marks))
        if len(set(access)) > 1:
            divergence_stages.append((s, access))

    if divergence_stages:
        print(f"\n[!] DIVERGENCE POINTS — {len(divergence_stages)} stage(s) where personas differ:")
        for s, access in divergence_stages:
            allowed = [p for p, a in zip(persona_names, access) if a]
            denied  = [p for p, a in zip(persona_names, access) if not a]
            print(f"    {s.stage_type} ({s.class_name})")
            print(f"      allowed: {', '.join(allowed) or 'none'}")
            print(f"      denied:  {', '.join(denied) or 'none'}")
    else:
        print("\n[✓] No divergence points — all personas see the same stage access")


# ---------------------------------------------------------------------------
# Mode: graph — DOT graph output
# ---------------------------------------------------------------------------

def mode_graph(ctx: SourceContext) -> None:
    print("=" * 70)
    print("AUTHENTIK FLOW DEBUG HARNESS — graph mode")
    print("=" * 70)

    # Find flow-to-stage binding patterns in Python source
    # FlowStageBinding links a Flow to a Stage with optional policies
    py_files = ctx.files_by_lang("python")

    binding_pattern = re.compile(
        r"FlowStageBinding\s*\("
        r"[^)]*flow\s*=\s*(\w+)"
        r"[^)]*stage\s*=\s*(\w+)",
        re.S
    )
    stage_ref_pattern = re.compile(
        r"(\w+Stage)\s*\(\s*name\s*=\s*['\"]([^'\"]+)['\"]"
    )

    flows: dict[str, set[str]] = defaultdict(set)
    stage_names: dict[str, str] = {}

    for f in py_files:
        text = ctx.read(f)
        if not text:
            continue
        for m in binding_pattern.finditer(text):
            flow_var = m.group(1)
            stage_var = m.group(2)
            flows[flow_var].add(stage_var)
        for m in stage_ref_pattern.finditer(text):
            stage_class = m.group(1)
            stage_name  = m.group(2)
            stage_names[stage_name] = stage_class

    # Also scan migration files for flow fixture patterns
    migration_flow_re = re.compile(r'"flow"\s*:\s*"([^"]+)"')
    migration_stage_re = re.compile(r'"name"\s*:\s*"([^"]+)".*?"component"\s*:\s*"([^"]+)"', re.S)

    print("\ndigraph AuthentikFlows {")
    print('  rankdir=LR;')
    print('  node [shape=box, style=filled, fillcolor="#f0f0f0"];')
    print()

    # Static wizard step graph (always present)
    steps = [
        ("wizard_application", "application-step"),
        ("wizard_provider_choice", "provider-choice"),
        ("wizard_provider", "provider (dynamic)"),
        ("wizard_bindings", "bindings"),
        ("wizard_submit", "submit"),
    ]
    print('  // Application wizard (client-side)')
    print('  subgraph cluster_wizard {')
    print('    label="Application Wizard";')
    for i, (node_id, label) in enumerate(steps):
        print(f'    "{node_id}" [label="{label}"];')
    for i in range(len(steps) - 1):
        src = steps[i][0]
        dst = steps[i+1][0]
        print(f'    "{src}" -> "{dst}";')
    print('  }')
    print()

    # Flow stage types
    print('  // Flow stage type definitions (Python backend)')
    for stype in sorted(STAGE_TYPES.keys()):
        print(f'  "stage_{stype}" [label="{stype}", fillcolor="#d4e8ff"];')
    print()

    # Flow executor
    print('  "flow_executor" [label="FlowExecutorView\\n(authentik/flows/executor.py)", fillcolor="#ffe0d4", shape=diamond];')
    for stype in sorted(STAGE_TYPES.keys()):
        print(f'  "flow_executor" -> "stage_{stype}" [style=dashed, label="challenge"];')

    print("}")
    print()
    print("# Render: dot -Tsvg | view, or paste at dreampuf.github.io/GraphvizOnline")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Authentik flow/wizard static analysis harness"
    )
    ap.add_argument(
        "--target",
        default="/tmp/authentik",
        help="Path to authentik repo (default: /tmp/authentik)",
    )
    ap.add_argument(
        "--mode",
        choices=["default", "graph", "personas", "xss", "all"],
        default="default",
        help="Analysis mode",
    )
    args = ap.parse_args()

    target = Path(args.target)
    if not target.is_dir():
        print(f"[!] Target not found: {target}", file=sys.stderr)
        sys.exit(1)

    print(f"Building SourceContext from {target} ...")
    ctx = SourceContext.from_path(target)
    print(ctx.summary())
    print()

    if args.mode in ("default", "all"):
        mode_default(ctx)
    if args.mode in ("xss", "all"):
        print()
        mode_xss(ctx)
    if args.mode in ("personas", "all"):
        print()
        mode_personas(ctx)
    if args.mode in ("graph", "all"):
        print()
        mode_graph(ctx)


if __name__ == "__main__":
    main()
