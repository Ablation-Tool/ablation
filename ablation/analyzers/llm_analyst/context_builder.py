"""
context_builder.py — Assembles the hierarchical prompt context for LLM analysis.

Context ordering (most signal first, per O'Reilly "Prompt Engineering for LLMs"):
  1. Prior findings from func_id_db — primes the model with confirmed RE
  2. Callee names — strongest semantic signal for function naming
  3. String xrefs — second strongest signal
  4. CFG summary — structural context (BB count, cyclomatic complexity)
  5. Raw disassembly — last, token-expensive, but necessary for specifics

System prompt is kept stable (same across all calls of the same task type)
so Anthropic's prompt cache TTL applies and repeated calls are cheap.
"""

from __future__ import annotations

from typing import Optional

# ── Task descriptors ──────────────────────────────────────────────────────────

TASK_INSTRUCTIONS = {
    'name_function': (
        'Analyze this function and propose a descriptive snake_case name and role.\n'
        'Use the prior findings, callee names, and string xrefs as your primary signals.\n'
        'Read disassembly only if the above signals are insufficient.\n'
        'Call done() when confident. If confidence < 0.5, still call done() with your best guess and low confidence.'
    ),
    'vuln_hypothesis': (
        'Analyze this function for vulnerability potential.\n'
        'Focus on: buffer size constraints, unchecked copies (strcpy/memcpy), '
        'integer arithmetic on externally-controlled values, use-after-free patterns, '
        'and unchecked return values from allocation.\n'
        'Check callee names and disassembly for copy operations.\n'
        'Call done() with vuln_notes describing any findings, or an empty string if none.'
    ),
    'struct_reconstruct': (
        'Analyze this function to infer the layout of any struct it accesses.\n'
        'Look for patterns of (register + constant) memory accesses — each unique offset is a candidate field.\n'
        'Group accesses by base register. Note the access size (byte/dword/qword) for each offset.\n'
        'Call done() with rationale describing the inferred struct layout as offset:width:name triples.'
    ),
    'patch_analysis': (
        'This function exists in two versions. Analyze the differences.\n'
        'Identify: what changed (new checks, removed code, changed constants), '
        'what vulnerability class the patch addresses, and which CWE applies.\n'
        'Call done() with vuln_notes containing: CWE ID, patch description, severity.'
    ),
    'exploit_chain': (
        'Given the confirmed primitives available (from prior findings), '
        'reason about how this function could serve as a link in an exploit chain.\n'
        'Consider: does it provide a write primitive? read primitive? type confusion? '
        'Can its output be used to corrupt an adjacent allocation?\n'
        'Call done() with vuln_notes describing the chain contribution, or empty if none.'
    ),
}

SYSTEM_PROMPT_TEMPLATE = """\
You are a senior reverse engineer analyzing {product} version {version}.
Binary: {binary_hint}

All binary data (disassembly, strings, imports, CFG) is pre-loaded in the user message.
No tool calls are available — produce a JSON result directly from the pre-loaded data.

Rules:
- Disassembly offsets are relative to the function entry — +0000 is the first instruction.
- Prior findings from func_id_db are listed at the top of the user message.
  Weight CONFIRMED findings above CANDIDATE; use retrieval_source as a confidence signal.
- Respond with a single JSON object only — no prose, no markdown fences.

Ablation role taxonomy (use one of these or UNKNOWN):
AAA_DISPATCH, RADIUS_PARSER, RADIUS_ATTR_HANDLER, RADIUS_DISPATCH,
TACACS_PARSER, CRYPTO_HPKE, CRYPTO_OPENSSL, CRYPTO_STRAP, CRYPTO_IPC,
FILE_IO, TIMER, STRUCT_INIT, STRUCT_ACCESSOR, SAML_HANDLER,
CSTP_HANDLER, DTLS_HANDLER, PLT_LIBC, UNKNOWN
"""

USER_PROMPT_TEMPLATE = """\
{prior_findings_block}\
[FUNCTION]
addr: {addr:#x}
size: {size_hint}
callers: {callers}
callees: {callees}

[STRINGS referenced by this function]
{strings}

[CFG SUMMARY]
{cfg_summary}

[TASK]
{task_instruction}
"""


class ContextBuilder:
    def __init__(
        self,
        product:       str = 'unknown',
        version:       str = 'unknown',
        binary_hint:   str = '',
        max_tool_calls: int = 10,   # kept for API compat; unused in single-shot mode
    ):
        self.product        = product
        self.version        = version
        self.binary_hint    = binary_hint

    def system_prompt(self, kg_context: str = '') -> str:
        """
        Build the system prompt.  kg_context is optional KnowledgeGraph output
        (get_context_for_binary) that is appended as a [KNOWLEDGE GRAPH] section
        when provided — the memory interface surface from the dual-graph architecture.
        """
        base = SYSTEM_PROMPT_TEMPLATE.format(
            product=self.product,
            version=self.version,
            binary_hint=self.binary_hint or 'unknown',
        ).strip()
        if kg_context.strip():
            base += f'\n\n[KNOWLEDGE GRAPH — arch context from prior RE sessions]\n{kg_context.strip()}'
        return base

    def user_prompt(
        self,
        func_addr:      int,
        task:           str = 'name_function',
        prior_findings: list[dict] | None = None,
        size_hint:      str = 'unknown',
        callers:        list[str] | None = None,
        callees:        list[str] | None = None,
        strings:        list[str] | None = None,
        cfg_summary:    str = '',
    ) -> str:
        task_instruction = TASK_INSTRUCTIONS.get(
            task,
            TASK_INSTRUCTIONS['name_function']
        )

        prior_block = self._format_prior_findings(prior_findings)
        callers_str = ', '.join(callers) if callers else '(unknown)'
        callees_str = ', '.join(callees) if callees else '(unknown — use get_imports to discover)'
        strings_str = self._format_strings(strings)

        return USER_PROMPT_TEMPLATE.format(
            prior_findings_block=prior_block,
            addr=func_addr,
            size_hint=size_hint,
            callers=callers_str,
            callees=callees_str,
            strings=strings_str,
            cfg_summary=cfg_summary or '(not pre-loaded — use get_cfg if needed)',
            task_instruction=task_instruction,
        ).strip()

    # ── formatting helpers ────────────────────────────────────────────────────

    def _format_prior_findings(self, findings: list[dict] | None) -> str:
        if not findings:
            return ''
        lines = ['[PRIOR FINDINGS from func_id_db — weight CONFIRMED above CANDIDATE]']
        for f in findings[:5]:  # cap at 5 to control token budget
            name     = f.get('name', '')
            role     = f.get('role', '')
            conf     = f.get('confidence', '')
            epistemic = f.get('epistemic', '')
            source   = f.get('retrieval_source', '')
            notes    = (f.get('notes') or '')[:150]
            product  = f.get('product', '')
            ver      = f.get('version', '')

            tag = ''
            if epistemic:
                tag = f' [{epistemic}]'
            if source:
                tag += f' via:{source}'

            lines.append(
                f'  {name} | {role} | {conf}{tag} | {product} {ver}'
                + (f'\n    note: {notes}' if notes else '')
            )
        lines.append('')
        return '\n'.join(lines) + '\n'

    def _format_strings(self, strings: list[str] | None) -> str:
        if not strings:
            return '(none pre-loaded — use get_strings to retrieve)'
        # Show up to 10 strings, trim each to 120 chars
        shown = strings[:10]
        return '\n'.join(f'  "{s[:120]}"' for s in shown)

    # ── patch analysis variant ─────────────────────────────────────────────────

    def patch_prompt(
        self,
        func_addr_v1:   int,
        func_addr_v2:   int,
        disasm_v1:      str,
        disasm_v2:      str,
        version_v1:     str,
        version_v2:     str,
        prior_findings: list[dict] | None = None,
    ) -> str:
        prior_block = self._format_prior_findings(prior_findings)
        return (
            f'{prior_block}'
            f'[PATCH ANALYSIS]\n'
            f'Function at {func_addr_v1:#x} in version {version_v1} '
            f'vs {func_addr_v2:#x} in version {version_v2}\n\n'
            f'[BEFORE — {version_v1}]\n{disasm_v1}\n\n'
            f'[AFTER — {version_v2}]\n{disasm_v2}\n\n'
            f'[TASK]\n{TASK_INSTRUCTIONS["patch_analysis"]}'
        ).strip()
