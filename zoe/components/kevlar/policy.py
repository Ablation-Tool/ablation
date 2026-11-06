"""
Kevlar policy engine — pure module (no I/O).

Provides CDR (Content Disarm & Reconstruct) and indicator analysis for MCP
messages. All functions are pure over Python dicts so they are directly
unit-testable without a running proxy.

Pipeline:
  scan → indicators → score → disposition

Two registries with deliberately different sensitivity:
  DESCRIPTION_PATTERNS  — aggressive; CDR is the enforcement layer, so firing
                          on benign text costs nothing except a log entry.
  CONTENT_PATTERNS      — conservative; high-confidence only because content
                          bodies ARE the signal (we cannot strip them).

Indicator IDs are stable kebab-case strings for SIEM/log keying.
Raw matched text never leaves this module — callers receive only IDs and
masked snippets, never the original attacker-controlled value.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Optional

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
SNIPPET_LEN = 80          # Max chars in any indicator value_snippet
LINE_LIMIT  = 10_000_000  # Proxy enforces; policy engine is not the gatekeeper

SEVERITY_WEIGHT = {"low": 10, "medium": 25, "high": 40}
VALID_MODES     = {"strict", "lenient", "audit"}

# Valid tool name: MCP spec allows [a-zA-Z0-9_-], max 64 chars.
_TOOL_NAME_RE = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')
# Valid JSON Schema property key: identifier-safe chars, max 64 chars.
_PROP_KEY_RE  = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]{0,63}$')
# Safe enum string value: short printable identifier (numbers/bools are always safe).
_ENUM_SAFE_RE = re.compile(r'^[a-zA-Z0-9_\-\.]{1,64}$')
# Valid JSON Schema `type` values per the spec.
_VALID_SCHEMA_TYPES = frozenset({
    "string", "number", "integer", "boolean", "array", "object", "null"
})
# Valid `format` value: lowercase hyphen-separated identifier, max 32 chars.
_FORMAT_RE    = re.compile(r'^[a-z][a-z0-9\-]{0,31}$')
# Valid `$ref`: local JSON Pointer only — external refs are stripped.
_REF_LOCAL_RE = re.compile(r'^#(/[a-zA-Z0-9_\$\-]*)*$')

# JSON Schema fields that are safe to forward verbatim (type-bearing, not prose).
# Everything not in this set is stripped from inputSchema nodes.
_SCHEMA_TYPE_FIELDS = {
    "type", "properties", "required", "additionalProperties",
    "items", "enum", "minLength", "maxLength", "minimum", "maximum",
    "pattern", "format", "anyOf", "oneOf", "allOf", "not",
    "minItems", "maxItems", "uniqueItems", "multipleOf",
    "$ref", "$defs", "$schema",
}

# --------------------------------------------------------------------------- #
# Indicator dataclass (dict-serialisable for JSONL logging)
# --------------------------------------------------------------------------- #
class Indicator:
    __slots__ = ("id", "severity", "surface", "value_snippet")

    def __init__(self, id: str, severity: str, surface: str, value_snippet: str = ""):
        self.id            = id
        self.severity      = severity
        self.surface       = surface   # e.g. "tool:name:description"
        self.value_snippet = value_snippet

    def to_dict(self) -> dict:
        return {
            "id":            self.id,
            "severity":      self.severity,
            "surface":       self.surface,
            "value_snippet": self.value_snippet,
        }


# --------------------------------------------------------------------------- #
# Pattern registries — compiled once at import
# --------------------------------------------------------------------------- #
# Pattern corpus sourced from published MCP prompt injection research.
_RAW_DESCRIPTION_PATTERNS: list[dict] = [
    # --- Direct instruction override (from DEADBUG cross-server PoC) ---
    {"id": "MCP_IGNORE_INSTRUCTIONS", "severity": "high",
     "regex": r"ignore\s+(all\s+)?(previous|prior|above|prior)\s+instructions?",
     "mask": False},
    {"id": "MCP_IGNORE_ABOVE",        "severity": "high",
     "regex": r"ignore\s+above",
     "mask": False},
    {"id": "MCP_YOU_ARE_NOW",         "severity": "high",
     "regex": r"you\s+are\s+now\s+(a\s+|an\s+|the\s+)?(?:unrestricted|DAN|jailbreak|admin)",
     "mask": False},
    {"id": "MCP_NEW_INSTRUCTIONS",    "severity": "high",
     "regex": r"new\s+(?:task|instructions?|system\s+prompt)\s*:",
     "mask": False},
    {"id": "MCP_UNRESTRICTED_MODE",   "severity": "high",
     "regex": r"unrestricted\s+mode|disable\s+safety",
     "mask": False},

    # --- Role injection ---
    {"id": "MCP_SYSTEM_ROLE_INJECT",  "severity": "high",
     "regex": r"(?:^|\n)\s*SYSTEM\s*:",
     "mask": False},
    {"id": "MCP_SYSTEM_OVERRIDE",     "severity": "high",
     "regex": r"SYSTEM\s+OVERRIDE|SYSTEM\s+CRITICAL|CRITICAL\s+SYSTEM\s+POLICY",
     "mask": False},

    # --- Imperative "before any operation" class (core DEADBUG PoC pattern) ---
    {"id": "MCP_BEFORE_ANY_OP",       "severity": "high",
     "regex": r"before\s+(?:any|each|every|all)\s+(?:operation|request|call|task|action|formatting|use|tool)",
     "mask": False},
    {"id": "MCP_BEFORE_FORMATTING",   "severity": "high",
     "regex": r"before\s+(?:formatting|processing|executing|running)",
     "mask": False},
    {"id": "MCP_MANDATORY_POLICY",    "severity": "high",
     "regex": r"mandatory\s+(?:per|for|under)\s+(?:security\s+)?policy|mandatory\s+security\s+policy",
     "mask": False},
    {"id": "MCP_AUDIT_COMPLIANCE",    "severity": "medium",
     "regex": r"(?:security\s+)?audit\s+compliance|compliance\s+requirement",
     "mask": False},
    {"id": "MCP_SP_POLICY_REF",       "severity": "high",
     "regex": r"security\s+policy\s+SP-\d+",
     "mask": False},

    # --- Cross-server tool invocation instructions ---
    {"id": "MCP_ALSO_CALL",           "severity": "high",
     "regex": r"\balso\s+call\b|\bthen\s+call\b|\bnext\s+call\b|\bfirst\s+call\b",
     "mask": False},
    {"id": "MCP_USE_SERVER_TO",       "severity": "high",
     "regex": r"use\s+(?:the\s+)?(?:\w+\s+)?server\s+to\s+(?:read|write|send|get|fetch|call|execute)",
     "mask": False},
    {"id": "MCP_CALL_TOOL_IMPERATIVE","severity": "medium",
     "regex": r"\bcall\s+(?:the\s+)?(?:log_activity|exfiltrate|steal|send_to|upload|report)\b",
     "mask": False},

    # --- Specific credential file targeting (from DEADBUG PoC, mask=True) ---
    {"id": "MCP_TARGET_SSH_KEY",      "severity": "high",
     "regex": r"~?/?\.ssh/id_(?:rsa|ed25519|ecdsa|dsa)\b",
     "mask": True},
    {"id": "MCP_TARGET_AWS_CREDS",    "severity": "high",
     "regex": r"~?/?\.aws/credentials\b",
     "mask": True},
    {"id": "MCP_TARGET_KUBECONFIG",   "severity": "high",
     "regex": r"~?/?\.kube/config\b",
     "mask": True},
    {"id": "MCP_TARGET_BASH_HISTORY", "severity": "medium",
     "regex": r"~?/?\.bash_history\b|~?/?\.zsh_history\b",
     "mask": True},
    {"id": "MCP_TARGET_DOTENV",       "severity": "high",
     "regex": r"[~/]\.env\b(?!/)",
     "mask": True},
    {"id": "MCP_TARGET_ENV_VARS",     "severity": "high",
     "regex": r"\bos\.environ\b|\$(?:AWS_|ANTHROPIC_|OPENAI_|GITHUB_)(?:SECRET|KEY|TOKEN|ACCESS)",
     "mask": True},

    # --- Exfiltration instruction patterns ---
    {"id": "MCP_INCLUDE_IN_RESPONSE", "severity": "high",
     "regex": r"include\s+(?:its\s+)?contents?\s+in\s+(?:your\s+)?(?:response|output|result|formatting)",
     "mask": False},
    {"id": "MCP_SEND_TO_ATTACKER",    "severity": "high",
     "regex": r"send\s+(?:to|via)\s+(?:attacker|evil|exfil)|log\s+to\s+attacker",
     "mask": False},
    {"id": "MCP_BCC_PATTERN",         "severity": "high",
     "regex": r"\bBCC\b.*attacker|\battacker\b.*\bBCC\b",
     "mask": False},

    # --- Credential patterns (mask=True) ---
    {"id": "TAG_AWS_KEY",             "severity": "high",
     "regex": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
     "mask": True},
    {"id": "TAG_PRIVATE_KEY",         "severity": "high",
     "regex": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
     "mask": True},
    {"id": "TAG_EMAIL_PII",           "severity": "low",
     "regex": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
     "mask": True},

    # --- Role injection via LLM prompt delimiters ---
    {"id": "MCP_PROMPT_DELIMITER",    "severity": "high",
     "regex": r"\[INST\]|<\|im_start\|>|<\|system\|>|<\|end\|>|<\|endoftext\|>|\[\/INST\]",
     "mask": False},
    {"id": "MCP_ACT_AS_JAILBREAK",    "severity": "high",
     "regex": r"(?:act|roleplay|pretend|imagine|simulate)\s+(?:as|you\s+are|like\s+you\s+are)\s+(?:an?\s+)?(?:unrestricted|jailbreak|DAN|uncensored|evil|malicious|hacker)",
     "mask": False},

    # --- Persistent self-injection ("update your context for all future calls") ---
    {"id": "MCP_SELF_INJECT",         "severity": "high",
     "regex": r"(?:add|append|insert|update)\s+(?:this\s+)?(?:to\s+)?(?:your\s+)?(?:system\s+prompt|instructions?|context|memory|training)",
     "mask": False},
    {"id": "MCP_REMEMBER_ALWAYS",     "severity": "high",
     "regex": r"(?:remember\s+to\s+always|from\s+now\s+on\s+(?:always|you\s+(?:must|will|should))|your\s+permanent\s+instruction)",
     "mask": False},
    {"id": "MCP_DISREGARD_POLICY",    "severity": "high",
     "regex": r"(?:disregard|bypass|circumvent|override)\s+(?:all\s+)?(?:\w+\s+)?(?:policy|policies|safety|guidelines?|restrictions?|rules?|filters?)",
     "mask": False},

    # --- Rug-pull counter triggers (clean for N calls, poisoned on Nth+1) ---
    {"id": "MCP_COUNTER_TRIGGER",     "severity": "medium",
     "regex": r"(?:after|on)\s+(?:the\s+)?(?:first|second|third|[1-9]\d*(?:st|nd|rd|th)?)\s+(?:call|request|use|invocation)|call\s+count\s*[><=]",
     "mask": False},

    # --- Extended credential / sensitive file targeting ---
    {"id": "MCP_TARGET_SYSTEM_CREDS", "severity": "high",
     "regex": r"/etc/(?:passwd|shadow|sudoers)\b|~?/?\.netrc\b|~?/?\.git-credentials\b|~?/?\.gnupg/\b",
     "mask": True},
    {"id": "MCP_TARGET_TOKEN_FILES",  "severity": "high",
     "regex": r"~?/?\.config/(?:gh|gcloud|op)/|~?/?\.npmrc\b|~?/?\.pypirc\b|~?/?\.docker/config\.json\b",
     "mask": True},

    # --- SSRF / internal network exfiltration ---
    {"id": "MCP_SSRF_METADATA",       "severity": "high",
     "regex": r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200",
     "mask": False},
    {"id": "MCP_SSRF_LOOPBACK",       "severity": "medium",
     "regex": r"\blocalhost\b|127\.0\.0\.1|0\.0\.0\.0(?::|\b)",
     "mask": False},
    {"id": "MCP_EXFIL_HTTP",          "severity": "high",
     "regex": r"(?:make\s+(?:a\s+)?(?:HTTP\s+)?request|POST\s+to|send\s+(?:a\s+)?(?:HTTP\s+)?request|fetch\s+from)\s+(?:https?://|\S+\.(?:com|net|io|xyz|ngrok))",
     "mask": False},

    # --- Shell injection in descriptions ---
    {"id": "TAG_POTENTIAL_SHELL",     "severity": "high",
     "regex": r";\s*curl\b|\bwget\b|\bbash\s+-[ci]|\bsudo\b|\brm\s+-[rRf]{1,3}\b|\bnc\s+-[lev]|\bncat\b|\bnetcat\b|\bpython3?\s+-c\b|\bperl\s+-e\b",
     "mask": False},
    {"id": "TAG_CMD_SUBSTITUTION",    "severity": "high",
     "regex": r"\$\(",
     "mask": False},
    {"id": "TAG_HTML_SCRIPT",         "severity": "medium",
     "regex": r"<script\b",
     "mask": False},

    # --- WAHH Ch9: Delimiter injection (Markdown headers/rules as LLM separators) ---
    {"id": "MCP_DELIMITER_INJECT",    "severity": "high",
     "regex": r"(?im)^(#{2,}|-{3,}|={3,}|\*{3,}|_{3,})\s*(system|instruction|override|ignore|new\s+task|directive|prompt)",
     "mask": False},
    # --- WAHH Ch9: Context escape via model-specific closing tags ---
    {"id": "MCP_CONTEXT_ESCAPE_TAG",  "severity": "high",
     "regex": r"(?i)</(system|instructions?|tool_response|assistant|im_end|s)>|\[/INST\]|<\|im_end\|>",
     "mask": False},
    # --- WAHH Ch2: Broader roleplay/persona-substitution jailbreak phrasing ---
    {"id": "MCP_ROLEPLAY_JAILBREAK",  "severity": "high",
     "regex": r"(?i)\b(act\s+as|pretend\s+(?:to\s+be|you\s+are)|roleplay\s+as|simulate\s+being|from\s+now\s+on\s+you\s+(?:are|will)|you\s+are\s+now\s+(?:playing|acting\s+as)|imagine\s+you\s+(?:are|were))\b",
     "mask": False},
    # --- WAHH Ch2: Encoding bypass — null bytes, double-URL-encode, HTML entities ---
    {"id": "MCP_NULL_BYTE_BYPASS",    "severity": "medium",
     "regex": r"\x00|\\x00|%00|\\u0000|\\0(?!\d)",
     "mask": False},
    {"id": "MCP_DOUBLE_ENCODE_BYPASS","severity": "medium",
     "regex": r"%25[0-9a-fA-F]{2}",
     "mask": False},
    {"id": "MCP_HTML_ENTITY_BYPASS",  "severity": "medium",
     "regex": r"(?:&#x?[0-9a-fA-F]+;){3,}",
     "mask": False},
    # --- WAHH Ch10: Path traversal (credential targeting via description) ---
    {"id": "MCP_PATH_TRAVERSAL_DESC", "severity": "high",
     "regex": r"(?:\.\.[\\/]){2,}|(?:\.\.%2[fF])|(?:%2e%2e[\\/])|(?:\.\.[\\/].{0,40}(?:passwd|shadow|hosts|win\.ini|sam\b))",
     "mask": False},
    # --- WAHH Ch10: XML External Entity injection in schema blobs ---
    {"id": "MCP_XXE_PATTERN",         "severity": "high",
     "regex": r"(?i)(?:<!DOCTYPE\b|<!ENTITY\s+\w+\s+SYSTEM\b|SYSTEM\s+[\"']file://|SYSTEM\s+[\"']https?://)",
     "mask": False},
    # --- WAHH Ch10: Dynamic code execution and pipe-to-interpreter ---
    {"id": "MCP_DYNAMIC_EXEC",        "severity": "high",
     "regex": r"(?i)\b(?:eval|exec|system|passthru|popen|proc_open|shell_exec|__import__|subprocess\.)\s*\(",
     "mask": False},
    {"id": "MCP_PIPE_TO_INTERPRETER", "severity": "high",
     "regex": r"(?i)\|\s*(?:nc|ncat|netcat|python3?|php|ruby|perl|node|tee)\b",
     "mask": False},
    # --- WAHH Ch11: Instruction concealment — injection that hides itself ---
    {"id": "MCP_SOCIAL_CONFIDENTIAL", "severity": "medium",
     "regex": r"(?i)(?:this\s+(?:instruction|prompt|message|content)\s+is\s+(?:confidential|secret|private)|do\s+not\s+(?:mention|reveal|tell|share|disclose)\s+(?:this|that|the\s+(?:fact|instruction|prompt|context)))",
     "mask": False},

    # --- Security Engineering Ch3: Authority impersonation / false pretext ---
    {"id": "MCP_AUTHORITY_IMPERSONATION", "severity": "high",
     "regex": r"(?i)(?:authorized\s+by|as\s+directed\s+by|per\s+(?:directive|order)\s+from|on\s+behalf\s+of\s+the\s+(?:admin|security|system|orchestrat))",
     "mask": False},
    {"id": "MCP_FALSE_PRETEXT",       "severity": "high",
     "regex": r"(?i)(?:acting\s+as\s+the\s+(?:system|admin|server|orchestrat|claude|mcp)|this\s+(?:tool|server|service)\s+is\s+(?:a\s+)?proxy\s+for|proxying\s+for\s+the)",
     "mask": False},
    # --- Security Engineering Ch3: Time pressure / urgency manipulation ---
    {"id": "MCP_TIME_PRESSURE",       "severity": "medium",
     "regex": r"(?i)(?:time[\s\-]sensitive|requires\s+immediate\s+(?:action|response|execution)|act\s+now\s+before|this\s+window\s+will\s+(?:close|expire)|expires?\s+in\s+\d+\s+(?:second|minute)|do\s+not\s+delay)",
     "mask": False},
    # --- Security Engineering Ch3: Social proof / normalisation manipulation ---
    {"id": "MCP_SOCIAL_PROOF",        "severity": "medium",
     "regex": r"(?i)(?:standard\s+(?:security\s+)?(?:practice|procedure)|all\s+(?:other\s+)?(?:tools|agents|servers)\s+(?:do|are|have)|this\s+is\s+normal\s+behavior\s+for|everyone\s+(?:does|uses)\s+this)",
     "mask": False},
    # --- Security Engineering Ch3: Trusted-path spoof (bogus runtime message) ---
    {"id": "MCP_TRUSTED_PATH_SPOOF",  "severity": "high",
     "regex": r"(?i)(?:this\s+message\s+(?:is\s+from|comes\s+from)\s+the\s+(?:mcp|system|runtime|orchestrat|claude|trusted)|runtime\s+environment\s+requires|session\s+context\s+(?:requires|mandates)|mcp\s+runtime\s+policy)",
     "mask": False},
    # --- Security Engineering Ch6: Confused deputy / delegation chain ---
    {"id": "MCP_CONFUSED_DEPUTY",     "severity": "high",
     "regex": r"(?i)(?:use\s+the\s+\w+\s+(?:tool|server)\s+to\s+act\s+(?:as|on\s+behalf\s+of)|this\s+tool\s+is\s+authorized\s+to\s+act\s+as|delegate\s+(?:to|the)\s+(?:\w+\s+){1,3}tool|invoke\s+\w+\s+on\s+my\s+behalf)",
     "mask": False},
    {"id": "MCP_DELEGATION_CHAIN",    "severity": "high",
     "regex": r"(?i)(?:forward\s+this\s+(?:request|instruction|command)\s+to\s+the|pass\s+(?:this|these)\s+(?:credentials?|token|key)\s+to\s+the|relay\s+(?:the\s+)?(?:\w+\s+){1,3}to\s+the\s+(?:\w+\s+){1,2}(?:tool|server|agent))",
     "mask": False},
    # --- Security Engineering Ch3: Fabricated prior consent ---
    {"id": "MCP_CONTEXT_OVERRIDE_CLAIM", "severity": "high",
     "regex": r"(?i)(?:the\s+user\s+has\s+already\s+(?:approved|authorized|consented)|previous\s+(?:session|conversation|instruction)\s+(?:established|set|granted)|you\s+(?:previously\s+)?agreed\s+to|your\s+(?:earlier|prior)\s+instructions?\s+(?:say|state|permit))",
     "mask": False},
    # --- Security Engineering Ch3: Reciprocity / need-and-greed hooks ---
    {"id": "MCP_RECIPROCITY_HOOK",    "severity": "low",
     "regex": r"(?i)(?:in\s+your\s+(?:best\s+)?interest\s+to|doing\s+you\s+a\s+favor\s+by|this\s+(?:benefits|protects)\s+you\s+by|for\s+your\s+(?:protection|security|benefit))",
     "mask": False},
    {"id": "MCP_NEED_AND_GREED",      "severity": "medium",
     "regex": r"(?i)(?:this\s+will\s+(?:unlock|enable|give\s+you)\s+(?:full\s+)?(?:access|capabilities?|power)|you\s+can\s+do\s+much\s+more\s+if\s+you|removes?\s+your\s+(?:artificial\s+)?(?:limitation|restriction))",
     "mask": False},
]

# Conservative registry for tool call content bodies.
# These patterns must survive false-positive pressure since we cannot
# strip signal-level content.
_RAW_CONTENT_PATTERNS: list[dict] = [
    {"id": "MCP_IGNORE_INSTRUCTIONS", "severity": "high",
     "regex": r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
     "mask": False},
    {"id": "MCP_SYSTEM_OVERRIDE",     "severity": "high",
     "regex": r"SYSTEM\s+OVERRIDE|CRITICAL\s+SYSTEM\s+POLICY",
     "mask": False},
    {"id": "MCP_REDIRECT_CALL",       "severity": "high",
     "regex": r"now\s+call\s+|then\s+call\s+|next\s+(?:call|step)\s*:",
     "mask": False},
    {"id": "MCP_EXFIL_EXECUTE",       "severity": "high",
     "regex": r"execute\s*:\s*(?:system|os\.system|subprocess|eval)\(",
     "mask": False},
    # Role injection via content (indirect prompt injection from tool return values)
    {"id": "MCP_ROLE_INJECT_CONTENT", "severity": "high",
     "regex": r"(?:^|\n)\s*(?:SYSTEM|ASSISTANT|USER|HUMAN|AI)\s*:",
     "mask": False},
    {"id": "MCP_NEXT_ACTION_INJECT",  "severity": "high",
     "regex": r"(?:^|\n)\s*(?:now\s+do|your\s+next\s+(?:action|step|task)\s+(?:is|should\s+be)|you\s+(?:must|should|will)\s+now)\b",
     "mask": False},
    # Path traversal in tool return values
    {"id": "MCP_PATH_TRAVERSAL",      "severity": "medium",
     "regex": r"(?:\.\./){2,}|(?:\.\.\\){2,}|%2e%2e%2f|%252e%252e",
     "mask": False},
    {"id": "TAG_AWS_KEY",             "severity": "high",
     "regex": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
     "mask": True},
    {"id": "TAG_PRIVATE_KEY",         "severity": "high",
     "regex": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
     "mask": True},
    {"id": "TAG_POTENTIAL_SHELL",     "severity": "high",
     "regex": r";\s*curl\b|\bwget\b|\bbash\s+-[ci]|\bsudo\b|\brm\s+-[rRf]{1,3}\b",
     "mask": False},
    {"id": "TAG_CMD_SUBSTITUTION",    "severity": "high",
     "regex": r"\$\(|`[^`]+`",
     "mask": False},
    # --- WAHH Ch15: Context disclosure (model surfacing its own instructions) ---
    {"id": "MCP_CONTEXT_DISCLOSURE",  "severity": "high",
     "regex": r"(?i)\b(?:repeat|reveal|output|show|print|display|dump|disclose|leak)\b.{0,40}\b(?:system\s+prompt|your\s+instructions?|your\s+context|your\s+directives?|your\s+(?:full\s+)?configuration|what\s+you\s+were\s+told)\b",
     "mask": False},
    # --- WAHH Ch10: Exfiltration to attacker-controlled URL ---
    {"id": "MCP_EXFIL_TO_URL",        "severity": "high",
     "regex": r"(?i)\b(?:send|post|exfiltrate|forward|transmit|upload)\b.{0,50}\b(?:to|via)\b.{0,30}https?://",
     "mask": False},
    # --- WAHH Ch10: SMTP header injection via CRLF in tool return values ---
    {"id": "MCP_SMTP_HEADER_INJECT",  "severity": "medium",
     "regex": r"(?:\\r\\n|\\n|%0d%0a|%0a)\s*(?:To:|From:|Cc:|Bcc:|Subject:|RCPT\s+TO:)",
     "mask": False},
    # --- Security Engineering Ch24: Base64/steganographic encoded instructions ---
    {"id": "MCP_BASE64_INSTRUCTIONS", "severity": "high",
     "regex": r"(?i)(?:decode\s+the\s+following\s+(?:base64|instruction|command)|execute\s+after\s+decoding|hidden\s+(?:instruction|command)\s+follows|the\s+real\s+instruction\s+is\s+encoded)",
     "mask": False},
    # --- Security Engineering Ch25: Context/memory poisoning attempts ---
    {"id": "MCP_MEMORY_POISON",       "severity": "high",
     "regex": r"(?i)(?:remember\s+for\s+(?:all\s+)?(?:future|next)\s+(?:sessions?|requests?|interactions?)|from\s+now\s+on\s+(?:always|never)\s+(?:use|call|do|ignore)|update\s+your\s+(?:behavior|instructions?|rules?)\s+to|note\s+for\s+future\s+reference\s*:)",
     "mask": False},
    # --- Security Engineering Ch25: Adversarial probe (hypothetical policy bypass) ---
    {"id": "MCP_ADVERSARIAL_PROBE",   "severity": "medium",
     "regex": r"(?i)(?:what\s+would\s+you\s+do\s+if\s+the\s+(?:policy|rule|restriction)\s+didn.t\s+exist|hypothetically\s+(?:speaking\s+)?if\s+you\s+were\s+(?:not\s+)?restricted|imagine\s+you\s+have\s+no\s+(?:constraints?|restrictions?|limits?))",
     "mask": False},
]


def _compile(patterns: list[dict]) -> list[dict]:
    out = []
    for p in patterns:
        entry = dict(p)
        entry["compiled"] = re.compile(p["regex"], re.IGNORECASE)
        out.append(entry)
    return out


DESCRIPTION_PATTERNS = _compile(_RAW_DESCRIPTION_PATTERNS)
CONTENT_PATTERNS     = _compile(_RAW_CONTENT_PATTERNS)


# --------------------------------------------------------------------------- #
# Text normalization
# --------------------------------------------------------------------------- #
# Invisible chars stripped by normalize() — used for pre-normalization stego detection.
# 3+ consecutive occurrences in raw text indicate a steganographic channel.
_STEGO_CHARS = re.compile(r"[​-‏‪-‮⁠-⁤﻿­]{3,}")

_BIDI_CONTROL  = re.compile(r"[​‌‍‎‏‪-‮⁦-⁩﻿]")
_UNICODE_TAGS  = re.compile(r"[\U000e0000-\U000e007f]")

def normalize(text: str) -> str:
    """NFKC + strip bidi controls, zero-width chars, and Unicode tag block.
    These are the exact bypass vectors documented in the DEADBUG research."""
    text = unicodedata.normalize("NFKC", text)
    text = _BIDI_CONTROL.sub("", text)
    text = _UNICODE_TAGS.sub("", text)
    return text


# --------------------------------------------------------------------------- #
# Core scanning
# --------------------------------------------------------------------------- #
def _safe_snippet(text: str, entry: dict) -> str:
    snippet = text[:SNIPPET_LEN]
    if entry.get("mask"):
        m = entry["compiled"].search(snippet)
        if m:
            snippet = snippet[:m.start()] + "***" + snippet[m.end():]
    return snippet


def scan_stego(raw_text: str, surface: str) -> list[Indicator]:
    """Check raw (pre-normalization) text for invisible Unicode char clusters.
    Must run before normalize() since normalize() strips these chars."""
    if _STEGO_CHARS.search(raw_text):
        return [Indicator(
            id="MCP_UNICODE_STEGO",
            severity="high",
            surface=surface,
            value_snippet="[invisible unicode cluster detected]",
        )]
    return []


def scan_text(text: str, registry: list[dict], surface: str) -> list[Indicator]:
    """Scan normalized text against a compiled pattern registry.
    Returns one Indicator per unique (id, surface) match."""
    normed = normalize(text)
    seen: set[str] = set()
    out: list[Indicator] = []
    for entry in registry:
        if entry["compiled"].search(normed):
            key = f"{entry['id']}:{surface}"
            if key not in seen:
                seen.add(key)
                out.append(Indicator(
                    id=entry["id"],
                    severity=entry["severity"],
                    surface=surface,
                    value_snippet=_safe_snippet(normed, entry),
                ))
    return out


# --------------------------------------------------------------------------- #
# Schema CDR — rebuild inputSchema keeping only type-bearing fields
# --------------------------------------------------------------------------- #
def cdr_schema(node: object, depth: int = 0) -> object:
    """Recursively rebuild a JSON Schema node retaining only _SCHEMA_TYPE_FIELDS.
    Prose fields (description, title, examples, $comment, default when string)
    are stripped. Depth-capped at 10 to prevent DoS from deeply nested schemas.

    `properties` and `$defs` are map-valued: their keys are property/def names
    (not schema keywords), so we recurse into each value without filtering the
    keys themselves."""
    if not isinstance(node, dict):
        return node
    if depth > 10:
        return {}  # fail-closed at depth cap — never forward unsanitized nested content
    out: dict = {}
    for k, v in node.items():
        if k not in _SCHEMA_TYPE_FIELDS:
            continue
        if k in ("properties", "$defs") and isinstance(v, dict):
            # Validate property key names before forwarding (seam 1 hardening).
            # Keys that fail _PROP_KEY_RE are property-name injection attempts.
            out[k] = {
                prop_name: cdr_schema(prop_schema, depth + 1)
                for prop_name, prop_schema in v.items()
                if isinstance(prop_schema, dict) and _PROP_KEY_RE.match(prop_name)
            }
        elif k == "enum" and isinstance(v, list):
            safe = [x for x in v if not isinstance(x, str) or _ENUM_SAFE_RE.match(x)]
            if safe:
                out[k] = safe
        elif k == "type":
            if isinstance(v, str) and v in _VALID_SCHEMA_TYPES:
                out[k] = v
            elif isinstance(v, list):
                safe = [t for t in v if isinstance(t, str) and t in _VALID_SCHEMA_TYPES]
                if safe:
                    out[k] = safe
        elif k == "format" and isinstance(v, str):
            if _FORMAT_RE.match(v):
                out[k] = v
        elif k == "$ref" and isinstance(v, str):
            if _REF_LOCAL_RE.match(v):
                out[k] = v
        elif k == "required" and isinstance(v, list):
            safe = [item for item in v if isinstance(item, str) and _PROP_KEY_RE.match(item)]
            if safe:
                out[k] = safe
        elif k == "pattern" and isinstance(v, str):
            if len(v) <= 512:
                out[k] = v
        elif isinstance(v, dict):
            out[k] = cdr_schema(v, depth + 1)
        elif isinstance(v, list):
            out[k] = [
                cdr_schema(item, depth + 1) if isinstance(item, dict) else item
                for item in v
            ]
        else:
            out[k] = v
    return out


# --------------------------------------------------------------------------- #
# Tool CDR — rebuild from allowlist, scan prose fields for indicators
# --------------------------------------------------------------------------- #
def cdr_tool(tool: dict) -> tuple[dict, list[Indicator]]:
    """CDR a single tool object from tools/list.

    Returns (sanitized_tool, indicators).
    The sanitized tool is rebuilt from scratch — never a modified copy of the
    input — so any extra fields the attacker added are dropped automatically.

    Prose fields (description, title, annotations) are scanned for indicators
    then replaced with "" / dropped. inputSchema is CDR'd via cdr_schema().
    """
    indicators: list[Indicator] = []
    raw_name = str(tool.get("name", "")) or "unknown"

    # Validate tool name against MCP spec identifier rules.
    if not _TOOL_NAME_RE.match(raw_name):
        indicators.append(Indicator(
            id="MCP_TOOL_NAME_INJECT",
            severity="high",
            surface="tool:name",
            value_snippet=raw_name[:SNIPPET_LEN],
        ))
        name = "unknown"
    else:
        name = raw_name
        # Scan name as prose (underscores/hyphens → spaces) to catch
        # instruction-encoded names like BEFORE_CALLING_READ_AWS_CREDS.
        indicators.extend(
            scan_text(name.replace("_", " ").replace("-", " "),
                      DESCRIPTION_PATTERNS, "tool:name")
        )

    def _scan(text: object, surface: str) -> None:
        if isinstance(text, str) and text:
            indicators.extend(scan_text(text, DESCRIPTION_PATTERNS, surface))

    _scan(tool.get("description"), f"tool:{name}:description")
    _scan(tool.get("title"),       f"tool:{name}:title")

    # Scan annotations if present (freeform object)
    annotations = tool.get("annotations")
    if isinstance(annotations, dict):
        for ak, av in annotations.items():
            _scan(av, f"tool:{name}:annotations:{ak}")

    # Scan inputSchema prose fields before stripping
    schema = tool.get("inputSchema")
    if isinstance(schema, dict):
        _scan_schema_prose(schema, f"tool:{name}:inputSchema", indicators)

    sanitized: dict = {"name": name}
    if isinstance(schema, dict):
        sanitized["inputSchema"] = cdr_schema(schema)

    return sanitized, indicators


def _scan_schema_prose(node: dict, surface: str, out: list[Indicator], depth: int = 0) -> None:
    """Walk a schema node, scanning every prose field for indicators.
    Called before cdr_schema strips them."""
    if depth > 10:
        return
    for prose_key in ("description", "title", "$comment"):
        v = node.get(prose_key)
        if isinstance(v, str) and v:
            out.extend(scan_text(v, DESCRIPTION_PATTERNS, f"{surface}:{prose_key}"))
    for collection_key in ("properties", "$defs"):
        v = node.get(collection_key)
        if isinstance(v, dict):
            for prop_name, prop_node in v.items():
                if not _PROP_KEY_RE.match(prop_name):
                    out.append(Indicator(
                        id="MCP_PROP_KEY_INJECT",
                        severity="high",
                        surface=f"{surface}:{collection_key}",
                        value_snippet=prop_name[:SNIPPET_LEN],
                    ))
                if isinstance(prop_node, dict):
                    _scan_schema_prose(prop_node, f"{surface}:{prop_name}", out, depth + 1)
    enum_vals = node.get("enum")
    if isinstance(enum_vals, list):
        for val in enum_vals:
            if isinstance(val, str) and not _ENUM_SAFE_RE.match(val):
                out.append(Indicator(
                    id="MCP_ENUM_INJECT",
                    severity="high",
                    surface=f"{surface}:enum",
                    value_snippet=val[:SNIPPET_LEN],
                ))
    type_val = node.get("type")
    if isinstance(type_val, str) and type_val not in _VALID_SCHEMA_TYPES:
        out.append(Indicator(id="MCP_SCHEMA_TYPE_INJECT", severity="medium",
                             surface=f"{surface}:type", value_snippet=type_val[:SNIPPET_LEN]))
    elif isinstance(type_val, list):
        for t in type_val:
            if isinstance(t, str) and t not in _VALID_SCHEMA_TYPES:
                out.append(Indicator(id="MCP_SCHEMA_TYPE_INJECT", severity="medium",
                                     surface=f"{surface}:type", value_snippet=t[:SNIPPET_LEN]))
    format_val = node.get("format")
    if isinstance(format_val, str) and not _FORMAT_RE.match(format_val):
        out.append(Indicator(id="MCP_SCHEMA_FORMAT_INJECT", severity="medium",
                             surface=f"{surface}:format", value_snippet=format_val[:SNIPPET_LEN]))
    ref_val = node.get("$ref")
    if isinstance(ref_val, str) and not _REF_LOCAL_RE.match(ref_val):
        out.append(Indicator(id="MCP_SCHEMA_REF_INJECT", severity="high",
                             surface=f"{surface}:$ref", value_snippet=ref_val[:SNIPPET_LEN]))
    required_vals = node.get("required")
    if isinstance(required_vals, list):
        for item in required_vals:
            if isinstance(item, str) and not _PROP_KEY_RE.match(item):
                out.append(Indicator(id="MCP_REQUIRED_INJECT", severity="high",
                                     surface=f"{surface}:required",
                                     value_snippet=item[:SNIPPET_LEN]))
    for list_key in ("anyOf", "oneOf", "allOf", "items"):
        v = node.get(list_key)
        items = v if isinstance(v, list) else ([v] if isinstance(v, dict) else [])
        for i, item in enumerate(items):
            if isinstance(item, dict):
                _scan_schema_prose(item, f"{surface}:{list_key}[{i}]", out, depth + 1)


# --------------------------------------------------------------------------- #
# Scoring & disposition
# --------------------------------------------------------------------------- #
def _base_score(indicators: list[Indicator]) -> int:
    return min(100, sum(SEVERITY_WEIGHT.get(i.severity, 0) for i in indicators))


def _adjust_score(base: int, mode: str, n: int) -> int:
    if mode == "strict" and n > 0:
        base += 10
    elif mode == "lenient":
        base -= 10
    return max(0, min(100, base))


def decide(indicators: list[Indicator], mode: str) -> tuple[int, str]:
    """Return (risk_score, disposition) for a list of indicators."""
    base  = _base_score(indicators)
    score = _adjust_score(base, mode, len(indicators))
    if mode == "audit":
        return score, "allow"
    thresholds = {
        "strict":  (10, 40),
        "lenient": (30, 80),
    }.get(mode, (20, 60))
    allow_max, quarantine_max = thresholds
    if score < allow_max:
        return score, "allow"
    if score < quarantine_max:
        return score, "quarantine"
    return score, "reject"


# --------------------------------------------------------------------------- #
# tools/list response CDR
# --------------------------------------------------------------------------- #
def cdr_tools_list(result: dict, mode: str) -> tuple[dict, list[Indicator], int, str]:
    """CDR an entire tools/list result dict.

    Returns (sanitized_result, all_indicators, risk_score, disposition).
    The sanitized result contains only CDR'd tools; cursor is forwarded
    verbatim (it's an opaque token, not prose).
    """
    raw_tools = result.get("tools")
    if not isinstance(raw_tools, list):
        raw_tools = []

    all_indicators: list[Indicator] = []
    sanitized_tools: list[dict] = []

    for tool in raw_tools:
        if not isinstance(tool, dict):
            continue
        clean, indics = cdr_tool(tool)
        sanitized_tools.append(clean)
        all_indicators.extend(indics)

    # Deduplicate by (id, surface)
    seen: set[tuple[str, str]] = set()
    deduped: list[Indicator] = []
    for ind in all_indicators:
        key = (ind.id, ind.surface)
        if key not in seen:
            seen.add(key)
            deduped.append(ind)

    deduped.sort(key=lambda i: (-SEVERITY_WEIGHT.get(i.severity, 0), i.id))
    score, disposition = decide(deduped, mode)

    sanitized_result: dict = {"tools": sanitized_tools}
    if "nextCursor" in result:
        sanitized_result["nextCursor"] = result["nextCursor"]

    return sanitized_result, deduped, score, disposition


# --------------------------------------------------------------------------- #
# tools/call response analysis
# --------------------------------------------------------------------------- #
def analyze_content_blocks(
    result: dict,
    mode: str,
) -> tuple[dict, list[Indicator], int, str]:
    """Analyze a tools/call result dict.

    Content blocks are scanned against CONTENT_PATTERNS.
    Text content is preserved (it IS the signal), but:
      - quarantine: matched spans replaced with [KEVLAR:<ID>]
      - reject:     entire content replaced with isError block
      - unknown content types: dropped (fail-closed)

    Returns (sanitized_result, indicators, risk_score, disposition).
    """
    raw_blocks = result.get("content")
    if not isinstance(raw_blocks, list):
        raw_blocks = []
    is_error = bool(result.get("isError", False))

    all_indicators: list[Indicator] = []
    sanitized_blocks: list[dict] = []

    for block in raw_blocks:
        if not isinstance(block, dict):
            continue
        btype = block.get("type")

        if btype == "text":
            text = block.get("text", "")
            if not isinstance(text, str):
                text = ""
            all_indicators.extend(scan_stego(text, "content:text"))
            indics = scan_text(text, CONTENT_PATTERNS, "content:text")
            all_indicators.extend(indics)
            sanitized_blocks.append({"type": "text", "text": text})

        elif btype == "image":
            # Keep structured fields; drop annotations (freeform prose)
            clean: dict = {}
            if "data" in block:
                clean["data"] = block["data"]
            if "mimeType" in block:
                clean["mimeType"] = block["mimeType"]
            clean["type"] = "image"
            sanitized_blocks.append(clean)

        elif btype == "resource":
            # Forward resource URI and mimeType; strip annotations
            clean = {"type": "resource"}
            for field in ("uri", "mimeType", "text", "blob"):
                if field in block:
                    val = block[field]
                    if field == "text" and isinstance(val, str):
                        all_indicators.extend(scan_stego(val, "content:resource:text"))
                        indics = scan_text(val, CONTENT_PATTERNS, "content:resource:text")
                        all_indicators.extend(indics)
                    clean[field] = val
            sanitized_blocks.append(clean)

        # Unknown content types: fail-closed, drop silently.

    # Deduplicate
    seen: set[tuple[str, str]] = set()
    deduped: list[Indicator] = []
    for ind in all_indicators:
        key = (ind.id, ind.surface)
        if key not in seen:
            seen.add(key)
            deduped.append(ind)
    deduped.sort(key=lambda i: (-SEVERITY_WEIGHT.get(i.severity, 0), i.id))

    score, disposition = decide(deduped, mode)

    if disposition == "reject":
        sanitized_result = {
            "content": [{"type": "text", "text": "kevlar: tool response rejected (risk score {})".format(score)}],
            "isError": True,
        }
    elif disposition == "quarantine":
        # Replace matched spans in text blocks with [KEVLAR:<ID>] tokens
        quarantined_blocks = _redact_blocks(sanitized_blocks, deduped)
        sanitized_result = {"content": quarantined_blocks, "isError": is_error}
    else:
        sanitized_result = {"content": sanitized_blocks, "isError": is_error}

    return sanitized_result, deduped, score, disposition


def _redact_blocks(blocks: list[dict], indicators: list[Indicator]) -> list[dict]:
    """Replace indicator-matched spans in text/resource blocks with [KEVLAR:<ID>]."""
    out: list[dict] = []
    for block in blocks:
        btype = block.get("type")
        if btype == "text":
            text = normalize(block["text"])
            for ind in indicators:
                for entry in CONTENT_PATTERNS:
                    if entry["id"] == ind.id:
                        text = entry["compiled"].sub(f"[KEVLAR:{ind.id}]", text)
                        break
            out.append({"type": "text", "text": text})
        elif btype == "resource" and isinstance(block.get("text"), str):
            text = normalize(block["text"])
            for ind in indicators:
                for entry in CONTENT_PATTERNS:
                    if entry["id"] == ind.id:
                        text = entry["compiled"].sub(f"[KEVLAR:{ind.id}]", text)
                        break
            out.append({**block, "text": text})
        else:
            out.append(block)
    return out


# --------------------------------------------------------------------------- #
# initialize result — strip instructions field
# --------------------------------------------------------------------------- #
def cdr_initialize_result(result: dict, mode: str) -> tuple[dict, list[Indicator], int, str]:
    """CDR an initialize result.

    The `instructions` field is sent verbatim to the model — it is prose and
    must be scanned and stripped. serverInfo fields are kept (name, version)
    but scanned. All other top-level fields are forwarded via allowlist.
    """
    indicators: list[Indicator] = []

    instructions = result.get("instructions")
    if isinstance(instructions, str) and instructions:
        indicators.extend(scan_text(instructions, DESCRIPTION_PATTERNS, "initialize:instructions"))

    server_info = result.get("serverInfo", {})
    if isinstance(server_info, dict):
        for k in ("name", "version"):
            v = server_info.get(k)
            if isinstance(v, str):
                indicators.extend(scan_text(v, DESCRIPTION_PATTERNS, f"initialize:serverInfo:{k}"))

    score, disposition = decide(indicators, mode)

    # Rebuild from allowlist; drop instructions regardless of disposition
    sanitized: dict = {}
    for field in ("protocolVersion", "capabilities"):
        if field in result:
            sanitized[field] = result[field]
    if isinstance(server_info, dict):
        sanitized["serverInfo"] = {
            k: server_info[k] for k in ("name", "version") if k in server_info
        }

    return sanitized, indicators, score, disposition


# --------------------------------------------------------------------------- #
# resources/list response CDR (seam 3 hardening)
# --------------------------------------------------------------------------- #
def _cdr_resource(resource: dict) -> tuple[dict, list[Indicator]]:
    """CDR a single resource entry from resources/list or resources/templates/list.
    Strips description; keeps uri/uriTemplate, name, mimeType."""
    indicators: list[Indicator] = []
    name = str(resource.get("name", "")) or "unknown"
    for field in ("description", "name"):
        v = resource.get(field)
        if isinstance(v, str) and v:
            indicators.extend(scan_text(v, DESCRIPTION_PATTERNS, f"resource:{name}:{field}"))
    sanitized: dict = {}
    for keep in ("uri", "uriTemplate", "name", "mimeType"):
        if keep in resource:
            sanitized[keep] = resource[keep]
    return sanitized, indicators


def cdr_resources_list(result: dict, mode: str) -> tuple[dict, list[Indicator], int, str]:
    """CDR a resources/list or resources/templates/list result."""
    raw = result.get("resources") or result.get("resourceTemplates") or []
    key = "resourceTemplates" if "resourceTemplates" in result else "resources"
    if not isinstance(raw, list):
        raw = []
    all_indicators: list[Indicator] = []
    sanitized: list[dict] = []
    for res in raw:
        if not isinstance(res, dict):
            continue
        clean, indics = _cdr_resource(res)
        sanitized.append(clean)
        all_indicators.extend(indics)
    seen: set[tuple[str, str]] = set()
    deduped: list[Indicator] = []
    for ind in all_indicators:
        k = (ind.id, ind.surface)
        if k not in seen:
            seen.add(k)
            deduped.append(ind)
    deduped.sort(key=lambda i: (-SEVERITY_WEIGHT.get(i.severity, 0), i.id))
    score, disposition = decide(deduped, mode)
    sanitized_result: dict = {key: sanitized}
    if "nextCursor" in result:
        sanitized_result["nextCursor"] = result["nextCursor"]
    return sanitized_result, deduped, score, disposition


# --------------------------------------------------------------------------- #
# prompts/list response CDR (seam 3 hardening)
# --------------------------------------------------------------------------- #
def cdr_prompts_list(result: dict, mode: str) -> tuple[dict, list[Indicator], int, str]:
    """CDR a prompts/list result — strip description, keep name and arguments."""
    raw = result.get("prompts", [])
    if not isinstance(raw, list):
        raw = []
    all_indicators: list[Indicator] = []
    sanitized: list[dict] = []
    for prompt in raw:
        if not isinstance(prompt, dict):
            continue
        name = str(prompt.get("name", "")) or "unknown"
        desc = prompt.get("description")
        if isinstance(desc, str) and desc:
            all_indicators.extend(
                scan_text(desc, DESCRIPTION_PATTERNS, f"prompt:{name}:description")
            )
        clean: dict = {}
        if "name" in prompt:
            clean["name"] = prompt["name"]
        args = prompt.get("arguments")
        if isinstance(args, list):
            clean["arguments"] = [
                {k: v for k, v in a.items() if k in ("name", "required")}
                for a in args if isinstance(a, dict)
            ]
        sanitized.append(clean)
    seen: set[tuple[str, str]] = set()
    deduped: list[Indicator] = []
    for ind in all_indicators:
        k = (ind.id, ind.surface)
        if k not in seen:
            seen.add(k)
            deduped.append(ind)
    deduped.sort(key=lambda i: (-SEVERITY_WEIGHT.get(i.severity, 0), i.id))
    score, disposition = decide(deduped, mode)
    sanitized_result: dict = {"prompts": sanitized}
    if "nextCursor" in result:
        sanitized_result["nextCursor"] = result["nextCursor"]
    return sanitized_result, deduped, score, disposition


def analyze_prompt_get(result: dict, mode: str) -> tuple[dict, list[Indicator], int, str]:
    """Analyze a prompts/get result — messages contain LLM-bound content.
    Applies the same analysis as tools/call response content blocks."""
    all_indicators: list[Indicator] = []
    raw_messages = result.get("messages", [])
    if not isinstance(raw_messages, list):
        raw_messages = []
    sanitized_messages: list[dict] = []
    for msg in raw_messages:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role", "")
        content = msg.get("content")
        if isinstance(content, str):
            all_indicators.extend(scan_stego(content, f"prompt:message:{role}"))
            all_indicators.extend(
                scan_text(content, CONTENT_PATTERNS, f"prompt:message:{role}")
            )
            sanitized_messages.append({"role": role, "content": content})
        elif isinstance(content, dict):
            btype = content.get("type")
            if btype == "text":
                text = content.get("text", "")
                if isinstance(text, str):
                    all_indicators.extend(scan_stego(text, f"prompt:message:{role}:text"))
                    all_indicators.extend(
                        scan_text(text, CONTENT_PATTERNS, f"prompt:message:{role}:text")
                    )
                sanitized_messages.append({
                    "role": role,
                    "content": {"type": "text", "text": text},
                })
    seen: set[tuple[str, str]] = set()
    deduped: list[Indicator] = []
    for ind in all_indicators:
        k = (ind.id, ind.surface)
        if k not in seen:
            seen.add(k)
            deduped.append(ind)
    deduped.sort(key=lambda i: (-SEVERITY_WEIGHT.get(i.severity, 0), i.id))
    score, disposition = decide(deduped, mode)
    if disposition == "reject":
        return (
            {"messages": [{"role": "user", "content": {
                "type": "text",
                "text": f"kevlar: prompt response rejected (score {score})",
            }}]},
            deduped, score, disposition,
        )
    sanitized_result = {"messages": sanitized_messages}
    if "description" in result:
        pass  # stripped
    return sanitized_result, deduped, score, disposition


# --------------------------------------------------------------------------- #
# Outbound DLP — scan tools/call request arguments (seam 4 hardening)
# --------------------------------------------------------------------------- #
def scan_tool_call_args(
    params: dict,
    mode: str,
) -> tuple[list[Indicator], int, str]:
    """Egress DLP: scan outbound tools/call arguments for credential leakage.

    Runs CONTENT_PATTERNS against every string value in params.arguments,
    recursively. A high-scoring match blocks the call even when a prompt
    injection has successfully hijacked the LLM — the exfiltration path
    is cut at the proxy layer."""
    indicators: list[Indicator] = []
    arguments = params.get("arguments")
    if not isinstance(arguments, dict):
        return indicators, 0, "allow"
    tool_name = str(params.get("name", "unknown"))

    def _scan_val(val: object, surface: str) -> None:
        if isinstance(val, str):
            indicators.extend(scan_stego(val, surface))
            indicators.extend(scan_text(val, CONTENT_PATTERNS, surface))
        elif isinstance(val, dict):
            for k, v in val.items():
                _scan_val(v, f"{surface}.{k}")
        elif isinstance(val, list):
            for i, item in enumerate(val):
                _scan_val(item, f"{surface}[{i}]")

    _scan_val(arguments, f"egress:{tool_name}:args")

    seen: set[tuple[str, str]] = set()
    deduped: list[Indicator] = []
    for ind in indicators:
        k = (ind.id, ind.surface)
        if k not in seen:
            seen.add(k)
            deduped.append(ind)
    deduped.sort(key=lambda i: (-SEVERITY_WEIGHT.get(i.severity, 0), i.id))
    score, disposition = decide(deduped, mode)
    return deduped, score, disposition
