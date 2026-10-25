"""
schemas.py — Pydantic output models for LLM analyst node I/O contracts.

Every AgentLoop.run() call must produce one AnalysisOutput.  Pydantic
validation runs at the analysis boundary so invalid model output raises
an error rather than silently writing a zero-confidence row to func_id_db.

Usage:
    from .schemas import parse_analysis_output, AnalysisOutput
    output = parse_analysis_output(model_text)   # raises on bad JSON/schema
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator


class AnalysisOutput(BaseModel):
    """
    Schema enforced on every LLM analysis response.

    Maps directly to AnalysisResult (the public return type) — fields are
    identical by design so _build_result can unpack via model_dump().
    """

    name:       str   = Field(default='unknown', description='Snake_case function name')
    role:       str   = Field(default='UNKNOWN')
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    rationale:  str   = Field(default='')
    vuln_notes: str   = Field(default='')

    @field_validator('confidence', mode='before')
    @classmethod
    def coerce_confidence(cls, v):
        try:
            # Clamp to [0.0, 1.0] so LLM outputs like 1.1 don't raise
            return max(0.0, min(1.0, float(v)))
        except (TypeError, ValueError):
            return 0.0

    @field_validator('name', mode='before')
    @classmethod
    def non_empty_name(cls, v):
        s = str(v).strip() if v else ''
        return s or 'unknown'

    @field_validator('role', mode='before')
    @classmethod
    def upper_role(cls, v):
        s = str(v).strip().upper() if v else ''
        return s or 'UNKNOWN'


def parse_analysis_output(text: str) -> AnalysisOutput:
    """
    Extract an AnalysisOutput from a model text response.

    Strips markdown code fences, finds the first JSON object, and validates
    against AnalysisOutput.  Raises ValueError if no JSON object is found;
    raises pydantic.ValidationError if the object does not match the schema.
    """
    cleaned = re.sub(r'^```(?:json)?\s*\n?', '', text, flags=re.MULTILINE)
    cleaned = re.sub(r'\n?```\s*$', '', cleaned, flags=re.MULTILINE)
    match = re.search(r'\{.*\}', cleaned.strip(), re.DOTALL)
    if not match:
        raise ValueError(f'no JSON object in response: {text[:200]}')
    return AnalysisOutput.model_validate_json(match.group())
