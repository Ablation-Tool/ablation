"""
test_llm_analyst.py — Tests for llm_analyst: schemas, FuncDB execution log,
AgentLoop cascade routing, SDK/CLI transport dispatch, KG wiring, and
ContextBuilder epistemic rendering.
"""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from ablation.analyzers.llm_analyst.schemas import AnalysisOutput, parse_analysis_output
from ablation.analyzers.func_id_db import FuncDB


# ── AnalysisOutput schema ─────────────────────────────────────────────────────

class TestAnalysisOutput:
    def test_valid(self):
        o = AnalysisOutput(name='parse_radius_attr', role='RADIUS_ATTR_HANDLER', confidence=0.9,
                           rationale='reads attr type', vuln_notes='')
        assert o.name == 'parse_radius_attr'
        assert o.role == 'RADIUS_ATTR_HANDLER'

    def test_confidence_clamped_high(self):
        o = AnalysisOutput(name='fn', confidence=1.1)
        assert o.confidence == pytest.approx(1.0)

    def test_confidence_clamped_low(self):
        o = AnalysisOutput(name='fn', confidence=-0.5)
        assert o.confidence == pytest.approx(0.0)

    def test_confidence_string_coerced(self):
        o = AnalysisOutput(name='fn', confidence='0.75')
        assert o.confidence == pytest.approx(0.75)

    def test_confidence_garbage_defaults_zero(self):
        o = AnalysisOutput(name='fn', confidence='not_a_number')
        assert o.confidence == 0.0

    def test_role_uppercased(self):
        o = AnalysisOutput(name='fn', role='radius_parser')
        assert o.role == 'RADIUS_PARSER'

    def test_empty_name_becomes_unknown(self):
        o = AnalysisOutput(name='   ')
        assert o.name == 'unknown'

    def test_empty_role_becomes_unknown(self):
        o = AnalysisOutput(name='fn', role='')
        assert o.role == 'UNKNOWN'

    def test_defaults(self):
        o = AnalysisOutput(name='fn')
        assert o.role == 'UNKNOWN'
        assert o.confidence == 0.0
        assert o.rationale == ''
        assert o.vuln_notes == ''


# ── parse_analysis_output ─────────────────────────────────────────────────────

class TestParseAnalysisOutput:
    def test_clean_json(self):
        text = '{"name":"do_auth","role":"AAA_DISPATCH","confidence":0.85,"rationale":"r","vuln_notes":""}'
        o = parse_analysis_output(text)
        assert o.name == 'do_auth'
        assert o.confidence == pytest.approx(0.85)

    def test_strips_markdown_fences(self):
        text = '```json\n{"name":"fn","confidence":0.5}\n```'
        o = parse_analysis_output(text)
        assert o.name == 'fn'

    def test_strips_plain_fences(self):
        text = '```\n{"name":"fn","confidence":0.6}\n```'
        o = parse_analysis_output(text)
        assert o.name == 'fn'

    def test_json_embedded_in_prose(self):
        text = 'Here is my analysis: {"name":"init_tls","confidence":0.7} thanks.'
        o = parse_analysis_output(text)
        assert o.name == 'init_tls'

    def test_no_json_raises(self):
        with pytest.raises(ValueError, match='no JSON object'):
            parse_analysis_output('plain text with no braces')

    def test_out_of_range_confidence_clamped(self):
        # Schema clamps rather than raises — LLM outputs like 2.5 are accepted
        o = parse_analysis_output('{"name":"fn","confidence":2.5}')
        assert o.confidence == pytest.approx(1.0)

    def test_negative_confidence_clamped(self):
        o = parse_analysis_output('{"name":"fn","confidence":-1.0}')
        assert o.confidence == pytest.approx(0.0)

    def test_missing_name_uses_default(self):
        o = parse_analysis_output('{"confidence":0.5}')
        assert o.name == 'unknown'


# ── FuncDB execution_log ──────────────────────────────────────────────────────

@pytest.fixture
def tmp_db(tmp_path):
    return FuncDB(str(tmp_path / 'test.db'))


class TestFuncDBExecutionLog:
    def test_log_and_query(self, tmp_db):
        tmp_db.log_execution(
            task='name_function',
            func_addr=0x1000,
            binary_sha256='abc123',
            model='claude-haiku-4-5',
            input_tokens=800,
            output_tokens=120,
            latency_ms=450,
            finished=True,
            result_name='parse_header',
            result_role='STRUCT_ACCESSOR',
            result_confidence=0.88,
        )
        rows = tmp_db._con.execute('SELECT * FROM execution_log').fetchall()
        assert len(rows) == 1
        r = dict(rows[0])
        assert r['task'] == 'name_function'
        assert r['func_addr'] == 0x1000
        assert r['binary_sha256'] == 'abc123'
        assert r['model'] == 'claude-haiku-4-5'
        assert r['input_tokens'] == 800
        assert r['output_tokens'] == 120
        assert r['latency_ms'] == 450
        assert r['finished'] == 1
        assert r['result_name'] == 'parse_header'
        assert r['result_role'] == 'STRUCT_ACCESSOR'
        assert r['result_confidence'] == pytest.approx(0.88)

    def test_log_multiple(self, tmp_db):
        for i in range(5):
            tmp_db.log_execution(
                task='vuln_hypothesis', func_addr=0x2000 + i,
                binary_sha256='sha', model='claude-sonnet-4-6',
                input_tokens=1000, output_tokens=200, latency_ms=600,
                finished=True, result_name=f'fn_{i}', result_role='UNKNOWN',
                result_confidence=0.5,
            )
        count = tmp_db._con.execute('SELECT COUNT(*) FROM execution_log').fetchone()[0]
        assert count == 5

    def test_finished_false_stored_as_zero(self, tmp_db):
        tmp_db.log_execution(
            task='name_function', func_addr=0x3000, binary_sha256='', model='',
            input_tokens=0, output_tokens=0, latency_ms=0,
            finished=False, result_name='unknown__parse_failed',
            result_role='UNKNOWN', result_confidence=0.0,
        )
        row = dict(tmp_db._con.execute('SELECT finished FROM execution_log').fetchone())
        assert row['finished'] == 0


# ── AgentLoop cascade routing ─────────────────────────────────────────────────

class TestAgentLoopCascadeRouting:
    """Test model selection without making any real API calls."""

    def _make_loop(self, model=None, api_key=None):
        from ablation.analyzers.llm_analyst.agent_loop import AgentLoop
        reg = MagicMock()
        return AgentLoop(reg, model=model, api_key=api_key)

    def test_name_function_uses_haiku(self):
        loop = self._make_loop()
        assert loop._effective_model('name_function') == 'claude-haiku-4-5'

    def test_struct_reconstruct_uses_haiku(self):
        loop = self._make_loop()
        assert loop._effective_model('struct_reconstruct') == 'claude-haiku-4-5'

    def test_vuln_hypothesis_uses_sonnet(self):
        loop = self._make_loop()
        assert loop._effective_model('vuln_hypothesis') == 'claude-sonnet-4-6'

    def test_patch_analysis_uses_sonnet(self):
        loop = self._make_loop()
        assert loop._effective_model('patch_analysis') == 'claude-sonnet-4-6'

    def test_exploit_chain_uses_opus(self):
        loop = self._make_loop()
        assert loop._effective_model('exploit_chain') == 'claude-opus-4-7'

    def test_unknown_task_uses_default(self):
        from ablation.analyzers.llm_analyst.agent_loop import _DEFAULT_TASK_MODEL
        loop = self._make_loop()
        assert loop._effective_model('unknown_task') == _DEFAULT_TASK_MODEL

    def test_explicit_model_overrides_cascade(self):
        loop = self._make_loop(model='claude-opus-4-7')
        assert loop._effective_model('name_function') == 'claude-opus-4-7'

    def test_explicit_model_overrides_all_tasks(self):
        loop = self._make_loop(model='claude-haiku-4-5')
        for task in ('name_function', 'vuln_hypothesis', 'exploit_chain'):
            assert loop._effective_model(task) == 'claude-haiku-4-5'


# ── AgentLoop transport dispatch ──────────────────────────────────────────────

class TestAgentLoopTransport:
    def _make_loop(self, api_key=None):
        from ablation.analyzers.llm_analyst.agent_loop import AgentLoop
        reg = MagicMock()
        reg._get_strings.return_value = '{"strings": []}'
        reg._get_cfg.return_value = ''
        reg._get_disassembly.return_value = 'nop'
        reg._get_imports.return_value = '{"imports": []}'
        return AgentLoop(reg, api_key=api_key)

    def test_uses_sdk_when_api_key_set(self):
        loop = self._make_loop(api_key='sk-ant-test-key')
        assert loop._use_sdk() is True

    def test_uses_cli_when_no_key(self):
        loop = self._make_loop(api_key=None)
        with patch.dict('os.environ', {}, clear=True):
            # ensure ANTHROPIC_API_KEY not in env
            import os
            os.environ.pop('ANTHROPIC_API_KEY', None)
            assert loop._use_sdk() is False

    def test_uses_sdk_when_env_key_set(self):
        loop = self._make_loop(api_key=None)
        with patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'sk-ant-env-key'}):
            assert loop._use_sdk() is True

    def test_run_calls_sdk_and_logs_execution(self, tmp_path):
        """End-to-end: mock SDK call, verify result + execution_log row."""
        from ablation.analyzers.llm_analyst.agent_loop import AgentLoop

        db  = FuncDB(str(tmp_path / 'test.db'))
        reg = MagicMock()
        reg._get_strings.return_value   = '{"strings": ["RADIUS-Access-Request"]}'
        reg._get_cfg.return_value       = ''
        reg._get_disassembly.return_value = '+0000  push rbp'
        reg._get_imports.return_value   = '{"imports": [{"name":"recv","plt":true}]}'

        loop = AgentLoop(reg, func_db=db, binary_sha256='deadbeef', api_key='sk-ant-test')

        canned_response = MagicMock()
        canned_response.content = [MagicMock(text='{"name":"parse_radius","role":"RADIUS_PARSER","confidence":0.9,"rationale":"recv+RADIUS strings","vuln_notes":""}')]
        canned_response.usage.input_tokens  = 500
        canned_response.usage.output_tokens = 80

        with patch.object(loop, '_call_sdk', return_value=('{"name":"parse_radius","role":"RADIUS_PARSER","confidence":0.9,"rationale":"recv+RADIUS strings","vuln_notes":""}', 500, 80)):
            result = loop.run(0x4000, task='name_function')

        assert result.name == 'parse_radius'
        assert result.role == 'RADIUS_PARSER'
        assert result.confidence == pytest.approx(0.9)
        assert result.finished is True
        assert result.model == 'claude-haiku-4-5'

        rows = db._con.execute('SELECT * FROM execution_log').fetchall()
        assert len(rows) == 1
        r = dict(rows[0])
        assert r['task'] == 'name_function'
        assert r['result_name'] == 'parse_radius'
        assert r['input_tokens'] == 500
        assert r['output_tokens'] == 80


# ── ContextBuilder — system prompt + epistemic rendering ─────────────────────

class TestContextBuilder:
    def test_system_prompt_no_react_language(self):
        from ablation.analyzers.llm_analyst.context_builder import ContextBuilder
        cb = ContextBuilder(product='FortiOS', version='7.4')
        p = cb.system_prompt()
        assert 'ReAct' not in p
        assert 'done()' not in p
        assert 'Use tools in a ReAct loop' not in p
        assert 'stopped after' not in p
        assert 'pre-loaded' in p

    def test_system_prompt_appends_kg_context(self):
        from ablation.analyzers.llm_analyst.context_builder import ContextBuilder
        cb = ContextBuilder()
        p = cb.system_prompt(kg_context='Modules: SinkArgClassifier\nGaps: stripped Go')
        assert '[KNOWLEDGE GRAPH' in p
        assert 'SinkArgClassifier' in p
        assert 'stripped Go' in p

    def test_system_prompt_no_kg_section_when_empty(self):
        from ablation.analyzers.llm_analyst.context_builder import ContextBuilder
        cb = ContextBuilder()
        p = cb.system_prompt(kg_context='')
        assert 'KNOWLEDGE GRAPH' not in p

    def test_prior_findings_shows_epistemic(self):
        from ablation.analyzers.llm_analyst.context_builder import ContextBuilder
        cb = ContextBuilder()
        findings = [{
            'name': 'parse_attr', 'role': 'RADIUS_ATTR_HANDLER',
            'confidence': 'CONFIRMED', 'epistemic': 'confirmed',
            'retrieval_source': 'callee_overlap',
            'product': 'CiscoASA', 'version': '9.8', 'notes': '',
        }]
        block = cb._format_prior_findings(findings)
        assert '[confirmed]' in block
        assert 'via:callee_overlap' in block
        assert 'CONFIRMED above CANDIDATE' in block

    def test_prior_findings_candidate_tagged(self):
        from ablation.analyzers.llm_analyst.context_builder import ContextBuilder
        cb = ContextBuilder()
        findings = [{
            'name': 'fn', 'role': 'UNKNOWN',
            'confidence': 'CANDIDATE', 'epistemic': 'candidate',
            'retrieval_source': 'role_match',
            'product': 'X', 'version': '1.0', 'notes': '',
        }]
        block = cb._format_prior_findings(findings)
        assert '[candidate]' in block
        assert 'via:role_match' in block


# ── AgentLoop KnowledgeGraph wiring ──────────────────────────────────────────

class TestAgentLoopKGWiring:
    def _make_loop(self, kg=None, arch='', fmt=''):
        from ablation.analyzers.llm_analyst.agent_loop import AgentLoop
        reg = MagicMock()
        return AgentLoop(reg, knowledge_graph=kg, arch=arch, fmt=fmt)

    def test_no_kg_context_when_no_kg(self):
        loop = self._make_loop()
        assert loop._kg_context == ''

    def test_no_kg_context_when_no_arch(self):
        kg = MagicMock()
        loop = self._make_loop(kg=kg, arch='')
        assert loop._kg_context == ''
        kg.get_context_for_binary.assert_not_called()

    def test_kg_context_fetched_at_init(self):
        kg = MagicMock()
        kg.get_context_for_binary.return_value = 'Modules: TaintTracker\nGaps: stripped Go'
        loop = self._make_loop(kg=kg, arch='x86-64', fmt='elf64')
        assert 'TaintTracker' in loop._kg_context
        kg.get_context_for_binary.assert_called_once_with(
            arch='x86-64', fmt='elf64', intent='sweep'
        )

    def test_kg_exception_produces_empty_context(self):
        kg = MagicMock()
        kg.get_context_for_binary.side_effect = RuntimeError('DB unavailable')
        loop = self._make_loop(kg=kg, arch='ppc32', fmt='xcoff32')
        assert loop._kg_context == ''

    def test_kg_context_injected_into_system_prompt(self):
        """KG context appears in the system prompt sent to the LLM."""
        from ablation.analyzers.llm_analyst.agent_loop import AgentLoop
        from ablation.analyzers.func_id_db import FuncDB
        import tempfile, os

        kg = MagicMock()
        kg.get_context_for_binary.return_value = 'Modules: SinkArgClassifier\nArch: x86-64'

        reg = MagicMock()
        reg._get_strings.return_value   = '{"strings": []}'
        reg._get_cfg.return_value       = ''
        reg._get_disassembly.return_value = 'nop'
        reg._get_imports.return_value   = '{"imports": []}'

        with tempfile.TemporaryDirectory() as tmpdir:
            db   = FuncDB(os.path.join(tmpdir, 'test.db'))
            loop = AgentLoop(reg, func_db=db, api_key='sk-ant-test',
                             knowledge_graph=kg, arch='x86-64', fmt='elf64')

            captured_system = []
            def fake_sdk(system, prompt, model):
                captured_system.append(system)
                return ('{"name":"fn","confidence":0.5}', 100, 20)

            with patch.object(loop, '_call_sdk', side_effect=fake_sdk):
                loop.run(0x1000, task='name_function')

        assert captured_system, 'SDK was not called'
        assert 'KNOWLEDGE GRAPH' in captured_system[0]
        assert 'SinkArgClassifier' in captured_system[0]
