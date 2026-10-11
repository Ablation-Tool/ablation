"""
Tests for LuaInjectionAnalyzer (TG-SIEM-LUA-1).

Covers:
  DIRECT injection:
    - str.format() result passed directly to lua.execute()
    - f-string with interpolation passed directly to lua.execute()
    - %-format passed directly to lua.execute()
    - literal string (no interpolation) → no finding
  INDIRECT injection:
    - variable assigned from .format() then passed to lua.execute()
    - variable assigned from f-string then passed to lua.execute()
    - variable assigned from literal (no format) → no finding
    - augmented assignment (code += f"...{x}...")
  SUBPROCESS injection:
    - subprocess.run(['lua', '-e', f'...{x}...']) → MEDIUM
    - subprocess.run(['lua', '-e', 'literal']) → no finding
  Severity:
    - known user-input names (description, log_str) → CRITICAL
    - generic variable names → HIGH
    - subprocess → MEDIUM
  Pre-filter:
    - file without lupa import and without lua execute → not scanned
    - file with lupa import but no format near execute → no finding
  Edge cases:
    - syntax error in file → no crash, no findings
    - nested function → finding reported at correct line
    - multiple findings in same file
    - lua.eval() as well as lua.execute()
    - LuaRuntime().execute(...) chained call pattern
    - non-subprocess call with 'lua' string → no false positive
"""

import textwrap
from pathlib import Path

import pytest

from ablation.analyzers.lua_injection_analyzer import (
    LuaInjectionAnalyzer,
    LuaInjectionFinding,
    _is_format_expression,
    _is_lua_execute_call,
    _is_subprocess_lua_call,
)
import ast


# ── Helper ────────────────────────────────────────────────────────────────────

def _analyzer_for(tmp_path: Path, code: str) -> LuaInjectionAnalyzer:
    """Write code to a temp .py file and return an analyzer pointing at it."""
    f = tmp_path / "target.py"
    f.write_text(textwrap.dedent(code))
    return LuaInjectionAnalyzer.from_path(tmp_path)


# ── Unit tests for AST helpers ────────────────────────────────────────────────

def _parse_expr(src: str) -> ast.expr:
    tree = ast.parse(src, mode='eval')
    return tree.body


class TestIsFormatExpression:
    def test_format_method(self):
        node = _parse_expr('"hello {}".format(x)')
        assert _is_format_expression(node)

    def test_fstring(self):
        node = _parse_expr('f"hello {x}"')
        assert _is_format_expression(node)

    def test_percent_format(self):
        node = _parse_expr('"hello %s" % x')
        assert _is_format_expression(node)

    def test_literal_fstring(self):
        node = _parse_expr('f"hello world"')
        assert not _is_format_expression(node)

    def test_literal_string(self):
        node = _parse_expr('"hello"')
        assert not _is_format_expression(node)

    def test_format_no_args(self):
        node = _parse_expr('"hello".format()')
        assert not _is_format_expression(node)

    def test_format_with_keyword_arg(self):
        node = _parse_expr('"hello {x}".format(x=val)')
        assert _is_format_expression(node)


def _parse_call(src: str) -> ast.Call:
    tree = ast.parse(src, mode='eval')
    assert isinstance(tree.body, ast.Call)
    return tree.body


class TestIsLuaExecuteCall:
    def test_lua_execute(self):
        assert _is_lua_execute_call(_parse_call('lua.execute(code)'))

    def test_lua_rt_execute(self):
        assert _is_lua_execute_call(_parse_call('lua_rt.execute(code)'))

    def test_lua_eval(self):
        assert _is_lua_execute_call(_parse_call('lua.eval(code)'))

    def test_LUA_execute_uppercase(self):
        assert _is_lua_execute_call(_parse_call('LUA.execute(code)'))

    def test_not_execute_wrong_method(self):
        assert not _is_lua_execute_call(_parse_call('lua.run(code)'))

    def test_not_execute_no_lua(self):
        assert not _is_lua_execute_call(_parse_call('db.execute(sql)'))

    def test_chained_LuaRuntime(self):
        assert _is_lua_execute_call(_parse_call('LuaRuntime().execute(code)'))


class TestIsSubprocessLuaCall:
    def test_subprocess_run_lua(self):
        assert _is_subprocess_lua_call(_parse_call("subprocess.run(['lua', '-e', code])"))

    def test_subprocess_popen_lua(self):
        assert _is_subprocess_lua_call(_parse_call("subprocess.Popen(['lua', code])"))

    def test_subprocess_luajit(self):
        assert _is_subprocess_lua_call(_parse_call("subprocess.run(['luajit', code])"))

    def test_subprocess_python_not_lua(self):
        assert not _is_subprocess_lua_call(_parse_call("subprocess.run(['python3', code])"))

    def test_subprocess_empty_list(self):
        assert not _is_subprocess_lua_call(_parse_call("subprocess.run([])"))

    def test_subprocess_string_command(self):
        # subprocess.run('lua ...' string form) — not detected (list only)
        assert not _is_subprocess_lua_call(_parse_call("subprocess.run('lua -e code')"))


# ── Integration tests ─────────────────────────────────────────────────────────

class TestDirectInjection:
    def test_format_direct(self, tmp_path):
        code = """
            from lupa import LuaRuntime
            def run(description):
                lua = LuaRuntime()
                lua.execute("-- '{}'\\n".format(description))
        """
        findings = _analyzer_for(tmp_path, code).scan()
        assert len(findings) == 1
        f = findings[0]
        assert f.injection_type == "DIRECT"
        assert f.severity == "CRITICAL"  # 'description' in USER_INPUT_NAMES
        assert f.cwe == "CWE-94"

    def test_fstring_direct(self, tmp_path):
        code = """
            from lupa import LuaRuntime
            def run(x):
                lua = LuaRuntime()
                lua.execute(f"value = {x}")
        """
        findings = _analyzer_for(tmp_path, code).scan()
        assert len(findings) == 1
        assert findings[0].injection_type == "DIRECT"
        assert findings[0].severity == "HIGH"  # 'x' not in USER_INPUT_NAMES

    def test_percent_format_direct(self, tmp_path):
        code = """
            import lupa
            def run(val):
                lua = lupa.LuaRuntime()
                lua.execute("v = '%s'" % val)
        """
        findings = _analyzer_for(tmp_path, code).scan()
        assert len(findings) == 1
        assert findings[0].injection_type == "DIRECT"

    def test_literal_no_finding(self, tmp_path):
        code = """
            from lupa import LuaRuntime
            def run():
                lua = LuaRuntime()
                lua.execute("return 1 + 1")
        """
        findings = _analyzer_for(tmp_path, code).scan()
        assert findings == []

    def test_lua_eval_detected(self, tmp_path):
        code = """
            import lupa
            def run(name):
                lua = lupa.LuaRuntime()
                lua.eval("return '{}'".format(name))
        """
        findings = _analyzer_for(tmp_path, code).scan()
        assert len(findings) == 1
        assert findings[0].injection_type == "DIRECT"


class TestIndirectInjection:
    def test_format_assigned_then_executed(self, tmp_path):
        code = """
            from lupa import LuaRuntime
            def build_and_run(description):
                lua_code = "-- '{}'\\n{}".format(description, 'return 1')
                lua = LuaRuntime()
                lua.execute(lua_code)
        """
        findings = _analyzer_for(tmp_path, code).scan()
        assert len(findings) == 1
        f = findings[0]
        assert f.injection_type == "INDIRECT"
        assert f.var_name == "lua_code"
        assert f.severity == "CRITICAL"

    def test_fstring_assigned_then_executed(self, tmp_path):
        code = """
            from lupa import LuaRuntime
            def run(value):
                code = f'result = "{value}"'
                lua = LuaRuntime()
                lua.execute(code)
        """
        findings = _analyzer_for(tmp_path, code).scan()
        assert len(findings) == 1
        assert findings[0].injection_type == "INDIRECT"
        assert findings[0].severity == "CRITICAL"  # 'value' in USER_INPUT_NAMES

    def test_literal_assigned_no_finding(self, tmp_path):
        code = """
            from lupa import LuaRuntime
            def run():
                code = "return 42"
                lua = LuaRuntime()
                lua.execute(code)
        """
        findings = _analyzer_for(tmp_path, code).scan()
        assert findings == []

    def test_augmented_assign(self, tmp_path):
        code = """
            from lupa import LuaRuntime
            def run(name):
                code = "local x = "
                code += f'"{name}"'
                lua = LuaRuntime()
                lua.execute(code)
        """
        findings = _analyzer_for(tmp_path, code).scan()
        # The augmented assignment makes 'code' format-derived; execute(code) is INDIRECT
        assert len(findings) == 1
        assert findings[0].injection_type == "INDIRECT"


class TestSubprocessInjection:
    def test_subprocess_env_wrapper(self, tmp_path):
        code = """
            import subprocess
            def run(user_code):
                subprocess.run(['/usr/bin/env', 'lua', '-e', f'print({user_code})'])
        """
        findings = _analyzer_for(tmp_path, code).scan()
        assert len(findings) == 1
        assert findings[0].injection_type == "SUBPROCESS"

    def test_subprocess_lua_format_arg(self, tmp_path):
        code = """
            import subprocess
            def run(user_code):
                subprocess.run(['lua', '-e', f'print({user_code})'])
        """
        findings = _analyzer_for(tmp_path, code).scan()
        assert len(findings) == 1
        f = findings[0]
        assert f.injection_type == "SUBPROCESS"
        assert f.severity == "MEDIUM"

    def test_subprocess_lua_literal_no_finding(self, tmp_path):
        code = """
            import subprocess
            def run():
                subprocess.run(['lua', '-e', 'print("hello")'])
        """
        findings = _analyzer_for(tmp_path, code).scan()
        assert findings == []

    def test_subprocess_python_no_finding(self, tmp_path):
        code = """
            import subprocess
            def run(x):
                subprocess.run(['python3', '-c', f'print({x})'])
        """
        findings = _analyzer_for(tmp_path, code).scan()
        assert findings == []


class TestPreFilter:
    def test_no_lupa_no_lua_skipped(self, tmp_path):
        code = """
            def run(x):
                result = "hello {}".format(x)
                return result
        """
        findings = _analyzer_for(tmp_path, code).scan()
        assert findings == []

    def test_lupa_import_but_no_format(self, tmp_path):
        code = """
            from lupa import LuaRuntime
            def run():
                lua = LuaRuntime()
                lua.execute("return 1")
        """
        findings = _analyzer_for(tmp_path, code).scan()
        assert findings == []

    def test_lua_var_name_without_lupa_import(self, tmp_path):
        # The pre-filter checks for lua execute pattern even without lupa import
        code = """
            def run(description):
                lua = get_lua_runtime()
                lua.execute("-- '{}'".format(description))
        """
        findings = _analyzer_for(tmp_path, code).scan()
        assert len(findings) == 1

    def test_syntax_error_no_crash(self, tmp_path):
        f = tmp_path / "bad.py"
        f.write_text("def foo(:\n    pass\n")
        analyzer = LuaInjectionAnalyzer.from_path(tmp_path)
        findings = analyzer.scan()
        assert findings == []


class TestSeverity:
    def test_description_is_critical(self, tmp_path):
        code = """
            from lupa import LuaRuntime
            def run(description):
                lua = LuaRuntime()
                lua.execute("-- '{}'".format(description))
        """
        f = _analyzer_for(tmp_path, code).scan()
        assert f[0].severity == "CRITICAL"

    def test_log_str_is_critical(self, tmp_path):
        code = """
            from lupa import LuaRuntime
            def run(log_str):
                lua = LuaRuntime()
                lua.execute(f"match('{log_str}')")
        """
        f = _analyzer_for(tmp_path, code).scan()
        assert f[0].severity == "CRITICAL"

    def test_generic_var_is_high(self, tmp_path):
        code = """
            from lupa import LuaRuntime
            def run(z):
                lua = LuaRuntime()
                lua.execute("local x = {}".format(z))
        """
        f = _analyzer_for(tmp_path, code).scan()
        assert f[0].severity == "HIGH"


class TestMultipleFindings:
    def test_two_findings_in_one_file(self, tmp_path):
        code = """
            from lupa import LuaRuntime
            def first(description):
                lua = LuaRuntime()
                lua.execute("-- '{}'".format(description))

            def second(value):
                lua = LuaRuntime()
                lua.execute(f'result = "{value}"')
        """
        findings = _analyzer_for(tmp_path, code).scan()
        assert len(findings) == 2

    def test_sorting_critical_first(self, tmp_path):
        code = """
            from lupa import LuaRuntime
            def high_finding(z):
                lua = LuaRuntime()
                lua.execute("local x = {}".format(z))

            def critical_finding(description):
                lua = LuaRuntime()
                lua.execute("-- '{}'".format(description))
        """
        findings = _analyzer_for(tmp_path, code).scan()
        assert len(findings) == 2
        assert findings[0].severity == "CRITICAL"
        assert findings[1].severity == "HIGH"


class TestNestedFunctions:
    def test_finding_in_nested_function(self, tmp_path):
        code = """
            from lupa import LuaRuntime
            def outer():
                def inner(description):
                    lua = LuaRuntime()
                    lua.execute("-- '{}'".format(description))
                return inner
        """
        findings = _analyzer_for(tmp_path, code).scan()
        assert len(findings) == 1
        assert findings[0].injection_type == "DIRECT"


class TestExtraUserInputNames:
    def test_custom_name_escalates_to_critical(self, tmp_path):
        code = """
            from lupa import LuaRuntime
            def run(my_custom_field):
                lua = LuaRuntime()
                lua.execute("local x = {}".format(my_custom_field))
        """
        # Without custom names: HIGH (my_custom_field not in default set)
        findings_default = _analyzer_for(tmp_path, code).scan()
        assert findings_default[0].severity == "HIGH"

        # With custom name added: CRITICAL
        from ablation.analyzers.lua_injection_analyzer import LuaInjectionAnalyzer
        analyzer = LuaInjectionAnalyzer.from_path(
            tmp_path,
            extra_user_input_names=frozenset({'my_custom_field'}),
        )
        findings_custom = analyzer.scan()
        assert findings_custom[0].severity == "CRITICAL"

    def test_extra_names_do_not_affect_other_instances(self, tmp_path):
        code = """
            from lupa import LuaRuntime
            def run(my_custom_field):
                lua = LuaRuntime()
                lua.execute("x = {}".format(my_custom_field))
        """
        # Fresh analyzer without extra names
        findings = _analyzer_for(tmp_path, code).scan()
        assert findings[0].severity == "HIGH"


class TestReport:
    def test_report_no_findings(self):
        report = LuaInjectionAnalyzer.report([])
        assert "no findings" in report

    def test_report_contains_path_and_line(self, tmp_path):
        code = """
            from lupa import LuaRuntime
            def run(description):
                lua = LuaRuntime()
                lua.execute("-- '{}'".format(description))
        """
        findings = _analyzer_for(tmp_path, code).scan()
        report = LuaInjectionAnalyzer.report(findings)
        assert "target.py" in report
        assert "DIRECT" in report
        assert "CRITICAL" in report
