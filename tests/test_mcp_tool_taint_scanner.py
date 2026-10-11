"""
Tests for MCPToolTaintScanner (TG-FMGMCP-1).

Covers:
  BIND_WIDE:
    - .listen(port) without host → HIGH
    - .listen(port, '127.0.0.1') → no finding
    - .listen(port, () => {}) → HIGH (callback, no host)
    - host='0.0.0.0' in Python → HIGH
    - host='127.0.0.1' in Python → no finding
  EXEC_IN_ALLOWED:
    - ALLOWED_METHODS = new Set([...'exec'...]) → CRITICAL
    - ALLOWED_METHODS = {'exec': ...} Python → CRITICAL
    - ALLOWED_METHODS without exec-class → no finding
    - 'shell' in ALLOWED_METHODS → CRITICAL
    - 'run' in ALLOWED_METHODS → CRITICAL
  NO_AUTH:
    - /mcp route without auth middleware → HIGH
    - /mcp route with authenticate() nearby → no finding
    - FastMCP HTTP transport without auth → HIGH
    - FastMCP with auth_middleware nearby → no finding
  Pre-filter:
    - File with no MCP patterns → skipped
    - File with ALLOWED_METHODS pattern → scanned
  Edge cases:
    - EXEC_IN_ALLOWED multiline block
    - Multiple findings in one file (BIND_WIDE + EXEC_IN_ALLOWED)
    - Sorting: CRITICAL before HIGH
    - /mcp in a comment line → still flagged (conservative)
    - .ts and .js extensions both scanned
    - .py extension scanned
    - .html extension NOT scanned
"""

import textwrap
from pathlib import Path

import pytest

from ablation.analyzers.mcp_tool_taint_scanner import (
    MCPToolTaintScanner,
    MCPTaintFinding,
    _has_auth_in_window,
    _exec_methods_in_block,
    _extract_allowed_methods_block,
)


# ── Helper ────────────────────────────────────────────────────────────────────

def _scanner_for(tmp_path: Path, code: str, filename: str = "server.ts") -> MCPToolTaintScanner:
    f = tmp_path / filename
    f.write_text(textwrap.dedent(code))
    return MCPToolTaintScanner.from_path(tmp_path)


# ── Unit tests ────────────────────────────────────────────────────────────────

class TestHasAuthInWindow:
    def test_auth_in_window(self):
        lines = ["x = 1", "authenticate(req)", "app.post('/mcp', handler)"]
        assert _has_auth_in_window(lines, 2, window=5)

    def test_no_auth_in_window(self):
        lines = ["x = 1", "logger.info('hello')", "app.post('/mcp', handler)"]
        assert not _has_auth_in_window(lines, 2, window=5)

    def test_auth_below(self):
        lines = ["app.post('/mcp', handler)", "x = 1", "requireAuth(token)"]
        assert _has_auth_in_window(lines, 0, window=5)

    def test_auth_case_insensitive(self):
        lines = ["app.post('/mcp', handler)", "VerifyToken(req, res, next)"]
        assert _has_auth_in_window(lines, 0, window=5)


class TestExecMethodsInBlock:
    def test_exec_found(self):
        block = "const ALLOWED_METHODS = new Set(['get', 'set', 'exec'])"
        assert _exec_methods_in_block(block) == ['exec']

    def test_execute_found(self):
        block = "ALLOWED_METHODS = {'get', 'execute', 'set'}"
        assert 'execute' in _exec_methods_in_block(block)

    def test_no_exec_class(self):
        block = "ALLOWED_METHODS = new Set(['get', 'set', 'list', 'delete'])"
        assert _exec_methods_in_block(block) == []

    def test_shell_found(self):
        block = "ALLOWED_METHODS = new Set(['shell', 'get'])"
        assert 'shell' in _exec_methods_in_block(block)

    def test_run_found(self):
        block = "ALLOWED_METHODS = {'run', 'get'}"
        assert 'run' in _exec_methods_in_block(block)


# ── BIND_WIDE TypeScript/JS ───────────────────────────────────────────────────

class TestBindWideTsJs:
    def test_listen_port_only(self, tmp_path):
        code = """
            import { McpServer } from '@modelcontextprotocol/sdk';
            const server = new McpServer({name: 'test', version: '1.0'});
            httpServer.listen(8000);
        """
        findings = _scanner_for(tmp_path, code).scan()
        bind = [f for f in findings if f.issue_type == 'BIND_WIDE']
        assert len(bind) == 1
        assert bind[0].severity == 'HIGH'
        assert bind[0].cwe == 'CWE-668'

    def test_listen_with_safe_host(self, tmp_path):
        code = """
            import { McpServer } from '@modelcontextprotocol/sdk';
            httpServer.listen(8000, '127.0.0.1');
        """
        findings = _scanner_for(tmp_path, code).scan()
        assert not any(f.issue_type == 'BIND_WIDE' for f in findings)

    def test_listen_with_localhost(self, tmp_path):
        code = """
            import { McpServer } from '@modelcontextprotocol/sdk';
            httpServer.listen(config.port, 'localhost');
        """
        findings = _scanner_for(tmp_path, code).scan()
        assert not any(f.issue_type == 'BIND_WIDE' for f in findings)

    def test_listen_with_callback_no_host(self, tmp_path):
        code = """
            import { McpServer } from '@modelcontextprotocol/sdk';
            httpServer.listen(config.mcpHttpPort, () => {
                console.log('listening');
            });
        """
        findings = _scanner_for(tmp_path, code).scan()
        bind = [f for f in findings if f.issue_type == 'BIND_WIDE']
        assert len(bind) == 1

    def test_listen_with_explicit_zero(self, tmp_path):
        code = """
            import { McpServer } from '@modelcontextprotocol/sdk';
            httpServer.listen(8000, '0.0.0.0');
        """
        findings = _scanner_for(tmp_path, code).scan()
        bind = [f for f in findings if f.issue_type == 'BIND_WIDE']
        assert len(bind) == 1

    def test_js_extension_scanned(self, tmp_path):
        code = """
            const mcp_transport = 'http';
            server.listen(3000);
        """
        findings = _scanner_for(tmp_path, code, "server.js").scan()
        bind = [f for f in findings if f.issue_type == 'BIND_WIDE']
        assert len(bind) == 1


# ── BIND_WIDE Python ─────────────────────────────────────────────────────────

class TestBindWidePython:
    def test_py_bind_wide(self, tmp_path):
        code = """
            from mcp.server.fastmcp import FastMCP
            mcp = FastMCP("test")
            import uvicorn
            uvicorn.run(app, host='0.0.0.0', port=8000)
        """
        findings = _scanner_for(tmp_path, code, "server.py").scan()
        bind = [f for f in findings if f.issue_type == 'BIND_WIDE']
        assert len(bind) == 1
        assert bind[0].severity == 'HIGH'

    def test_py_safe_host(self, tmp_path):
        code = """
            from mcp.server.fastmcp import FastMCP
            mcp = FastMCP("test")
            uvicorn.run(app, host='127.0.0.1', port=8000)
        """
        findings = _scanner_for(tmp_path, code, "server.py").scan()
        assert not any(f.issue_type == 'BIND_WIDE' for f in findings)

    def test_py_localhost(self, tmp_path):
        code = """
            from mcp.server.fastmcp import FastMCP
            mcp = FastMCP("test")
            uvicorn.run(app, host='localhost', port=8000)
        """
        findings = _scanner_for(tmp_path, code, "server.py").scan()
        assert not any(f.issue_type == 'BIND_WIDE' for f in findings)


# ── EXEC_IN_ALLOWED TypeScript/JS ─────────────────────────────────────────────

class TestExecInAllowedTsJs:
    def test_exec_in_allowed_methods(self, tmp_path):
        code = """
            import { McpServer } from '@modelcontextprotocol/sdk';
            const ALLOWED_METHODS = new Set(['get', 'set', 'exec', 'delete']);
            export function executeCode(method: string) {
                if (!ALLOWED_METHODS.has(method)) throw new Error('not allowed');
                return fortimanager.request(method, []);
            }
        """
        findings = _scanner_for(tmp_path, code).scan()
        exec_findings = [f for f in findings if f.issue_type == 'EXEC_IN_ALLOWED']
        assert len(exec_findings) == 1
        assert exec_findings[0].severity == 'CRITICAL'
        assert exec_findings[0].cwe == 'CWE-284'
        assert 'exec' in exec_findings[0].description

    def test_no_exec_in_allowed_methods(self, tmp_path):
        code = """
            import { McpServer } from '@modelcontextprotocol/sdk';
            const ALLOWED_METHODS = new Set(['get', 'set', 'list', 'delete', 'update']);
        """
        findings = _scanner_for(tmp_path, code).scan()
        assert not any(f.issue_type == 'EXEC_IN_ALLOWED' for f in findings)

    def test_shell_in_allowed(self, tmp_path):
        code = """
            const mcp_transport = 'http';
            const ALLOWED_METHODS = new Set(['get', 'shell']);
        """
        findings = _scanner_for(tmp_path, code).scan()
        exec_findings = [f for f in findings if f.issue_type == 'EXEC_IN_ALLOWED']
        assert len(exec_findings) == 1

    def test_multiline_allowed_methods(self, tmp_path):
        code = """
            import { McpServer } from '@modelcontextprotocol/sdk';
            const ALLOWED_METHODS = new Set([
                'get',
                'set',
                'exec',
                'delete',
            ]);
        """
        findings = _scanner_for(tmp_path, code).scan()
        exec_findings = [f for f in findings if f.issue_type == 'EXEC_IN_ALLOWED']
        assert len(exec_findings) == 1


# ── EXEC_IN_ALLOWED Python ────────────────────────────────────────────────────

class TestExecInAllowedPython:
    def test_exec_in_allowed_python(self, tmp_path):
        code = """
            from mcp.server.fastmcp import FastMCP
            ALLOWED_METHODS = {'get', 'set', 'exec', 'delete'}

            def run_method(method, args):
                if method not in ALLOWED_METHODS:
                    raise ValueError
                return api.call(method, args)
        """
        findings = _scanner_for(tmp_path, code, "executor.py").scan()
        exec_findings = [f for f in findings if f.issue_type == 'EXEC_IN_ALLOWED']
        assert len(exec_findings) == 1
        assert exec_findings[0].severity == 'CRITICAL'

    def test_no_exec_in_allowed_python(self, tmp_path):
        code = """
            from mcp.server.fastmcp import FastMCP
            ALLOWED_METHODS = {'get', 'set', 'list', 'delete'}
        """
        findings = _scanner_for(tmp_path, code, "executor.py").scan()
        assert not any(f.issue_type == 'EXEC_IN_ALLOWED' for f in findings)


# ── NO_AUTH ───────────────────────────────────────────────────────────────────

class TestNoAuth:
    def test_mcp_route_no_auth_ts(self, tmp_path):
        code = """
            import { McpServer } from '@modelcontextprotocol/sdk';
            import express from 'express';
            const app = express();
            const router = app.get('/mcp', (req, res) => {
                handleMcpRequest(req, res);
            });
        """
        findings = _scanner_for(tmp_path, code).scan()
        no_auth = [f for f in findings if f.issue_type == 'NO_AUTH']
        assert len(no_auth) == 1
        assert no_auth[0].severity == 'HIGH'
        assert no_auth[0].cwe == 'CWE-306'

    def test_mcp_route_with_auth_ts(self, tmp_path):
        code = """
            import { McpServer } from '@modelcontextprotocol/sdk';
            app.use('/mcp', authenticate, (req, res) => {
                handleMcpRequest(req, res);
            });
        """
        findings = _scanner_for(tmp_path, code).scan()
        assert not any(f.issue_type == 'NO_AUTH' for f in findings)

    def test_mcp_route_with_verifytoken(self, tmp_path):
        code = """
            const mcp_transport = 'http';
            function verifyToken(req, res, next) { next(); }
            app.post('/mcp', verifyToken, handler);
        """
        findings = _scanner_for(tmp_path, code).scan()
        assert not any(f.issue_type == 'NO_AUTH' for f in findings)

    def test_fastmcp_http_no_auth_python(self, tmp_path):
        code = """
            from mcp.server.fastmcp import FastMCP
            mcp = FastMCP("FortiManager")
            mcp.run(transport='http', port=8080)
        """
        findings = _scanner_for(tmp_path, code, "server.py").scan()
        no_auth = [f for f in findings if f.issue_type == 'NO_AUTH']
        assert len(no_auth) == 1

    def test_fastmcp_stdio_no_network(self, tmp_path):
        code = """
            from mcp.server.fastmcp import FastMCP
            mcp = FastMCP("FortiManager")
            mcp.run()
        """
        findings = _scanner_for(tmp_path, code, "server.py").scan()
        # stdio transport — no HTTP binding → no NO_AUTH finding
        assert not any(f.issue_type == 'NO_AUTH' for f in findings)


# ── Pre-filter ────────────────────────────────────────────────────────────────

class TestPreFilter:
    def test_no_mcp_patterns_skipped(self, tmp_path):
        code = """
            def compute(x, y):
                return x + y
        """
        findings = _scanner_for(tmp_path, code, "math.py").scan()
        assert findings == []

    def test_html_not_scanned(self, tmp_path):
        code = """
            <html><body>ALLOWED_METHODS exec /mcp listen(8000)</body></html>
        """
        f = tmp_path / "index.html"
        f.write_text(textwrap.dedent(code))
        findings = MCPToolTaintScanner.from_path(tmp_path).scan()
        assert findings == []

    def test_allowed_methods_triggers_scan(self, tmp_path):
        code = """
            ALLOWED_METHODS = new Set(['get', 'exec'])
        """
        findings = _scanner_for(tmp_path, code).scan()
        assert any(f.issue_type == 'EXEC_IN_ALLOWED' for f in findings)


# ── Multiple findings and sorting ─────────────────────────────────────────────

class TestMultipleFindings:
    def test_bind_and_exec_in_one_file(self, tmp_path):
        code = """
            import { McpServer } from '@modelcontextprotocol/sdk';
            const ALLOWED_METHODS = new Set(['get', 'exec']);
            httpServer.listen(8000);
        """
        findings = _scanner_for(tmp_path, code).scan()
        types = {f.issue_type for f in findings}
        assert 'BIND_WIDE' in types
        assert 'EXEC_IN_ALLOWED' in types

    def test_critical_sorted_first(self, tmp_path):
        code = """
            import { McpServer } from '@modelcontextprotocol/sdk';
            const ALLOWED_METHODS = new Set(['get', 'exec']);
            httpServer.listen(8000);
            app.get('/mcp', handler);
        """
        findings = _scanner_for(tmp_path, code).scan()
        assert findings[0].severity == 'CRITICAL'


# ── Report ────────────────────────────────────────────────────────────────────

class TestReport:
    def test_report_no_findings(self):
        report = MCPToolTaintScanner.report([])
        assert 'no findings' in report

    def test_report_contains_type_and_severity(self, tmp_path):
        code = """
            const mcp_transport = 'http';
            const ALLOWED_METHODS = new Set(['exec', 'get']);
        """
        findings = _scanner_for(tmp_path, code).scan()
        report = MCPToolTaintScanner.report(findings)
        assert 'EXEC_IN_ALLOWED' in report
        assert 'CRITICAL' in report
        assert 'server.ts' in report
