"""
anti_analysis_string_detector.py: Analysis-tool enumeration string detector.

Scans binary rodata for arrays of security tool executable names — the
Qakbot-style sandbox/analyst detection checklist. When a binary contains
a list of tools like "x64dbg.exe", "wireshark.exe", "procmon.exe" embedded
in its string table, it is performing environment scanning to detect whether
it is running inside a sandbox or under analyst monitoring tools.

This is a defense-evasion finding independent of execution: the binary
contains the strings regardless of what code paths use them.

Detection categories:
  - Debuggers: x64dbg, OllyDbg, WinDbg, Ghidra, IDA Pro, Radare2
  - Dynamic analysis: Process Hacker, Process Monitor, API Monitor
  - Network analysis: Wireshark, Fiddler, Burp Suite, mitmproxy
  - Sandbox indicators: Sandboxie, Cuckoo, Noriben, VMware tools
  - Endpoint detection: Autoruns, Regshot, TCPView, MalwareBytes

Usage:
    detector = AntiAnalysisStringDetector('/path/to/binary')
    findings = detector.scan()
    print(detector.report(findings))
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


# Tool categories and their indicator strings
_TOOL_CATEGORIES: dict[str, list[bytes]] = {
    'debugger': [
        b'x64dbg.exe', b'x32dbg.exe', b'ollydbg.exe', b'OllyDbg.exe',
        b'windbg.exe', b'ntsd.exe', b'cdb.exe', b'kd.exe',
        b'ida.exe', b'ida64.exe', b'idaq.exe', b'idaq64.exe',
        b'ghidra.exe', b'ghidraRun.exe',
        b'radare2.exe', b'r2.exe',
        b'binaryninjaui.exe', b'ImHex.exe',
    ],
    'dynamic_analysis': [
        b'procexp.exe', b'procexp64.exe', b'procmon.exe', b'procmon64.exe',
        b'ProcessHacker.exe', b'ph.exe',
        b'apimonitor-x86.exe', b'apimonitor-x64.exe',
        b'APIMonitor.exe',
        b'autoruns.exe', b'autoruns64.exe', b'autorunsc.exe',
        b'regshot.exe', b'regshot-x64-ANSI.exe',
    ],
    'network_analysis': [
        b'wireshark.exe', b'Wireshark.exe',
        b'fiddler.exe', b'Fiddler.exe', b'FiddlerRoot.exe',
        b'BurpSuitePro.exe', b'BurpSuiteEnterprise.exe',
        b'mitmproxy.exe', b'mitmdump.exe', b'mitmweb.exe',
        b'tcpview.exe', b'tcpview64.exe', b'TCPView.exe',
        b'NetworkMiner.exe',
        b'Charles.exe',
    ],
    'sandbox': [
        b'SandboxieDcomLaunch.exe', b'SbieCtrl.exe', b'SandboxieRpcSs.exe',
        b'cuckoo.exe',
        b'VBoxService.exe', b'VBoxTray.exe', b'VBoxGuest.exe',
        b'vmtoolsd.exe', b'vmwaretray.exe', b'vmwareuser.exe',
        b'prl_tools.exe', b'prl_cc.exe',
        b'xenservice.exe', b'XenGuestAgent.exe',
        b'noriben.exe',
    ],
    'edr_av': [
        b'MalwareBytes.exe', b'mbam.exe', b'MBAMService.exe',
        b'MsMpEng.exe', b'MpCmdRun.exe',
        b'avp.exe', b'kavtray.exe',
        b'bdagent.exe', b'vsserv.exe',
        b'sfc.exe',  # Windows SFC
    ],
}

# Minimum number of tool strings from the same category to flag
_MIN_MATCH = 3


@dataclass
class AntiAnalysisFinding:
    category:      str         # tool category
    matched:       list[str]   # tool names found
    match_count:   int
    severity:      str         # HIGH for 5+, MEDIUM for 3-4

    def fmt(self) -> str:
        tools = ', '.join(self.matched[:6])
        if len(self.matched) > 6:
            tools += f' (+{len(self.matched) - 6} more)'
        return (f"  {self.severity:6s}  [ANTI_ANALYSIS]  category={self.category}\n"
                f"         {self.match_count} tool strings: {tools}")


class AntiAnalysisStringDetector:
    """Detect analysis-tool enumeration strings in binary rodata."""

    def __init__(self, path: str) -> None:
        self._path = path

    @classmethod
    def from_context(cls, ctx) -> 'AntiAnalysisStringDetector':
        obj = cls.__new__(cls)
        obj._path = ctx.path
        return obj

    def _read_raw(self) -> bytes:
        try:
            return open(self._path, 'rb').read()
        except OSError:
            return b''

    def scan(self) -> List[AntiAnalysisFinding]:
        raw = self._read_raw()
        if not raw:
            return []

        findings: list[AntiAnalysisFinding] = []
        for category, tool_strings in _TOOL_CATEGORIES.items():
            matched = [t.decode('ascii') for t in tool_strings if t in raw]
            if len(matched) < _MIN_MATCH:
                continue
            severity = 'HIGH' if len(matched) >= 5 else 'MEDIUM'
            findings.append(AntiAnalysisFinding(
                category=category,
                matched=matched,
                match_count=len(matched),
                severity=severity,
            ))

        findings.sort(key=lambda f: f.match_count, reverse=True)
        return findings

    def report(self, findings: Optional[List[AntiAnalysisFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'AntiAnalysisStringDetector: no analysis-tool strings in {self._path}'
        lines = [f'AntiAnalysisStringDetector: {len(findings)} category/categories in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
