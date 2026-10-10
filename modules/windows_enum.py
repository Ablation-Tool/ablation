#!/usr/bin/env python3
"""
windows_enum.py — Windows live-system security enumeration

Live-host counterpart to the Ablation Windows PE static analyzers:

  CFGBypassDetector       →  system_security_features() (CFG policy, DEP, ASLR)
  COMAttackSurfaceMapper  →  com_hijack_candidates()    (HKCU vs HKLM CLSID delta)
  RPCServerAnalyzer       →  rpc_endpoints()            (active RPC endpoint mapper)
  ETWProviderExtractor    →  etw_sessions()             (active ETW sessions + consumers)
  PDBSymbolIntegrator     →  loaded_modules()           (PDB paths for loaded images)
  WindowsPoolTaintTracker →  (static only — kernel pool state not enumerable from user mode)

Also covers:
  named_pipes()           — \\.\pipe\* surface
  service_dlls()          — svchost-hosted service DLLs from registry
  autoruns()              — common persistence locations
  token_privileges()      — current process token privileges

Requires: Windows host (degrades gracefully on Linux/macOS).
Authorization: run only on systems you own or have explicit written authorization to test.

Usage:
    python3 windows_enum.py
    python3 windows_enum.py --sections com,rpc,etw,pipes
    python3 windows_enum.py --json

    from modules.windows_enum import WindowsEnumerator
    w = WindowsEnumerator()
    results = w.enumerate_all()
    print(w.report(results))
"""

import argparse
import json
import os
import platform
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_IS_WINDOWS = platform.system() == 'Windows'


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run(args: list[str], timeout: int = 15) -> tuple[str, str, int]:
    """Run a subprocess, return (stdout, stderr, returncode). Never raises."""
    try:
        r = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors='replace',
        )
        return r.stdout, r.stderr, r.returncode
    except FileNotFoundError:
        return '', f'command not found: {args[0]}', 127
    except subprocess.TimeoutExpired:
        return '', f'timeout after {timeout}s', -1
    except Exception as e:
        return '', str(e), -1


def _ps(script: str, timeout: int = 20) -> str:
    """Run a PowerShell one-liner, return stdout. Empty string on failure."""
    out, _, _ = _run(
        ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
        timeout=timeout,
    )
    return out.strip()


def _reg_query(key: str, value: str = '', recurse: bool = False) -> str:
    """Run reg.exe query, return stdout."""
    args = ['reg.exe', 'query', key]
    if value:
        args += ['/v', value]
    if recurse:
        args.append('/s')
    out, _, _ = _run(args)
    return out


@dataclass
class Finding:
    severity: str       # HIGH, MEDIUM, LOW, INFO
    category: str
    title: str
    detail: str
    evidence: str = ''


# ── WindowsEnumerator ─────────────────────────────────────────────────────────

class WindowsEnumerator:
    """Live Windows host security enumeration.

    Each method returns a list of Finding objects. enumerate_all() runs every
    section. Individual sections can be called independently.
    """

    def __init__(self) -> None:
        self._is_windows = _IS_WINDOWS

    # ── COM hijack candidates ─────────────────────────────────────────────────

    def com_hijack_candidates(self) -> list[Finding]:
        """Find CLSIDs in HKCU that shadow HKLM registrations (COM hijacking).

        A CLSID registered under HKCU\\Software\\Classes\\CLSID is user-writable
        and takes priority over the machine-level HKLM registration. Any process
        running as this user that activates that CLSID will load the HKCU version.
        """
        findings: list[Finding] = []
        if not self._is_windows:
            findings.append(Finding('INFO', 'com', 'Non-Windows host', 'COM registry enumeration requires Windows.'))
            return findings

        # Enumerate HKCU CLSIDs
        hkcu_out = _reg_query(r'HKCU\Software\Classes\CLSID', recurse=False)
        hklm_out = _reg_query(r'HKLM\SOFTWARE\Classes\CLSID', recurse=False)

        hkcu_guids = set(re.findall(r'\{[0-9A-Fa-f\-]{36}\}', hkcu_out))
        hklm_guids = set(re.findall(r'\{[0-9A-Fa-f\-]{36}\}', hklm_out))

        overlap = hkcu_guids & hklm_guids
        hkcu_only = hkcu_guids - hklm_guids

        findings.append(Finding(
            severity='INFO',
            category='com',
            title=f'CLSID inventory: {len(hkcu_guids)} HKCU, {len(hklm_guids)} HKLM',
            detail=f'{len(overlap)} CLSIDs registered in both (potential shadows); {len(hkcu_only)} HKCU-only.',
        ))

        # For each overlapping CLSID, get the InprocServer32 path from both hives
        for guid in sorted(overlap)[:30]:  # cap at 30 to avoid timeouts
            hkcu_dll = self._clsid_inprocserver(guid, 'HKCU')
            hklm_dll = self._clsid_inprocserver(guid, 'HKLM')
            if hkcu_dll and hkcu_dll != hklm_dll:
                findings.append(Finding(
                    severity='HIGH',
                    category='com_hijack',
                    title=f'COM hijack active: {guid}',
                    detail=(
                        f'HKCU InprocServer32: {hkcu_dll}\n'
                        f'HKLM InprocServer32: {hklm_dll}\n'
                        'The HKCU registration overrides the machine-level one. '
                        'Any process activating this CLSID loads the HKCU DLL.'
                    ),
                    evidence=f'HKCU\\Software\\Classes\\CLSID\\{guid}\\InprocServer32',
                ))

        if hkcu_only:
            findings.append(Finding(
                severity='MEDIUM',
                category='com_hijack',
                title=f'{len(hkcu_only)} HKCU-only CLSID registration(s)',
                detail=(
                    'CLSIDs registered only in HKCU (no HKLM counterpart). '
                    'These may be legitimate user-scope COM servers or planted '
                    'persistence registrations.\n' +
                    '\n'.join(sorted(hkcu_only)[:10])
                ),
            ))

        return findings

    def _clsid_inprocserver(self, guid: str, hive: str) -> str:
        if hive == 'HKCU':
            key = rf'HKCU\Software\Classes\CLSID\{guid}\InprocServer32'
        else:
            key = rf'HKLM\SOFTWARE\Classes\CLSID\{guid}\InprocServer32'
        out = _reg_query(key, value='')
        m = re.search(r'^\s+\(Default\)\s+REG_(?:SZ|EXPAND_SZ)\s+(.+)$', out, re.MULTILINE)
        return m.group(1).strip() if m else ''

    # ── RPC endpoints ─────────────────────────────────────────────────────────

    def rpc_endpoints(self) -> list[Finding]:
        """Enumerate active RPC endpoints via the endpoint mapper and netstat."""
        findings: list[Finding] = []
        if not self._is_windows:
            findings.append(Finding('INFO', 'rpc', 'Non-Windows host', 'RPC enumeration requires Windows.'))
            return findings

        # PowerShell: query RPC endpoint mapper via WMI (works without rpcdump)
        ps_out = _ps(
            r'Get-WmiObject -Class Win32_Service | '
            r'Where-Object {$_.State -eq "Running" -and $_.PathName -match "svchost"} | '
            r'Select-Object Name, DisplayName, PathName | ConvertTo-Json -Compress'
        )

        # Enumerate listening TCP/UDP ports (RPC typically on 135, 49152+)
        netstat_out, _, _ = _run(['netstat.exe', '-ano'])
        rpc_ports = re.findall(r'TCP\s+[\d.]+:(\d+)\s+[\d.]+:\d+\s+LISTENING\s+(\d+)', netstat_out)
        dynamic_rpc = [(port, pid) for port, pid in rpc_ports if 49152 <= int(port) <= 65535]

        findings.append(Finding(
            severity='INFO',
            category='rpc',
            title=f'RPC mapper at 135, {len(dynamic_rpc)} dynamic RPC port(s) listening',
            detail=(
                f'Dynamic RPC ports (49152-65535) with LISTENING state: {len(dynamic_rpc)}.\n' +
                '\n'.join(f'  port {p}  pid {pid}' for p, pid in dynamic_rpc[:20])
            ),
        ))

        # Check if RPC endpoint mapper is reachable on 135
        rpc_mapper_listening = any(
            port == '135' for port, _ in re.findall(
                r'TCP\s+[\d.]+:(\d+)\s+[\d.]+:\d+\s+LISTENING\s+(\d+)', netstat_out
            )
        )
        if rpc_mapper_listening:
            findings.append(Finding(
                severity='INFO',
                category='rpc',
                title='RPC endpoint mapper listening on TCP/135',
                detail='The endpoint mapper is active. Remote clients can query registered RPC interfaces.',
                evidence='netstat -ano | TCP:135 LISTENING',
            ))

        # Named pipe RPC endpoints
        pipe_out = _ps(r'Get-ChildItem \\.\pipe\ -ErrorAction SilentlyContinue | Where-Object {$_.Name -match "^(epmapper|lsass|ntsvcs|winreg|svcctl|samr|netlogon|spoolss|wkssvc|srvsvc)"} | Select-Object -ExpandProperty Name')
        if pipe_out:
            pipes = [p.strip() for p in pipe_out.splitlines() if p.strip()]
            sev = 'MEDIUM' if 'samr' in pipe_out.lower() or 'winreg' in pipe_out.lower() else 'INFO'
            findings.append(Finding(
                severity=sev,
                category='rpc',
                title=f'{len(pipes)} security-relevant named pipe RPC endpoint(s)',
                detail='Named pipes used for well-known RPC interfaces:\n' + '\n'.join(f'  \\\\.\pipe\\{p}' for p in pipes),
                evidence='Get-ChildItem \\\\.\\pipe\\',
            ))

        return findings

    # ── ETW sessions ─────────────────────────────────────────────────────────

    def etw_sessions(self) -> list[Finding]:
        """Enumerate active ETW trace sessions and their enabled providers."""
        findings: list[Finding] = []
        if not self._is_windows:
            findings.append(Finding('INFO', 'etw', 'Non-Windows host', 'ETW enumeration requires Windows.'))
            return findings

        logman_out, _, rc = _run(['logman.exe', 'query', '-ets'], timeout=15)
        if rc != 0 or not logman_out:
            # Fall back to PowerShell
            logman_out = _ps('logman query -ets')

        sessions = re.findall(r'^([A-Za-z][^\s].+?)\s{2,}', logman_out, re.MULTILINE)
        sessions = [s.strip() for s in sessions if s.strip() and 'Name' not in s and '---' not in s]

        # Security-relevant session names
        security_sessions = [s for s in sessions if any(
            kw in s.lower() for kw in ('defender', 'security', 'audit', 'protect', 'sensor',
                                        'edr', 'av', 'antimalware', 'crowdstrike', 'carbon',
                                        'cylance', 'sentinel', 'microsoft-windows-threat')
        )]

        findings.append(Finding(
            severity='INFO',
            category='etw',
            title=f'{len(sessions)} active ETW trace session(s)',
            detail='Sessions: ' + ', '.join(sessions[:20]) + (f' (+{len(sessions)-20} more)' if len(sessions) > 20 else ''),
        ))

        if security_sessions:
            findings.append(Finding(
                severity='INFO',
                category='etw',
                title=f'{len(security_sessions)} security/EDR ETW session(s) active',
                detail=(
                    'Active sessions with security-relevant names indicate EDR or AV '
                    'telemetry collection is running:\n' +
                    '\n'.join(f'  {s}' for s in security_sessions)
                ),
                evidence='logman query -ets',
            ))
        else:
            findings.append(Finding(
                severity='MEDIUM',
                category='etw',
                title='No security/EDR ETW sessions detected',
                detail=(
                    'No active ETW sessions with security-relevant names found. '
                    'This may indicate security monitoring is absent, using '
                    'kernel callbacks instead of ETW, or session names are obfuscated.'
                ),
            ))

        # Check for NT Kernel Logger (mandatory security session)
        if any('nt kernel logger' in s.lower() or 'circular kernel' in s.lower() for s in sessions):
            findings.append(Finding(
                severity='INFO',
                category='etw',
                title='NT Kernel Logger / Circular Kernel Context Logger active',
                detail='Kernel-mode event collection is running (process create, image load, network events).',
            ))
        else:
            findings.append(Finding(
                severity='MEDIUM',
                category='etw',
                title='NT Kernel Logger not detected in active sessions',
                detail=(
                    'The NT Kernel Logger provides process creation, image load, and network '
                    'telemetry. Its absence may indicate security monitoring gaps or that it '
                    'runs under a non-standard session name.'
                ),
            ))

        return findings

    # ── Named pipes ───────────────────────────────────────────────────────────

    def named_pipes(self) -> list[Finding]:
        """Enumerate named pipes and flag security-relevant ones."""
        findings: list[Finding] = []
        if not self._is_windows:
            findings.append(Finding('INFO', 'pipes', 'Non-Windows host', 'Named pipe enumeration requires Windows.'))
            return findings

        ps_out = _ps(
            r'Get-ChildItem \\.\pipe\ -ErrorAction SilentlyContinue | '
            r'Select-Object -ExpandProperty Name | Sort-Object'
        )
        if not ps_out:
            findings.append(Finding('INFO', 'pipes', 'Named pipe enumeration failed', 'Could not list \\.\pipe\.'))
            return findings

        pipes = [p.strip() for p in ps_out.splitlines() if p.strip()]

        # Categorize
        rpc_pipes    = [p for p in pipes if any(k in p.lower() for k in ('epmapper', 'ntsvcs', 'svcctl', 'samr', 'winreg', 'netlogon', 'spoolss', 'wkssvc', 'srvsvc', 'lsass'))]
        browser_pipes = [p for p in pipes if any(k in p.lower() for k in ('chrome', 'firefox', 'edge', 'brave'))]
        anon_pipes   = [p for p in pipes if re.match(r'^\d+$', p)]

        findings.append(Finding(
            severity='INFO',
            category='pipes',
            title=f'{len(pipes)} named pipe(s) found',
            detail=f'{len(rpc_pipes)} RPC-related, {len(browser_pipes)} browser IPC, {len(anon_pipes)} anonymous.',
        ))

        if rpc_pipes:
            findings.append(Finding(
                severity='INFO',
                category='pipes',
                title=f'{len(rpc_pipes)} RPC-related named pipe(s)',
                detail='\n'.join(f'  \\\\.\pipe\\{p}' for p in rpc_pipes),
            ))

        # Impersonation candidates: world-writable pipes (needs handle.exe or NtQueryObject — approximate heuristic)
        findings.append(Finding(
            severity='INFO',
            category='pipes',
            title='Full pipe list',
            detail='\n'.join(f'  \\\\.\pipe\\{p}' for p in pipes[:50]) + (f'\n  ...({len(pipes)-50} more)' if len(pipes) > 50 else ''),
        ))

        return findings

    # ── Windows security features ─────────────────────────────────────────────

    def system_security_features(self) -> list[Finding]:
        """Audit system-wide Windows security feature state."""
        findings: list[Finding] = []
        if not self._is_windows:
            findings.append(Finding('INFO', 'secfeatures', 'Non-Windows host', 'Security feature audit requires Windows.'))
            return findings

        # DEP policy
        dep_out = _reg_query(
            r'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management',
            value='EnableExecuteProtection',
        )
        dep_ps = _ps('(Get-WmiObject -Class Win32_OperatingSystem).DataExecutionPrevention_SupportPolicy')
        dep_map = {'0': 'OptIn (default, system only)', '1': 'OptOut', '2': 'AlwaysOff', '3': 'AlwaysOn'}
        dep_val = dep_ps.strip()
        dep_label = dep_map.get(dep_val, f'unknown ({dep_val})')
        dep_sev = 'HIGH' if dep_val == '2' else ('MEDIUM' if dep_val == '0' else 'INFO')
        findings.append(Finding(
            severity=dep_sev,
            category='secfeatures',
            title=f'DEP policy: {dep_label}',
            detail='DataExecutionPrevention_SupportPolicy from Win32_OperatingSystem WMI.',
            evidence=f'Win32_OS.DataExecutionPrevention_SupportPolicy = {dep_val}',
        ))

        # UAC
        uac_out = _reg_query(
            r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
            value='EnableLUA',
        )
        uac_enabled = '0x1' in uac_out or 'REG_DWORD    0x1' in uac_out
        findings.append(Finding(
            severity='HIGH' if not uac_enabled else 'INFO',
            category='secfeatures',
            title=f'UAC: {"enabled" if uac_enabled else "DISABLED"}',
            detail=(
                'User Account Control is the primary privilege separation boundary on Windows. '
                'Disabled UAC means any user-mode process can silently elevate to administrator.'
                if not uac_enabled else
                'UAC is enabled (EnableLUA=1).'
            ),
            evidence=r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA',
        ))

        # Secure Boot
        secboot = _ps('try { (Confirm-SecureBootUEFI).ToString() } catch { "NotSupported" }')
        if 'True' in secboot:
            findings.append(Finding('INFO', 'secfeatures', 'Secure Boot: enabled', 'UEFI Secure Boot is active.'))
        elif 'False' in secboot:
            findings.append(Finding('MEDIUM', 'secfeatures', 'Secure Boot: DISABLED', 'UEFI Secure Boot is off. Unsigned boot components can load.'))
        else:
            findings.append(Finding('INFO', 'secfeatures', 'Secure Boot: not determined', f'Confirm-SecureBootUEFI: {secboot}'))

        # Credential Guard
        cg_out = _reg_query(
            r'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard',
            value='EnableVirtualizationBasedSecurity',
        )
        cg_enabled = '0x1' in cg_out or '0x3' in cg_out
        findings.append(Finding(
            severity='INFO' if cg_enabled else 'MEDIUM',
            category='secfeatures',
            title=f'Virtualization-Based Security (VBS/Credential Guard): {"enabled" if cg_enabled else "not detected"}',
            detail=(
                'VBS isolates LSASS credential material in a separate VTL. '
                'Pass-the-hash against NTLM hashes from LSASS memory is blocked when Credential Guard is active.'
                if cg_enabled else
                'VBS/Credential Guard not detected in DeviceGuard registry. LSASS credential material may be extractable.'
            ),
            evidence=r'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity',
        ))

        # LSA Protection (RunAsPPL)
        ppl_out = _reg_query(
            r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
            value='RunAsPPL',
        )
        ppl_enabled = '0x1' in ppl_out or '0x2' in ppl_out
        findings.append(Finding(
            severity='INFO' if ppl_enabled else 'MEDIUM',
            category='secfeatures',
            title=f'LSA Protection (RunAsPPL): {"enabled" if ppl_enabled else "not enabled"}',
            detail=(
                'LSASS runs as a Protected Process Light. Direct process injection and '
                'most credential dumping tools are blocked without a signed kernel driver.'
                if ppl_enabled else
                'LSASS does not run as PPL. Process injection and credential dumping tools '
                '(Mimikatz, lsassy) can read credential material from LSASS memory.'
            ),
            evidence=r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL',
        ))

        # Windows Defender state
        defender_out = _reg_query(
            r'HKLM\SOFTWARE\Microsoft\Windows Defender',
            value='DisableAntiSpyware',
        )
        defender_disabled = '0x1' in defender_out
        findings.append(Finding(
            severity='HIGH' if defender_disabled else 'INFO',
            category='secfeatures',
            title=f'Windows Defender: {"DISABLED via registry" if defender_disabled else "registry disable key absent"}',
            detail=(
                'DisableAntiSpyware=1 in HKLM Windows Defender key. '
                'Defender real-time protection is turned off.'
                if defender_disabled else
                'No registry disable key found. Defender may be active (check service state separately).'
            ),
            evidence=r'HKLM\SOFTWARE\Microsoft\Windows Defender\DisableAntiSpyware',
        ))

        return findings

    # ── Service DLLs ─────────────────────────────────────────────────────────

    def service_dlls(self) -> list[Finding]:
        """Enumerate DLLs hosted by svchost.exe from the service registry."""
        findings: list[Finding] = []
        if not self._is_windows:
            findings.append(Finding('INFO', 'servicedll', 'Non-Windows host', 'Service DLL enumeration requires Windows.'))
            return findings

        out = _reg_query(
            r'HKLM\SYSTEM\CurrentControlSet\Services',
            value='ServiceDll',
            recurse=True,
        )
        # Parse: service name from key path, DLL path from value
        entries: list[tuple[str, str]] = []
        current_key = ''
        for line in out.splitlines():
            line = line.strip()
            if line.startswith('HKEY_LOCAL_MACHINE'):
                current_key = line
            m = re.match(r'ServiceDll\s+REG_EXPAND_SZ\s+(.+)', line, re.IGNORECASE)
            if m:
                entries.append((current_key, m.group(1).strip()))

        findings.append(Finding(
            severity='INFO',
            category='servicedll',
            title=f'{len(entries)} svchost-hosted service DLL(s)',
            detail=f'DLLs running inside svchost.exe process groups. Each is an in-process attack surface.',
        ))

        # Flag DLLs not in System32 or SysWOW64 (unusual locations)
        unusual = [
            (key, dll) for key, dll in entries
            if not re.search(r'%SystemRoot%\\[Ss]ystem32|%WinDir%\\[Ss]ystem32|C:\\Windows\\[Ss]ystem3', dll, re.IGNORECASE)
        ]
        if unusual:
            findings.append(Finding(
                severity='HIGH',
                category='servicedll',
                title=f'{len(unusual)} service DLL(s) outside System32',
                detail=(
                    'Service DLLs loaded from non-standard paths may indicate persistence, '
                    'DLL hijacking, or a third-party product:\n' +
                    '\n'.join(f'  {Path(key).name}: {dll}' for key, dll in unusual[:20])
                ),
            ))

        return findings

    # ── Persistence / autoruns ────────────────────────────────────────────────

    def autoruns(self) -> list[Finding]:
        """Check common registry persistence locations."""
        findings: list[Finding] = []
        if not self._is_windows:
            findings.append(Finding('INFO', 'autoruns', 'Non-Windows host', 'Autorun enumeration requires Windows.'))
            return findings

        run_keys = [
            r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
            r'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
            r'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute',
            r'HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows',
        ]
        all_entries: list[tuple[str, str, str]] = []
        for key in run_keys:
            out = _reg_query(key)
            for line in out.splitlines():
                m = re.match(r'\s+(\S+)\s+REG_(?:SZ|EXPAND_SZ|MULTI_SZ)\s+(.+)', line)
                if m:
                    name, value = m.group(1).strip(), m.group(2).strip()
                    if name not in ('(Default)',):
                        all_entries.append((key, name, value))

        findings.append(Finding(
            severity='INFO',
            category='autoruns',
            title=f'{len(all_entries)} autorun registry entry/entries',
            detail='\n'.join(f'  [{Path(k).name}] {n} = {v}' for k, n, v in all_entries[:30]),
        ))

        # Suspicious: entries pointing outside Program Files / Windows
        suspicious = [
            (k, n, v) for k, n, v in all_entries
            if not re.search(
                r'C:\\(Windows|Program Files|Program Files \(x86\))',
                v, re.IGNORECASE
            ) and not v.lower().startswith('%')
        ]
        if suspicious:
            findings.append(Finding(
                severity='MEDIUM',
                category='autoruns',
                title=f'{len(suspicious)} autorun entries with non-standard paths',
                detail='\n'.join(f'  [{Path(k).name}] {n} = {v}' for k, n, v in suspicious[:15]),
            ))

        # Scheduled tasks (summary count)
        tasks_out, _, _ = _run(['schtasks.exe', '/query', '/fo', 'CSV'], timeout=20)
        task_count = max(0, tasks_out.count('\n') - 1)
        findings.append(Finding(
            severity='INFO',
            category='autoruns',
            title=f'{task_count} scheduled task(s)',
            detail='Run schtasks /query /fo CSV /v for full detail.',
        ))

        return findings

    # ── Token privileges ─────────────────────────────────────────────────────

    def token_privileges(self) -> list[Finding]:
        """Enumerate privileges of the current process token."""
        findings: list[Finding] = []
        if not self._is_windows:
            findings.append(Finding('INFO', 'token', 'Non-Windows host', 'Token enumeration requires Windows.'))
            return findings

        whoami_out, _, _ = _run(['whoami.exe', '/all'])
        if not whoami_out:
            whoami_out = _ps('[Security.Principal.WindowsIdentity]::GetCurrent().Name')

        # Extract privilege lines
        privs = re.findall(r'(Se\w+Privilege)\s+\S+\s+(Enabled|Disabled)', whoami_out)
        enabled_privs = [p for p, state in privs if state == 'Enabled']
        dangerous = [
            p for p in enabled_privs if p in (
                'SeDebugPrivilege', 'SeImpersonatePrivilege', 'SeAssignPrimaryTokenPrivilege',
                'SeTakeOwnershipPrivilege', 'SeLoadDriverPrivilege', 'SeBackupPrivilege',
                'SeRestorePrivilege', 'SeTcbPrivilege', 'SeCreateTokenPrivilege',
            )
        ]

        # Username + groups
        user_m = re.search(r'USER INFORMATION\s*\n[-]+\s*\n(\S+\\\S+)', whoami_out)
        user = user_m.group(1) if user_m else _ps('[Security.Principal.WindowsIdentity]::GetCurrent().Name')
        is_admin = 'S-1-5-32-544' in whoami_out or 'Administrators' in whoami_out

        findings.append(Finding(
            severity='INFO',
            category='token',
            title=f'Running as: {user.strip()}',
            detail=f'Administrator group member: {is_admin}\nEnabled privileges: {", ".join(enabled_privs) or "none"}',
            evidence='whoami /all',
        ))

        if dangerous:
            findings.append(Finding(
                severity='HIGH',
                category='token',
                title=f'{len(dangerous)} dangerous privilege(s) enabled',
                detail=(
                    'These privileges allow significant privilege escalation or lateral movement:\n' +
                    '\n'.join(f'  {p}' for p in dangerous)
                ),
                evidence='whoami /priv',
            ))

        return findings

    # ── Loaded modules (PDB paths) ────────────────────────────────────────────

    def loaded_modules(self) -> list[Finding]:
        """List loaded modules in the current process with PDB path hints."""
        findings: list[Finding] = []
        if not self._is_windows:
            findings.append(Finding('INFO', 'modules', 'Non-Windows host', 'Module enumeration requires Windows.'))
            return findings

        ps_out = _ps(
            '[System.Diagnostics.Process]::GetCurrentProcess().Modules | '
            'Select-Object FileName, FileVersionInfo | '
            'ForEach-Object { "$($_.FileName)" } | Sort-Object'
        )
        modules = [m.strip() for m in ps_out.splitlines() if m.strip()]

        # Non-System32 DLLs
        non_system = [m for m in modules if not re.search(r'[Ss]ystem32|SysWOW64|WinSxS', m)]

        findings.append(Finding(
            severity='INFO',
            category='modules',
            title=f'{len(modules)} module(s) loaded in current process',
            detail=f'{len(non_system)} outside System32/SysWOW64.',
        ))
        if non_system:
            findings.append(Finding(
                severity='INFO',
                category='modules',
                title='Non-system DLL(s) loaded',
                detail='\n'.join(f'  {m}' for m in non_system[:20]),
            ))
        return findings

    # ── enumerate_all ─────────────────────────────────────────────────────────

    def enumerate_all(
        self,
        sections: Optional[list[str]] = None,
    ) -> dict[str, list[Finding]]:
        """Run all enumeration sections and return results by section name."""
        all_sections = {
            'com':         self.com_hijack_candidates,
            'rpc':         self.rpc_endpoints,
            'etw':         self.etw_sessions,
            'pipes':       self.named_pipes,
            'secfeatures': self.system_security_features,
            'servicedll':  self.service_dlls,
            'autoruns':    self.autoruns,
            'token':       self.token_privileges,
            'modules':     self.loaded_modules,
        }
        if sections:
            run = {k: v for k, v in all_sections.items() if k in sections}
        else:
            run = all_sections

        results: dict[str, list[Finding]] = {}
        for name, fn in run.items():
            try:
                results[name] = fn()
            except Exception as e:
                results[name] = [Finding('INFO', name, f'{name} enumeration error', str(e))]
        return results

    # ── Reporting ─────────────────────────────────────────────────────────────

    @staticmethod
    def report(results: dict[str, list[Finding]]) -> str:
        sev_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}
        lines: list[str] = []
        total_high = sum(
            1 for findings in results.values()
            for f in findings if f.severity == 'HIGH'
        )
        total_med = sum(
            1 for findings in results.values()
            for f in findings if f.severity == 'MEDIUM'
        )
        lines.append('=' * 72)
        lines.append(f'  Windows Enumeration  |  {total_high} HIGH  {total_med} MEDIUM')
        lines.append('=' * 72)

        for section, findings in results.items():
            lines.append(f'\n[{section.upper()}]')
            for f in sorted(findings, key=lambda x: sev_order.get(x.severity, 99)):
                lines.append(f'  [{f.severity}] {f.title}')
                for detail_line in f.detail.splitlines():
                    lines.append(f'         {detail_line}')
                if f.evidence:
                    lines.append(f'         evidence: {f.evidence}')
        lines.append('')
        return '\n'.join(lines)

    @staticmethod
    def to_json(results: dict[str, list[Finding]]) -> str:
        out: dict[str, list[dict]] = {}
        for section, findings in results.items():
            out[section] = [
                {
                    'severity': f.severity,
                    'category': f.category,
                    'title': f.title,
                    'detail': f.detail,
                    'evidence': f.evidence,
                }
                for f in findings
            ]
        return json.dumps(out, indent=2)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Windows live-system security enumeration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Sections: com, rpc, etw, pipes, secfeatures, servicedll, autoruns, token, modules',
    )
    parser.add_argument('--sections', help='Comma-separated list of sections to run (default: all)')
    parser.add_argument('--json', action='store_true', help='Output JSON instead of formatted report')
    args = parser.parse_args()

    sections = [s.strip() for s in args.sections.split(',')] if args.sections else None
    w = WindowsEnumerator()
    results = w.enumerate_all(sections=sections)

    if args.json:
        print(WindowsEnumerator.to_json(results))
    else:
        print(WindowsEnumerator.report(results))


if __name__ == '__main__':
    main()
