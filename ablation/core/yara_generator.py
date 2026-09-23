#!/usr/bin/env python3
"""
YARA rule generation from binary scan results.
Generates detection rules from pe_parser/elf_parser findings.

API/technique basis drawn from:
  - Mohanta & Saldanha, "Malware Analysis and Detection Engineering" (Apress, 2020)
    Ch 10: Code Injection, Process Hollowing, API Hooking
    Ch 11: Stealth and Rootkits (SSDT/DKOM/IRP)
    Ch 15: Payload Dissection and Classification (API import sets)
    Ch 20: Fileless, Macros, and Other Malware Trends (PS/VBA/WMI patterns)
"""
import re
import struct
import hashlib
import os
from dataclasses import dataclass, field
from datetime import date
from typing import List, Tuple, Dict, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class YARARule:
    """Represents a single YARA rule."""
    name: str
    meta: Dict[str, str] = field(default_factory=dict)
    # Each entry: (identifier, value, modifiers)
    # value may be a quoted string like '"FunctionName"' or hex like '{ 4D 5A }'
    strings: List[Tuple[str, str, str]] = field(default_factory=list)
    condition: str = "any of them"

    def to_text(self) -> str:
        """Serialize rule to YARA syntax."""
        lines = []
        lines.append(f"rule {self.name}")
        lines.append("{")

        if self.meta:
            lines.append("    meta:")
            for k, v in self.meta.items():
                lines.append(f'        {k} = "{v}"')

        if self.strings:
            lines.append("    strings:")
            for ident, value, mods in self.strings:
                mod_str = (" " + mods) if mods else ""
                lines.append(f"        {ident} = {value}{mod_str}")

        lines.append("    condition:")
        lines.append(f"        {self.condition}")
        lines.append("}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_IDENT_RE = re.compile(r"[^a-zA-Z0-9_]")


def _safe_ident(raw: str, prefix: str = "s", idx: int = 0) -> str:
    """Return a YARA-safe identifier from a raw string."""
    cleaned = _IDENT_RE.sub("_", raw)
    if cleaned and cleaned[0].isdigit():
        cleaned = "_" + cleaned
    cleaned = cleaned[:48].rstrip("_") or "x"
    return f"${prefix}_{idx}_{cleaned}"


def _today() -> str:
    return date.today().isoformat()


def _file_sha256(filepath: str) -> str:
    try:
        h = hashlib.sha256(open(filepath, "rb").read()).hexdigest()
    except Exception:
        h = hashlib.sha256(filepath.encode()).hexdigest()
    return h


def _rule_name_from_path(filepath: str) -> str:
    sha = _file_sha256(filepath)[:16]
    base = re.sub(r"[^a-zA-Z0-9]", "_", os.path.basename(filepath))[:32]
    return f"mal_{base}_{sha}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_from_pe_findings(findings: dict, filepath: str) -> YARARule:
    """
    Build a YARA rule from scan_pe_file() output.

    findings keys consumed:
      ioc_strings   - list of {"type": ..., "value": str}
      malware_apis  - list of {"api": str, "severity": str}
      anti_debug    - list of {"type": str, "details": ...}
      sections      - list of section dicts (unused here, kept for extension)
      imports       - dict {dll: [func, ...]}
    """
    name = _rule_name_from_path(filepath)

    meta: Dict[str, str] = {
        "description": f"Auto-generated rule for {os.path.basename(filepath)}",
        "author_type": "automated",
        "date": _today(),
        "sha256": _file_sha256(filepath),
    }

    strings: List[Tuple[str, str, str]] = []
    seen_values: set = set()

    # --- ioc_strings: IP, domain, registry path -------------------------
    ioc_list = findings.get("ioc_strings", []) or []
    s_idx = 0
    for ioc in ioc_list:
        val = (ioc.get("value") or "").strip()
        if not val or val in seen_values:
            continue
        seen_values.add(val)
        escaped = val.replace("\\", "\\\\").replace('"', '\\"')
        ident = _safe_ident(val, "s", s_idx)
        strings.append((ident, f'"{escaped}"', "ascii wide nocase"))
        s_idx += 1

    # --- malware_apis: CRITICAL severity only ---------------------------
    api_list = findings.get("malware_apis", []) or []
    a_idx = 0
    for entry in api_list:
        sev = (entry.get("severity") or "").upper()
        if sev != "CRITICAL":
            continue
        api_name = (entry.get("api") or "").strip()
        if not api_name or api_name in seen_values:
            continue
        seen_values.add(api_name)
        ident = _safe_ident(api_name, "api", a_idx)
        strings.append((ident, f'"{api_name}"', "ascii wide"))
        a_idx += 1

    # --- anti_debug: byte patterns if present ---------------------------
    ad_list = findings.get("anti_debug", []) or []
    b_idx = 0
    for entry in ad_list:
        details = entry.get("details") or ""
        # Accept pre-formatted hex strings like "EB 04 74 02" or bytes
        if isinstance(details, (bytes, bytearray)):
            hex_str = " ".join(f"{b:02X}" for b in details)
            if hex_str in seen_values:
                continue
            seen_values.add(hex_str)
            ident = f"$b_{b_idx}"
            strings.append((ident, f"{{ {hex_str} }}", ""))
            b_idx += 1
        elif isinstance(details, str):
            hex_clean = re.sub(r"[^0-9a-fA-F\s]", "", details).strip()
            if len(hex_clean.replace(" ", "")) >= 4 and hex_clean not in seen_values:
                seen_values.add(hex_clean)
                ident = f"$b_{b_idx}"
                strings.append((ident, f"{{ {hex_clean.upper()} }}", ""))
                b_idx += 1

    # --- condition assembly ---------------------------------------------
    parts = []
    if s_idx > 0:
        parts.append("(2 of ($s_*))")
    if a_idx > 0:
        parts.append("(any of ($api_*))")
    if b_idx > 0:
        parts.append("(any of ($b_*))")

    condition = " or ".join(parts) if parts else "false"

    return YARARule(name=name, meta=meta, strings=strings, condition=condition)


def generate_from_strings(strings: list, name: str = "generic_rule") -> YARARule:
    """
    Build a YARA rule from a raw list of strings.
    Deduplicates and sanitizes identifiers.
    """
    safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", name) or "generic_rule"

    meta = {
        "description": f"String-based rule: {name}",
        "author_type": "automated",
        "date": _today(),
    }

    rule_strings: List[Tuple[str, str, str]] = []
    seen: set = set()
    idx = 0

    for raw in strings:
        val = str(raw).strip()
        if not val or val in seen:
            continue
        seen.add(val)
        escaped = val.replace("\\", "\\\\").replace('"', '\\"')
        ident = _safe_ident(val, "str", idx)
        rule_strings.append((ident, f'"{escaped}"', "ascii wide nocase"))
        idx += 1

    condition = "any of them" if rule_strings else "false"
    return YARARule(name=safe_name, meta=meta, strings=rule_strings, condition=condition)


def generate_process_injection_rule() -> YARARule:
    """
    Classic process injection API triad detection.

    Technique (Ch 10): OpenProcess → VirtualAllocEx (memory alloc in target)
    → WriteProcessMemory (code copy) → CreateRemoteThread (execution trigger).
    Rule requires all three write/exec APIs — weakest-link detection: if any
    is absent the injection sequence cannot complete.

    Additional coverage: QueueUserAPC (APC injection variant, Ch 10 p.234)
    and RtlCreateUserThread / NtCreateThreadEx (undocumented thread creation).
    """
    meta = {
        "description": "Classic process injection: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread",
        "author_type": "automated",
        "date": _today(),
        "technique": "T1055 Process Injection",
        "reference": "Mohanta/Saldanha Ch10 p.134-258",
    }

    strings: List[Tuple[str, str, str]] = [
        ("$api_VirtualAllocEx",     '"VirtualAllocEx"',     "ascii wide"),
        ("$api_WriteProcessMemory", '"WriteProcessMemory"',  "ascii wide"),
        ("$api_CreateRemoteThread", '"CreateRemoteThread"',  "ascii wide"),
        # APC injection variant
        ("$api_QueueUserAPC",       '"QueueUserAPC"',        "ascii wide"),
        # Undocumented thread creation (DKOM bypass)
        ("$api_RtlCreateUserThread","'RtlCreateUserThread'", "ascii wide"),
        ("$api_NtCreateThreadEx",   '"NtCreateThreadEx"',    "ascii wide"),
    ]

    condition = (
        "($api_VirtualAllocEx and $api_WriteProcessMemory and $api_CreateRemoteThread)"
        " or ($api_VirtualAllocEx and $api_WriteProcessMemory and $api_QueueUserAPC)"
    )

    return YARARule(
        name="process_injection_classic",
        meta=meta,
        strings=strings,
        condition=condition,
    )


def generate_ransomware_rule() -> YARARule:
    """
    Ransomware detection rule.

    Indicators (Ch 15 p.497-543):
    - CryptEncrypt: file encryption primitive
    - FindFirstFile/FindNextFile: file enumeration over victim FS
    - DeleteFile: used to delete originals and shadow copies
    - vssadmin + bcdedit commands: shadow copy deletion (near-universal behavior)
    - Extension strings: common ransomware output suffixes
    - WinAPI string indicators from GandCrab, CryptoLocker variants
    """
    meta = {
        "description": "Ransomware: file encryption APIs, shadow copy deletion, encrypted extension strings",
        "author_type": "automated",
        "date": _today(),
        "technique": "T1486 Data Encrypted for Impact",
        "reference": "Mohanta/Saldanha Ch15 p.497-543",
    }

    strings: List[Tuple[str, str, str]] = [
        # Core crypto + file enumeration APIs
        ("$api_CryptEncrypt",       '"CryptEncrypt"',        "ascii wide"),
        ("$api_FindFirstFile",      '"FindFirstFile"',        "ascii wide"),
        ("$api_FindNextFile",       '"FindNextFile"',          "ascii wide"),
        ("$api_DeleteFile",         '"DeleteFile"',           "ascii wide"),
        ("$api_CryptGenKey",        '"CryptGenKey"',          "ascii wide"),
        ("$api_CryptAcquireContext",'"CryptAcquireContext"',  "ascii wide"),
        # Shadow copy deletion (near-universal ransomware behavior)
        ("$cmd_vssadmin",
         '"vssadmin" wide ascii',
         "nocase"),
        ("$cmd_delete_shadows",
         '"delete shadows" wide ascii',
         "nocase"),
        ("$cmd_bcdedit",
         '"bcdedit" wide ascii',
         "nocase"),
        ("$cmd_recoveryenabled",
         '"recoveryenabled no" wide ascii',
         "nocase"),
        # Encrypted file extension strings
        ("$ext_locked",    '".locked"',    "ascii wide nocase"),
        ("$ext_encrypted", '".encrypted"', "ascii wide nocase"),
        ("$ext_crypt",     '".crypt"',     "ascii wide nocase"),
        ("$ext_enc",       '".enc"',       "ascii wide nocase"),
        ("$ext_crypted",   '".crypted"',   "ascii wide nocase"),
        # Ransom note filenames (GandCrab/common)
        ("$note_readme",   '"READ_ME"',    "ascii wide nocase"),
        ("$note_decrypt",  '"DECRYPT"',    "ascii wide nocase"),
        ("$note_recover",  '"RECOVER"',    "ascii wide nocase"),
    ]

    condition = (
        "($api_CryptEncrypt and $api_FindFirstFile)"
        " or ($api_CryptEncrypt and $api_CryptGenKey)"
        " or (2 of ($ext_*))"
        " or ($cmd_vssadmin and $cmd_delete_shadows)"
        " or (2 of ($note_*))"
    )

    return YARARule(
        name="ransomware_generic",
        meta=meta,
        strings=strings,
        condition=condition,
    )


def generate_rootkit_rule() -> YARARule:
    """
    Kernel rootkit detection rule.

    Indicators (Ch 11 p.193-413):
    - KeServiceDescriptorTable: exported kernel symbol; the pointer malware
      reads to locate the SSDT for table-pointer or inline hooking (p.282-293).
    - IoCreateDevice: kernel driver entrypoint API; all kernel modules call
      this to register a device object with the I/O manager.
    - ObReferenceObjectByHandle: used by DKOM rootkits to obtain EPROCESS
      object pointers for linked-list manipulation (p.333-363).
    - Driver install sequence APIs: OpenSCManager → CreateService → StartService
      — the invariant sequence for loading any kernel module (p.264-276).
    - DKOM-specific kernel structs referenced in rootkit tooling.
    """
    meta = {
        "description": "Kernel rootkit: SSDT hook indicators, DKOM EPROCESS manipulation, driver install sequence",
        "author_type": "automated",
        "date": _today(),
        "technique": "T1014 Rootkit",
        "reference": "Mohanta/Saldanha Ch11 p.193-413",
    }

    strings: List[Tuple[str, str, str]] = [
        # SSDT location struct (exported from ntoskrnl/ntkrnlpa)
        ("$sym_KeServiceDescriptorTable", '"KeServiceDescriptorTable"', "ascii wide"),
        # Kernel driver device creation
        ("$sym_IoCreateDevice",          '"IoCreateDevice"',           "ascii wide"),
        # DKOM object reference
        ("$sym_ObReferenceObjectByHandle",'"ObReferenceObjectByHandle"',"ascii wide"),
        # EPROCESS structure field (DKOM process hiding)
        ("$sym_ActiveProcessLinks",      '"ActiveProcessLinks"',        "ascii wide"),
        # IRP major function table (IRP filter rootkits)
        ("$sym_IoGetCurrentIrpStackLocation",
         '"IoGetCurrentIrpStackLocation"', "ascii wide"),
        # Driver install sequence
        ("$api_OpenSCManager",           '"OpenSCManager"',            "ascii wide"),
        ("$api_CreateService",           '"CreateService"',            "ascii wide"),
        ("$api_StartService",            '"StartService"',             "ascii wide"),
        # NT-layer driver load
        ("$api_ZwLoadDriver",            '"ZwLoadDriver"',             "ascii wide"),
        # SSDT hook: common targets (Ch11 p.321-331)
        ("$ssdt_ZwOpenFile",             '"ZwOpenFile"',               "ascii wide"),
        ("$ssdt_ZwQuerySystemInfo",      '"ZwQuerySystemInformation"', "ascii wide"),
        ("$ssdt_ZwTerminateProcess",     '"ZwTerminateProcess"',       "ascii wide"),
    ]

    condition = (
        "$sym_KeServiceDescriptorTable"
        " or ($api_OpenSCManager and $api_CreateService and $api_StartService)"
        " or ($sym_IoCreateDevice and $sym_ObReferenceObjectByHandle)"
        " or (2 of ($ssdt_*))"
    )

    return YARARule(
        name="kernel_rootkit_generic",
        meta=meta,
        strings=strings,
        condition=condition,
    )


def generate_downloader_rule() -> YARARule:
    """
    Downloader / dropper detection.

    Indicators (Ch 20 p.191-260):
    - MSXML2.ServerXMLHTTP COM object: HTTP download primitive in VBScript/VBA
    - ADODB.Stream: write downloaded bytes to disk
    - WScript.Shell.Run: execute downloaded payload
    - PowerShell DownloadFile / DownloadString cmdlets
    - IEX (Invoke-Expression) for in-memory PS execution
    - WinInet download sequence: InternetOpen → InternetOpenUrl → InternetReadFile
    """
    meta = {
        "description": "Downloader/dropper: COM HTTP objects, PS download cmdlets, WinInet sequence",
        "author_type": "automated",
        "date": _today(),
        "technique": "T1105 Ingress Tool Transfer",
        "reference": "Mohanta/Saldanha Ch20 p.191-260",
    }

    strings: List[Tuple[str, str, str]] = [
        # VBScript/VBA COM download objects
        ("$com_ServerXMLHTTP", '"MSXML2.ServerXMLHTTP"', "ascii wide nocase"),
        ("$com_ADODBStream",   '"ADODB.Stream"',          "ascii wide nocase"),
        ("$com_WScriptShell",  '"WScript.Shell"',         "ascii wide nocase"),
        # PowerShell download primitives
        ("$ps_DownloadFile",   '"DownloadFile"',          "ascii wide"),
        ("$ps_DownloadString", '"DownloadString"',        "ascii wide"),
        ("$ps_IEX",            '"Invoke-Expression"',     "ascii wide nocase"),
        ("$ps_IEX_alias",      '"iex"',                   "ascii wide"),
        # PowerShell encoded command flag (fileless delivery)
        ("$ps_enc",            '"-EncodedCommand"',       "ascii wide nocase"),
        ("$ps_enc_short",      '" -enc "',                "ascii wide nocase"),
        # WinInet download sequence
        ("$inet_Open",         '"InternetOpenUrl"',       "ascii wide"),
        ("$inet_Read",         '"InternetReadFile"',      "ascii wide"),
        # SaveToFile (ADODB stream method)
        ("$com_SaveToFile",    '"SaveToFile"',             "ascii wide nocase"),
    ]

    condition = (
        "($com_ServerXMLHTTP and ($com_ADODBStream or $com_SaveToFile))"
        " or ($ps_DownloadFile or $ps_DownloadString)"
        " or ($ps_IEX and $ps_enc)"
        " or ($inet_Open and $inet_Read)"
    )

    return YARARule(
        name="downloader_dropper_generic",
        meta=meta,
        strings=strings,
        condition=condition,
    )


def generate_rat_rule() -> YARARule:
    """
    Remote Access Trojan detection.

    Indicators (Ch 15 p.444-493):
    - WSAStartup / WSASocket: backdoor socket creation
    - GetAsyncKeyState + SetWindowsHookEx: keylogger component (WH_KEYBOARD_LL)
    - BitBlt / GetDC / CreateCompatibleDC: screenshot capability
    - OpenClipboard / GetClipboardData: clipboard theft
    - Shell32 / ShellExecute: command execution
    - WH_KEYBOARD_LL (0x0D = 13): hook type flag for low-level keyboard hook
    """
    meta = {
        "description": "RAT: backdoor socket, keylogger, screenshot, clipboard, remote exec indicators",
        "author_type": "automated",
        "date": _today(),
        "technique": "T1219 Remote Access Software",
        "reference": "Mohanta/Saldanha Ch15 p.444-493",
    }

    strings: List[Tuple[str, str, str]] = [
        # Backdoor comms
        ("$api_WSAStartup",          '"WSAStartup"',          "ascii wide"),
        ("$api_WSASocket",           '"WSASocket"',           "ascii wide"),
        # Keylogger component
        ("$api_GetAsyncKeyState",    '"GetAsyncKeyState"',    "ascii wide"),
        ("$api_SetWindowsHookEx",    '"SetWindowsHookEx"',    "ascii wide"),
        ("$api_CallNextHookEx",      '"CallNextHookEx"',      "ascii wide"),
        # Screenshot capability
        ("$api_BitBlt",              '"BitBlt"',              "ascii wide"),
        ("$api_GetDC",               '"GetDC"',               "ascii wide"),
        ("$api_CreateCompatibleDC",  '"CreateCompatibleDC"',  "ascii wide"),
        # Clipboard theft
        ("$api_OpenClipboard",       '"OpenClipboard"',       "ascii wide"),
        ("$api_GetClipboardData",    '"GetClipboardData"',    "ascii wide"),
        # WH_KEYBOARD_LL hook type constant (0x0D)
        ("$const_WH_KEYBOARD_LL",   "{ 0D 00 00 00 }",       ""),
    ]

    condition = (
        "($api_WSAStartup and $api_WSASocket)"
        " or ($api_SetWindowsHookEx and $api_GetAsyncKeyState)"
        " or ($api_BitBlt and $api_GetDC and $api_CreateCompatibleDC)"
        " or ($api_OpenClipboard and $api_GetClipboardData)"
    )

    return YARARule(
        name="rat_generic",
        meta=meta,
        strings=strings,
        condition=condition,
    )


def generate_keylogger_rule() -> YARARule:
    """
    Keylogger detection.

    Indicators (Ch 15 p.127-180):
    - SetWindowsHookEx with WH_KEYBOARD_LL (0x0D) or WH_KEYBOARD (0x02)
    - GetAsyncKeyState polling loop
    - TranslateMessage / DispatchMessage: message pump hooking
    - Special-key label strings left by keyloggers for log formatting
    """
    meta = {
        "description": "Keylogger: SetWindowsHookEx keyboard hook, GetAsyncKeyState, message pump APIs",
        "author_type": "automated",
        "date": _today(),
        "technique": "T1056.001 Keylogging",
        "reference": "Mohanta/Saldanha Ch15 p.127-180",
    }

    strings: List[Tuple[str, str, str]] = [
        ("$api_SetWindowsHookEx",  '"SetWindowsHookEx"',   "ascii wide"),
        ("$api_GetAsyncKeyState",  '"GetAsyncKeyState"',   "ascii wide"),
        ("$api_CallNextHookEx",    '"CallNextHookEx"',     "ascii wide"),
        ("$api_GetMessage",        '"GetMessage"',         "ascii wide"),
        ("$api_TranslateMessage",  '"TranslateMessage"',   "ascii wide"),
        ("$api_DispatchMessage",   '"DispatchMessage"',    "ascii wide"),
        ("$api_GetKeyboardState",  '"GetKeyboardState"',   "ascii wide"),
        # Special-key label strings common in keylogger logs
        ("$str_Backspace",  '"Backspace"',  "ascii wide nocase"),
        ("$str_CapsLock",   '"Caps Lock"',  "ascii wide nocase"),
        ("$str_ArrowDown",  '"Arrow Down"', "ascii wide nocase"),
        ("$str_Delete",     '"Delete"',     "ascii wide nocase"),
    ]

    condition = (
        "($api_SetWindowsHookEx and ($api_GetMessage or $api_TranslateMessage))"
        " or ($api_GetAsyncKeyState and $api_CallNextHookEx)"
        " or ($api_SetWindowsHookEx and 2 of ($str_*))"
    )

    return YARARule(
        name="keylogger_generic",
        meta=meta,
        strings=strings,
        condition=condition,
    )


def generate_fileless_powershell_rule() -> YARARule:
    """
    Fileless / PowerShell in-memory execution detection.

    Indicators (Ch 20 p.460-531):
    - -EncodedCommand / -enc / -e: base64-encoded PS payload (fileless delivery)
    - -WindowStyle hidden / -w hidden: console concealment
    - -ExecutionPolicy Bypass / -Exec Bypass: policy bypass
    - IEX + DownloadString: in-memory download + exec (no disk write)
    - WMI persistence: SELECT * FROM __EventFilter + CommandLineEventConsumer
    - AutoOpen / Document_Open: VBA macro auto-execution triggers
    """
    meta = {
        "description": "Fileless: PS encoded commands, in-memory IEX, WMI persistence, VBA auto-macros",
        "author_type": "automated",
        "date": _today(),
        "technique": "T1059.001 PowerShell / T1546.003 WMI Event Subscription",
        "reference": "Mohanta/Saldanha Ch20 p.460-531",
    }

    strings: List[Tuple[str, str, str]] = [
        # PowerShell encoded command flags
        ("$ps_EncodedCommand",   '"-EncodedCommand"',      "ascii wide nocase"),
        ("$ps_enc_short_e",      '" -e "'                 , "ascii wide nocase"),
        ("$ps_enc_short_Enc",    '" -Enc "'               , "ascii wide nocase"),
        # Execution policy bypass
        ("$ps_bypass",           '"Bypass"',               "ascii wide nocase"),
        # Window hiding
        ("$ps_hidden",           '"WindowStyle Hidden"',   "ascii wide nocase"),
        ("$ps_w_hidden",         '"-w hidden"',            "ascii wide nocase"),
        # In-memory download + exec
        ("$ps_IEX",              '"Invoke-Expression"',    "ascii wide nocase"),
        ("$ps_DownloadString",   '"DownloadString"',       "ascii wide"),
        # WMI persistence queries
        ("$wmi_EventFilter",     '"__EventFilter"',        "ascii wide nocase"),
        ("$wmi_EventConsumer",   '"CommandLineEventConsumer"', "ascii wide nocase"),
        ("$wmi_Subscribe",       '"__EventSubscription"',  "ascii wide nocase"),
        # VBA macro auto-execution triggers
        ("$vba_AutoOpen",        '"AutoOpen"',             "ascii wide nocase"),
        ("$vba_Document_Open",   '"Document_Open"',        "ascii wide nocase"),
        ("$vba_AutoExec",        '"AutoExec"',             "ascii wide nocase"),
        # Eval in script context
        ("$vba_Eval",            '"VMSXE.Eval"',           "ascii wide nocase"),
    ]

    condition = (
        "($ps_EncodedCommand or $ps_enc_short_e or $ps_enc_short_Enc)"
        " or ($ps_IEX and $ps_DownloadString)"
        " or ($ps_hidden and $ps_bypass)"
        " or (2 of ($wmi_*))"
        " or (2 of ($vba_*))"
    )

    return YARARule(
        name="fileless_powershell_macro",
        meta=meta,
        strings=strings,
        condition=condition,
    )


def generate_worm_rule() -> YARARule:
    """
    Worm / lateral movement detection.

    Indicators:
    - WMI remote process creation: wmic /node: process call create
    - NetShareEnum / NetSessionEnum: network share enumeration
    - CopyFile + CreateRemoteThread: file-copy + remote execution
    - GetAdaptersInfo / GetAdaptersAddresses: subnet scanning setup
    """
    meta = {
        "description": "Worm: WMI lateral movement, net share enumeration, remote copy-exec",
        "author_type": "automated",
        "date": _today(),
        "technique": "T1021 Remote Services / T1570 Lateral Tool Transfer",
        "reference": "Mohanta/Saldanha Ch20 p.422-458",
    }

    strings: List[Tuple[str, str, str]] = [
        ("$wmi_node",              '"/node:"',                 "ascii wide nocase"),
        ("$wmi_create",            '"process call create"',    "ascii wide nocase"),
        ("$api_NetShareEnum",      '"NetShareEnum"',           "ascii wide"),
        ("$api_NetSessionEnum",    '"NetSessionEnum"',         "ascii wide"),
        ("$api_CopyFile",          '"CopyFileEx"',             "ascii wide"),
        ("$api_GetAdaptersInfo",   '"GetAdaptersInfo"',        "ascii wide"),
        ("$api_CreateRemoteThread",'"CreateRemoteThread"',     "ascii wide"),
        ("$api_WNetOpenEnum",      '"WNetOpenEnum"',           "ascii wide"),
    ]

    condition = (
        "($wmi_node and $wmi_create)"
        " or ($api_NetShareEnum and $api_CreateRemoteThread)"
        " or ($api_WNetOpenEnum and $api_CopyFile)"
    )

    return YARARule(
        name="worm_lateral_movement",
        meta=meta,
        strings=strings,
        condition=condition,
    )


# ---------------------------------------------------------------------------
# Batch output
# ---------------------------------------------------------------------------

def write_rules_file(rules: list, output_path: str) -> None:
    """
    Write multiple YARARule objects to a .yar file.
    Skips rules with empty strings and no meaningful condition.
    """
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(f"// Generated by ablation yara_generator — {_today()}\n")
        fh.write("// Do not modify manually; re-generate from scan findings.\n\n")
        for rule in rules:
            if not isinstance(rule, YARARule):
                continue
            fh.write(rule.to_text())
            fh.write("\n\n")


# ---------------------------------------------------------------------------
# Convenience: return all built-in hardcoded rules
# ---------------------------------------------------------------------------

def builtin_rules() -> list:
    """Return all hardcoded detection rules."""
    return [
        generate_process_injection_rule(),
        generate_ransomware_rule(),
        generate_rootkit_rule(),
        generate_downloader_rule(),
        generate_rat_rule(),
        generate_keylogger_rule(),
        generate_fileless_powershell_rule(),
        generate_worm_rule(),
    ]


# ---------------------------------------------------------------------------
# Smoke test (not a test suite — just structural validation)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    print("[*] Generating built-in rules...")
    rules = builtin_rules()

    out = "/tmp/ablation_test.yar"
    write_rules_file(rules, out)
    print(f"[+] Wrote {len(rules)} rules to {out}")

    for r in rules:
        text = r.to_text()
        # Basic structural checks
        assert r.name, "Rule has no name"
        assert "rule " in text, f"Missing 'rule' keyword in {r.name}"
        assert "meta:" in text, f"Missing meta in {r.name}"
        assert "strings:" in text, f"Missing strings in {r.name}"
        assert "condition:" in text, f"Missing condition in {r.name}"
        assert text.count("{") == text.count("}"), f"Brace mismatch in {r.name}"
        print(f"    [ok] {r.name} ({len(r.strings)} strings)")

    # Test generate_from_strings
    r2 = generate_from_strings(["malware.exe", "C:\\Windows\\temp\\drop.exe", "192.168.1.1"])
    assert len(r2.strings) == 3
    print(f"    [ok] generate_from_strings: {r2.name}")

    # Test generate_from_pe_findings with mock data
    mock = {
        "ioc_strings": [
            {"type": "ip", "value": "10.10.10.5"},
            {"type": "domain", "value": "evil.example.com"},
        ],
        "malware_apis": [
            {"api": "VirtualAllocEx", "severity": "CRITICAL"},
            {"api": "WriteProcessMemory", "severity": "HIGH"},
        ],
        "anti_debug": [
            {"type": "timing", "details": "EB 02 74 01"},
        ],
    }
    r3 = generate_from_pe_findings(mock, "/tmp/fakesample.exe")
    assert r3.name.startswith("mal_")
    assert len(r3.strings) >= 3  # 2 ioc + 1 critical api + 1 antidebug
    print(f"    [ok] generate_from_pe_findings: {r3.name} ({len(r3.strings)} strings)")

    print("[+] All checks passed.")
