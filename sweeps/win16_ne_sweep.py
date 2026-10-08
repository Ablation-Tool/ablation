#!/usr/bin/env python3
"""
sweeps/win16_ne_sweep.py — Windows 16-bit NE (New Executable) binary vulnerability sweep.

Adapted from pe_sweep.py for Win16 NE targets. Key differences:
  - Pure-Python NE header parser (lief does not support NE format)
  - CS_ARCH_X86 + CS_MODE_16 for 16-bit x86 disassembly
  - 16-bit function prologue detection: push bp; mov bp, sp (0x55 0x8B 0xEC / 0x55 0x89 0xE5)
  - NEAR call recovery: scan for E8 rel16 targets within the same segment
  - Import resolution via per-segment relocation records (module_ref + ordinal/name)
  - Win16 API ordinal → name table for KERNEL, USER, GDI, SHELL
  - No lief; no IAT; all struct parsing is manual

Pipeline
--------
Phase 1: Parse NE header → segment table → module reference table → imported names table.
Phase 2: For each CODE segment, parse relocation records to build segment import map.
Phase 3: Find function starts via prologue + NEAR call target recovery.
Phase 4: Disassemble with Capstone CS_MODE_16; resolve calls via reloc map.
Phase 5: Semantic sweep (same MiniLM-L6-v2 model as pe_sweep.py).

Usage
-----
Single binary:
    python3 sweeps/win16_ne_sweep.py /path/to/target.exe --vendor apple --product qtvr --version 2.1

Output:
    reports/sweep_ne_<vendor>_<product>_<version>_<ts>.md
"""
from __future__ import annotations

import argparse
import re
import struct
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

# ── Win16 API ordinal tables ───────────────────────────────────────────────────
# Source: Windows 3.1 SDK, Undocumented Windows (Schulman/Pietrek), public RE
# Incomplete — unknown ordinals appear as "MODULE!ordN"

_KERNEL_ORDS: Dict[int, str] = {
    1: "FatalExit", 2: "ExitKernel", 3: "GetVersion", 4: "LocalInit",
    5: "LocalAlloc", 6: "LocalReAlloc", 7: "LocalFree", 8: "LocalLock",
    9: "LocalUnlock", 10: "LocalSize", 11: "LocalHandle", 12: "LocalFlags",
    13: "LocalCompact", 14: "LocalNotify", 15: "GlobalInit",
    16: "GlobalAlloc", 17: "GlobalReAlloc", 18: "GlobalFree",
    19: "GlobalLock", 20: "GlobalUnlock", 21: "GlobalSize",
    22: "GlobalHandle", 23: "GlobalFlags", 24: "GlobalCompact",
    25: "GlobalFreeAll", 26: "GetGlobalTableBase", 27: "GlobalMasterHandle",
    28: "Yield", 29: "WaitEvent", 30: "PostEvent", 31: "SetPriority",
    32: "LockCurrentTask", 33: "SetTaskQueue", 34: "GetTaskQueue",
    35: "GetCurrentTask", 36: "GetCurrentPDB", 37: "SetTaskSignalProc",
    38: "EnableDOS", 39: "DisableDOS", 40: "IsWinMode",
    41: "CheckWindowsVersion", 42: "InitTask", 43: "GetTempDrive",
    44: "GetHugeShift", 45: "IsReadOnly", 46: "Nohookintapi",
    47: "IsTaskLocked", 48: "IsGlobalLocked",
    49: "LockData", 50: "UnlockData", 51: "GetCodeHandle",
    52: "DefineHandleTable", 53: "LoadLibrary", 54: "FreeLibrary",
    55: "GetLibraryName", 56: "GetLibraryHandle", 57: "GetNextLibrary",
    58: "GetDOSEnvironment", 59: "GetWinFlags", 60: "GetExeVersion",
    61: "RegisterWithServer", 62: "ExitWindows",
    63: "IsTask",
    64: "GetModuleHandle", 79: "GetModuleHandle",
    80: "GetProcAddress", 81: "MakeProcInstance", 82: "FreeProcInstance",
    83: "CallProcInstance", 84: "GetTempFileName",
    85: "AnsiUpper", 86: "AnsiLower", 87: "IsSpace",
    88: "lstrcpy", 89: "lstrcat", 90: "lstrlen",
    91: "_lclose", 92: "_lread", 93: "_lcreat", 94: "_llseek",
    95: "_lopen", 96: "_lwrite", 97: "lstrcmp",
    98: "lstrcmpi", 99: "AnsiUpperBuff", 100: "AnsiLowerBuff",
    101: "AnsiPrev", 102: "AnsiNext", 103: "GetModuleUsage",
    104: "GetModuleFileName", 105: "GetDebugger",
    109: "OpenSystemFile", 110: "CloseSystemFile",
    114: "IsWindowsOldApp",
    116: "GetNumTasks", 117: "GetTaskDS",
    120: "WritePrivateProfileString", 121: "GetPrivateProfileString",
    122: "WriteProfileString", 123: "GetProfileString",
    124: "GetPrivateProfileInt", 125: "GetProfileInt",
    126: "FindResource", 127: "LoadResource", 128: "LockResource",
    129: "FreeResource", 130: "AccessResource", 131: "SizeofResource",
    132: "AllocResource", 133: "SetResourceHandler",
    134: "InitAtomTable", 135: "FindAtom", 136: "AddAtom",
    137: "DeleteAtom", 138: "GetAtomName", 139: "GetAtomHandle",
    140: "OpenFile", 141: "OpenPathname",
    142: "DeletePathname",
    143: "GetSystemDirectory", 144: "GetWindowsDirectory",
    145: "SetErrorMode",
    146: "GetDriveType",
    147: "InquireSystem",
    148: "PrestoChangoSelector",
    149: "LongPtrAdd",
    150: "GetSelectorBase", 151: "SetSelectorBase",
    152: "GetSelectorLimit", 153: "SetSelectorLimit",
    154: "SwitchStackTo", 155: "SwitchStackBack",
    156: "PatchCodeHandle",
    157: "GlobalHandleToSel",
    158: "GetExePtr", 159: "GetLastDiskChange",
    160: "GetLPErrMode",
    161: "ValidateCodeSegments",
    162: "NoHookDOSCall",
    163: "DOS3Call",
    164: "NetBIOSCall",
    165: "GetCodeInfo",
    166: "GetWndExtents",
    167: "ValidateFreeSpaces",
    168: "ReplaceInst",
    169: "RegisterPtrace",
    170: "DebugBreak",
    171: "SwapRecording",
    172: "CVWBreak",
    173: "AllocSelectorArray",
    174: "FreeSelector",
    175: "AllocSelector",
    176: "FreeAllGDIMem",
    177: "PrestoChangoSelector",
    178: "GetModuleFileName",
    179: "GetModuleHandle",
    180: "GetInstanceData",
    181: "GlobalWire", 182: "GlobalUnWire",
    183: "EnableKernel",
    184: "DisableKernel",
    185: "MemoryRead",
    186: "MemoryWrite",
    187: "GetKernelProcTable",
    188: "OpenComm",
    189: "WriteComm",
    190: "ReadComm",
    191: "CloseComm",
    192: "GetCommError",
    193: "SetCommBreak",
    194: "ClearCommBreak",
    195: "BuildCommDCB",
    196: "GetCommState",
    197: "SetCommState",
    198: "GetCommEventMask",
    199: "SetCommEventMask",
    200: "EnableCommNotification",
    201: "GetCommTimeouts",
    202: "SetCommTimeouts",
}

_USER_ORDS: Dict[int, str] = {
    1: "RegisterClass", 2: "UnregisterClass", 3: "GetClassInfo",
    4: "GetClassWord", 5: "GetClassLong", 6: "SetClassWord",
    7: "SetClassLong", 8: "GetClassName",
    9: "SetWindowWord", 10: "GetWindowWord",
    11: "SetWindowLong", 12: "GetWindowLong",
    13: "SetWindowExtra", 14: "GetWindowExtra",
    15: "CreateWindow", 16: "DestroyWindow",
    17: "ShowWindow", 18: "FlashWindow",
    19: "MoveWindow", 20: "SetWindowPos",
    21: "UpdateWindow", 22: "SetFocus", 23: "GetFocus",
    24: "RemoveProp", 25: "GetProp", 26: "SetProp",
    27: "EnumProps", 28: "ClientToScreen", 29: "ScreenToClient",
    30: "WindowFromPoint", 31: "IsChild", 32: "GetParent",
    33: "IsWindowVisible", 34: "IsIconic",
    35: "GetWindowRect", 36: "GetClientRect",
    37: "GetWindowTask",
    38: "EnableWindow", 39: "IsWindowEnabled",
    40: "IsWindow",
    41: "SetWindowText", 42: "GetWindowText", 43: "GetWindowTextLength",
    44: "BeginPaint", 45: "EndPaint",
    46: "OpenClipboard", 47: "CloseClipboard",
    48: "EmptyClipboard", 49: "CountClipboardFormats",
    50: "EnumClipboardFormats", 51: "RegisterClipboardFormat",
    52: "GetClipboardFormatName", 53: "SetClipboardData",
    54: "GetClipboardData", 55: "GetClipboardOwner",
    56: "SetClipboardViewer", 57: "GetClipboardViewer",
    58: "ChangeClipboardChain", 59: "SendMessage",
    60: "PostMessage", 61: "PostAppMessage",
    62: "TranslateMessage", 63: "DispatchMessage",
    64: "GetMessage", 65: "PeekMessage",
    66: "ReplyMessage", 67: "TranslateAccelerator",
    68: "LoadAccelerators", 69: "SetWindowsHook",
    70: "DefWindowProc", 71: "CallWindowProc",
    72: "GetSystemMetrics", 73: "GetSysColor",
    74: "SetSysColors", 75: "GetWindowPlacement",
    76: "SetWindowPlacement", 77: "AdjustWindowRect",
    78: "AdjustWindowRectEx",
    79: "ScrollWindow", 80: "ScrollDC",
    81: "GetScrollPos", 82: "GetScrollRange",
    83: "SetScrollPos", 84: "SetScrollRange",
    85: "ShowScrollBar",
    86: "GetDC", 87: "GetWindowDC", 88: "ReleaseDC",
    89: "LoadBitmap", 90: "LoadCursor", 91: "LoadIcon",
    92: "LoadString", 93: "LoadMenu",
    94: "DefMenuProc", 95: "DrawMenuBar",
    96: "GetMenu", 97: "SetMenu",
    98: "AppendMenu", 99: "InsertMenu",
    100: "ModifyMenu", 101: "RemoveMenu", 102: "DeleteMenu",
    103: "CheckMenuItem", 104: "EnableMenuItem",
    105: "GetMenuItemCount", 106: "GetMenuItemID",
    107: "GetMenuState", 108: "GetMenuString",
    109: "CreateMenu", 110: "CreatePopupMenu",
    111: "DestroyMenu", 112: "TrackPopupMenu",
    113: "GetMenuCheckMarkDimensions",
    114: "CreateWindow", 115: "CreateWindowEx",
    116: "GetDlgItem", 117: "GetDlgItemInt",
    118: "GetDlgItemText", 119: "SendDlgItemMessage",
    120: "SetDlgItemInt", 121: "SetDlgItemText",
    122: "CheckDlgButton", 123: "CheckRadioButton",
    124: "IsDlgButtonChecked", 125: "DialogBox",
    126: "EndDialog", 127: "CreateDialog",
    128: "IsDialogMessage", 129: "GetDialogBaseUnits",
    130: "MapDialogRect", 131: "DlgDirList",
    132: "DlgDirSelect",
    133: "OpenComm", 134: "CloseComm",
    135: "MessageBox", 136: "MessageBeep",
    137: "WinHelp",
    138: "ExitWindows",
    139: "DestroyWindow",
    140: "ShowOwnedPopups",
    141: "SetActiveWindow", 142: "GetActiveWindow",
    143: "BringWindowToTop",
    144: "GetNextWindow",
    145: "EnumWindows", 146: "EnumChildWindows",
    147: "EnumTaskWindows",
    148: "GetDesktopHwnd", 149: "GetDesktopWindow",
    150: "SetForegroundWindow", 151: "GetForegroundWindow",
    152: "SetCapture", 153: "ReleaseCapture", 154: "GetCapture",
    155: "SetCaretPos", 156: "GetCaretPos",
    157: "HideCaret", 158: "ShowCaret",
    159: "SetCaretBlinkTime", 160: "GetCaretBlinkTime",
    161: "SetCursor", 162: "GetCursor",
    163: "ClipCursor", 164: "GetCursorPos",
    165: "GetCursorInfo", 166: "SetCursorPos",
    167: "ShowCursor", 168: "CreateCaret",
    169: "DestroyCaret",
    170: "OpenIcon",
    171: "CloseWindow",
    172: "ArrangeIconicWindows",
    173: "TileChildWindows",
    174: "CascadeChildWindows",
    175: "DrawIcon",
    176: "InvalidateRect", 177: "InvalidateRgn",
    178: "ValidateRect", 179: "ValidateRgn",
    180: "GetUpdateRect",
    181: "GetUpdateRgn", 182: "ExcludeUpdateRgn",
    183: "GetBkColor",
    184: "SetBkColor",
    185: "RedrawWindow",
    186: "InvalidateMappedRegion",
    187: "GetClassInfo",
    188: "GetKeyState", 189: "GetAsyncKeyState",
    190: "GetKeyboardState", 191: "SetKeyboardState",
    192: "GetKeyboardType",
    193: "GetKeyNameText",
    194: "KeyboardLayout",
    195: "OemToAnsi", 196: "AnsiToOem",
    197: "AnsiUpper", 198: "AnsiLower",
    199: "AnsiUpperBuff", 200: "AnsiLowerBuff",
    201: "AnsiPrev", 202: "AnsiNext",
    203: "IsCharAlpha", 204: "IsCharAlphaNumeric",
    205: "IsCharUpper", 206: "IsCharLower",
    207: "LoadKeyboardLayout",
    208: "ActivateKeyboardLayout",
    209: "UnloadKeyboardLayout",
    210: "GetKeyboardLayoutName",
    211: "GetKeyboardLayoutList",
    212: "GetKeyboardLayout",
    213: "CreateIcon", 214: "DestroyIcon",
    215: "LoadCursorFromFile",
    216: "CreateCursorIconIndirect",
    217: "CopyCursor",
    218: "CopyIcon",
    219: "GetIconInfo",
    220: "GetCursorInfo",
    221: "FindWindow", 222: "GetWindow",
    223: "EnumParentWindows",
    224: "GetTopWindow",
    225: "GetNextDlgTabItem",
    226: "GetNextDlgGroupItem",
    227: "SetWindowsHookEx",
    228: "UnhookWindowsHookEx",
    229: "CallNextHookEx",
    230: "DefHookProc",
    231: "CallMsgFilter",
    232: "RegisterHotKey", 233: "UnregisterHotKey",
    234: "SetDoubleClickTime", 235: "GetDoubleClickTime",
    236: "SetTimer", 237: "KillTimer",
    238: "WinExec",
    239: "OpenSound", 240: "CloseSound",
    241: "StartSound", 242: "StopSound",
    243: "WaitSoundState", 244: "SyncAllVoices",
    245: "CountVoiceNotes", 246: "GetThresholdEvent",
    247: "GetThresholdStatus", 248: "SetVoiceAccent",
    249: "SetVoiceEnvelope", 250: "SetSoundNoise",
    251: "SetVoiceSound", 252: "StartSound",
    253: "SetVoiceNote", 254: "GetThresholdEvent",
    255: "DrawText",
    256: "TextOut", 257: "ExtTextOut",
    258: "TabbedTextOut",
    259: "GetTabbedTextExtent",
    260: "DrawTextEx",
    261: "GrayString",
    262: "DrawFocusRect",
    263: "DrawFrame",
    264: "DrawEdge",
    265: "DrawFrameControl",
    266: "DrawState",
    267: "SetRect", 268: "SetRectEmpty",
    269: "CopyRect", 270: "IsRectEmpty",
    271: "PtInRect", 272: "OffsetRect",
    273: "InflateRect", 274: "IntersectRect",
    275: "UnionRect", 276: "SubtractRect",
    277: "EqualRect",
    278: "FillRect", 279: "FrameRect",
    280: "InvertRect",
    281: "LoadLibrary",
    282: "FreeLibrary",
    283: "GetProcAddress",
    284: "SetSysModalWindow",
    285: "GetSysModalWindow",
    286: "GetSystemMenu",
    287: "EnableMenuItem",
    288: "CheckMenuItem",
    289: "AppendMenu",
    290: "InsertMenu",
    291: "RemoveMenu",
    292: "ModifyMenu",
    293: "HiliteMenuItem",
    294: "GetMenuItemCount",
    295: "GetMenuItemID",
    296: "GetMenuString",
    297: "GetMenuState",
    298: "DrawMenuBar",
    299: "CreateMenu",
    300: "DestroyMenu",
    301: "DragDetect",
    302: "DragObject",
    303: "DragQueryFile",
    304: "DropFinish",
    305: "DropObject",
    306: "QueryDropObject",
    307: "LockWindowUpdate",
    308: "ReleaseCapture",
    309: "ScrollWindowEx",
    310: "SubclassWindow",
    311: "SubclassDialog",
    312: "SubclassCombo",
    313: "SubclassEdit",
    314: "SubclassListbox",
    315: "GetMenuBarInfo",
    411: "GetWindowWord",
    420: "SetWindowWord",
}

_GDI_ORDS: Dict[int, str] = {
    1: "DeleteDC", 2: "CreateDC", 3: "CreateCompatibleDC",
    4: "GetDeviceCaps", 5: "CancelDC",
    10: "CreateBitmap", 11: "CreateBitmapIndirect",
    12: "CreateCompatibleBitmap", 13: "CreateDIBitmap",
    14: "SetBitmapDimension", 15: "GetBitmapDimension",
    16: "DeleteObject", 17: "GetObject",
    18: "CreateSolidBrush", 19: "CreateHatchBrush",
    20: "CreatePatternBrush", 21: "CreateBrushIndirect",
    22: "CreateFont", 23: "CreateFontIndirect",
    24: "GetTextMetrics", 25: "GetCharWidth",
    26: "GetTextExtent", 27: "GetTextExtentPoint",
    28: "GetTabbedTextExtent",
    29: "SelectObject", 30: "GetStockObject",
    31: "CreatePen", 32: "CreatePenIndirect",
    33: "CreateRgn",
    34: "CombineRgn", 35: "OffsetRgn",
    36: "SetRectRgn", 37: "FillRgn", 38: "PaintRgn",
    39: "EqualRgn", 40: "GetRgnBox",
    41: "SelectClipRgn", 42: "GetClipRgn",
    43: "PtVisible", 44: "RectVisible",
    45: "SetTextColor", 46: "GetTextColor",
    47: "SetBkColor", 48: "GetBkColor",
    49: "SetBkMode", 50: "GetBkMode",
    51: "SetROP2", 52: "GetROP2",
    53: "SetPolyFillMode", 54: "GetPolyFillMode",
    55: "SetStretchBltMode", 56: "GetStretchBltMode",
    57: "SetTextCharacterExtra", 58: "GetTextCharacterExtra",
    59: "SetTextJustification",
    60: "SetTextAlign", 61: "GetTextAlign",
    62: "SetMapMode", 63: "GetMapMode",
    64: "SetWindowOrg", 65: "GetWindowOrg",
    66: "SetWindowExt", 67: "GetWindowExt",
    68: "SetViewportOrg", 69: "GetViewportOrg",
    70: "SetViewportExt", 71: "GetViewportExt",
    72: "OffsetWindowOrg", 73: "ScaleWindowExt",
    74: "OffsetViewportOrg", 75: "ScaleViewportExt",
    76: "SetMapperFlags", 77: "IntersectClipRect",
    78: "ExcludeClipRect", 79: "OffsetClipRgn",
    80: "MoveTo", 81: "LineTo",
    82: "Rectangle", 83: "Ellipse",
    84: "RoundRect", 85: "Arc",
    86: "Chord", 87: "Pie",
    88: "BitBlt", 89: "StretchBlt",
    90: "PatBlt", 91: "Polygon",
    92: "Polyline", 93: "PolyPolygon",
    94: "FloodFill", 95: "ExtFloodFill",
    96: "SetPixel", 97: "GetPixel",
    98: "DrawIcon",
    99: "TextOut", 100: "ExtTextOut",
    101: "DrawText",
    102: "CreateMetaFile", 103: "CloseMetaFile",
    104: "DeleteMetaFile", 105: "PlayMetaFile",
    106: "GetMetaFile", 107: "CopyMetaFile",
    108: "Escape",
    109: "GetDCOrg", 110: "SaveDC",
    111: "RestoreDC",
    112: "SelectPalette", 113: "RealizePalette",
    114: "CreatePalette", 115: "UpdateColors",
    116: "AnimatePalette", 117: "GetPaletteEntries",
    118: "SetPaletteEntries", 119: "GetSystemPaletteEntries",
    120: "GetNearestPaletteIndex", 121: "GetNearestColor",
    122: "ResizePalette",
    123: "GetRGBMask", 124: "SetRGBMask",
}

_SHELL_ORDS: Dict[int, str] = {
    1: "RegOpenKey", 2: "RegCreateKey", 3: "RegDeleteKey",
    4: "RegCloseKey", 5: "RegSetValue", 6: "RegDeleteValue",
    7: "RegQueryValue", 8: "RegEnumKey",
    9: "ShellAbout", 10: "ShellExecute",
    11: "FindExecutable", 12: "ShellExecute",
    13: "AboutDlgProc", 14: "ExtractAssociatedIcon",
    20: "DoEnvironmentSubst", 22: "ExtractIcon",
    26: "StrToOleStr", 27: "OleStrToStr",
    30: "DragQueryFile", 31: "DragDropFile",
    32: "DragFinish", 33: "DragQueryPoint",
    36: "DragAcceptFiles", 37: "SHGetFileInfo",
}

_MODULE_ORD_TABLES: Dict[str, Dict[int, str]] = {
    "KERNEL": _KERNEL_ORDS,
    "USER": _USER_ORDS,
    "GDI": _GDI_ORDS,
    "SHELL": _SHELL_ORDS,
    "KRNL286": _KERNEL_ORDS,
    "KRNL386": _KERNEL_ORDS,
}


def _resolve_ordinal(module_name: str, ordinal: int) -> str:
    tbl = _MODULE_ORD_TABLES.get(module_name.upper(), {})
    name = tbl.get(ordinal)
    return f"{module_name}!{name}" if name else f"{module_name}!ord_{ordinal}"


# ── Win16 NE vulnerability profiles ───────────────────────────────────────────

WIN16_NE_PROFILES: List[Tuple[str, str]] = [
    ("win16_lstrcpy_overflow",
     "FUNC | calls: lstrcpy lstrcat lstrcpyn | "
     "vuln: 16-bit string copied into fixed-size local or global buffer without length "
     "check; lstrcpy has no bounds parameter and overwrites adjacent data in the "
     "Windows 3.x DGROUP data segment; input from clipboard, dialog edit control, "
     "or file path passed directly to lstrcpy"),

    ("win16_globalalloc_overflow",
     "FUNC | calls: GlobalAlloc LocalAlloc GlobalReAlloc | "
     "vuln: 16-bit allocation size computed from arithmetic on user-controlled value "
     "without overflow check; 16-bit wrap at 64KB causes small allocation then "
     "buffer overflow when data is written; size derived from file header, message, "
     "or dialog input"),

    ("win16_getdlgitemtext_overflow",
     "FUNC | calls: GetDlgItemText GetWindowText | "
     "vuln: Win16 API copies window or dialog text into caller-supplied buffer; "
     "buffer on stack or in DGROUP data segment with size smaller than maximum "
     "window text; no bounds check on dialog item text length"),

    ("win16_openfile_path_overflow",
     "FUNC | calls: OpenFile _lopen _lcreat | "
     "vuln: file path argument to OpenFile constructed from user input without "
     "length bounds; Win16 OpenFile takes OFSTRUCTs with fixed 128-byte path field; "
     "path from command line, clipboard, or URL handler overflows OFSTRUCT buffer"),

    ("win16_winexec_injection",
     "FUNC | calls: WinExec ExecProgram ShellExecute | "
     "vuln: command string passed to WinExec built from user-controlled data (file "
     "path, URL, registry value) without sanitization; Win16 WinExec spawns program "
     "via command line; attacker-crafted movie file or URL triggers execution of "
     "arbitrary Windows application"),

    ("win16_writeprofile_injection",
     "FUNC | calls: WritePrivateProfileString WriteProfileString | "
     "vuln: application name, section, or value written to Windows .INI file from "
     "user-controlled input; INI injection can alter system configuration or "
     "DLL search paths affecting other applications"),

    ("win16_message_format",
     "FUNC | calls: wsprintf MessageBox SetWindowText | "
     "vuln: user-controlled string used as format argument to wsprintf in Win16; "
     "stack-based format string vulnerability in Windows 3.x; "
     "attacker-crafted movie file title or metadata triggers format string write"),

    ("win16_resource_overflow",
     "FUNC | calls: FindResource LoadResource SizeofResource LockResource | "
     "vuln: Win16 resource data loaded from file without validating size against "
     "allocation; resource header size field in crafted executable or DLL causes "
     "heap or DGROUP data segment overflow when resource data is copied"),
]


def _build_win16_profiles() -> List[Tuple[str, str]]:
    try:
        from sweeps.base_sweep import VULN_PROFILES as BASE
    except ImportError:
        BASE = []
    seen = {name for name, _ in BASE}
    extra = [(n, q) for n, q in WIN16_NE_PROFILES if n not in seen]
    return list(BASE) + extra


# ── NE format parsing ──────────────────────────────────────────────────────────

class NEBinary:
    """Parsed Win16 NE binary."""

    def __init__(self, path: str):
        self.path = path
        self.data = Path(path).read_bytes()
        self._parse()

    def _parse(self):
        d = self.data
        ne_off = struct.unpack_from('<H', d, 0x3c)[0]
        if d[ne_off:ne_off+2] != b'NE':
            raise ValueError(f"Not a Win16 NE binary: magic={d[ne_off:ne_off+2].hex()}")
        self.ne_off = ne_off
        ne = d[ne_off:]

        self.seg_count    = struct.unpack_from('<H', ne, 0x1c)[0]
        self.mod_ref_cnt  = struct.unpack_from('<H', ne, 0x1e)[0]
        self.seg_tbl_off  = struct.unpack_from('<H', ne, 0x22)[0]
        self.mod_ref_off  = struct.unpack_from('<H', ne, 0x28)[0]
        self.imp_names_off= struct.unpack_from('<H', ne, 0x2a)[0]
        self.align_shift  = struct.unpack_from('<H', ne, 0x32)[0]
        if self.align_shift == 0:
            self.align_shift = 9  # default 512-byte alignment

        # Build module name list (1-indexed)
        self.module_names: List[str] = [""]   # index 0 unused
        mod_ref_abs = ne_off + self.mod_ref_off
        for i in range(self.mod_ref_cnt):
            name_off = struct.unpack_from('<H', d, mod_ref_abs + i * 2)[0]
            name_abs = ne_off + self.imp_names_off + name_off
            if name_abs >= len(d):
                continue
            nlen = d[name_abs]
            name = d[name_abs + 1: name_abs + 1 + nlen].decode('ascii', 'replace')
            self.module_names.append(name)

        # Build segment list
        self.segments = []
        seg_tbl_abs = ne_off + self.seg_tbl_off
        for i in range(self.seg_count):
            off = seg_tbl_abs + i * 8
            page_off  = struct.unpack_from('<H', d, off)[0]
            file_size = struct.unpack_from('<H', d, off + 2)[0] or 65536
            flags     = struct.unpack_from('<H', d, off + 4)[0]
            file_offset = page_off << self.align_shift
            is_code   = not (flags & 0x0001)
            has_reloc = bool(flags & 0x0100)
            self.segments.append({
                'index': i + 1,
                'file_offset': file_offset,
                'file_size': file_size,
                'is_code': is_code,
                'has_reloc': has_reloc,
                'flags': flags,
            })

    def build_segment_import_map(self, seg: dict) -> Dict[int, str]:
        """Parse relocation records for a segment → {source_offset: 'MOD!func'}."""
        if not seg['has_reloc']:
            return {}
        d = self.data
        seg_end = seg['file_offset'] + seg['file_size']
        reloc_count = struct.unpack_from('<H', d, seg_end)[0]
        import_map: Dict[int, str] = {}
        rec_off = seg_end + 2
        for _ in range(reloc_count):
            if rec_off + 8 > len(d):
                break
            # src_type = d[rec_off]        # source type (FAR_ADDR, OFFSET, etc.)
            flags    = d[rec_off + 1]
            src_off  = struct.unpack_from('<H', d, rec_off + 2)[0]
            target_type = flags & 0x03    # 0=INTERNAL, 1=IMPORTORDINAL, 2=IMPORTNAME
            if target_type == 1:
                mod_ref = struct.unpack_from('<H', d, rec_off + 4)[0]
                ordinal = struct.unpack_from('<H', d, rec_off + 6)[0]
                if 1 <= mod_ref <= len(self.module_names) - 1:
                    mod_name = self.module_names[mod_ref]
                    import_map[src_off] = _resolve_ordinal(mod_name, ordinal)
                else:
                    import_map[src_off] = f"mod{mod_ref}!ord_{ordinal}"
            elif target_type == 2:
                mod_ref  = struct.unpack_from('<H', d, rec_off + 4)[0]
                name_off = struct.unpack_from('<H', d, rec_off + 6)[0]
                name_abs = self.ne_off + self.imp_names_off + name_off
                if name_abs >= len(d):
                    rec_off += 8
                    continue
                nlen = d[name_abs]
                name = d[name_abs + 1: name_abs + 1 + nlen].decode('ascii', 'replace')
                if 1 <= mod_ref <= len(self.module_names) - 1:
                    mod_name = self.module_names[mod_ref]
                    import_map[src_off] = f"{mod_name}!{name}"
                else:
                    import_map[src_off] = name
            rec_off += 8
        return import_map

    def code_segments(self) -> List[dict]:
        return [s for s in self.segments if s['is_code'] and s['file_offset'] > 0]


# ── 16-bit function start detection ───────────────────────────────────────────

def _find_prologue_starts_x86_16(
    data: bytes, start_offset: int, end_offset: int
) -> List[int]:
    """
    Return file offsets of likely x86-16 function starts.

    Detects:
      0x55 0x8B 0xEC  — push bp; mov bp, sp  (MSVC form)
      0x55 0x89 0xE5  — push bp; mov bp, sp  (GCC/Watcom form)
    Both forms are identical bytes in 16-bit vs 32-bit; CS_MODE_16 decodes correctly.
    """
    hits = []
    end = min(end_offset, len(data) - 3)
    i = start_offset
    while i < end:
        if data[i] == 0x55:
            b12 = data[i + 1: i + 3]
            if b12 == b"\x8B\xEC" or b12 == b"\x89\xE5":
                hits.append(i)
        i += 1
    return hits


def _find_near_call_targets_x86_16(
    data: bytes, seg_file_off: int, seg_size: int
) -> set:
    """
    Recover function starts missed by prologue detection.

    Scans for NEAR CALL rel16 (opcode 0xE8) within segment data.
    Returns file offsets of call targets that land within the segment.
    Note: rel16 is signed 16-bit; target = (next_insn_offset + rel16) mod 65536 within seg.
    """
    seg_end = seg_file_off + seg_size
    recovered: set = set()
    for i in range(seg_file_off, min(seg_end - 2, len(data) - 2)):
        if data[i] == 0xE8:
            rel16 = int.from_bytes(data[i + 1: i + 3], 'little', signed=True)
            # next instruction is at offset (i - seg_file_off + 3) within segment
            next_seg_off = (i - seg_file_off) + 3
            target_seg_off = (next_seg_off + rel16) & 0xFFFF
            if 0 <= target_seg_off < seg_size:
                recovered.add(seg_file_off + target_seg_off)
    return recovered


# ── FAR call source offset → import name ──────────────────────────────────────

_FAR_CALL_RE = re.compile(r'ptr 0x([0-9a-f]+):0x([0-9a-f]+)', re.I)
_NEAR_CALL_RE = re.compile(r'^0x([0-9a-f]+)$')


def _resolve_ne_call(op_str: str, import_map: Dict[int, str], seg_file_off: int,
                     call_file_off: int) -> str:
    """
    Resolve a Capstone x86-16 CALL operand to an import name.

    FAR calls: the immediate operand bytes at call_file_off+1 contain the target;
    we look up call_file_off - seg_file_off in the relocation map (reloc source = call opcode + 1).
    NEAR calls: direct offset — no reloc lookup needed for semantic purposes.
    """
    # For FAR CALL (0x9A), the relocation source is at the byte after the opcode
    far_reloc_key = (call_file_off + 1) - seg_file_off
    if far_reloc_key in import_map:
        return import_map[far_reloc_key]
    # Try without the +1 offset
    reloc_key = call_file_off - seg_file_off
    if reloc_key in import_map:
        return import_map[reloc_key]
    # For near direct call, return the raw address
    m = _NEAR_CALL_RE.match(op_str.strip())
    if m:
        return f"near_0x{m.group(1)}"
    return op_str


# ── function extraction (NE / x86-16) ────────────────────────────────────────

def _extract_functions_ne(
    ne: NEBinary,
    max_bytes: int = 512,
) -> List[dict]:
    """
    Disassemble all code segments; return function dicts compatible with pe_sweep.py.
    """
    import capstone
    from ablation.analyzers import describe_function

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    md.detail = False

    funcs = []
    data = ne.data

    for seg in ne.code_segments():
        seg_file_off = seg['file_offset']
        seg_size     = seg['file_size']
        seg_idx      = seg['index']

        if seg_file_off + seg_size > len(data):
            print(f"  [!] Seg {seg_idx}: file offset {seg_file_off:#x} + size {seg_size:#x} "
                  f"exceeds file length {len(data):#x}")
            continue

        import_map = ne.build_segment_import_map(seg)

        # Function starts
        prologue_offs = _find_prologue_starts_x86_16(data, seg_file_off,
                                                      seg_file_off + seg_size)
        near_offs = _find_near_call_targets_x86_16(data, seg_file_off, seg_size)
        prologue_set = set(prologue_offs)
        all_offs = sorted(prologue_set | near_offs)

        if not all_offs:
            print(f"  [*] Seg {seg_idx}: 0 functions found (no prologues/call targets)")
            continue

        fpo_count = len(near_offs - prologue_set)
        if fpo_count:
            print(f"  [*] Seg {seg_idx}: +{fpo_count} call-target functions "
                  f"(total {len(all_offs)} incl. {len(prologue_set)} prologue)")

        for file_off in all_offs:
            is_fpo = file_off not in prologue_set
            seg_off = file_off - seg_file_off
            # VA in Win16 = segment_number : offset (we use flat seg*0x1000 + off for display)
            va = (seg_idx << 16) | seg_off

            chunk = data[file_off: file_off + max_bytes]
            lines, calls, str_refs = [], [], []
            cur_file_off = file_off

            for insn in md.disasm(chunk, seg_off):
                text = f"{insn.mnemonic} {insn.op_str}".strip()
                lines.append(text)
                cur_file_off = file_off + (insn.address - seg_off)

                if insn.mnemonic in ('call', 'callf', 'lcall'):
                    resolved = _resolve_ne_call(insn.op_str, import_map,
                                                seg_file_off, cur_file_off)
                    calls.append(resolved)

                # String push detection: push imm16 — in 16-bit, strings are in DS
                # We capture string from data segment textually if we can match

                if insn.mnemonic in ('ret', 'retf', 'retn'):
                    break

            if len(lines) < 4:
                continue

            role = "FPO" if is_fpo else "FUNC"
            desc = describe_function(
                name=f"func_{va:08x}",
                role=role,
                call_targets=calls,
                strings=str_refs,
                asm_lines=lines,
            )
            funcs.append({
                'va': va,
                'desc': desc,
                'calls': calls,
                'strings': str_refs,
                'fpo': is_fpo,
                'seg': seg_idx,
                'seg_off': seg_off,
            })

    return funcs


# ── semantic sweep ────────────────────────────────────────────────────────────

def _semantic_sweep_ne(
    funcs: List[dict],
    model,
    profiles: List[Tuple[str, str]],
    top_k: int = 5,
) -> Dict[str, List[Tuple[float, int, List[str], str]]]:
    from ablation.analyzers import FindingRegistry

    registry = FindingRegistry()
    try:
        if not funcs:
            return {}

        print(f"  [*] {len(funcs)} functions; encoding ...")
        corpus = model.encode(
            [f['desc'] for f in funcs],
            normalize_embeddings=True,
            batch_size=128,
            show_progress_bar=False,
        ).astype(np.float32)

        all_profiles = list(profiles)
        prior = registry.prior_queries(top_n=15)
        for i, desc in enumerate(prior):
            label = (
                f"prior:{i:02d}:{desc[:35].replace(' ', '_').replace('|', '').strip('_')}"
            )
            all_profiles.append((label, desc))
        if prior:
            print(f"  [*] +{len(prior)} prior-finding queries from registry")

        n_built = registry.build_embeddings(model)
        if n_built:
            print(f"  [*] Registry embeddings: {n_built} entries cached")

        results: Dict = {}
        for name, query in all_profiles:
            qvec = model.encode(query, normalize_embeddings=True).astype(np.float32)
            scores = corpus @ qvec
            top = np.argsort(scores)[::-1][:top_k]
            results[name] = [
                (float(scores[i]), funcs[i]['va'], funcs[i]['calls'], funcs[i]['desc'])
                for i in top
            ]

        return results
    finally:
        registry.close()


# ── per-binary sweep orchestrator ────────────────────────────────────────────

def _sweep_ne_one(
    binary_path: str,
    model,
    profiles: List[Tuple[str, str]],
    top_k: int,
) -> dict:
    name = Path(binary_path).name
    print(f"\n[{name}] Win16 NE")

    result: dict = {
        'path': binary_path,
        'arch': 'Win16 NE i8086',
        'functions_found': 0,
        'segment_count': 0,
        'modules': [],
        'semantic': {},
        'error': None,
    }

    try:
        ne = NEBinary(binary_path)
    except Exception as e:
        result['error'] = f"NE parse failed: {e}"
        print(f"  [!] {e}")
        return result

    result['segment_count'] = ne.seg_count
    result['modules'] = ne.module_names[1:]
    code_segs = ne.code_segments()

    print(f"  [*] Segments: {ne.seg_count} total, {len(code_segs)} code")
    print(f"  [*] Imports from: {', '.join(ne.module_names[1:])}")

    # Build import summary for display
    total_imports = 0
    for seg in code_segs:
        imp = ne.build_segment_import_map(seg)
        total_imports += len(imp)
    print(f"  [*] Relocation entries (imports): {total_imports}")

    try:
        funcs = _extract_functions_ne(ne)
        result['functions_found'] = len(funcs)
        print(f"  [*] Functions extracted: {len(funcs)}")
    except Exception as e:
        result['error'] = f"function extraction: {e}\n{traceback.format_exc()}"
        print(f"  [!] Extraction failed: {e}")
        return result

    if not funcs:
        print(f"  [!] No functions extracted — skipping semantic sweep")
        return result

    try:
        print(f"  [*] Semantic sweep ({len(profiles)} profiles) ...")
        result['semantic'] = _semantic_sweep_ne(funcs, model, profiles, top_k=top_k)
    except Exception as e:
        result['error'] = f"semantic: {e}\n{traceback.format_exc()}"
        print(f"  [!] Semantic sweep failed: {e}")

    return result


# ── report generation ─────────────────────────────────────────────────────────

def _render_report(
    results: List[dict],
    vendor: str,
    product: str,
    version: str,
    threshold: float = 0.30,
) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Win16 NE Sweep Report",
        "",
        f"**Vendor:** {vendor}  **Product:** {product}  **Version:** {version}",
        f"**Generated:** {ts}  **Targets:** {len(results)} binaries",
        "",
        "---",
        "",
    ]

    total_hits = 0
    for r in results:
        name = Path(r['path']).name
        lines.append(f"## {name}")
        lines.append("")
        segs = r.get('segment_count', '?')
        funcs = r.get('functions_found', 0)
        mods = ', '.join(r.get('modules', []))
        lines.append(
            f"**Path:** `{r['path']}`  **Arch:** `{r['arch']}`  "
            f"**Segments:** {segs}  **Functions found:** {funcs}"
        )
        if mods:
            lines.append(f"**Imports from:** {mods}")
        lines.append("")

        if r.get('error'):
            lines.append(f"**ERROR:** `{r['error']}`")
            lines.append("")
            continue

        if not r.get('semantic'):
            lines.append("*(no functions extracted)*")
            lines.append("")
            continue

        lines.append("### Semantic Sweep")
        lines.append("")

        for profile_name, hits in r['semantic'].items():
            top = hits[0] if hits else None
            if not top or top[0] < threshold:
                continue
            score, va, calls, desc = top
            total_hits += 1

            # Display VA as seg:offset
            seg_idx = (va >> 16) & 0xFFFF
            seg_off = va & 0xFFFF
            va_str = f"seg{seg_idx}:{seg_off:#06x}"

            call_str = (
                ", ".join(c for c in calls if c and not c.startswith("near_"))[:120]
                if calls else "none"
            )
            lines.append(
                f"**{profile_name}** — top score `{score:.4f}` @ `{va_str}`"
            )
            lines.append(f"  calls: {call_str}")
            lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        f"*[*] Summary: {len(results)} binary(ies) swept, "
        f"{total_hits} semantic hit(s) >= {threshold}*"
    )
    return "\n".join(lines)


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description="Win16 NE binary vulnerability sweep")
    ap.add_argument("target", help="Path to a Win16 NE .exe / .dll / .qtc / .x16")
    ap.add_argument("--vendor",  required=True)
    ap.add_argument("--product", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--top-k",   type=int, default=5)
    ap.add_argument("--threshold", type=float, default=0.30)
    args = ap.parse_args()

    # Load model
    print("[*] Loading sentence transformer (all-MiniLM-L6-v2) ...")
    from sentence_transformers import SentenceTransformer
    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device="cpu")
    print("[*] Model loaded")

    profiles = _build_win16_profiles()
    print(f"[*] Profiles: {len(profiles)} (base + {len(WIN16_NE_PROFILES)} Win16-specific)")

    result = _sweep_ne_one(args.target, model, profiles, top_k=args.top_k)

    # Write report
    reports_dir = Path(__file__).parent.parent / "reports"
    reports_dir.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    safe_product = re.sub(r'[^a-z0-9_\-]', '', args.product.lower().replace(' ', '_'))
    safe_vendor = re.sub(r'[^a-z0-9_\-]', '', args.vendor.lower())
    out_name = f"sweep_ne_{safe_vendor}_{safe_product}_{args.version}_{ts}.md"
    out_path = reports_dir / out_name

    report = _render_report([result], args.vendor, args.product, args.version,
                            threshold=args.threshold)
    out_path.write_text(report, encoding='utf-8')
    print(f"\n[*] Report written to reports/{out_name}")

    hits = sum(
        1 for hits in result.get('semantic', {}).values()
        if hits and hits[0][0] >= args.threshold
    )
    print(f"[*] Summary: 1 binary swept, {hits} semantic hit(s) >= {args.threshold}")


if __name__ == "__main__":
    main()
