#!/usr/bin/env python3
"""
binder_scanner.py -- Binder IPC attack surface scanner for Android APKs.

Maps exported Binder service interfaces from DEX class definitions and the
Android manifest. Binder is Android's primary IPC mechanism; exported services
are the first-hop attack surface for privilege escalation and auth bypass.

Detection:
  1. ClassDef superclass in Service/IntentService → potential Binder server
  2. ClassDef extending android.os.Binder directly → raw transaction handler
  3. Inner classes named $Stub extending Binder → AIDL-generated dispatchers
  4. onTransact MethodRef presence → integer-dispatched transaction handler
  5. Messenger usage → message-passing IPC

Exported services are cross-referenced against the manifest exported component
list to separate intra-app-only services from inter-app-accessible ones.

Usage:
    from ablation.analyzers.binder_scanner import BinderScanner

    scanner = BinderScanner.from_path('/path/to/app.apk')
    findings = scanner.scan()
    print(BinderScanner.report(findings))
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set

from ablation.core.apk_parser import APKParser


HIGH   = "HIGH"
MEDIUM = "MEDIUM"
INFO   = "INFO"


# ── Binder-related class names (descriptor form) ──────────────────────────────

_SERVICE_SUPERS: Set[str] = {
    "Landroid/app/Service;",
    "Landroid/app/IntentService;",
    "Landroid/app/JobService;",
}

_BINDER_CLASS    = "Landroid/os/Binder;"
_MESSENGER_CLASS = "Landroid/os/Messenger;"
_IBINDER_CLASS   = "Landroid/os/IBinder;"


@dataclass
class BinderFinding:
    severity: str
    category: str
    title: str
    detail: str
    source: str
    evidence: str


class BinderScanner:
    """Binder IPC attack surface scanner for Android APKs."""

    def __init__(self, apk: APKParser) -> None:
        self._apk = apk

    @classmethod
    def from_path(cls, path) -> "BinderScanner":
        return cls(APKParser.from_path(str(path)))

    def scan(self) -> List[BinderFinding]:
        findings: List[BinderFinding] = []

        mf = self._apk.parse_manifest()
        exported_names: Set[str] = {
            c.name for c in mf.exported_components()
        }

        # Phase 1: class hierarchy scan
        service_classes:   List[str] = []
        binder_classes:    List[str] = []
        aidl_stub_classes: List[str] = []

        for dex in self._apk.iter_dex():
            for cls in dex.iter_classes():
                cname = cls.class_name
                super_ = cls.superclass

                if super_ in _SERVICE_SUPERS:
                    service_classes.append(cname)
                elif super_ == _BINDER_CLASS:
                    if cname.endswith("$Stub;") or "$Stub$" in cname:
                        aidl_stub_classes.append(cname)
                    else:
                        binder_classes.append(cname)

        # Phase 2: method reference scan for onTransact + Messenger
        transact_classes:   Set[str] = set()
        messenger_found:    bool = False

        for dex in self._apk.iter_dex():
            for m in dex.iter_method_refs():
                if m.method_name == "onTransact":
                    transact_classes.add(m.class_name)
                if m.class_name == _MESSENGER_CLASS:
                    messenger_found = True

        # Phase 3: emit findings

        # Exported services (cross-reference with manifest)
        for sc in service_classes:
            # Convert descriptor "Lcom/foo/Bar;" → "com.foo.Bar"
            java_name = sc.lstrip("L").rstrip(";").replace("/", ".")
            is_exported = any(java_name.endswith(e) or e.endswith(java_name)
                              for e in exported_names)
            if is_exported:
                findings.append(BinderFinding(
                    severity=HIGH,
                    category="binder/exported_service",
                    title=f"Exported Service: {java_name}",
                    detail=(
                        f"Service is declared exported=true in the manifest. Any app on the device "
                        f"can bind to it and invoke its Binder interface. "
                        f"Verify onBind() returns an IBinder and check what the bound interface "
                        f"exposes — look for missing permission checks in onStartCommand() or "
                        f"the AIDL interface's methods."
                    ),
                    source=sc,
                    evidence=f"manifest exported + Service subclass",
                ))
            else:
                findings.append(BinderFinding(
                    severity=MEDIUM,
                    category="binder/service_subclass",
                    title=f"Service subclass (not exported): {java_name}",
                    detail=(
                        "Service subclass not marked exported=true in manifest. "
                        "Only accessible within the app unless a component explicitly sets "
                        "android:exported=\"true\" at runtime or via intent-filter. "
                        "Confirm manifest — exported status can be set implicitly by intent-filters."
                    ),
                    source=sc,
                    evidence=f"superclass={super_}",
                ))

        # Raw Binder implementations
        for bc in binder_classes:
            java_name = bc.lstrip("L").rstrip(";").replace("/", ".")
            findings.append(BinderFinding(
                severity=HIGH,
                category="binder/raw_transact",
                title=f"Raw Binder implementation: {java_name}",
                detail=(
                    "Class extends android.os.Binder directly (not via AIDL-generated Stub). "
                    "The onTransact(int code, Parcel data, Parcel reply, int flags) method "
                    "receives raw integer transaction codes and unmarshals a Parcel manually. "
                    "Missing authentication on transaction codes is a common vulnerability: "
                    "any caller can invoke any transaction code. "
                    "RE priority: find onTransact(), enumerate all handled transaction codes, "
                    "verify each checks Binder.getCallingUid() / checkCallingPermission()."
                ),
                source=bc,
                evidence="extends android.os.Binder",
            ))

        # AIDL Stub classes
        if aidl_stub_classes:
            # Derive interface names from stub class names
            iface_names = []
            for sc in aidl_stub_classes:
                # "Lcom/foo/IMyService$Stub;" → "IMyService"
                outer = sc.lstrip("L").split("$")[0].split("/")[-1]
                iface_names.append(outer)
            findings.append(BinderFinding(
                severity=MEDIUM,
                category="binder/aidl_stub",
                title=f"{len(aidl_stub_classes)} AIDL Stub class(es) found",
                detail=(
                    "AIDL-generated Stub classes dispatch incoming Binder transactions on integer "
                    "transaction codes (FIRST_CALL_TRANSACTION=1 incrementing per method). "
                    "Each AIDL method corresponds to exactly one transaction code. "
                    "RE approach: decompile the Stub class to recover the interface method list. "
                    "Fuzz transaction codes beyond the defined range for unguarded paths. "
                    "Each interface is a named IPC contract the app exposes or consumes."
                ),
                source="dex",
                evidence=", ".join(sorted(set(iface_names))[:10]),
            ))

        # onTransact override sites (not already classified as raw Binder)
        raw_binder_set = {bc for bc in binder_classes}
        unclassified_transact = [
            tc for tc in transact_classes
            if tc not in raw_binder_set and tc != _BINDER_CLASS
        ]
        if unclassified_transact:
            findings.append(BinderFinding(
                severity=MEDIUM,
                category="binder/raw_transact",
                title=f"{len(unclassified_transact)} additional onTransact call site(s)",
                detail=(
                    "MethodRef scan found onTransact invocations in classes not yet classified "
                    "as direct Binder subclasses. These may be wrappers, proxies, or inline "
                    "Binder implementations. Each is an integer-dispatched IPC handler."
                ),
                source="dex",
                evidence=", ".join(sorted(unclassified_transact)[:5]),
            ))

        # Messenger IPC
        if messenger_found:
            findings.append(BinderFinding(
                severity=INFO,
                category="binder/messenger",
                title="android.os.Messenger IPC usage",
                detail=(
                    "Messenger wraps a Handler behind a Binder interface for message-passing IPC. "
                    "Lower attack surface than raw Binder since messages are typed, but "
                    "the Handler that processes them is still an IPC entry point. "
                    "Verify the Handler checks message.what codes and sender identity."
                ),
                source="dex",
                evidence="Landroid/os/Messenger; method references found",
            ))

        return findings

    @staticmethod
    def report(findings: List[BinderFinding]) -> str:
        if not findings:
            return "BinderScanner: no findings.\n"

        sev_order = {HIGH: 0, MEDIUM: 1, INFO: 2}
        findings = sorted(findings, key=lambda f: sev_order.get(f.severity, 9))

        lines = ["── Binder Scanner ────────────────────────────────────────────"]
        for f in findings:
            lines.append(f"[{f.severity}] {f.category}")
            lines.append(f"  {f.title}")
            lines.append(f"  src: {f.source}")
            lines.append(f"  evidence: {f.evidence}")
            lines.append(f"  {f.detail}")
            lines.append("")
        return "\n".join(lines)
