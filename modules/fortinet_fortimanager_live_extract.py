"""
FortiManager KVM Live Extraction Tool
--------------------------------------
Extracts decrypted C binaries from a running FortiManager KVM guest.

The rootfs.gz is encrypted on disk; decryption happens in initrd.
Once the VM is running, the decrypted filesystem lives in RAM.
This tool dumps guest physical memory via QEMU monitor (QMP) and
reconstructs ELF64 binaries from the dump.

Primary targets:
  fazmerge    -- logview filter backend (FMG-F80/F81/F83 injection candidates)
  fgfmd       -- FGFM daemon port 8082 (FMG-F89)
  fgdsvc      -- device service (FMG-F91)
  webmcpserver -- MCP stdio server
  sdnproxyd   -- SDN proxy backend port 7080 (FMG-F87)

Usage:
  python3 fortinet_fortimanager_live_extract.py --monitor /tmp/fmg.sock --out /tmp/fmg-bins
  python3 fortinet_fortimanager_live_extract.py --monitor tcp:localhost:4444 --out /tmp/fmg-bins
  python3 fortinet_fortimanager_live_extract.py --dump /tmp/existing_dump.bin --out /tmp/fmg-bins
  python3 fortinet_fortimanager_live_extract.py --guest-tar <domain> --out /tmp/fmg-bins
"""

import argparse
import hashlib
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterator, Optional

# FMG binary targets with expected size ranges (bytes) and identifying strings
FMG_TARGETS = {
    "fazmerge": {
        "paths": ["/usr/sbin/fazmerge", "/bin/fazmerge"],
        "size_range": (500_000, 50_000_000),
        "strings": [b"fazmerge", b"loginsert", b"filter", b"clickhouse"],
    },
    "fgfmd": {
        "paths": ["/usr/sbin/fgfmd", "/bin/fgfmd"],
        "size_range": (200_000, 20_000_000),
        "strings": [b"fgfmd", b"FGFM", b"8082"],
    },
    "fgdsvc": {
        "paths": ["/usr/sbin/fgdsvc", "/bin/fgdsvc"],
        "size_range": (100_000, 10_000_000),
        "strings": [b"fgdsvc"],
    },
    "webmcpserver": {
        "paths": ["/usr/bin/webmcpserver"],
        "size_range": (100_000, 20_000_000),
        "strings": [b"webmcpserver", b"--cookies", b"11345"],
    },
    "sdnproxyd": {
        "paths": ["/usr/sbin/sdnproxyd", "/bin/sdnproxyd"],
        "size_range": (100_000, 10_000_000),
        "strings": [b"sdnproxyd", b"7080", b"sdnproxy"],
    },
    "fmguimgmt": {
        "paths": ["/usr/sbin/fmguimgmt"],
        "size_range": (100_000, 10_000_000),
        "strings": [b"fmguimgmt"],
    },
}

ELF_MAGIC = b"\x7fELF"
ELF64_IDENT = b"\x7fELF\x02\x01"  # ELF64, little-endian

# ELF64 header layout
ELF64_HDR_FMT = "<4s5B7xHHIQQQIHHHHHH"
ELF64_HDR_SIZE = 64

# PT_LOAD program header
PT_LOAD = 1
ELF64_PHDR_FMT = "<IIQQQQQQ"
ELF64_PHDR_SIZE = 56


def parse_elf64_header(data: bytes, offset: int = 0):
    if offset + ELF64_HDR_SIZE > len(data):
        return None
    try:
        fields = struct.unpack_from(ELF64_HDR_FMT, data, offset)
    except struct.error:
        return None
    magic = fields[0]
    if magic != ELF_MAGIC:
        return None
    ei_class = fields[1]
    ei_data = fields[2]
    if ei_class != 2 or ei_data != 1:  # not ELF64 LE
        return None
    e_type = fields[7]
    e_machine = fields[8]
    e_phoff = fields[10]
    e_shoff = fields[11]
    e_phnum = fields[13]
    e_shnum = fields[15]
    e_shstrndx = fields[16]
    return {
        "e_type": e_type,
        "e_machine": e_machine,
        "e_phoff": e_phoff,
        "e_shoff": e_shoff,
        "e_phnum": e_phnum,
        "e_shnum": e_shnum,
        "e_shstrndx": e_shstrndx,
    }


def elf64_file_size(data: bytes, offset: int) -> Optional[int]:
    hdr = parse_elf64_header(data, offset)
    if hdr is None:
        return None
    # Sanity checks
    if hdr["e_phnum"] > 128 or hdr["e_phnum"] == 0:
        return None
    if hdr["e_phoff"] == 0 or hdr["e_phoff"] > 0x10000:
        return None
    # e_machine: x86_64=62, ARM64=183, MIPS=8
    if hdr["e_machine"] not in (0, 2, 3, 8, 20, 40, 62, 183):
        return None

    end = ELF64_HDR_SIZE
    # Walk program headers to find the last byte of file data
    phoff = hdr["e_phoff"]
    for i in range(hdr["e_phnum"]):
        ph_start = offset + phoff + i * ELF64_PHDR_SIZE
        if ph_start + ELF64_PHDR_SIZE > len(data):
            break
        try:
            ph = struct.unpack_from(ELF64_PHDR_FMT, data, ph_start)
        except struct.error:
            break
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = ph
        if p_offset > 0 and p_filesz > 0:
            candidate = int(p_offset) + int(p_filesz)
            if candidate > end:
                end = candidate

    # Also consider section headers if present
    if hdr["e_shoff"] > 0 and hdr["e_shnum"] > 0:
        sh_end = hdr["e_shoff"] + hdr["e_shnum"] * 64
        if sh_end > end:
            end = sh_end

    # Apply size sanity
    if end < 1024 or end > 200_000_000:
        return None
    return end


def scan_elf64_binaries(data: bytes) -> Iterator[tuple[int, int]]:
    """Yield (offset, size) for each plausible ELF64 LE binary in data."""
    pos = 0
    while True:
        idx = data.find(ELF64_IDENT, pos)
        if idx < 0:
            break
        size = elf64_file_size(data, idx)
        if size is not None:
            yield idx, size
        pos = idx + 4


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def identify_binary(data: bytes) -> Optional[str]:
    """Match extracted ELF to a known FMG target by string content."""
    for name, info in FMG_TARGETS.items():
        lo, hi = info["size_range"]
        if not (lo <= len(data) <= hi):
            continue
        hits = sum(1 for s in info["strings"] if s in data)
        if hits >= 2:
            return name
    return None


def extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    """Extract printable ASCII strings from binary data."""
    results = []
    pat = re.compile(rb"[ -~]{%d,}" % min_len)
    for m in pat.finditer(data[:4_000_000]):
        results.append(m.group().decode("ascii", errors="replace"))
        if len(results) > 2000:
            break
    return results


class QMPConnection:
    """Minimal QEMU Machine Protocol client."""

    def __init__(self, path_or_host: str, port: int = 0):
        self.sock = None
        if path_or_host.startswith("tcp:"):
            parts = path_or_host.split(":")
            host = parts[1]
            port = int(parts[2])
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))
        else:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(path_or_host)
        self.sock.settimeout(120)
        self._handshake()

    def _recv_json(self) -> dict:
        buf = b""
        while True:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("QMP socket closed")
            buf += chunk
            try:
                return json.loads(buf.decode())
            except json.JSONDecodeError:
                continue

    def _send(self, obj: dict):
        self.sock.sendall((json.dumps(obj) + "\n").encode())

    def _handshake(self):
        banner = self._recv_json()
        if "QMP" not in banner:
            raise ValueError(f"Unexpected QMP banner: {banner}")
        self._send({"execute": "qmp_capabilities"})
        resp = self._recv_json()
        if "return" not in resp:
            raise ValueError(f"qmp_capabilities failed: {resp}")

    def execute(self, cmd: str, args: Optional[dict] = None) -> dict:
        payload: dict = {"execute": cmd}
        if args:
            payload["arguments"] = args
        self._send(payload)
        while True:
            resp = self._recv_json()
            if "return" in resp or "error" in resp:
                return resp
            # event - skip and wait

    def dump_guest_memory(self, out_path: str) -> bool:
        print(f"[qmp] issuing dump-guest-memory -> {out_path}")
        resp = self.execute(
            "dump-guest-memory",
            {
                "paging": False,
                "protocol": f"file:{out_path}",
                "format": "elf",
                "detach": True,
            },
        )
        if "error" in resp:
            # detach not supported on all QEMU versions; try synchronous
            resp = self.execute(
                "dump-guest-memory",
                {"paging": False, "protocol": f"file:{out_path}", "format": "elf"},
            )
        if "error" in resp:
            print(f"[qmp] dump-guest-memory error: {resp['error']}")
            return False

        # Wait for DUMP_COMPLETED event
        print("[qmp] waiting for DUMP_COMPLETED event ...")
        deadline = time.time() + 600
        while time.time() < deadline:
            try:
                resp = self._recv_json()
            except socket.timeout:
                print("[qmp] still waiting ...")
                continue
            if resp.get("event") == "DUMP_COMPLETED":
                result = resp.get("data", {}).get("result", {})
                if result.get("status") == "completed":
                    print(f"[qmp] dump complete: {result}")
                    return True
                else:
                    print(f"[qmp] dump status: {result}")
                    return False
        print("[qmp] timeout waiting for dump")
        return False

    def close(self):
        if self.sock:
            self.sock.close()


class GuestAgentExtractor:
    """Extract binaries using QEMU guest agent (virsh qemu-agent-command)."""

    def __init__(self, domain: str):
        self.domain = domain

    def _agent_command(self, cmd: dict) -> Optional[dict]:
        try:
            result = subprocess.run(
                ["virsh", "qemu-agent-command", self.domain, json.dumps(cmd)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                print(f"[agent] virsh error: {result.stderr.strip()}")
                return None
            return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            print(f"[agent] exception: {e}")
            return None

    def extract_binary(self, guest_path: str, local_path: str) -> bool:
        """Execute tar on guest and pull binary via guest-file-read."""
        exec_cmd = {
            "execute": "guest-exec",
            "arguments": {
                "path": "/bin/cat",
                "arg": [guest_path],
                "capture-output": True,
            },
        }
        resp = self._agent_command(exec_cmd)
        if not resp or "return" not in resp:
            return False
        pid = resp["return"]["pid"]

        # Wait for completion
        for _ in range(30):
            status = self._agent_command(
                {"execute": "guest-exec-status", "arguments": {"pid": pid}}
            )
            if status and status.get("return", {}).get("exited"):
                break
            time.sleep(1)

        status_data = status.get("return", {}) if status else {}
        if not status_data.get("exited") or status_data.get("exitcode", 1) != 0:
            return False

        import base64

        out_b64 = status_data.get("out-data", "")
        if not out_b64:
            return False
        data = base64.b64decode(out_b64)
        with open(local_path, "wb") as f:
            f.write(data)
        return True

    def extract_targets(self, out_dir: Path) -> dict:
        results = {}
        for name, info in FMG_TARGETS.items():
            for guest_path in info["paths"]:
                local = out_dir / name
                print(f"[agent] trying {guest_path} ...")
                if self.extract_binary(guest_path, str(local)):
                    digest = sha256(local.read_bytes())
                    results[name] = {"path": str(local), "sha256": digest, "source": guest_path}
                    print(f"[agent] extracted {name} ({local.stat().st_size} bytes) sha256={digest}")
                    break
        return results


def load_dump(dump_path: str) -> bytes:
    """Load memory dump, handling both raw and ELF core formats."""
    with open(dump_path, "rb") as f:
        header = f.read(4)
        f.seek(0)
        data = f.read()

    if data[:4] == ELF_MAGIC:
        print(f"[dump] ELF core format detected ({len(data):,} bytes)")
        return _flatten_elf_core(data)
    else:
        print(f"[dump] Raw format assumed ({len(data):,} bytes)")
        return data


def _flatten_elf_core(data: bytes) -> bytes:
    """
    Extract and concatenate PT_LOAD segment data from an ELF core file.
    Returns a flat buffer with all physical memory regions concatenated.
    We preserve relative ordering but regions may have gaps.
    """
    hdr = parse_elf64_header(data, 0)
    if not hdr:
        # Not a valid ELF - return as-is
        return data

    segments = []
    phoff = hdr["e_phoff"]
    for i in range(hdr["e_phnum"]):
        ph_start = phoff + i * ELF64_PHDR_SIZE
        if ph_start + ELF64_PHDR_SIZE > len(data):
            break
        ph = struct.unpack_from(ELF64_PHDR_FMT, data, ph_start)
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = ph
        if p_type == PT_LOAD and p_filesz > 0:
            segments.append((p_offset, p_filesz, p_paddr))

    segments.sort(key=lambda x: x[2])  # sort by physical address

    print(f"[dump] ELF core has {len(segments)} PT_LOAD segments")
    # Return a bytes object that contains all segment data concatenated
    # We scan this flattened buffer for nested ELF headers
    parts = []
    for p_offset, p_filesz, p_paddr in segments:
        parts.append(data[p_offset : p_offset + p_filesz])
    flat = b"".join(parts)
    print(f"[dump] flattened to {len(flat):,} bytes")
    return flat


def extract_from_dump(dump_path: str, out_dir: Path) -> dict:
    """Scan a memory dump for FMG ELF64 binaries and extract them."""
    data = load_dump(dump_path)
    results = {}
    seen_hashes = set()

    print(f"[scan] scanning {len(data):,} bytes for ELF64 binaries ...")
    count = 0
    for offset, size in scan_elf64_binaries(data):
        blob = data[offset : offset + size]
        digest = sha256(blob)
        if digest in seen_hashes:
            continue
        seen_hashes.add(digest)

        name = identify_binary(blob)
        count += 1
        label = name if name else f"unknown_{count}"
        out_path = out_dir / label

        # Avoid overwriting a larger version of the same binary
        if out_path.exists() and out_path.stat().st_size >= len(blob):
            # keep the larger one
            suffix = 1
            while (out_dir / f"{label}.{suffix}").exists():
                suffix += 1
            out_path = out_dir / f"{label}.{suffix}"

        with open(out_path, "wb") as f:
            f.write(blob)
        out_path.chmod(0o755)

        if name:
            results[name] = {"path": str(out_path), "sha256": digest, "size": len(blob)}
            print(f"[scan] FOUND {name} @ offset 0x{offset:x} size={len(blob):,} sha256={digest[:16]}...")
        else:
            results[label] = {"path": str(out_path), "sha256": digest, "size": len(blob)}

    print(f"[scan] total ELF64 candidates: {count}, identified FMG targets: {len([r for r in results if r in FMG_TARGETS])}")
    return results


def analyze_binary(path: str) -> dict:
    """Run strings analysis and basic ELF metadata on an extracted binary."""
    data = open(path, "rb").read()
    strings = extract_strings(data, min_len=8)
    hdr = parse_elf64_header(data, 0)

    # Find interesting strings for each target
    security_patterns = [
        "memcpy", "strcpy", "sprintf", "snprintf", "system(", "popen",
        "exec", "shell", "filter", "sql", "query", "clickhouse",
        "lua_", "luaL_", "inject", "format", "printf",
        "/bin/sh", "bash", "cmd", "command",
        "password", "passwd", "secret", "token", "key",
        "admin", "root", "superuser",
        "8082", "9005", "7080", "11345",
        "FGFM", "fazmerge", "fgfmd", "fgdsvc", "sdnproxy",
    ]
    hits = {}
    for pat in security_patterns:
        matches = [s for s in strings if pat.lower() in s.lower()]
        if matches:
            hits[pat] = matches[:5]

    machine_map = {62: "x86_64", 183: "aarch64", 40: "arm", 8: "mips"}
    arch = machine_map.get(hdr["e_machine"], f"e_machine={hdr['e_machine']}") if hdr else "unknown"

    return {
        "size": len(data),
        "sha256": sha256(data),
        "arch": arch,
        "string_count": len(strings),
        "security_hits": hits,
    }


def main():
    ap = argparse.ArgumentParser(description="FortiManager KVM live binary extractor")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--monitor", help="QEMU QMP monitor: unix socket path or tcp:host:port")
    group.add_argument("--dump", help="Existing memory dump file to scan")
    group.add_argument("--guest-tar", metavar="DOMAIN", help="Extract via QEMU guest agent (requires virsh)")
    ap.add_argument("--out", required=True, help="Output directory for extracted binaries")
    ap.add_argument("--dump-path", default="/tmp/fmg_memdump.bin", help="Temp path for QEMU dump output")
    ap.add_argument("--analyze", action="store_true", help="Run string analysis on extracted binaries")
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    results = {}

    if args.monitor:
        print(f"[*] connecting to QEMU monitor: {args.monitor}")
        qmp = QMPConnection(args.monitor)
        ok = qmp.dump_guest_memory(args.dump_path)
        qmp.close()
        if not ok:
            print("[!] dump failed")
            sys.exit(1)
        results = extract_from_dump(args.dump_path, out_dir)

    elif args.dump:
        results = extract_from_dump(args.dump, out_dir)

    elif args.guest_tar:
        extractor = GuestAgentExtractor(args.guest_tar)
        results = extractor.extract_targets(out_dir)

    if args.analyze:
        print("\n[*] analysis pass ...")
        for name, info in results.items():
            if name in FMG_TARGETS:
                print(f"\n--- {name} ---")
                analysis = analyze_binary(info["path"])
                print(f"  arch:    {analysis['arch']}")
                print(f"  size:    {analysis['size']:,} bytes")
                print(f"  sha256:  {analysis['sha256']}")
                print(f"  strings: {analysis['string_count']}")
                if analysis["security_hits"]:
                    print("  security pattern hits:")
                    for pat, matches in analysis["security_hits"].items():
                        print(f"    {pat}: {matches[:3]}")

    # Summary
    print("\n[*] extraction summary:")
    for name, info in results.items():
        print(f"  {name}: {info['path']} ({info.get('size', '?')} bytes) {info['sha256'][:16]}...")

    # Write manifest
    manifest = out_dir / "manifest.json"
    with open(manifest, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[*] manifest written: {manifest}")

    found_targets = [n for n in results if n in FMG_TARGETS]
    if found_targets:
        print(f"\n[+] FMG target binaries extracted: {', '.join(found_targets)}")
        print("[+] run ablation semantic sweep next:")
        print(f"    python3 modules/semantic_search.py <binary_path>")
    else:
        print("\n[-] no FMG target binaries identified in dump")
        print("    try: --analyze flag to inspect unknown ELFs manually")


if __name__ == "__main__":
    main()
