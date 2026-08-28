"""
vmnetd_re.py — Docker vmnetd socket protocol RE module
Target: com.docker.vmnetd (macOS privileged helper)
Goal: map command IDs and handshake format to craft SymlinkMessage as root
"""

import subprocess
import struct
import re
import socket
import os


VMNETD_BINARY = os.environ.get("VMNETD_BINARY", "/path/to/com.docker.vmnetd")
VMNETD_SOCKET = "/var/run/com.docker.vmnetd.sock"


def extract_go_strings(binary_path):
    """Extract all printable strings >= 4 chars from Go binary."""
    result = subprocess.run(["strings", "-n", "4", binary_path], capture_output=True, text=True)
    return result.stdout.splitlines()


def find_command_ids(binary_path):
    """
    Go binary maps command int IDs to handler functions.
    Look for the dispatch table by finding all handler refs + context around them.
    """
    data = open(binary_path, "rb").read()

    # Find all known handler function name offsets in the binary
    handlers = {
        b"handlePing": None,
        b"handleBindIpv4": None,
        b"handleAddExtraHosts": None,
        b"handleEnsureLocalhost": None,
        b"handleInstallSymlinks": None,
        b"handleUninstall": None,
        b"handleUninstallSymlinks": None,
        b"handleDiagnose": None,
    }

    for name in handlers:
        idx = data.find(name)
        if idx >= 0:
            handlers[name] = idx

    print("[+] Handler locations in binary:")
    for name, offset in sorted(handlers.items(), key=lambda x: x[1] or 0):
        if offset:
            print(f"    {name.decode()} @ {hex(offset)}")
    return handlers


def find_command_constants(binary_path):
    """
    Look for integer constants near the command type names.
    In Go, the map[int]CommandHandler dispatch table embeds the int keys.
    """
    data = open(binary_path, "rb").read()

    # Search for the string "commands" package path marker near the handlers
    # and look at surrounding bytes for uint8/uint16 command IDs
    target = b"vmnetd/commands.Handle"
    idx = data.find(target)
    if idx < 0:
        print("[-] Could not find commands.Handle reference")
        return

    print(f"[+] commands.Handle found at {hex(idx)}")
    print(f"    context hex: {data[idx-32:idx+32].hex()}")

    # Look for the handlers map initialization
    # In Go, a map[int]func literal is built at runtime but the int keys are constants
    # Search for uint32/uint8 patterns that could be command IDs (1-20 range)
    for handler_name in [b"handlePing", b"handleBindIpv4", b"handleInstallSymlinks",
                         b"handleUninstall", b"handleDiagnose"]:
        pos = data.find(handler_name)
        if pos >= 0:
            # Look at bytes before the function name for potential command ID
            context = data[max(0, pos-64):pos]
            print(f"\n[+] {handler_name.decode()} context (before):")
            print(f"    hex: {context[-32:].hex()}")
            # Small integers (1-20) that could be command IDs
            for i in range(len(context)-4):
                val = struct.unpack("<I", context[i:i+4])[0]
                if 1 <= val <= 20:
                    print(f"    possible cmd_id={val} at -{len(context)-i} from handler")


def find_handshake_magic(binary_path):
    """
    Find the VMN3T magic and associated handshake message structure.
    """
    data = open(binary_path, "rb").read()

    # Find all VMN3T occurrences
    positions = []
    start = 0
    while True:
        idx = data.find(b"VMN3T", start)
        if idx < 0:
            break
        positions.append(idx)
        start = idx + 1

    print(f"\n[+] VMN3T magic found at {len(positions)} locations: {[hex(p) for p in positions]}")
    for p in positions:
        print(f"    @ {hex(p)}: {data[p:p+32].hex()}")

    # Also search for the handshake.go source path
    hs_path = b"vmnet/handshake/handshake.go"
    idx = data.find(hs_path)
    if idx >= 0:
        print(f"\n[+] handshake.go ref at {hex(idx)}")
        print(f"    context: {data[idx-16:idx+len(hs_path)+16].hex()}")


def probe_protocol(socket_path, payload, label=""):
    """Send payload to vmnetd socket, return response."""
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(socket_path)
        s.settimeout(3)
        s.sendall(payload)
        try:
            resp = s.recv(4096)
        except socket.timeout:
            resp = b"(timeout)"
        s.close()
        return resp
    except Exception as e:
        return f"(error: {e})".encode()


def map_command_ids_via_probe(socket_path):
    """
    Probe vmnetd to determine command IDs.
    The handshake sends: [MAGIC][version][...] and server responds with challenge.
    After handshake, each command is a frame: [cmd_id:1][length:4][payload]
    """
    print("\n[+] Probing vmnetd socket command dispatch...")

    # First: understand server hello format
    # From earlier probe: {"version":1} -> b'VMN3T\x16\x00\x00\x00<22 bytes>'
    # Theory: server sends [MAGIC:5][LEN:4][CHALLENGE:LEN]

    # Try structured binary probes
    probes = [
        # Format 1: single byte command IDs 0-20
        (b"\x00", "cmd_id=0"),
        (b"\x01", "cmd_id=1"),
        (b"\x02", "cmd_id=2"),
        (b"\x03", "cmd_id=3"),
        (b"\x04", "cmd_id=4"),
        (b"\x05", "cmd_id=5"),
        (b"\x06", "cmd_id=6"),
        (b"\x07", "cmd_id=7"),

        # Format 2: length-prefixed
        (b"\x00\x00\x00\x01\x00", "len=1 cmd=0"),
        (b"\x00\x00\x00\x01\x01", "len=1 cmd=1"),
        (b"\x00\x00\x00\x01\x02", "len=1 cmd=2"),
        (b"\x00\x00\x00\x01\x03", "len=1 cmd=3"),

        # Format 3: what the server challenge + cmd format might be
        (b"VMN3T\x00\x00\x00\x01\x01", "magic+len1+cmd1"),
        (b"VMN3T\x00\x00\x00\x00", "magic+empty"),
    ]

    for payload, label in probes:
        resp = probe_protocol(socket_path, payload, label)
        print(f"    [{label}] -> {resp[:32].hex() if isinstance(resp, bytes) else resp}")


def extract_symlink_paths(binary_path):
    """
    Extract hardcoded paths used in symlinkBinary and symlinkDockerSock.
    These tell us what paths vmnetd can create symlinks at/to.
    """
    strings_list = extract_go_strings(binary_path)

    print("\n[+] Path strings in vmnetd binary:")
    path_patterns = [
        r"^/usr/local/",
        r"^/usr/bin/",
        r"^/var/run/",
        r"^/etc/",
        r"^/Library/",
        r"^/private/",
        r"^/tmp/",
        r"^/Applications/Docker",
    ]

    for s in strings_list:
        for p in path_patterns:
            if re.match(p, s):
                print(f"    {s}")
                break


def find_userwritablepaths(binary_path):
    """
    Extract UserWritablePaths struct fields from binary.
    These define what paths vmnetd considers user-writable.
    """
    data = open(binary_path, "rb").read()

    idx = data.find(b"UserWritablePaths")
    if idx >= 0:
        print(f"\n[+] UserWritablePaths ref at {hex(idx)}")
        # Look at surrounding context
        print(f"    context: {data[idx:idx+64].hex()}")
        print(f"    ascii: {data[idx:idx+64]}")


def run(binary=None, socket_path=None):
    """Main RE entry point."""
    binary = binary or VMNETD_BINARY
    socket_path = socket_path or VMNETD_SOCKET

    print(f"[*] vmnetd RE module — target: {binary}")
    print(f"[*] socket: {socket_path}")

    find_command_ids(binary)
    find_handshake_magic(binary)
    extract_symlink_paths(binary)
    find_userwritablepaths(binary)

    if os.path.exists(socket_path):
        map_command_ids_via_probe(socket_path)
    else:
        print(f"\n[-] Socket {socket_path} not accessible locally (target is remote)")

    print("\n[*] RE complete. See findings above.")


if __name__ == "__main__":
    run()
