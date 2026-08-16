#!/usr/bin/env python3
"""
sendsignaling_fuzzer.py — SendSignaling Protocol Fuzzer

Generates malformed PTT signaling messages for fuzzing SendSignaling @ 0x2511c

Protocol structure (from static analysis):
  struct PTTSignalingMessage {
      uint8_t  command_class;      // 3 (normal)
      uint8_t  message_length;     // 18 bytes (normal)
      uint8_t  version_or_type;    // 2 (normal)
      uint8_t  error_code;         // 6 (normal)
      uint8_t  payload[14];        // Variable
  };

Fuzzing strategies:
  1. Boundary values (0, 255, length overflows)
  2. Format string payloads
  3. Buffer overflows (length > 18)
  4. Integer overflows
  5. NULL bytes / control characters
  6. Repeated patterns (AAAA, 0x41414141)

Usage:
  python3 sendsignaling_fuzzer.py --output fuzz_cases/
  python3 sendsignaling_fuzzer.py --mode afl  # Generate for AFL++

Output:
  Directory of binary message files ready for fuzzing

Author: NuClide Research
Date: 2026-08-16
"""

import argparse
import struct
import os
from pathlib import Path
from itertools import product


class PTTMessageFuzzer:
    """Generates fuzzed PTT signaling messages"""

    # Known good values from static analysis
    GOOD_COMMAND_CLASS = 3
    GOOD_LENGTH = 18
    GOOD_VERSION = 2
    GOOD_ERROR = 6

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.case_counter = 0

    def save_case(self, data: bytes, description: str):
        """Save a fuzz case to disk"""
        filename = f"case_{self.case_counter:05d}_{description}.bin"
        filepath = self.output_dir / filename
        with open(filepath, 'wb') as f:
            f.write(data)
        self.case_counter += 1
        return filename

    def generate_baseline(self):
        """Generate known-good baseline message"""
        msg = struct.pack('BBBB',
            self.GOOD_COMMAND_CLASS,
            self.GOOD_LENGTH,
            self.GOOD_VERSION,
            self.GOOD_ERROR
        )
        msg += b'\x00' * 14  # Payload

        self.save_case(msg, "baseline_good")

    def generate_boundary_values(self):
        """Fuzz with boundary values in each field"""
        boundaries = [0, 1, 127, 128, 254, 255]

        # Command class boundaries
        for val in boundaries:
            msg = struct.pack('BBBB', val, self.GOOD_LENGTH, self.GOOD_VERSION, self.GOOD_ERROR)
            msg += b'\x00' * 14
            self.save_case(msg, f"boundary_cmd_{val}")

        # Length boundaries (important for buffer overflow)
        for val in boundaries + [17, 19, 32, 64, 128, 255]:
            msg = struct.pack('BBBB', self.GOOD_COMMAND_CLASS, val, self.GOOD_VERSION, self.GOOD_ERROR)
            msg += b'\x00' * 14
            self.save_case(msg, f"boundary_len_{val}")

        # Version boundaries
        for val in boundaries:
            msg = struct.pack('BBBB', self.GOOD_COMMAND_CLASS, self.GOOD_LENGTH, val, self.GOOD_ERROR)
            msg += b'\x00' * 14
            self.save_case(msg, f"boundary_ver_{val}")

        # Error code boundaries
        for val in boundaries:
            msg = struct.pack('BBBB', self.GOOD_COMMAND_CLASS, self.GOOD_LENGTH, self.GOOD_VERSION, val)
            msg += b'\x00' * 14
            self.save_case(msg, f"boundary_err_{val}")

    def generate_length_overflows(self):
        """Generate messages with length field > actual size"""
        # Length says 18, but we send more
        for extra in [1, 2, 4, 8, 16, 32, 64, 128, 256]:
            msg = struct.pack('BBBB',
                self.GOOD_COMMAND_CLASS,
                18,  # Claims 18 bytes
                self.GOOD_VERSION,
                self.GOOD_ERROR
            )
            # Send 18 + extra bytes
            msg += b'A' * (14 + extra)
            self.save_case(msg, f"overflow_plus{extra}")

        # Length says more than we send
        for claimed in [32, 64, 128, 255]:
            msg = struct.pack('BBBB',
                self.GOOD_COMMAND_CLASS,
                claimed,  # Claims more than 18
                self.GOOD_VERSION,
                self.GOOD_ERROR
            )
            msg += b'B' * 14  # But only send normal size
            self.save_case(msg, f"underflow_claim{claimed}")

    def generate_format_strings(self):
        """Generate format string payloads in payload field"""
        format_strings = [
            b'%s%s%s%s%s',
            b'%x%x%x%x',
            b'%n%n%n%n',
            b'%p%p%p%p',
            b'AAAA%08x.%08x',
            b'%1$s%2$s%3$s',
        ]

        for i, fmt in enumerate(format_strings):
            msg = struct.pack('BBBB',
                self.GOOD_COMMAND_CLASS,
                self.GOOD_LENGTH,
                self.GOOD_VERSION,
                self.GOOD_ERROR
            )
            payload = fmt.ljust(14, b'\x00')[:14]
            msg += payload
            self.save_case(msg, f"format_string_{i}")

    def generate_integer_overflows(self):
        """Generate integer overflow conditions"""
        # All max values
        msg = struct.pack('BBBB', 0xff, 0xff, 0xff, 0xff)
        msg += b'\xff' * 14
        self.save_case(msg, "int_overflow_all_max")

        # Length field integer wraps
        for length in [0, 1, 255, 256 & 0xff]:
            msg = struct.pack('BBBB',
                self.GOOD_COMMAND_CLASS,
                length,
                self.GOOD_VERSION,
                self.GOOD_ERROR
            )
            msg += b'\x00' * 14
            self.save_case(msg, f"int_wrap_len_{length}")

    def generate_null_bytes(self):
        """Generate messages with NULL bytes in various positions"""
        # NULL in each header field
        for pos in range(4):
            msg = bytearray([
                self.GOOD_COMMAND_CLASS,
                self.GOOD_LENGTH,
                self.GOOD_VERSION,
                self.GOOD_ERROR
            ])
            msg[pos] = 0
            msg = bytes(msg) + b'\x00' * 14
            self.save_case(msg, f"null_header_{pos}")

        # NULL-terminated payload
        msg = struct.pack('BBBB',
            self.GOOD_COMMAND_CLASS,
            self.GOOD_LENGTH,
            self.GOOD_VERSION,
            self.GOOD_ERROR
        )
        msg += b'TEST\x00' + b'A' * 9
        self.save_case(msg, "null_in_payload")

    def generate_repeated_patterns(self):
        """Generate repeated byte patterns"""
        patterns = {
            'all_a': b'A' * 18,
            'all_zero': b'\x00' * 18,
            'all_ff': b'\xff' * 18,
            'de_de': b'\xde' * 18,
            'pattern_inc': bytes(range(18)),
            'pattern_dec': bytes(range(17, -1, -1)),
        }

        for name, pattern in patterns.items():
            self.save_case(pattern, f"pattern_{name}")

    def generate_shellcode_patterns(self):
        """Generate shellcode-like payloads (for ROP detection)"""
        # ARM32 NOP sled (mov r0, r0)
        arm_nop = b'\x00\x00\xa0\xe1'  # Little-endian ARM NOP
        msg = struct.pack('BBBB',
            self.GOOD_COMMAND_CLASS,
            self.GOOD_LENGTH,
            self.GOOD_VERSION,
            self.GOOD_ERROR
        )
        msg += (arm_nop * 3)[:14]
        self.save_case(msg, "shellcode_arm_nop")

        # Common ROP gadget addresses (libc)
        rop_addrs = [
            b'\x00\x10\x00\x00',  # 0x00001000
            b'\x00\x20\x00\x00',  # 0x00002000
            b'\xef\xbe\xad\xde',  # 0xdeadbeef
        ]

        for i, addr in enumerate(rop_addrs):
            msg = struct.pack('BBBB',
                self.GOOD_COMMAND_CLASS,
                self.GOOD_LENGTH,
                self.GOOD_VERSION,
                self.GOOD_ERROR
            )
            msg += (addr * 4)[:14]
            self.save_case(msg, f"shellcode_rop_{i}")

    def generate_control_characters(self):
        """Generate control characters that might trigger parser issues"""
        control_chars = [
            (b'\r\n' * 7, 'crlf'),
            (b'\x1b' * 14, 'escape'),
            (b'\x7f' * 14, 'delete'),
            (b'\t' * 14, 'tab'),
        ]

        for payload, name in control_chars:
            msg = struct.pack('BBBB',
                self.GOOD_COMMAND_CLASS,
                self.GOOD_LENGTH,
                self.GOOD_VERSION,
                self.GOOD_ERROR
            )
            msg += payload[:14]
            self.save_case(msg, f"control_{name}")

    def generate_all(self):
        """Generate all fuzz cases"""
        print(f"[*] Generating fuzz cases to {self.output_dir}")

        self.generate_baseline()
        print(f"    Baseline: {self.case_counter} cases")

        self.generate_boundary_values()
        print(f"    Boundary values: {self.case_counter} cases")

        self.generate_length_overflows()
        print(f"    Length overflows: {self.case_counter} cases")

        self.generate_format_strings()
        print(f"    Format strings: {self.case_counter} cases")

        self.generate_integer_overflows()
        print(f"    Integer overflows: {self.case_counter} cases")

        self.generate_null_bytes()
        print(f"    NULL bytes: {self.case_counter} cases")

        self.generate_repeated_patterns()
        print(f"    Repeated patterns: {self.case_counter} cases")

        self.generate_shellcode_patterns()
        print(f"    Shellcode patterns: {self.case_counter} cases")

        self.generate_control_characters()
        print(f"    Control characters: {self.case_counter} cases")

        print(f"\n[+] Generated {self.case_counter} total fuzz cases")
        return self.case_counter


def generate_afl_dict(output_path: Path):
    """Generate AFL++ dictionary for guided fuzzing"""
    dict_entries = [
        # Protocol constants from static analysis
        b'\\x03',  # command_class
        b'\\x12',  # length (18)
        b'\\x02',  # version
        b'\\x06',  # error_code

        # Common values
        b'\\x00',
        b'\\xff',
        b'\\x00\\x00',
        b'\\xff\\xff',

        # Format strings
        b'%s',
        b'%x',
        b'%n',
        b'%p',
    ]

    with open(output_path, 'w') as f:
        for i, entry in enumerate(dict_entries):
            f.write(f'token_{i}=\"{entry.decode()}\"\n')

    print(f"[+] AFL++ dictionary written to {output_path}")


def main():
    parser = argparse.ArgumentParser(description='SendSignaling Protocol Fuzzer')
    parser.add_argument('--output', type=Path, default=Path('fuzz_cases'),
                       help='Output directory for fuzz cases')
    parser.add_argument('--mode', choices=['standalone', 'afl'], default='standalone',
                       help='Generate standalone cases or AFL++ corpus')
    parser.add_argument('--dict', type=Path, help='Generate AFL++ dictionary file')

    args = parser.parse_args()

    # Generate fuzz cases
    fuzzer = PTTMessageFuzzer(args.output)
    count = fuzzer.generate_all()

    # Generate AFL dictionary if requested
    if args.mode == 'afl' or args.dict:
        dict_path = args.dict or (args.output / 'ptt.dict')
        generate_afl_dict(dict_path)

    print(f"\n{'='*80}")
    print("FUZZING RECOMMENDATIONS")
    print('='*80)
    print(f"\n1. Standalone fuzzing:")
    print(f"   for case in {args.output}/*.bin; do")
    print(f"       ./send_to_target.sh $case")
    print(f"   done")
    print(f"\n2. AFL++ fuzzing:")
    print(f"   afl-fuzz -i {args.output} -o findings -x {args.output}/ptt.dict -- ./target @@")
    print(f"\n3. Network fuzzing:")
    print(f"   cat {args.output}/case_*.bin | nc <target_ip> 5000")
    print(f"\n4. Frida fuzzing:")
    print(f"   Use frida to inject cases directly into SendSignaling()")
    print()


if __name__ == '__main__':
    main()
