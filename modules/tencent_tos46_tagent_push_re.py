"""
TencentOS 4.6 — tmp-tagent-push binary reverse engineering module.

Binary: tmp-tagent-push (packaged in tagent-2.1.6-1.tl4)
Path: /usr/local/tagent/tmp-tagent-push
ELF: 64-bit LSB executable, x86-64, BuildID=4b63b617cd63d5cc3e94600360cec0662f97a495
Debug info: WITH debug_info (NOT stripped)
Size: 3.0MB
Language: C++ with CryptoPP cryptography library
Stripped: NO (full symbol table present, debug_info present)

Function inventory (from nm):
  main                  0x405cd8 — arg parsing, 5 required args (argc=6)
  verify_signature      0x406ade — CryptoPP DSA2<SHA256> verification
  push_data             0x406ea1 — JSON construction + IPC write
  adv_attr_set          0x4f28ab — SysV shared memory write primitive
  Base64ToBytes         0x4069ef — base64 decoder
  GetShm2               0x4f2079 — shmget/shmat wrapper
  init_sem              0x4f278c — semget/semctl wrapper
  semlock               0x4f26a6 — semop acquire
  semunlock             0x4f2726 — semop release

Total CryptoPP symbols: 1289 (full library linked statically)

=== PROTOCOL OVERVIEW ===

Usage (from embedded help string at 0x4f7718):
  ./tagent-push <sig_b64> <mod> <id_int> <type> <data_json>

  argv[1] = sig_b64   — base64-encoded DSA signature (used as JSON "key" field)
  argv[2] = mod       — module/component name (≤100 chars, becomes JSON "mod")
  argv[3] = id_int    — integer data_id (becomes JSON "id")
  argv[4] = type      — data type string (≤100 chars, becomes JSON "type")
  argv[5] = data_json — payload JSON (≤65535 bytes, becomes JSON "data")

JSON envelope written to shared memory:
  { "key":  "<argv[1]>",
    "mod":  "<argv[2]>",
    "type": "<argv[4]>",
    "id":   <argv[3]>,
    "data": "<argv[5]>",
    "ts":   <time(0)> }

Signed message format: "tagent+" + mod + str(id) + "+kh3ynYGL9uByKZ5"
  Example: "tagent+" + "test" + "100" + "+kh3ynYGL9uByKZ5"
         = "tagent+test100+kh3ynYGL9uByKZ5"

The sig_b64 (argv[1]) is the DSA signature over this derived string.
The payload data (argv[5]) is NOT included in the signed message.

=== IPC MECHANISM ===

adv_attr_set(attr_id=0x1a8962, json_c_str, json_size):
  1. semlock() — acquire SysV semaphore (semaphore key: separate from shmkey)
  2. GetShm2(g_pBusiShareMem, 0x5fe8, 0x200000, 0x1b6)
     — shmget(key=0x5fe8, size=2MB, IPC_CREAT|0666)
     — shmat() to g_pBusiShareMem
  3. Shared memory layout:
       [0x00]: used_offset (4 bytes) — current write position
       [0x04+used_offset]: next entry write target
     Each entry: [4B size][4B attr_id][data bytes]  (8-byte header per entry)
  4. Bounds: used_offset ≤ 0x1ffffc; rejects if insufficient space
  5. Writes JSON, increments used_offset by (json_size + 8)
  6. semunlock()

Input validation in adv_attr_set:
  attr_id > 0x257 (= 599)    — minimum attr_id value
  size > 0 && size ≤ 0x10000 — 1–65536 byte range
  data != NULL               — non-null check

Static public key (from .rodata at VA 0x4f7c28, 592 bytes):
  MIIBtjCCASsGByqGSM44BAEwggEeAoGBAOetYr1sPssc1oYIOhl1AKXBnb68QXXQ5eYQx07KxRn1
  swLi8231bvPeTVpTYwr9zhkNOowUiRAtUPDihkdShcY85cr3rNIcuCaOadeeUNSpUyrJ4bVrc11z
  xelTpm4wSIt/IfPn4fqKHxlxXQZBlDBHNyLvAtPDlICgkXEeXh+rAhUA/cheZ0UMOMq1LWd7Tqu
  BotyqyT0CgYBOFjemJzrMU1GGIkGeJVRxptQ66YIOJ/6uxsPcb/ffIIDskjbvFIh5yOmqf7PJsb
  NZBUtPDE7bhWBsOqD/9/iaWzECTStYHZY7q13+bZFTsP/uOyXVFbyE0vWKzer5Lm8bkjIZOsxpb
  FBS0z1qVTcVJ8FwQySzijfiJLIan9auWwOBhAACgYA+4nDm92//9tqXLJRCRe09szxMzDQkjFRV
  GCeuoU8e8Y83bqoQdrxiQZ1JPmHHooCscTr/RKliNRW33v98vtEX2JTg9HhbXuJbWY2hL0TkujE
  1BoTFSyTRS1SFjG9YhKXJ001RxhSwn06iQ5iaqGvduWfyHQd5RYaNIQ/K3RCorw==

Key parameters (confirmed via openssl dsa -pubin):
  Algorithm: DSA (OID 1.2.840.10040.4.1)
  Key size: 1024-bit (FIPS 186-2: L=1024, N=160)
  P: 1024-bit prime
  Q: 160-bit subgroup order (20 bytes)
  G: 1024-bit generator
  Public key Y: 1024-bit value

Hardcoded salt: "+kh3ynYGL9uByKZ5" (16 bytes, ASCII, at .rodata VA 0x4f7e81)
"""

METADATA = {
    "target": "TencentOS 4.6",
    "binary": "tmp-tagent-push",
    "build_id": "4b63b617cd63d5cc3e94600360cec0662f97a495",
    "stripped": False,
    "debug_info": True,
    "crypto_lib": "CryptoPP (statically linked)",
    "sig_scheme": "DSA2<SHA256> (CryptoPP DL_VerifierImpl)",
    "ipc_shmkey": 0x5fe8,
    "ipc_shm_size": 0x200000,  # 2MB
    "ipc_attr_id_used": 0x1a8962,
    "ipc_attr_id_minimum": 0x257,
    "hardcoded_salt": "+kh3ynYGL9uByKZ5",
    "dsa_key_va": 0x4f7c28,
    "dsa_key_size_b64": 592,
    "dsa_modulus_bits": 1024,
    "dsa_subgroup_bits": 160,
    "dsa_hash": "SHA256",
}

# DSA public key from static .rodata (DER-encoded SubjectPublicKeyInfo, base64)
DSA_PUBLIC_KEY_B64 = (
    "MIIBtjCCASsGByqGSM44BAEwggEeAoGBAOetYr1sPssc1oYIOhl1AKXBnb68QXXQ"
    "5eYQx07KxRn1swLi8231bvPeTVpTYwr9zhkNOowUiRAtUPDihkdShcY85cr3rNIcu"
    "CaOadeeUNSpUyrJ4bVrc11zxelTpm4wSIt/IfPn4fqKHxlxXQZBlDBHNyLvAtPDlI"
    "CgkXEeXh+rAhUA/cheZ0UMOMq1LWd7TquBotyqyT0CgYBOFjemJzrMU1GGIkGeJV"
    "RxptQ66YIOJ/6uxsPcb/ffIIDskjbvFIh5yOmqf7PJsbNZBUtPDE7bhWBsOqD/9/"
    "iaWzECTStYHZY7q13+bZFTsP/uOyXVFbyE0vWKzer5Lm8bkjIZOsxpbFBS0z1qVT"
    "cVJ8FwQySzijfiJLIan9auWwOBhAACgYA+4nDm92//9tqXLJRCRe09szxMzDQkjFR"
    "VGCeuoU8e8Y83bqoQdrxiQZ1JPmHHooCscTr/RKliNRW33v98vtEX2JTg9HhbXuJb"
    "WY2hL0TkujE1BoTFSyTRS1SFjG9YhKXJ001RxhSwn06iQ5iaqGvduWfyHQd5RYaN"
    "IQ/K3RCorw=="
)

VERIFY_SIGNATURE_FLOW = {
    "addr": "0x406ade",
    "size_bytes": 452,
    "prototype": "bool verify_signature(std::string& data, std::string& sig)",
    "steps": [
        "1. Guard-init (once): construct pub_key std::string from .rodata at 0x4f7c28",
        "2. Base64-decode sig argument -> raw_sig_bytes (string temp at rbp-0x48)",
        "3. Base64-decode pub_key static string -> raw_pub_bytes",
        "4. CryptoPP::StringSource(raw_pub_bytes, true, nullptr)",
        "5. DL_PublicKey_GFP<DL_GroupParameters_DSA> pubkey",
        "6. ASN1CryptoMaterial::Load(stringsource) -> parse DER SubjectPublicKeyInfo",
        "7. AutoSeededRandomPool pool (not used in verify, but required by API)",
        "8. PK_FinalTemplate<DL_VerifierImpl<DSA2<SHA256>,...>> verifier(pubkey)",
        "9. SignatureVerificationFilter svf(verifier, nullptr, SIGNATURE_AT_END=0x10)",
        "10. StringSource(data + raw_sig_bytes, true, &svf) -> feeds verifier",
        "    (note: data is the FULL signed-message string; raw_sig_bytes appended)",
        "11. Success: returns 1 (ebx=1 at 0x406cfa)",
        "12. CryptoPP::Exception: prints error to stderr via cout, returns 0 (ebx=0)",
    ],
    "exception_handling": {
        "catch_1": "CryptoPP::Exception (rdx==1) -> print what() to stderr, return 0",
        "catch_2": "any other exception -> return 0",
    },
}

PUSH_DATA_FLOW = {
    "addr": "0x406ea1",
    "prototype": "int push_data(std::string& sig_b64, std::string& mod, int id, std::string& type, std::string& data)",
    "steps": [
        "1. Build signed_msg = 'tagent+' + mod + to_string(id) + '+kh3ynYGL9uByKZ5'",
        "2. verify_signature(signed_msg, sig_b64) -- ONLY covers mod+id, NOT data/type",
        "3. If verify fails: return -2 (0xfffffffe)",
        "4. Validate type.length() <= 100",
        "5. Validate sig_b64.length() (used as 'key' field) <= 100",
        "6. Validate id > 0",
        "7. Validate data.length() <= 0xffff (65535)",
        "8. Build Json::Value: {key:sig_b64, mod:mod, type:type, id:id, data:data, ts:time(0)}",
        "9. Json::StreamWriter with empty indentation (compact JSON)",
        "10. adv_attr_set(0x1a8962, json.c_str(), json.size())",
        "11. If adv_attr_set fails: return -3 (0xfffffffd)",
        "12. Print success: 'push data succeed, json data size=%ld, item size=%ld'",
        "13. Return 0",
    ],
    "signed_msg_format": '"tagent+" + mod + str(id) + "+kh3ynYGL9uByKZ5"',
    "data_not_signed": True,
}

ADV_ATTR_SET_FLOW = {
    "addr": "0x4f28ab",
    "prototype": "int adv_attr_set(int attr_id, size_t size, const char* data)",
    "note": "NOTE: argument order in push_data call is adv_attr_set(0x1a8962, json_str, json_size) -- "
            "rdi=attr_id, rsi=json_size, rdx=json_str. "
            "Internal validation uses: attr_id field (rbp-0x2c), size (rbp-0x38), data (rbp-0x40).",
    "shmkey": 0x5fe8,
    "shm_size": 0x200000,
    "shm_mode": 0x1b6,  # 0666
    "entry_layout": "[4B: used_offset_at_write] [4B: attr_id] [data bytes]",
    "ring_buffer_max": 0x1ffffc,
    "validation": [
        "attr_id > 0x257 (601+ only)",
        "0 < size <= 0x10000",
        "data != NULL",
    ],
    "steps": [
        "1. semlock() -> SysV semaphore acquire",
        "2. GetShm2(g_pBusiShareMem, 0x5fe8, 0x200000, 0x1b6) -> shmget/shmat",
        "3. Read used_offset from [g_pBusiShareMem+0x0]",
        "4. Check: 0x1ffffc - used_offset >= size + 8 (space check)",
        "5. Write entry at [g_pBusiShareMem+4+used_offset]: {old_offset, attr_id?, data...}",
        "6. Update used_offset: [g_pBusiShareMem+0x0] += size + 8",
        "7. semunlock()",
    ],
}

FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": "Push payload not included in DSA signature — auth covers address, not content",
        "functions": ["verify_signature:0x406ade", "push_data:0x406ea1"],
        "detail": (
            "The DSA signature covers ONLY: 'tagent+' + mod + str(id) + '+kh3ynYGL9uByKZ5'. "
            "The actual payload (argv[5], JSON 'data' field) is completely absent from the signed message. "
            "An attacker who obtains any valid (mod, id, sig) triple — from traffic capture, "
            "log files, or shared tagent-push invocations — can push ARBITRARY data content "
            "to any tagent with those same mod+id values. The signature authenticates the destination "
            "address (mod+id), not the payload being pushed. "
            "The hardcoded salt '+kh3ynYGL9uByKZ5' (extracted from binary at .rodata 0x4f7e81) "
            "makes the signed message format fully reconstructable from a target mod+id pair alone. "
            "The 'ts' timestamp in the JSON envelope is set from time(0) and is NOT part of the "
            "signature — there is no replay protection."
        ),
        "disasm_evidence": [
            "push_data+0x106: lea rax, [rbp-0x190]  ; signed_msg = 'tagent+' + mod + id_str + '+kh3ynYGL9uByKZ5'",
            "push_data+0x10d: lea rdx, [rbp-0x198]  ; sig_b64 copy",
            "push_data+0x114: call 406ade verify_signature(signed_msg, sig_b64)",
            "push_data+0x329: lea rax, [rbp-0xb0]   ; Json Value(data) -- data is argv[5], added AFTER verification",
            "push_data+0x337: call 4e7f10 Json::Value::operator[]('data')",
        ],
        "impact": "Forged config/script payloads delivered to tagent as authorized push operations",
    },
    {
        "id": "F2",
        "severity": "CRITICAL",
        "title": "SysV IPC shared memory auth bypass — local processes can write tagent push channel without signing",
        "functions": ["adv_attr_set:0x4f28ab", "GetShm2:0x4f2079"],
        "detail": (
            "The signature verification in verify_signature is performed inside the tagent-push CLIENT binary. "
            "The tagent DAEMON does not re-verify the signature when reading from shared memory. "
            "Any local process with the SysV IPC key (shmkey=0x5fe8, shmsize=2MB, mode=0666) can: "
            "1. shmget(0x5fe8, 0, 0) -> get the existing segment. "
            "2. shmat() -> map it. "
            "3. Write a crafted entry at [shm+4+used_offset] with any attr_id and payload. "
            "4. Increment [shm+0x0] (used_offset) by (entry_size + 8). "
            "5. Acquire the semaphore if needed, or write during the semaphore-free window. "
            "The shmkey 0x5fe8 and the entry format (4B size header + data) are fully disclosed "
            "by disassembly of adv_attr_set. There is no signature check in the daemon read path. "
            "Any unprivileged local user on the TOS node can inject arbitrary push payloads "
            "directly into the tagent message bus."
        ),
        "disasm_evidence": [
            "adv_attr_set+0x76: mov esi, 0x5fe8   ; shmkey",
            "adv_attr_set+0x81: mov edx, 0x200000 ; shmsize=2MB",
            "adv_attr_set+0x86: mov ecx, 0x1b6    ; mode=0666",
            "adv_attr_set+0x8b: call 4f2079 GetShm2",
            "Mode 0666 = world-readable and world-writable shared memory",
        ],
        "ipc_primitives": {
            "shmkey": "0x5fe8 (23528 decimal)",
            "shmsize": "0x200000 (2MB)",
            "shm_mode": "0666 (world read/write)",
            "entry_format": "[4B: used_offset] [4B: ?] [json_bytes]",
        },
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "1024-bit DSA key — NIST-deprecated weak key, FIPS 186-2 parameters",
        "functions": ["verify_signature:0x406ade"],
        "detail": (
            "The static DSA public key at .rodata 0x4f7c28 is a 1024-bit DSA key "
            "(OID 1.2.840.10040.4.1, FIPS 186-2, L=1024 N=160). "
            "NIST SP 800-131A (2013): 1024-bit DSA disallowed for generating new signatures beyond 2013. "
            "NIST SP 800-57 Part 1: minimum 2048 bits for use through 2030. "
            "Q is 160-bit (20 bytes) — subgroup order matching old DSA standard, not FIPS 186-4. "
            "With SHA256 hashing (256-bit digest) but 160-bit Q, the effective signing strength "
            "is bounded by the smaller of SHA256 and DSA's discrete log security, which for "
            "1024-bit DSA is approximately 80 bits (GNFS-equivalent). "
            "The key pair is hardcoded: the binary ships with the public key; Tencent holds the private key. "
            "Breaking the 1024-bit DSA private key enables arbitrary signed push commands."
        ),
        "key_material": {
            "algorithm": "DSA",
            "oid": "1.2.840.10040.4.1",
            "modulus_bits": 1024,
            "subgroup_bits": 160,
            "hash": "SHA256",
            "standard": "FIPS 186-2",
            "status": "NIST disallowed for new use since 2013",
        },
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "No replay protection in signed message — valid (mod, id, sig) tuples reusable indefinitely",
        "functions": ["push_data:0x406ea1"],
        "detail": (
            "The signed message format is: 'tagent+' + mod + str(id) + '+kh3ynYGL9uByKZ5'. "
            "There is no nonce, no timestamp, no counter, and no challenge in the signed portion. "
            "The 'ts' field (time(0)) is written into the JSON envelope AFTER verification and is not signed. "
            "A captured valid invocation of tagent-push can be replayed indefinitely to the same "
            "(mod, id) address to re-deliver the same or a different payload (per F1)."
        ),
        "disasm_evidence": [
            "push_data+0x37e: call time(0)               ; ts set AFTER verify_signature returns",
            "push_data+0x391: Json Value 'ts' = time(0)  ; ts added to envelope, not signed",
        ],
    },
    {
        "id": "F5",
        "severity": "HIGH",
        "title": "Hardcoded salt disclosed in binary — signed message format fully reconstructable",
        "functions": ["push_data:0x406ea1"],
        "detail": (
            "The static salt '+kh3ynYGL9uByKZ5' is embedded in .rodata at VA 0x4f7e81. "
            "With this salt and the known message format, an attacker can construct the exact "
            "byte sequence that tagent-push would present to verify_signature for any (mod, id) pair. "
            "This is not a direct exploit but eliminates any ambiguity about what needs to be signed. "
            "Combined with the 1024-bit DSA weakness (F3), the salt disclosure means that once "
            "the private key is recovered, arbitrary valid signatures can be generated for any target."
        ),
        "disasm_evidence": [
            "push_data+0xd4: mov edx, 0x4f7e81     ; '+kh3ynYGL9uByKZ5' literal address in .rodata",
            "push_data+0xd9: mov rcx, rbp-0x180    ; prefix 'tagent+' + mod + id_str",
            "push_data+0xdf: call std::operator+(string, const char*)",
        ],
        "extracted_salt": "+kh3ynYGL9uByKZ5",
        "salt_location": ".rodata VA 0x4f7e81",
    },
    {
        "id": "F6",
        "severity": "INFO",
        "title": "Push JSON schema: {key, mod, type, id, data, ts} — tagent internal message format",
        "functions": ["push_data:0x406ea1"],
        "detail": (
            "The push JSON envelope fields (from Json::Value::operator[] calls): "
            "'key'  = argv[1] (sig_b64 — the DSA signature itself is used as a bearer token), "
            "'mod'  = argv[2] (module/component identifier, ≤100 chars), "
            "'type' = argv[4] (data type string, ≤100 chars), "
            "'id'   = argv[3] as int (data_id, must be > 0), "
            "'data' = argv[5] (payload, ≤65535 bytes), "
            "'ts'   = time(0) (Unix timestamp at push time, not signed). "
            "IPC attr_id used: 0x1a8962 = 1,739,106 decimal. "
            "Minimum attr_id accepted by adv_attr_set: 0x257 = 599. "
            "The SysV semaphore key appears separate from the shmkey; semaphore mode 0666."
        ),
        "json_schema": {
            "key": "DSA sig_b64 (argv[1], bearer token for tagent identification)",
            "mod": "module name (argv[2])",
            "type": "data type (argv[4])",
            "id": "integer data_id (argv[3] via atoi)",
            "data": "payload (argv[5], NOT signed)",
            "ts": "time(0) (NOT signed)",
        },
        "attr_id": "0x1a8962 (1,739,106)",
    },
]

if __name__ == '__main__':
    print(f"tmp-tagent-push RE — {len(FINDINGS)} findings")
    for f in FINDINGS:
        print(f"  [{f['severity']:8s}] {f['id']}: {f['title']}")
    print(f"\nProtocol: DSA2<SHA256> via CryptoPP, SysV IPC shmkey=0x5fe8 (2MB, mode=0666)")
    print(f"DSA key: 1024-bit ({METADATA['dsa_key_va']:#x}), salt: {METADATA['hardcoded_salt']!r}")
