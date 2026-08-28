# WeChat Android RE

WeChat 8.0.56 arm64 static RE. Covers the MMTLS transport protocol, DB encryption key derivation, and runtime key extraction via ptrace — no Frida. Synthesized from symbol tables, embedded source paths, and log strings in `libwechatnetwork.so` and `libMMProtocalJni.so`.

Native ARM64 tooling lives in [mmtls-lab](https://github.com/sshpie/mmtls-lab). `wechat_re.py` drives it via adb.

---

## `wechat_re` — MMTLS + DB key + ptrace key extraction

### MMTLS protocol

WeChat's custom TLS replacement, private `mars-wechat` repo:

- Two-tier key architecture: `HybridEcdh` (static+ephemeral) → `AxEcdh` (double ratchet / Signal-style forward secrecy)
- Cipher suites: AES-GCM (primary), SM4-GCM (Chinese national standard GB/T 32907)
- KDF: HKDF-SHA384 (TLS 1.3 style)
- PSK 0-RTT session resumption: `HS_MODE_ZERO_RTT_PSK`, tickets stored in `ClientCredStorage`

### Key offsets — libwechatnetwork.so 8.0.56 arm64

| Symbol | VA | Notes |
|--------|----|-------|
| `gILinkKey` | `0x3d4648` | 72-byte live session key (BSS) |
| HKDF call | `0x1ce28c` | BL `0x1dc424`; return site `0x1ce290` |
| key-insert orchestrator | `0x303fb0` | hlist splice at `0x304074` |

### Findings

| ID | Severity | Finding |
|----|----------|---------|
| WX-F1 | INFO | MMTLS two-tier crypto: HybridEcdh + AxEcdh double ratchet |
| WX-F2 | MEDIUM | `ALERT_FALLBACK_NO_MMTLS` — network-level downgrade to HTTPS |
| WX-F3 | HIGH | PSK 0-RTT session resumption — extracted PSK enables replay |
| WX-F4 | HIGH | `gILinkKey` (72B, BSS, `0x3d4648`) — live MMTLS session key; extractable via ptrace |
| WX-F5 | HIGH | DB key: `computerKeyWithAllStr(IMEI, UIN)` → 7-char hex → SQLite SEE |
| WX-F6 | INFO | Pack format reconstructed: header (clientVer/type/flag/seq) + body (uin/func/encryptAlgo) |

### Usage

```bash
# Full static RE (APK + libs)
./ablation --wechat \
  --wechat-apk /path/to/wechat-arm64.apk \
  --wechat-libs /path/to/native-libs/lib

# Compute EnMicroMsg.db decryption key offline
./ablation --wechat-db-key 123456789012345 987654321
# [+] WeChat DB key (MD5(IMEI+UIN)[:7]): a3f9e2c
```

```python
from modules.wechat_re import WeChatRE
wx = WeChatRE()

# Discover gILinkKey write site
result = wx.probe_discover()
# {'writer_pc': 0x1cad30, 'key': 'a3f9...', 'steps': 317}

# Continuous key capture
wx.probe_hook(writer_pc=0x1cad30)

# One-shot key snapshot
wx.probe_dump()
```

### ptrace intercept points (mmtls_probe)

- `probe_discover` — plants `BRK #0` at HKDF return (`0x1ce290`), single-steps until `gILinkKey` changes — resolves write site dynamically
- `probe_hook` — persistent `BRK #0` at `writer_pc`, re-armed after each hit; captures 72-byte key on every MMTLS session establishment
- `probe_dump` — polls `/proc/pid/mem` at `gILinkKey` until non-zero + stable (200ms verify)

### Injector (mmtls_inject)

PLT/GOT patcher with FULL_RELRO bypass. Android linker marks `.got.plt` `PROT_READ` after relocations — bypassed by injecting `mprotect()` via ptrace register manipulation (no shellcode). Patches `connect`/`send`/`recv`/`sendto`/`recvfrom` GOT entries to redirect through `libhook.so` globals.

### DB encryption

SQLCipher (`libWCDB.so`) — not SQLite SEE. Key is 7 hex chars derived from MD5(IMEI+UIN).
