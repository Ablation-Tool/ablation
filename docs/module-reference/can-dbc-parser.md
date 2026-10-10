# CanDbcParser

**File:** `ablation/analyzers/can_dbc_parser.py`

---

## Why this exists

4 things that were not possible before in Ablation:

**1. No CAN DBC database parsing.** The Vector DBC format is the universal interchange format
for CAN signal databases. Every major CAN analysis tool uses it: CANdb++, SavvyCAN, Wireshark,
BUSMASTER, cantools. DBC files carry all message IDs, signal bit layouts, physical conversion
factors, and enumerated state names for a CAN network. Without a parser, ECU calibration work
had no signal-level context. Table addresses from XDF or A2L parsers were available, but the
CAN bus signals those tables feed were invisible.

**2. No 29-bit extended frame ID decoding.** The DBC format encodes extended CAN frames by
setting bit 31 of the raw message ID field. J1939 industrial and agricultural ECUs use 29-bit
extended frames (e.g., raw ID 0x0CF004FE for EEC1 Engine Speed). Without explicit bit-31
detection and masking, a DBC parser assigns wrong IDs to every J1939 message and all extended
messages appear absent when searched by canonical CAN ID. This parser detects
`raw_id & 0x80000000` at parse time and strips bit 31 to produce the 29-bit canonical ID.

**3. No value table resolution.** DBC `VAL_` records map raw integer signal values to
human-readable state names: gear positions, fault codes, operating modes, switch positions.
These names are the primary source of signal intent documentation in production automotive DBC
files. Without a second-pass `VAL_` parser, signal objects had only a name and a scale factor.
Enumerated state meanings were inaccessible. This parser resolves value tables per signal and
stores them as `CANSignal.value_table`.

**4. No manufacturer signal comment recovery.** DBC `CM_` records carry the manufacturer's
own descriptions of signal and message semantics. These comments survive DBC export from CANdb++
and, when present, are the richest source of signal intent available outside the OEM data
dictionary. `CM_` records trail all `BO_`/`SG_` blocks in the file and can span multiple lines.
Without a second-pass `DOTALL` regex over the full text, comment content was unreachable. This
parser recovers both signal and message comments.

---

## Format overview

A DBC file is a plain text document. It contains three kinds of records that this parser reads:

```
BO_ <raw_id> <msg_name>: <dlc> <sender>     -- message definition
 SG_ <sig_name> : <start>|<len>@<byte_order><sign> (<factor>,<offset>) [<min>|<max>] "<unit>" <receivers>
CM_ BO_ <raw_id> "comment text";            -- message comment (anywhere in file, multi-line)
CM_ SG_ <raw_id> <sig_name> "comment text"; -- signal comment (same)
VAL_ <raw_id> <sig_name> 1 "OK" 0 "ERROR";  -- enumerated state names (same)
```

### Extended frame IDs

The DBC raw ID field uses bit 31 to flag 29-bit extended frames:

| raw_id | is_extended | canonical msg_id |
|---|---|---|
| 790 (0x316) | False | 790 |
| 2164260096 (0x813B3500) | True (bit 31 set) | 0x013B3500 |
| 0x0CF004FE or 0x8CF004FE | True | 0x0CF004FE |

J1939 PGN-based addresses appear as extended frames. The DBC convention is not universal:
some tools omit bit 31 for extended frames and use a separate `[ATTR_DEF_ "SystemSignalLongSymbol"...]`
block. This parser follows the bit-31 convention used by CANdb++, SavvyCAN, and cantools.

### Signal bit layout fields

```
SG_ EngineSpeed : 24|16@1+ (0.125,0) [0|8031.875] "rpm" Vector__XXX
                  ^^ ^^  ^  ^     ^
                  |  |   |  |     offset
                  |  |   |  factor
                  |  |   byte_order: 1=Intel/little-endian, 0=Motorola/big-endian
                  |  length in bits
                  start bit
```

Physical value: `physical = raw_integer * factor + offset`

The `+` sign after byte_order means unsigned; `-` means signed. An optional `M` or `m<n>`
multiplexor indicator between the signal name and `:` is accepted and silently skipped.

---

## Usage

```python
from ablation.analyzers.can_dbc_parser import CanDbcParser

# Load from file
db = CanDbcParser.from_file("/path/to/network.dbc")
print(db.summary())

# Iterate all messages
for msg in db.messages():
    print(f"0x{msg.msg_id:03X}  {'EXT' if msg.is_extended else 'STD'}  {msg.name}  {msg.dlc}B")
    for sig in msg.signals:
        print(f"  {sig.name}  {sig.start_bit}|{sig.length}  x{sig.factor}+{sig.offset}  {sig.unit}")

# Look up a specific message by canonical CAN ID
msg = db.message(0x0CF004FE)    # J1939 EEC1
if msg:
    spn = msg.signal("EngineSpeed")
    print(f"raw=2000 -> {spn.decode(2000)} {spn.unit}")   # 250.0 rpm

# Find all signals whose name contains a pattern
for msg, sig in db.find_signals("speed"):
    print(f"0x{msg.msg_id:03X} {msg.name}.{sig.name}")

# Extended vs standard message counts
print(f"Standard: {len(db.standard_messages())}  Extended: {len(db.extended_messages())}")
```

---

## API reference

### `CanDbcParser.from_file(path)`

Parse a DBC file. Raises `FileNotFoundError` when the path does not exist. Encoding is
UTF-8 with `errors="replace"` to handle DBC files with Latin-1 comment text. Malformed signal
lines are silently skipped.

### `CanDbcParser.from_string(text)`

Parse DBC text directly. Used in testing and when the DBC content is already in memory.

### `messages() -> list[CANMessage]`

Return all messages sorted by canonical CAN ID.

### `message(can_id: int) -> Optional[CANMessage]`

Return the message for a canonical CAN ID, or None. Pass the 29-bit ID (not the raw DBC ID
with bit 31 set).

### `find_signals(pattern: str) -> list[tuple[CANMessage, CANSignal]]`

Return all (message, signal) pairs where the signal name contains `pattern` as a
case-insensitive substring. Results are sorted by (msg_id, signal name).

### `standard_messages() -> list[CANMessage]`

Return only 11-bit standard frame messages.

### `extended_messages() -> list[CANMessage]`

Return only 29-bit extended frame messages.

### `signal_count() -> int`

Return total signal count across all messages.

### `summary() -> str`

Return a short text block with message count (standard/extended split), signal count, and
value table count.

---

## Data types

### `CANMessage`

| Field | Type | Description |
|---|---|---|
| `msg_id` | `int` | Canonical CAN ID (bit 31 stripped) |
| `name` | `str` | Message name from DBC |
| `dlc` | `int` | Data length code in bytes |
| `sender` | `str` | Sender node name |
| `is_extended` | `bool` | True for 29-bit extended frame |
| `signals` | `list[CANSignal]` | Signals in this message |
| `comment` | `str` | Message comment from CM_ record |
| `raw_id` | property | DBC raw ID (bit 31 set for extended) |

### `CANSignal`

| Field | Type | Description |
|---|---|---|
| `name` | `str` | Signal name |
| `start_bit` | `int` | Start bit position |
| `length` | `int` | Bit length |
| `little_endian` | `bool` | True = Intel byte order; False = Motorola |
| `is_signed` | `bool` | True when `-` sign flag present |
| `factor` | `float` | Scale factor for raw -> physical |
| `offset` | `float` | Offset for raw -> physical |
| `min_val` | `float` | Physical minimum |
| `max_val` | `float` | Physical maximum |
| `unit` | `str` | Physical unit string |
| `receivers` | `list[str]` | Receiver node names |
| `comment` | `str` | Signal comment from CM_ record |
| `value_table` | `dict[int, str]` | Enumerated state names from VAL_ record |

`CANSignal.decode(raw_int)` returns `raw_int * factor + offset`.

---

## Validated results

### BMW E39 (3-message sample)

```
CAN DBC database
  messages : 3 total (3 standard  0 extended)
  signals  : 20
  val_tables: 4
  DME_316.Status_DSC: {1: 'OK', 0: 'DSC_ERROR'}
```

### BMW E90 (full network)

```
CAN DBC database
  messages : 66 total (66 standard  0 extended)
  signals  : 96
  val_tables: 34
  Messages with comments: 66
  Signals with comments: 37
```

Sample: `TORQ_0A8` comment: `0x0A8 TORQ (DME): Torque/Brake/Clutch Data`

### SAE J1939 (multi-PGN sample)

```
CAN DBC database
  messages : 8 total (1 standard  7 extended)
  signals  : 32
  val_tables: 5
  EEC1 EngineSpeed: start=24, factor=0.125, decode(2000)=250.0 rpm
```

EEC1 message ID: 0x0CF004FE (PGN 0xF004, source 0xFE). Raw DBC ID: 0x8CF004FE (bit 31 set).
Signal decode at raw=2000: 2000 * 0.125 + 0 = 250.0 rpm.

---

## Limitations

- **Motorola byte order not decoded.** `CANSignal.little_endian = False` is stored correctly,
  but `decode()` applies the same linear formula regardless of byte order. Callers that need
  Motorola bit extraction must implement it separately using `start_bit` and `length`.

- **Multiplexed signals stored but not grouped.** The `M`/`m<n>` multiplexor indicator is
  detected and skipped. All signals are stored flat under the message; multiplexor ID grouping
  is not provided.

- **`ENVVAR_` and `SIGGROUP_` records not parsed.** Environment variable declarations and
  signal groups are not extracted. Most RE use cases do not need them.

- **`DEFINE_` attribute records not parsed.** Extended attribute definitions (`DEFINE_`,
  `ATTRIBUTE_`, `BA_`) are not extracted. Signal-level attribute data (e.g. `SystemSignalLongSymbol`
  for names longer than 128 characters) is not available.
