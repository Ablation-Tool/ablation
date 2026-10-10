# CanDbcParser

**File:** `ablation/analyzers/can_dbc_parser.py`

---

## Why this exists

4 things that were not possible before in Ablation:

**1. No CAN DBC database parsing.** CANdb++, SavvyCAN, Wireshark, BUSMASTER, and cantools all
use the Vector DBC format as their CAN signal database file. A DBC file defines every message
ID, signal bit layout, scale factor, and offset for a CAN network. Without a DBC parser, ECU
analysis had table addresses from XDF and A2L parsers but no signal layout. There was no way to
look up which CAN signal a ROM calibration table feeds.

**2. No 29-bit extended frame ID decoding.** DBC files mark 29-bit extended CAN frames by
setting bit 31 in the raw message ID field. J1939 ECUs use extended frames for every
PGN-addressed message (e.g., EEC1 Engine Speed at raw ID 0x0CF004FE). Without bit-31
detection, a parser stores the wrong canonical ID and every extended message is unreachable by
`message()` lookup. This parser masks bit 31 at parse time and stores the 29-bit ID in
`msg_id`.

**3. No value table resolution.** DBC `VAL_` records map raw signal integers to state names:
gear positions, fault codes, mode flags. Without a second pass over the file to read `VAL_`
entries, a signal object has a name and a scale factor but no state names. This parser reads
`VAL_` records in a second pass and stores the result in `CANSignal.value_table`.

**4. No signal comment recovery.** DBC `CM_` records carry the manufacturer's description of
each signal and message. These descriptions survive DBC export from CANdb++ and often say what
a signal controls or which ECU subsystem produces it. `CM_` records appear after all `BO_`/`SG_`
blocks in the file and can span multiple lines. Without a second pass with `re.DOTALL` over the
full file text, all comment content was missing. This parser recovers both signal and message
comments in the second pass.

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
