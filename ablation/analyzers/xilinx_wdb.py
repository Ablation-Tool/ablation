"""Streaming Xilinx WDB 01 event recovery for legacy two-section files.

The legacy profile has RTTI and WDB.Event pointers at 0x48/0x50 and no embedded
Xilinx ISim DBG 006 database. Events are decoded with storage identifiers only;
names and types are never invented. The newer three-section event layout is
accepted for bounded event-only analysis, not DBG name/type resolution.

Format evidence: Vivado-WDB-Waveform-Converter, MIT license, commit
419f78bad3e8286a70574a685acf1043e33105c5. See the upstream license in
``ablation/data/vivado_wdb_upstream_LICENSE.txt``.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
import mmap
from pathlib import Path
import struct
from typing import Iterable, Iterator, Optional
import zlib

WDB_MAGIC = b'Xilinx WAVE DATABASE 01\x00'
EVENT_MAGIC = b'WDB.Event\x00'
PAGE_SIZE = 0x4C0
MAX_CHUNKS_PER_PAGE = 100
MAX_DECOMPRESSED_CHUNK = 64 * 1024 * 1024
MAX_EVENT_PAYLOAD = 1024 * 1024


class WdbDecodeError(ValueError):
    pass


@dataclass(frozen=True)
class WdbEvent:
    root_index: int
    storage_id: int
    time: int
    payload: bytes
    chunk_serial: int
    slot: int

    def to_dict(self, payload_limit: int = 64) -> dict[str, object]:
        if not 1 <= payload_limit <= MAX_EVENT_PAYLOAD:
            raise ValueError('payload export limit outside supported range')
        return {
            'root_index': self.root_index,
            'storage_id': f'0x{self.storage_id:X}',
            'time': self.time,
            'time_ps': self.time,
            'payload_bytes': len(self.payload),
            'payload_hex': self.payload[:payload_limit].hex(),
            'payload_truncated': len(self.payload) > payload_limit,
            'chunk_serial': self.chunk_serial,
            'slot': self.slot,
        }


@dataclass
class _Root:
    index: int
    first_page: int
    pages: list[int] = field(default_factory=list)
    chunks: int = 0
    records: int = 0


@dataclass
class _StreamSummary:
    root_index: int
    storage_id: int
    count: int = 0
    first_time: int = 0
    last_time: int = 0
    first_payload: bytes = b''
    last_payload: bytes = b''
    payload_sizes: set[int] = field(default_factory=set)

    def to_dict(self) -> dict[str, object]:
        return {
            'root_index': self.root_index,
            'storage_id': f'0x{self.storage_id:X}',
            'events': self.count,
            'first_time': self.first_time,
            'last_time': self.last_time,
            'payload_sizes': sorted(self.payload_sizes),
            'first_payload_hex': self.first_payload.hex(),
            'last_payload_hex': self.last_payload.hex(),
        }


class WdbReader:
    """Read a WDB through a bounded memory map and streaming event iterator."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_file_bytes: int = 4 * 1024 * 1024 * 1024,
        max_events: int = 50_000_000,
        max_streams: int = 100_000,
    ) -> None:
        if max_file_bytes < 0x60 or max_file_bytes > 4 * 1024 * 1024 * 1024:
            raise ValueError('WDB file-size limit outside 0x60..4 GiB')
        if not 1 <= max_events <= 1_000_000_000:
            raise ValueError('WDB event limit outside 1..1000000000')
        if not 1 <= max_streams <= 1_000_000:
            raise ValueError('WDB stream limit outside 1..1000000')
        self.path = Path(path)
        self.max_events = max_events
        self.max_streams = max_streams
        self._stream = self.path.open('rb')
        try:
            size = self.path.stat().st_size
            if size < 0x60:
                raise WdbDecodeError('truncated WDB header')
            if size > max_file_bytes:
                raise WdbDecodeError(f'WDB exceeds configured {max_file_bytes} byte limit')
            self._map = mmap.mmap(self._stream.fileno(), 0, access=mmap.ACCESS_READ)
        except Exception:
            self._stream.close()
            raise
        self.size = size
        self.sections: dict[str, int] = {}
        self.profile = ''
        self.final_section = 0
        self.event_wrapper = 0
        try:
            self._parse_header()
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        if self._map is not None:
            self._map.close()
            self._map = None
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    def __enter__(self) -> 'WdbReader':
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def _data(self) -> mmap.mmap:
        if self._map is None:
            raise WdbDecodeError('WDB reader is closed')
        return self._map

    def _u32(self, offset: int) -> int:
        data = self._data()
        if offset < 0 or offset + 4 > self.size:
            raise WdbDecodeError(f'uint32 outside WDB at 0x{offset:X}')
        return struct.unpack_from('<I', data, offset)[0]

    def _u64(self, offset: int) -> int:
        data = self._data()
        if offset < 0 or offset + 8 > self.size:
            raise WdbDecodeError(f'uint64 outside WDB at 0x{offset:X}')
        return struct.unpack_from('<Q', data, offset)[0]

    def _magic(self, offset: int) -> str:
        data = self._data()
        if offset < 0 or offset >= self.size:
            return '<outside-file>'
        end = data.find(b'\0', offset, min(self.size, offset + 64))
        if end < 0:
            end = min(self.size, offset + 32)
        return bytes(data[offset:end]).decode('ascii', errors='replace')

    def _parse_header(self) -> None:
        data = self._data()
        if bytes(data[:len(WDB_MAGIC)]) != WDB_MAGIC:
            raise WdbDecodeError(f'unsupported WDB signature: {bytes(data[:32])!r}')
        pointers = [self._u64(offset) for offset in (0x48, 0x50, 0x58)]
        if any(pointer < 0 or pointer >= self.size for pointer in pointers[:2]):
            raise WdbDecodeError('WDB RTTI/Event pointers are outside the file')
        if pointers[0] == pointers[1]:
            raise WdbDecodeError('WDB RTTI and Event sections overlap')
        if pointers[2] == 0:
            self.profile = 'legacy-two-section'
            selected = pointers[:2]
            expected = {'Xilinx RTTI', 'WDB.Event'}
        else:
            self.profile = 'three-section-event-only'
            selected = pointers
            expected = {'Xilinx RTTI', 'Xilinx DBG', 'WDB.Event'}
        if any(pointer <= 0 or pointer >= self.size for pointer in selected):
            raise WdbDecodeError('WDB section pointer is outside the file')
        if selected != sorted(selected) or len(set(selected)) != len(selected):
            raise WdbDecodeError('WDB sections are not unique ascending offsets')
        self.sections = {self._magic(pointer): pointer for pointer in selected}
        if set(self.sections) != expected or len(self.sections) != len(selected):
            raise WdbDecodeError(
                f'unsupported {self.profile} section set: {sorted(self.sections)!r}'
            )
        self.final_section = selected[-1]
        self.event_wrapper = self.sections['WDB.Event']
        scanned = data.find(EVENT_MAGIC)
        if scanned != self.event_wrapper:
            raise WdbDecodeError(
                f'WDB.Event header pointer 0x{self.event_wrapper:X} does not match wrapper scan 0x{scanned:X}'
            )

    def _page_valid(self, offset: int, *, require_nonempty: bool) -> bool:
        if offset < 0 or offset + PAGE_SIZE > self.size:
            return False
        count = self._u32(offset + 0x4B8)
        if count > MAX_CHUNKS_PER_PAGE or (require_nonempty and count == 0):
            return False
        for index in range(count):
            pointer = self._u64(offset + 0x08 + index * 8)
            size = self._u32(offset + 0x328 + index * 4)
            if pointer <= 0 or size <= 0 or pointer + size > self.size:
                return False
        return True

    def _discover_roots(self) -> list[_Root]:
        start = self.final_section + 0x30
        roots = []
        earliest_payload = self.size
        for index in range(1024):
            offset = start + index * PAGE_SIZE
            if offset >= earliest_payload or not self._page_valid(offset, require_nonempty=True):
                break
            count = self._u32(offset + 0x4B8)
            for slot in range(count):
                earliest_payload = min(earliest_payload, self._u64(offset + 0x08 + slot * 8))
            roots.append(_Root(index, offset))
        if not roots:
            raise WdbDecodeError(f'no event roots recognized at 0x{start:X}')
        return roots

    def _page_chain(self, first: int) -> Iterator[int]:
        seen = set()
        page = first
        while page:
            if page in seen:
                raise WdbDecodeError(f'cycle in event page chain at 0x{page:X}')
            if len(seen) >= 100_000:
                raise WdbDecodeError('event page chain exceeds 100000 pages')
            seen.add(page)
            if not self._page_valid(page, require_nonempty=False):
                raise WdbDecodeError(f'invalid event index page at 0x{page:X}')
            yield page
            following = self._u64(page)
            if following and following + PAGE_SIZE > self.size:
                raise WdbDecodeError(f'continuation page 0x{following:X} is outside WDB')
            page = following

    def _decompress(self, compressed: bytes) -> bytes:
        engine = zlib.decompressobj()
        try:
            result = engine.decompress(compressed, MAX_DECOMPRESSED_CHUNK + 1)
            if len(result) <= MAX_DECOMPRESSED_CHUNK:
                result += engine.flush(MAX_DECOMPRESSED_CHUNK + 1 - len(result))
        except zlib.error as error:
            raise WdbDecodeError(f'zlib event payload failure: {error}') from error
        if len(result) > MAX_DECOMPRESSED_CHUNK or engine.unconsumed_tail or not engine.eof:
            raise WdbDecodeError('decompressed event chunk exceeds configured limit')
        return result

    @staticmethod
    def _decode_chunk(
        payload: bytes,
        root: _Root,
        chunk_serial: int,
    ) -> Iterator[WdbEvent]:
        if len(payload) < 20:
            raise WdbDecodeError(f'decompressed chunk {chunk_serial} is truncated')
        record_count = struct.unpack_from('<I', payload, 16)[0]
        offset = 20
        for slot in range(record_count):
            if offset + 16 > len(payload):
                raise WdbDecodeError(f'chunk {chunk_serial}: record header exceeds chunk')
            time_lo, time_hi, storage_id, payload_bytes = struct.unpack_from('<4I', payload, offset)
            offset += 16
            if payload_bytes == 0 or payload_bytes > MAX_EVENT_PAYLOAD:
                raise WdbDecodeError(
                    f'chunk {chunk_serial}: implausible payload size {payload_bytes}'
                )
            if offset + payload_bytes > len(payload):
                raise WdbDecodeError(f'chunk {chunk_serial}: event payload exceeds chunk')
            yield WdbEvent(
                root.index,
                storage_id,
                time_lo | (time_hi << 32),
                payload[offset:offset + payload_bytes],
                chunk_serial,
                slot,
            )
            offset += payload_bytes
        if any(payload[offset:]):
            raise WdbDecodeError(f'chunk {chunk_serial}: nonzero trailing bytes')

    def events(self) -> Iterator[WdbEvent]:
        roots = self._discover_roots()
        chunk_serial = 0
        total_records = 0
        for root in roots:
            for page in self._page_chain(root.first_page):
                root.pages.append(page)
                count = self._u32(page + 0x4B8)
                for slot in range(count):
                    pointer = self._u64(page + 0x08 + slot * 8)
                    size = self._u32(page + 0x328 + slot * 4)
                    payload = self._decompress(bytes(self._data()[pointer:pointer + size]))
                    for event in self._decode_chunk(payload, root, chunk_serial):
                        root.records += 1
                        total_records += 1
                        if total_records > self.max_events:
                            raise WdbDecodeError('WDB event count exceeds configured limit')
                        yield event
                    root.chunks += 1
                    chunk_serial += 1

    def summary(self, *, stream_limit: int = 64) -> dict[str, object]:
        if not 1 <= stream_limit <= 100_000:
            raise ValueError('WDB summary stream limit outside 1..100000')
        roots: dict[int, dict[str, object]] = {}
        streams: dict[tuple[int, int], _StreamSummary] = {}
        event_count = 0
        first_time = None
        last_time = None
        for event in self.events():
            event_count += 1
            if event_count > self.max_events:
                raise WdbDecodeError('WDB event count exceeds configured limit')
            first_time = event.time if first_time is None else min(first_time, event.time)
            last_time = event.time if last_time is None else max(last_time, event.time)
            root = roots.setdefault(event.root_index, {'root_index': event.root_index, 'events': 0})
            root['events'] = int(root['events']) + 1
            key = (event.root_index, event.storage_id)
            if key not in streams:
                if len(streams) >= self.max_streams:
                    raise WdbDecodeError('WDB storage stream count exceeds configured limit')
                streams[key] = _StreamSummary(
                    event.root_index,
                    event.storage_id,
                    first_time=event.time,
                    first_payload=event.payload[:16],
                )
            stream = streams[key]
            stream.count += 1
            stream.last_time = event.time
            stream.last_payload = event.payload[:16]
            if len(stream.payload_sizes) < 32:
                stream.payload_sizes.add(len(event.payload))
        if event_count == 0:
            raise WdbDecodeError('WDB event table contained no waveform records')
        ordered = sorted(streams.values(), key=lambda item: (-item.count, item.root_index, item.storage_id))
        return {
            'schema': 'ablation.xilinx-wdb-summary.v1',
            'path': str(self.path.resolve()),
            'size': self.size,
            'profile': self.profile,
            'sections': {name: f'0x{offset:X}' for name, offset in sorted(self.sections.items())},
            'event_wrapper': f'0x{self.event_wrapper:X}',
            'event_ticks': '1 ps for the characterized XSim profile',
            'events': event_count,
            'roots': [roots[index] for index in sorted(roots)],
            'storage_streams': len(streams),
            'first_time': first_time,
            'last_time': last_time,
            'top_streams': [stream.to_dict() for stream in ordered[:stream_limit]],
            'name_mapping': 'not available in legacy event-only profile',
        }

    def export_jsonl(
        self,
        destination: str | Path,
        *,
        roots: Optional[Iterable[int]] = None,
        max_events: int = 100_000,
        start_time: Optional[int] = None,
        end_time: Optional[int] = None,
        payload_limit: int = 64,
    ) -> dict[str, object]:
        if not 1 <= max_events <= 1_000_000:
            raise ValueError('JSONL event export limit outside 1..1000000')
        selected = set(roots) if roots is not None else None
        if selected is not None and len(selected) > 1024:
            raise ValueError('too many selected WDB roots')
        if start_time is not None and end_time is not None and start_time > end_time:
            raise ValueError('WDB start time is after end time')
        output = Path(destination)
        temporary = output.with_suffix(output.suffix + '.tmp')
        exported = 0
        try:
            with temporary.open('w', encoding='utf-8') as stream:
                for event in self.events():
                    if selected is not None and event.root_index not in selected:
                        continue
                    if start_time is not None and event.time < start_time:
                        continue
                    if end_time is not None and event.time > end_time:
                        continue
                    if exported >= max_events:
                        break
                    stream.write(json.dumps(event.to_dict(payload_limit)) + '\n')
                    exported += 1
            temporary.replace(output)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        return {
            'path': str(output.resolve()),
            'events': exported,
            'max_events': max_events,
            'complete_within_limit': exported < max_events,
            'payload_limit': payload_limit,
        }


def _cli(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--events-output', type=Path)
    parser.add_argument('--summary-output', type=Path)
    parser.add_argument('--root', action='append', type=int)
    parser.add_argument('--max-events', type=int, default=100_000)
    parser.add_argument('--payload-limit', type=int, default=64)
    args = parser.parse_args(argv)
    with WdbReader(args.input) as reader:
        summary = reader.summary()
        export = None
        if args.events_output:
            export = reader.export_jsonl(
                args.events_output,
                roots=args.root,
                max_events=args.max_events,
                payload_limit=args.payload_limit,
            )
    if export is not None:
        summary['event_export'] = export
    text = json.dumps(summary, indent=2) + '\n'
    if args.summary_output:
        args.summary_output.write_text(text, encoding='utf-8')
    else:
        print(text, end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(_cli())
