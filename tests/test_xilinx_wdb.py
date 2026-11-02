import json
from pathlib import Path
import struct
import zlib

import pytest

import ablation.analyzers.xilinx_wdb as xilinx_wdb
from ablation.analyzers.xilinx_wdb import WdbDecodeError, WdbReader


LEGACY_WDB = Path('/media/cowboy/research/CERN/analysis/wdb/endeavour_tb_behav.wdb')


def legacy_image(record_count: int = 2) -> bytearray:
    compressed_pointer = 0x1000
    chunk = bytearray(20)
    struct.pack_into('<QQI', chunk, 0, 42, 43, record_count)
    records = (
        struct.pack('<4I', 42, 0, 7, 1) + b'\x01',
        struct.pack('<4I', 43, 0, 7, 1) + b'\x00',
    )
    chunk.extend(b''.join(records[:record_count]))
    compressed = zlib.compress(bytes(chunk))
    image = bytearray(compressed_pointer + len(compressed))
    image[:24] = b'Xilinx WAVE DATABASE 01\x00'
    image[0x60:0x60 + 12] = b'Xilinx RTTI\x00'
    image[0x80:0x80 + 10] = b'WDB.Event\x00'
    struct.pack_into('<Q', image, 0x48, 0x60)
    struct.pack_into('<Q', image, 0x50, 0x80)
    struct.pack_into('<Q', image, 0x58, 0)
    page = 0xB0
    struct.pack_into('<Q', image, page + 0x08, compressed_pointer)
    struct.pack_into('<I', image, page + 0x328, len(compressed))
    struct.pack_into('<I', image, page + 0x4B8, 1)
    image[compressed_pointer:] = compressed
    return image


def test_legacy_summary_and_filtered_jsonl(tmp_path):
    source = tmp_path / 'sample.wdb'
    source.write_bytes(legacy_image())
    output = tmp_path / 'events.jsonl'

    with WdbReader(source) as reader:
        summary = reader.summary()
        export = reader.export_jsonl(output, roots={0}, payload_limit=1)

    assert summary['profile'] == 'legacy-two-section'
    assert summary['events'] == 2
    assert summary['storage_streams'] == 1
    assert summary['first_time'] == 42
    assert summary['last_time'] == 43
    assert summary['top_streams'][0]['payload_sizes'] == [1]
    assert summary['top_streams'][0]['first_payload_hex'] == '01'
    assert summary['top_streams'][0]['last_payload_hex'] == '00'
    assert export['events'] == 2
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    assert [row['time'] for row in rows] == [42, 43]
    assert rows[0]['storage_id'] == '0x7'
    assert not output.with_suffix('.jsonl.tmp').exists()


def test_invalid_signature_and_out_of_range_section(tmp_path):
    source = tmp_path / 'bad.wdb'
    image = legacy_image()
    image[0] = 0
    source.write_bytes(image)
    with pytest.raises(WdbDecodeError, match='signature'):
        WdbReader(source)

    image = legacy_image()
    struct.pack_into('<Q', image, 0x50, len(image) + 1)
    source.write_bytes(image)
    with pytest.raises(WdbDecodeError, match='outside'):
        WdbReader(source)


def test_bad_zlib_and_page_cycle_fail_closed(tmp_path):
    source = tmp_path / 'bad-zlib.wdb'
    image = legacy_image()
    image[0x1000] = 0
    source.write_bytes(image)
    with WdbReader(source) as reader, pytest.raises(WdbDecodeError, match='zlib'):
        list(reader.events())

    source = tmp_path / 'cycle.wdb'
    image = legacy_image()
    struct.pack_into('<Q', image, 0xB0, 0xB0)
    source.write_bytes(image)
    with WdbReader(source) as reader, pytest.raises(WdbDecodeError, match='cycle'):
        list(reader.events())


def test_event_and_stream_limits(tmp_path):
    source = tmp_path / 'limited.wdb'
    source.write_bytes(legacy_image())
    with WdbReader(source, max_events=1) as reader, pytest.raises(WdbDecodeError, match='event count'):
        reader.summary()
    with WdbReader(source, max_streams=1) as reader, pytest.raises(ValueError, match='payload export limit'):
        reader.export_jsonl(tmp_path / 'bad.jsonl', payload_limit=0)


def test_decompression_limit_cannot_be_bypassed_by_flush(tmp_path, monkeypatch):
    source = tmp_path / 'compressed.wdb'
    source.write_bytes(legacy_image())
    monkeypatch.setattr(xilinx_wdb, 'MAX_DECOMPRESSED_CHUNK', 32)
    with WdbReader(source) as reader, pytest.raises(WdbDecodeError, match='decompressed event chunk'):
        list(reader.events())


def test_empty_event_table_is_rejected(tmp_path):
    source = tmp_path / 'empty.wdb'
    source.write_bytes(legacy_image(record_count=0))
    with WdbReader(source) as reader, pytest.raises(WdbDecodeError, match='no waveform records'):
        reader.summary()


@pytest.mark.integration
@pytest.mark.skipif(not LEGACY_WDB.is_file(), reason='Endeavour WDB not available')
def test_real_legacy_wdb_summary_and_export(tmp_path):
    with WdbReader(LEGACY_WDB) as reader:
        summary = reader.summary()
        export = reader.export_jsonl(tmp_path / 'first.jsonl', max_events=16)

    assert summary['profile'] == 'legacy-two-section'
    assert len(summary['roots']) == 21
    assert summary['events'] == 10_759_544
    assert summary['first_time'] == 0
    assert summary['last_time'] == 10_030_000_000
    assert export['events'] == 16
    assert not export['complete_within_limit']
    assert summary['name_mapping'] == 'not available in legacy event-only profile'
