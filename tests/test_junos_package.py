import hashlib
import io
import tarfile

import pytest

from ablation.core.junos_package import extract_package, extract_tar_safely, verify_embedded_hashes
from tests.test_iso9660 import _iso
from tests.test_junos_compressed_iso import _build_image


def _member(name: str, data: bytes) -> tuple[tarfile.TarInfo, io.BytesIO]:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o644
    return info, io.BytesIO(data)


def test_extract_package_and_hashes(tmp_path):
    compressed, _ = _build_image([b"a" * 65536])
    package = tmp_path / "package.tgz"
    with tarfile.open(package, "w:gz") as archive:
        archive.addfile(*_member("payload", compressed))
        archive.addfile(*_member("payload.sha1", hashlib.sha1(compressed).hexdigest().encode() + b"\n"))

    result = extract_package(package, tmp_path / "output", extract_iso=False)

    assert result.iso_info.block_count == 1
    assert len(result.hashes) == 1
    assert result.hashes[0].valid
    assert (tmp_path / "output" / "payload.iso").is_file()
    assert (tmp_path / "output" / "metadata.json").is_file()


def test_extract_tar_rejects_traversal(tmp_path):
    package = tmp_path / "malicious.tgz"
    with tarfile.open(package, "w:gz") as archive:
        archive.addfile(*_member("../escape", b"bad"))

    with pytest.raises(ValueError, match="Unsafe archive path"):
        extract_tar_safely(package, tmp_path / "output")


def test_hash_mismatch_is_reported(tmp_path):
    target = tmp_path / "payload"
    target.write_bytes(b"actual")
    target.with_suffix(".sha1").write_text("0000000000000000000000000000000000000000\n")

    results = verify_embedded_hashes(tmp_path)

    assert len(results) == 1
    assert not results[0].valid
    assert results[0].actual == hashlib.sha1(b"actual").hexdigest()
