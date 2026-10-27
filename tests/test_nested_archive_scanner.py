import io
import tarfile
import zipfile

import pytest

import ablation.analyzers.nested_archive_scanner as nested


ELF = b'\x7fELF' + b'\x00' * 60


def make_zip(path, members):
    with zipfile.ZipFile(path, 'w') as archive:
        for name, data in members:
            archive.writestr(name, data)


def make_tar_gz(members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


def test_extract_zip_valid_member(tmp_path):
    archive = tmp_path / 'valid.zip'
    make_zip(archive, [('usr/lib/example.so', ELF)])

    with nested._extract_to_tmpdir(str(archive), 'zip') as extracted:
        assert (nested.Path(extracted) / 'usr/lib/example.so').read_bytes() == ELF


def test_zip_member_traversal_is_rejected(tmp_path):
    archive = tmp_path / 'traversal.zip'
    make_zip(archive, [('../escape.so', ELF)])

    with pytest.raises(ValueError, match='unsafe archive member path'):
        with nested._extract_to_tmpdir(str(archive), 'zip'):
            pass
    assert not (tmp_path.parent / 'escape.so').exists()


def test_zip_symlink_is_rejected(tmp_path):
    archive = tmp_path / 'link.zip'
    with zipfile.ZipFile(archive, 'w') as output:
        info = zipfile.ZipInfo('usr/lib/link.so')
        info.external_attr = 0o120777 << 16
        output.writestr(info, 'target.so')

    with pytest.raises(ValueError, match='links are not allowed'):
        with nested._extract_to_tmpdir(str(archive), 'zip'):
            pass


def test_tar_member_traversal_is_rejected(tmp_path):
    archive = tmp_path / 'traversal.tar'
    with tarfile.open(archive, 'w') as output:
        info = tarfile.TarInfo('../escape.so')
        info.size = len(ELF)
        output.addfile(info, io.BytesIO(ELF))

    with pytest.raises(ValueError, match='unsafe archive member path'):
        with nested._extract_to_tmpdir(str(archive), 'tar'):
            pass


def test_member_size_budget_is_enforced(tmp_path, monkeypatch):
    monkeypatch.setattr(nested, '_MAX_MEMBER_BYTES', 4)
    archive = tmp_path / 'large.zip'
    make_zip(archive, [('large.so', ELF)])

    with pytest.raises(ValueError, match='member size exceeds'):
        with nested._extract_to_tmpdir(str(archive), 'zip'):
            pass


def test_total_size_budget_is_enforced(tmp_path, monkeypatch):
    monkeypatch.setattr(nested, '_MAX_TOTAL_BYTES', 7)
    archive = tmp_path / 'total.zip'
    make_zip(archive, [('one', b'1234'), ('two', b'5678')])

    with pytest.raises(ValueError, match='expands beyond'):
        with nested._extract_to_tmpdir(str(archive), 'zip'):
            pass


def test_file_count_budget_is_enforced(tmp_path, monkeypatch):
    monkeypatch.setattr(nested, '_MAX_FILES', 1)
    archive = tmp_path / 'count.zip'
    make_zip(archive, [('one', b'1'), ('two', b'2')])

    with pytest.raises(ValueError, match='more than 1 files'):
        with nested._extract_to_tmpdir(str(archive), 'zip'):
            pass


def test_nested_archive_scanner_extracts_elf(tmp_path):
    inner_tar = make_tar_gz([('usr/lib/nested.so', ELF)])
    outer_zip = tmp_path / 'outer.zip'
    make_zip(outer_zip, [('payload/inner.tgz', inner_tar)])

    results = list(nested.NestedArchiveScanner.scan_archive(str(outer_zip)))
    assert len(results) == 1
    _, virtual = results[0]
    assert virtual.endswith('payload/inner.tgz/usr/lib/nested.so')


def test_invalid_nested_archive_warns_instead_of_disappearing(tmp_path):
    bad_inner = tmp_path / 'bad.zip'
    make_zip(bad_inner, [('../escape.so', ELF)])
    outer = tmp_path / 'outer.zip'
    make_zip(outer, [('bad.zip', bad_inner.read_bytes())])

    with pytest.warns(RuntimeWarning, match='Skipping archive'):
        assert list(nested.NestedArchiveScanner.scan_archive(str(outer))) == []


def test_cpio_listing_is_validated():
    budget = nested._new_budget()
    nested._validate_cpio_listing(
        '-rw-r--r--   1 root root 4 Jan  1  2020 usr/bin/example', budget
    )
    assert budget == {'bytes': 4, 'files': 1}

    with pytest.raises(ValueError, match='unsafe archive member path'):
        nested._validate_cpio_listing(
            '-rw-r--r--   1 root root 4 Jan  1  2020 ../escape', nested._new_budget()
        )
