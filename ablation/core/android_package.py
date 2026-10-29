"""APK and XAPK container decoding with in-memory split APK support."""

from __future__ import annotations

import hashlib
import json
import struct
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from ablation.core.apk_parser import APKParser, axml_to_xml, decode_axml


@dataclass
class APKInventory:
    name: str
    split_id: str
    size: int
    sha256: str
    package: str = ""
    version_name: str = ""
    version_code: int = 0
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: List[str] = field(default_factory=list)
    dex_files: List[str] = field(default_factory=list)
    native_libs: List[str] = field(default_factory=list)
    network_security_config: Optional[str] = None
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class NativeLibrary:
    apk_name: str
    entry_path: str
    abi: str
    data: bytes = field(repr=False)

    @property
    def name(self) -> str:
        return Path(self.entry_path).name


class AndroidPackage:
    """Decode a plain APK or an XAPK containing base and configuration APKs."""

    def __init__(self, path: Path, max_apk_bytes: int = 256 * 1024 * 1024) -> None:
        if max_apk_bytes <= 0:
            raise ValueError("max_apk_bytes must be positive")
        self.path = path
        self.max_apk_bytes = max_apk_bytes
        self._zf: Optional[zipfile.ZipFile] = None
        self._apk_names: List[str] = []
        self._manifest: Dict = {}

    @classmethod
    def from_path(cls, path: str | Path, max_apk_bytes: int = 256 * 1024 * 1024) -> "AndroidPackage":
        package_path = Path(path)
        if not package_path.is_file():
            raise FileNotFoundError(f"Android package not found: {package_path}")
        inst = cls(package_path, max_apk_bytes=max_apk_bytes)
        try:
            inst._zf = zipfile.ZipFile(package_path, "r")
            names = inst._zf.namelist()
            if "AndroidManifest.xml" in names:
                if package_path.stat().st_size > max_apk_bytes:
                    raise ValueError(f"APK exceeds the {max_apk_bytes}-byte limit")
                inst._apk_names = [package_path.name]
            else:
                inst._apk_names = sorted(name for name in names if name.endswith(".apk"))
                if not inst._apk_names:
                    raise ValueError(f"No APK members found in {package_path}")
                if "manifest.json" in names:
                    if inst._zf.getinfo("manifest.json").file_size > 1024 * 1024:
                        raise ValueError("XAPK manifest.json exceeds the 1 MiB limit")
                    raw = json.loads(inst._zf.read("manifest.json"))
                    if not isinstance(raw, dict):
                        raise ValueError("XAPK manifest.json must contain an object")
                    inst._manifest = raw
            return inst
        except Exception:
            inst.close()
            raise

    def close(self) -> None:
        if self._zf is not None:
            self._zf.close()

    def __enter__(self) -> "AndroidPackage":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    @property
    def is_xapk(self) -> bool:
        return not self._apk_names or self._apk_names != [self.path.name]

    @property
    def xapk_manifest(self) -> Dict:
        return dict(self._manifest)

    def apk_names(self) -> List[str]:
        return list(self._apk_names)

    def read_apk(self, name: str) -> bytes:
        if self._zf is None:
            raise ValueError("Package is closed")
        if name not in self._apk_names:
            raise KeyError(name)
        if not self.is_xapk:
            if self.path.stat().st_size > self.max_apk_bytes:
                raise ValueError(f"APK exceeds the {self.max_apk_bytes}-byte limit")
            return self.path.read_bytes()
        if self._zf.getinfo(name).file_size > self.max_apk_bytes:
            raise ValueError(f"APK member {name!r} exceeds the {self.max_apk_bytes}-byte limit")
        return self._zf.read(name)

    def iter_apks(self) -> Iterator[APKParser]:
        for name in self._apk_names:
            yield APKParser.from_bytes(self.read_apk(name), name=name)

    def split_id(self, name: str) -> str:
        for split in self._manifest.get("split_apks", []):
            if split.get("file") == name:
                return str(split.get("id", ""))
        return "base" if not self.is_xapk else ""

    def inventory(self) -> List[APKInventory]:
        records: List[APKInventory] = []
        for apk in self.iter_apks():
            raw = self.read_apk(apk._path.name)
            record = APKInventory(
                name=apk._path.name,
                split_id=self.split_id(apk._path.name),
                size=len(raw),
                sha256=hashlib.sha256(raw).hexdigest(),
            )
            try:
                manifest = apk.parse_manifest()
                record.package = manifest.package
                record.version_name = manifest.version_name
                record.version_code = manifest.version_code
                record.min_sdk = manifest.min_sdk
                record.target_sdk = manifest.target_sdk
                record.permissions = list(manifest.permissions)
                record.network_security_config = manifest.network_security_config
                record.dex_files = [
                    name for name in apk.namelist()
                    if name.startswith("classes") and name.endswith(".dex")
                ]
                record.native_libs = apk.native_libs()
            except (KeyError, ValueError, struct.error) as exc:
                record.error = str(exc)
            finally:
                apk.close()
            records.append(record)
        return records

    def decode_xml(self, apk_name: str, entry_name: str) -> str:
        with APKParser.from_bytes(self.read_apk(apk_name), name=apk_name) as apk:
            return axml_to_xml(apk.read_file(entry_name, max_size=self.max_apk_bytes))

    def decode_xml_tree(self, apk_name: str, entry_name: str) -> Dict:
        with APKParser.from_bytes(self.read_apk(apk_name), name=apk_name) as apk:
            return decode_axml(apk.read_file(entry_name, max_size=self.max_apk_bytes))

    def iter_native_libraries(self, abi: str = "") -> Iterator[NativeLibrary]:
        for apk in self.iter_apks():
            try:
                for entry in apk.native_libs(abi=abi):
                    entry_abi = entry.split("/")[1] if entry.count("/") >= 2 else ""
                    yield NativeLibrary(apk._path.name, entry, entry_abi, apk.read_file(entry, max_size=self.max_apk_bytes))
            finally:
                apk.close()

    def to_dict(self) -> dict:
        return {
            "path": str(self.path),
            "format": "xapk" if self.is_xapk else "apk",
            "xapk_manifest": self.xapk_manifest,
            "apks": [record.to_dict() for record in self.inventory()],
        }
