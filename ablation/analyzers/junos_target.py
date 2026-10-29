"""Junos target-profile loading and component selection."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from ablation.analyzers.mips_elf import describe_mips_elf


@dataclass(frozen=True)
class JunosTargetProfile:
    name: str
    data: dict

    @classmethod
    def from_name(cls, name: str = "junos-octeon-o32") -> "JunosTargetProfile":
        path = Path(__file__).parent.parent / "profiles" / f"{name}.yaml"
        if not path.is_file():
            raise FileNotFoundError(f"No Junos target profile: {path}")
        with path.open() as stream:
            data = yaml.safe_load(stream)
        return cls(name=name, data=data)

    def report(self, binary: str | Path) -> dict[str, object]:
        return {
            "profile": self.name,
            "configured": self.data,
            "elf": describe_mips_elf(binary),
        }
