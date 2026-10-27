"""Compatibility entry point for the Junos compressed-ISO decoder."""
from ablation.parsers.junos_container import (
    BLOCK_SIZE,
    COMPOSITE_MAGIC,
    JunosISOInfo,
    decompress,
    main,
    probe,
)

__all__ = [
    "BLOCK_SIZE",
    "COMPOSITE_MAGIC",
    "JunosISOInfo",
    "decompress",
    "main",
    "probe",
]


if __name__ == "__main__":
    main()
