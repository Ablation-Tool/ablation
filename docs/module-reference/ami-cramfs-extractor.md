# AmiCramFSExtractor

## Why this exists

3 things that weren't possible before in Ablation:

1. **Extract files from AMI BMC firmware.** Standard CramFS tools (`cramfsck`, `unsquashfs`, binwalk's cramfs handler) all fail on AMI-modified CramFS because the directory inode structure changed. Before this module, analyzing the Redfish REST service (`spx_restservice`) inside an AMI SPX BMC image required guessing file offsets manually.

2. **Resolve AMI's 16-byte extended inode format.** AMI moved the data offset out of `w2` (bits[6:31], standard CramFS) into a separate 4th word `w3`, and relocated `namelen` from bits[0:5] to bits[8:13] of `w2`. No tool or public writeup documents this layout. This module reverse-engineered and encodes the format.

3. **Feed the ARM32 taint pipeline.** Once `spx_restservice` and `psme-rest-server` are extractable, `ARM32TaintTracker` can trace HTTP FastCGI input to `system()`/`strcpy()` sinks. Before this module, the attack surface of AMI-based QTECH, Supermicro, and Lenovo BMCs was opaque.

## Format notes

AMI CramFS is standard CramFS (`magic=0x28cd3d45`) with one structural change: the inode is extended from 12 to 16 bytes.

**Standard CramFS inode (12 bytes):**
```
[w0: mode(16) | uid(16)]
[w1: size(24) | gid(8)]
[w2: namelen(6,bits0-5) | offset(26,bits6-31)]
```

**AMI extended inode (16 bytes):**
```
[w0: mode(16) | uid(16)]
[w1: size(24) | gid(8)]
[w2: 0 | namelen(6,bits8-13) | other_flags(bits0-7,14+)]
[w3: data_off — absolute offset in 4-byte units from CramFS start]
```

Data storage is **unchanged** from standard CramFS:
- Directories: raw uncompressed inode list, bounded by `size` from parent inode
- Regular files: zlib-compressed 4 KB blocks with an end-pointer table at `data_off × 4`
- Symlinks: same block structure as files, target string is the "file content"

Confirmed on: QTECH BMC `G4DCL-UX-V3R29A-L01-C06087.ima`, CramFS at offset `0x160000` (36.5 MB), 3532 files.

## Usage

```python
from ablation.analyzers.ami_cramfs_extractor import AmiCramFSExtractor

# From a raw CramFS image
ext = AmiCramFSExtractor.from_path('/path/to/rootfs.cramfs')

# From inside a multi-partition firmware image
ext = AmiCramFSExtractor.from_image('/path/to/bmc.ima', offset=0x160000)

# List all files
for path in ext.list_files():
    print(path)

# Extract one binary
data = ext.extract_file('/usr/local/bin/spx_restservice')
with open('/tmp/spx_restservice', 'wb') as f:
    f.write(data)

# Extract everything
ext.extract_all('/tmp/bmc_root/', progress=print)
```

## Known targets

- QTECH BMC (ASPEED AST2xxx, SPX Redfish) — confirmed
- Supermicro BMC (same AMI SPX stack) — expected to work
- Lenovo BMC (AMI SPX) — expected to work
