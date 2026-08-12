# Ablation

**Autonomous Reverse Engineering Tool**

Deploy inside compromised systems to autonomously reverse engineer unknown platforms.

```
    ___    ____  __    ___  ______________  _   __
   /   |  / __ )/ /   /   |/_  __/  _/ __ \/ | / /
  / /| | / __  / /   / /| | / /  / // / / /  |/ / 
 / ___ |/ /_/ / /___/ ___ |/ / _/ // /_/ / /|  /  
/_/  |_/_____/_____/_/  |_/_/ /___/\____/_/ |_/   
                                                  
                                                   
 Autonomous Reverse Engineering Tool v2.2.0
```
Know the system before you own the system.
---

  <br>

  <!-- Badges styled with Deep Magenta (#961490) -->
  <img src="https://img.shields.io/badge/Language-Python_3-961490?style=flat-square" alt="Language">
  <img src="https://img.shields.io/badge/Build-PyInstaller-961490?style=flat-square" alt="Build">
  <img src="https://img.shields.io/badge/License-Research_Only-961490?style=flat-square" alt="License">
</div>

---

## ⚡ Overview

**Ablation** is a reverse engineering tool that you deploy from the inside.

### macOS
macOS support is now first-class. Ablation runs natively without modification or target environment setup.
* **`bv41` Decoder:** Standalone decoding for Apple's `Compression.framework` proprietary LZ4 containers, explicitly targeting MacStadium Orka VM image layers and APFS snapshots without requiring an Apple runtime.
* **Orka RE Module:** Advanced enumeration for Kubernetes-based macOS virtualization. Detects gRPC sockets (`/var/run/orka-engine.sock`), extracts embedded credentials from binaries, and maps cluster infrastructure from inside a macOS VM.

### 🍏 The "Special Sauce"
It's in the sauce

**Cool shit that nobody else has**
* **Cross-Platform:** Runs offline with no Apple runtime and no macOS required.
* **Targeted:** Explicitly built for Orka VM image layers and APFS snapshots for reverse engineering and supply-chain inspection.
* **Metadata Probing:** Features a `probe_bv41()` API for metadata-only inspection (chunk count, compression ratio, uncompressed size) without requiring a full decode.
* **Integrated:** Seamlessly baked into a post-exploitation autonomous RE tool with CLI one-liner capabilities and PyInstaller single-binary packaging.

---

## 🚀 Quick Start

### Build & Deploy

**1. Compile from source**
On your development machine (requires Python 3.8+, PyInstaller, and Capstone):
```bash
git clone [https://github.com/NuClide-Research/ablation.git](https://github.com/NuClide-Research/ablation.git)
cd ablation
./build.sh
