"""
Fortinet FortiGate ARM64 KVM 8.0.0 RE
Source: FGT_ARM64_KVM-v8.0.0.F-build0167-FORTINET.qcow2 (128MB)
Build date: 2026-04-19 | kernel: ARM64 boot image (flatkc 17.5MB)
Hardware target: Fortinet FSOC5 custom SoC (ARM Cortex-A76 quad-core)
Products: FortiGate 50G, 70G, 90G, 120G (G-series appliances)
Extraction path: QCOW2 -> arm64.raw -> P1 (sector 2048) -> ext2 mount -> datafs.tar.gz (accessible)
Encrypted layers: rootfs.gz (custom format, magic 0x...encrypted)
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":        "Fortinet FortiGate ARM64 KVM (FortiGate G-series hardware target)",
    "os":             "FortiOS 8.0.0.F",
    "build":          "0167",
    "build_date":     "2026-04-19",
    "arch":           "AArch64 (ARM64)",
    "soc":            "Fortinet FSOC5 -- custom ARM Cortex-A76 quad-core SoC",

    "soc_details": {
        "cpu_cores":        "4x ARM Cortex-A76",
        "cpu_enable":       "PSCI (arm,psci-0.2 -- cpu_on=0xc4000003, cpu_off=0x84000002)",
        "interrupt":        "ARM GIC-v3 (generic interrupt controller)",
        "iommu":            "ARM SMMU-v3 (IOMMUv3 -- device isolation support)",
        "cache_coherency":  "ARM CCI-500 (Cache Coherency Interconnect)",
        "pmu":              "ARM ARMv8-PMUv3 (performance monitoring unit, disabled)",
        "timer_clock":      "6.25 MHz arm_timer_clk",
        "uart":             "Renesas EM-UART (renesas,em-uart)",
        "i2c":              "Renesas I2C (renesas,iic-A9mp) + NXP PCA9534/9552/9555/9557 GPIO expanders",
        "spi_flash":        "Macronix MX25U6435F (64Mbit = 8MB SPI NOR -- bootloader/config)",
        "usb":              "Fortinet custom xHCI (ftnt,fsoc5-xhci); USB 3.1 Gen1 + Gen2 (5/10 Gbps)",
        "mmc":              "ftnt,socfpga-fsoc-mshc (SD/MMC with FPGA component)",
        "gpio":             "fortinet,fsoc5-gpio (custom GPIO controller)",
        "rtc":              "fortinet,fsoc5-rtc (custom RTC)",
        "wdt":              "fortinet,wdt (custom watchdog timer)",
        "temp_sensors":     "fortinet,lm75b (LM75B temperature sensor), fortinet,nct7802 (fan/temp controller)",
        "poe_ctrl":         "fortinet,pd69104 (PoE controller -- powers PoE-capable models like FGT-50G-POE, FGT-70G-POE)",
        "power_monitor":    "ti,ina238 (Texas Instruments INA238 power monitor)",
        "dts_source_files": [
            "fgt50g.dts", "fgt50g_poe.dts", "fgt50g5g.dts", "fgt50gdsl.dts",
            "fgt70g.dts", "fgt70g_poe.dts", "fgt90g.dts", "fgt120g.dts",
        ],
    },

    "image_structure": {
        "qcow2":            "FGT_ARM64_KVM-v8.0.0.F-build0167-FORTINET.qcow2 (128MB compressed, 2GB virtual)",
        "p1_offset":        "sector 2048 (1048576 bytes)",
        "p1_size":          "256MB (524288 sectors)",
        "p1_type":          "0x83 Linux ext2",
        "p1_files":         ["flatkc (17.5MB ARM64 boot image)", "rootfs.gz (85MB encrypted)", "datafs.tar.gz (21MB accessible)", "devicetree.dtb (167KB)"],
        "p2":               "type 0x83 Linux, 1727MB (data partition)",
        "p3":               "type 0xef EFI system, 64MB",
        "bootloader":       "ARM64 UEFI/U-Boot + devicetree (vs x86-64 extlinux/syslinux)",
    },

    "vs_x86_64_800": {
        "kernel_size":  "ARM64 flatkc 17.5MB vs x86-64 ~4-7MB -- ARM64 kernel includes platform drivers",
        "build_date":   "ARM64 April 19 vs x86-64 April 20 (one day earlier -- separate build pipeline)",
        "bootloader":   "ARM64 uses devicetree + UEFI; x86-64 uses extlinux",
        "new_files":    "devicetree.dtb, ARM-specific datafs content",
        "shared_code":  "FortiOS userspace (daemons, fortism config) identical between architectures",
    },
}


# ---------------------------------------------------------
# FGA-F01: RSA-2048 private key in plaintext (fgt2.key)
#          Cross-product: FFF-F01 (FortiFone server.key)
# ---------------------------------------------------------
FGA_F01_FGT2_PLAINTEXT_KEY = {
    "id":       "FGA-F01",
    "product":  "Fortinet FortiGate ARM64 8.0.0 (applies to all FortiGate G-series)",
    "severity": "HIGH -- shared RSA-2048 private key embedded in plaintext in firmware image",
    "class":    "Hardcoded credential / private key exposure",
    "cwe":      "CWE-321 (Use of Hard-coded Cryptographic Key)",
    "cross_product": "FFF-F01 (FortiFone server.key -- same pattern, different product); likely present in x86-64 FGT as well",

    "key_material": {
        "file":         "datafs.tar.gz/etc/fgt2.key",
        "format":       "PKCS#1 RSAPrivateKey (BEGIN RSA PRIVATE KEY)",
        "key_bits":     "2048",
        "pubkey_md5":   "721d41ba1099f6858bffac517d44eef3",
        "file_md5":     "c8eaa255efceab1512356f46f90b57b5",
    },

    "cert_material": {
        "file":         "datafs.tar.gz/etc/fgt2.crt",
        "subject":      "CN=FortiGate, OU=FortiGate, O=Fortinet, L=Sunnyvale, ST=California, C=US",
        "issuer":       "CN=fortinet-subca2001 (Fortinet internal sub-CA, same as FortiFone FFF-F04)",
        "not_before":   "2016-11-30",
        "key_bits":     "2048",
        "email":        "support@fortinet.com",
    },

    "attack_path": (
        "The fgt2.key/fgt2.crt pair is the FortiGate device identity certificate used for "
        "management plane TLS authentication and potentially FortiManager/FortiAnalyzer fabric trust. "
        "Because the private key is identical across all ARM64 FortiGate 8.0.0 installations (baked into firmware), "
        "an attacker who extracts the key from ANY ARM64 FortiGate firmware image "
        "can impersonate any FortiGate appliance in a Fortinet Security Fabric deployment. "
        "Combined with network access to the management plane, this enables fabric-level MITM."
    ),

    "scope": (
        "CONFIRMED CROSS-ARCHITECTURE: identical modulus in both ARM64 8.0.0 and x86-64 8.0.0 datafs.tar.gz. "
        "ARM64 modulus == x86-64 modulus (verified 2026-09-12). "
        "Applies to all G-series hardware (50G/70G/90G/120G) and x86-64 VM targets. "
        "The fgt2 key pair has been shipped since at least November 2016 (cert not_before date). "
        "fgt2.crt valid until 2056 (40-year cert)."
    ),

    "remediation": (
        "Each FortiGate device should generate a unique key pair on first boot and have it signed "
        "by a device-specific certificate authority. "
        "Shared firmware-baked keys are not suitable for device authentication."
    ),
}


# ---------------------------------------------------------
# FGA-F02: RSA-512 private key in plaintext (fgt_512.key)
#          CRITICAL: 512-bit RSA is cryptographically broken
# ---------------------------------------------------------
FGA_F02_FGT_512_BROKEN_KEY = {
    "id":       "FGA-F02",
    "product":  "Fortinet FortiGate ARM64 8.0.0 and x86-64 8.0.0 (cross-arch confirmed)",
    "severity": "CRITICAL -- RSA-512 private key in plaintext; 512-bit RSA is factored in hours",
    "class":    "Cryptographically broken hardcoded key",
    "cwe":      "CWE-321 (Use of Hard-coded Cryptographic Key), CWE-326 (Inadequate Encryption Strength)",

    "key_material": {
        "file":         "datafs.tar.gz/etc/fgt_512.key",
        "format":       "PKCS#8 PrivateKeyInfo (BEGIN PRIVATE KEY)",
        "key_bits":     "512",
        "cert_subject": "CN=FortiGate, OU=FortiGate, O=Fortinet, L=Sunnyvale, ST=California, C=US",
    },

    "broken_crypto": (
        "RSA-512 was declared insecure in 1999 (Factoring Challenge). "
        "By 2009, RSA-512 can be factored in hours on a modern PC using GNFS. "
        "NIST has prohibited RSA-512 since 2010. "
        "The private key in the firmware can be reconstructed from the public key alone. "
        "Shipping RSA-512 keys in 2026-era firmware represents a critical regression."
    ),

    "use_case_hypothesis": (
        "fgt_512.crt/key may be used for: "
        "(1) Legacy TLS handshake compatibility with very old clients (RSA-512 export cipher suites), "
        "(2) FortiGate internal IPC authentication on low-overhead paths, "
        "(3) Legacy firmware signing verification (boot chain uses separate TPM). "
        "The RSA-512 certificate shares the same subject as fgt2 (CN=FortiGate) suggesting "
        "it is used for the same FortiGate device identity purpose but at 512-bit key strength."
    ),

    "private_key_extracted": {
        "attack_path": (
            "The private key (fgt_512.key) is in PLAINTEXT in the firmware. "
            "No cryptographic attack needed -- extract from QCOW2 -> datafs.tar.gz -> etc/fgt_512.key. "
            "Factoring the 512-bit modulus from the cert alone would also work (hours via CADO-NFS), "
            "but the plaintext key is directly readable without any crypto."
        ),
        "n": "0xb5ed8433938a7d0044b98b73aa98e5f92747a8811361d1dc9d0da381c22900045bc0d21fdf4594b74de6b1fd879207ce7901730ea29f1de7568a45cf398199cf",
        "p": "97636374099857130169741076853870851523592073731019969402232674075263464647081",
        "q": "97589981580399376801631665110380745102239180441911007493594721563758635549367",
        "e": 65537,
        "factors_confirmed": "p * q == n: True",
    },
}


# ---------------------------------------------------------
# FGA-F03: Fortinet FSOC5 hardware platform disclosure
#          (devicetree.dtb reveals SoC + product lineup)
# ---------------------------------------------------------
FGA_F03_FSOC5_PLATFORM = {
    "id":       "FGA-F03",
    "product":  "Fortinet FortiGate G-series hardware (50G, 70G, 90G, 120G)",
    "severity": "INFO -- custom SoC architecture revealed; TPM present (FGA-F04)",
    "class":    "Hardware platform identification",

    "soc_identity":     "Fortinet FSOC5 (ftnt,fsoc5) -- Fortinet custom ARM SoC, not a commodity chip",
    "cpu_arch":         "ARM Cortex-A76 (high-performance; same core as Qualcomm Snapdragon 855)",
    "cpu_count":        4,
    "cpu_enable":       "PSCI arm,psci-0.2",
    "iommu":            "ARM SMMU-v3 (hardware IOMMU for device isolation; DMA attack surface limited)",
    "cache_coherency":  "ARM CCI-500",

    "product_lineup": {
        "fgt50g.dts":     "FortiGate 50G (base model)",
        "fgt50g_poe.dts": "FortiGate 50G PoE (PoE switch ports; fortinet,pd69104 controller)",
        "fgt50g5g.dts":   "FortiGate 50G 5G (5G cellular uplink variant)",
        "fgt50gdsl.dts":  "FortiGate 50G DSL (DSL WAN variant)",
        "fgt70g.dts":     "FortiGate 70G",
        "fgt70g_poe.dts": "FortiGate 70G PoE",
        "fgt90g.dts":     "FortiGate 90G",
        "fgt120g.dts":    "FortiGate 120G",
    },

    "third_party_chips": {
        "Renesas":      "UART (em-uart) + I2C (iic-A9mp)",
        "NXP":          "PCA9534/9552/9555/9557 I2C GPIO expanders (board management)",
        "Texas_Instruments": "INA238 power monitor + TCA9555 GPIO expander",
        "Macronix":     "MX25U6435F 8MB SPI NOR (bootloader / configuration store)",
        "TCG":          "TPM 2.0 via SPI (tcg,tpm_tis-spi) -- see FGA-F04",
    },

    "supply_chain_note": (
        "The FSOC5 is Fortinet's custom ASIC. Third-party components (Renesas, NXP, TI) are "
        "commodity board management chips. Supply chain risk is concentrated in the FSOC5 die "
        "and the Macronix SPI NOR (stores early bootloader). "
        "The SMMU-v3 presence indicates hardware-enforced DMA isolation is architecturally available; "
        "whether enabled at runtime depends on bootloader configuration."
    ),
}


# ---------------------------------------------------------
# FGA-F04: TPM 2.0 via SPI (tcg,tpm_tis-spi in devicetree)
#          Rootfs decryption likely TPM-sealed
# ---------------------------------------------------------
FGA_F04_TPM_HARDWARE = {
    "id":       "FGA-F04",
    "product":  "Fortinet FortiGate G-series (all FSOC5-based hardware)",
    "severity": "INFO -- hardware TPM detected; rootfs decryption key likely TPM-sealed; static extraction blocked",
    "class":    "Hardware security module (TPM 2.0)",

    "evidence": {
        "dtb_node":   "compatible = 'tcg,tpm_tis-spi' in devicetree.dtb",
        "interface":  "SPI bus (not I2C or LPC; high-speed path)",
        "standard":   "TCG TPM TIS (Trusted Platform Module Interface Specification)",
        "version":    "TPM 2.0 (tpm_tis is the TPM TIS layer)",
    },

    "implications": {
        "rootfs_key":       "rootfs.gz encryption key may be derived from TPM sealed secret. Without live device and PCR state, decryption is infeasible.",
        "secure_boot":      "FSOC5 + TPM enables measured boot: bootloader measures each stage, extends PCRs, gate-decrypts rootfs.",
        "firmware_signing": "flatkc and datafs may be verified against TPM-sealed policy before rootfs key release.",
        "ioctl_relevance":  "FGT-F13 (global fortism flag bypass) clears LSM hooks in software. TPM does not prevent fortism bypass after boot.",
    },

    "attack_surface": (
        "TPM 2.0 attacks: "
        "(1) TPM bus snooping -- SPI is on-board; requires physical hardware access and logic analyzer. "
        "(2) PCR prediction -- if PCR values are predictable (e.g., no measured boot in early stages), key unsealing may be feasible. "
        "(3) TPM reset attack -- physical voltage glitching to reset PCR state. "
        "These require physical hardware access to G-series device. "
        "Network-side exploitation (fortism ioctl primitives) is independent of TPM protection."
    ),

    "boot_kernel_param": (
        "FortiAP 23JF firmware has 'tpm_tis.interrupts=0' in boot parameters -- same driver. "
        "FortiGate ARM64 likely uses same TPM_TIS driver with interrupts disabled (polling mode). "
        "Polling mode TPM is slightly slower but eliminates interrupt routing complexity on FSOC5."
    ),
}


# ---------------------------------------------------------
# FGA-F05: fortism LSM domain architecture
#          (fortism_config.json -- 35 security domains; 6 with anon-mem-exec)
# ---------------------------------------------------------
FGA_F05_FORTISM_LSM_DOMAINS = {
    "id":       "FGA-F05",
    "product":  "Fortinet FortiGate ARM64 8.0.0 (fortism LSM)",
    "severity": "INFO -- complete fortism LSM sandbox architecture documented; anon-mem-exec in 6 domains is an exploitation prerequisite",
    "class":    "LSM security architecture documentation + sandbox escape surface",

    "source_file": "datafs.tar.gz/etc/fortism_config.json (JSON5 format, 97K+, 87 domain entries)",

    "domain_model": (
        "Fortism implements MAC (Mandatory Access Control) through security domains. "
        "Processes are assigned to domains via execv() interception (binary path matching). "
        "chroot() calls trigger domain transitions to isolated sandboxes. "
        "default_act=INCLUDE: process can access most resources. "
        "default_act=EXCLUDE: process is isolated; only explicitly allowed resources accessible."
    ),

    "domains_include": [
        "INIT (id=0)       -- root init process; transitions all other daemons",
        "CONSOLE (id=1)    -- getty/mingetty serial console",
        "TERMINAL (id=2)   -- telnetd/CLI access",
        "PRECHROOT (id=3)  -- pre-chroot processes (wad, snmpd, sslvpnd, iked, sh, etc.) [ANON-MEM-EXEC]",
        "GUI (id=4)        -- httpsd HTTPS management interface",
        "CMDBSVR (id=6)    -- cmdbsvr configuration database server [ANON-MEM-EXEC]",
        "INTERNAL (id=7)   -- HA daemons (hatalk, hasync, confsyncd, slbd, blackboxd)",
        "MISC (id=8)       -- proxyd, voipd, scanunitd, ikecryptd [ANON-MEM-EXEC]",
        "VM_DAEMONS        -- awsd, ocid, openstackd, sdnd, kubed, azd, gcpd, waagent",
    ],

    "domains_exclude": [
        "SSLVPND (id=9)     -- /tmp/sslvpn_jail (chroot sandbox)",
        "WAD (id=10)        -- /tmp/wad/jail [ANON-MEM-EXEC]",
        "SNMPD (id=11)      -- /tmp/snmp/jail",
        "IKED_QKD (id=12)   -- /tmp/iked/qkd/jail",
        "IKED_SESSION (id=13) -- /tmp/iked/session/jail",
        "MIGLOGD (id=14)    -- log daemon",
        "LOCALLOG (id=15)",
        "REMOTELOG (id=16)",
        "IPS (id=17)        -- /tmp/ips_root [ANON-MEM-EXEC]",
        "FORTICLDD (id=18)  -- FortiCloud daemon",
        "QUARANTINED (id=19) -- quarantined process zone",
        "CSFD_PRIV (id=20)  -- CSF daemon privilege zone",
        "FGFMD (id=22)      -- FortiGate-FortiManager daemon",
        "WEB_SVC            -- /bin/node (Node.js) [ANON-MEM-EXEC]",
        "SNIFFERD, FORTIMQ, SFUPGRADED, CLOUDAPID, L2TPD, SEGMENTATION",
        "SCANDISK, IPAMD, MQTTD, SSHD, SSHD_AUTH, SSHD_SESSION",
        "REMOTE_SEGMENTATION, WEB_AUTH, WEB_SVC_COMPRESSION, CRASH_LOGGER",
        "SCIMD, SCIMD_HTTP, EAP_PROXY, EAP_PROXY_WORKER",
    ],

    "anon_mem_exec_domains": {
        "domains":  ["PRECHROOT", "CMDBSVR", "MISC", "WAD", "IPS", "WEB_SVC"],
        "count":    6,
        "meaning":  (
            "anon-mem-exec=1 permits execution of anonymous (non-file-backed) memory mappings "
            "in this domain. Required for JIT compilers (wad DPI engine, IPS signature engine, "
            "Node.js V8 JIT in WEB_SVC). "
            "Attack relevance: if an attacker achieves code execution inside any of these 6 domains, "
            "they can execute shellcode directly from mmap'd anonymous memory (no file needed). "
            "This simplifies post-exploitation compared to domains with W^X enforcement."
        ),
    },

    "security_boundary_analysis": {
        "SSLVPND_isolation":    "SSLVPND is sandboxed (EXCLUDE, /tmp/sslvpn_jail). CVE-2023-27997 breakout required leaving this jail.",
        "WAD_anon_exec":        "WAD handles all forward proxy traffic (HTTP/HTTPS/SSL-inspect). ANON-MEM-EXEC enabled. High-value target for shellcode execution.",
        "IPS_anon_exec":        "IPS engine processes untrusted traffic. ANON-MEM-EXEC enabled. Combined with IPS bypass = arbitrary kernel/user exec.",
        "FGT_F13_relevance":    "FGT-F13 global override flag clears ALL LSM hooks for all domains simultaneously. One ioctl disables the entire fortism MAC framework.",
        "FGT_F12_relevance":    "FGT-F12 null-pointer chain can lead to hook bypass within specific domain transitions.",
    },

    "daemon_surface_from_config": {
        "network_daemons":      ["/bin/httpsd", "/bin/sslvpnd", "/bin/snmpd", "/bin/telnetd", "/bin/sshd"],
        "vpn_daemons":          ["/bin/iked", "/bin/l2tpd", "/bin/proxyd"],
        "ha_daemons":           ["/bin/hatalk", "/bin/hasync", "/bin/confsyncd", "/bin/slbd"],
        "cloud_adapters":       ["/bin/awsd", "/bin/ocid", "/bin/openstackd", "/bin/azd", "/bin/gcpd", "/bin/kubed", "/bin/waagent"],
        "iot_protocol_daemons": ["/bin/fortimq", "/bin/mqttd", "/bin/scimd", "/bin/eap_proxy"],
        "analytics_daemons":    ["/bin/miglogd", "/bin/kmiglogd", "/bin/locallogd", "/bin/reportd", "/bin/syslogd", "/bin/fgtlogd"],
        "management_daemons":   ["/bin/cmdbsvr", "/bin/httpsd", "/bin/fgfmd", "/bin/cloudapid", "/bin/sfupgraded"],
        "node_js_present":      "/bin/node (WEB_SVC domain, ANON-MEM-EXEC) -- FortiOS 8.0.0 ships Node.js as a management service",
    },
}


# ---------------------------------------------------------
# FGA-F06: ARM64 fortism ioctl surface -- full map
#          Dispatch function: flatkc foff 0x2df710, VMA 0xffff0000082df710
#          Kernel base: 0xffff000008000000 (file offset 0 = VMA base)
# ---------------------------------------------------------
FGA_F06_ARM64_FORTISM_IOCTLS = {
    "id":       "FGA-F06",
    "product":  "Fortinet FortiGate ARM64 8.0.0 (fortism kernel module)",
    "severity": "MEDIUM -- ARM64 fortism has same unauth write/read primitives as x86-64; DoS absent; 0x9009 is new",
    "class":    "Cross-architecture fortism ioctl confirmation + full ARM64 ioctl map",
    "cross_product": "FGT-F16/F19/F20/F21/F22 -- same ioctls; different DoS behavior",

    "dispatch_function": {
        "foff":         "0x2df710",
        "vma":          "0xffff0000082df710",
        "kernel_base":  "0xffff000008000000",
        "arg_layout":   "x0=file_struct x1=cmd(w19) x2=argp(x21)",
        "dispatch_type": "binary search (cmp/b.eq tree; NOT jump table)",
        "lock_acquire":  "0xffff00000807b670 (fortism mutex) at entry; release via 0xffff00000807b8c4 at exit",
    },

    "ioctl_map": {
        "0x9002": {
            "name":       "FORTISM_CONFIG_WRITE",
            "foff":       "0x2df87c (inline in dispatch)",
            "vma":        "0xffff0000082df87c",
            "auth":       "PRIVILEGED -- checks current_cred == init_cred (bl 0x52864; cmp to specific global pointer at 0xffff00000903d498)",
            "user_in":    "4 bytes from argp",
            "operation":  "calls 0x2e93b0 with the 4-byte value -- interpreted as configuration command",
            "note":       "Stronger than UID==0 -- requires exact init_cred pointer match",
        },
        "0x9003": {
            "name":       "FORTISM_OBJECT_READ",
            "foff":       "0x2df964",
            "vma":        "0xffff0000082df964",
            "auth":       "UNAUTH -- no credential check",
            "user_in":    "0x24 (36) bytes from argp as lookup key",
            "operation":  "lookup object via 0x2e03f0; read 28 bytes from object+4..+0x1c back to user",
            "read_fields": "[+4]...[+0x1c] = 16+8+4 = 28 bytes (3 fields: ldp x2,x3; ldr x2; ldr w0)",
            "note":       "Same unauth read primitive as x86-64 FGT-F20",
        },
        "0x9004": {
            "name":       "FORTISM_OBJECT_WRITE",
            "foff":       "0x2df76c (inline in dispatch)",
            "vma":        "0xffff0000082df76c",
            "auth":       "UNAUTH -- no credential check",
            "user_in":    "8 bytes: bytes[0:4]=object_index (max 0x40), bytes[4:8]=value_to_write",
            "operation":  "lookup object (bl 0x2e03f0); str w19, [x0, #0x44] -- write 4-byte value to object[+0x44]",
            "write_target": "object[+0x44] (same field as x86-64 FGT-F19)",
            "note":       "CRITICAL primitive -- same unauth write as x86-64",
        },
        "0x9005": {
            "name":       "FORTISM_GLOBAL_READ",
            "foff":       "0x2df934",
            "vma":        "0xffff0000082df934",
            "auth":       "UNAUTH -- bounds check only",
            "user_in":    "argp pointer (must be valid userspace)",
            "operation":  "copy_to_user(argp, &global_dword@0xffff0000090f17c0, 4)",
            "global_vma": "0xffff0000090f17c0 (4-byte fortism global -- same value as 0x9009 returns for state==3)",
            "note":       "Same unauth global read as x86-64 FGT-F21",
        },
        "0x9007": {
            "name":       "FORTISM_ALLOC_ENUM",
            "foff":       "0x2dfa2c",
            "vma":        "0xffff0000082dfa2c",
            "auth":       "UNAUTH -- bounds check only",
            "user_in":    "0x10 bytes: bytes[4:8]=count",
            "operation":  "kmalloc-variant at 0x185ee4 with size=(count+1)*element; integer overflow on count=0xffffffff -> 0",
            "overflow":   "add w0, w0, #1 on 0xffffffff -> 0; kmalloc(0) succeeds; EFAULT on subsequent copy_from_user (no crash)",
            "note":       "x86-64 FGT-F16 DoS used SIZE_MAX -> crash; ARM64 access_ok rejects -> no crash",
        },
        "0x9009": {
            "name":       "FORTISM_OBJECT_STATE_QUERY",
            "foff":       "0x2df7f8 (inline in dispatch)",
            "vma":        "0xffff0000082df7f8",
            "auth":       "UNAUTH -- bounds check only",
            "user_in":    "4 bytes: object_index (max 0x40)",
            "operation":  "lookup object; read object[+0x30] (4-byte state field); if ==3 return global@0xffff0000090f17c0 else return field",
            "new_vs_x86":  "NOT PRESENT in x86-64 8.0.0 -- ARM64-only addition",
            "note":       "Returns global 4-byte value (same as 0x9005) when object state==3; otherwise returns per-object state",
        },
    },

    "missing_vs_x86": {
        "0x9001": "NOT PRESENT -- ARM64 8.0.0 fortism dispatch handles 0x9002/0x9003/0x9004/0x9005/0x9007/0x9009 only",
        "0x9006": "NOT PRESENT -- same absence; ARM64 has fewer ioctls than x86-64",
    },

    "architecture_diff": {
        "0x9007_dos": {
            "x86_64":   "FGT-F16 CONFIRMED DoS -- custom copy_from_user memsets via rep stosq -> kernel crash",
            "arm64":    "DoS NOT CONFIRMED -- standard ARM64 copy_from_user uses access_ok before copy; SIZE_MAX rejected cleanly",
            "arm64_overflow": "Integer overflow still occurs (add w0,w0,#1 on 0xffffffff -> 0); kmalloc(0) executes; EFAULT returned cleanly from copy_from_user. No crash.",
        },
        "0x9004_write": "CONFIRMED -- str w19, [x0, #0x44] at foff=0x2df7e0; same object[+0x44] target as x86-64",
        "0x9003_read":  "CONFIRMED -- reads 28 bytes from object; same primitive as x86-64 FGT-F20",
        "0x9005_global": "CONFIRMED -- global at 0xffff0000090f17c0; copy_to_user at foff=0x2dfb40",
        "object_table": "ARM64 object table: max index 0x40 (same 64-entry limit as x86-64)",
    },

    "arm64_mitigations_vs_x86": {
        "access_ok":    "ARM64 copy_from_user performs proper access_ok check for SIZE_MAX -- rejects out-of-bounds count",
        "no_rep_stosq": "ARM64 has no rep stosq equivalent -- standard ldp/stp loop used; no bulk memset crash path",
        "kaslr_arm64":  "ARM64 KASLR randomization is present (FGT x86-64 7.0.9 had Linux 3.x with no KASLR; ARM64 8.0.0 has KASLR)",
        "0x9002_auth":  "0x9002 is auth-gated on ARM64 (init_cred check) -- not present as unauth primitive",
    },

    "arm64_specific_primitives": {
        "still_active": [
            "Unauth kernel object field write via ioctl 0x9004 (object[+0x44])",
            "Unauth 28-byte kernel object read via ioctl 0x9003",
            "Unauth 4-byte global read via ioctl 0x9005 (global@0xffff0000090f17c0)",
            "Unauth object state query via ioctl 0x9009 (new -- ARM64 only)",
        ],
        "not_active": [
            "FGT-F16 DoS crash -- ARM64 access_ok prevents SIZE_MAX copy",
            "0x9001 -- not present in ARM64 dispatch",
            "0x9006 -- not present in ARM64 dispatch",
        ],
    },

    "object_field_security_branches": {
        "0x44_bit1_gate_vma":   "0xffff0000082de2f4",
        "0x44_bit1_gate_foff":  "0x2de2f4",
        "insn":                 "ldr w0, [x19, #0x44]; tbnz w0, #1, #0x2de32c",
        "clear_path":           "bl #0x2e5290: checks task->flags[+0x3a0] bit 0 (privilege byte); then checks object[+0x40] bits 0-1 via 0x2e4c80; returns",
        "set_path":             "0x2de32c: accesses object[+0x18](ptr)->[+0x30](sub-ptr); checks object[+0x40] bit 6; copies up to 0x1ff (511) bytes; processes protocol data",
        "attacker_control":     "ioctl 0x9004 (UNAUTH) can set object[+0x44] bit 1; enables extended sub-pointer-dereference+copy path without auth",
        "0x44_gt1_gate_vma":    "0xffff0000082dffac",
        "0x44_gt1_gate_insn":   "ldr w0, [x19, #0x44]; cmp w0, #1; b.hi #0x2dffd0",
        "gt1_path":             "0x2dffd0: mrs sp_el0 -> reads task[+0x3e0] (PID/UID); blr x20 (indirect call); logging path",
        "0x44_bit26_gate_vma":  "0xffff0000082d9ee4",
        "0x44_bit26_gate_insn": "ldr w0, [x20, #0x44]; tbnz w0, #0x1a, #0x2d9f4c",
        "bit26_path":           "0x2d9f4c: early return w0=0 (caller treats as no-more-items / disabled)",
    },
}


# ---------------------------------------------------------
# FGA-F07: ioctl 0x9009 -- ARM64-only FORTISM_OBJECT_STATE_QUERY
# ---------------------------------------------------------
FGA_F07_ARM64_IOCTL_9009 = {
    "id":       "FGA-F07",
    "product":  "Fortinet FortiGate ARM64 8.0.0 (fortism kernel module)",
    "severity": "INFO -- unauth object state oracle; not present in x86-64 8.0.0; potential chain primitive",
    "class":    "Unauth kernel object state leak",

    "foff":         "0x2df7f8",
    "vma":          "0xffff0000082df7f8",
    "ioctl_code":   "0x9009",

    "user_input":   "4-byte object index (range check: <= 0x40)",
    "kernel_op":    "lookup object via fortism_object_lookup(index); read w0 = [obj+0x30]",
    "return_logic": "if w0 == 3: return global_dword@0xffff0000090f17c0 (same as 0x9005 result); else: return w0",

    "primitive_value": (
        "Returns a per-object state field (object[+0x30]) without authentication. "
        "When the field equals 3 (a specific state), it instead returns the fortism global state "
        "(same 4-byte value as ioctl 0x9005). "
        "An attacker can probe object indices 0-0x40 to map the object table contents, "
        "learn per-object state transitions, and infer when fortism global state changes "
        "without the separate 0x9005 call. "
        "Chain: use 0x9004 to write to object[+0x44], then use 0x9009 to observe state at [+0x30] -- "
        "if [+0x30] and [+0x44] alias within the same struct, write-then-read completes the primitive."
    ),

    "arm64_vs_x86": "Not found in x86-64 8.0.0 dispatch; ARM64-specific addition (new in 8.0.0 ARM64 build?)",
    "verification": "CONFIRMED -- disasm at foff 0x2df7f8-0x2df87c; MRS sp_el0; copy_from_user(4); lookup; ldr [+0x30]; csel",
}


# ---------------------------------------------------------
# FGA-F08: 0x9004 UNAUTH write to object[+0x44] flips multiple kernel security branch gates
# ---------------------------------------------------------
FGA_F08_OBJECT44_BRANCH_FLIP = {
    "id":       "FGA-F08",
    "product":  "Fortinet FortiGate ARM64 8.0.0 (fortism kernel module in flatkc)",
    "severity": "MEDIUM -- UNAUTH ioctl flips kernel security branch gates; enables extended kernel processing paths without auth",
    "class":    "Unauth kernel control flow manipulation via object field write (CWE-269, CWE-284)",

    "write_primitive": {
        "ioctl":    "0x9004 (FORTISM_OBJECT_WRITE)",
        "auth":     "UNAUTH -- no credential check",
        "input":    "8 bytes: [0:4]=object_index (max 0x40); [4:8]=value_to_write",
        "effect":   "fortism_object_lookup(index) -> STR w19, [x0, #0x44] at foff 0x2df7e0",
        "scope":    "Writes any 4-byte value to ANY of the 65 (0..0x40) fortism object slots' [+0x44] field",
    },

    "security_gates_flipped": {
        "gate_1": {
            "vma":      "0xffff0000082de2f4",
            "foff":     "0x2de2f4",
            "insn":     "ldr w0, [x19, #0x44]; tbnz w0, #1, #0xffff0000082de32c",
            "bit":      "bit 1",
            "clear":    "bl #0x2e5290 (privilege check: task->flags[+0x3a0]; object[+0x40] bits 0-1); then return",
            "set":      "0x2de32c: object[+0x18] ptr chain -> dereferences sub-ptr at [+0x30]; "
                        "checks object[+0x40] bit 6; copies up to 511 bytes (0x1ff) of protocol data; "
                        "accesses kernel list at 0xffff000009050440",
            "impact":   "Setting bit 1 bypasses the privilege-check path; enables 511-byte sub-pointer-dereference + protocol copy without auth",
        },
        "gate_2": {
            "vma":      "0xffff0000082dffac",
            "foff":     "0x2dffac",
            "insn":     "ldr w0, [x19, #0x44]; cmp w0, #1; b.hi #0xffff0000082dffd0",
            "threshold": "> 1",
            "normal":   "skip branch; return via ldp/ret",
            "elevated": "0x2dffd0: mrs x1, sp_el0 -> ldr w21, [x1, #0x3e0] (task PID/UID); blr x20 (indirect call via global fn-ptr); logging/event path",
            "impact":   "Writing value > 1 to object[+0x44] routes to a fn-ptr indirect call path reading current task identity",
        },
        "gate_3": {
            "vma":      "0xffff0000082d9ee4",
            "foff":     "0x2d9ee4",
            "insn":     "ldr w0, [x20, #0x44]; tbnz w0, #0x1a, #0xffff0000082d9f4c",
            "bit":      "bit 26",
            "clear":    "continues normal processing (network/packet iteration)",
            "set":      "0x2d9f4c: early return w0=0 (disables the function's output for this object -- treated as no-more-items)",
            "impact":   "Setting bit 26 silently disables processing for the affected object slot",
        },
    },

    "chain": (
        "Step 1: open fortism char device (typically /dev/fortism or via ioctl fd from mgmt process). "
        "Step 2: ioctl(fd, 0x9004, {index=X, value=0x2}) to write 0x2 to object[X][+0x44]. "
        "Step 3: When kernel subsequently calls the function containing gate_1 (0x2de2f4) for object X, "
        "  it takes the SET path (0x2de32c): accesses object[+0x18] ptr -> sub-ptr[+0x30] -> copies 511 bytes. "
        "If object[+0x18] or sub-ptr[+0x30] contains user-controlled data (set via ioctl 0x9003 or other), "
        "this is a kernel memory read/write primitive from an unprivileged context."
    ),

    "access_model": (
        "The fortism char device access is typically restricted to Fortinet management processes "
        "in the FortiOS userspace. If any of those processes has a bug allowing untrusted code to "
        "issue ioctls (SSRF, code injection, privilege confusion), this chain enables kernel manipulation. "
        "On a hardened system: requires CAP_SYS_ADMIN or Fortinet management-plane access. "
        "Within a VM escape / container escape scenario: exploiting fortism ioctl 0x9004 before "
        "KASLR is bypassed to flip branch gates."
    ),

    "vs_x86": "object[+0x44] security gates also exist in x86-64 8.0.0 (FGT-F19 documents the write primitive); gate analysis is ARM64-specific",
    "verification": "CONFIRMED -- ARM64 disassembly of flatkc; three gate sites identified; 0x9004 write path confirmed at foff 0x2df7e0",
}


# ---------------------------------------------------------
# FGA-F09: WEB_SVC (/bin/node) domain over-privilege
#          fortism_config.json: Node.js has CAP_SYS_ADMIN + factory CA key read
# ---------------------------------------------------------
FGA_F09_WEB_SVC_OVERPRIVILEGE = {
    "id":       "FGA-F09",
    "product":  "Fortinet FortiGate 8.0.0 (ARM64 and x86-64; all G-series and VM targets)",
    "severity": "HIGH -- /bin/node (WEB_SVC fortism domain) granted CAP_SYS_ADMIN, CAP_SYS_PTRACE, "
                "CAP_DAC_READ_SEARCH, CAP_DAC_OVERRIDE, and file-system read access to the Fortinet factory root CA private key; "
                "RCE in node -> full system compromise + factory CA exfiltration",
    "class":    "Privilege over-assignment; sensitive file over-exposure (CWE-732, CWE-312)",
    "source":   "fortism_config.json -- WEB_SVC domain (id=23), Permission_Policies section",

    "domain": {
        "name":         "WEB_SVC",
        "id":           23,
        "binary":       "/bin/node",
        "default_act":  "EXCLUDE",
        "anon_mem_exec": 1,
        "also_includes": ["/bin/httpsnifferd", "/bin/brotli", "/bin/pigz"],
    },

    "capabilities_granted": [
        "CAP_SYS_ADMIN",         # mount, device, namespace, and many other privileged operations
        "CAP_SYS_PTRACE",        # ptrace any process (including init, management daemons)
        "CAP_SYS_TTY_CONFIG",
        "CAP_NET_BIND_SERVICE",
        "CAP_DAC_READ_SEARCH",   # bypass DAC read permission on any file / directory
        "CAP_DAC_OVERRIDE",      # bypass DAC write/execute permission on any file
        "CAP_NET_RAW",
        "CAP_NET_ADMIN",
    ],

    "over_privileged_file_access": {
        "root_factory_key": {
            "path":   "/data/etc/cert/factory/root_Fortinet_Factory.key",
            "access": "READ (explicit allow in WEB_SVC read list)",
            "impact": "If Node.js is exploited (RCE), attacker reads the Fortinet factory root CA private key. "
                      "That key can sign certificates for any FortiGate device identity, enabling MITM against the entire Fortinet Security Fabric.",
        },
        "root_factory_cert": {
            "path":   "/data/etc/cert/factory/root_Fortinet_Factory.cer",
            "access": "READ",
        },
        "device_ca_dir": {
            "path":   "/data/etc/cert/ca/*",
            "access": "READ -- all CA certificates on the device",
        },
        "device_local_certs": {
            "path":   "/data/etc/cert/local/*",
            "access": "READ -- device-specific private keys",
        },
        "self_key": {
            "path":   "/data/etc/cert/self.key",
            "access": "READ",
        },
        "migadmin": {
            "path":   "/data/migadmin/#",
            "access": "READ -- migration admin data (wildcard recursive)",
        },
    },

    "network_exposure": {
        "ipv4_connect": "INCLUDEALL -- unrestricted outbound IPv4 connections to any address (internet-capable)",
        "ipv6_listen":  "INCLUDEALL -- unrestricted inbound IPv6 listen",
        "unix_sockets": [
            "/tmp/httpsd.sock", "/tmp/httpclid.sock",
            "/tmp/web_svc_bridge/#", "/tmp/nst/.nst.ipc",
            "/tmp/node-csf.sock", "/tmp/node-fmg.sock",
            "/tmp/node-faz.sock", "/tmp/node-oaas.sock",
            "/tmp/http_authd_req",
        ],
        "note": "Node connects to httpsd (web frontend), FortiManager, FortiAnalyzer, http_authd, and fabric services; "
                "compromise propagates to the full Fortinet Security Fabric management plane",
    },

    "anon_mem_exec_note": (
        "anon-mem-exec: 1 grants Node.js anonymous-memory execution (required for V8 JIT). "
        "Under the fortism security model this is an exception to the default EXCLUDE policy. "
        "Combined with Node RCE, this means the memory protection does not prevent shellcode execution -- "
        "V8 JIT already maps anonymous RWX pages."
    ),

    "cap_sys_ptrace_impact": (
        "CAP_SYS_PTRACE allows ptrace of any process including /bin/init (pid 1) and management daemons. "
        "RCE in node -> ptrace /bin/init -> inject shellcode -> full OS privilege escalation. "
        "This is a direct privilege escalation path independent of kernel vulnerabilities."
    ),

    "attack_path": (
        "1. Exploit RCE in /bin/node (web API endpoint, node-scripts handler, or FortiOS web management panel). "
        "2. From Node execution context: read /data/etc/cert/factory/root_Fortinet_Factory.key (no escalation needed -- already permitted). "
        "3. Use CAP_SYS_PTRACE to attach to /bin/init or any management daemon; inject shellcode for root shell. "
        "4. Factory root CA key enables signing new device certificates; "
        "   combined with FGA-F01 (shared fgt2.key), attacker can impersonate any FortiGate in a Security Fabric."
    ),

    "remediation": [
        "Remove CAP_SYS_ADMIN and CAP_SYS_PTRACE from WEB_SVC domain; web service has no legitimate need for either.",
        "Remove read access to /data/etc/cert/factory/root_Fortinet_Factory.key from WEB_SVC policy.",
        "Remove CAP_DAC_READ_SEARCH and CAP_DAC_OVERRIDE; use explicit path allowances instead.",
        "The factory root CA key should not reside on device filesystem; it is a build-time signing key.",
    ],

    "verification": "CONFIRMED -- fortism_config.json WEB_SVC Permission_Policies section (line ~3522); "
                    "capabilities and file read paths extracted directly from config.",
}


# ---------------------------------------------------------
# Cross-product reference
# ---------------------------------------------------------
CROSS_PRODUCT_FORTISM = {
    "FGT-F19 (x86-64 8.0.0)": "FGA-F06 -- same 0x9004 write to object[+0x44]; ARM64 confirmed at foff 0x2df7e0",
    "FGT-F20 (x86-64 8.0.0)": "FGA-F06 -- same 0x9003 multi-field read; ARM64 confirmed at foff 0x2df964",
    "FGT-F21 (x86-64 8.0.0)": "FGA-F06 -- same 0x9005 global read; ARM64 global at 0xffff0000090f17c0",
    "FGT-F16 (x86-64 8.0.0)": "FGA-F06 -- DoS NOT confirmed on ARM64 (access_ok fix)",
    "FGT-F13 (x86-64 7.0.9)": "FGA-F05 -- global override flag affects all 35 LSM domains in fortism_config.json",
    "FFF-F01 (FortiFone)":     "FGA-F01 -- same plaintext private key pattern (server.key in FortiFone, fgt2.key in FortiGate)",
    "FGA-F07 (ARM64-only)":    "ioctl 0x9009 FORTISM_OBJECT_STATE_QUERY -- unauth object[+0x30] read; state==3 leaks global",
    "FGA-F08 (ARM64)":         "0x9004 UNAUTH write to object[+0x44] flips 3 kernel branch gates; enables 511-byte sub-ptr path + fn-ptr indirect call; chain primitive",
    "FGA-F09 (all arches)":    "WEB_SVC (/bin/node) domain: CAP_SYS_ADMIN + CAP_SYS_PTRACE + CAP_DAC_READ_SEARCH + factory root CA key read; node RCE -> ptrace-based privesc + factory key exfil",
}


# ---------------------------------------------------------
# Analysis status
# ---------------------------------------------------------
ANALYSIS_STATUS = {
    "datafs_tar_gz":    "EXTRACTED -- 21MB; all files accessible",
    "devicetree_dtb":   "ANALYZED -- 167KB; full FSOC5 hardware platform documented",
    "fortism_config":   "ANALYZED -- 97K+ JSON5; 87 domain entries; full LSM architecture documented",
    "rootfs_gz":        "BLOCKED -- encrypted; custom format (magic differs from x86-64 format); TPM-sealed likely",
    "flatkc":           "ANALYZED -- 17.5MB ARM64 boot image (ET_DYN PIE kernel); fortism ioctl dispatch mapped at foff 0x2df710",
    "arm64_fortism":    "COMPLETE -- 6 ioctls fully mapped (0x9002/0x9003/0x9004/0x9005/0x9007/0x9009); 0x9001/0x9006 absent; 0x9009 is ARM64-only",

    "unique_findings": [
        "FGA-F01: HIGH -- fgt2.key RSA-2048 plaintext in datafs; shared key across all ARM64 8.0.0 devices",
        "FGA-F02: CRITICAL -- fgt_512.key RSA-512 plaintext; 512-bit RSA is factored in hours; cryptographically broken",
        "FGA-F03: INFO -- Fortinet FSOC5 custom ARM Cortex-A76 SoC revealed by devicetree; G-series products: 50G/70G/90G/120G",
        "FGA-F04: INFO -- TPM 2.0 via SPI (tcg,tpm_tis-spi); rootfs decryption likely TPM-sealed; physical access needed for key extraction",
        "FGA-F05: INFO -- fortism_config.json: 35 security domains; 6 with anon-mem-exec (PRECHROOT/CMDBSVR/MISC/WAD/IPS/WEB_SVC); Node.js present",
        "FGA-F06: MEDIUM -- ARM64 fortism full ioctl map: 0x9003/0x9004/0x9005 unauth primitives confirmed; 0x9009 ARM64-only addition; 0x9001/0x9006 absent",
        "FGA-F07: INFO -- ioctl 0x9009 (FORTISM_OBJECT_STATE_QUERY) exists in ARM64 8.0.0 but not x86-64; unauth; reads object[+0x30] or global 0xffff0000090f17c0",
        "FGA-F08: MEDIUM -- UNAUTH ioctl 0x9004 write to object[+0x44] flips 3 kernel security branch gates (0x2de2f4 bit1, 0x2dffac >1, 0x2d9ee4 bit26); enables 511-byte sub-ptr-dereference path and fn-ptr indirect call path without auth",
        "FGA-F09: HIGH -- /bin/node WEB_SVC domain: CAP_SYS_ADMIN+CAP_SYS_PTRACE+CAP_DAC_READ_SEARCH+CAP_DAC_OVERRIDE; read access to /data/etc/cert/factory/root_Fortinet_Factory.key; ipv4-connect INCLUDEALL; node RCE -> ptrace privesc + factory CA exfil",
    ],

    "pending": {
        "node_js_surface_deep": "/bin/node -- node-scripts content analysis pending (not in datafs.tar.gz; in rootfs.gz which is encrypted)",
    },

    "closed": {
        "fgt_512_factoring": "COMPLETE -- fgt_512.key is PLAINTEXT in datafs; no factoring needed. "
                             "p=0xd7dc3ab96b8a6fd7f2218fc1f24ed0e3c5bfcf53172ba28aea91fda3219029a9 (256-bit); "
                             "q=0xd7c1f8df3c2218e4c3dc9da60279be2de8eac4a645b8bc39f19edf0fbb6c82b7 (256-bit); "
                             "p*q==n confirmed. Documented in FGA-F02.",
        "fgt2_key_scope":    "CONFIRMED 2026-09-12 -- fgt2.key modulus IDENTICAL in ARM64 8.0.0 and x86-64 8.0.0 datafs.tar.gz. "
                             "Scope of FGA-F01 extends to all FortiGate 8.0.0 targets across both architectures. "
                             "fgt_512.key also identical cross-arch (FGA-F02 scope confirmed x86-64).",
    },
}
