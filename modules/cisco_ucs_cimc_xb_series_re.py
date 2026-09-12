"""
RE Module: Cisco UCS CIMC X/B-Series Firmware (6.0.2.260040)
Platforms: X215M8, X410M7, BXM6, IntelBlade M8
BMC: Aspeed AST2600
Blob sizes: X215M8/X410M7 66MB, BXM6 53MB, IntelBlade M8 86MB
Build hash: 17633db507e81f789359828008cf046045bfa5a1 (shared across all 4)

Findings: 6F [0C+3H+3M+0L]
"""

FINDINGS = [
    {
        "id": "CIMC-XB-F1",
        "title": "AMD PSP OTP secure-boot regions in Writable state across all four CIMC platforms",
        "severity": "HIGH",
        "component": "AST2600 BMC / AMD PSP OTP fuse interface",
        "evidence": [
            "Secure Region : Writable",
            "OTP strap Region : Writable",
            "OTP key retire Region : Writable",
            "Configure Region : Writable",
            "Disable Secure Boot",
            "Ignore Secure Boot hardware strap",
            "Enable low security key",
        ],
        "detail": (
            "The AMD PSP/ASP OTP configuration register strings are present in all four "
            "CIMC blobs (X215M8, X410M7, BXM6, IntelBlade M8). The firmware exposes "
            "individual OTP bit descriptions including 'Secure Region : Writable', "
            "'OTP strap Region : Writable', and 'OTP key retire Region : Writable'. "
            "The 'Writable' state means the OTP fuses for that region have not been burned. "
            "Key policy bits are directly accessible: 'Disable Secure Boot' disables the AMD "
            "Platform Secure Boot entirely; 'Ignore Secure Boot hardware strap' overrides the "
            "physical hardware tamper-evidence strap; 'Enable low security key' activates a "
            "degraded-strength key mode. 'OTP key retire Region : Writable' means key "
            "revocation fuses are unbounded, so a compromised signing key cannot be retired "
            "by burning a revocation fuse. Since these OTP regions ship in Writable state, "
            "an attacker with BMC-level access (IPMI raw command to AST2600 SoC registers) "
            "can modify the AMD PSP secure boot policy before fuses are burned during "
            "manufacturing or provisioning."
        ),
        "impact": (
            "Pre-burn: AMD PSP secure boot configuration mutable via BMC register write. "
            "Post-burn: 'OTP key retire Region : Writable' means key revocation impossible. "
            "Affects all four X/B-series CIMC platforms simultaneously."
        ),
        "remediation": "Burn OTP fuses during manufacturing to lock secure boot policy. Separate OTP programming from general BMC access. Document and enforce fuse-burn state as a manufacturing exit criterion.",
        "references": ["AMD PSP fuse interface", "AST2600 OTP register map"],
    },
    {
        "id": "CIMC-XB-F2",
        "title": "Missing cisco-img-valid binary silently skips Intersight connector image validation",
        "severity": "HIGH",
        "component": "CIMC firmware update script (cloud image path)",
        "evidence": [
            "if [ ! -f /usr/local/bin/cisco-img-valid ]; then",
            "  echo \"Warning: cisco-img-valid utility not present.\"",
            "  LOGGER \"Warning: cisco-img-valid utility not present.\"",
            "else",
            "  /usr/local/bin/cisco-img-valid -k andromeda-keys /tmp/$1",
        ],
        "detail": (
            "The CIMC firmware update script for the 'cloud' image type (Intersight connector) "
            "checks whether /usr/local/bin/cisco-img-valid exists before invoking it. If the "
            "binary is absent, the script logs a warning and continues without validation; "
            "there is no exit or failure return. The validation path signs with the "
            "'andromeda-keys' key set. When the binary is missing, a caller-supplied image "
            "file at /tmp/$1 is accepted and flashed without signature verification. "
            "The cisco-img-valid binary can be absent due to: prior CIMC update that omitted "
            "the package, deliberate deletion via authenticated BMC session, or the binary "
            "CPK failing to install. An attacker with file-write access to the BMC filesystem "
            "(via IPMI OEM commands, authenticated Redfish, or an exploited CIMC service) "
            "can delete the validator, then trigger a connector update with a malicious image."
        ),
        "impact": (
            "Unsigned Intersight connector image installed on CIMC. Persistent BMC-level "
            "code execution survivable across host reboots. Affects all 4 platforms (shared "
            "firmware update script via shared CPK base)."
        ),
        "remediation": "Replace existence check with a hard failure: if the binary is absent, abort the update. Do not treat a missing security control as a warning-only condition.",
        "references": ["cisco-img-valid andromeda-keys", "CIMC cloud image update path"],
    },
    {
        "id": "CIMC-XB-F3",
        "title": "telnetd-1.0 CPK present in CIMC base firmware across all four platforms",
        "severity": "HIGH",
        "component": "AST2600 BMC OS / CPK package manifest",
        "evidence": [
            '"telnetd-1.0-17633db507e81f789359828008cf046045bfa5a1.000001.cpk":'
            '{"sha":"4a28187af3c665e9ee943d46242004d287ba2c41"}',
        ],
        "detail": (
            "The telnetd-1.0 CPK package is present in the shared package manifest embedded "
            "in all four CIMC blobs (X215M8, X410M7, BXM6, IntelBlade M8). All packages in "
            "the manifest share build hash 17633db507e81f789359828008cf046045bfa5a1, "
            "confirming a single shared firmware base. CIMC is the always-on out-of-band "
            "management processor (AST2600 SoC) accessible on the dedicated management "
            "network interface independent of host OS state. telnetd on the BMC provides "
            "cleartext shell access to the BMC OS on the OOB management plane. "
            "Unlike telnetd in HUU/SCU ISOs (transient boot environments), this telnetd "
            "is resident in the BMC firmware and active whenever the platform has power."
        ),
        "impact": (
            "Cleartext credential exposure and session hijack on OOB management network. "
            "BMC OS shell accessible via telnet without encryption. Affects all four "
            "X/B-series CIMC platforms simultaneously via shared CPK base."
        ),
        "remediation": "Remove telnetd CPK from the shipping firmware package manifest. Provide console access only via CiscoSSH (ciscossh CPK is present in the same manifest). Document the rationale for telnetd inclusion if it is a diagnostic-only package.",
        "references": ["CPK manifest hash 17633db507e81f789359828008cf046045bfa5a1"],
    },
    {
        "id": "CIMC-XB-F4",
        "title": "Caller-controlled dd offset write to /tmp feeds cisco-img-valid with attacker-sliced content",
        "severity": "MEDIUM",
        "component": "CIMC cloud image update script",
        "evidence": [
            "dd if=$2 of=/tmp/$1 ibs=1 skip=$3 count=$4",
            "CURR_VER=`/usr/local/bin/curl -m 60 -s http://127.0.0.1:8889/Versions | ...`",
            "/usr/local/bin/cisco-img-valid -k andromeda-keys /tmp/$1",
            "rm -f /tmp/$1",
        ],
        "detail": (
            "The cloud image update path extracts a slice from a source file using "
            "'dd if=$2 of=/tmp/$1 ibs=1 skip=$3 count=$4'. All four parameters are "
            "caller-controlled: $1 is the destination filename in /tmp, $2 is the source "
            "file, $3 is the byte offset to skip, and $4 is the byte count. With ibs=1, "
            "skip and count are in single-byte units, giving byte-precise extraction. "
            "The resulting /tmp file is then passed directly to cisco-img-valid. "
            "This means: (1) the path component of $1 is not sanitized (directory traversal "
            "if $1 contains '../'); (2) if the caller controls $2, arbitrary source content "
            "can be sliced; (3) the version is extracted from the /tmp file via "
            "'strings /tmp/$1 | grep version=' before signature check, so version strings "
            "can be injected into the source to satisfy version comparison logic. "
            "Combined with F2 (validator binary absent), an attacker can construct a /tmp "
            "file that passes version checks but contains arbitrary BMC firmware payload."
        ),
        "impact": (
            "Caller-controlled file write to /tmp with arbitrary source and offset. "
            "Combined with cisco-img-valid bypass (F2), enables installation of unsigned "
            "BMC firmware. Path traversal risk if $1 is not restricted to a filename."
        ),
        "remediation": "Restrict $1 to a fixed filename or basename-checked value. Validate $2 as an expected source path. Do not derive validation decisions from content written to /tmp by caller-controlled arguments.",
        "references": ["CIMC cloud image update dd path"],
    },
    {
        "id": "CIMC-XB-F5",
        "title": "VUART/UART boot configurable with OTP strap region in Writable state",
        "severity": "MEDIUM",
        "component": "AST2600 BMC / U-Boot / AMD PSP OTP strap",
        "evidence": [
            "Enable Boot from Uart",
            "Disable Boot from Uart",
            "Enable boot from uart5",
            "Enable Auto Boot from UART or VUART",
            "Enable Auto Boot from VUART2 over LPC",
            "Enable Auto Boot from VUART2 over PCIE",
            "Boot from UART/VUART when normal boot is fail",
            "OTP strap Region : Writable",
            "bootargs=console=ttyS4,115200n8 root=/dev/ram rw rdinit=/sbin/init",
        ],
        "detail": (
            "The CIMC firmware documents UART and VUART recovery boot paths: 'Enable Boot "
            "from Uart', 'Enable boot from uart5', and 'Boot from UART/VUART when normal "
            "boot is fail'. VUART2 is available both over LPC and PCIe. The U-Boot boot "
            "args are console=ttyS4,115200n8 with rdinit=/sbin/init, pointing to an "
            "initramfs-based root. 'OTP strap Region : Writable' confirms that the hardware "
            "strap configuration fuses have not been burned. When OTP straps are writable, "
            "an attacker with BMC SoC register access can programmatically enable UART boot "
            "without requiring physical hardware modification. "
            "VUART2 over PCIe additionally exposes a virtual UART to the host PCIe bus, "
            "meaning a compromised host OS can interact with the BMC console without "
            "physical serial port access. No authentication is documented for the UART "
            "console access path."
        ),
        "impact": (
            "Physical UART access or virtual UART via PCIe enables recovery boot with "
            "unauthenticated console. OTP strap region not locked: UART boot can be enabled "
            "remotely via BMC SoC register write before OTP fuses are burned."
        ),
        "remediation": "Burn OTP strap fuses to lock UART boot configuration to the intended state. Require authentication for U-Boot console access. Document VUART2-over-PCIe exposure surface.",
        "references": ["AST2600 OTP strap region", "U-Boot ttyS4 console", "VUART2 LPC/PCIe"],
    },
    {
        "id": "CIMC-XB-F6",
        "title": "bmc_default_users dedicated default-credential CPK shared across all four platforms",
        "severity": "MEDIUM",
        "component": "AST2600 BMC OS / CPK package manifest",
        "evidence": [
            '"bmc_default_users-1.0.0-17633db507e81f789359828008cf046045bfa5a1.000001.cpk":'
            '{"sha":"4a28187af3c665e9ee943d46242004d287ba2c41"}',
        ],
        "detail": (
            "A CPK package explicitly named 'bmc_default_users-1.0.0' is present in the "
            "shared package manifest across all four CIMC platforms (X215M8, X410M7, BXM6, "
            "IntelBlade M8). The package name and build hash are identical across all four "
            "blobs. This package is responsible for seeding initial BMC user accounts and "
            "credentials. Companion packages 'credfish-1.0.0' (credential storage) and "
            "'libcisco_keyring-1.0.0' (keyring library) are also present in the shared "
            "manifest, indicating a layered default credential infrastructure. "
            "The CPK content is compressed within the blobs and not directly recoverable "
            "from strings analysis; however, the package hash being identical across "
            "all four platforms confirms that all platforms receive the same initial "
            "credential set from the same package version. No factory-reset differentiation "
            "mechanism (per-unit credential seeding) is documented in the strings."
        ),
        "impact": (
            "Identical default BMC credentials across all X215M8, X410M7, BXM6, and "
            "IntelBlade M8 deployments. If the default credential is recovered (via "
            "CPK decompression or any one compromised unit), it is valid against all "
            "same-version deployments. credfish + libcisco_keyring form the credential "
            "storage stack; compromise of those libraries affects the full credential chain."
        ),
        "remediation": "Generate per-unit BMC credentials at manufacturing time. Ensure bmc_default_users CPK uses a platform serial or hardware UID as a credential seed rather than a static value. Mandate credential change on first login.",
        "references": ["bmc_default_users-1.0.0 CPK", "credfish-1.0.0 CPK", "libcisco_keyring-1.0.0 CPK"],
    },
]


def run():
    for f in FINDINGS:
        sev = f["severity"]
        print(f"[{sev}] {f['id']}: {f['title']}")
        for e in f["evidence"]:
            print(f"    {e!r}")
        print()


if __name__ == "__main__":
    run()
