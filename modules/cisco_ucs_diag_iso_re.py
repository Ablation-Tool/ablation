"""
Cisco UCS Diagnostics ISO 7.1.4.260010 RE

Target:  ucs-diag-7.1.4.260010.iso (377MB)
         UCS Server Diagnostics tool for hardware validation (DIAG product line)
         Yocto Linux 6.12.31-yocto-standard kernel; UEFI + legacy boot
         Features: NonInteractiveSupport, RedfishSupport, UISupport, F7Support
         ISO layout: bzImage, initrd (gzip+cpio, 64MB), rootfs.img (squashfs), efi.img
         + ucs-sdu-container-7.1.4.260010.squashfs (146MB, container for diagnostics tools)
Files:   /hsu-keys/*.pem/*.der (7 verification keys: 2 distinct public keys x 7 files)
         /init.d/00-prehsu (800 lines; signature verification, backend enable, boot flow)
         /init.d/90-rootfs (rootfs mount + signature verification)
         /bin/backend_passwd_enable (POSIX shell, 2 lines)
         /etc/profile.d/hsu-profile.sh (HSU environment variables, IMG_VERIFY, HSU_KERNEL_IMGVERIFY)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_diag_iso_re",
    "firmware": "ucs-diag-7.1.4.260010.iso",
    "components": {
        "init.d/00-prehsu (signature + backend logic)": (
            "enable_backend(): polls $CONTAINER_MNTPOINT/tmp/enable_backend_flag; "
            "password MD5 check: 942aa63a77ccc253c5f97b152479e544 = cis@123co; "
            "/bin/sh +m on match; "
            "post_init(): creates enable_backend_flag when CONFIG_SEC_UTILS_SIGN_MODE != 'rel'; "
            "enable_debug_env_in_base_img_boot(): "
            "echo 'root::0:0:root:/initramfs/:/bin/sh' >> /etc/passwd; "
            "IMG_VERIFY=1 set, HSU_KERNEL_IMGVERIFY=0 (profile); "
            "imgverify fallback: try rel-key -> if fail try dev-key -> if pass set mode=dev"
        ),
        "bin/backend_passwd_enable": (
            "chroot /rootfs usermod -p $(openssl passwd cis@123co) root"
        ),
        "hsu-keys/ (7 files, 2 distinct keys)": (
            "dev-key MD5 4a68951576b7b145d2d457a5cf7c0bc2: "
            "container-dev-verify-key.{pem,der} + rootfs-dev-verify-key.{pem,der} + tools-dev-verify-key.{pem,der}; "
            "rel-key MD5 1fd3bddb4b88e0e879c4a11868153659: "
            "container-rel-verify-key.{pem,der} + rootfs-rel-verify-key.{pem,der} + tools-rel-verify-key.{pem,der} + tools-verify-key.{pem,der}; "
            "tools-verify-key == tools-rel-verify-key (same file)"
        ),
        "etc/profile.d/hsu-profile.sh": (
            "IMG_VERIFY=1; "
            "HSU_KERNEL_IMGVERIFY=0; "
            "HSU_STANDALONE_OS=1; "
            "DISPLAY=':0'; WORKBASE=/initramfs/; MNTPATH=/mnt/cdrom"
        ),
    },
    "finding_count": "6F [2C+2H+2M+0L]",
    "cumulative": "843 [80C+289H+273M+200L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": "backend_passwd_enable sets hardcoded root password 'cis@123co' on server rootfs via chroot usermod",
        "description": (
            "/bin/backend_passwd_enable (2-line POSIX shell script shipped in initrd): "
            "'chroot /rootfs usermod -p $(openssl passwd cis@123co) root'. "
            "This script is callable from within the container environment. "
            "It executes in a chroot to /rootfs (the server's actual filesystem, not the initrd). "
            "openssl passwd generates a crypt() hash of 'cis@123co' which is set as root's password. "
            "After this runs, anyone can SSH/console to the server as root with password 'cis@123co'. "
            "The script is triggered when the backend container runs diagnostics in backend mode. "
            "Backend mode is entered via the MD5 password check (see F2), which uses the same password. "
            "Sequence: (1) Diagnostics ISO boots -> dev-signed container loaded "
            "-> post_init() creates enable_backend_flag; "
            "(2) Operator enters 'cis@123co' at backend prompt -> root shell in initrd; "
            "(3) backend_passwd_enable called -> root password on server OS set to 'cis@123co'; "
            "(4) Server persists the root password after reboot."
        ),
        "evidence": {
            "file": "/bin/backend_passwd_enable",
            "content": "chroot /rootfs usermod -p $(openssl passwd cis@123co) root",
            "password": "cis@123co",
            "target": "/rootfs (server OS root filesystem, not initrd)",
        },
        "impact": (
            "Root password on the target UCS server set to 'cis@123co' after diagnostics run. "
            "Persists across reboots. Credential is identical for every server that runs this ISO."
        ),
        "remediation": "Remove backend_passwd_enable. Replace static password with a server-unique derivation or interactive prompt.",
    },
    {
        "id": "F2",
        "severity": "CRITICAL",
        "title": "Backend mode access password MD5 hash 942aa63a77ccc253c5f97b152479e544 = 'cis@123co'; same as F1 chroot password",
        "description": (
            "init.d/00-prehsu enable_backend() function: "
            "'password_md5=$(echo -n \"$password\" | md5sum | awk '{print $1}')' "
            "'if [ \"$password_md5\" == \"942aa63a77ccc253c5f97b152479e544\" ]'. "
            "MD5 of 'cis@123co' = 942aa63a77ccc253c5f97b152479e544 (confirmed). "
            "On match: '/bin/sh +m' (interactive root shell in initrd). "
            "MD5 is not collision-resistant and is reversible by hash lookup tables -- "
            "a cryptographically weak comparison for an access gate. "
            "The password is identical to the one in backend_passwd_enable (F1). "
            "Backend mode access is enabled automatically (post_init creates the flag) "
            "whenever a dev-signed container is loaded -- which happens on any system "
            "that does not have a release-signed container present."
        ),
        "evidence": {
            "file": "init.d/00-prehsu lines 70-83",
            "hash": "942aa63a77ccc253c5f97b152479e544",
            "plaintext": "cis@123co (confirmed: echo -n 'cis@123co' | md5sum)",
            "trigger": "post_init(): if CONFIG_SEC_UTILS_SIGN_MODE != 'rel' -> create enable_backend_flag",
        },
        "impact": (
            "Any operator who boots the diagnostics ISO with a dev-signed container "
            "is prompted for a password that is known and identical on every UCS system."
        ),
        "remediation": "Replace MD5 check with a hardware-bound or per-system credential. Remove enable_backend_flag auto-creation.",
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "enable_debug_env_in_base_img_boot() inserts passwordless root to /etc/passwd; getty on serial port",
        "description": (
            "init.d/00-prehsu enable_debug_env_in_base_img_boot() function: "
            "'echo \"root::0:0:root:/initramfs/:/bin/sh\" >> /etc/passwd'. "
            "This appends a second root entry (UID 0) to /etc/passwd with no password (:: = empty). "
            "On systems where /etc/passwd takes precedence over /etc/shadow for null passwords, "
            "root can log in with no password. "
            "The function also starts a getty on the serial port (start_getty), "
            "so serial console access yields an interactive prompt. "
            "After writing the empty-password root, the function calls '/bin/sh +m' "
            "which is a root shell in the initrd environment. "
            "This function is invoked during base image debug boot mode -- "
            "a mode triggered by a kernel parameter or build flag."
        ),
        "evidence": {
            "file": "init.d/00-prehsu lines 686-714",
            "empty_root": "echo 'root::0:0:root:/initramfs/:/bin/sh' >> /etc/passwd",
            "shell": "/bin/sh +m (job control disabled, root shell)",
        },
        "impact": "Serial console yields root without any password credential when debug boot mode is active.",
        "remediation": "Remove the empty-password root entry insertion. Gate debug mode behind a hardware RoT assertion.",
    },
    {
        "id": "F4",
        "severity": "HIGH",
        "title": "Dev-signed containers accepted as fallback in production diagnostics; auto-trigger backend mode",
        "description": (
            "init.d/00-prehsu container signature verification flow: "
            "1. Try imgverify with container-rel-verify-key.pem. "
            "2. If release verification fails -> retry with container-dev-verify-key.pem. "
            "3. If dev key passes -> set CONFIG_SEC_UTILS_SIGN_MODE=dev. "
            "4. post_init(): 'if [ \"$CONFIG_SEC_UTILS_SIGN_MODE\" != \"rel\" ]' -> "
            "   'touch $CONTAINER_MNTPOINT/tmp/enable_backend_flag' -> enable_backend() activates. "
            "The dev key is an RSA-2048 public key distinct from the release key. "
            "Compromise of the Cisco development signing private key allows an attacker "
            "to sign a malicious diagnostics container that passes verification with the dev key, "
            "loads in the diagnostics environment, and automatically creates the backend flag "
            "enabling further exploitation via F1/F2. "
            "The dev key is present in every copy of this ISO on every UCS server that "
            "runs diagnostics version 7.1.4.260010."
        ),
        "evidence": {
            "file": "init.d/00-prehsu lines 263-282",
            "flow": (
                "imgverify(rel-key) fails -> imgverify(dev-key) passes "
                "-> CONFIG_SEC_UTILS_SIGN_MODE=dev "
                "-> post_init() creates enable_backend_flag "
                "-> enable_backend() armed"
            ),
            "dev_key_fingerprint": "MD5: 4a68951576b7b145d2d457a5cf7c0bc2",
        },
        "impact": "Dev-key-signed container on production system auto-enables the F1/F2 backdoor chain.",
        "remediation": "Remove dev verification keys from production ISOs. Ship only release-key trust roots.",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "HSU_KERNEL_IMGVERIFY=0 in default profile; all hsu-set-verify-key calls are dead code",
        "description": (
            "etc/profile.d/hsu-profile.sh: 'export HSU_KERNEL_IMGVERIFY=0'. "
            "All occurrences of signature key loading via hsu-set-verify-key in 00-prehsu are "
            "guarded by '[ $HSU_KERNEL_IMGVERIFY = \"1\" ] && hsu-set-verify-key ...'. "
            "With HSU_KERNEL_IMGVERIFY=0 (the permanent default), "
            "hsu-set-verify-key is never called. "
            "The kernel-level image verification (hardware trust path) is always disabled. "
            "Only the software-level imgverify (executable in /usr/bin or similar) runs, "
            "which is a process-level check without hardware-backed enforcement. "
            "Both the initial imgverify run (container) and the utility package verification "
            "rely solely on the software imgverify without hardware key enforcement."
        ),
        "evidence": {
            "profile": "HSU_KERNEL_IMGVERIFY=0 (etc/profile.d/hsu-profile.sh)",
            "dead_calls": "[ $HSU_KERNEL_IMGVERIFY = \"1\" ] && hsu-set-verify-key ... (always false)",
        },
        "impact": "Hardware-backed signature verification never active; all verification is software-only.",
        "remediation": "Enable HSU_KERNEL_IMGVERIFY=1 or remove the conditional guard from hsu-set-verify-key calls.",
    },
    {
        "id": "F6",
        "severity": "MEDIUM",
        "title": "Both dev and release RSA-2048 verify keys shipped in production initrd; 7 key files, 2 distinct keys",
        "description": (
            "hsu-keys/ contains 7 PEM/DER files representing only 2 distinct public keys: "
            "dev key (MD5: 4a68951576b7b145d2d457a5cf7c0bc2): "
            "container-dev, rootfs-dev, tools-dev all share this public key. "
            "rel key (MD5: 1fd3bddb4b88e0e879c4a11868153659): "
            "container-rel, rootfs-rel, tools-rel, tools-verify all share this public key. "
            "Consequence: there is a single dev private key that signs all categories "
            "(container, rootfs, tools). "
            "Compromise of the dev private key covers the entire signing surface. "
            "The dev and rel keys are functionally distinct -- they are not the same key -- "
            "but shipping the dev key in the production ISO means the production trust root "
            "includes a key whose private counterpart is in use in development CI/CD pipelines, "
            "which have a broader threat surface than production signing HSMs."
        ),
        "evidence": {
            "dev_key_files": "container-dev, rootfs-dev, tools-dev (all same RSA-2048 pub key)",
            "rel_key_files": "container-rel, rootfs-rel, tools-rel, tools-verify (all same RSA-2048 pub key)",
            "key_count": "7 files, 2 distinct public keys",
        },
        "impact": "Dev CI/CD signing key is a valid trust root on production diagnostics systems.",
        "remediation": "Remove dev keys from production ISOs. Use dedicated per-environment signing keys.",
    },
]


if __name__ == "__main__":
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Findings: {MODULE_SUMMARY['finding_count']}")
    print(f"Cumulative: {MODULE_SUMMARY['cumulative']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['id']}: {f['title']}")
