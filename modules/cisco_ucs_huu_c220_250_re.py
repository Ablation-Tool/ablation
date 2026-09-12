"""
Cisco UCS C220 M8 HUU 4.3.6.250039 RE

Target:  ucs-c220m8-huu-4.3.6.250039.iso (April 2025 build branch)
         Platform: GODZILLA1 (UCSC-C220-M8S, UCSC-C220-M8E3S)
         Distinct from the 260054 build already analyzed in cisco_ucs_huu_c220_436_re.py
         ISO layout: squashfs container (catalog/ cpk/ firmware/ tools/ base.tar.gz)
         base.tar.gz: Yocto Linux container root (Python 3.11, nginx, gunicorn3)
         hsu.tgz.enc: AES-256-CBC encrypted HUU Python application (29MB)
Key files: etc/init.sh (boot orchestration, timefile injection, post_init backdoor call)
           etc/init-huu.sh (Flask startup, set_timezone, WORKBASE=/root/hsu)
           usr/sbin/decrypt-file (ELF x86-64 stripped, hardcoded AES key in string table)
           huu_decrypted/hsu/HuuApp.py (Flask app, CMCSecureBoot + UCSUpdate endpoints)
           huu_decrypted/hsu/app.py (Flask app factory, no before_request auth)
           catalog/Catalog.json (platform=GODZILLA1, CIMC=cimc.bin 158MB)
           cpk/hsu_agent.json (hsu_agent v1.0.2, git sha 4383a41)
Session: 39
"""

MODULE_SUMMARY = {
    "module": "cisco_ucs_huu_c220_250_re",
    "firmware": "ucs-c220m8-huu-4.3.6.250039.iso (April 2025 build, GODZILLA1 platform)",
    "components": {
        "usr/sbin/decrypt-file (ELF x86-64, stripped)": (
            "Called by set_workbase.sh to decrypt hsu.tgz.enc -> /tmp/hsu.tgz. "
            "String table contains the full openssl command with hardcoded key: "
            "openssl enc -aes-256-cbc -d -md sha256 -pbkdf2 -in %s -out %s.gz "
            "-k zfguijkophju@*%1] -nosalt; "
            "confirmed: openssl enc with this key successfully decrypts hsu.tgz.enc"
        ),
        "etc/init.sh (boot orchestration)": (
            "start_hsu_agent(): "
            "chroot ${MNTPATH} sh -c \"cd ${WORKBASE} && $(cat ${MNTPATH}/${WORKBASE}/logs/timefile) "
            "&& python ${WORKBASE}/hsu-redfish.py ...\"; "
            "timefile written by set_timezone() from BMC jolt response (tsa_ucs -R -r 66); "
            "post_init() { backend_passwd_enable } called unconditionally at boot end; "
            "setup_rootfs(): commented-out chroot usermod cis@123co still present"
        ),
        "huu_decrypted/hsu/HuuApp.py (Flask-RESTful, no auth)": (
            "UCSUpdate.post() at /redfish/v1/UpdateService/Actions/Oem/CiscoUCSExtensions.UCSUpdate: "
            "no auth decorator; steps: verify_post_request -> verify_update_request -> "
            "validate_update_targets -> AsyncUpdate.start(); "
            "CMCSecureBoot.post() at /huu/v1/CMCSecureBoot: no auth decorator; "
            "app.py: Flask() with no before_request auth; api.add_resource() for both handlers"
        ),
        "etc/init.sh setup_rootfs() dev-mode block": (
            "if [ $CONFIG_SEC_UTILS_SIGN_MODE == \"dev\" ]: "
            "append 5:12345:respawn:/sbin/getty 38400 tty5, tty6, tty7 to $ROOTFS_DIR/etc/inittab; "
            "dev-signed containers accepted as fallback per 00-prehsu flow (diag ISO F4)"
        ),
        "catalog/Catalog.json": (
            "platform_name=GODZILLA1; "
            "platform_supported_pids=[UCSC-C220-M8S, UCSC-C220-M8E3S]; "
            "firmware/cimc/cimc.bin: 158MB; firmware/bios/bios.pkg; "
            "common-tools: secure-copy enabled=true for sg_inq/ipmitool/nvme"
        ),
    },
    "finding_count": "6F [1C+2H+2M+1L]",
    "cumulative": "849 [81C+291H+275M+201L]",
}


FINDINGS = [
    {
        "id": "F1",
        "severity": "CRITICAL",
        "title": "decrypt-file binary hardcodes AES-256-CBC key 'zfguijkophju@*%1]'; HUU Python app decryptable from any copy of the ISO",
        "description": (
            "usr/sbin/decrypt-file (ELF x86-64 stripped, BuildID b8e2689db8c1561c0283d137360916fae75598f2) "
            "is called by etc/set_workbase.sh to decrypt hsu.tgz.enc before the HUU app starts. "
            "The binary's string table contains the full decryption command verbatim: "
            "'openssl enc -aes-256-cbc -d -md sha256 -pbkdf2 -in %s -out %s.gz "
            "-k zfguijkophju@*%1] -nosalt 2>&1'. "
            "The passphrase 'zfguijkophju@*%1]' is the same for all UCS C220-M8 HUU 4.3.6.250039 deployments. "
            "Confirmed: running this openssl command against the ISO's hsu.tgz.enc produces a valid "
            "29MB tarball containing all HUU Python source (HuuApp.py, RedfishApp.py, CMC_Hook.py, etc.). "
            "The encryption provides no confidentiality: any party with the ISO can decrypt the app. "
            "Beyond code exposure, the decrypted app confirms all unauthenticated endpoints (F2) "
            "and the exact Flask route registrations. "
            "Two openssl command variants are present: one decompresses the output in place "
            "(.gz suffix), one outputs the raw .tgz -- both use the same key."
        ),
        "evidence": {
            "binary": "usr/sbin/decrypt-file (stripped ELF x86-64)",
            "string_table": (
                "openssl enc -aes-256-cbc -d -md sha256 -pbkdf2 -in %s -out %s.gz "
                "-k zfguijkophju@*%1] -nosalt 2>&1"
            ),
            "confirmed": "openssl enc -aes-256-cbc -d -md sha256 -pbkdf2 -in hsu.tgz.enc -out hsu.tgz -k 'zfguijkophju@*%1]' -nosalt -> exit 0, valid tarball",
            "decrypted_size": "29MB (hsu.tgz.enc) -> 29MB (hsu.tgz) containing root/hsu/*.py",
        },
        "impact": (
            "All HUU Python source for GODZILLA1 platform is readable from any ISO copy. "
            "Hardcoded key is the same across the entire HUU 4.3.6.250039 fleet."
        ),
        "remediation": (
            "Do not hardcode encryption keys in shipped binaries. "
            "Derive the decryption key from a hardware identity (SUDI, BMC-unique secret) at runtime."
        ),
    },
    {
        "id": "F2",
        "severity": "HIGH",
        "title": "CMCSecureBoot (/huu/v1/CMCSecureBoot) and UCSUpdate (/redfish/v1/UpdateService/Actions/Oem/CiscoUCSExtensions.UCSUpdate) have no authentication in 4.3.6.250039",
        "description": (
            "Confirmed via F1 decryption of hsu.tgz.enc. "
            "hsu_decrypted/hsu/HuuApp.py: "
            "UCSUpdate.post() and CMCSecureBoot.post() are Flask-RESTful Resource classes. "
            "Neither has an auth decorator. "
            "app.py: Flask() app factory with no before_request authentication hook. "
            "api.add_resource() registers both handlers directly: "
            "CMCSecureBoot -> /huu/v1/CMCSecureBoot, "
            "UCSUpdate -> /redfish/v1/UpdateService/Actions/Oem/CiscoUCSExtensions.UCSUpdate. "
            "CMCSecureBoot.post() flow: verify_post_request -> verify_cmc_secure_boot_request -> "
            "get_cmc_comp_obj(CMC1) + get_cmc_comp_obj(CMC2) -> cmc_obj.set_secure_boot(secure_boot). "
            "UCSUpdate.post() flow: verify_post_request -> verify_update_request -> "
            "validate_update_targets -> AsyncUpdate.start(). "
            "Nginx listens on 0.0.0.0:80 (NGINX_DEFAULT_IP=0.0.0.0, NGINX_DEFAULT_PORT=80). "
            "HUU is accessible from any host on the network with a route to port 80. "
            "This pattern persists from 4.3.6 across platforms (C220-M8, C245-M8, XE130) and "
            "from 4.x through 6.0.2 as documented in prior ablation modules."
        ),
        "evidence": {
            "file": "huu_decrypted/hsu/HuuApp.py lines 321-360, 424-490, 535-543",
            "routes": (
                "CMCSecureBoot: /huu/v1/CMCSecureBoot (POST)\n"
                "UCSUpdate: /redfish/v1/UpdateService/Actions/Oem/CiscoUCSExtensions.UCSUpdate (POST)"
            ),
            "no_auth_evidence": "no @login_required, no before_request, no HTTPTokenAuth in app.py or HuuApp.py",
            "network_binding": "NGINX_DEFAULT_IP=0.0.0.0, NGINX_DEFAULT_PORT=80 (init-huu.sh)",
        },
        "impact": (
            "Unauthenticated access to: toggle chassis secure boot on GODZILLA1 (C220-M8S/E3S) "
            "CMC1 and CMC2 via set_secure_boot(); trigger async firmware update with arbitrary "
            "targets/excludes list; no credential required."
        ),
        "remediation": (
            "Add Flask HTTPTokenAuth or equivalent auth decorator to UCSUpdate.post() and CMCSecureBoot.post(). "
            "Bind gunicorn to localhost only (127.0.0.1) and require nginx auth_request for all non-GET paths."
        ),
    },
    {
        "id": "F3",
        "severity": "HIGH",
        "title": "timefile cmd injection in start_hsu_agent: BMC-controlled timezone written to timefile executed as shell command in chroot",
        "description": (
            "etc/init.sh start_hsu_agent() line 57: "
            "\"chroot ${MNTPATH} sh -c 'cd ${WORKBASE} && $(cat ${MNTPATH}/${WORKBASE}/logs/timefile) "
            "&& python ${WORKBASE}/hsu-redfish.py ...'\" "
            "$(cat ... timefile) is a command substitution inside the sh -c argument. "
            "The shell evaluates the contents of timefile as a command before executing. "
            "timefile is written by set_timezone() in init-huu.sh (lines 391-405): "
            "'echo \"export TZ=UTC\" > $TIME_FILE' (default) OR "
            "'echo \"export TZ=$time_zone\" > $TIME_FILE' where time_zone comes from "
            "'/opt/cisco/tsa_ucs -R -r 66 -l time_response.json' -> jq '.timezone'. "
            "tsa_ucs is a CIMC communication binary that reads a BMC response. "
            "A compromised or spoofed BMC can return a timezone value containing shell metacharacters. "
            "Example: timezone value 'UTC; id>/tmp/pwned' in the BMC jolt response would inject "
            "'export TZ=UTC; id>/tmp/pwned' into timefile, executing id as root inside the chroot. "
            "init-huu.sh does not sanitize $time_zone before writing it to $TIME_FILE."
        ),
        "evidence": {
            "file": "etc/init.sh line 57",
            "injection_point": "$(cat ${MNTPATH}/${WORKBASE}/logs/timefile) in sh -c argument",
            "timefile_write": "etc/init-huu.sh lines 391-405: echo 'export TZ=$time_zone' > $TIME_FILE (unsanitized)",
            "bmc_source": "tsa_ucs -R -r 66 -l time_response.json -> jq -r .timezone",
        },
        "impact": "BMC-controlled timezone value executes as root shell commands inside the chroot at HUU boot.",
        "remediation": (
            "Replace $(cat timefile) with sourcing or explicit var assignment: "
            ". $TIMEFILE or TZ=$(cat $TIMEFILE). Sanitize timezone to [A-Za-z/_+0-9] before write."
        ),
    },
    {
        "id": "F4",
        "severity": "MEDIUM",
        "title": "setup_rootfs() appends getty on tty5/tty6/tty7 to server OS /etc/inittab when dev-signed container loads",
        "description": (
            "etc/init.sh setup_rootfs() lines 88-96: "
            "if [ $CONFIG_SEC_UTILS_SIGN_MODE == \"dev\" ]: "
            "append '5:12345:respawn:/sbin/getty 38400 tty5', tty6, tty7 "
            "to $ROOTFS_DIR/etc/inittab. "
            "ROOTFS_DIR=/rootfs is the server's runtime OS mounted from rootfs.img. "
            "The inittab modification persists on the overlay filesystem for the duration of the HUU session. "
            "CONFIG_SEC_UTILS_SIGN_MODE is set to 'dev' in 00-prehsu when a dev-signed "
            "container passes imgverify with the dev key (same trigger as diag ISO F4). "
            "Three additional getty processes on tty5-7 provide root serial console sessions "
            "on the server without any credential requirement beyond physical access. "
            "The dev-signed container fallback path in 00-prehsu also auto-creates "
            "enable_backend_flag (diag ISO F2/F4), chaining to the cis@123co backdoor. "
            "The HUU ISO ships the same dev + release verify keys as the diag ISO "
            "(dev MD5: 4a68951576b7b145d2d457a5cf7c0bc2)."
        ),
        "evidence": {
            "file": "etc/init.sh lines 88-96",
            "inittab_injection": (
                "echo '5:12345:respawn:/sbin/getty 38400 tty5' >> $ROOTFS_DIR/etc/inittab\n"
                "echo '6:12345:respawn:/sbin/getty 38400 tty6' >> $ROOTFS_DIR/etc/inittab\n"
                "echo '7:12345:respawn:/sbin/getty 38400 tty7' >> $ROOTFS_DIR/etc/inittab"
            ),
            "trigger": "CONFIG_SEC_UTILS_SIGN_MODE == 'dev' (set when dev-signed container accepted by imgverify)",
        },
        "impact": (
            "Dev-signed container on production HUU boot adds three root serial console sessions "
            "to the server OS /etc/inittab. No credential required on getty login."
        ),
        "remediation": "Remove the dev-mode inittab block. Do not modify the server OS /etc/inittab during HUU boot.",
    },
    {
        "id": "F5",
        "severity": "MEDIUM",
        "title": "post_init() calls backend_passwd_enable unconditionally at every HUU boot; same function name as diag ISO root backdoor",
        "description": (
            "etc/init.sh main body (line 218-220 region): "
            "post_init() { backend_passwd_enable } is called unconditionally at the end of the "
            "init.sh main execution path, after start_client() returns. "
            "backend_passwd_enable is not a shell function defined in init.sh or the sourced scripts "
            "(init-huu.sh, huu-utilities.sh, huu-exports.sh). "
            "It is also not present as a binary in the extracted base container /bin/ or /usr/bin/. "
            "However, huu-exports.sh adds $WORKBASE to PATH, and hsu.tgz.enc decrypts to WORKBASE=/root/hsu. "
            "If backend_passwd_enable exists in the WORKBASE (the decrypted HUU app directory), "
            "it executes as root in the initrd after HUU completes. "
            "In the diag ISO, /bin/backend_passwd_enable does "
            "'chroot /rootfs usermod -p $(openssl passwd cis@123co) root'. "
            "The same binary could exist in hsu.tgz.enc without appearing in the base container "
            "(the container base is pre-decryption; the workbase is populated at runtime). "
            "A separate commented-out line in setup_rootfs() confirms the intended password: "
            "'# chroot $ROOTFS_DIR sh -c \"usermod --password $(openssl passwd cis@123co) root\"' -- "
            "the exact cis@123co pattern from the diag ISO backdoor (diag ISO F1/F2)."
        ),
        "evidence": {
            "file": "etc/init.sh",
            "unconditional_call": "post_init() { backend_passwd_enable }  (called at boot end)",
            "not_in_base": "no backend_passwd_enable binary in /bin/ or /usr/bin/ of base container",
            "commented_evidence": (
                "# chroot $ROOTFS_DIR sh -c 'usermod --password $(openssl passwd cis@123co) root' "
                "(setup_rootfs(), commented out but present)"
            ),
            "cross_product": "Identical function name and password as diag ISO backend_passwd_enable",
        },
        "impact": (
            "If backend_passwd_enable is present in the decrypted workbase, "
            "it executes as root after every HUU boot, setting server OS root password to 'cis@123co'."
        ),
        "remediation": (
            "Remove unconditional post_init() -> backend_passwd_enable call. "
            "Remove commented-out usermod line. "
            "Audit hsu.tgz.enc contents for backend_passwd_enable."
        ),
    },
    {
        "id": "F6",
        "severity": "LOW",
        "title": "Python 3.11 in Yocto container but app invoked as 'python' (without version suffix) in multiple init.sh calls",
        "description": (
            "etc/init-huu.sh lines: "
            "'python ${WORKBASE}/huu_prerequisite.py' (prerequisite_check()); "
            "start_tech_support_daemon() uses 'python3 hsu_logs_daemon.py'; "
            "diag_prepare_common_tools() uses 'python3 -c ...'. "
            "etc/init.sh start_hsu_agent() uses 'python ${WORKBASE}/hsu-redfish.py'. "
            "The base container ships python3.11 at /usr/lib/python3.11/ but the HUU PATH "
            "(huu-exports.sh) does not canonically define whether 'python' resolves to python3. "
            "init.sh: 'pre_init() { cp /bin/bash /usr/bin/bash; chmod +x /bin/ldd }'. "
            "The cp /bin/bash to /usr/bin/bash in pre_init() suggests the PATH resolution "
            "for busybox-based commands may be non-standard. "
            "If an attacker can write a file named 'python' to a PATH-precedent directory "
            "within the chroot (e.g., ${WORKBASE}/python since WORKBASE is in PATH via huu-exports.sh), "
            "hsu-redfish.py launch is hijacked. "
            "The WORKBASE is created from the decrypted hsu.tgz.enc and "
            "any writable path in WORKBASE or a PATH-precedent directory enables this. "
            "The /tmp directory within the chroot is world-writable."
        ),
        "evidence": {
            "file": "etc/init.sh line 57; etc/init-huu.sh prerequisite_check()",
            "python_call": "python ${WORKBASE}/hsu-redfish.py (no version suffix)",
            "path": "PATH=$PATH:/bin:/usr/bin:/sbin:/usr/sbin:$WORKBASE/diag_scripts:$WORKBASE (huu-exports.sh)",
            "pre_init": "cp /bin/bash /usr/bin/bash (non-standard bash placement)",
        },
        "impact": (
            "Writable directory at WORKBASE precedence in PATH allows python binary hijack "
            "to redirect hsu-redfish.py launch to attacker-controlled executable."
        ),
        "remediation": "Use absolute paths to the python3 interpreter. Remove WORKBASE from PATH.",
    },
]


if __name__ == "__main__":
    print(f"Module: {MODULE_SUMMARY['module']}")
    print(f"Findings: {MODULE_SUMMARY['finding_count']}")
    print(f"Cumulative: {MODULE_SUMMARY['cumulative']}")
    print()
    for f in FINDINGS:
        print(f"  [{f['severity']}] {f['id']}: {f['title']}")
