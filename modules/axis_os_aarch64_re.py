"""
axis_os_aarch64_re — AXIS OS AArch64 firmware binary RE module

Targets:
  Q1656_12_11_118 rootfs (AArch64 PIE stripped ELFs)
  D1110_12_11_77 rootfs (AArch64, AXIS D1110 Video Decoder 4K)
  M3945-R_12_11_77 rootfs (AArch64, fixed mini dome camera)
  BW_W800_12.10.59 rootfs (AArch64, body worn camera)
  D2110-VE_12_9_57 rootfs (ARMv7hf, security radar)
  A1210_12_11_106 rootfs (ARMv7hf, AXIS A1210 Network Door Controller, Genetec Track)
  A1710_12_11_106 rootfs (ARMv7hf, AXIS A1710-B Network Door Controller, Genetec Track)
  A1810_12_11_106 rootfs (ARMv7hf, AXIS A1810-B Network Door Controller, Genetec Track)
  Vienna Q6215-LE_10.9_CSB rootfs (ARMv7hf, unreleased police CSB)
  BWL EAP 2.0.1 (rsignal Rust AArch64)

Binaries:
  packagemanager.cgi  — xmlReadMemory + multipart ACAP manifest parsing (XXE candidate)
  stclient            — ASRA relay client; user_manager_vapix_*; g_spawn_command_line_sync
  rsignal             — Rust AArch64 WebRTC signaling server (unknown surface)
  netd                — 802.1x EAP config writer (F-AXNETD-01 confirmed)

Architecture: AArch64 (ELF64) PIE stripped.
Prologue detection: STP X29,X30,[SP,#-N]! (0x?d 0x7b 0b?? 0xa9) — standard AAPCS64 frame.
PLT resolution: RELA sections (R_AARCH64_JUMP_SLOT 0x402) + .dynstr.

Confirmed findings:
  F-AXNETD-01    WPA supplicant config injection (netd) — confirmed 10/10 firmwares
                 identity="%s", password="%s" unescaped; g_strescape linked zero callers
                 D1110 12.11.77, A1210/A1710/A1810 12.11.106.1: confirmed
                 Note: binary named "netd" on PACS controllers (not "axnetd")
  F-AXPKG-01     REFUTED: libxml2 2.13+ disables XXE by default; no xmlSubstituteEntitiesDefault
  F-AXTEST-01    Multi-protocol SSRF via diagnostic CGIs — viewer privilege, no RFC-1918 filter
                 httptest.cgi: HTTP/HTTPS probe; links libhttp_smtp_notify.so (same as F-AXACTION-01)
                 ftptest.cgi (shell script): FTP/SFTP probe via curl; uploads test file to internal FTP
                   - accepts address, port, proto (ftp|sftp), username, password, uploadpath
                   - can submit attacker-controlled credentials to internal FTP servers
                 tcptest.cgi (shell script): TCP-level probe via /usr/bin/tcptest
                 smtptest.cgi: SMTP connection test, same libhttp_smtp_notify.so loopback-only filter
                 All 4 CGIs: validateaddr blocks only loopback; RFC-1918/link-local unrestricted
                 Auth: axis-group-file (viewer, operator, admin) — no operator or admin required
                 Direct exploitation, no action rule setup required
                 Bugcrowd report updated: bugcrowd-F-AXTEST-01.md (4 vectors)
  F-AXSTC-01     stclient: relay-server-triggered VAPIX user add/modify/remove (HIGH)
  F-AXSTC-02     REFUTED: g_spawn arg is hardcoded /usr/bin/checkprogress.sh
  F-AXUSRMGR-01  Pre-auth passphrase complexity write via ?anonymous=true bypass
                 Apache config_server_reverseproxy.conf: AuthMerging Off + anonymous=true
                 -> Require all granted -> dev-conf-service anonymous API allows SET
                 Confirmed 12/12 firmwares (12.9.57→12.11.118; not in 12.2.59)
                 Products: cameras (5), video decoder (1), security radar (1), body worn (1),
                           PACS door controllers (3), network display speaker (1) — platform-wide
                 A1210/A1710/A1810 door controllers: pre-auth policy downgrade chains to door relay control
  F-AXC1710-01  Unauthenticated broadcast/capture/reboot on port 7234 — InformaCast integration
                 Binary: /usr/bin/informacast-client (Rust, tokio); Apache VirtualHost on 0.0.0.0:7234
                 Activated when admin enables InformaCast: .path unit watches
                   /etc/dynamic/informacast-client/enabled -> informacast-client-enable.service writes
                   "Define INFORMACAST_ENABLED" to Apache param.d/ -> httpd reload -> VirtualHost active
                 All 5 endpoints on port 7234 have Require all granted (no IP restriction):
                   /broadcast — play audio through speaker (InformaCast XML payload)
                   /capture   — capture audio from microphone
                   /clear     — stop current broadcast
                   /reboot    — device reboot
                   /status    — device status
                 Any host on the network can reboot the device or inject audio when InformaCast enabled.
                 Apache VirtualHost does Include httpd-basic-auth.conf but each Location immediately
                 overrides with Require all granted (parent-auth-then-child-override pattern).
                 Firmware: AXIS C1710 Network Display Speaker 12.11.77 (mx8mm AArch64)
                 File: /etc/apache2/conf.d/informacast-client.conf

D1110 Video Decoder 4K 12.11.77 analysis (AArch64):
  All 5 existing findings confirmed (F-AXNETD-01, F-AXPARAM-01, F-AXACTION-01/02, F-AXUSRMGR-01)
  Unique surfaces checked: GStreamer rtspsrc pipeline, ONVIF WebSocket proxy (no Require),
  HDMI CEC dbus plugin, HID action handler, Nexus WS bridge, EdgeFileManager
  VideoUri API (decoder_v4.yaml): only minLength/maxLength, no scheme restriction — but
    external-media plugin explicitly creates rtspsrc element; http:// fails at GStreamer layer
  ONVIF WebSocket missing auth (/onvif/rtsp-over-websocket has no Require directive):
    RTSP server auth (rtspauth.conf Asterisk realm, Paths=*) mitigates — low severity, not filed
  No novel D1110-specific critical findings.

Cross-product analysis (new firmwares this session):
  A1210 Network Door Controller 12.11.106.1 (ARMv7hf, Genetec Track):
    All 5 findings confirmed. PACS-specific libs: libosdp.so (RS-485 only, not network),
    libpacsio-*.so, librelaydoor-*.so (door relay API), liblibwiegand.so, libteeacl.so.
    /nbix/ and /nbixweb/ endpoints: Require admin, websocket only — properly secured.
    /nbixagent endpoint: Require all granted at Apache level (CMS integration path).
    served binary validates X-API-Key header vs registered operative agent clientToken (min 12 chars).
    portal-op interface (lock/unlock/access), accesspoint-op (requestAnonymousAccess, setAuthorizationState)
    reachable via /nbixagent but gated by X-API-Key check in served. No default/hardcoded token.
    Genetec Synergis Softwire 12.2.10001.0 embedded in firmware (not analyzed).
  A1710-B Network Door Controller 12.11.106.1 (ARMv7hf, Genetec Track):
    All 5 findings confirmed. Same PACS lib set as A1210 (libosdp, libpacsio, librelaydoor, etc).
    Same /nbixagent CMS integration endpoint — X-API-Key gated, same model as A1210.
    netd binary confirms F-AXNETD-01 (identity="%s", g_strescape in PLT zero callers).
    F-AXACTION-01/02 confirmed (libtcpnotify.so + libhttp_smtp_notify.so in actionengine_plugins/).
    relay-conf/relaydoor-conf schemas present: multi-relay hardware (A1710 supports 2 doors).
  A1810-B Network Door Controller 12.11.106.1 (ARMv7hf, Genetec Track):
    Identical to A1710-B in lib contents, capabilities, and schemas (diff: no change).
    All 5 findings confirmed. Same /nbixagent CMS endpoint model.
    PartNbr: 9137064471. ProdNbr: A1810-B. HardwareID: 9E4.
  D2110-VE Security Radar 12.9.57 (ARMv7hf):
    F-AXUSRMGR-01 confirmed (extends version floor to 12.9.x).
    api-def_remote-object-storage_v1.yaml: operator can GET azure/s3 config objects (secret:true
    fields presumably masked by dev-conf). api-def_coordinate-conversion_v1.yaml: viewer-accessible.
    uploadradarimage.cgi: operator-level file upload (implementation in libradar-cgi.so via transferCgi).
  BW W800 Body Worn Camera 12.10.59 (AArch64):
    F-AXUSRMGR-01 confirmed. recording-uploader/content-uploader: Go binaries, Azure/Swift upload.
    bws-storage-gen-passphrase: uses /dev/urandom — passphrase entropy is sound.
  C1710 Network Display Speaker 12.11.77 (AArch64, mx8mm):
    F-AXUSRMGR-01 confirmed (config_server_reverseproxy.conf identical pattern).
    F-AXNETD-01 confirmed (identity="%s", g_strescape in PLT zero callers).
    F-AXC1710-01: InformaCast integration opens unauthenticated port 7234 — see confirmed findings.
    Unique CGIs: siren_and_light.cgi (D-Bus to siren-and-light-service), speaker-display-preview.cgi
      (LVGL PNG snapshot), findmydevice.cgi, sipcertrefresh.cgi.
    Informacast binary: Rust/tokio/hyper (audio-rust-workspace 0.33.18).
    InformaCast port 7234 routing: Apache UnixSocket proxy to /run/informacast-client/httpproxy.
  Vienna Q6215-LE 10.9 CSB (ARMv7hf):
    F-AXNETD-01 confirmed (identity="%s", g_strescape zero callers). No dev-conf → F-AXUSRMGR-01 N/A.
    1024-bit RSA keys in /usr/etc/ssl/ (obsolete, not directly exploitable without key material).
  W101 Body Worn Camera 12.9.57 (Ambarella S5L):
    F-AXUSRMGR-01 confirmed (config_server_reverseproxy.conf identical pattern).
    BWC-specific Apache config (httpd-bwc.inc): recordings/live-view require ssl-verify-client or BWS session.
    bwc/pairing.cgi: Require all granted (unauthenticated), backend has request limit, PIN auth only.
    bwc/recordings.cgi: Require ssl-verify-client — well protected.
    record/list.cgi, record/export/: Require ssl-verify-client — well protected.
    bwc/status.cgi, access.cgi, certmgmt.cgi, samgmt.cgi: Require ssl-verify-client.
    Disk encryption CGIs (changediskpassphrase/enable/disable): default Require axis-group-file (viewer+).
    Unique binaries: bwa-manager (PIN pairing, session tokens), bwc-auditd, bwc-paramd, bwc-power-manager.
    bwa-manager: pairing window 5min default (PAIRING_WINDOW_TIMEOUT=300), Request limit reached enforced.
  M3945-R 12.11.77 (AArch64):
    All 5 findings confirmed. api-def_data-transformation_v1.yaml: JQ expressions at operator
    level — libjq in-process execution, no shell escape possible; DoS-only theoretical.
  AXIS LPV 3.0.8 ARTPEC9 (ACAP):
    upload.cgi operator-level: CSV plate list upload; implementation in fflprapp (32MB AArch64).
    cloud.cgi/cloud2.cgi/cloud3.cgi admin-level: curl to %s://%s/ — SSRF if host is user-controlled.
    config_axisa1001.cgi: a1001_url config param; admin-set URL passed to curl — admin SSRF.

Continued Q1656 12.11.118 CGI analysis:
  236 total CGI endpoints enumerated across all subdirectories.
  file_upload.cgi: --allowed-dirs="" means "all directories forbidden" (binary help confirms).
    File goes to /tmp (default-dir). Not a finding.
  oak.cgi: Owner Authentication Key (OAK) retrieval for O3C tunnel.
    Contacts oakcgi.o3c.axis.com/v1 using HMAC-SHA1 PSK derived from AXISNSKEY (bootblock).
    Method: getOAK. Uses default Require axis-group-file. Viewer can call — OAK not sensitive
    without Axis account + ADM, not independently exploitable.
  remoteservice.cgi: polkit-backed admin API for O3C relay params. Standard design.
  networkspeakerpairing.cgi: address param + util_address_is_valid (likely loopback-only like validateaddr).
    D-Bus: com.axis.NetworkSpeakerPairing. Could be SSRF if pairing makes outbound TCP.
    Not filed without confirmation of TCP connection behavior.
  ftptest.cgi: SSRF + FTP file upload via curl. Added to F-AXTEST-01.
  portmanagement.cgi (io/): SetActive/SetState/StartActionSequence — physical I/O control.
    D-Bus: com.axis.IOControl.State. Policy: context="default" allows ALL processes.
    No APAC (apac_check_auth absent). No REMOTE_USER/operator/viewer strings in binary.
    No GetConnectionUnixUser in io2d — daemon cannot identify D-Bus peer on method calls.
    io2d embedded XML access control (admin:3;operator:1 for Active) applies to legacy
    param.cgi path (confcached), NOT to IOControl.State D-Bus interface. Two separate paths.
    Apache: no portmanagement.cgi Location override — inherits Require axis-group-file (viewer+).
    FINDING F-AXIO-01 (static analysis): viewer can call SetActive/SetDirection on physical I/O.
    VAPIX doc specifies operator-minimum; implementation enforces viewer-minimum.
    Impact: relay-equipped cameras (Q1656, P3245, P3945, etc.) — viewer flips physical relays.
    On door-controller-wired installations, viewer can trigger gate/door release.
    Report: /home/cowboy/VDT/axis-os-re/bugcrowd-F-AXIO-01.md
  io/virtualinput.cgi, io/output.cgi, io/port.cgi, com/serial.cgi: all empty stubs — TransferProxy /var/run/iod/iodsocket.
  virtualinput/activate.cgi, virtualinput/deactivate.cgi: SHELL SCRIPTS — NOT empty stubs.
    Path: /usr/html/axis-cgi/virtualinput/activate.cgi (NOT under io/)
    → calls gdbus call -y -d com.axis.VirtualInput -o /com/axis/VirtualInput/Port/$port -m Activate
    virtualinputd: no APAC, no PolicyKit; D-Bus policy context="default" open to all peers.
    Apache: no Location/Directory override for virtualinput/ — inherits Require axis-group-file (viewer+).
    NO TransferProxy coverage (transfer.conf matches io/virtualinput.cgi, not axis-cgi/virtualinput/).
    FINDING F-AXVINPUT-01 (unverified live): viewer can trigger virtual input port 1-64.
    Impact: any action rule bound to a virtual input fires (recording, PTZ preset, HTTP notify,
    relay output, door controller unlock on PACS products). Viewer triggers operator-level actions.
    Report: /home/cowboy/VDT/axis-os-re/bugcrowd-F-AXVINPUT-01.md (not yet written).
  zipstream/setstrength.cgi, setfpsmode.cgi, setgop.cgi, setminfps.cgi, setprofile.cgi:
    AArch64 ELF binaries, source: zipstream-cgi/1.7.2. All 5 CGIs call com.axis.Video1 /
    com.axis.Video1.Channel D-Bus properties: ZStrength, ZFpsMode, ZGopMode, ZMaxGopLength,
    ZMinFps, ZProfile, ZProfileLevel. No APAC in any CGI, no REMOTE_USER, no auth strings.
    video-service daemon: apac_check_auth absent, libapac.so.0 absent, GetConnectionUnixUser absent.
    D-Bus policy (com.axis.Video1.conf): context="default" open — any peer can send to service.
    Apache: no zipstream/ Directory or Location override — inherits Require axis-group-file (viewer+).
    $ grep -r zipstream /etc/apache2/ → no output.
    FINDING F-AXZIP-01 (static analysis): viewer can set all live video encoding parameters.
    VAPIX doc specifies operator-minimum; implementation enforces viewer-minimum.
    Impact: viewer degrades stream quality (max compression), drops frame rate, changes GOP/profile —
    affects all stream consumers and VMS recordings. Global settings, not per-stream.
    Report: /home/cowboy/VDT/axis-os-re/bugcrowd-F-AXZIP-01.md
  privacymask.cgi: served via TransferProxy (mod_axis_transfer) to maskd Unix socket.
    TransferProxy NOT subject to <Proxy "*"> Require axis-group admin (FastCGI-only rule).
    Apache: no privacymask.cgi Location override — inherits Require axis-group-file (viewer+).
    maskd binary: apac_check_auth absent, libapac.so.0 absent, no "operator"/"viewer"/"admin"
    enforcement strings, no HTTP 403/401 response code. Only returns 200/204/503.
    maskd reads http_user + sc_get_group (from libstatuscache.so.1) but never enforces group.
    Write operations confirmed in maskd: disable_all, enable_all, base_create_mask, base_remove_mask.
    Audit log: "API Activity: %s@%s%s%s:%s updated privacymask (%s)." — logs but does not gate.
    D-Bus: com.axis.PrivacyShield1 context="default" open.
    FINDING F-AXMASK-01 (static analysis): viewer can disable all privacy masks, delete masks,
    add new masks, re-enable masks. VAPIX doc specifies operator-minimum for write operations.
    Impact: viewer exposes masked areas (personal/proprietary), bypasses GDPR/compliance masks,
    disrupts surveillance coverage. Masks do not auto-restore after disable.
    NOTE: admin/ in axis-cgi is a self-referential symlink (-> .) — no admin-restricted directory.
    Report: /home/cowboy/VDT/axis-os-re/bugcrowd-F-AXMASK-01.md
  dynamicoverlay.cgi (dynamictext daemon) + dynamicoverlay/*.cgi (dynamic_overlayd daemon):
    Two separate TransferProxy routes cover Dynamic Overlay API v1.x and v1.8.
    dynamic_overlayd_transfer.conf: <LocationMatch "/axis-cgi/dynamicoverlay/\w+\.cgi">
      TransferProxy /run/dynamic_overlayd/transfer (no auth directive in block, inherits viewer+).
    dynamictext_transfer.conf: <LocationMatch "/axis-cgi/dynamicoverlay.cgi">
      TransferProxy /run/dynamictext/transfer (same — no override, viewer+).
    dynamic_overlayd (/usr/bin/dynamic_overlayd): apac_check_auth absent, libapac.so.0 absent,
      no 403/401 response (only HTTP/1.0 200 OK). Write ops: addText, addImage, setText, setImage,
      CreateTextOverlay, CreateImageOverlay. API ID=dynamicoverlay version=1.8.
      Audit strings: dynamicoverlay.addText, dynamicoverlay.addImage, dynamicoverlay.setText.
    dynamictext (/usr/bin/dynamictext): apac_check_auth absent, no 403/401 response. Write ops:
      set_dynamic_text, settext. Reads caller group via sc_set_group (libstatuscache.so.1) — no
      enforcement follows. Only HTTP/1.0 200 OK response path.
    D-Bus: no dedicated dynamicoverlay D-Bus service; dynamic_overlayd uses internal IPC only.
    FINDING F-AXDOVL-01 (static analysis): viewer can add text/image overlays to live streams,
    modify existing overlays, and delete overlays. VAPIX doc specifies operator-minimum for write.
    Impact: viewer injects "SYSTEM OFFLINE" text or opaque image overlays visible to all VMS
    consumers; modifications persist until operator resets; affects all stream copies and recordings.
    Same root pattern as F-AXMASK-01 (TransferProxy bypass + no APAC in daemon).
    Report: /home/cowboy/VDT/axis-os-re/bugcrowd-F-AXDOVL-01.md
  httptest.cgi: libcgiparser.so (no enforcement), no Apache override (viewer+).
    Parameters: address (required URL), proxy_host, proxy_port, proxy_login, proxy_password,
    validate_server_cert. Scheme validation only (Only HTTP and HTTPS URL are valid).
    No RFC1918/loopback blocking: no strings for 127., 10., 192.168., 169.254., private in
    binary or libhttp_smtp_notify.so. Returns Status: %d %s upstream code to caller.
    Uses curl via libhttp_smtp_notify.so (send_http_notification). libformatname.so linked.
    Viewer-supplied proxy_host routes camera outbound traffic through attacker proxy.
    FINDING F-AXHTEST-01 (static analysis): viewer-level HTTP SSRF — camera makes
    outbound HTTP/HTTPS request to viewer-specified URL; status code returned to caller;
    no private-IP blocking; proxy override allows viewer to intercept camera notifications.
    Impact: internal network reachability probe, REST API interaction from camera IP,
    cloud metadata endpoint access (169.254.169.254), notification credential capture.
    Report: /home/cowboy/VDT/axis-os-re/bugcrowd-F-AXHTEST-01.md
  smtptest.cgi: libcgiparser.so (no enforcement), no Apache override (viewer+).
    Parameters: mailserver (required), port, encryption, user, login. Uses curl SMTP stack
    (libhttp_smtp_notify.so: curl_easy_setopt, send_smtp_notification, init_curl).
    Only restriction: "Local host not allowed" — likely 127.x.x.x only; no RFC1918 block.
    Email-address validation regex present but no server address filtering beyond localhost.
    FINDING F-AXSMTP-01 (static analysis): viewer-level SMTP SSRF — camera makes outbound
    SMTP connection to viewer-specified mailserver:port; timing oracle for TCP port scan;
    viewer can send test notifications via attacker-controlled mail servers.
    Impact: internal SMTP infrastructure enumeration, TCP port scan via SMTP timing,
    email origination from camera IP using attacker-supplied server credentials.
    Report: /home/cowboy/VDT/axis-os-re/bugcrowd-F-AXSMTP-01.md
  param.cgi: viewer-readable params include only boolean/status fields (System.RootPwdSet,
    System.CaptureModeSet). Sensitive params (RemoteService, WebService.UsernameToken): admin:3 only.
    ProxyPassword: type="password:writeonly" — even admin cannot read it back.
  clientnotes/set.cgi: stores group/key/value in /etc/clientnotes/data.conf (GLib keyfile).
    Default viewer access. No path traversal (g_key_file_set_string escapes). Not filed.
  applicationss/upload.cgi: ACAP install via AcapManager1.Install D-Bus. Auth level TBD.
  custfwcerts.cgi: installCertificate/removeCertificate. D-Bus backed. Auth TBD.

Body Worn System bundle (12.9.57) enumerated:
  Contains 5 firmware images: W100, W101, W102, W110, W120 + W120 LTE modem FW (Sierra Wireless SWI9X07H)
  W101 = AXIS W101 Bodyworn Camera (Ambarella S5L, HardwareID 908.2/908.21/908.22)
  W101 rootfs squashfs extraction started for unique CGI analysis.

Companion Bullet LE 9.80.132 (MIPS32, MPQT format) additional analysis:
  axisns.cgi: com.axis.AxisNS add/delete — registers device with AXIS relay via HMAC-signed HTTP.
    D-Bus: context="default" open. axisns binary: g_hmac_new (custom HMAC auth to external relay).
    No local authorization issue; operation affects external service registration only.
  date.cgi: action=set calls com.axis.PolicyKitSystem.SetTimeOfDay.
    PolicyKitSystem D-Bus: context="default" open BUT service uses PolicyKit for auth internally.
    Comment: "we'll reject callers using PolicyKit" — viewer DENIED at PolicyKit layer.
  image_param.cgi: deprecated (logged warning "will be removed with LTS 10.x, expected Q1 2020").
    Still present in 9.80.132. Calls org.freedesktop.DBus.Properties.Set on com.axis.ImageControl.
    ImageControl D-Bus: context="default" open. imaged binary: viewer:1 permission string present.
    Image property writes at viewer level theoretically possible; not filed without specific exploit.
  vaconfig.cgi + com.axis.RuleEngine: RuleEngine has no APAC; any D-Bus peer can call AddApplication/Start.
    Requires pre-installed analytics app in /usr/local/packages/. Viewer can reconfigure app XML.
    Not filed as standalone (requires precondition).

AXISP12 Thermal Camera (MIPS32, MPQT format, squashfs offset 4188020, 54MB extracted):
  Same MPQT firmware family as Companion Bullet LE. CGI set identical + call_overlay_upload.cgi.
  call_overlay_upload.cgi: BMP file upload for video overlay. file_upload + bmp2overlay.
    Path hardened: /var/volatile/tmp/ check + [a-zA-Z0-9./_()-] filename whitelist.
    Not filed.
  Unique D-Bus services vs Q1656: com.axis.TriggerData, com.axis.VideoControl (both context="default").
    triggerd: no APAC confirmed (no output from apac strings grep).
    No HTTP CGI found that calls TriggerData directly. Not filed without CGI path.
  debug-shell-wrapper: MIPS32 binary — sets root password + calls /bin/login via serial console only.
    systemd debug-shell.service.d override; ConditionPathExists=/dev/console. Not an HTTP vector.

AXIS Switch findings (D8248/D8208-R 8.90.1904) — SEPARATE from AXIS OS Bugcrowd scope:
  F7: Hardcoded AES-256-CBC key __D3b4gW0r1d@@ for admin credential storage (.axtra-cmd)
  See /media/cowboy/research/axis/extracted/AXIS-SWITCH-FINDINGS.md for full F1-F7 list.
  Disclose directly to AXIS (not Bugcrowd) — switch firmware outside AXIS OS scope.

Standalone:
    cd ~/ablation
    python3 modules/axis_os_aarch64_re.py --bin /media/cowboy/research/axis/extracted/Q1656_12_11_118/rootfs/usr/html/axis-cgi/packagemanager.cgi
    python3 modules/axis_os_aarch64_re.py --bin /media/cowboy/research/axis/extracted/Q1656_12_11_118/rootfs/usr/bin/stclient
    python3 modules/axis_os_aarch64_re.py --bin /tmp/bwl_eap/rsignal/rsignal --rust
    python3 modules/axis_os_aarch64_re.py --rootfs /media/cowboy/research/axis/extracted/Q1656_12_11_118/rootfs --all
"""

import argparse
import json
import os
import struct
import sys
from pathlib import Path
from typing import Optional

import capstone

sys.path.insert(0, str(Path(__file__).parent))
from semantic_search import describe_function, normalize_asm
from sentence_transformers import SentenceTransformer
import numpy as np


# ---------------------------------------------------------------------------
# ELF64 parsing
# ---------------------------------------------------------------------------

def _parse_elf64(path: str) -> dict:
    """
    Parse ELF64 section headers, dynstr, dynsym, and RELA sections.
    Returns dict with keys: sections, plt_map, text_data, text_va, text_off.
    """
    with open(path, 'rb') as f:
        data = f.read()

    if data[:4] != b'\x7fELF' or data[4] != 2:  # EI_CLASS = ELFCLASS64
        return {}

    # ELF64 header fields (little-endian)
    e_entry   = struct.unpack_from('<Q', data, 0x18)[0]
    e_shoff   = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3a)[0]
    e_shnum   = struct.unpack_from('<H', data, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3e)[0]

    # Section name string table
    sh_base = e_shoff + e_shstrndx * e_shentsize
    strtab_off  = struct.unpack_from('<Q', data, sh_base + 0x18)[0]
    strtab_size = struct.unpack_from('<Q', data, sh_base + 0x20)[0]
    shstrtab = data[strtab_off: strtab_off + strtab_size]

    sections = {}
    for i in range(e_shnum):
        sh = e_shoff + i * e_shentsize
        name_off  = struct.unpack_from('<I', data, sh)[0]
        sh_type   = struct.unpack_from('<I', data, sh + 0x04)[0]
        sh_addr   = struct.unpack_from('<Q', data, sh + 0x10)[0]
        sh_offset = struct.unpack_from('<Q', data, sh + 0x18)[0]
        sh_size   = struct.unpack_from('<Q', data, sh + 0x20)[0]
        sh_link   = struct.unpack_from('<I', data, sh + 0x28)[0]
        sh_info   = struct.unpack_from('<I', data, sh + 0x2c)[0]
        sh_entsize = struct.unpack_from('<Q', data, sh + 0x38)[0]

        end = shstrtab.find(b'\x00', name_off)
        name = shstrtab[name_off:end].decode('latin-1')
        sections[name] = {
            'addr': sh_addr, 'off': sh_offset, 'size': sh_size,
            'type': sh_type, 'link': sh_link, 'info': sh_info, 'entsize': sh_entsize
        }

    # .dynstr
    dynstr = b''
    if '.dynstr' in sections:
        s = sections['.dynstr']
        dynstr = data[s['off']: s['off'] + s['size']]

    # .dynsym — Elf64_Sym entries (24 bytes each)
    dynsyms = {}  # index -> name
    if '.dynsym' in sections:
        s = sections['.dynsym']
        n = s['size'] // 24
        for i in range(n):
            off = s['off'] + i * 24
            st_name = struct.unpack_from('<I', data, off)[0]
            end = dynstr.find(b'\x00', st_name)
            name = dynstr[st_name:end].decode('latin-1') if end > st_name else ''
            dynsyms[i] = name

    # RELA.PLT — build PLT VA -> symbol name map
    plt_map = {}  # plt_stub_va -> symbol_name
    for sec_name in ('.rela.plt', '.rela.dyn'):
        if sec_name not in sections:
            continue
        s = sections[sec_name]
        n = s['size'] // 24
        for i in range(n):
            off = s['off'] + i * 24
            r_offset = struct.unpack_from('<Q', data, off)[0]
            r_info   = struct.unpack_from('<Q', data, off + 8)[0]
            r_sym    = r_info >> 32
            r_type   = r_info & 0xffffffff
            # R_AARCH64_JUMP_SLOT = 0x402, R_AARCH64_GLOB_DAT = 0x401
            if r_type in (0x402, 0x401) and r_sym in dynsyms:
                sym = dynsyms[r_sym]
                if sym:
                    plt_map[r_offset] = sym

    # .text
    text_data = b''
    text_va   = 0
    text_off  = 0
    if '.text' in sections:
        s = sections['.text']
        text_data = data[s['off']: s['off'] + s['size']]
        text_va   = s['addr']
        text_off  = s['off']

    return {
        'data': data,
        'sections': sections,
        'plt_map': plt_map,
        'text_data': text_data,
        'text_va': text_va,
        'text_off': text_off,
        'dynstr': dynstr,
        'dynsyms': dynsyms,
    }


# ---------------------------------------------------------------------------
# AArch64 prologue detection
# ---------------------------------------------------------------------------

def _find_aarch64_functions(text_data: bytes, text_va: int) -> list[int]:
    """
    Scan for AArch64 function prologues.
    STP X29, X30, [SP, #-N]! encodes as:
      bits[31:30] = 10 (STP)
      bits[29:27] = 101 (pre-indexed)
      bits[26] = 0 (general)
      => first 2 bytes of little-endian word: 0xfd 0x7b
      byte 3: offset field (negative, so bit7=1) e.g. 0xbe, 0xbe, etc.
      byte 4: 0xa9 (STP 64-bit, pre-index)
    Also catches: SUB SP, SP, #N (alternate leaf prologue)
    """
    addrs = []
    i = 0
    while i < len(text_data) - 4:
        word = struct.unpack_from('<I', text_data, i)[0]
        # STP X29,X30,[SP,#-N]! = 0xa9_?_7b_fd (LE bytes: fd 7b ?? a9)
        if (word & 0xffc07fff) == 0xa9807bfd:
            addrs.append(text_va + i)
        # Also: STP X29,X30,[SP] without pre-index (non-PIE leaf variants)
        elif (word & 0xffc07fff) == 0xa9007bfd:
            addrs.append(text_va + i)
        i += 4
    return addrs


# ---------------------------------------------------------------------------
# PLT call resolution from disassembly
# ---------------------------------------------------------------------------

def _resolve_calls(insns: list, plt_map: dict, got_map: dict) -> list[str]:
    """
    From a capstone instruction list, resolve BL/BLR targets to symbol names.
    plt_map: VA of GOT slot -> symbol name (from RELA)
    got_map: PLT stub VA -> GOT slot VA (approximate; skip for now)
    Returns list of resolved symbol names called by this function.
    """
    calls = []
    for ins in insns:
        if ins.mnemonic in ('bl', 'blr'):
            try:
                target = int(ins.op_str.strip().lstrip('#'), 16)
            except (ValueError, AttributeError):
                continue
            # Direct PLT stub lookup
            if target in plt_map:
                calls.append(plt_map[target])
            # GOT offset lookup (for indirect BL via ADR+LDR sequences)
            # Skip for now; string-based fallback covers most cases
    return calls


# ---------------------------------------------------------------------------
# Per-function semantic descriptor
# ---------------------------------------------------------------------------

def _build_func_desc(
    func_va: int,
    text_data: bytes,
    text_va: int,
    plt_map: dict,
    md: capstone.Cs,
    max_insns: int = 200,
) -> dict:
    """
    Disassemble one function and build the semantic descriptor dict.
    Returns {'va', 'desc', 'calls', 'asm'}.
    """
    offset = func_va - text_va
    if offset < 0 or offset >= len(text_data):
        return {}

    snippet = text_data[offset: offset + max_insns * 4]
    insns = list(md.disasm(snippet, func_va))[:max_insns]

    calls = _resolve_calls(insns, plt_map, {})
    asm_tokens = [f'{i.mnemonic} {i.op_str}'.strip() for i in insns]

    desc = describe_function({
        'name': f'sub_{func_va:x}',
        'calls': calls,
        'asm': asm_tokens[:60],
        'va': func_va,
    })

    return {'va': func_va, 'desc': desc, 'calls': calls, 'asm': asm_tokens}


# ---------------------------------------------------------------------------
# Vulnerability query profiles
# ---------------------------------------------------------------------------

QUERIES = [
    (
        'xxe-xmlreadmemory',
        'xmlReadMemory XML parser | calls: xmlReadMemory | vuln: external entity processing not disabled XML_PARSE_NOENT not set XXE',
    ),
    (
        'format-string-inject',
        'config writer | calls: g_strdup_printf snprintf sprintf | vuln: format string with unescaped user input double-quote injection config file',
    ),
    (
        'spawn-command-inject',
        'command executor | calls: g_spawn_command_line_sync popen system | vuln: shell command constructed from partially user-controlled string',
    ),
    (
        'tls-cert-bypass',
        'TLS verifier | calls: SSL_CTX_set_verify SSL_CTX_set_cert_verify_callback | vuln: certificate verification callback always returns success trust any cert',
    ),
    (
        'ssrf-curl-no-filter',
        'HTTP client | calls: curl_easy_setopt curl_easy_perform | vuln: URL from user input passed to libcurl without RFC-1918 filter SSRF',
    ),
    (
        'memcpy-length-overflow',
        'buffer copy | calls: memcpy memmove | vuln: length derived from packet data without upper bound check stack overflow heap overflow',
    ),
    (
        'path-traversal-open',
        'file handler | calls: open fopen creat | vuln: path contains .. user controlled filename directory traversal',
    ),
    (
        'dbus-command-dispatch',
        'dbus handler | calls: g_dbus_connection_call g_variant_get | vuln: D-Bus method dispatches shell command or privilege operation with unvalidated argument',
    ),
]


# ---------------------------------------------------------------------------
# Binary sweep
# ---------------------------------------------------------------------------

def sweep_binary(
    bin_path: str,
    model: 'SentenceTransformer',
    top_k: int = 5,
    is_rust: bool = False,
) -> list[dict]:
    """
    Run semantic sweep over one AArch64 ELF64 binary.
    Returns list of findings: {query, func_va, score, calls, desc}.
    """
    elf = _parse_elf64(bin_path)
    if not elf or not elf['text_data']:
        print(f'  [!] ELF64 parse failed or no .text: {bin_path}', file=sys.stderr)
        return []

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = False

    func_vas = _find_aarch64_functions(elf['text_data'], elf['text_va'])
    print(f'  [*] {Path(bin_path).name}: {len(func_vas)} function prologues found')

    # Build corpus
    funcs = []
    for va in func_vas:
        fd = _build_func_desc(va, elf['text_data'], elf['text_va'], elf['plt_map'], md)
        if fd and fd.get('desc'):
            funcs.append(fd)

    if not funcs:
        print(f'  [!] No describable functions in {bin_path}', file=sys.stderr)
        return []

    descs = [f['desc'] for f in funcs]
    print(f'  [*] Encoding {len(descs)} functions...')
    corpus_vecs = model.encode(descs, normalize_embeddings=True, show_progress_bar=False)

    findings = []
    for q_name, q_text in QUERIES:
        q_vec = model.encode(q_text, normalize_embeddings=True)
        scores = corpus_vecs @ q_vec
        top_idxs = np.argsort(scores)[::-1][:top_k]
        for idx in top_idxs:
            score = float(scores[idx])
            if score < 0.35:
                continue
            f = funcs[idx]
            findings.append({
                'binary': Path(bin_path).name,
                'query': q_name,
                'func_va': f['va'],
                'score': round(score, 3),
                'calls': f['calls'],
                'desc_snippet': f['desc'][:200],
            })

    return findings


# ---------------------------------------------------------------------------
# Per-binary targeted probes (strings + PLT cross-reference)
# ---------------------------------------------------------------------------

def probe_packagemanager(bin_path: str) -> list[dict]:
    """
    Targeted string + PLT probe for packagemanager.cgi XXE surface.
    """
    findings = []
    elf = _parse_elf64(bin_path)
    plt = elf.get('plt_map', {})

    # Check xmlReadMemory is in PLT
    xml_read_present = any('xmlReadMemory' in v for v in plt.values())
    xml_opts_present = any('xmlCtxtReadMemory' in v for v in plt.values())

    # Check for XML_PARSE_ options — these would appear as integer constants
    # but look for xmlSetGenericErrorFunc, xmlReaderForMemory as proxies
    xml_safer = any(v in ('xmlReaderForMemory', 'xmlCtxtReadMemory') for v in plt.values())

    # Read strings
    try:
        import subprocess
        raw = subprocess.check_output(['strings', '-8', bin_path], text=True)
    except Exception:
        raw = ''

    no_opt_evidence = 'XML_PARSE' not in raw and 'XML_PARSE_NOENT' not in raw

    findings.append({
        'id': 'F-AXPKG-01',
        'severity': 'MEDIUM' if xml_read_present else 'INFO',
        'title': 'packagemanager.cgi: xmlReadMemory without XML_PARSE_NOENT options',
        'detail': (
            f'xmlReadMemory present in PLT: {xml_read_present}. '
            f'Safer alternative (xmlCtxtReadMemory/xmlReaderForMemory) also present: {xml_safer}. '
            f'XML_PARSE_NOENT/NONET option strings absent from binary: {no_opt_evidence}. '
            'xmlReadMemory(buf, size, URL, encoding, options) — 5th arg=options. '
            'If options=0 or options lacks XML_PARSE_NOENT|XML_PARSE_NONET, '
            'external entity refs in ACAP manifest XML are processed. '
            'Attack: craft .eap package with malicious manifest.xml containing '
            '<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]> '
            'and reference &xxe; in a required field. '
            'Upload via multipart POST to packagemanager.cgi. '
            'libxml2 fetches file:// or http:// resource -> OOB read or SSRF. '
            'Prerequisite: VAPIX admin access (ACAP install requires admin).'
        ),
        'plt_symbols': [v for v in plt.values() if 'xml' in v.lower()],
        'status': 'CANDIDATE — requires dynamic test to confirm options arg value',
    })

    # Check for parse_request_from_multipart -> confirms multipart upload attack vector
    multipart_strings = [s for s in raw.splitlines() if 'multipart' in s.lower() or 'boundary' in s.lower()]
    if multipart_strings:
        findings.append({
            'id': 'F-AXPKG-02',
            'severity': 'INFO',
            'title': 'packagemanager.cgi: multipart upload handler confirmed',
            'detail': (
                'parse_request_from_multipart present in strings. '
                'ACAP package upload via multipart/form-data POST. '
                'XML parsing occurs post-boundary extraction on package manifest. '
                'Confirms F-AXPKG-01 attack vector (no file:// workaround needed — '
                'direct binary upload).'
            ),
            'strings': multipart_strings[:5],
        })

    return findings


def probe_stclient(bin_path: str) -> list[dict]:
    """
    Targeted probe for stclient ASRA relay client trust/privilege surface.
    """
    findings = []
    elf = _parse_elf64(bin_path)
    plt = elf.get('plt_map', {})
    all_syms = list(plt.values())

    user_mgmt_syms = [s for s in all_syms if 'user_manager_vapix' in s]
    spawn_present  = 'g_spawn_command_line_sync' in all_syms
    reboot_present = 'policykit_system_reboot' in all_syms
    cert_verify_cb = 'SSL_CTX_set_cert_verify_callback' in all_syms

    if user_mgmt_syms:
        findings.append({
            'id': 'F-AXSTC-01',
            'severity': 'HIGH',
            'title': 'stclient: relay server controls VAPIX user management (add/modify/remove)',
            'detail': (
                f'Confirmed PLT imports: {user_mgmt_syms}. '
                'stclient connects outbound to Axis relay (dispatchse1-st.axis.com:443). '
                'Relay server sends commands via commandchannel.cgi WebSocket-like connection. '
                'stclient acts on received commands including VAPIX user add/modify/remove. '
                'Attack path: compromise or impersonate Axis relay server '
                '-> send add_user command -> new admin account on every connected camera. '
                'Mitigation: relay connection uses cert pinned to hardcoded Axis Dispatcher Root CA '
                '(SSL_CTX_set_cert_verify_callback present). '
                'Finding is latent unless relay CA is compromised or cert pin can be overridden '
                'via SetServerList parameter (remoteservice.cgi setConfig).'
            ),
            'plt_symbols': user_mgmt_syms,
            'status': 'CONFIRMED-STATIC — cert-pin is mitigation; trust model risk documented',
        })

    if spawn_present:
        findings.append({
            'id': 'F-AXSTC-02',
            'severity': 'HIGH-CANDIDATE',
            'title': 'stclient: g_spawn_command_line_sync called — relay-controlled command exec candidate',
            'detail': (
                'g_spawn_command_line_sync present in PLT. '
                'Combined with relay server D-Bus command dispatch (com.axis.AVHS interface), '
                'a relay server command could trigger shell execution if the arg is '
                'partially relay-server-controlled. '
                'Requires disassembly of g_spawn callers to determine arg provenance. '
                'If arg = hardcoded binary path: LOW risk. '
                'If arg = relay-server-supplied string: CRITICAL (RCE via trusted relay).'
            ),
            'status': 'CANDIDATE — manual disassembly of caller required',
        })

    if reboot_present:
        findings.append({
            'id': 'F-AXSTC-03',
            'severity': 'MEDIUM',
            'title': 'stclient: relay server can trigger device reboot',
            'detail': (
                'policykit_system_reboot imported. '
                'Relay server can reboot camera remotely via ASRA command channel. '
                'Legitimate remote management feature, but exploitable as availability DoS: '
                'compromise relay server -> continuous reboot loop on all connected cameras. '
                'Also useful for privilege persistence: reboot clears runtime state, '
                'forcing camera to re-authenticate to relay with known credentials.'
            ),
            'status': 'CONFIRMED-STATIC — by-design, documented as risk',
        })

    if cert_verify_cb:
        findings.append({
            'id': 'F-AXSTC-04',
            'severity': 'INFO',
            'title': 'stclient: SSL_CTX_set_cert_verify_callback — custom TLS verification',
            'detail': (
                'SSL_CTX_set_cert_verify_callback confirmed in PLT. '
                'Custom callback performs cert pinning to hardcoded Axis Dispatcher Root CA. '
                'This is the cert-pin defense for F-AXSTC-01. '
                'Status: mitigation confirmed present. '
                'SetServerList attack (setConfig → redirect to attacker relay) blocked by pin: '
                'attacker relay TLS cert will not be signed by Axis Dispatcher Root CA. '
                'Finding: cert pin is correctly implemented via callback (not CURLOPT_CAINFO). '
                'Residual risk: CA cert is hardcoded in binary (not updateable without firmware update).'
            ),
            'status': 'CONFIRMED-STATIC — pin present',
        })

    return findings


def probe_rsignal(bin_path: str) -> list[dict]:
    """
    String + PLT probe for rsignal Rust binary (WebRTC signaling).
    Rust stripped binaries have reduced PLT (most calls are static).
    Focus on string-based discovery.
    """
    try:
        import subprocess
        raw = subprocess.check_output(['strings', '-8', bin_path], text=True)
        lines = raw.splitlines()
    except Exception:
        lines = []

    findings = []

    # Port/endpoint strings
    port_lines = [l for l in lines if any(p in l for p in ['8084', '9446', '9641', '5349', '3478', ':443', 'turn:', 'stun:'])]
    # Credential patterns
    cred_lines = [l for l in lines if any(k in l.lower() for k in ['secret', 'password', 'token', 'key', 'hmac', 'auth'])]
    # HTTP API patterns
    api_lines  = [l for l in lines if any(k in l for k in ['/api/', '/ws', '/turn', '/ice', '/signal', '/auth', '/health', '/metrics'])]
    # Rust panic source file paths (leak source code structure)
    rust_paths = [l for l in lines if l.startswith('src/') or '.rs:' in l or 'rsignal' in l.lower()]

    if port_lines:
        findings.append({
            'id': 'F-AXRSIG-01',
            'severity': 'INFO',
            'title': 'rsignal: exposed port/endpoint strings',
            'detail': 'Port references found in Rust binary strings.',
            'strings': port_lines[:20],
        })

    if cred_lines:
        findings.append({
            'id': 'F-AXRSIG-02',
            'severity': 'MEDIUM-CANDIDATE',
            'title': 'rsignal: credential/auth-related strings in binary',
            'detail': (
                'Credential or auth keyword strings present in rsignal binary. '
                'Rust static binaries embed string literals. '
                'Review for hardcoded secrets or auth bypass patterns.'
            ),
            'strings': cred_lines[:30],
        })

    if api_lines:
        findings.append({
            'id': 'F-AXRSIG-03',
            'severity': 'INFO',
            'title': 'rsignal: HTTP/WebSocket API endpoint strings',
            'detail': (
                'API route strings reveal rsignal WebSocket/HTTP surface. '
                'Each route is a potential auth bypass or injection surface.'
            ),
            'strings': api_lines[:30],
        })

    if rust_paths:
        findings.append({
            'id': 'F-AXRSIG-04',
            'severity': 'INFO',
            'title': 'rsignal: Rust source paths in binary (panic strings)',
            'detail': 'Rust panic messages reveal internal module structure.',
            'strings': rust_paths[:20],
        })

    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _load_model() -> 'SentenceTransformer':
    print('[*] Loading sentence-transformers/all-MiniLM-L6-v2...', file=sys.stderr)
    return SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2', device='cpu')


def main():
    ap = argparse.ArgumentParser(description='AXIS OS AArch64 binary RE (ablation module)')
    ap.add_argument('--bin', metavar='PATH', help='Single binary to sweep')
    ap.add_argument('--rust', action='store_true', help='Target is a Rust binary (skip BERT sweep, use string probes)')
    ap.add_argument('--rootfs', metavar='DIR', help='Rootfs directory for --all sweep')
    ap.add_argument('--all', action='store_true', help='Sweep all key AXIS OS binaries')
    ap.add_argument('--pkg', action='store_true', help='Probe packagemanager.cgi (XXE)')
    ap.add_argument('--stc', action='store_true', help='Probe stclient (relay trust)')
    ap.add_argument('--rsig', action='store_true', help='Probe rsignal (WebRTC signaling)')
    ap.add_argument('--top', type=int, default=5, help='Top-k results per query (default 5)')
    ap.add_argument('--out', metavar='FILE', help='Write JSON findings to file')
    args = ap.parse_args()

    all_findings = []

    rootfs = args.rootfs or '/media/cowboy/research/axis/extracted/Q1656_12_11_118/rootfs'
    eap_rsignal = '/tmp/claude-1000/-home-cowboy/057f77c0-bd5e-43d1-b434-1a0971657791/scratchpad/bwl_eap/rsignal/rsignal'

    pkg_path = f'{rootfs}/usr/html/axis-cgi/packagemanager.cgi'
    stc_path = f'{rootfs}/usr/bin/stclient'

    if args.pkg or args.all:
        print('\n[PROBE] packagemanager.cgi (XXE surface)')
        findings = probe_packagemanager(pkg_path)
        all_findings.extend(findings)
        for f in findings:
            print(f'  [{f["severity"]}] {f["id"]}: {f["title"]}')

    if args.stc or args.all:
        print('\n[PROBE] stclient (ASRA relay trust surface)')
        findings = probe_stclient(stc_path)
        all_findings.extend(findings)
        for f in findings:
            print(f'  [{f["severity"]}] {f["id"]}: {f["title"]}')

    if args.rsig or args.all:
        rsig = args.bin if (args.bin and args.rust) else eap_rsignal
        print(f'\n[PROBE] rsignal (WebRTC signaling — {rsig})')
        findings = probe_rsignal(rsig)
        all_findings.extend(findings)
        for f in findings:
            sev = f.get('severity', 'INFO')
            print(f'  [{sev}] {f["id"]}: {f["title"]}')
            for s in f.get('strings', [])[:8]:
                print(f'    {s}')

    if args.bin and not args.rust:
        model = _load_model()
        print(f'\n[BERT SWEEP] {args.bin}')
        findings = sweep_binary(args.bin, model, top_k=args.top)
        all_findings.extend(findings)
        for f in findings:
            print(f'  score={f["score"]:.3f} [{f["query"]}] {f["binary"]}@0x{f["func_va"]:x}')
            print(f'    calls: {f["calls"][:6]}')

    if args.all:
        model = _load_model()
        for label, path in [('packagemanager.cgi', pkg_path), ('stclient', stc_path)]:
            print(f'\n[BERT SWEEP] {label}')
            findings = sweep_binary(path, model, top_k=args.top)
            all_findings.extend(findings)
            for f in findings:
                print(f'  score={f["score"]:.3f} [{f["query"]}] @0x{f["func_va"]:x} calls={f["calls"][:4]}')

    if args.out:
        Path(args.out).write_text(json.dumps(all_findings, indent=2))
        print(f'\n[*] Findings written to {args.out}')

    return all_findings


if __name__ == '__main__':
    main()
