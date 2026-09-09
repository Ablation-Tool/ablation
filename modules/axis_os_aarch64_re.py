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
  io/portmanagement.cgi: LINKS libjsoncgi.so.0 (auth-enforcing library — enforces operator+).
    Auth protected. NOT the bypass path. Previous annotation was incorrect.
  io/input.cgi, io/output.cgi, io/port.cgi, io/virtualinput.cgi: all 0-byte stubs.
    TransferProxy: transfer.conf LocationMatch /axis-cgi/io/(input|output|port|virtualinput)\.cgi
      → /var/run/iod/iodsocket (same as /run/iod/iodsocket via /var/run→/run symlink)
    io_cgi.socket: ListenDatagram=/run/iod/iodsocket, SocketGroup=www, SocketMode=0660
      → Apache (www group) can connect; viewer HTTP auth level has no effect on socket access.
    io_cgi daemon (0 APAC refs, no auth strings, no X-Remote-User check):
      Owns com.axis.IOControl.State directly (no conf, no D-Bus intermediary).
      Write handlers: handle-set-state, handle-set-active, handle-set-direction,
        handle-set-enabled, handle-set-name, handle-set-usage, handle-set-virtual.
      Output params: action (set state), active/activelow (HIGH/LOW), close, checkactive.
      No APAC policy entry for io_cgi or com.axis.iocontrol.* in policy.conf.
    Apache: no Require override in LocationMatch block → inherits parent: viewer+.
    FINDING F-AXIO-01 (static analysis): viewer can write physical I/O output state.
      Viewer sends: GET /axis-cgi/io/output.cgi?action=1/ → activates I/O output port.
      VAPIX doc specifies operator-minimum for write; io_cgi enforces NO auth at all.
      Impact: relay-equipped cameras — viewer flips physical relay outputs.
        On door-controller-wired installations: viewer can trigger gate/door release.
        On alarm-wired installations: viewer can trigger false alarm notifications.
    Report: /home/cowboy/VDT/axis-os-re/bugcrowd-F-AXIO-01.md
  virtualinput/activate.cgi, virtualinput/deactivate.cgi: SHELL SCRIPTS — NOT stubs.
    Path: /usr/html/axis-cgi/virtualinput/activate.cgi
    → calls gdbus call -y -d com.axis.VirtualInput -o /com/axis/VirtualInput/Port/$port -m Activate
    virtualinputd: 0 APAC refs.
    D-Bus: NO com.axis.VirtualInput*.conf in /usr/share/dbus-1/system.d/
      Without a conf, D-Bus system bus default policy applies: DENY send to unregistered names.
      gdbus call from suexec'd www user (wwwv) would be REJECTED at D-Bus layer.
    Apache: no Location/Directory override → viewer+, but D-Bus access denied anyway.
    NO TransferProxy coverage (transfer.conf has io/virtualinput.cgi, not virtualinput/).
    FINDING F-AXVINPUT-01: D-Bus policy UNCERTAIN — no conf; call may fail at bus layer.
      Live verification required before filing. Current status: UNCONFIRMED.
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
  overlaywidget/overlaywidget.cgi: 0-byte stub.
    widgetd_transfer.conf: <LocationMatch "/axis-cgi/overlaywidget/\w+\.cgi">
      TransferProxy /run/widgetd/transfer (no auth directive, inherits viewer+).
    widgetd.socket: SocketGroup=www, SocketMode=0660 — Apache can connect.
    widgetd (/usr/bin/widgetd): 0 APAC refs. Write ops: addWidget, axo_create_overlay,
      axo_adjust_overlay, axo_props_set_anchor_point, axo_props_set_is_background_overlay.
      Also calls com.axis.GeoLocation1, com.axis.PrioritizedTextOverlay, com.axis.PTZ.Coordinator
      to populate widget data — these are READ-only calls from widgetd.
    FINDING F-AXWIDGET-01 (static analysis): viewer can add/modify data visualization widgets
      as video overlays (geolocation data widgets, graphs, etc.) without operator auth.
      APAC policy: widgetd: com.axis.overlay2.* / com.axis.graphics2.* -- blanket write access.
      Identity-launder: viewer HTTP -> widgetd (www socket) -> overlay2/graphics2 as widgetd identity.
      com.axis.Overlay2.conf / com.axis.Graphics2.conf: context=default OPEN at bus layer.
      APAC inside overlay2d sees widgetd identity -- grants all com.axis.overlay2.* methods.
      Write ops reach AXIS Overlay2 service (video stream graphics layer) at viewer level.
      Impact: viewer injects overlay graphics, graphs, position data into all camera streams.
      Variations: SkLineGraphWidget (graph), WidgetCompositionSurface (composite), axo_create_overlay.
  ledcontrol/: all CGIs are 0-byte stubs (getleds.cgi, getschemaversions.cgi, getstatus.cgi, set.cgi, stop.cgi).
    transfer.conf: <LocationMatch "/axis-cgi/ledcontrol/\w+\.cgi">
      TransferProxy /var/run/blinkenlights/transfer (no auth directive, inherits viewer+).
    led-controller-cgi.socket: ListenDatagram=/run/blinkenlights/transfer,
      SocketMode=0660, SocketGroup=www -- Apache (www group) can connect.
    blinkenlights (/usr/bin/blinkenlights): 0 APAC refs.
      IS the LED controller daemon directly (no CGI intermediary).
      Owns D-Bus name com.axis.LEDController; calls com.axis.Configuration.Legacy.
      D-Bus introspection XML embedded: color, set (as, i direction=in), BootColor, ColorName args.
      accessControl XML embedded: admin:3 and admin:3;operator:1 -- legacy config METADATA only.
      No auth header reading: 0 strings matching http_user, REMOTE_USER, X-Remote, auth_info.
      No enforcement mechanism: binary has no mechanism to identify HTTP caller role.
      setuid/setgid called at startup for privilege drop (daemon init only, not per-request auth).
      write ops: color set, flash effect (bwc-front-indicator-flash), BootColor config, stop sequence.
    Apache: no Require override in LocationMatch block -- inherits parent: viewer+.
    FINDING F-AXLED-01 (static analysis): viewer can control camera LED state without operator auth.
      Viewer calls /axis-cgi/ledcontrol/set.cgi to set LED color, flash effects, status sequences.
      VAPIX doc specifies operator-minimum for LED control; blinkenlights enforces no auth.
      Impact: viewer changes camera status LED color (green/red/amber/off), triggers flash patterns,
        modifies IR illumination boot behavior. Physical indicator manipulation visible on device.
      Root: blinkenlights is the production LED daemon; TransferProxy gives Apache direct socket
        access; daemon has accessControl metadata but no reader for HTTP user identity.
  airquality/: all CGIs are 0-byte stubs (config.cgi, download.cgi, metadata.cgi, statistics.cgi, status.cgi).
    airqualityd_transfer.conf: <LocationMatch "/axis-cgi/airquality/\w+\.cgi">
      TransferProxy /run/airqualityd/transfer (no auth directive, inherits viewer+).
    airqualityd.socket: SocketGroup=www, SocketMode=0660 -- Apache can connect.
    airqualityd (/usr/bin/airqualityd): 0 APAC refs.
      Auth strings PRESENT: HTTP/1.0 401 Unauthorized, <h1>Unauthorized</h1>,
        <title>401 Unauthorized</title>, Forbidden permission response,
        http_user_realms, Administrator, Operator, Viewer.
      Self-enforcing: reads http_user_realms CGI env var, returns 401/403 on privilege gap.
    F-AXAIRQ-01 REFUTED: airqualityd is self-enforcing at HTTP layer.
      Socket accessible from Apache but daemon blocks unauthorized callers.
      NOT a bypass. NOT filed.
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
  tcptest.cgi: shell script, no auth library, no Apache override (viewer+).
    Accepts address + port parameters. Calls validateaddr (blocks 127.x.x.x only,
    no RFC1918 check) then /usr/bin/tcptest to make TCP connection to arbitrary host:port.
    Returns "Test successful." on open port; error text on closed/filtered.
    FINDING (part of F-AXNETPROBE-01): viewer-level TCP port scan oracle.
  ftptest.cgi: shell script, no auth library, no Apache override (viewer+).
    Accepts address, proto (ftp/sftp), port, username, password, uploadpath parameters.
    Calls validateaddr then curl to upload /tmp/.test.XXXXXX file to arbitrary FTP/SFTP server.
    Creates file from camera's IP to viewer-supplied FTP host using viewer-supplied credentials.
    SFTP mode accepts publickeyfp/publickeysha256 host key bypass.
    FINDING (part of F-AXNETPROBE-01): viewer-level FTP SSRF / credential probe.
  pingtest.cgi: shell script, no auth library, no Apache override (viewer+).
    Accepts ip parameter with NO validateaddr call (no localhost check either).
    Executes /usr/bin/ping "$ip" directly. Returns "got response" or "no response".
    FINDING (part of F-AXNETPROBE-01): viewer-level ICMP host discovery probe.
    NOTE: pingtest.cgi has no validateaddr call — unique among the *test.cgi set.
  F-AXNETPROBE-01: consolidated — viewer operates 5-protocol probe suite from camera:
    httptest (HTTP), smtptest (SMTP), tcptest (TCP), ftptest (FTP/SFTP), pingtest (ICMP).
    All inherit viewer+ default auth; all use validateaddr's localhost-only check (except ping).
    No RFC1918 blocking. Camera's privileged network position (management VLAN, OT) exposed.
    Report: /home/cowboy/VDT/axis-os-re/bugcrowd-F-AXNETPROBE-01.md
  axis-cgi/audio/level.cgi: AArch64 ELF (39,000 bytes), source audio-level-cgi/1.0.3/src/main.c.
    No auth library (no libaxcgijson.so, libcgiparser.so, libjsoncgi.so.0).
    No Apache Require override — inherits parent directory default: Require axis-group-file (viewer+).
    Connects to PipeWire audio subsystem directly via pw_main_loop_*, g_bus_get_sync NOT called —
      bypasses D-Bus/APAC enforcement chain entirely. Third distinct bypass pattern:
      (1) TransferProxy-no-APAC, (2) shell-no-validateaddr, (3) raw-PipeWire-no-auth.
    Parameters: audioinputid, audiodeviceid, format.
    Output: multipart JavaScript stream: window.parent.update(peak, ..., channels[])
      encoding peak dBFS per channel in real-time. Output also supports raw channel array.
    audio/receive.cgi and audio/transmit.cgi: 0-byte stubs; served via TransferProxy
      (transfer.conf LocationMatch); real handler is in downstream daemon.
    audio/streamingcapabilities.cgi: libcgiparser.so, no override, calls com.axis.Audio1
      (D-Bus context=default open) + com.axis.AudioControl (group=operator restricted at bus).
      Read-only capabilities query; AudioControl writes blocked at bus layer. Not a finding.
    audiomixer.cgi: calls com.axis.AudioMixer2/AudioMixer. AudioMixer D-Bus policy:
      context=default DENY; only operator/audiomixer/actionengined groups allowed. Not a finding.
    FINDING F-AXAUDIO-01 (static analysis): viewer-level real-time audio level monitoring.
      Viewer retrieves live peak dBFS readings from camera microphone(s) without operator auth.
      Can enumerate multiple audio inputs via audioinputid parameter.
      Reveals audio presence/activity in camera surveillance zone (speech, motion sound detection).
      VAPIX specification requires operator privilege for audio monitoring configuration.
      Impact: viewer detects audio activity in secured area; audio-level oracle for surveillance bypass.
    Report: /home/cowboy/VDT/axis-os-re/bugcrowd-F-AXAUDIO-01.md

#   axis-cgi/straightenimage/: All CGIs are 0-byte stubs served via TransferProxy to
#     /run/straightenimage-cgi/transfer. No Apache auth override in any conf.
#     TransferProxy target: straightenimage-cgi daemon (User=straightenimage-cgi).
#     Socket unit: SocketGroup=www, SocketMode=0660 — any Apache process (www group) can connect.
#     Apache auth: inherits parent directory default (viewer+).
#     straightenimage-cgi binary: 0 APAC refs. No auth check before D-Bus forwarding.
#     D-Bus target: com.axis.StraightenImage (straightenimage_dbus.conf context=default OPEN;
#       comment: "Authorization is done inside the service using APAC").
#     Main daemon: straightenimage (5 APAC refs, enforces APAC). BUT caller identity seen by
#       APAC is straightenimage-cgi (the daemon's OS user), not the HTTP user (wwwv/wwwo/wwwa).
#     APAC policy: straightenimage-cgi: com.axis.straightenimage.* — blanket access to all methods.
#     APAC policy: com.axis.horizonstraightening.write.enabled is in wwwa (admin) section.
#     Bypass: viewer HTTP request → TransferProxy (www group socket) → straightenimage-cgi
#       (0 APAC, runs as daemon user) → calls com.axis.StraightenImage as privileged process →
#       APAC grants blanket access to straightenimage-cgi process identity → operation executes.
#     Write operations accessible to viewer:
#       enable.cgi    — enables horizon straightening
#       disable.cgi   — disables horizon straightening
#       autoadjust.cgi   — auto-adjusts horizon from accelerometer
#       manualadjust.cgi — manually sets horizon angle (angle param)
#       restart.cgi   — restarts straightening service
#     FINDING F-AXSTRAIGHT-01 (static analysis): viewer-level image straightening write ops.
#       Viewer can enable/disable/adjust the camera's horizon correction without operator auth.
#       APAC policy explicitly restricts horizonstraightening.write to admin; daemon has 5 APAC
#       refs but caller identity laundering via straightenimage-cgi intermediary bypasses check.
#       Pattern: same class as F-AXMASK-01 (TransferProxy + no-APAC CGI daemon + www socket).
#       Impact: viewer distorts camera's recorded image by disabling/adjusting horizon correction;
#         video surveillance integrity compromised without physical access.
#     Report: /home/cowboy/VDT/axis-os-re/bugcrowd-F-AXSTRAIGHT-01.md

#   customhttpheader.cgi (22808 bytes): No auth library (libaxcgijson/libcgiparser/libjsoncgi all absent).
#     No Apache auth override: grep of /etc/apache2/ for customhttpheader returns nothing.
#     Links libcgihelper.so (CGI parsing utility — no auth enforcement; exports cgi_request_parse,
#       cgi_response_print only; no operator/admin/viewer/401/403 strings in library).
#     Links libpolicykit_system.so.7 — calls only policykit_system_reload_service (privilege
#       escalation to reload Apache after write), NOT policykit_system_check_auth (auth gate).
#     Reads http_user, http_user_realms CGI env vars — used for logging ("%s: running as: %s")
#       NOT for enforcement: binary has no 401/403/Unauthorized/Forbidden output strings.
#     Operation: reads/writes /etc/httpconf/customheader.conf via g_key_file_* GLib functions.
#       Supports methods: list, remove, remove_custom_headers. Direct file write, no D-Bus.
#     customheader.conf default content (the file being writable):
#       0=X-Content-Type-Options:nosniff
#       1=X-Frame-Options:SAMEORIGIN
#       2=X-XSS-Protection:1; mode=block
#       3=Content-Security-Policy:default-src 'self'; frame-ancestors 'self'; ... (full CSP)
#       4=Referrer-Policy:strict-origin-when-cross-origin
#     These are the browser security headers Apache injects into all camera HTTP responses.
#     POST body: JSON {"method":"remove","params":{"customheaders":["3"]}} removes CSP by index.
#     After write, policykit_system_reload_service reloads Apache — changes take effect immediately.
#     FINDING F-AXCUSTHDR-01 (static analysis): viewer can remove browser security headers.
#       Viewer can DELETE CSP, X-Frame-Options, X-XSS-Protection, Referrer-Policy from all
#       camera HTTP responses. After reload:
#         - No CSP: stored XSS in admin web UI becomes exploitable cross-origin
#         - No X-Frame-Options: clickjacking against admin login frame
#         - No X-Content-Type-Options: MIME-type confusion attacks
#       Viewer can also ADD arbitrary custom headers (e.g. Access-Control-Allow-Origin: *)
#         to enable cross-origin data exfiltration of camera APIs from attacker-controlled page.
#       No chain required: viewer deletes CSP, then any stored XSS (if present) in admin UI
#         executes. Standalone: viewer weakens camera HTTP security posture without admin auth.
#       Auth gap: libcgihelper.so provides no auth enforcement; polkit call is reload-only.

#   auditlog.cgi (14344 bytes): Self-enforcing via getegid() / getgrnam("admin") OS-level group
#     check. Suexec sets process EGID = authenticated HTTP user's primary group GID. Viewer (wwwv)
#     EGID = viewer GID (103) ≠ admin GID (101) → "Only an admin can access the audit logs."
#     No Apache override needed; the OS-level group check is the enforcement. NOT a finding.

#   trafficcamerainstallation.cgi (453048 bytes): Has Status: 401 Unauthorized / Status: 403
#     Forbidden strings — self-enforcing. Also has admin/viewer strings for role check. NOT a finding.

#   networkspeakerpairing.cgi (35104 bytes): 0 APAC refs. No Apache override. BUT:
#     com.axis.NetworkSpeakerPairing.conf D-Bus policy: <policy group="admin"> only — no
#     context="default" open. System bus default denies wwwv/wwwo method calls to this service.
#     D-Bus DENY at bus layer for viewer/operator. NOT a finding.

#   deviceselftest.cgi: Status: 401 Unauthorized string — self-enforcing. NOT a finding.

#   serverreport.cgi (shell script): No auth enforcement — no Apache override, no group check,
#     no REMOTE_USER test. Sources lib/functions.sh (__whoami returns script name, not HTTP user).
#     Inherits parent dir default: Require axis-group-file (viewer+).
#     httpd-auth-preview-mode.conf sets axis-preview-mode-allowed for preview mode (separate gate).
#     For authenticated normal mode: viewer can invoke all serverreport modes.
#     Modes and data collected:
#       text (default): calls /usr/sbin/gen_serverreport.sh → outputs full server diagnostic:
#         product name (parhandclient Brand.ProdFullName), serial number (bootblocktool SERNO),
#         processor serial (/sys/devices/soc0/serial_number), device time (TimeService1 D-Bus),
#         action engine configs (find /usr/local/ -type f → XML + conf), network config,
#         firmware version, installed packages, running services, memory status.
#         gen_serverreport.sh censors password fields but collects all configuration.
#       zip: same as text + packages as ZIP archive with filename Axis_SR_<date>_<MAC>
#       zip_with_image: same + live JPEG snapshot from jpeg_snapshot binary
#       tar_all: merge_logs_in_dir for /usr/local/, /var/lib/syslog-ng/, /var/log/ →
#         includes ALL rotated logs: info.log*, warning.log*, error.log*, critical.log*,
#         segfault.log*; audit.json (find … -name "audit.json") explicitly collected.
#         Also: syslog.complete, syslog.startup, messages, persist-all.log, dmesg.startup,
#         /mnt/flash/messages, memory_status.csv. Archived as tar with full content.
#       tar_kernel_log: primary + secondary kernel logs via /usr/bin/klog, secondary-klog.
#     gen_serverreport.sh (2296 lines) data inventory — confirmed via static read:
#       Hardware identity: product name, serial (bootblocktool SERNO), processor serial
#         (/sys/devices/soc0/serial_number), board info, DRAM info, MAC (zip filename).
#       Runtime state: uptime, boot count, reboot count (UsageStatistics1 D-Bus),
#         firmware history (/lib/persistent/var/lib/system/system-status/fwhistory),
#         memory cgroup peaks (system/services/acap slices).
#       System logs (all rotated): /var/log/info.log*, warning.log*, error.log*,
#         critical.log*, segfault.log*, /var/lib/syslog-ng/syslog.log*.
#       Access log: /var/log/auth.log* — authentication events.
#       Audit log: /var/lib/syslog-ng/audit.log* — security event records.
#       Kernel logs: klog (primary), secondary-klog, pstore console-ramoops-0 (previous
#         kernel log), dmesg-ramoops-0 (kernel crash log), bootloader log.
#       Full Axis Parameter List: parhandclient --maskpasswords getgroup root - NAMEVALUESECTIONS
#         dumps ENTIRE root.* namespace — network config, event rules, stream profiles,
#         SMTP settings, PTZ positions, all service params. Passwords masked; all else exposed.
#       VAPIX user list: UserManagement1.Vapix.ListUsers — full list of VAPIX accounts
#         with usernames AND roles (viewer/operator/admin). Complete credential target list.
#       ONVIF user list: UserManagement1.System.ListOnvifUsers — all ONVIF accounts + roles.
#       Installed certificates: PolicyKitCert.ListInstalledCerts — cert ID, CN, filename,
#         keystore for every installed TLS certificate.
#       Certificate sets: PolicyKitCert.ListInstalledCertSets — set IDs and assigned cert IDs.
#       Straightenimage config: /etc/straightenimage/straightenimage.conf (if present).
#       Remote camera control connections.
#       Audio + stream cache snapshots (active stream routing state).
#     FINDING F-AXSRVRPT-01 (static analysis): viewer-level server diagnostic report access.
#       Viewer downloads full diagnostic bundle including device serial, MAC, network config,
#       complete VAPIX user list (usernames + roles), complete ONVIF user list,
#       all installed TLS certificate CNs, full parameter namespace (passwords masked),
#       all system logs, access log (auth events), audit log, kernel logs and crash dumps,
#       and — via tar_all — audit.json (the same file that auditlog.cgi properly protects
#       with admin-only getegid/getgrnam check).
#       VAPIX user enumeration is the highest-impact item: viewer extracts all account names
#       and privilege levels, enabling targeted credential attacks against admin/operator accounts.
#       VAPIX documentation specifies serverreport.cgi requires operator privilege minimum.
#       Pattern: no auth library, no Apache override → viewer+ default inherited.
#       zip_with_image mode also triggers live JPEG snapshot at viewer level.

#   systemlog.cgi (shell script): No auth enforcement — no Apache override, no group check.
#     No Require directive found in any conf for /axis-cgi/systemlog.cgi.
#     Sources admin/lib/systemlog.sh (log-reading utility, no auth) and
#       admin/lib/adp.sh (path setup, logger wrappers only — no auth).
#     Reads from /var/log/info.log*, /var/log/warning.log*, /var/log/error.log*,
#       /var/log/critical.log*, /var/log/segfault.log* — all rotated log files.
#     Accepts params: format=text|html, tail=N, appname=<name>, search_txt=<query>.
#     __check_arbitrary_args enforces only allowed param names — not auth levels.
#     FINDING F-AXSYSLOG-01 (static analysis): viewer-level system log access.
#       Viewer reads AXIS system log (all severity levels) at viewer level.
#       Logs include authentication events, service start/stop, configuration changes,
#       error traces, segfault records. VAPIX specifies operator+ for log endpoints.
#       Pattern: shell script CGI with no auth, no override → viewer+ inherited.
#       Impact: viewer maps system events, tracks admin activity, reads error traces.

#   remoteservice.cgi (22544 bytes ELF): uses libpolicykit_parhand.so.1 for param access.
#     Methods: getConfig (reads RemoteService.* params), setConfig, getProxy, setProxy.
#     Params: root.RemoteService.{Enabled,ServerList,ProxyServer,ProxyPort,ProxyLogin,
#       ProxyPassword,DSCP,BackOffFactorMin/Span,BackOffMaxSec,TimeSyncEnabled}.
#     policykit_parhand APAC model: anonymous (unlisted) → getparameter only; setparameter
#       requires explicit daemon entry — wwwv not listed → set calls DENIED by APAC.
#     getProxy returns ProxyLogin/Server/Port but NOT ProxyPassword (write-only type).
#     Result: viewer can READ non-credential remote service config; cannot SET. Not filed.

  param.cgi: viewer-readable params include only boolean/status fields (System.RootPwdSet,
    System.CaptureModeSet). Sensitive params (RemoteService, WebService.UsernameToken): admin:3 only.
    ProxyPassword: type="password:writeonly" — even admin cannot read it back.
  paramlist.cgi: shell script (987 bytes). No Apache override, no auth library, no group check.
    Dumps: /usr/share/axis-release/variables then parhandclient getgroup root - NAMEVALUESECTIONS
    or NAMEVALUE (depending on ?sections param). Full root.* namespace except password fields
    (masked via sed regex: passwd=, Password=, Pass=, Passphrase=, Key1-4=). Includes:
    network config, SMTP settings, event rules, stream profiles, PTZ positions, service params.
    FINDING F-AXPARAMLIST-01 (static analysis): viewer-level full parameter namespace dump.
      Viewer queries ?sections=sections to get full root.* parameter tree with section headings.
      Passwords masked; all other config values exposed including: network interface config,
      DNS/NTP servers, SMTP server/auth config, event rule parameters, stream profile names.
      This is the same data as F-AXSRVRPT-01's "Axis Parameter List" section, but as a
      direct targeted endpoint without the overhead of a full server report.
      Pattern: legacy shell script CGI, no Require override, viewer+ inherited.
  clientnotes/set.cgi: stores group/key/value in /etc/clientnotes/data.conf (GLib keyfile).
    Default viewer access. No path traversal (g_key_file_set_string escapes). Not filed.
  shuttergain.cgi (43160 bytes): calls com.axis.ShuttergainControl — D-Bus context="default" open.
    No Apache override (grep of /etc/apache2/ for shuttergain: 0 results). Default: viewer+.
    CGI enforcements: (1) Content-Type: must be application/json (Rejected: invalid content type);
      (2) Sec-Fetch-Site: same-origin check (Rejected: cross-origin request). NO privilege check.
    Enforcements in CGI: CORS/content-type only. REMOTE_USER/REMOTE_ADDR/REMOTE_PORT used for
      audit logging only: "API Activity: %s@%s%s%s:%s updated shuttergain.%s (%s)."
    shuttergaind daemon: 0 APAC refs. Shuttergaind.conf: context="default" allow send_destination.
    APAC policy: 0 entries for com.axis.shuttergaincontrol.*.
    Write operations: setShutter (shutter speed), setGain (ISO/sensor gain).
    FINDING F-AXSHUTTERGAIN-01 (static analysis): viewer-level exposure control write.
      Viewer can set camera shutter speed and gain via shuttergain.cgi setShutter/setGain.
      VAPIX specifies operator minimum for exposure parameter writes.
      No privilege check in CGI (CORS/content-type only); no APAC in daemon; D-Bus open.
      Impact: viewer can over-expose or under-expose camera image (max gain = sensor noise;
        min shutter = motion blur; strobe attack: rapid shutter cycling disrupts capture).
        Changes are persistent until operator resets. Affects all stream consumers.
      Bypass: CORS check (Sec-Fetch-Site) bypassed by direct curl (browser header, not API).
  lightcontrol.cgi (39008 bytes): links libaxcgijson.so — NEGATIVE. Operator-minimum enforced.
  irissetup.cgi (shell script): $(id -nG | grep -qw admin) || __cgi_errhd 403 — admin-only.
    NEGATIVE. OS group check in script body.
  image_stabilization.cgi (92360 bytes): 2 auth strings — self-enforcing. NEGATIVE.
  regionalsettings.cgi (14352 bytes): 0 auth strings, calls com.axis.RegionalSettings1.
    D-Bus (RegionalSettings1.conf): context="default" allow — bus layer open.
    regional-settingsd daemon: apac_check_auth/apac_init/libapac.so.0 present (APAC v1, SO_PEERCRED).
    APAC policy: setconfiguration in wwwa,...,wwwo,wwwop,wwwov,wwwovp section (operator minimum).
    Viewer (wwwv) not in any settconfiguration section → APAC DENIES. NEGATIVE.
  temperaturecontrol.cgi (0-byte stub): TransferProxy to /var/run/temperature_ctrld/transfer.
    temperature_ctrld: apac_check_auth present (APAC v1). All temp operations (setpowerconsumer,
    getpowerconsumers, resetpowerconsumer) in wwwa,...,wwwav (admin minimum) APAC section.
    NEGATIVE. APAC denies viewer and operator calls.
  streamstatus.cgi (26752 bytes): 0 auth strings. Calls com.axis.Streamer, JpegStreamer1,
    HTTPStreamProperties, MediaCGI1, VdoStreamInfo. READ-only stream status query.
    No Apache override. Viewer+ by default. Not filed (read-only, expected viewer access).
  power-settings.cgi (51296 bytes): links libaxcgijson.so — NEGATIVE. Operator-minimum enforced.
  mqtt/client.cgi, mqtt/event.cgi (195KB, 191KB): 6 auth strings each — self-enforcing. NEGATIVE.
  basicdeviceinfo.cgi (22656 bytes): 3 auth strings — self-enforcing. NEGATIVE.
  pwdgrp.cgi (30888 bytes): 7 auth strings — self-enforcing password management. NEGATIVE.
  ssh.cgi (10320 bytes): 1 auth string — self-enforcing. NEGATIVE.
  usergroup.cgi (shell script, 193 bytes): returns $REMOTE_USER and $USER_GROUPS for calling HTTP
    user. Reflects the requesting user's own identity/groups. NOT a privilege escalation; intended
    viewer-accessible for UI session display. Not filed.
  viewarea/configure.cgi: links libaxcgijson.so — NEGATIVE. Operator-minimum enforced.
  viewarea/info.cgi: 2 auth strings — self-enforcing. NEGATIVE.
  ptz/cookietest.cgi (14344 bytes): "Operator" string + vapix_get_param_int + user_group check
    — self-enforcing via OS group check. NEGATIVE.
  ptz/ptzsetactivedrivermode.cgi (shell script, 7452 bytes): no auth strings, no admin/operator
    check found. Changes PTZ driver mode config files. Auth level TBD pending further analysis.
  shockdetection/ (all 0-byte stubs): TransferProxy to /var/run/posd/transfer.
    posd binary: apac_check_auth present. BUT no posd.socket file found in systemd — posd creates
    socket itself. Without SocketGroup=www in a socket unit, socket permissions depend on posd's
    umask/explicit chmod. If socket is not www-accessible, TransferProxy fails at connection layer.
    Shock APAC policy: no direct shock detection entries in any www* section found.
    Status: UNCERTAIN — socket accessibility unresolved without live device test.
  applications/upload.cgi: ACAP install via AcapManager1.Install — NEGATIVE.
    gdbus call to com.axis.AcapManager1.Install with caller_info=(user,addr,port) audit arg.
    D-Bus policy (acapmanager.conf): context="default" allow (bus layer open).
    APAC inside AcapManager1: install action is in wwwa section (admin minimum, line 681).
    apac2_check_username validates HTTP username from forwarded CGI env (not SO_PEERCRED).
    Caller_info argument is audit logging only — not bypassing auth.
    Applications/control.cgi (start/stop/uninstall): start/stop = operator min (line 820);
      uninstall = admin min (line 688). APAC enforced. NOT a bypass.
    Applications/config.cgi (SetAllowUnsigned): admin section only (lines 760-763). NEGATIVE.
  secure_boot/custfwcerts.cgi: installCertificate/removeCertificate — NEGATIVE.
    D-Bus: com.axis.CustomFirmwareCertificates1 in fwmgr.conf.
    fwmgr.conf policy: only user="root" and group="admin" allowed — NO context="default".
    www user (wwwv/wwwo) DENIED at D-Bus bus layer for all CustomFirmwareCertificates1 calls.
    Apache path: /secure_boot/ — no special Apache auth override found but D-Bus gate sufficient.

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
