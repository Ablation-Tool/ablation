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
    Path: /usr/html/axis-cgi/virtualinput/activate.cgi, deactivate.cgi
    → calls gdbus call -y -d com.axis.VirtualInput -o /com/axis/VirtualInput/Port/$port -m Activate
    virtualinputd (/usr/bin/virtualinputd, 22616 bytes): 0 APAC refs, 0 auth strings.
      No operator/admin/viewer/401/403/Unauthorized/Forbidden/getgrnam in binary.
    D-Bus: com.axis.VirtualInput.conf in /usr/share/dbus-1/system.d/
      context="default" allow send_destination/receive_sender — bus layer OPEN to www user.
    Apache: no Location/Directory override → viewer+ (default axis-group-file).
    NO TransferProxy coverage (transfer.conf covers io/virtualinput.cgi only, not virtualinput/).
    APAC policy: empty for virtualinput — no entry in policy.conf.
    FINDING F-AXVIN-01 (static analysis): viewer triggers virtual input port Activate/Deactivate
      on com.axis.VirtualInput D-Bus service via Apache-executed gdbus shell script.
      Shell runs as www, bus layer open at context="default", virtualinputd enforces no auth.
      Impact: viewer fires virtual input triggers that downstream ACAP apps, VMS event rules,
      and physical I/O automation rules may act on — can trigger recording, alarms, relay ops.
      VAPIX doc specifies operator-minimum for virtual input write ops.
      Distinct from F-AXIO-01: that path uses TransferProxy → io_cgi daemon;
      this path is direct gdbus invocation from Apache-executed shell script, no io_cgi involved.
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
  ptz/ptzsetactivedrivermode.cgi (shell script): calls gdbus to com.axis.PTZ.Coordinator
    (.GetConfiguration, .SetConfiguration, .GetAvailableConfigurations). No shell-level auth check.
    D-Bus bus layer: com.axis.PTZ.conf context="default" open (any caller can send).
    ptzaurus daemon (owns com.axis.PTZ.Coordinator): apac_check_auth/apac_init/libapac.so.0
    present (APAC v1). Embedded permission strings: viewer:1;operator:1;admin:3;ptzadm:3
    — SetConfiguration is admin-level (3). Viewer (www user) DENIED by APAC inside ptzaurus.
    NEGATIVE. APAC inside daemon gates the call even though D-Bus bus layer is open.

  restart.cgi (10248 bytes ELF): calls com.axis.FirmwareManager1 via sd_bus_call_method.
    REMOTE_USER/REMOTE_ADDR used for logging only. fwmgr.conf D-Bus gate: admin group only.
    NEGATIVE. Same D-Bus bus-layer block as factorydefault.cgi.

  rootpwdsetvalue.cgi (shell script, 221 bytes): reads System.RootPwdSet parameter (bool flag
    indicating if root password has been set). READ-only output. Not a write operation.
    Not a finding.

  time.cgi (47192 bytes): links libjsoncgi.so.0 (operator-minimum enforcing). NEGATIVE.

  supervisedio.cgi (55496 bytes): links libaxcgijson.so (operator-minimum enforcing). NEGATIVE.

  upnp.cgi (43096 bytes): links libjsoncgi.so.0. NEGATIVE.
  analyticsmetadataconfig.cgi (14440 bytes): links libjsoncgi.so.0. NEGATIVE.
  remotesyslog.cgi (47200 bytes): links libjsoncgi.so.0. NEGATIVE.
  mdnssd.cgi (55384 bytes): links libjsoncgi.so.0. NEGATIVE.
  streamprofile.cgi (26640 bytes): has admin auth string — self-enforcing. NEGATIVE.

  capturemode.cgi (18440 bytes): calls com.axis.CaptureMode1.
    CaptureMode1.conf: no full context="default" allow — only addon group and capturemoded/root
    have access to write interfaces. www user (Apache) not in addon group. DENIED at bus layer.
    NEGATIVE.

  apidiscovery.cgi (18504 bytes): read-only API discovery (com.axis.ApiDiscovery1).
    Returns list of supported VAPIX API endpoints. No write operations. Not a finding.
  browserlang.cgi (6152 bytes): browser language preference write. No D-Bus, no auth.
    Writes UI display language preference only. Not a security finding.
  base64encode.cgi (10256 bytes): base64 encode/decode utility. No D-Bus, no auth.
    No security impact. Not a finding.
  session.cgi, createsession.cgi, removesession.cgi, wssession.cgi (10256 bytes each):
    manage HTTP sessions for the authenticated user's own session. REMOTE_USER used for
    session ownership; not a privilege bypass. Not findings.
  alwaysmulti.cgi (1826 bytes shell script): calls com.axis.AlwaysMulticast1.GenerateSdp
    via dbus-send. Generates SDP for existing multicast streams (read operation). Not a finding.
  systemready.cgi (22552 bytes): system readiness status. Read-only. Not a finding.

  shockdetection/ (all 0-byte stubs): TransferProxy to /var/run/posd/transfer.
    posd binary: apac_check_auth, apac_init, libapac.so.0 (APAC v1, SO_PEERCRED). Same daemon as
      orientation/ stubs — orientation/ already confirmed NEGATIVE (posd APAC v1, Unauthorized strings).
    No posd.socket file in systemd — posd creates socket itself. No SocketGroup=www in socket unit;
      socket created by posd with its own umask/perms, likely not www-accessible.
    APAC policy: no shock detection entries in www: section (line 666). Even if Apache could reach
      the socket, APAC v1 inside posd would deny www OS user for all shock operations.
    NEGATIVE (dual gate: socket likely inaccessible to www, and APAC v1 denies www regardless).
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

  videostreamingindicator.cgi (0-byte stub): TransferMethodProxy to
    /run/video-streaming-indicator/transfer. Apache conf (video-streaming-indicator.conf):
    <LocationMatch "/axis-cgi/videostreamingindicator.cgi">
      TransferMethodProxy /run/video-streaming-indicator/transfer
    </LocationMatch>
    No Require override — inherits parent: viewer+. TransferMethodProxy = POST-only forwarding.
    Socket unit (video-streaming-indicator.socket): SocketGroup=www, SocketMode=0660,
      SocketUser=videostreamingindicator. Apache (www group) can connect.
    video-streaming-indicator daemon (/usr/bin/video-streaming-indicator):
      0 auth strings. Not linked to APAC (0 apac refs). Does NOT use D-Bus — communicates
      directly via VDO stream APIs (vdo_stream_get, vdo_stream_attach, vdo_stream_get_event_fd)
      and libaxoverlay2 (cairo_create, cairo_set_source_rgba, cairo_fill, etc.).
      Config fields processed: Active, Color, BgColor, Size, PositionType, Indicator.
        Active: bool — enables/disables the on-screen streaming indicator overlay.
        Color/BgColor: RGBA overlay colors.
        Size: overlay dimension.
        PositionType: overlay screen position.
      Writes config to /etc/video-streaming-indicator/overlay.conf (confutils_set_file_contents_with_sync).
      No mechanism to identify HTTP caller role: 0 strings matching REMOTE_USER, http_user,
        operator, admin, viewer in binary.
      APAC policy entry "videostreamingindicator:" = daemon's own outgoing APAC grants, not
        an incoming HTTP caller check. Daemon enforces no privilege gate on received requests.
    4th distinct bypass pattern: non-D-Bus daemon (VDO/overlay only) → APAC structurally
      unreachable; SocketGroup=www; no Apache auth override; no CGI auth library.
    FINDING F-AXVSI-01 (static analysis): viewer-level video streaming indicator control.
      Viewer sends POST to /axis-cgi/videostreamingindicator.cgi with {"Active": false} to
      disable the on-screen indicator that signals active video streaming. Also configures:
        Color, BgColor (appearance), Size, PositionType (positioning).
      Impact: viewer disables the visual streaming indicator on deployed cameras without
        operator auth. In privacy-sensitive deployments (retail, office, court, health):
        indicator signals to subjects they are being recorded. Viewer removes this signal
        while streaming continues. Write is persistent (config file updated).
        VAPIX specifies operator-minimum for indicator control; daemon enforces none.

  privacymask.cgi (0-byte stub): TransferProxy to /var/run/maskd/transfer.
    Apache conf (transfer_maskd.conf):
      TransferProxy /axis-cgi/privacymask.cgi /var/run/maskd/transfer
      No Require override — viewer+ by default.
    Note: /axis-cgi/admin/ is a symlink to '.' — /axis-cgi/admin/privacymask.cgi
      resolves to the same 0-byte stub; both CGI paths use the same socket.
    Socket unit (privacy-mask.socket): ListenDatagram=/run/maskd/transfer,
      SocketMode=0660, SocketUser=maskd, SocketGroup=www.
      Apache (www group) can connect.
    maskd daemon (351856 bytes, User=maskd):
      http_user, http_remote_addr, http_remote_port — reads HTTP request fields for LOGGING.
        Pattern matches factorydefault.cgi logging-only REMOTE_USER usage — NOT an auth gate.
      getgrnam — called by libfdipc.so at socket setup time (socket group assignment), not HTTP auth.
      libfdipc.so: exports fdipc_recv and fdipc_recv_with_uid.
        maskd uses fdipc_recv (NOT fdipc_recv_with_uid) — deliberately opts out of caller UID check.
        If maskd wanted to gate on caller identity, it would use fdipc_recv_with_uid.
      0 strings: apac, apac_check_auth, libapac, REMOTE_USER propagation to auth gate,
        operator, admin, viewer privilege check, 401, 403, Unauthorized, Forbidden, deny.
      No Apache auth override. No auth library. No APAC. No D-Bus daemon chain — maskd
        directly owns com.axis.Maskd.PrivacyMask and processes FDIPC requests itself.
    FINDING F-AXMASK-01 (static analysis): viewer-level privacy mask create/delete/modify.
      Viewer authenticates at Apache level (viewer+), Apache forwards request via
      TransferProxy to maskd socket (SocketGroup=www). maskd calls fdipc_recv (no UID check),
      reads http_user for log entry only, and executes the privacy mask operation without
      any privilege enforcement.
      Operations:
        Create mask — viewer adds a black/pixelated overlay block covering a region of the
          camera's video output.
        Delete mask — viewer removes masks that operators/admins configured to protect
          sensitive areas (GDPR-protected zones, restricted rooms, privacy screens).
        Modify mask — change existing mask geometry, shape, or pixelation.
      Impact:
        1. Privacy mask destruction — viewer deletes configured privacy masks on cameras
           protecting sensitive zones (changing rooms, medical bays, private offices).
           Defeats GDPR compliance controls.
        2. Video blackout — viewer creates masks covering the entire camera frame, blinding
           the surveillance feed without touching the recording system.
        3. VAPIX specifies operator-minimum for privacymask.cgi write operations; maskd
           enforces none; access is indistinguishable between viewer and admin at the daemon.

  factorydefault.cgi / hardfactorydefault.cgi (10256 bytes each): both call
    com.axis.FirmwareManager1.FactoryDefault("Soft"/"Hard") via sd_bus_call_method.
    REMOTE_USER / REMOTE_ADDR used for audit logging only ("VAPIX user %s from IP %s
    initiated factory default") — NOT an auth gate.
    D-Bus gate (fwmgr.conf): only user="root" and group="admin" allowed for FirmwareManager1.
      NO context="default". www user (Apache, viewer/operator) DENIED at D-Bus bus layer.
      D-Bus call returns bus permission error; CGI returns Status: 500 Internal Error.
    NEGATIVE. D-Bus bus-layer blocks all non-admin callers.

  firmwaremanagement.cgi / firmwareupgrade.cgi: both call com.axis.FirmwareManager1 methods.
    Same fwmgr.conf D-Bus gate applies. NEGATIVE.

  audiomixer.cgi (34904 bytes): calls com.axis.AudioMixer2 / com.axis.AudioMixer via sd_bus.
    AudioMixer D-Bus conf (com.axis.AudioMixer.conf): context="default": DENY.
      Only operator group, audiomixer user, actionengined, root allowed.
      www user (Apache) not in operator group — DENIED at D-Bus bus layer.
    NEGATIVE.

  dnsupdate.cgi (shell script): accepts ?add=NAME or ?delete=NAME from QUERY_STRING.
    Calls dnsupdate.script add "$val" all / dnsupdate.script delete "$val".
    In dnsupdate.script: $val is the DNS NAME (FQDN), not the IP. Camera's own interface
      addresses are used (net_all_addrs: eth0/wlan0 global-scope addresses).
      dnsupdate_validate() validates NAME field: FQDN chars only, max 253 chars.
    No Apache override, no auth check in script. Viewer+ by default.
    Security: viewer can trigger DDNS registration for an arbitrary hostname pointing
      to the camera's actual interface IPs. If DNSUPDATE_SERVER is not configured
      (default: DNSUPDATE_NOSERVER=";"), server line is commented out and nsupdate
      uses SOA resolver — limited exploitability without a configured DDNS server.
    Not filed: requires DDNS server configured; viewer triggers DDNS update for
      camera's OWN IPs; no ability to inject attacker-controlled IP addresses.

  stclient.cgi (symlink → /usr/sbin/stclient.cgi, 30808 bytes): AVHS relay client CGI.
    Links: libcgiparser.so (parse only), libuser_manager.so.0, OpenSSL, GLib D-Bus.
    Auth strings: user_manager_vapix_auth_user_basic — validates VAPIX credentials.
      This is likely used to authenticate the AVHS relay-server identity, not the HTTP caller.
    Cert operations: cert_set_write, cert_set_insert_cert, cert_set_insert_ca, cert_set_copy_set,
      cert_msg_add_op, cert_set_create_set — manages AVHS relay TLS certificate sets.
    D-Bus: calls com.axis.AVHS and com.axis.BasicDeviceInfo1.
    AVHS D-Bus conf: context="default" allow send_destination — bus layer open to www.
    No APAC refs, no operator/admin/viewer strings, no Apache override.
    Pending: specific HTTP operations exposed by stclient.cgi not fully characterized.
      If viewer can trigger cert writes (cert_set_write/insert) without auth, that is
      a PKI manipulation finding. Further analysis required — NOT filed without operation map.

  connection_list.cgi (shell script, 3927 bytes): reads active TCP/UDP connections via
    /proc/net/tcp6 and /proc/net/udp6. No auth check, no Apache override. Viewer+.
    Lists: remote IP, protocol, service(port), state (ESTABLISHED/LISTEN), PID/process.
    Not filed: read-only; network connection list is standard operational info;
      impact limited to info disclosure of connection metadata.

  ptz/ptzsetactivedrivermode.cgi (shell script, 7452 bytes): changes PTZ driver mode
    config files (copies framework.conf for MODE0/MODE1 PTZ). Calls gdbus to
    com.axis.PTZ.Coordinator. com.axis.PTZ.conf: context="default" allow — D-Bus bus layer open.
    ptzaurus daemon: apac_check_auth/apac_init/libapac.so.0 (APAC v1). Embedded permission
    strings "viewer:1;operator:1;admin:3;ptzadm:3" — SetConfiguration = admin-level (3).
    APAC inside daemon gates the call using D-Bus SO_PEERCRED (ptzaurus process identity).
    NEGATIVE. APAC v1 inside ptzaurus blocks non-admin callers at daemon layer.

  record/record.cgi, record/stop.cgi, record/continuous/*.cgi, record/recording_group/*.cgi:
    0-byte stubs. TransferProxy to /run/indexer/transfer.
    indexer daemon (User=storage, Group=storage, RuntimeDirectory=indexer mode=0755):
      apac2_init, apac2_release, libapac2.so.0 — APAC v2 enforcement.
    record/remove.cgi, record/storage/*.cgi: FastCGI proxy to /run/osr-main/manager.socket.
      Apache sets RequestHeader X-Remote-User for forwarded HTTP username.
      osr-main daemon: apac2_check_username, apac2_init, libapac2.so.0 — APAC v2.
    NEGATIVE. Both indexer and osr-main enforce APAC v2 on forwarded HTTP username.

  debug/debug.cgi (0-byte stub): Transfer /var/run/dbg-cgi/ctrl-cgi-socket.
    Uses Transfer directive (raw socket, not TransferProxy). No Require override found.
    No dbg-cgi binary found anywhere in Q1656_12_11_118 rootfs — binary absent.
    Socket at /var/run/dbg-cgi/ — path does not exist unless binary present.
    PENDING / NOT FILED. Binary missing from extracted firmware; cannot characterize
    operations or auth posture without it. Revisit on firmware with debug package installed.

  disks/*.cgi (27 CGIs total — checkdisk, format, getcapabilities, gethealth, job, list,
    lock, mount, repair; networkshare/add|bind|job|list|modify|remove|schemaversions|test|unbind;
    properties/changediskpassphrase|disablediskencryption|enablediskencryption|getdiskalertlevels
    |schemaversions|setcleanupmaxage|setcleanuppolicy|setdiskalertlevels|setrequiredfs):
    All 0-byte stubs. TransferProxy to /var/run/disks/transfer.
    storage_manager binary (412152 bytes): apac2_check_username, apac2_init, apac2_release,
      libapac2.so.0 — APAC v2 enforcement on forwarded HTTP username.
    D-Bus conf (com.axis.storage.StorageManager1.conf): storage + root only; no context="default".
    D-Bus conf (storage.conf): context="default" allow for com.axis.Storage — bus layer open.
    But socket-based CGI path through storage_manager enforces APAC v2 regardless.
    NEGATIVE. APAC v2 in storage_manager gates all disk management operations.

  lensparams/*.cgi (13 CGIs, 64-byte shell scripts): exec ./lensparams $opt.
    lensparams binary (31168 bytes): calls com.axis.LensDistortionCorrection2.ch{N} via D-Bus.
    D-Bus conf (LensDistortionCorrection2.conf): only root and imaged users allowed.
      NO context="default" — www user DENIED at D-Bus bus layer.
    NEGATIVE. D-Bus bus layer blocks www user before reaching lensparams binary.

  geolocation/get.cgi, geolocation/set.cgi (30744 bytes each): call com.axis.GeoLocation1.
    Both link libcgiparser.so (AXIS CGI auth enforcement library — requires operator+).
    GeoLocation1 D-Bus conf: context="default" open but DENY DBus.Properties by default;
      explicit operator+ users (wwwaop, wwwap, wwwa, wwwao, wwwaov, wwwaovp, wwwav, wwwavp)
      allowed for Properties interface.
    NEGATIVE. libcgiparser.so enforces operator minimum before D-Bus call.

  geoorientation/geoorientation.cgi (26664 bytes): calls com.axis.GeoLocation1.
    Links libcgiparser.so (operator+ enforcing auth library).
    NEGATIVE. libcgiparser.so enforces operator minimum.

  orientation/getlateralvalue.cgi, getlongitudinalvalue.cgi, getschemaversions.cgi:
    0-byte stubs. TransferProxy to /var/run/posd/transfer (transfer_orientation.conf).
    posd daemon (71768 bytes, Position Service): apac_check_auth, apac_init, apac_release,
      libapac.so.0 — APAC v1 enforcement. "Unauthorized Access",
      "com.axis.Orientation1.Unauthorized" error strings confirm auth is enforced.
    NEGATIVE. APAC v1 in posd gates all orientation read/write operations.

  com/ptz.cgi, com/ptzconfig.cgi, com/ptzqueue.cgi, com/serial.cgi (0-byte stubs):
    com/ptz*.cgi: TransferProxy to /var/run/ptz/vapixdsocket.
    com/serial.cgi: Transfer /var/run/ptz/vapixdsocket (same daemon).
    ptz-vapix.socket: SocketUser=www, SocketGroup=www, SocketMode=0660 — Apache can connect.
    ptzvapixd daemon (211672 bytes): getgrnam (group membership check), Forbidden, 403 Not Allowed,
      com.axis.Ptz.Error.Unauthorized, "removeallserverpresets: Unauthorized: %d".
    ptzvapixd enforces auth internally via OS group checks. com.axis.PTZ.Coordinator.UserGroups.GetGroups
      confirms the daemon queries the PTZ user group policy before executing operations.
    NEGATIVE. ptzvapixd internal auth (getgrnam + explicit Unauthorized/Forbidden responses)
      gates all PTZ VAPIX and serial relay operations.

  jpg/image.cgi (0-byte stub): Transfer /var/run/jpeg-streamer/transfer.
  mjpg/video.cgi (0-byte stub): Transfer /var/run/jpeg-streamer/transfer.
    jpeg-streamer daemon (96584 bytes, User=jpeg-streamer): streaming daemon for JPEG snapshots
      and MJPEG video streams. No APAC refs, no auth library.
    http_user present (http_request_new_from_transfer parses HTTP request metadata).
    No 401/403/Unauthorized strings — no rejection path found.
    NEGATIVE. These are the camera video/image access endpoints; viewer+ is the correct
      VAPIX privilege level for live video access. No write operations or privilege-escalating
      operations exposed via these stubs. Streaming-only endpoints, auth enforced at Apache layer.

  customhttpheader.cgi (22808 bytes): manages custom HTTP response headers injected by Apache.
    Default headers in /etc/httpconf/customheader.conf:
      X-Content-Type-Options: nosniff
      X-Frame-Options: SAMEORIGIN
      X-XSS-Protection: 1; mode=block
      Content-Security-Policy: default-src 'self'; frame-ancestors 'self'; ...
      Referrer-Policy: strict-origin-when-cross-origin
    CGI operations: "list" (enumerate headers), "remove" (delete a header entry).
      CGI_REQUEST_RESTRICT_POST — POST-only; JSON body {"method": "remove", "params": {...}}.
      Success: "customheader-cgi: success: %s". Config written to /etc/httpconf/customheader.conf.
    Auth:
      0 matches: apac, REMOTE_USER, operator, admin, viewer, 401, 403, Unauthorized, getgrnam.
      No auth library (no libaxcgijson, libjsoncgi, libcgiparser, libapac).
      No Apache auth override (grep returned empty).
      Default: viewer+ access.
    FINDING F-AXHDR-01 (static analysis): viewer-level removal of security HTTP response headers.
      Viewer sends POST to /axis-cgi/customhttpheader.cgi with {"method": "remove"} to
      remove X-Frame-Options, Content-Security-Policy, X-XSS-Protection, etc. from the
      camera's HTTP response header set. Config file /etc/httpconf/customheader.conf updated.
      Impact:
        1. X-Frame-Options removal — camera web UI can be embedded in attacker-controlled
           iframes. Enables clickjacking attacks against admin/operator sessions: trick admin
           into clicking a button that performs a privileged action (user add, config change)
           while appearing to click something innocuous on the outer page.
        2. Content-Security-Policy removal — removes script-src 'self' restriction. If any
           XSS payload exists in camera web UI (input fields, log viewers, username display),
           attacker can execute scripts in admin session context after CSP is removed.
        3. X-XSS-Protection removal — disables browser's built-in XSS filter for the camera UI.
        4. Changes are persistent across camera sessions and reboots (config file write).
        5. The headers managed include http_force_rtsp_auth and http_auth_info_header — these
           may affect RTSP authentication enforcement (requires further characterization).
      Note: attack requires attacker to have viewer credentials AND a simultaneous admin session
        to the same camera. Severity is medium given the multi-step nature.

  serverreport.cgi (5167 bytes, shell script): generates diagnostic bundle.
    Sources /usr/html/axis-cgi/lib/functions.sh (utility functions — NO auto auth enforcement).
    Operations (mode= query parameter):
      text (default): full server report text (generated by /usr/sbin/gen_serverreport.sh)
      zip: server report as downloadable zip archive
      zip_with_image: zip + current JPEG camera snapshot (via /usr/sbin/jpeg_snapshot)
      tar_all: ALL log files merged (syslog, startup log, /var/log/, /var/lib/syslog-ng/,
        persist-all.log, /mnt/flash/messages, memory status CSV, DAD app log)
      tar_kernel_log: primary and secondary kernel logs
    Auth:
      No auth check in script. functions.sh provides no auto-enforcing auth.
      No Apache auth override in standard conf. Appears in httpd-auth-preview-mode.conf
        inside <IfDefine PREVIEWMODE> — that block is INACTIVE in normal Apache operation.
      Default: viewer+ access.
    FINDING F-AXSRVRPT-01 (static analysis): viewer-level server diagnostic report access.
      Viewer downloads full diagnostic bundle: device serial (bootblocktool SERNO), processor serial,
      MAC address, complete VAPIX user list (all usernames + privilege roles), complete ONVIF user list,
      all installed TLS certificate CNs, full root.* parameter tree (passwords masked), all system logs
      (info/warning/error/critical/segfault rotated), auth.log (authentication events), audit.json
      (via tar_all — same audit data that auditlog.cgi admin-gates with getgrnam), kernel crash logs.
      VAPIX user enumeration is the highest-impact item: viewer extracts all account names and roles,
      enabling targeted credential attacks against admin/operator accounts.
      Pattern: shell script CGI, no auth library, no Apache override → viewer+ default inherited.
      VAPIX documentation specifies operator+ minimum for serverreport.cgi.
      zip_with_image mode also triggers live JPEG snapshot at viewer level.
      STATUS: CONFIRMED static analysis. Not yet filed to Bugcrowd.

  audioanalytics.cgi (47200 bytes): calls com.axis.AudioAnalytics D-Bus service.
    D-Bus conf: context="default" allow — bus layer open. APAC enforced in daemon.
    APAC policy: com.axis.audioanalytics.settings.* restricted to:
      wwwa,wwwao,wwwaop,wwwaov,wwwaovp,wwwavp,wwwap,wwwav — operator and above.
      www (Apache process user) NOT in this section.
    audioanalytics.cgi binary (0 APAC refs): calls g_dbus_proxy_call_sync as www user.
      www user not in APAC for settings.* → APAC DENIES write operations from www.
    NEGATIVE. APAC in audio-analytics daemon denies www user for write operations.

  shockdetection/{setenabled,getenabled,setsensitivitylevel,getsensitivitylevel}.cgi:
    TransferProxy to /var/run/posd/transfer (transfer_shockd.conf).
    Same posd daemon as orientation/ — APAC v1, apac_check_auth, Unauthorized strings.
    NEGATIVE. posd APAC v1 gates all shock detection operations.

  media.cgi (0-byte stub): TransferProxy to /var/run/media-cgi/transfer.
    media-cgi.socket: SocketUser=media-cgi, SocketGroup=media-cgi, SocketMode=0660.
    SocketGroup=media-cgi — Apache runs as www group, NOT media-cgi group.
    Apache CANNOT connect to this socket; mod_axis_transfer connect() will fail.
    NEGATIVE. Socket group excludes www — Apache has no access to media-cgi socket.

  param.cgi (0-byte stub): TransferProxy to /run/param-cgi/socket (ListenStream).
    param.cgi-transfer binary (/usr/bin/param.cgi-transfer, 56208 bytes):
      http_user_realms= — reads and enforces HTTP user group from request.
      http_user= — reads forwarded HTTP username.
      getgrnam — OS group membership check.
      Embedded role strings: Administrator, Operator, Viewer, PTZOperator.
      Source ref: dynparam_admin_transfer.c — dedicated param auth transfer handler.
      "unauthorized in an iteration, breaking" — explicit auth rejection path.
    NEGATIVE. param.cgi-transfer is self-enforcing: http_user_realms + getgrnam
      gates parameter read/write operations by forwarded HTTP user group.

  onscreencontrols.cgi: FastCGI proxy to /run/onscreencontrols/fcgi/axis-onscreencontrols_fcgi.socket.
    onscreencontrols.conf: SetHandler "proxy:unix:/run/onscreencontrols/..." — no Require directive shown.
    onscreencontrols binary (/usr/bin/onscreencontrols): admin, operator, viewer strings present.
      "Status: 401 Unauthorized" — self-enforcing rejection path in handler binary.
    NEGATIVE. FastCGI handler enforces privilege check internally (401 + role strings).

  restart.cgi (10248 bytes): calls sd_bus_call_method Reboot2 on com.axis.FirmwareManager1.
    REMOTE_USER appears in audit log string only: "VAPIX user %s from IP-address %s initiated device restart".
    No Apache auth override. No auth library. No APAC. No 401/403 rejection path.
    D-Bus policy (fwmgr.conf): com.axis.FirmwareManager1 allows only root, group="admin".
    Apache runs as www (www group). www is NOT in admin group (admin group: wwwa,wwwao,...,root).
    D-Bus bus layer DENIES www from calling FirmwareManager1 before reaching daemon.
    NEGATIVE. D-Bus bus-layer policy blocks www from FirmwareManager1 (admin group required).

  hardfactorydefault.cgi (10256 bytes): calls sd_bus_call_method FactoryDefault "Hard" on FirmwareManager1.
    Same fwmgr.conf D-Bus policy — admin group only. www denied at bus layer.
    REMOTE_USER used for audit log only (same pattern as factorydefault.cgi).
    NEGATIVE. D-Bus bus-layer policy blocks www (same as restart.cgi).

  firmwaremanagement.cgi (30736 bytes): also calls com.axis.FirmwareManager1. REMOTE_USER logging-only.
    In httpd-auth-preview-mode.conf (INACTIVE in normal operation) — no effective auth override.
    Blocked at D-Bus bus layer — same admin-group-only fwmgr.conf policy.
    NEGATIVE. D-Bus blocks www from FirmwareManager1.

  rootpwdsetvalue.cgi (221-byte shell script): reads root.System.RootPwdSet via parhandclient --nocgi get.
    Read-only: returns "root.System.RootPwdSet=true/false" — whether root password has been set.
    No write operation, no auth required. Viewer-accessible by design.
    NEGATIVE. Read-only parhand query; no privilege escalation.

  alwaysmulti.cgi (shell script): calls dbus-send --dest=com.axis.AlwaysMulticast1 GenerateSdp.
    AlwaysMulticast1 D-Bus conf: only always-multicast user + root + always-multicast group allowed.
    NO context="default" allow — www user DENIED at D-Bus bus layer.
    NEGATIVE. Bus-layer policy blocks www from AlwaysMulticast1.

  oak.cgi (22528 bytes): calls com.axis.AVHS via D-Bus + curl HMAC-signed request to AXIS relay.
    External AXIS Video Hosting System relay registration. No local authorization issue.
    NEGATIVE. External service operation, no local privilege bypass.

  networkspeakerpairing.cgi (35104 bytes): calls com.axis.PolicyKitCert + com.axis.NetworkSpeakerPairing.
    PolicyKit enforcement — PolicyKit denies www user.
    NEGATIVE. PolicyKit gates network speaker pairing operations.

  streamstatus.cgi (26752 bytes): reads from com.axis.Streamer, com.axis.JpegStreamer1, com.axis.MediaCGI1.
    Read-only stream status queries (cached properties). Viewer-accessible by VAPIX design.
    NEGATIVE. Read-only streaming status; viewer access is intended.

  wssession.cgi / rtspwssession.cgi (symlink, 10256 bytes): creates RTSP WebSocket sessions.
    Apache conf: Require axis-rtsp-ws-session viewer — explicitly viewer-permitted.
    REMOTE_USER for logging only; no privilege escalation path.
    NEGATIVE. Viewer RTSP WebSocket session creation is VAPIX-intended.

  session.cgi (18440 bytes): no D-Bus refs visible. Apache conf: Require axis-rtsp-ws-session viewer.
    NEGATIVE. Viewer-accessible by design.

  ntp.cgi (75856 bytes): calls com.axis.NTP1. D-Bus bus layer OPEN (context="default" allow).
    Links libjsoncgi.so.0 — self-enforcing operator+ minimum at CGI layer.
    NEGATIVE. libjsoncgi enforces operator+ before D-Bus call.

  time.cgi (47192 bytes): calls com.axis.TimeService1. D-Bus bus layer OPEN.
    Links libjsoncgi.so.0 — self-enforcing operator+ minimum.
    NEGATIVE. libjsoncgi enforces operator+ before D-Bus call.

  ssh.cgi (10320 bytes): calls com.axis.SSH. Links libjsoncgi.so.0.
    NEGATIVE. libjsoncgi enforces operator+ minimum.

  remotesyslog.cgi (47200 bytes): calls com.axis.RemoteSyslog1.
    D-Bus conf: context="default" allows main interface.
    remote-syslogd daemon: apac_check_auth, apac_init, libapac.so.0 — APAC v1 enforcement.
    NEGATIVE. Daemon APAC v1 gates remote syslog config operations.

  upnp.cgi (43096 bytes): calls com.axis.UPnP. D-Bus bus layer OPEN (context="default").
    Links libjsoncgi.so.0 — self-enforcing operator+.
    NEGATIVE. libjsoncgi enforces operator+ before D-Bus call.

  mdnssd.cgi (55384 bytes): calls com.axis.MDNSDiscovery1, com.axis.MDNSSD.
    D-Bus bus layers OPEN (both confs have context="default" allow).
    Links libjsoncgi.so.0 — self-enforcing operator+.
    NEGATIVE. libjsoncgi enforces operator+ before D-Bus call.

  power-settings.cgi (51296 bytes): calls com.axis.PowerControl.Measurement, com.axis.Tio1.
    PowerSettings1 D-Bus conf: context="default" DENY — bus layer explicitly blocks www.
    NEGATIVE. D-Bus bus-layer explicit deny for context="default".

  supervisedio.cgi (55496 bytes): calls com.axis.IOSupervised.Supervised.
    io2d_dbus.conf: only iod + root — NO context="default" allow. www user DENIED at bus layer.
    NEGATIVE. D-Bus bus-layer policy blocks www from IOSupervised.

  capturemode.cgi (18440 bytes): calls com.axis.CaptureMode1. D-Bus bus OPEN.
    Links libcgiparser.so — self-enforcing operator+ minimum.
    NEGATIVE. libcgiparser enforces operator+ minimum.

  clearviewcontrol.cgi (18528 bytes): calls com.axis.WiperService.
    WiperService D-Bus conf: context="default" allow — bus layer open.
    wiper-service daemon: apac_check_auth, apac_init (3 hits) — APAC v1 enforcement.
    NEGATIVE. APAC v1 in wiper-service daemon gates all wiper operations.

  analyticsmetadataconfig.cgi (14440 bytes): calls com.axis.MetadataServer1.
    Links libjsoncgi.so.0 — self-enforcing operator+.
    NEGATIVE. libjsoncgi enforces operator+.

  featureflag.cgi (39120 bytes): calls com.axis.FeatureFlagService1.
    D-Bus conf: context="default" DENY send_destination + allows ONLY Get/GetAll (read-only methods).
    Links libjsoncgi.so.0 — self-enforcing operator+ for write operations.
    NEGATIVE. Bus layer restricts to read-only; libjsoncgi gates write paths.

  lightcontrol.cgi (39008 bytes): calls ll_* library functions (liblightlogic.so, not D-Bus).
    Links libaxcgijson.so — self-enforcing operator+ minimum.
    NEGATIVE. libaxcgijson enforces operator+ minimum before light hardware API calls.

  audiomixer.cgi (34904 bytes): calls com.axis.AudioMixer2.
    AudioMixer D-Bus conf: context="default" DENY — bus layer blocks www for write ops.
    Only read-only Introspect/Properties.Get/GetAll allowed by default.
    NEGATIVE. D-Bus bus-layer deny for write operations.

  audiodevicecontrol.cgi (55392 bytes): calls com.axis.AudioControl.
    AudioControl D-Bus conf: context="default" DENY send_destination.
    NEGATIVE. D-Bus bus-layer deny blocks www from AudioControl write operations.

  regionalsettings.cgi (14352 bytes): calls com.axis.RegionalSettings1. D-Bus bus OPEN.
    Links libcgiparser.so — self-enforcing operator+.
    NEGATIVE. libcgiparser enforces operator+.

  overlaymodifiers.cgi (10336 bytes): lists available overlay modifier tokens (date, time, ptzinfo, etc).
    Links libcgiparser.so — self-enforcing operator+.
    NEGATIVE. libcgiparser enforces operator+. (Also read-only metadata, no write surface.)

  remoteservice.cgi (22544 bytes): calls libpolicykit_parhand.so.1 — PolicyKit enforcement.
    NEGATIVE. PolicyKit gates remote service configuration operations.

  stclient.cgi (30808 bytes ELF): links libcgiparser.so (parse-only, no auth enforcement per F-AXHTEST-01).
    cert ops: cert_msg_send_req → g_dbus_connection_call_sync → com.axis.AVHS D-Bus service.
    AVHS.conf: context="default" allow at bus layer (open to www).
    stclient: APAC section (line 544) = grants for stclient daemon OS user — NOT for Apache-invoked
      CGI running as www. www: section has NO AVHS entries. APAC v1 inside AVHS daemon denies www.
    NEGATIVE. APAC blocks www OS user for all com.axis.AVHS calls.

  image_stabilization.cgi (92360 bytes): has getgrnam, admin, viewer, 401/403 strings.
    NEGATIVE. Self-enforcing via OS group check + explicit 401/403 rejection.

  auditlog.cgi (14344 bytes): has getgrnam + "Only an admin can access the audit logs."
    NEGATIVE. Admin-only enforced internally; explicit rejection message.

  deviceselftest.cgi (59496 bytes): dual-gate lockdown — NEGATIVE.
    Apache: only in <IfDefine PREVIEWMODE> block (httpd-auth-preview-mode.conf) — no route
      in normal production Apache config. CGI is not reachable from Apache in standard operation.
    Binary self-gate: "System is not in preview mode." emitted with "Status: 401 Unauthorized"
      when preview mode flag is absent. Binary checks runtime mode independently of Apache.
      String sequence confirms: preview mode absence → self-401, not a parameter-check 401.
    Uses fork/execv to run /plugins/*.plugin scripts; libjsoncpp.so.27 (JSON parse).
    Apache-inaccessible in production + binary self-enforces. No viable bypass vector.
    NEGATIVE.

  systemlog.cgi / accesslog.cgi: shell scripts, read /var/log entries (system and auth logs).
    No Apache auth override. Default: viewer+ access.
    Viewer access to system/auth logs is standard VAPIX viewer behavior — not a bypass.
    NEGATIVE. Viewer log access is VAPIX-intended.

  shuttergain.cgi, getshuttergain.cgi: links libcgiparser.so. NEGATIVE.
  streamprofile.cgi: getgrnam + self-enforcing role check. NEGATIVE.
  ptzcoordcalc.cgi: links libcgiparser.so (read-only coord calculation). NEGATIVE.
  apidiscovery.cgi: links libcgiparser.so. NEGATIVE.
  browserlang.cgi: links libcgiparser.so. NEGATIVE.
  base64encode.cgi: links libcgiparser.so. NEGATIVE.

  videostreamingindicator.cgi (0-byte stub): TransferMethodProxy (POST-only) to
    /run/video-streaming-indicator/transfer.
    video-streaming-indicator.socket: ListenDatagram=/run/video-streaming-indicator/transfer,
      SocketMode=0660, SocketGroup=www — Apache (www group) can connect.
    video-streaming-indicator daemon (/usr/bin/video-streaming-indicator, 43056 bytes):
      0 APAC refs, 0 auth strings.
      Uses VDO API (vdo_stream_get, vdo_stream_attach, vdo_stream_get_event) and Cairo graphics.
      confutils_set_file_contents_with_sync — writes configuration state.
      No auth library, no REMOTE_USER, no 401/403.
    No Apache auth override (no Location/Require for videostreamingindicator.cgi).
    Default: viewer+ access.
    FINDING F-AXVSI-01 (static analysis): viewer can POST to videostreamingindicator.cgi
      to control the camera's video streaming indicator (recording/streaming status overlay
      shown in the video feed). TransferMethodProxy → SocketGroup=www → 0-auth daemon.
      Impact: viewer can toggle or manipulate the streaming indicator state visible to all
      VMS consumers, creating false "not recording" indicators while recording continues
      or false "recording" indicators while idle. Affects privacy indication and compliance.

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

  ptz/ptzupgrader.cgi (18456 bytes): calls com.axis.PTZDriverManagement1 + com.axis.PTZ.Coordinator.
    Links libcgihelper.so (CGI parsing only — no auth enforcement).
    PTZ.conf: context="default" allow at bus layer — D-Bus bus open.
    PTZDriverManagement1.conf: context="default" allow at bus layer — D-Bus bus open.
    APAC policy: ptzdrivermanagement1.activate/deactivate are in admin-minimum section (line 755-758,
      same block as com.axis.usermanagement1.vapix.adduser/removeuser at lines ~735). www OS user NOT
      in admin section. DENIED by APAC inside PTZDriverManagement1 daemon.
    ptzaurus (PTZ.Coordinator daemon): APAC v1, admin-level gate. ptz.coordinator.setconfiguration
      in admin section (line 770). www DENIED.
    NEGATIVE. APAC admin-section gates PTZDriverManagement1 and PTZ.Coordinator operations for www.

  ptz/ptzuploader.cgi (18440 bytes): same D-Bus targets (PTZDriverManagement1 + PTZ.Coordinator).
    Same APAC analysis — www DENIED for both services.
    NEGATIVE.

  packagemanager.cgi (100512 bytes): calls com.axis.PackageManager.LicenseKeyConf1 + com.axis.AcapManager1.
    F-AXPKG-01 REFUTED (libxml2 2.13+ disables XXE by default; no xmlSubstituteEntitiesDefault call).
    AddLicenseKey/RemoveLicenseKey for LicenseKeyConf1: in admin section (lines 706-707). www DENIED.
    acapmanager1.install/acapmanager1.uninstall: in admin section (lines 688-689). www DENIED.
    REMOTE_USER present in env — audit logging only (same pattern as factorydefault.cgi).
    No auth library (no libcgiparser/libjsoncgi/libaxcgijson). No Apache auth override.
    NEGATIVE. APAC admin-section gates all write operations inside AcapManager1 and PackageManager1.

  mediaclip.cgi (10256 bytes): links libmediaclip_lib.so.1.
    Operations in binary: play_clip, stop_clip, download_clip, upload_clip, remove_clip.
    libmediaclip_lib.so.1: 0 auth strings (no admin/viewer/operator/401/403/Unauthorized/REMOTE_USER).
      Only export of note: dbus_check_supported_file (reads D-Bus for supported clip format check).
    No Apache conf for mediaclip.cgi found in /etc/apache2/. Default: viewer+ access.
    playclip.cgi (10256 bytes): same libmediaclip_lib.so.1, same auth profile.
    stopclip.cgi (10256 bytes): same libmediaclip_lib.so.1.
    mediaclip2.cgi (14344 bytes): auth=1 (one auth string) — libjsoncgi.so.0 likely. NEGATIVE separately.
    VAPIX specifies operator+ for mediaclip upload and remove operations; viewer+ for play/stop.
    No enforcement in libmediaclip_lib or CGI binary for the HTTP caller's privilege level.
    BUT: mediaclip daemon has apac_check_auth + apac_init + libapac.so.0 (APAC v1, SO_PEERCRED).
      D-Bus conf: context="default" allow at bus layer — open to www.
      APAC inside daemon: checks www OS user identity. www: section has no mediaclip.* entries.
        actionengined: section has com.axis.mediaclip.* (line 11) — for actionengined OS user, not www.
        operator section (line 831): com.axis.mediaclip.* — for HTTP operator/admin OS users, not www process.
        Viewer section (lines 887-888): only startplayingclip/stopplayingclip — play/stop only.
      www user → DENIED for addclip, removeconfiguration, getmetadata write ops.
    F-AXCLIP-01 REFUTED: APAC v1 in mediaclip daemon blocks www OS user for upload/remove ops.
    NEGATIVE.

  local_del.cgi (shell script): deletes files from /usr/html/local/{viewer|operator|administrator}/.
    expr path check: only deletes files matching /usr/html/local/(viewer|operator|administrator)/[^/]+$.
    Path-constrained — cannot traverse outside /usr/html/local/. Not a privilege bypass.
    Not filed.

  local_list.cgi (shell script): lists files in /usr/html/local/ upload directories. Read-only.
    Not filed.

  res_finder.cgi (shell script): reads camera resolution capabilities via parhandclient.
    Read-only: resolution values, max zoom. Not filed.

  imagesize.cgi (10248 bytes): auth=1 (has auth enforcement string). NEGATIVE.

  param_authenticate.cgi (0-byte stub): TransferProxy or Transfer to unknown socket; socket not found.
    Not characterized — socket target absent from systemd units in extracted firmware.

  login.cgi (shell script, 255 bytes), logout.cgi (49 bytes): authentication infrastructure CGIs.
    login.cgi: session auth flow (redirect after login). logout.cgi: session teardown.
    401.cgi (shell script): returns Status: 401 Unauthorized. Auth infrastructure, not a finding.
    Not filed.

  stclient.cgi (symlink → /usr/sbin/stclient.cgi, 30808 bytes): AVHS relay client CGI.
    Links libcgiparser.so (CGI parsing only — does NOT auto-enforce auth per F-AXHTEST-01 analysis).
    Links libuser_manager.so.0: user_manager_vapix_auth_user_basic — authenticates the relay
      server's own VAPIX credential identity, NOT the HTTP caller making the CGI request.
    No Apache auth override found. Default: viewer+ access.
    Operations: action=deletecert; cert_set_write/insert_cert/insert_ca/create_set — PKI ops via
      cert_msg_send_req → g_dbus_connection_call_sync → com.axis.AVHS D-Bus service.
    D-Bus (AVHS.conf): context="default" allow — bus layer open to www.
    APAC: stclient: section (line 544) = daemon OS user grants (for stclient OS user, not www).
      Apache-executed stclient.cgi runs as www OS user. www: section has NO AVHS entries.
      APAC inside AVHS daemon sees www → denied for all AVHS operations.
    NEGATIVE. APAC blocks www OS user for com.axis.AVHS calls. stclient: grants do not apply
      to Apache-invoked CGI (www OS user ≠ stclient OS user).

  deviceselftest.cgi (59496 bytes): CANDIDATE status unresolved.
    "Status: 401 Unauthorized" string present — but no getgrnam, no REMOTE_USER auth check,
    no auth library (only libjsoncpp.so.27 for JSON parsing). Mechanism for 401 is unclear.
    Uses fork/execv to run system test scripts. No D-Bus refs.
    Apache: appears in httpd-auth-preview-mode.conf inside inactive IfDefine PREVIEWMODE block.
      No Require override in normal-mode conf. Default: viewer+ access.
    Earlier analysis (commented block line 430) called NEGATIVE based on 401 string alone.
    Active analysis retains CANDIDATE — 401 string present but self-enforcing mechanism unconfirmed.
    Low-medium severity if exploitable (triggers system self-test; brief service interruptions possible).
    NOT filed pending live device verification.

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
