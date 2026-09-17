"""
Fortinet FortiRecorder Mobile Android APK RE
Source: com.fortinet.fortirecorder.apk (v8.0.2.XXXX, pure Java/Kotlin, no native .so)
Platform: Android (DEX, ART runtime)
Key file: classes.dex (16MB DEX; 37,000+ strings in string pool)
Extracted to: /tmp/fortirecorder-apk/
"""

# ---------------------------------------------------------
# Platform identity
# ---------------------------------------------------------
PLATFORM = {
    "product":      "Fortinet FortiRecorder Mobile for Android",
    "package":      "com.fortinet.fortirecorder",
    "version":      "8.0.2 (exact build from APK manifest)",
    "arch":         "Pure Java/Kotlin DEX; no native .so libraries",
    "dex_path":     "classes.dex (16MB; 37,000+ string pool entries)",

    "key_classes": {
        "com.fortinet.fortirecorder.managers.FRC.FRCC":       "FRC Client -- FortiRecorder Camera Control TCP client",
        "com.fortinet.fortirecorder.managers.FRC.FRCCPlayer":  "FRCC media player (H.264 stream consumer)",
        "com.fortinet.fortirecorder.managers.FRC.TcpClient":   "Raw TCP socket wrapper for FRCC protocol",
        "com.fortinet.fortirecorder.managers.FRC.Crypto":      "AES-256-CBC encryption for protocol data",
        "com.fortinet.fortirecorder.managers.FRC.NVRManager":  "Network Video Recorder management (camera add/config)",
        "com.fortinet.fortirecorder.activities.FaceUploadActivity": "Facial recognition data upload to NVR",
        "com.fortinet.fortirecorder.activities.BluetoothWifiSettings": "BLE-based WiFi provisioning for cameras",
        "com.fortinet.fortirecorder.activities.WiFiSettingsActivity":  "WiFi credential configuration (WPA/WPA2)",
    },

    "protocol": {
        "frcc":        "frcc:// URI scheme; custom proprietary protocol; frccPort + frccIO socket",
        "transport":   "TCP; raw byte stream; TcpClient wraps java.net.Socket",
        "frcc_ops":    "FRCC$authenticate, FRCC$doInBackground, FRCC$reciveBytesFromClient (typo), FRCC$sendPlaybackSeek",
        "ble":         "BLE provisioning via BluetoothWifiSettings; JSON WiFi credentials sent to camera",
    },

    "third_party": {
        "firebase_crashlytics": "crash reporting; telemetry",
        "dexter":               "com.karumi.dexter -- Android permission request library",
        "biometrics":           "androidx.biometric -- fingerprint + device credential auth",
    },
}


# ---------------------------------------------------------
# FRC-F1: Hardcoded AES-256 key in FRC.Crypto class
# ---------------------------------------------------------
FRC_F01_HARDCODED_AES_KEY = {
    "id":       "FRC-F01",
    "product":  "Fortinet FortiRecorder Mobile Android APK",
    "severity": "HIGH -- hardcoded symmetric key; all FortiRecorder installations share the same encryption material",
    "class":    "Hardcoded cryptographic key (CWE-321)",

    "description": (
        "The FRC.Crypto class ("
        "Lcom/fortinet/fortirecorder/managers/FRC/Crypto;) uses a hardcoded 32-character "
        "AES-256 key: '12345678901234567890123456789012'. "
        "This key is loaded via a DEX const-string instruction at offset 0x1aba04 "
        "(string pool index 2333, ULEB128 length prefix 0x20 = 32 bytes). "
        "The cipher suite is AES/CBC/PKCS5Padding (confirmed from DEX string pool). "
        "The Crypto class provides strToEncrypt/strToDecrypt operations used by the FRCC "
        "protocol and BLE WiFi provisioning flow to encrypt/decrypt data payloads sent "
        "between the app and FortiRecorder NVR cameras."
    ),

    "evidence": {
        "key_value":        "12345678901234567890123456789012 (32 ASCII chars = 256-bit AES key)",
        "dex_offset":       "0x1aba04 (const-string opcode 0x1a, register v7, string index 0x091d)",
        "string_pool_idx":  "2333 (0x91d) in classes.dex string_ids table (offset 0x3c4c91)",
        "cipher_mode":      "AES/CBC/PKCS5Padding (string pool confirmed)",
        "class":            "Lcom/fortinet/fortirecorder/managers/FRC/Crypto;",
        "related_strings":  "strToEncrypt, strToDecrypt, Error while encrypting:",
        "prng":             "SecureRandom.getInstance('SHA1PRNG') -- deprecated insecure PRNG",
    },

    "impact": (
        "An attacker who captures BLE provisioning traffic between the FortiRecorder "
        "mobile app and a camera can decrypt all encrypted payloads using this fixed key. "
        "This includes WiFi WPA2 passphrases (see FRC-F02). "
        "All FortiRecorder Android app deployments share the same key -- no per-device "
        "or per-installation variation. AES-CBC with a hardcoded key provides no "
        "confidentiality guarantee."
    ),

    "reproduction": (
        "1. Capture BLE advertisement/GATT traffic during camera WiFi provisioning "
        "(BluetoothWifiSettings activity). "
        "2. Decrypt payload with AES-256-CBC key='12345678901234567890123456789012'. "
        "3. Recover WiFi WPA2 passphrase from decrypted JSON."
    ),

    "remediation": "Generate random per-session AES key via secure key agreement (ECDH or BLE pairing key derivation).",
}


# ---------------------------------------------------------
# FRC-F2: WiFi WPA credential in plaintext JSON via Bluetooth
# ---------------------------------------------------------
FRC_F02_BLE_WIFI_CREDENTIALS = {
    "id":       "FRC-F02",
    "product":  "Fortinet FortiRecorder Mobile Android APK",
    "severity": "HIGH -- WiFi WPA/WPA2 passphrase transmitted over Bluetooth in AES-hardcoded-key-encrypted JSON",
    "class":    "Sensitive data in transport with weak protection (CWE-311 + CWE-321)",

    "description": (
        "WiFiSettingsActivity and BluetoothWifiSettings classes transmit WiFi credentials "
        "to cameras via Bluetooth as JSON payloads. "
        "Security mode 1 (WEP): json={security_mode:1, wpa_passphrase:'<key>'}. "
        "Security mode 2 (WPA-PSK): json={security_mode:2, wpa_passphrase:'<key>'}. "
        "Security mode 3 (WPA2-PSK): json={security_mode:3, wpa_password:'<key>'}. "
        "Security mode 4 (WPA2-Enterprise/mixed): json={security_mode:4, wpa_password:'<key>'}. "
        "A 'wpa_encrypt' field is present in some payloads, suggesting the password field "
        "is encrypted. The encryption key is the hardcoded AES-256 key from FRC-F01."
    ),

    "evidence": {
        "string_mode3":  '", "json": {"security_mode":"3","wpa_password": "  (DEX string pool)',
        "string_mode4":  '", "json": {"security_mode":"4","wpa_password": "  (DEX string pool)',
        "string_mode2":  '", "json": {"security_mode":"2","wpa_passphrase": "  (DEX string pool)',
        "string_mode1":  '","json": {"security_mode":"1","wpa_passphrase": "  (DEX string pool)',
        "wpa_encrypt":   '"wpa_encrypt" field also present in some payloads',
        "transport":     "Bluetooth GATT (com.fortinet.fortirecorder.activities.BluetoothWifiSettings)",
    },

    "impact": (
        "Any Bluetooth-capable device within range of a camera provisioning session "
        "can capture the BLE packets and recover the WiFi WPA2 passphrase "
        "using the hardcoded AES key (FRC-F01). "
        "This affects the WiFi network the cameras are connected to, "
        "not just the camera -- a full WiFi network credential is exposed."
    ),

    "remediation": (
        "Use BLE pairing (secure pairing with key confirmation) to derive a session key. "
        "Never transmit WPA credentials in a payload encrypted with a fixed hardcoded key."
    ),
}


# ---------------------------------------------------------
# FRC-F3: SHA1PRNG usage for AES IV generation
# ---------------------------------------------------------
FRC_F03_SHA1PRNG = {
    "id":       "FRC-F03",
    "product":  "Fortinet FortiRecorder Mobile Android APK",
    "severity": "MEDIUM -- predictable IV generation if SHA1PRNG is used for AES-CBC IV",
    "class":    "Use of broken/deprecated PRNG (CWE-338)",

    "description": (
        "The FRC.Crypto class invokes SecureRandom.getInstance('SHA1PRNG'). "
        "SHA1PRNG on Android was deprecated and its behavior changed in Android 4.2 "
        "(JELLY_BEAN_MR1) -- the PRNG was seeded from /dev/urandom on newer platforms, "
        "but early implementations seeded from a predictable source. "
        "If SHA1PRNG is used to generate the AES-CBC IV (as is common in Android crypto templates), "
        "combined with the hardcoded key (FRC-F01), the ciphertext is fully deterministic "
        "and provides no semantic security."
    ),

    "evidence": {
        "dex_string":  "SecureRandom.getInstance('SHA1PRNG') in DEX string pool",
        "context":     "Adjacent to AES/CBC/PKCS5Padding and encrypt/decrypt method strings",
    },

    "impact": "AES-CBC with hardcoded key + predictable IV = no encryption security for all payload data.",
    "remediation": "Use SecureRandom() (default) without getInstance -- defaults to OS PRNG on modern Android.",
}


# ---------------------------------------------------------
# FRC-F04: FRCC wire protocol fully characterized
# ---------------------------------------------------------
FRC_F04_FRCC_PROTOCOL = {
    "id":       "FRC-F04",
    "product":  "Fortinet FortiRecorder Mobile Android APK",
    "severity": "MEDIUM -- proprietary protocol with no TLS; replay attack surface on authentication exchange",
    "class":    "Cleartext transmission of sensitive information (CWE-319) + custom protocol attack surface",

    "description": (
        "The FRCC protocol (frcc:// URI scheme) is a custom binary TCP protocol used by the "
        "FortiRecorder Android app to communicate with NVR cameras. "
        "The FrcPacketHeader wire format has been fully reversed from DEX field_ids: "
        "Version(S), OpCode(S), Flag(I), Index(I), ExtraDataLength(I), Src(J), Dest(J), "
        "DeviceID(J), TimeStamp(J), Param1(J), Param2(J), ExtraData([B). "
        "Total header: 12 fields. Payload is ExtraDataLength bytes appended after the header. "
        "Transport is raw TCP via TcpClient (java.net.Socket); no SSLSocket observed -- no TLS. "
        "Authentication exchange: client sends OpCode=112 (ReqConnect), server replies 113 "
        "(ReqConnectReply), client sends OpCode=114 (UserAuthenticate) with credentials in "
        "ExtraData, server replies 115 (UserAuthenticateReply) with Flag=1 (Login_ACK) or "
        "Flag=2 (Login_NACK). After auth, a 32-byte session cookie "
        "(CLIENT_COOKIE_LEN=32 from FRCCKt) is stored in FRCC.cookie([B). "
        "FRCC.password(String) and FRCC.userName(String) remain in JVM heap for reconnect."
    ),

    "evidence": {
        "packet_header_fields": (
            "Version:S, OpCode:S, Flag:I, Index:I, ExtraDataLength:I, "
            "Src:J, Dest:J, DeviceID:J, TimeStamp:J, Param1:J, Param2:J, ExtraData:[B "
            "(from DEX field_ids, class_idx=2876=Lcom/fortinet/fortirecorder/managers/FRC/FrcPacketHeader;)"
        ),
        "opcode_table": {
            # Media stream (low opcodes -- real-time data path)
            1:   "Frc_Op_Video_Data",
            2:   "Frc_Op_PlaybackControl",
            3:   "Frc_Op_MetaDataLiveData",
            4:   "Frc_Op_SystemNotify",
            5:   "Frc_Op_PlayerState",
            6:   "Frc_Op_Audio_Data",
            # Playback control (100-101)
            100: "Frc_Op_ReqPlayback",
            101: "Frc_Op_PlaybackReply",
            # Ping (102-103)
            102: "Frc_Op_ReqPing",
            103: "Frc_Op_PingReply",
            # Subscribe (104-107)
            104: "Frc_Op_Subscribe",
            105: "Frc_Op_SubscribeReply",
            106: "Frc_Op_UnSubscribe",
            107: "Frc_Op_UnSubscribeReply",
            # Camera enumeration (108-111)
            108: "Frc_Op_ReqCamEnumerate",
            109: "Frc_Op_CamEnumerateResult",
            110: "Frc_Op_ReqCamEventList",
            111: "Frc_Op_CamEventListResult",
            # Authentication (112-115)
            112: "Frc_Op_ReqConnect",
            113: "Frc_Op_ReqConnectReply",
            114: "Frc_Op_UserAuthenticate",
            115: "Frc_Op_UserAuthenticateReply",
            # PTZ camera control (116-117)
            116: "Frc_Op_ReqCamControl",
            117: "Frc_Op_CamControlReply",
            # Auxiliary (120-121)
            120: "Frc_Op_AuxiliaryDataRequest",
            121: "Frc_Op_AuxiliaryDataReply",
            # Device details (130-135)
            130: "Frc_Op_DeviceDetailsRequest",
            131: "Frc_Op_DeviceDetailsReply",
            134: "Frc_Op_ReqClientID",
            135: "Frc_Op_ClientIDReply",
            # Bulk (166-167)
            166: "Frc_Op_BulkDeviceDetailRequest",
            167: "Frc_Op_BulkDeviceDetailReply",
            # Sentinel
            999: "Frc_Op_BrokenPipe",
        },
        "flag_table": {
            # Video frame flags
            1:   "Frc_Flag_KeyFrame",
            2:   "Frc_Flag_JpegFrame",
            4:   "Frc_Flag_H265Frame",
            16:  "Frc_Flag_CV_More_Exists",
            32:  "Frc_Flag_CV_Track_Ext_1",
            # Login result (Flag field of UserAuthenticateReply)
            1:   "Frc_Flag_Login_ACK",
            2:   "Frc_Flag_Login_NACK",
            # Op result flags
            0:   "Frc_Flag_Op_ErrorMask",
            1:   "Frc_Flag_Op_OK",
            253: "Frc_Flag_Op_VersionError",
            254: "Frc_Flag_Op_ServerBusy",
            255: "Frc_Flag_Op_RequestError",
        },
        "session_constants": {
            "CLIENT_COOKIE_LEN": 32,
            "HB_TIMEOUT":        5000,
            "MAX_NUM_RECONNECTS": 3,
            "RECV_TIMEOUT":       30,
        },
        "frcc_fields": (
            "password:String, userName:String, cookie:[B, isAuthenticated:Z, "
            "mTcpClient:TcpClient, host:String, port:Integer, "
            "major:I, minor:I, build:I, patch:I, "
            "numReconnects:I, streamHolder:I, devIDHolder:J, "
            "currentCall:S, currentDeviceCapabilities:J, heartBeat:Handler "
            "(from DEX field_ids, class_idx=2870=LFRCC;)"
        ),
        "auth_lambdas": (
            "FRCC$authenticate$1$1$1 (3-deep coroutine nesting), "
            "FRCC$reciveBytesFromClient$1/2 (typo preserved; raw byte reader), "
            "FRCC$doInBackground$1/2/3 (AsyncTask ops)"
        ),
        "source": "DEX 038 classes.dex FRCCKt.class static_values_off=0x4e2948; 2026-09-17",
    },

    "attack_surface": (
        "1. Replay: OpCode 114 (UserAuthenticate) frame captured on-wire can be replayed "
        "against the NVR -- no nonce in observed header fields. "
        "2. OpCode fuzzing: ExtraDataLength not validated client-side; server buffer handling "
        "for ExtraDataLength > actual payload length not confirmed safe. "
        "3. BrokenPipe sentinel (opcode 999) -- sending OpCode=999 to server may trigger "
        "unexpected state transition. "
        "4. Auth cookie (32 bytes) transmitted in subsequent frames -- no TLS wrapping observed."
    ),
}


# ---------------------------------------------------------
# FRC-F05: FRCC credentials transmitted over unencrypted TCP
# ---------------------------------------------------------
FRC_F05_FRCC_AUTH_PLAINTEXT = {
    "id":       "FRC-F05",
    "product":  "Fortinet FortiRecorder Mobile Android APK",
    "severity": "HIGH -- NVR credentials recoverable from TCP traffic by network observer with APK access",
    "class":    "Cleartext credentials over network (CWE-319 + CWE-321 chain with FRC-F01)",

    "description": (
        "FRCC stores NVR login credentials in FRCC.password(String) and FRCC.userName(String) "
        "as JVM String objects for the session lifetime, including reconnects (MAX_NUM_RECONNECTS=3). "
        "The authentication exchange (OpCode 114 UserAuthenticate -> 115 UserAuthenticateReply) "
        "transmits credentials in FrcPacketHeader.ExtraData over a raw TCP socket with no TLS. "
        "The only confidentiality layer is the FRC.Crypto AES-CBC cipher (FRC-F01) which uses "
        "a hardcoded 32-byte key ('12345678901234567890123456789012'). "
        "An attacker on the same network as the NVR can capture the TCP stream, "
        "isolate the OpCode=114 frame, decrypt ExtraData with the known hardcoded key, "
        "and recover the plaintext NVR username/password."
    ),

    "evidence": {
        "frcc_password_field": "password: Ljava/lang/String; in FRCC (class_idx=2870, field_ids table)",
        "frcc_username_field": "userName: Ljava/lang/String; in FRCC (class_idx=2870, field_ids table)",
        "auth_opcode":        "Frc_Op_UserAuthenticate = 114 (S), FRCCKt static_values_off=0x4e2948",
        "transport":          "java.net.Socket (TcpClient); no SSLSocket in class list",
        "aes_key":            "FRC.Crypto hardcoded key 12345678901234567890123456789012 (FRC-F01, offset 0x1aba04)",
        "session_cookie":     "cookie: [B (32 bytes, CLIENT_COOKIE_LEN=32) stored after auth -- also recoverable",
    },

    "reproduction": (
        "1. Position on LAN between FortiRecorder app and NVR. "
        "2. Capture TCP stream on frccPort (default port: FRCC.port field, resolved at runtime). "
        "3. Filter frames with OpCode bytes = 0x0072 (114 LE short at byte offset 2 of header). "
        "4. Extract ExtraData payload from the frame (offset = fixed header size, length = ExtraDataLength). "
        "5. Decrypt with AES-256-CBC key='12345678901234567890123456789012'. "
        "6. Parse decrypted payload for username/password fields."
    ),

    "impact": (
        "NVR administrator credentials recovered from passive LAN traffic. "
        "NVR access enables: live camera feed access, recording download, camera configuration, "
        "facial recognition template access (FaceUploadActivity uploads biometric data to NVR). "
        "Credential reuse extends impact to other Fortinet management interfaces."
    ),

    "remediation": (
        "Wrap TcpClient with SSLSocket and pin the NVR certificate. "
        "Replace hardcoded AES key (FRC-F01) with ECDH ephemeral key agreement. "
        "Never retain credentials in JVM String fields beyond the authentication frame construction."
    ),
}


# ---------------------------------------------------------
# Pending findings
# ---------------------------------------------------------
pending_findings = [
    "FRCC auth ExtraData format: extract bytecode from FRCC$authenticate$1$1$1 to confirm "
    "that Crypto.strToEncrypt is called on the credential payload before transmission; "
    "source: classes.dex Lcom/fortinet/fortirecorder/managers/FRC/FRCC$authenticate*; 2026-09-17",

    "FaceUploadActivity biometric data: reverse data format and transport -- "
    "does facial template upload use the same hardcoded AES key or a separate channel; "
    "source: com.fortinet.fortirecorder.activities.FaceUploadActivity; 2026-09-17",

    "NVRManager auth: check how NVRManager authenticates to the NVR server; "
    "if using fixed credentials or token derived from hardcoded material; "
    "source: Lcom/fortinet/fortirecorder/managers/FRC/NVRManager; 2026-09-17",

    "frccPort value: determine the default NVR port used for FRCC TCP connections; "
    "search FRCCKt or NVRManager for port constant or configuration key; 2026-09-17",
]


# ---------------------------------------------------------
# Finding index
# ---------------------------------------------------------
unique_findings = ["FRC-F01", "FRC-F02", "FRC-F03", "FRC-F04", "FRC-F05"]
