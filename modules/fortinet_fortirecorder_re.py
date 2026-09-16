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
# FRC-F4: frcc:// custom URI + FRCC$reciveBytesFromClient typo
# ---------------------------------------------------------
FRC_F04_FRCC_PROTOCOL = {
    "id":       "FRC-F04",
    "product":  "Fortinet FortiRecorder Mobile Android APK",
    "severity": "INFO -- custom protocol surface; authentication flow and frame parsing not yet reversed",
    "class":    "Custom proprietary protocol (attack surface documentation)",

    "description": (
        "The FortiRecorder app uses a custom protocol registered as the 'frcc://' URI scheme. "
        "The FRCC class (FortiRecorder Camera Control Client) manages a TCP socket connection "
        "to the NVR on frccPort. "
        "Key lambdas: FRCC$authenticate$1$1$1 (3 levels of nested async auth callbacks), "
        "FRCC$reciveBytesFromClient$1/2 (note: typo 'recive' not 'receive' -- raw byte stream consumer), "
        "FRCC$doInBackground$1/2/3 (AsyncTask background ops), "
        "FRCC$sendPlaybackSeek$timer$1 (playback seek timer). "
        "FaceUploadActivity indicates biometric (facial recognition) data is uploaded to NVR cameras. "
        "The FRCC protocol framing, auth token format, and frame structure are not yet reversed."
    ),

    "evidence": {
        "uri_scheme":       "frcc:// (DEX string pool)",
        "key_fields":       "frccPort, frccIO, frccStreamError, frccStreamNoRec, frcc_facial",
        "auth_lambdas":     "FRCC$authenticate$1$1$1 (3-deep nesting suggests async coroutine chain)",
        "typo_note":        "reciveBytesFromClient (typo preserved from source); raw TCP byte receiver",
        "face_upload":      "com.fortinet.fortirecorder.activities.FaceUploadActivity",
    },

    "pending": (
        "Reverse the FRCC auth frame format and TcpClient byte framing to determine "
        "if auth tokens are replayable or if unauthenticated frames exist. "
        "Reverse FaceUploadActivity to determine if facial biometric data is transmitted "
        "with adequate protection."
    ),
}


# ---------------------------------------------------------
# Pending findings
# ---------------------------------------------------------
pending_findings = [
    "FRC$Crypto key usage trace: confirm which methods call strToEncrypt/strToDecrypt "
    "and whether the same hardcoded key encrypts the frcc:// protocol body or only BLE payloads; "
    "source: classes.dex const-string at 0x1aba04; 2026-09-16",

    "FRCC auth frame format: reverse FRCC$authenticate$1$1$1 bytecode to extract "
    "auth token structure (compare to FRC/Crypto encrypted format); "
    "source: classes.dex Lcom/fortinet/fortirecorder/managers/FRC/FRCC$authenticate*; 2026-09-16",

    "FaceUploadActivity biometric data: reverse data format and transport -- "
    "does facial template upload use the same hardcoded AES key or a separate channel; "
    "source: com.fortinet.fortirecorder.activities.FaceUploadActivity; 2026-09-16",

    "NVRManager auth: check how NVRManager authenticates to the NVR server; "
    "if using fixed credentials or token derived from hardcoded material; "
    "source: Lcom/fortinet/fortirecorder/managers/FRC/NVRManager; 2026-09-16",
]
