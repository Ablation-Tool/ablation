"""
AXIS Metadata Provider (metadata_provider) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Metadata Provider (metadata_provider), appId 413493
Version: (ARM32 armhf ELF stripped)
Arch: ARM32 (armv7hf)
Ships: mosquitto MQTT broker (ARM32), libpaho-mqtt3as.so.1.3.1, libmetadataproducer.so

Architecture: metadata_provider subscribes to Axis camera metadata (video analytics,
PTZ events, audio detect) via libmetadataproducer.so, bridges to external MQTT broker.
Bundled mosquitto runs at localhost:1883 with allow_anonymous true (no auth, no ACL).

addhost.sh: 'echo $1 $2 >> /etc/hosts' — no sanitization, no dedup.
/etc/hosts injection triggers via bridgeBroker CGI hostname parameter.
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-MDP"
LABEL = "metadata_provider: MQTT SSRF + /etc/hosts inject + anon broker"

MOSQUITTO_CONFIG = {
    "listener": "localhost:1883",
    "allow_anonymous": True,
    "password_file": None,
    "acl_file": None,
    "tls": False,
    "log_dest": "$SYS/broker/log/# subscribed",
}

FINDINGS = [
    {
        "id": "AXIS-MDP-01",
        "severity": "HIGH",
        "title": "MQTT bridge SSRF via bridgeBroker CGI + /etc/hosts injection",
        "detail": (
            "CGI_MethodHandlerBridgeBroker creates outbound MQTT connection to operator-supplied URL. "
            "addhost.sh: 'echo $1 $2 >> /etc/hosts' — no sanitization, no dedup, no validation. "
            "Bridge URL hostname resolved after /etc/hosts injection -> SSRF to internal host "
            "by hostname injection. "
            "Chain: operator auth -> POST bridgeBroker with brokerUrl=mqtt://internal-host:1883 "
            "+ addhost hostname injection -> metadata_provider opens MQTT to attacker/internal broker."
        ),
        "cgi": "CGI_MethodHandlerBridgeBroker (method: bridgeBroker)",
        "shell_command": "echo $1 $2 >> /etc/hosts",
        "prerequisite": "Operator-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-MDP-02",
        "severity": "HIGH",
        "title": "Camera metadata stream exfiltration via MQTT bridge",
        "detail": (
            "Once MQTT bridge established to attacker broker: "
            "all camera metadata forwarded in real time to external broker. "
            "Metadata types: face detections, person counts, license plate reads, "
            "motion events, PTZ positions, audio detection events. "
            "No per-topic ACL by default (acl_file not configured in mosquitto.conf). "
            "Attacker MQTT broker receives continuous surveillance data stream."
        ),
        "data_types": [
            "face detections", "person counts", "plate reads",
            "motion events", "PTZ positions", "audio detect",
        ],
        "prerequisite": "Successful MDP-01 bridge establishment",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-MDP-03",
        "severity": "MEDIUM",
        "title": "Anonymous MQTT broker localhost:1883 — post-RCE metadata access",
        "detail": (
            "Bundled mosquitto at localhost:1883 with allow_anonymous=true and no ACL file. "
            "Any local process on the camera (post-RCE) can subscribe to all camera metadata "
            "topics without auth. "
            "$SYS/broker/log/# subscribed -> full broker log visibility. "
            "From co-resident ACAP with loopback access: subscribe to all metadata topics "
            "without any credential."
        ),
        "prerequisite": "Post-RCE local process access on camera (or another ACAP with loopback)",
        "status": "UNPATCHED",
        "cve": None,
    },
]
