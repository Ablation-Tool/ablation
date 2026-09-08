"""
AXIS Face Detector (facedetector) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Face Detector (facedetector), appId 412581
Versions:
  v2.1.2 / v2.1.3 (aarch64, stripped) — SHA identical between 2.1.2 and 2.1.3 (packaging bump only)
  v1.2.2 (6) (ARM32 armhf, stripped) — uses libvideo-object-detection-subscriber.so.0 (legacy)
  v1.2.2 (S5L) (aarch64, stripped) — uses liblarod (ARTPEC-5/6+), libyuv.so.1 bundled

CGI: administrator /control.cgi only (all versions).
No liblicensekey.so in any variant — not license-gated, runs unattended.

Critical: com.axis.Param.* wildcard D-Bus permission in 2.x manifests.
com.axis.VideoObjectDetection1.* wildcard in CV25 (Ambarella) variant.
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-FD"
LABEL = "facedetector: protobuf fuzz, wildcard D-Bus permissions, operator group"

VERSIONS = {
    "v2.1.2_v2.1.3_aarch64": {
        "arch": "aarch64 stripped",
        "sha_note": "SHA identical between 2.1.2 and 2.1.3 (packaging bump only, same binary)",
        "libs": ["liblarod.so.1", "libyuv.so.1", "libvdostream.so.1", "libaxhttp.so.1",
                 "libaxevent.so.1", "libaxparameter.so.1", "libjansson.so.4"],
        "license_gate": False,
    },
    "v1.2.2_6_armhf": {
        "arch": "ARM32 armhf stripped",
        "libs": ["libvideo-object-detection-subscriber.so.0", "libcairo.so.2",
                 "libaxoverlay.so", "libaxhttp.so.1", "libaxevent.so.1",
                 "libaxparameter.so.1", "libjansson.so.4"],
        "note": "Legacy generation: D-Bus VideoObjectDetection subscriber, no liblarod",
    },
    "v1.2.2_s5l_aarch64": {
        "arch": "aarch64 stripped",
        "libs": ["libyuv.so.1 (bundled)", "liblarod.so.1", "libaxhttp.so.1",
                 "libaxevent.so.1", "libaxparameter.so.1", "libvdostream.so.1", "libjansson.so.4"],
        "models": [
            "ssdlite_mobilenet_v3_small_320x320_oidface-alpha.larod",
            "ssdlite_mobilenet_v3_small_320x320_oidface-rot90-alpha.larod",
        ],
    },
}

FINDINGS = [
    {
        "id": "AXIS-FD-01",
        "severity": "HIGH",
        "title": "SendAlarmEvent protobuf fuzz — crash/RCE via malformed proto",
        "detail": (
            "admin /control.cgi method SendAlarmEvent decodes a protobuf payload in CGI handler. "
            "No explicit size guard visible in binary strings. "
            "Malformed protobuf field (crafted repeated field length, varint overflow, "
            "embedded message recursion depth) may overflow facedetector process memory "
            "-> crash or controlled write in protobuf parser. "
            "All versions affected (common CGI handler pattern)."
        ),
        "cgi": "administrator /control.cgi (SendAlarmEvent method)",
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-FD-02",
        "severity": "LOW",
        "title": "SetConfig mandatory param injection — error path reflection",
        "detail": (
            "'A mandatory parameter is missing' error string from SetConfig handler. "
            "Missing-param error may reflect input data in error message context. "
            "Lower severity — admin-only access required."
        ),
        "cgi": "administrator /control.cgi (SetConfig method)",
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-FD-03",
        "severity": "MEDIUM",
        "title": "v1.2.2 VideoObjectDetection D-Bus subscriber — legacy API fuzz",
        "detail": (
            "libvideo-object-detection-subscriber.so.0 receives analytics data via D-Bus "
            "VideoObjectDetection subscriber interface. "
            "Old D-Bus VideoObjectDetection API predates larod safety improvements. "
            "Malformed analytics event from co-resident app may crash facedetector v1.2.2 process."
        ),
        "affected": "v1.2.2 ARM32 (armhf) only",
        "prerequisite": "Another ACAP on same camera that can send VideoObjectDetection events",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-FD-04",
        "severity": "MEDIUM",
        "title": "com.axis.Param.* wildcard D-Bus permission — broad param read/write scope",
        "detail": (
            "manifest.json resources.dbus.requiredMethods includes 'com.axis.Param.*' (wildcard). "
            "facedetector is granted permission to call ANY method on com.axis.Param D-Bus interface, "
            "not scoped to face detection parameters. "
            "Includes reading: network config, credentials, VAPIX service accounts. "
            "Wildcard scope confirmed in 2.1.3 ARTPEC-7 and CV25 manifests."
        ),
        "affected": "v2.x aarch64 (ARTPEC-7 and CV25)",
        "prerequisite": "Code execution in facedetector context or D-Bus message bus access",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-FD-05",
        "severity": "MEDIUM",
        "title": "com.axis.VideoObjectDetection1.* wildcard — full object detection interface (CV25)",
        "detail": (
            "CV25 (Ambarella) variant 2.1.3 manifest declares 'com.axis.VideoObjectDetection1.*' "
            "(wildcard) as a required D-Bus method. "
            "facedetector granted permission to call ANY method on com.axis.VideoObjectDetection1. "
            "Includes: subscription management, object class configuration, sensitivity tuning "
            "for OTHER ACAP apps. "
            "Can suppress or spoof detections in co-resident analytics ACAPs "
            "(Object Analytics, Loitering Guard, Fence Guard) on same camera."
        ),
        "affected": "v2.1.3 CV25 (Ambarella) build only",
        "prerequisite": "CV25-based camera with co-resident Object Analytics or similar ACAP",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-FD-06",
        "severity": "LOW",
        "title": "Linux 'operator' group membership — privilege scope beyond sdk user (CV25)",
        "detail": (
            "CV25 manifest declares resources.linux.user.groups: ['video', 'operator']. "
            "facedetector process added to 'operator' Linux group in addition to 'video'. "
            "'operator' group on Axis cameras may grant access to operator-level device files, "
            "sockets, or IPC channels. "
            "Attack chain: compromise facedetector -> operator group file access "
            "-> read operator-privileged device state or inject into operator-accessible IPC."
        ),
        "affected": "v2.1.3 CV25 (Ambarella) build — ARTPEC-7 variant lacks operator group",
        "prerequisite": "Code execution in facedetector context on CV25 camera",
        "status": "UNPATCHED",
        "cve": None,
    },
]
