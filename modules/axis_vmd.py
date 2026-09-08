"""
AXIS Video Motion Detection 4 (vmd) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Video Motion Detection 4 (vmd), appId 143440
Version: 4.4.4 (ARM32 armhf stripped)
CGI: administrator /control.cgi (admin-only)

Architecture: ONVIF CGI handler + standard CGI handler.
Proprietary scene libs: libscene.so, libgeometry.so (loaded from camera firmware path).
C++ classes: ExclusionFilter, SwayingFilter, SizeFilterPerspective, ObjectLifetimeFilter.
libexpat.so.1 for XML config parsing.
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-VMD"
LABEL = "vmd 4.4.4: ONVIF handler fuzz, object ID OOB, libexpat, libscene.so sub"

FILTER_CLASSES = [
    "ExclusionFilter", "SwayingFilter", "SizeFilterPercent",
    "SizeFilterPerspective", "ObjectLifetimeFilter", "LowConfidentObjectFilter",
    "PerspectiveFilterExternalData",
]

FINDINGS = [
    {
        "id": "AXIS-VMD-01",
        "severity": "MEDIUM",
        "title": "ONVIF CGI handler malformed message crash",
        "detail": (
            "vmd implements Onvif_CGI_Handler in addition to the standard CGI_Handler. "
            "ONVIF protocol parsing is a complex attack surface. "
            "Malformed ONVIF payload submitted via admin CGI may crash or corrupt "
            "vmd process state. "
            "ONVIF CGI handler confirmed by symbol Onvif_CGI_Handler in binary strings."
        ),
        "cgi": "administrator /control.cgi (Onvif_CGI_Handler)",
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-VMD-02",
        "severity": "LOW",
        "title": "AlarmData::didTriggerAlarm object ID OOB read",
        "detail": (
            "'Could not find an object with id %i' — integer object ID from CGI input. "
            "If object ID is user-supplied and out-of-range, may cause OOB read "
            "of object array -> process state leak or crash."
        ),
        "prerequisite": "Admin-level camera auth",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-VMD-03",
        "severity": "MEDIUM",
        "title": "libexpat XML config parsing — CVE exposure",
        "detail": (
            "VMD configuration written via CGI then parsed by libexpat.so.1. "
            "Malformed XML in config file triggers libexpat vulnerability surface. "
            "Audit NVD for libexpat CVEs applicable to version bundled with firmware."
        ),
        "prerequisite": "Admin-level auth to write VMD config",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-VMD-04",
        "severity": "LOW",
        "title": "libscene.so / libgeometry.so substitution via firmware path",
        "detail": (
            "libscene.so and libgeometry.so are loaded from camera firmware path. "
            "If another ACAP can write to the library search path ahead of the firmware "
            "directory, substitute with malicious .so -> code execution in vmd context."
        ),
        "libs": ["libscene.so", "libgeometry.so"],
        "prerequisite": "Write access to library search path directory",
        "status": "UNPATCHED",
        "cve": None,
    },
]
