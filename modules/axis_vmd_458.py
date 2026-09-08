"""
AXIS Video Motion Detection 4.5.8 (vmd) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Video Motion Detection 4 (vmd), appId 143440
Version: 4.5.8  Arch: aarch64 stripped (upgraded from ARM32 in 4.4.4)
CGI: administrator /control.cgi (admin-only)

Changes from 4.4.4:
  Architecture upgrade: ARM32 -> aarch64.
  XML_SetNamespaceDeclHandler added: namespace-aware XML parsing in libexpat.
  libscene.so, libgeometry.so, libfixmath.so.0 still loaded (same substitution surface).
  ONVIF CGI handler still present.
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-VMD45"
LABEL = "vmd 4.5.8: libexpat namespace confusion, libscene.so substitution"

FINDINGS = [
    {
        "id": "AXIS-VMD45-01",
        "severity": "LOW",
        "title": "libexpat XML namespace confusion via malformed namespace declaration",
        "detail": (
            "XML_SetNamespaceDeclHandler installed in 4.5.8 (not present in 4.4.4). "
            "Namespace-aware XML parsing added for VMD config. "
            "Malformed xmlns declarations in VMD config may trigger libexpat "
            "namespace parsing edge case -> heap corruption. "
            "Admin writes XML config via /control.cgi -> parsed by libexpat with namespace handling."
        ),
        "cgi": "administrator /control.cgi",
        "prerequisite": "Admin-level auth to write VMD config",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-VMD45-02",
        "severity": "LOW",
        "title": "libscene.so / libgeometry.so substitution (inherited from 4.4.4)",
        "detail": (
            "Same firmware-path library substitution surface as VMD-04 and LG-02. "
            "libscene.so, libgeometry.so, libfixmath.so.0 loaded from firmware path. "
            "aarch64 architecture: bypasses any ARM32-specific exploit mitigations "
            "but reduces legacy ROP gadget availability."
        ),
        "libs": ["libscene.so", "libgeometry.so", "libfixmath.so.0"],
        "prerequisite": "Write access to library search path directory",
        "status": "UNPATCHED",
        "cve": None,
    },
]
