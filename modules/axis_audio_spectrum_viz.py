"""
AXIS Audio Spectrum Visualizer (AudioSpectrumVisualizer) — RE findings
CONTROLLED ENVIRONMENT ONLY

Affected: AXIS Audio Spectrum Visualizer (AudioSpectrumVisualizer), appId 413132
Version: 2.3.0  Arch: aarch64 stripped
LICENSEPAGE: none  No admin CGI — parameter-driven only.

Reads audio from camera microphone, renders spectrum overlay.
cairo rendering library used for video overlay.
"""

# CONTROLLED ENVIRONMENT ONLY

FINDING = "AXIS-ASV"
LABEL = "AudioSpectrumVisualizer: spectrum param overflow, cairo OOB rendering"

FINDINGS = [
    {
        "id": "AXIS-ASV-01",
        "severity": "LOW",
        "title": "Integer overflow in spectrum parameter parsing",
        "detail": (
            "'Unable to parse parameter %s = %s as an integer' confirms integer parameter reads from axparam. "
            "'Invalid value of parameter Channel1SpectrumAnalyzerPosition' identifies specific named param. "
            "If operator sets extreme integer value (INT_MAX, negative overflow) for spectrum parameter: "
            "integer overflow in audio spectrum calculation -> "
            "undefined behavior in spectrum bin sizing or FFT buffer allocation."
        ),
        "param": "Channel1SpectrumAnalyzerPosition (and other integer axparams)",
        "prerequisite": "Operator-level axparam write",
        "status": "UNPATCHED",
        "cve": None,
    },
    {
        "id": "AXIS-ASV-02",
        "severity": "LOW",
        "title": "Cairo OOB rendering via unchecked audio frequency bins",
        "detail": (
            "Audio frequency bins fed to cairo rendering calls for spectrum overlay. "
            "If bin magnitude values are not range-checked before cairo draw coordinates: "
            "cairo_rectangle or cairo_move_to receives OOB coordinates -> "
            "cairo crash or OOB write in rendering surface. "
            "Triggerable by audio input to the camera microphone with specific frequency profile (physical attack)."
        ),
        "lib": "libcairo.so.2",
        "prerequisite": "Control of audio input to camera microphone (physical access) or extreme axparam value",
        "status": "UNPATCHED",
        "cve": None,
    },
]
