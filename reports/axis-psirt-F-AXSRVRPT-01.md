# AXIS OS — Viewer-Level Access to Full Device Diagnostic Report

**Severity:** Medium  
**CWE:** CWE-269 (Improper Privilege Management)  
**CVSS 3.1:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N — 6.5  
**Affected versions:** AXIS OS 9.x – 12.x (confirmed across 3 major version branches)  
**Affected products:** Platform-wide — all products shipping `serverreport.cgi`

---

## Summary

AXIS OS exposes `serverreport.cgi` to any authenticated viewer-level user. The VAPIX API documentation specifies that `serverreport.cgi` requires an operator-level account minimum. The shell CGI implementation has no auth check and inherits the parent `/usr/html` Apache directive (`Require axis-group-file`) which allows any authenticated user — including viewers. A viewer-level account can download a diagnostic bundle containing every VAPIX account name and privilege role, every ONVIF account name, all installed TLS certificate CNs, full system logs including `auth.log` and `audit.json`, and (via `mode=tar_all`) all merged log files since last rotation.

---

## Affected Component

**File:** `/usr/html/axis-cgi/serverreport.cgi`

Shell script. No auth library. No APAC reference. No Apache `Require` override for this CGI.

**Parent auth directive** (`/etc/apache2/httpd-basic-auth.conf`):

```apache
<Directory "/usr/html">
    Include /etc/apache2/httpd-basic.conf
    Require axis-group-file
</Directory>
```

`axis-group-file` — any user present in the device auth file (viewer, operator, or admin). `serverreport.cgi` has no stricter `Require` in any Apache conf fragment, so it inherits this minimum.

**VAPIX documentation** specifies `operator` as the minimum group for this endpoint. The CGI does not enforce it.

---

## Data Exposed at Viewer Level

All items below are accessible to any valid viewer credential:

**`mode=text` (plain text report via `gen_serverreport.sh`):**
- Device serial number (bootblocktool SERNO)
- Processor serial number
- MAC address
- Complete VAPIX user list — all usernames and their privilege roles (viewer/operator/admin)
- Complete ONVIF user list
- All installed TLS certificate CNs
- Full root parameter tree (passwords masked, all other parameters in cleartext)
- System logs: info, warning, error, critical, segfault (rotated)
- `auth.log` — authentication events
- Kernel crash logs (via `klog` / `secondary-klog`)

**`mode=zip` / `mode=zip_with_image`:**
Same as text, packaged as ZIP. `zip_with_image` additionally captures a live JPEG snapshot from the camera at the time of the request.

**`mode=tar_all`** (12.x only, via `prepare_files`):
All of the above plus merged log archives from `/usr/local/`, `/var/lib/syslog-ng/`, `/var/log/`. This includes `audit.json` — the same data that `auditlog.cgi` gates behind admin access via `getgrnam`.

---

## Proof of Concept

Replace `<IP>` and `<viewer:password>` with the device address and a viewer credential. Digest auth is the default on most AXIS OS devices.

**Read the device report (text):**
```
GET /axis-cgi/serverreport.cgi?mode=text HTTP/1.1
Host: <IP>
Authorization: Digest <viewer credentials>
```

**Download full ZIP with live snapshot:**
```
GET /axis-cgi/serverreport.cgi?mode=zip_with_image HTTP/1.1
Host: <IP>
Authorization: Digest <viewer credentials>
```

**Download merged logs including audit.json (12.x):**
```
GET /axis-cgi/serverreport.cgi?mode=tar_all HTTP/1.1
Host: <IP>
Authorization: Digest <viewer credentials>
```

curl equivalents in attached `poc_F-AXSRVRPT-01.sh`.

---

## Impact

VAPIX user enumeration is the highest-impact item: a viewer can extract every account name and its privilege role from the device. This directly enables targeted credential attacks against the operator and admin accounts — the viewer learns the exact target usernames before attempting any credential stuffing or brute-force.

The `auth.log` disclosure shows recent authentication activity (timestamps, source IPs, success/failure), enabling an attacker to infer operational patterns. `audit.json` contains the same data that requires admin access when fetched via the dedicated `auditlog.cgi` endpoint — `serverreport.cgi` bypasses that gate entirely via `mode=tar_all`.

The `zip_with_image` snapshot allows a viewer to capture a timestamped camera frame without triggering any admin-visible recording event (the snapshot is taken directly, not via the event system).

---

## Confirmed Affected Products

Verified by static analysis of extracted firmware rootfs. `serverreport.cgi` is a shell script; the code is identical in all versions except for the addition of `tar_all` and `tar_kernel_log` modes in 11.x+.

| Product | Version | Notes |
|---|---|---|
| AXIS Companion Bullet LE | 9.80.132 | ARMv7hf; 9.x baseline — zip/zip_with_image modes |
| AXIS P3245-V | 11.11.220 | ARMv7hf; 11.x |
| AXIS A8207-VE | 11.11.220 | AArch64 |
| AXIS Q6215-LE | 10.9 CSB | ARMv7hf |
| AXIS Q1656 | 12.11.118 | AArch64; tar_all confirmed |
| AXIS P3945-R | 12.11.77 | AArch64 |
| AXIS P3947-R | 12.11.77 | AArch64 |
| AXIS M3945-R | 12.11.77 | AArch64 |
| AXIS M3138-LVE | 12.11.77 | AArch64 |
| AXIS F9114-R Mk II | 12.11.77 | AArch64 |
| AXIS D1110 Video Decoder 4K | 12.11.77 | AArch64 |
| AXIS C1710 Network Display Speaker | 12.11.77 | AArch64 |
| AXIS BW W102/W110/W120 | 12.10.59 | Body-worn; tar_all confirmed |

The pattern is a shell script with no auth library, inheriting the parent `/usr/html` Apache directive. This design has been present since at least AXIS OS 9.x (2020) and is not a regression — it was never restricted.

---

## Root Cause

`serverreport.cgi` is a plain shell script. It does not call any APAC or AXIS auth library function. There is no `Require axis-group operator` (or stricter) directive in any Apache configuration file for this endpoint. The CGI inherits `Require axis-group-file` — the `/usr/html` default, which permits any valid credential.

The VAPIX documentation specifies `operator` as the minimum required group. This is a documentation-to-implementation gap that has persisted across every major AXIS OS version.

**Fix:** Add an Apache `<Files serverreport.cgi>` or `<Location>` block that requires `axis-group operator` (or stronger). The CGI itself does not need changes — the fix belongs in the Apache layer.

```apache
<Files "serverreport.cgi">
    Require axis-group operator
</Files>
```

---

## Evidence

Static analysis only. No device was accessed.

All artifacts extracted from publicly available signed firmware images downloaded from axis.com/support/firmware. `serverreport.cgi` is a plain-text shell script present identically across all listed firmware versions (with minor additions in 12.x). `httpd-basic-auth.conf` is the upstream Apache include that sets the `/usr/html` auth default.

No credential was used. No device was connected. All findings are from offline firmware analysis.
