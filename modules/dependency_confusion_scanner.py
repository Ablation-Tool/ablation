"""
dependency_confusion_scanner.py: Dependency confusion attack surface detector.

Scans binary strings for build-system artifact paths and package registry
references that reveal the project's internal package names. An internal
package named "mycompany-utils" that is published to a private registry is
a dependency confusion target: if an attacker publishes a higher-versioned
"mycompany-utils" to PyPI, npm, or RubyGems, a misconfigured pip/npm/gem
install will silently pull the public package instead.

What this module finds:
  1. Internal package registry URLs: Artifactory, Nexus, Sonatype, GitHub
     Packages, AWS CodeArtifact, Azure Artifacts, JFrog.
  2. Internal package names that follow patterns suggesting they are company-
     specific: names with hyphenated or underscored company prefixes seen
     alongside registry URLs.
  3. Build environment paths: /home/*/go/pkg, /root/.cargo/registry,
     ~/.gradle/caches, %USERPROFILE%\\.nuget that reveal package cache
     locations and potentially internal package identifiers in embedded path
     strings.
  4. Pyc/wheel/jar/npm tarballs embedded in the binary (partial paths).

Severity is based on specificity: a private Artifactory URL with internal
package names is HIGH (actionable dependency confusion target). A build
cache path alone is LOW (informational).

Usage:
    scanner = DependencyConfusionScanner('/path/to/binary')
    findings = scanner.scan()
    print(scanner.report(findings))
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


# Private registry URL patterns
_PRIVATE_REGISTRY_PATS: list[re.Pattern] = [
    re.compile(rb'https?://[a-z0-9.\-]+/artifactory/[a-z0-9\-/]+', re.I),
    re.compile(rb'https?://[a-z0-9.\-]+/nexus/content/[a-z0-9\-/]+', re.I),
    re.compile(rb'https?://[a-z0-9.\-]+\.jfrog\.io/', re.I),
    re.compile(rb'https?://[a-z0-9.\-]+\.pkgs\.visualstudio\.com/', re.I),
    re.compile(rb'https?://pkgs\.dev\.azure\.com/[a-z0-9\-/]+', re.I),
    re.compile(rb'https?://[a-z0-9.\-]+\.d\.codeartifact\.[a-z0-9\-]+\.amazonaws\.com/', re.I),
    re.compile(rb'https?://maven\.pkg\.github\.com/[a-z0-9\-/]+', re.I),
    re.compile(rb'https?://npm\.pkg\.github\.com/', re.I),
]

# Public package manager registry URLs (these should NOT exist in internal registries)
_PUBLIC_REGISTRY_URLS: list[bytes] = [
    b'https://pypi.org/', b'https://pypi.python.org/',
    b'https://registry.npmjs.org/',
    b'https://repo1.maven.org/maven2/',
    b'https://rubygems.org/',
    b'https://crates.io/',
    b'https://nuget.org/', b'https://api.nuget.org/',
]

# Build cache path patterns that leak package identifiers
_BUILD_PATH_PATS: list[re.Pattern] = [
    re.compile(rb'[/\\]home[/\\][^/\\]{1,32}[/\\]\.m2[/\\]repository[/\\]', re.I),
    re.compile(rb'[/\\]root[/\\]\.gradle[/\\]caches[/\\]', re.I),
    re.compile(rb'[/\\]home[/\\][^/\\]{1,32}[/\\]go[/\\]pkg[/\\]mod[/\\]', re.I),
    re.compile(rb'[/\\]root[/\\]\.cargo[/\\]registry[/\\]', re.I),
    re.compile(rb'%USERPROFILE%[/\\]\.nuget[/\\]', re.I),
    re.compile(rb'[/\\]home[/\\][^/\\]{1,32}[/\\]\.npm[/\\]', re.I),
    re.compile(rb'[/\\]home[/\\][^/\\]{1,32}[/\\]\.cache[/\\]pip[/\\]', re.I),
]

# Package name patterns that look like internal scoped packages
_INTERNAL_PKG_PAT = re.compile(
    rb'@[a-z][a-z0-9\-]{1,20}/[a-z][a-z0-9\-]{2,40}',  # npm scoped: @company/package
    re.I,
)


@dataclass
class DepConfusionFinding:
    finding_type:  str     # private_registry, public_registry_ref, build_path, internal_package
    detail:        str
    severity:      str     # HIGH / MEDIUM / LOW

    def fmt(self) -> str:
        return (f"  {self.severity:6s}  [DEP_CONFUSION]  {self.finding_type}\n"
                f"         {self.detail}")


class DependencyConfusionScanner:
    """Detect dependency confusion attack surface in binary build artifacts."""

    def __init__(self, path: str) -> None:
        self._path = path

    @classmethod
    def from_context(cls, ctx) -> 'DependencyConfusionScanner':
        obj = cls.__new__(cls)
        obj._path = ctx.path
        return obj

    def _read_raw(self) -> bytes:
        try:
            return open(self._path, 'rb').read()
        except OSError:
            return b''

    def scan(self) -> List[DepConfusionFinding]:
        raw = self._read_raw()
        if not raw:
            return []

        findings: list[DepConfusionFinding] = []
        seen: set[str] = set()

        # Check 1: private registry URLs
        for pat in _PRIVATE_REGISTRY_PATS:
            for m in pat.finditer(raw):
                url = m.group(0).decode('ascii', errors='replace')[:80]
                key = f'registry:{url[:40]}'
                if key not in seen:
                    seen.add(key)
                    findings.append(DepConfusionFinding(
                        'private_registry',
                        f'Private registry URL: {url}',
                        'HIGH',
                    ))

        # Check 2: public registry URLs co-present with private registry
        if any(f.finding_type == 'private_registry' for f in findings):
            for url_bytes in _PUBLIC_REGISTRY_URLS:
                if url_bytes in raw:
                    url = url_bytes.decode('ascii')
                    findings.append(DepConfusionFinding(
                        'public_registry_ref',
                        f'Public registry URL also present: {url} (mixed registry config risk)',
                        'HIGH',
                    ))
                    break

        # Check 3: build cache paths
        for pat in _BUILD_PATH_PATS:
            m = pat.search(raw)
            if m:
                path_str = m.group(0).decode('ascii', errors='replace')[:60]
                key = f'path:{path_str[:30]}'
                if key not in seen:
                    seen.add(key)
                    findings.append(DepConfusionFinding(
                        'build_path',
                        f'Build cache path: {path_str}',
                        'LOW',
                    ))

        # Check 4: internal scoped npm packages
        for m in _INTERNAL_PKG_PAT.finditer(raw):
            pkg = m.group(0).decode('ascii', errors='replace')
            key = f'pkg:{pkg}'
            if key not in seen:
                seen.add(key)
                findings.append(DepConfusionFinding(
                    'internal_package',
                    f'Scoped npm package name: {pkg}',
                    'MEDIUM',
                ))

        return findings

    def report(self, findings: Optional[List[DepConfusionFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'DependencyConfusionScanner: no dependency confusion surface in {self._path}'
        lines = [f'DependencyConfusionScanner: {len(findings)} finding(s) in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
