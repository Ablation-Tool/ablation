"""Unit tests for EmbeddedRootfsScanner.

Tests exercise the scanner against temporary rootfs directory trees.
Each test creates a minimal /etc structure with specific security
signals and asserts the expected findings are produced.
"""

import pathlib
import tempfile

import pytest

from ablation.analyzers.embedded_rootfs_scanner import (
    EmbeddedRootfsScanner,
    RootfsFinding,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def make_rootfs(files: dict[str, str]) -> pathlib.Path:
    """
    Create a temporary rootfs directory from a path→content mapping.

    Keys may use nested paths, e.g. 'etc/shadow'. The tmpdir is automatically
    cleaned up when the test ends; call site must hold the reference.
    """
    d = pathlib.Path(tempfile.mkdtemp(prefix='ablation_rootfs_test_'))
    for rel_path, content in files.items():
        target = d / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    return d


def scan(rootfs: pathlib.Path) -> list[RootfsFinding]:
    return EmbeddedRootfsScanner.from_dir(str(rootfs)).scan()


def titles(findings: list[RootfsFinding]) -> list[str]:
    return [f.title for f in findings]


# ── credential tests ──────────────────────────────────────────────────────────

def test_empty_root_password_detected() -> None:
    """Empty password field in /etc/shadow (root::...) → HIGH CREDENTIAL finding."""
    d = make_rootfs({'etc/shadow': 'root::15069:0:99999:7:::\n'})
    findings = scan(d)
    assert any(f.severity == 'HIGH' and f.category == 'CREDENTIAL' for f in findings), (
        f'Expected HIGH CREDENTIAL, got: {[(f.severity, f.category, f.title) for f in findings]}'
    )


def test_empty_password_title_names_user() -> None:
    """Finding title includes the username with the empty password."""
    d = make_rootfs({'etc/shadow': 'root::15069:0:99999:7:::\n'})
    findings = scan(d)
    cred = next((f for f in findings if f.category == 'CREDENTIAL'), None)
    assert cred is not None
    assert 'root' in cred.title.lower()


def test_non_empty_password_not_flagged() -> None:
    """A properly hashed root password should not produce a CREDENTIAL finding."""
    hashed = '$6$salt$hashedpassword1234'
    d = make_rootfs({'etc/shadow': f'root:{hashed}:15069:0:99999:7:::\n'})
    findings = scan(d)
    cred = [f for f in findings if f.category == 'CREDENTIAL']
    assert not cred, f'Unexpected CREDENTIAL findings: {cred}'


def test_multiple_empty_passwords_all_found() -> None:
    """Multiple users with empty passwords should all be flagged."""
    d = make_rootfs({'etc/shadow': (
        'root::15069:0:99999:7:::\n'
        'admin::15069:0:99999:7:::\n'
        'user1:$6$hash:15069:0:99999:7:::\n'
    )})
    findings = scan(d)
    cred = [f for f in findings if f.category == 'CREDENTIAL']
    assert len(cred) >= 2, f'Expected >= 2 CREDENTIAL findings, got {len(cred)}'


# ── inetd tests ───────────────────────────────────────────────────────────────

def test_inetd_telnet_detected() -> None:
    """telnet service in /etc/inetd.conf → HIGH INETD finding."""
    d = make_rootfs({'etc/inetd.conf': 'telnet\tstream\ttcp\tnowait\troot\ttelnetd\ttelnetd -i\n'})
    findings = scan(d)
    inetd = [f for f in findings if f.category == 'INETD']
    assert inetd, f'Expected INETD finding, got: {[(f.category, f.title) for f in findings]}'
    assert inetd[0].severity == 'HIGH'


def test_inetd_rsh_detected() -> None:
    """rsh in /etc/inetd.conf (remote shell) → HIGH INETD finding."""
    d = make_rootfs({'etc/inetd.conf': 'shell\tstream\ttcp\tnowait\troot\t/usr/sbin/in.rshd\tin.rshd\n'})
    findings = scan(d)
    inetd = [f for f in findings if f.category == 'INETD']
    assert inetd, 'Expected INETD finding for rsh/shell service'


def test_inetd_comment_ignored() -> None:
    """Lines starting with # in inetd.conf should be ignored."""
    d = make_rootfs({'etc/inetd.conf': '# telnet stream tcp nowait root telnetd telnetd\n'})
    findings = scan(d)
    inetd = [f for f in findings if f.category == 'INETD']
    assert not inetd, f'Comment line should not produce INETD finding: {inetd}'


def test_inetd_safe_service_not_flagged() -> None:
    """A non-dangerous service (e.g. time) in inetd.conf should not produce HIGH/MEDIUM findings."""
    d = make_rootfs({'etc/inetd.conf': 'time\tstream\ttcp\tnowait\troot\t/usr/sbin/in.timed\tin.timed\n'})
    findings = scan(d)
    # Scanner may emit INFO for unknown services; only HIGH/MEDIUM indicate dangerous svc
    high_medium = [f for f in findings if f.category == 'INETD' and f.severity in ('HIGH', 'MEDIUM')]
    assert not high_medium, f'Safe service should not produce HIGH/MEDIUM INETD finding: {high_medium}'


# ── SSH config tests ──────────────────────────────────────────────────────────

def test_ssh_permit_root_login_detected() -> None:
    """PermitRootLogin yes in sshd_config → SSH finding."""
    d = make_rootfs({'etc/ssh/sshd_config': 'PermitRootLogin yes\nPasswordAuthentication yes\n'})
    findings = scan(d)
    ssh = [f for f in findings if f.category == 'SSH']
    assert ssh, f'Expected SSH finding, got: {[(f.category, f.title) for f in findings]}'


def test_ssh_permit_root_no_not_flagged() -> None:
    """PermitRootLogin no should not produce an SSH finding."""
    d = make_rootfs({'etc/ssh/sshd_config': 'PermitRootLogin no\n'})
    findings = scan(d)
    ssh = [f for f in findings if f.category == 'SSH']
    assert not ssh, f'PermitRootLogin no should not be flagged: {ssh}'


# ── systemd autostart tests ───────────────────────────────────────────────────

def test_tcf_agent_autostart_detected() -> None:
    """tcf-agent.service in multi-user.target.wants → HIGH SERVICE finding."""
    d = make_rootfs({
        'etc/systemd/system/multi-user.target.wants/tcf-agent.service': '[Unit]\nDescription=TCF\n'
    })
    findings = scan(d)
    service = [f for f in findings if f.category == 'DEBUG']
    assert service, f'Expected DEBUG finding for tcf-agent, got: {[(f.category, f.title) for f in findings]}'
    assert service[0].severity == 'HIGH'


def test_no_services_no_service_findings() -> None:
    """A rootfs with no systemd units produces no SERVICE findings."""
    d = make_rootfs({'etc/passwd': 'root:x:0:0:root:/root:/bin/sh\n'})
    # No multi-user.target.wants directory at all
    findings = scan(d)
    service = [f for f in findings if f.category in ('DEBUG', 'SERVICE', 'NFS')]
    assert not service, f'Unexpected service findings: {service}'


# ── IPBus shim tests ──────────────────────────────────────────────────────────

def test_ipbus_shim_port_and_address_extracted() -> None:
    """IPBus shim startup script with -p and -m args → SERVICE finding with port info."""
    d = make_rootfs({
        'usr/bin/runGepIpbusShim.sh': (
            '#!/bin/sh\n'
            'versalTcpIpbusShim -p 8061 -m 0x20200000000 &\n'
        )
    })
    findings = scan(d)
    service = [f for f in findings if 'IPBus' in f.title or 'ipbus' in f.title.lower()
               or 'shim' in f.title.lower() or 'shim' in f.detail.lower()]
    assert service, (
        f'Expected IPBus shim finding, got: {[(f.title, f.detail[:60]) for f in findings]}'
    )


# ── severity ordering tests ───────────────────────────────────────────────────

def test_findings_sorted_by_severity() -> None:
    """scan() returns findings sorted HIGH → MEDIUM → LOW → INFO."""
    order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}
    d = make_rootfs({
        'etc/shadow': 'root::15069:0:99999:7:::\n',
        'etc/inetd.conf': 'telnet\tstream\ttcp\tnowait\troot\ttelnetd\ttelnetd\n',
    })
    findings = scan(d)
    ranks = [order.get(f.severity, 99) for f in findings]
    assert ranks == sorted(ranks), f'Findings not sorted by severity: {[f.severity for f in findings]}'


# ── no-findings case ──────────────────────────────────────────────────────────

def test_clean_rootfs_no_findings() -> None:
    """A rootfs with no security signals produces no findings."""
    hashed = '$6$salt$somehashvalue'
    d = make_rootfs({
        'etc/shadow': f'root:{hashed}:15069:0:99999:7:::\n',
        'etc/ssh/sshd_config': 'PermitRootLogin no\nPasswordAuthentication no\n',
    })
    findings = scan(d)
    assert not findings, f'Unexpected findings on clean rootfs: {[(f.severity, f.title) for f in findings]}'


# ── report smoke test ─────────────────────────────────────────────────────────

def test_report_string_output() -> None:
    """report() returns a non-empty string without raising."""
    d = make_rootfs({'etc/shadow': 'root::15069:0:99999:7:::\n'})
    scanner = EmbeddedRootfsScanner.from_dir(str(d))
    findings = scanner.scan()
    out = scanner.report(findings)
    assert isinstance(out, str)
    assert 'HIGH' in out
