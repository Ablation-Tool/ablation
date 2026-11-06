#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import getpass
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess


SAFE_NAME = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")
SAFE_GROUP = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _text(value, label):
    if not isinstance(value, str) or not SAFE_NAME.fullmatch(value):
        raise ValueError(f"{label} must contain only letters, digits, underscore, dot, @, or hyphen")
    return value


def _directory(path, reader_group):
    path = Path(path).expanduser()
    root = os.geteuid() == 0
    if root and path != Path("/var/lib/zoe-unlock-guard"):
        raise ValueError("root captures must use /var/lib/zoe-unlock-guard")
    if root:
        group = grp.getgrnam(reader_group).gr_gid
        if not SAFE_GROUP.fullmatch(reader_group) or group == 0:
            raise ValueError("reader-group must name a non-root group")
    else:
        group = os.getgid()
    path.mkdir(parents=True, exist_ok=True)
    if root and (path.stat().st_uid != 0 or path.stat().st_mode & 0o022):
        raise ValueError("capture directory must be root-owned and not group/world-writable")
    os.chown(path, 0 if root else os.getuid(), group)
    os.chmod(path, 0o750 if root else 0o700)
    return path, group, root


def capture(output_dir, *, event, service, user, device="/dev/video0", reader_group=None, runner=subprocess.run):
    event = _text(event, "event")
    service = _text(service, "service")
    user = _text(user, "user")
    if event not in {"test", "failed-unlock"}:
        raise ValueError("event must be test or failed-unlock")
    device = Path(device)
    if os.geteuid() == 0:
        if not re.fullmatch(r"/dev/video\d+", str(device)) or not device.exists() or not stat.S_ISCHR(device.stat().st_mode):
            raise ValueError("root capture requires a real /dev/videoN character device")
    output, group, root = _directory(output_dir, reader_group)
    timestamp = datetime.now(timezone.utc)
    result = runner(
        [
            "/usr/bin/ffmpeg", "-hide_banner", "-loglevel", "error",
            "-f", "video4linux2", "-input_format", "mjpeg", "-video_size", "1280x720",
            "-i", str(device), "-frames:v", "1", "-q:v", "2", "-f", "image2pipe", "-vcodec", "mjpeg", "-",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    image = result.stdout
    error = result.stderr.decode("utf-8", "replace")[:500]
    valid = result.returncode == 0 and 1024 <= len(image) <= 16 * 1024 * 1024 and image.startswith(b"\xff\xd8") and image.endswith(b"\xff\xd9")
    record = {
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "event": event,
        "service": service,
        "user": user,
        "executed": "camera_capture" if valid else "camera_unavailable",
        "network": False,
        "face_recognition": False,
    }
    path = None
    if valid:
        path = output / f"{event}-{timestamp.strftime('%Y%m%dT%H%M%S.%fZ')}-{os.getpid()}.jpg"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640 if root else 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(image)
        os.chown(path, 0 if root else os.getuid(), group)
        os.chmod(path, 0o640 if root else 0o600)
        record["image"] = path.name
        record["sha256"] = hashlib.sha256(image).hexdigest()
    else:
        record["error"] = error or "camera returned no valid JPEG image"
    log = output / "events.jsonl"
    descriptor = os.open(log, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o640 if root else 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    os.chown(log, 0 if root else os.getuid(), group)
    os.chmod(log, 0o640 if root else 0o600)
    return path, record


def main(argv=None):
    parser = argparse.ArgumentParser(description="Capture one local image for an explicit test or failed PAM unlock attempt")
    events = parser.add_mutually_exclusive_group(required=True)
    events.add_argument("--test", action="store_true")
    events.add_argument("--failed-unlock", action="store_true")
    parser.add_argument("--output-dir", default=os.environ.get("ZOE_GUARD_OUTPUT", str(Path.home() / ".local/share/zoe-unlock-guard")))
    parser.add_argument("--device", default=os.environ.get("ZOE_GUARD_DEVICE", "/dev/video0"))
    parser.add_argument("--reader-group", default=os.environ.get("ZOE_GUARD_READER_GROUP"))
    arguments = parser.parse_args(argv)
    event = "failed-unlock" if arguments.failed_unlock else "test"
    service = os.environ.get("PAM_SERVICE", "manual-test")
    user = os.environ.get("PAM_USER", getpass.getuser())
    if os.geteuid() == 0 and arguments.output_dir == str(Path.home() / ".local/share/zoe-unlock-guard"):
        arguments.output_dir = "/var/lib/zoe-unlock-guard"
    reader_group = arguments.reader_group or user
    try:
        path, record = capture(arguments.output_dir, event=event, service=service, user=user, device=arguments.device, reader_group=reader_group)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Zoe unlock guard: {error}")
        return 0 if event == "failed-unlock" else 1
    if path is None:
        print("Zoe unlock guard: no image captured; see events.jsonl")
        return 0 if event == "failed-unlock" else 1
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
