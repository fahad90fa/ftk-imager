from __future__ import annotations

import subprocess
from pathlib import Path


def _mount_options_for_fstype(fstype: str | None) -> str:
    # Default to strict read-only and reduce risk if something goes wrong.
    # Note: noexec does not prevent all writes, but it reduces accidental execution from evidence.
    base = ["ro", "nosuid", "nodev", "noexec"]
    if not fstype:
        return ",".join(base)

    fs = fstype.lower()
    # ext* supports noload (do not replay journal). This is desirable for forensic read-only mounts.
    if fs in {"ext2", "ext3", "ext4"}:
        return ",".join(base + ["noload"])

    return ",".join(base)


def mount_image_readonly(image_path: Path, mount_point: Path, offset: int = 0, fstype: str | None = None) -> str:
    mount_point.mkdir(parents=True, exist_ok=True)

    cmd = ["losetup", "--find", "--show", "--read-only"]
    if offset > 0:
        cmd.extend(["-o", str(offset)])
    cmd.append(str(image_path))
    cp = subprocess.run(cmd, check=True, capture_output=True, text=True)
    loopdev = cp.stdout.strip()

    mount_cmd = ["mount", "-o", _mount_options_for_fstype(fstype)]
    if fstype:
        mount_cmd.extend(["-t", fstype])
    mount_cmd.extend([loopdev, str(mount_point)])
    try:
        subprocess.run(mount_cmd, check=True)
    except Exception:
        subprocess.run(["losetup", "-d", loopdev], check=False)
        raise

    return loopdev


def unmount_image(mount_point: Path, loopdev: str | None = None) -> None:
    subprocess.run(["umount", str(mount_point)], check=True)
    if loopdev:
        subprocess.run(["losetup", "-d", loopdev], check=True)
