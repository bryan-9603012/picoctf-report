from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

FDISK_PART_RE = re.compile(
    r"^(?P<dev>\S+)\s+(?P<boot>\*)?\s*"
    r"(?P<start>\d+)\s+(?P<end>\d+)\s+(?P<sectors>\d+)\s+"
    r"(?P<size>\S+)\s+(?P<id>\S+)\s+(?P<type>.+)$"
)

RAW_GIT_PATTERNS = [
    (b".git/config", "config file"),
    (b"refs/heads/", "branch reference"),
    (b"packed-refs", "packed refs"),
    (b"ref: refs/", "HEAD reference"),
]

RAW_FLAG_PATTERNS = [
    re.compile(rb"picoCTF\{[^}\r\n]{1,120}\}"),
    re.compile(rb"flag\{[^}\r\n]{1,120}\}", re.IGNORECASE),
    re.compile(rb"ctf\{[^}\r\n]{1,120}\}", re.IGNORECASE),
]


def _run(cmd: List[str], timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _extract_partition_number(dev: str) -> int:
    m = re.search(r"(\d+)$", dev)
    return int(m.group(1)) if m else 0


def parse_partition_info(image_path: Path) -> List[Dict[str, object]]:
    try:
        proc = _run(["fdisk", "-l", str(image_path)], timeout=20)
    except Exception:
        return []

    parts: List[Dict[str, object]] = []

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or image_path.name not in line:
            continue

        m = FDISK_PART_RE.match(line)
        if not m:
            continue

        start = int(m.group("start"))
        sectors = int(m.group("sectors"))
        offset_bytes = start * 512
        size_bytes = sectors * 512
        ptype = m.group("type").strip()

        fs_type = "Unknown"
        if "Linux swap" in ptype:
            fs_type = "Linux swap"
        elif "Linux" in ptype:
            fs_type = "Linux"
        elif "NTFS" in ptype:
            fs_type = "NTFS"
        elif "FAT" in ptype:
            fs_type = "FAT"

        dev = m.group("dev")
        part_no = _extract_partition_number(dev)

        parts.append(
            {
                "partition": part_no,
                "active": bool(m.group("boot")),
                "offset_bytes": offset_bytes,
                "size_bytes": size_bytes,
                "size_mb": round(size_bytes / (1024 * 1024)),
                "fs_type": fs_type,
                "type": ptype,
            }
        )

    return parts


def search_git_in_raw_data(data: bytes, limit: int = 20) -> List[Dict[str, object]]:
    hits: List[Dict[str, object]] = []

    for needle, marker in RAW_GIT_PATTERNS:
        start = 0
        while True:
            idx = data.find(needle, start)
            if idx == -1:
                break
            hits.append({"marker": marker, "offset": idx})
            if len(hits) >= limit:
                return hits
            start = idx + 1

    return hits


def _is_ascii_mostly(text: str, threshold: float = 0.92) -> bool:
    if not text:
        return False
    printable = sum(1 for ch in text if 32 <= ord(ch) <= 126)
    return (printable / len(text)) >= threshold


def search_flag_in_raw_data(data: bytes, limit: int = 20) -> List[Dict[str, object]]:
    hits: List[Dict[str, object]] = []

    for pat in RAW_FLAG_PATTERNS:
        for m in pat.finditer(data):
            raw = m.group()
            text = raw.decode("latin-1", errors="replace")

            if not _is_ascii_mostly(text):
                continue

            if "{" not in text or not text.endswith("}"):
                continue

            inner = text[text.find("{") + 1 : -1]
            if not inner or len(inner) > 100:
                continue

            hits.append(
                {
                    "pattern": pat.pattern.decode(errors="ignore")
                    if isinstance(pat.pattern, bytes)
                    else str(pat.pattern),
                    "match": text,
                    "offset": m.start(),
                }
            )
            if len(hits) >= limit:
                return hits

    return hits


def _is_mounted(path: Path) -> bool:
    try:
        proc = _run(["mount"], timeout=10)
        return str(path) in proc.stdout
    except Exception:
        return False


def _safe_umount(path: Path) -> None:
    if _is_mounted(path):
        _run(["sudo", "umount", str(path)], timeout=10)


def _safe_detach_loop(loop_dev: Optional[str]) -> None:
    if loop_dev and loop_dev.startswith("/dev/loop"):
        _run(["sudo", "losetup", "-d", loop_dev], timeout=10)


def get_mount_point(image_path: Path, offset: int, fs_type: str, size_bytes: int = 0) -> Optional[Path]:
    if fs_type not in ("Linux", "ext", "NTFS", "FAT"):
        return None

    mount_root = Path("/tmp/artifactscope")
    mount_root.mkdir(parents=True, exist_ok=True)
    mount_path = mount_root / f"part_{offset}"
    mount_path.mkdir(parents=True, exist_ok=True)

    if _is_mounted(mount_path):
        return mount_path

    _safe_umount(mount_path)

    direct = _run(
        [
            "sudo",
            "mount",
            "-o",
            f"loop,ro,offset={offset}",
            str(image_path),
            str(mount_path),
        ],
        timeout=20,
    )
    if direct.returncode == 0 and _is_mounted(mount_path):
        return mount_path

    loop_dev = None
    try:
        cmd = ["sudo", "losetup", "-f", "--show", "-r", "-o", str(offset)]
        if size_bytes > 0:
            cmd.extend(["--sizelimit", str(size_bytes)])
        cmd.append(str(image_path))

        proc = _run(cmd, timeout=20)
        if proc.returncode != 0:
            return None

        loop_dev = proc.stdout.strip()
        if not loop_dev:
            return None

        mount_proc = _run(["sudo", "mount", "-o", "ro", loop_dev, str(mount_path)], timeout=20)
        if mount_proc.returncode == 0 and _is_mounted(mount_path):
            return mount_path

        _safe_detach_loop(loop_dev)
        return None

    except Exception:
        _safe_detach_loop(loop_dev)
        return None


def extract_partitions_7z(image_path: Path) -> Dict[int, Path]:
    # 先保留最小 fallback 介面，避免 analyzer 壞掉
    return {}


def search_raw_for_flag(part_path: Path) -> Dict[str, object]:
    if not part_path.exists():
        return {"flag_candidates": []}

    try:
        data = part_path.read_bytes()
    except Exception:
        return {"flag_candidates": []}

    candidates = []
    for hit in search_flag_in_raw_data(data, limit=20):
        candidates.append(
            {
                "flag": hit["match"],
                "offset": hit["offset"],
            }
        )

    return {"flag_candidates": candidates}