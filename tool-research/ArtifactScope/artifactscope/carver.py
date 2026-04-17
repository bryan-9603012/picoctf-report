from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

from .utils import ensure_dir


@dataclass
class CarvePattern:
    name: str
    extension: str
    start_magic: bytes
    end_magic: bytes | None


PATTERNS = [
    CarvePattern("PNG image", ".png", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82"),
    CarvePattern("JPEG image", ".jpg", b"\xff\xd8\xff", b"\xff\xd9"),
    CarvePattern("PDF document", ".pdf", b"%PDF", b"%%EOF"),
    CarvePattern("ZIP archive", ".zip", b"PK\x03\x04", None),
    CarvePattern("ELF executable", ".elf", b"\x7fELF", None),
    CarvePattern("PE executable", ".exe", b"MZ", None),
]


def discover_embedded(data: bytes) -> List[dict]:
    findings: List[dict] = []
    for pattern in PATTERNS:
        start = 0
        while True:
            idx = data.find(pattern.start_magic, start)
            if idx == -1:
                break

            end_offset = None
            if pattern.end_magic:
                end_idx = data.find(pattern.end_magic, idx + len(pattern.start_magic))
                if end_idx != -1:
                    end_offset = end_idx + len(pattern.end_magic)

            findings.append({
                "name": pattern.name,
                "extension": pattern.extension,
                "offset": idx,
                "end_offset": end_offset,
            })
            start = idx + 1
    findings.sort(key=lambda x: x["offset"])
    return findings


def carve_embedded(data: bytes, out_dir: Path, source_name: str) -> List[dict]:
    ensure_dir(out_dir)
    findings = discover_embedded(data)
    carved = []

    for idx, item in enumerate(findings, start=1):
        start = item["offset"]
        end = item["end_offset"] if item["end_offset"] is not None else min(len(data), start + 1024 * 1024)
        chunk = data[start:end]
        out_name = f"{Path(source_name).stem}_carved_{idx:03d}{item['extension']}"
        out_path = out_dir / out_name
        out_path.write_bytes(chunk)

        carved.append({
            **item,
            "output_path": str(out_path),
            "size": len(chunk),
        })

    return carved
