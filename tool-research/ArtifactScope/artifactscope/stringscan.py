from __future__ import annotations

import re
from typing import Dict, List


URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")

SUSPICIOUS_TERMS = [
    "powershell",
    "cmd.exe",
    "/bin/sh",
    "/bin/bash",
    "wget",
    "curl",
    "nc ",
    "ncat",
    "netcat",
    "eval(",
    "exec(",
    "system(",
    "token",
    "password",
    "secret",
    "flag",
    "base64",
]


def extract_ascii_strings(data: bytes, min_length: int = 4, max_results: int = 500) -> List[str]:
    pattern = re.compile(rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}")
    strings = [m.decode("utf-8", errors="replace") for m in pattern.findall(data)]
    return strings[:max_results]


def analyze_strings(data: bytes, max_results: int = 500) -> Dict[str, List[str]]:
    strings = extract_ascii_strings(data, max_results=max_results)
    joined = "\n".join(strings)

    urls = _unique(URL_RE.findall(joined))
    emails = _unique(EMAIL_RE.findall(joined))
    ips = _unique([ip for ip in IP_RE.findall(joined) if _valid_ipv4(ip)])
    base64_like = _unique(BASE64_RE.findall(joined))
    suspicious = _unique([s for s in strings if any(term.lower() in s.lower() for term in SUSPICIOUS_TERMS)])

    return {
        "sample_strings": strings[:50],
        "urls": urls[:50],
        "emails": emails[:50],
        "ips": ips[:50],
        "base64_like": base64_like[:50],
        "suspicious_strings": suspicious[:50],
    }


def _unique(items: List[str]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _valid_ipv4(ip: str) -> bool:
    try:
        parts = [int(p) for p in ip.split(".")]
    except ValueError:
        return False
    return len(parts) == 4 and all(0 <= p <= 255 for p in parts)
