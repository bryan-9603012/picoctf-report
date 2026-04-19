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

GIT_PATTERNS = [
    ".git",
    ".git/HEAD",
    ".git/index",
    ".git/config",
    ".git/refs",
    "refs/heads",
    "refs/tags",
    "refs/remotes",
    "HEAD",
    "commit ",
    "Author: ",
    "Date: ",
    "git-svn-id",
    "gitdir:",
    "objects/",
    "packed-refs",
    "tree ",
    "blob ",
]

GIT_INDICATOR_STRINGS = [
    ".git/HEAD",
    ".git/index",
    ".git/config",
    ".git/refs/heads",
    "refs/heads/",
    "refs/tags/",
    "packed-refs",
    "objects/",
    "gitdir:",
]

GIT_FILES = [
    ".git/HEAD",
    ".git/index",
    ".git/config",
    ".git/objects",
    ".git/refs/heads",
    ".git/hooks",
    ".git/logs",
]

FLAG_PATTERNS = [
    "picoCTF{",
    "flag{",
    "CTF{",
    "actf{",
    "dctf{",
]

FLAG_REGEXES = [
    r"picoCTF\{[^}\r\n]{1,100}\}",
    r"flag\{[^}\r\n]{1,100}\}",
    r"ACTF\{[^}\r\n]{1,100}\}",
    r"DCTF\{[^}\r\n]{1,100}\}",
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


def detect_git_artifacts(strings: List[str], sample_strings: List[str]) -> Dict[str, object]:
    all_text = "\n".join(sample_strings) + "\n" + "\n".join(strings)

    found_git_files = []
    for pattern in GIT_FILES:
        if pattern in all_text or pattern.replace("/", "\\") in all_text:
            found_git_files.append(pattern)

    found_indicators = []
    for indicator in GIT_INDICATOR_STRINGS:
        if indicator in all_text or indicator.replace("/", "\\") in all_text:
            found_indicators.append(indicator)

    found_git_refs = []
    refs_pattern = re.compile(r"refs/(heads|tags|remotes)/[^\s]+")
    for s in strings:
        for m in refs_pattern.findall(s):
            found_git_refs.append(s)

    found_commits = []
    commit_hash = re.compile(r"[0-9a-f]{40}|\b[0-9a-f]{7,40}\b")
    for s in strings:
        if commit_hash.match(s) and len(s) <= 50:
            found_commits.append(s[:50])

    total_indicators = len(found_git_files) + len(found_indicators)
    if total_indicators >= 3:
        confidence = "high"
    elif total_indicators >= 1:
        confidence = "medium"
    else:
        confidence = "none"

    return {
        "git_files": _unique(found_git_files),
        "git_related_strings": _unique(found_indicators),
        "git_refs": _unique(found_git_refs)[:20],
        "commit_hashes": _unique(found_commits)[:20],
        "confidence": confidence,
        "indicator_count": total_indicators,
    }


def detect_flag_patterns(strings: List[str], all_text: str = "") -> List[Dict[str, str]]:
    flags = []
    seen = set()

    for pattern in FLAG_REGEXES:
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            for match in regex.finditer(all_text):
                flag_str = match.group(0)
                if flag_str not in seen and len(flag_str) < 100:
                    flags.append({
                        "pattern": pattern_str,
                        "match": flag_str,
                    })
                    seen.add(flag_str)
        except:
            pass

    for pattern_str in FLAG_PATTERNS:
        for s in strings:
            if pattern_str.lower() in s.lower():
                if s not in seen:
                    flags.append({
                        "pattern": pattern_str,
                        "match": s[:200],
                    })
                    seen.add(s)
            if pattern_str.lower() in all_text.lower():
                idx = all_text.lower().find(pattern_str.lower())
                if idx != -1:
                    match_end = idx + 200
                    snippet = all_text[idx:match_end]
                    if snippet not in seen:
                        flags.append({
                            "pattern": pattern_str,
                            "match": snippet,
                        })
                        seen.add(snippet)

    return flags[:50]
