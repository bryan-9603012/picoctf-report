from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional


FLAG_PATTERNS = [
    r"picoCTF\{[^}\r\n]{1,300}\}",
    r"flag\{[^}\r\n]{1,300}\}",
    r"ctf\{[^}\r\n]{1,300}\}",
]


def is_git_repo(path: Path) -> bool:
    head = path / ".git" / "HEAD"
    if not head.exists():
        return False
    try:
        content = head.read_text(errors="replace")
    except Exception:
        return False
    return "ref: refs/" in content or len(content.strip()) == 40


def analyze_git_repo(repo_path: Path) -> Dict[str, object]:
    result = {
        "is_git_repo": False,
        "commits": [],
        "branches": [],
        "tags": [],
        "flag_search": [],
        "deleted_files": [],
        "current_branch": None,
    }

    if not is_git_repo(repo_path):
        return result

    result["is_git_repo"] = True
    result["current_branch"] = get_current_branch(repo_path)
    result["branches"] = get_branches(repo_path)
    result["tags"] = get_tags(repo_path)
    result["commits"] = get_recent_commits(repo_path)

    result["flag_search"] = search_in_git(repo_path, "picoCTF")
    result["flag_search"] += search_in_git(repo_path, "flag{")
    result["flag_search"] += search_in_git(repo_path, "CTF{")

    result["deleted_files"] = find_deleted_files(repo_path)
    return result


def get_current_branch(repo_path: Path) -> Optional[str]:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def get_branches(repo_path: Path) -> List[str]:
    try:
        result = subprocess.run(
            ["git", "branch", "-a"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            return [b.strip().replace("* ", "") for b in result.stdout.splitlines() if b.strip()][:50]
    except Exception:
        pass
    return []


def get_tags(repo_path: Path) -> List[str]:
    try:
        result = subprocess.run(
            ["git", "tag"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            return [t.strip() for t in result.stdout.splitlines() if t.strip()]
    except Exception:
        pass
    return []


def get_recent_commits(repo_path: Path, limit: int = 20) -> List[Dict[str, str]]:
    commits: List[Dict[str, str]] = []
    try:
        result = subprocess.run(
            ["git", "log", "--oneline", f"-{limit}", "--all"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split(None, 1)
                commits.append(
                    {
                        "hash": parts[0][:40],
                        "message": parts[1] if len(parts) > 1 else "",
                    }
                )
    except Exception:
        pass
    return commits


def search_in_git(repo_path: Path, pattern: str) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    for search_type in ["--all", "--cached"]:
        try:
            cmd = ["git", "grep", "-n", search_type, pattern, "--", "*"]
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.splitlines()[:20]:
                    parts = line.split(":", 2)
                    if len(parts) >= 2:
                        results.append(
                            {
                                "file": parts[0],
                                "line": parts[1],
                                "content": parts[2] if len(parts) > 2 else "",
                            }
                        )
        except Exception:
            pass
    return results[:50]


def find_deleted_files(repo_path: Path) -> List[Dict[str, str]]:
    deleted: List[Dict[str, str]] = []
    try:
        result = subprocess.run(
            ["git", "log", "--all", "--name-status", "--diff-filter=D"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines()[:100]:
                parts = line.split("\t", 1)
                if len(parts) > 1 and parts[0].startswith("D"):
                    deleted.append({"path": parts[1].strip()})
    except Exception:
        pass
    return deleted[:20]


def extract_git_repo_from_file(
    source_data: bytes,
    output_dir: Path,
    source_name: str,
) -> Optional[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)

    git_marker = b".git"
    pos = source_data.find(git_marker)
    if pos == -1:
        return None

    candidate_start = max(0, pos - 5000)
    candidate_end = min(len(source_data), pos + 50000)
    candidate = source_data[candidate_start:candidate_end]

    test_dir = output_dir / f"{source_name}_git"
    test_dir.mkdir(exist_ok=True)

    git_dir = test_dir / ".git"
    git_dir.mkdir(exist_ok=True)

    marker_offsets = []
    search_pos = 0
    while True:
        idx = candidate.find(b".git", search_pos)
        if idx == -1:
            break
        marker_offsets.append(idx)
        search_pos = idx + 1

    return None


def find_git_repos(root: Path) -> List[Dict[str, str]]:
    repos: List[Dict[str, str]] = []
    try:
        for git_dir in root.rglob(".git"):
            repo_root = git_dir.parent
            branch = get_current_branch(repo_root) or "unknown"
            try:
                rel_path = str(repo_root.relative_to(root))
            except ValueError:
                rel_path = str(repo_root)
            repos.append(
                {
                    "path": rel_path,
                    "branch": branch,
                }
            )
    except Exception:
        pass
    return repos[:20]


def analyze_git_history(repo_path: Path) -> Dict[str, object]:
    result: Dict[str, object] = {
        "repo_path": str(repo_path),
        "commits": [],
        "deleted_files": [],
        "flag_candidates": [],
        "recovered_content": [],
        "last_commit_message": "",
        "source": "git_history",
    }

    if not is_git_repo(repo_path):
        return result

    commits = get_recent_commits(repo_path, limit=20)
    result["commits"] = commits
    if commits:
        result["last_commit_message"] = commits[0].get("message", "")

    deleted = find_deleted_files(repo_path)
    result["deleted_files"] = [d.get("path", "") for d in deleted if d.get("path")]

    try:
        proc = subprocess.run(
            ["git", "log", "-p", "--all"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        if proc.returncode == 0:
            text = proc.stdout

            for pat in FLAG_PATTERNS:
                for m in re.finditer(pat, text, flags=re.IGNORECASE):
                    result["flag_candidates"].append(m.group(0))

            current_file = None
            deleted_lines: List[str] = []

            for line in text.splitlines():
                if line.startswith("diff --git "):
                    if current_file and deleted_lines:
                        result["recovered_content"].append(
                            {
                                "file": current_file,
                                "content": "\n".join(deleted_lines[:20]),
                            }
                        )
                    current_file = None
                    deleted_lines = []
                    continue

                if line.startswith("--- a/"):
                    current_file = line[6:].strip()
                    continue

                if line.startswith("-") and not line.startswith("---"):
                    deleted_lines.append(line[1:])

            if current_file and deleted_lines:
                result["recovered_content"].append(
                    {
                        "file": current_file,
                        "content": "\n".join(deleted_lines[:20]),
                    }
                )

    except Exception:
        pass

    seen = set()
    uniq_flags = []
    for item in result["flag_candidates"]:
        if item not in seen:
            seen.add(item)
            uniq_flags.append(item)
    result["flag_candidates"] = uniq_flags[:20]

    if result["flag_candidates"] or result["deleted_files"]:
        result["source"] = "deleted_content_recovery"

    return result


def full_git_recovery(part_img: Path) -> Dict[str, object]:
    return {
        "repo_path": "",
        "commits": [],
        "deleted_files": [],
        "flag_candidates": [],
        "recovered_content": [],
        "source": "full_git_recovery",
    }