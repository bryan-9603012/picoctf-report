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

HINT_PATTERNS = [
    r"g17_[A-Za-z0-9_]+",
    r"Wrap this phrase in the flag format:\s*([A-Za-z0-9_]+)",
]


def _run_git(repo_path: Path, args: List[str], timeout: int = 90) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def is_git_repo(path: Path) -> bool:
    head = path / ".git" / "HEAD"
    if not head.exists():
        return False
    try:
        content = head.read_text(errors="replace").strip()
    except Exception:
        return False

    if content.startswith("ref: refs/"):
        return True

    if re.fullmatch(r"[0-9a-fA-F]{40}", content):
        return True

    return False


def get_current_branch(repo_path: Path) -> Optional[str]:
    try:
        result = _run_git(repo_path, ["rev-parse", "--abbrev-ref", "HEAD"], timeout=15)
        if result.returncode == 0:
            out = result.stdout.strip()
            if out and out != "HEAD":
                return out
    except Exception:
        pass

    try:
        head = (repo_path / ".git" / "HEAD").read_text(errors="replace").strip()
        if head.startswith("ref: refs/heads/"):
            return head.rsplit("/", 1)[-1]
    except Exception:
        pass

    return None


def get_branches(repo_path: Path) -> List[str]:
    try:
        result = _run_git(repo_path, ["branch", "-a"], timeout=15)
        if result.returncode == 0:
            return [b.strip().replace("* ", "") for b in result.stdout.splitlines() if b.strip()][:50]
    except Exception:
        pass
    return []


def get_tags(repo_path: Path) -> List[str]:
    try:
        result = _run_git(repo_path, ["tag"], timeout=15)
        if result.returncode == 0:
            return [t.strip() for t in result.stdout.splitlines() if t.strip()]
    except Exception:
        pass
    return []


def get_recent_commits(repo_path: Path, limit: int = 20) -> List[Dict[str, str]]:
    commits: List[Dict[str, str]] = []
    try:
        result = _run_git(repo_path, ["log", "--oneline", f"-{limit}", "--all"], timeout=60)
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

    for args in (
        ["grep", "-n", pattern],
        ["grep", "-n", pattern, "--", "*"],
    ):
        try:
            result = _run_git(repo_path, args, timeout=30)
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.splitlines()[:50]:
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

    try:
        revs = _run_git(repo_path, ["rev-list", "--all"], timeout=60)
        if revs.returncode == 0:
            for commit in [c.strip() for c in revs.stdout.splitlines() if c.strip()][:100]:
                show = _run_git(repo_path, ["show", "--format=fuller", "--stat", commit], timeout=60)
                if show.returncode != 0:
                    continue
                text = show.stdout
                if pattern.lower() in text.lower():
                    results.append(
                        {
                            "file": f"<commit:{commit[:7]}>",
                            "line": "N/A",
                            "content": text[:200],
                        }
                    )
    except Exception:
        pass

    dedup = []
    seen = set()
    for item in results:
        key = (item["file"], item["line"], item["content"])
        if key not in seen:
            seen.add(key)
            dedup.append(item)
    return dedup[:50]


def find_deleted_files(repo_path: Path) -> List[Dict[str, str]]:
    deleted: List[Dict[str, str]] = []
    try:
        result = _run_git(repo_path, ["log", "--all", "--name-status", "--diff-filter=D"], timeout=60)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split("\t", 1)
                if len(parts) == 2 and parts[0].startswith("D"):
                    deleted.append({"path": parts[1].strip()})
    except Exception:
        pass

    uniq = []
    seen = set()
    for item in deleted:
        p = item.get("path", "")
        if p and p not in seen:
            seen.add(p)
            uniq.append(item)
    return uniq[:20]


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
    result["flag_search"] += search_in_git(repo_path, "g17_")

    result["deleted_files"] = find_deleted_files(repo_path)
    return result


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

            score = 0
            low = rel_path.lower()
            for kw in ["secret", "flag", "chat", "app", "killer", "ctf"]:
                if kw in low:
                    score += 1

            repos.append(
                {
                    "path": rel_path,
                    "branch": branch,
                    "score": score,
                }
            )
    except Exception:
        pass

    repos.sort(key=lambda x: x.get("score", 0), reverse=True)
    return repos[:20]


def _extract_flags_from_text(text: str) -> List[str]:
    found = []
    for pat in FLAG_PATTERNS:
        for m in re.finditer(pat, text, flags=re.IGNORECASE):
            found.append(m.group(0))
    return found


def _extract_hints_from_text(text: str) -> List[str]:
    hints = []
    for pat in HINT_PATTERNS:
        for m in re.finditer(pat, text, flags=re.IGNORECASE):
            if m.groups():
                hints.append(m.group(1))
            else:
                hints.append(m.group(0))
    return hints


def analyze_git_history(repo_path: Path) -> Dict[str, object]:
    result: Dict[str, object] = {
        "repo_path": str(repo_path),
        "commits": [],
        "deleted_files": [],
        "flag_candidates": [],
        "hint_candidates": [],
        "recovered_content": [],
        "last_commit_message": "",
        "source": "git_history",
    }

    if not is_git_repo(repo_path):
        return result

    proc_log = _run_git(repo_path, ["log", "--oneline", "--all"], timeout=60)
    if proc_log.returncode == 0:
        for line in proc_log.stdout.splitlines()[:100]:
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            result["commits"].append(
                {
                    "hash": parts[0],
                    "message": parts[1] if len(parts) > 1 else "",
                }
            )

    if result["commits"]:
        result["last_commit_message"] = result["commits"][0]["message"]

    result["deleted_files"] = [d["path"] for d in find_deleted_files(repo_path) if d.get("path")]

    proc_patch = _run_git(repo_path, ["log", "-p", "--all"], timeout=120)
    if proc_patch.returncode == 0 and proc_patch.stdout.strip():
        patch_text = proc_patch.stdout
        result["flag_candidates"].extend(_extract_flags_from_text(patch_text))
        result["hint_candidates"].extend(_extract_hints_from_text(patch_text))

        current_file = None
        deleted_lines: List[str] = []

        for line in patch_text.splitlines():
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

    no_commit_repo = len(result["commits"]) == 0

    if no_commit_repo:
        result["source"] = "working_tree_recovery"

        proc_status = _run_git(repo_path, ["status", "--short"], timeout=30)
        if proc_status.returncode == 0 and proc_status.stdout.strip():
            result["recovered_content"].append(
                {
                    "file": "<git-status>",
                    "content": proc_status.stdout[:2000],
                }
            )
            result["hint_candidates"].extend(_extract_hints_from_text(proc_status.stdout))
            result["flag_candidates"].extend(_extract_flags_from_text(proc_status.stdout))

        proc_cached = _run_git(repo_path, ["diff", "--cached"], timeout=60)
        if proc_cached.returncode == 0 and proc_cached.stdout.strip():
            text = proc_cached.stdout
            result["recovered_content"].append(
                {
                    "file": "<git-diff-cached>",
                    "content": text[:4000],
                }
            )
            result["hint_candidates"].extend(_extract_hints_from_text(text))
            result["flag_candidates"].extend(_extract_flags_from_text(text))

        for path in repo_path.rglob("*"):
            if not path.is_file():
                continue
            if ".git" in path.parts:
                continue

            try:
                data = path.read_text(errors="replace")
            except Exception:
                continue

            if not data.strip():
                continue

            if (
                "flag" in path.name.lower()
                or "log" in path.name.lower()
                or "chat" in path.name.lower()
                or "secret" in path.name.lower()
                or "g17_" in data
                or "picoCTF" in data
                or "flag{" in data.lower()
            ):
                result["recovered_content"].append(
                    {
                        "file": str(path.relative_to(repo_path)),
                        "content": data[:2000],
                    }
                )

            result["hint_candidates"].extend(_extract_hints_from_text(data))
            result["flag_candidates"].extend(_extract_flags_from_text(data))

    else:
        proc_rev = _run_git(repo_path, ["rev-list", "--all"], timeout=60)
        if proc_rev.returncode == 0:
            commit_ids = [c.strip() for c in proc_rev.stdout.splitlines() if c.strip()]

            for commit in commit_ids[:150]:
                show = _run_git(repo_path, ["show", "--format=fuller", "--stat", commit], timeout=60)
                if show.returncode == 0:
                    text = show.stdout
                    result["flag_candidates"].extend(_extract_flags_from_text(text))
                    result["hint_candidates"].extend(_extract_hints_from_text(text))

                for deleted_file in result["deleted_files"][:20]:
                    blob = _run_git(repo_path, ["show", f"{commit}:{deleted_file}"], timeout=30)
                    if blob.returncode == 0 and blob.stdout:
                        content = blob.stdout
                        result["recovered_content"].append(
                            {
                                "file": deleted_file,
                                "content": content[:2000],
                            }
                        )
                        result["flag_candidates"].extend(_extract_flags_from_text(content))
                        result["hint_candidates"].extend(_extract_hints_from_text(content))

    for rc in result["recovered_content"]:
        content = rc.get("content", "")
        if content:
            result["flag_candidates"].extend(_extract_flags_from_text(content))
            result["hint_candidates"].extend(_extract_hints_from_text(content))

    for hint in list(result["hint_candidates"]):
        if hint.startswith("g17_"):
            wrapped = f"picoCTF{{{hint}}}"
            result["flag_candidates"].append(wrapped)

    result["flag_candidates"] = list(dict.fromkeys([x for x in result["flag_candidates"] if x]))[:20]
    result["hint_candidates"] = list(dict.fromkeys([x for x in result["hint_candidates"] if x]))[:20]

    if (
        result["flag_candidates"]
        or result["deleted_files"]
        or result["recovered_content"]
        or result["hint_candidates"]
    ):
        if result["source"] == "git_history":
            result["source"] = "deleted_content_recovery"

    return result


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

    test_dir = output_dir / f"{source_name}_git"
    test_dir.mkdir(exist_ok=True)

    git_dir = test_dir / ".git"
    git_dir.mkdir(exist_ok=True)

    return None


def full_git_recovery(part_img: Path) -> Dict[str, object]:
    return {
        "repo_path": "",
        "commits": [],
        "deleted_files": [],
        "flag_candidates": [],
        "hint_candidates": [],
        "recovered_content": [],
        "source": "full_git_recovery",
    }