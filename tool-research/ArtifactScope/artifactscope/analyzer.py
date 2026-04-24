from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .carver import carve_embedded, discover_embedded
from .entropy import classify_entropy, shannon_entropy
from .fs_analyzer import (
    extract_partitions_7z,
    get_mount_point,
    parse_partition_info,
    search_flag_in_raw_data,
    search_git_in_raw_data,
    search_raw_for_flag,
)
from .git_analyzer import analyze_git_history, find_git_repos, full_git_recovery
from .hashing import compute_hashes
from .rules import apply_rules, load_rules
from .signatures import detect_signature
from .stringscan import analyze_strings, detect_flag_patterns, detect_git_artifacts


def analyze_file(
    file_path: Path,
    rules_path: Optional[Path] = None,
    scan_strings: bool = False,
    carve: bool = False,
    carve_dir: Optional[Path] = None,
    mount_git: bool = False,
) -> Dict[str, object]:
    data = file_path.read_bytes()
    stat = file_path.stat()

    file_info = {
        "name": file_path.name,
        "path": str(file_path.resolve()),
        "extension": file_path.suffix.lower(),
        "size": stat.st_size,
        "created": datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
        "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
    }

    hashes = compute_hashes(file_path)
    sig = detect_signature(data, file_path)

    entropy_score = shannon_entropy(data)
    entropy = {
        "score": entropy_score,
        "classification": classify_entropy(entropy_score),
    }

    embedded = discover_embedded(data)

    carved = []
    if carve and carve_dir:
        carved = carve_embedded(data, carve_dir, file_path.name)

    strings_result: Dict[str, object] = {}
    git_artifacts: Dict[str, object] = {}
    flag_patterns: List[Dict[str, object]] = []

    if scan_strings:
        strings_result = analyze_strings(data)

        sample_strings = strings_result.get("sample_strings", [])
        suspicious_strings = strings_result.get("suspicious_strings", [])

        all_strings = list(sample_strings) + list(suspicious_strings)
        all_text = "\n".join(sample_strings) + "\n" + "\n".join(suspicious_strings)

        git_artifacts = detect_git_artifacts(all_strings, sample_strings)
        flag_patterns = detect_flag_patterns(all_strings, all_text)

    result: Dict[str, object] = {
        "file_info": file_info,
        "hashes": hashes,
        "signature": sig,
        "entropy": entropy,
        "embedded": embedded,
        "carved": carved,
    }

    if strings_result:
        result["strings"] = strings_result

    if git_artifacts:
        result["git_artifacts"] = git_artifacts

    if flag_patterns:
        result["flag_patterns"] = flag_patterns

    rules = []
    if rules_path and rules_path.exists():
        rules = load_rules(rules_path)

    if rules:
        result["risk"] = apply_rules(result, rules)
    else:
        result["risk"] = {
            "findings": [],
            "risk_score": 0,
            "risk_level": "Unknown",
        }

    partitions = parse_partition_info(file_path)
    if partitions:
        result["partitions"] = partitions

        git_hits = search_git_in_raw_data(data)
        if git_hits:
            result["git_in_raw_data"] = git_hits[:20]

        flag_hits = search_flag_in_raw_data(data)
        if flag_hits:
            result["flag_in_raw_data"] = flag_hits[:20]

    if mount_git:
        mounted: List[Dict[str, object]] = []
        git_repos: List[Dict[str, object]] = []
        git_history: List[Dict[str, object]] = []

        for part in result.get("partitions", []):
            offset = int(part.get("offset_bytes", 0) or 0)
            size_bytes = int(part.get("size_bytes", 0) or 0)
            fs_type = str(part.get("fs_type", "") or "")

            if offset and fs_type in ("Linux", "ext", "NTFS", "FAT"):
                mount_path = get_mount_point(file_path, offset, fs_type, size_bytes)
                if mount_path:
                    mounted.append(
                        {
                            "partition": f"p{part.get('partition', '?')}",
                            "offset": offset,
                            "mount_path": str(mount_path),
                        }
                    )

                    repos = find_git_repos(mount_path)
                    for repo in repos:
                        repo_rel = repo.get("path", "")
                        repo_full = mount_path / repo_rel if repo_rel else mount_path

                        repo_info = {
                            "repo_path": str(repo_full),
                            "branch": repo.get("branch", "unknown"),
                        }
                        git_repos.append(repo_info)

                        history = analyze_git_history(repo_full)
                        if (
                            history.get("commits")
                            or history.get("deleted_files")
                            or history.get("flag_candidates")
                            or history.get("hint_candidates")
                            or history.get("recovered_content")
                        ):
                            history["repo_path"] = str(repo_full)
                            git_history.append(history)

        extracted_parts = extract_partitions_7z(file_path)
        all_flag_candidates: List[Dict[str, object]] = []

        for part_idx, part_img in extracted_parts.items():
            if not isinstance(part_idx, int):
                continue

            full_recovery = full_git_recovery(part_img)
            if (
                full_recovery.get("repo_path")
                and (
                    full_recovery.get("commits")
                    or full_recovery.get("flag_candidates")
                    or full_recovery.get("hint_candidates")
                    or full_recovery.get("recovered_content")
                )
            ):
                full_recovery["source"] = "full_git_recovery"
                full_recovery["partition_index"] = part_idx
                git_history.append(full_recovery)

            raw_flag_result = search_raw_for_flag(part_img)
            if raw_flag_result.get("flag_candidates"):
                for fc in raw_flag_result["flag_candidates"]:
                    fc["partition"] = part_idx
                    fc["source"] = "raw_search"
                    all_flag_candidates.append(fc)

        if all_flag_candidates:
            result["flag_candidates"] = all_flag_candidates

        if mounted:
            result["mounted_partitions"] = mounted
        if git_repos:
            result["git_repos"] = git_repos
        if git_history:
            result["git_history"] = git_history

    return result
