#!/usr/bin/env python3
from pathlib import Path
from collections import defaultdict
import re

ROOT = Path(__file__).resolve().parent.parent
WRITEUPS = ROOT / "writeups"
PROGRESS = ROOT / "PROGRESS.md"

EXCLUDE_FILENAMES = {
    "notes.md",
    "draft.md",
    "template.md",
    "index.md",
    "readme-template.md",
}

PREFERRED_NAMES = [
    "readme.md",
    "report.md",
    "writeup.md",
]


def natural_key(s: str):
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", s)]


def titleize(name: str) -> str:
    return name.replace("-", " ").replace("_", " ")


def is_report_file(md_path: Path, challenge_dir: Path) -> bool:
    name = md_path.name.lower()
    stem = md_path.stem.lower()
    challenge = challenge_dir.name.lower()

    if name in EXCLUDE_FILENAMES:
        return False
    if name == "readme.md":
        return True
    if name.endswith("-report.md") or name in {"report.md", "writeup.md"}:
        return True
    if stem == challenge:
        return True
    return True


def pick_report_file(challenge_dir: Path):
    md_files = [p for p in challenge_dir.iterdir() if p.is_file() and p.suffix.lower() == ".md"]
    candidates = [p for p in md_files if is_report_file(p, challenge_dir)]
    if not candidates:
        return None

    def score(p: Path):
        lname = p.name.lower()
        if lname in PREFERRED_NAMES:
            pref = 0
        elif lname.endswith("-report.md"):
            pref = 1
        elif p.stem.lower() == challenge_dir.name.lower():
            pref = 2
        else:
            pref = 3
        return (pref, natural_key(p.name))

    return sorted(candidates, key=score)[0]


def collect():
    data = defaultdict(list)
    total = done = 0
    if not WRITEUPS.exists():
        return data, total, done

    for category_dir in sorted((p for p in WRITEUPS.iterdir() if p.is_dir()), key=lambda p: natural_key(p.name)):
        for challenge_dir in sorted((p for p in category_dir.iterdir() if p.is_dir()), key=lambda p: natural_key(p.name)):
            total += 1
            report = pick_report_file(challenge_dir)
            completed = report is not None
            if completed:
                done += 1
            data[category_dir.name].append((challenge_dir.name, completed, report))
    return data, total, done


def build_markdown(data, total, done):
    rate = (done / total * 100) if total else 0.0
    lines = [
        "# picoCTF Progress",
        "",
        f"- Completed reports: **{done}**",
        f"- Total challenge folders: **{total}**",
        f"- Completion rate: **{rate:.1f}%**",
        "",
        "> Rule: a challenge counts as done if its folder contains a main markdown report, not only `README.md`.",
        "",
    ]

    for category in sorted(data.keys(), key=natural_key):
        entries = data[category]
        cat_done = sum(1 for _, completed, _ in entries if completed)
        lines.append(f"## {titleize(category)} ({cat_done}/{len(entries)})")
        for challenge, completed, report in entries:
            mark = "x" if completed else " "
            if report is not None:
                rel = report.relative_to(ROOT).as_posix()
                lines.append(f"- [{mark}] [{challenge}]({rel})")
            else:
                lines.append(f"- [{mark}] {challenge}")
        lines.append("")
    return "
".join(lines).rstrip() + "
"


def main():
    data, total, done = collect()
    PROGRESS.write_text(build_markdown(data, total, done), encoding="utf-8")


if __name__ == "__main__":
    main()
