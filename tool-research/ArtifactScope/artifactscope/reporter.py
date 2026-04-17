from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from .utils import human_size


def render_terminal_summary(results: List[Dict[str, object]]) -> str:
    lines = []
    for result in results:
        file_info = result["file_info"]
        if "error" in result:
            lines.append("=" * 70)
            lines.append(f"File:         {file_info['path']}")
            lines.append(f"Error:        {result['error']}")
            continue
        sig = result["signature"]
        entropy = result["entropy"]
        risk = result["risk"]

        lines.append("=" * 70)
        lines.append(f"File:         {file_info['path']}")
        lines.append(f"Size:         {human_size(file_info['size'])} ({file_info['size']} bytes)")
        lines.append(f"SHA256:       {result['hashes']['sha256']}")
        lines.append(f"Detected:     {sig['name']} ({sig['type']})")
        lines.append(f"Ext Match:    {'Yes' if sig['extension_matches'] else 'No'}")
        lines.append(f"Entropy:      {entropy['score']:.3f} ({entropy['classification']})")
        lines.append(f"Risk:         {risk['risk_level']} ({risk['risk_score']}/100)")
        lines.append(f"Findings:     {len(risk['findings'])}")
        if result.get("embedded"):
            lines.append(f"Embedded:     {len(result['embedded'])} candidate(s)")
        if result.get("strings"):
            lines.append(
                f"Strings:      urls={len(result['strings']['urls'])}, "
                f"emails={len(result['strings']['emails'])}, "
                f"ips={len(result['strings']['ips'])}, "
                f"suspicious={len(result['strings']['suspicious_strings'])}"
            )
    if lines:
        lines.append("=" * 70)
    return "\n".join(lines)


def write_json_report(results: List[Dict[str, object]], out_path: Path) -> Path:
    out_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path


def write_markdown_report(results: List[Dict[str, object]], out_path: Path) -> Path:
    lines = ["# ArtifactScope Report", ""]
    for result in results:
        file_info = result["file_info"]
        if "error" in result:
            lines.extend([
                f"## {file_info['name']}",
                "",
                f"- **Path:** `{file_info['path']}`",
                f"- **Error:** {result['error']}",
                "",
                "---",
                "",
            ])
            continue

        sig = result["signature"]
        entropy = result["entropy"]
        risk = result["risk"]

        lines.extend([
            f"## {file_info['name']}",
            "",
            f"- **Path:** `{file_info['path']}`",
            f"- **Size:** {human_size(file_info['size'])} ({file_info['size']} bytes)",
            f"- **Extension:** `{file_info['extension'] or '(none)'}`",
            f"- **Created:** {file_info['created']}",
            f"- **Modified:** {file_info['modified']}",
            "",
            "### Hashes",
            "",
            f"- **MD5:** `{result['hashes']['md5']}`",
            f"- **SHA1:** `{result['hashes']['sha1']}`",
            f"- **SHA256:** `{result['hashes']['sha256']}`",
            "",
            "### Type Detection",
            "",
            f"- **Detected Type:** {sig['name']} (`{sig['type']}`)",
            f"- **Extension Match:** {'Yes' if sig['extension_matches'] else 'No'}",
            f"- **Expected Extensions:** {', '.join(sig['expected_extensions']) if sig['expected_extensions'] else '(unknown)'}",
            "",
            "### Entropy",
            "",
            f"- **Score:** {entropy['score']:.3f}",
            f"- **Classification:** {entropy['classification']}",
            "",
            "### Risk",
            "",
            f"- **Risk Level:** {risk['risk_level']}",
            f"- **Risk Score:** {risk['risk_score']}/100",
            "",
            "### Findings",
            "",
        ])

        if risk["findings"]:
            for finding in risk["findings"]:
                lines.extend([
                    f"- **{finding['name']}** [{finding['severity'].upper()} | +{finding['score']}]",
                    f"  - {finding['description']}",
                    f"  - Evidence: {finding['evidence']}",
                ])
        else:
            lines.append("- No rule-based findings.")

        if result.get("strings"):
            s = result["strings"]
            lines.extend([
                "",
                "### String Scan Summary",
                "",
                f"- URLs: {len(s['urls'])}",
                f"- Emails: {len(s['emails'])}",
                f"- IPs: {len(s['ips'])}",
                f"- Base64-like strings: {len(s['base64_like'])}",
                f"- Suspicious strings: {len(s['suspicious_strings'])}",
            ])

        if result.get("embedded"):
            lines.extend([
                "",
                "### Embedded Artifact Candidates",
                "",
            ])
            for item in result["embedded"]:
                lines.append(
                    f"- {item['name']} at offset `{item['offset']}`"
                    + (f", end `{item['end_offset']}`" if item['end_offset'] is not None else "")
                )

        if result.get("carved"):
            lines.extend([
                "",
                "### Carved Files",
                "",
            ])
            for item in result["carved"]:
                lines.append(f"- `{item['output_path']}` ({item['size']} bytes)")

        lines.extend(["", "---", ""])

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path
