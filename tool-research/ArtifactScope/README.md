# ArtifactScope

ArtifactScope is a lightweight, security-oriented file triage and artifact analysis tool for CTF, DFIR learning, and suspicious file inspection.

## Features

- File metadata collection
- MD5 / SHA1 / SHA256 hashing
- Magic byte / signature-based type detection
- Extension mismatch detection
- Shannon entropy analysis
- ASCII strings extraction
- IOC-style extraction:
  - URLs
  - IP addresses
  - Email addresses
  - Base64-like strings
  - Suspicious commands / keywords
- Simple rule engine with severity and risk scoring
- Embedded artifact discovery and optional carving
- JSON and Markdown report output

## Project Structure

```text
ArtifactScope/
├─ artifactscope/
│  ├─ __init__.py
│  ├─ cli.py
│  ├─ analyzer.py
│  ├─ carver.py
│  ├─ entropy.py
│  ├─ hashing.py
│  ├─ reporter.py
│  ├─ rules.py
│  ├─ signatures.py
│  ├─ stringscan.py
│  └─ utils.py
├─ rules/
│  └─ default_rules.yaml
├─ tests/
├─ requirements.txt
├─ main.py
└─ README.md
```

## Installation

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

## Usage

### Quick analysis

```bash
python main.py sample.bin
```

### Enable strings scan and Markdown report

```bash
python main.py sample.bin --strings --report-md
```

### Enable carving and JSON report

```bash
python main.py sample.bin --carve --report-json
```

### Analyze a directory recursively

```bash
python main.py samples --recursive --strings --report-md
```

## Output

By default, ArtifactScope prints a terminal summary.

Optional outputs:

- `--report-json`: writes JSON report
- `--report-md`: writes Markdown report
- `--carve`: writes carved files into `output/carved/`

## Notes

- This is an educational MVP, not a replacement for Autopsy, FTK, Volatility, or YARA-based triage pipelines.
- Signature matching is intentionally lightweight and transparent.
- Carving is heuristic-based and best used as a triage aid.

## Recommended next upgrades

- ZIP unpack and nested analysis
- YARA integration
- Disk image support (`.img`, `.dd`)
- Timeline view
- Recursive archive analysis
- PE / ELF metadata parsing
