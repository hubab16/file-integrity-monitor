# File Integrity Monitor (SHA-256)

A Python-based File Integrity Monitor that detects unauthorized file modifications using SHA-256 cryptographic hashing, with HMAC-signed baselines for tamper-evident verification.

## Features

- Scans a folder and computes SHA-256 hashes for every file
- Saves a baseline (JSON) of file hashes for later comparison
- Verifies current files against the baseline to detect: modifications, new files, and deleted files
- Signed baseline support using HMAC to prevent baseline tampering
- Interactive CLI menu for creating baselines, verifying integrity, and viewing stored hashes
- Full test suite demonstrating detection of tampering, new files, and deletions

## Tech Stack

- Python 3.x
- `hashlib` (SHA-256 hashing)
- `hmac` (signed baseline verification)
- `json` (baseline storage)

## How to Run

```bash
git clone https://github.com/hubab16/file-integrity-monitor.git
cd file-integrity-monitor
python integrity_cli.py
```

Menu options let you create a baseline, verify integrity, view stored hashes, and work with signed baselines.

To run the test suite:
```bash
python test_integrity.py
```

## What This Project Demonstrates

Core information assurance concepts: cryptographic hashing for integrity verification, tamper detection, and signed baselines to protect against baseline manipulation itself — the same principles used in real-world file integrity monitoring tools (e.g. Tripwire, OSSEC).

## Contact

Open to freelance and project work in Python, security tooling, and SQL. Reach out via Fiverr or GitHub.
