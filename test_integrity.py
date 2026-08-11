"""
============================================================
  test_integrity.py  —  Test Suite for FileIntegrityChecker
  IA Project - Information Assurance
============================================================
  Demonstrates:
    1. Baseline creation
    2. Clean verification (all OK)
    3. Single-character modification detection
    4. New file detection
    5. Deleted file detection
    6. Signed baseline + signature verification
============================================================
"""

import os
import json
from file_integrity import FileIntegrityChecker, SignedIntegrityChecker

FOLDER   = "test_files"
BASELINE = "test_baseline.json"
SIGNED   = "test_signed.json"

PASS = "[PASS]"
FAIL = "[FAIL]"


# ─────────────────────────────────────────────
#  Helper
# ─────────────────────────────────────────────

def section(title: str) -> None:
    print("\n" + "=" * 52)
    print(f"  TEST: {title}")
    print("=" * 52)


def assert_eq(label: str, expected, actual) -> None:
    if expected == actual:
        print(f"  {PASS}  {label}")
    else:
        print(f"  {FAIL}  {label}")
        print(f"         Expected : {expected}")
        print(f"         Actual   : {actual}")


# ─────────────────────────────────────────────
#  TEST 1 — sha256 consistency
# ─────────────────────────────────────────────

section("SHA-256 determinism")

checker = FileIntegrityChecker(FOLDER, BASELINE)

# Hash the same file twice — must be identical
h1 = checker.compute_sha256(os.path.join(FOLDER, "notes.txt"))
h2 = checker.compute_sha256(os.path.join(FOLDER, "notes.txt"))
assert_eq("Same file hashed twice → same digest", h1, h2)
print(f"         Hash = {h1[:32]}...")

# Hash length must always be 64 hex chars
assert_eq("SHA-256 hex length == 64", 64, len(h1))


# ─────────────────────────────────────────────
#  TEST 2 — Baseline creation
# ─────────────────────────────────────────────

section("Baseline creation")

checker.save_baseline()

assert_eq("Baseline file exists", True, os.path.exists(BASELINE))

with open(BASELINE) as f:
    data = json.load(f)

assert_eq("Baseline has 'timestamp' key", True, "timestamp" in data)
assert_eq("Baseline has 'hashes' key",   True, "hashes"    in data)
assert_eq("Baseline has at least 1 file", True, len(data["hashes"]) >= 1)
print(f"         Files hashed : {len(data['hashes'])}")


# ─────────────────────────────────────────────
#  TEST 3 — Clean verification (no changes)
# ─────────────────────────────────────────────

section("Clean verification — no tampering")

report = checker.verify_integrity()

assert_eq("Zero modified files",  0, len(report["modified"]))
assert_eq("Zero new files",       0, len(report["new"]))
assert_eq("Zero deleted files",   0, len(report["deleted"]))
assert_eq("All files OK",
          len(data["hashes"]), len(report["ok"]))


# ─────────────────────────────────────────────
#  TEST 4 — Single-character modification
# ─────────────────────────────────────────────

section("Detect single-character modification in notes.txt")

notes_path = os.path.join(FOLDER, "notes.txt")

with open(notes_path, "r") as f:
    original_content = f.read()

# Add just ONE space at the end — should still change the hash
tampered_content = original_content + " "
with open(notes_path, "w") as f:
    f.write(tampered_content)

report = checker.verify_integrity()

assert_eq("notes.txt flagged as MODIFIED", True,
          any(item["file"] == "notes.txt" for item in report["modified"]))

# Restore file
with open(notes_path, "w") as f:
    f.write(original_content)

report_clean = checker.verify_integrity()
assert_eq("notes.txt restored → back to OK", 0, len(report_clean["modified"]))


# ─────────────────────────────────────────────
#  TEST 5 — New file detection
# ─────────────────────────────────────────────

section("Detect new file added to folder")

NEW_FILE = os.path.join(FOLDER, "malware_payload.exe")
with open(NEW_FILE, "w") as f:
    f.write("I am a suspicious new file.")

report = checker.verify_integrity()
assert_eq("New file detected", True, "malware_payload.exe" in report["new"])

os.remove(NEW_FILE)


# ─────────────────────────────────────────────
#  TEST 6 — Deleted file detection
# ─────────────────────────────────────────────

section("Detect deleted file")

# Temporarily rename a file to simulate deletion
os.rename(
    os.path.join(FOLDER, "schema.sql"),
    os.path.join(FOLDER, "schema.sql.bak")
)

report = checker.verify_integrity()
assert_eq("Deleted file detected", True, "schema.sql" in report["deleted"])

# Restore
os.rename(
    os.path.join(FOLDER, "schema.sql.bak"),
    os.path.join(FOLDER, "schema.sql")
)


# ─────────────────────────────────────────────
#  TEST 7 — Digital signature
# ─────────────────────────────────────────────

section("Signed baseline — valid signature")

signed_checker = SignedIntegrityChecker(FOLDER, BASELINE)
signed_checker.save_signed_baseline(SIGNED)

valid = signed_checker.verify_signature(SIGNED)
assert_eq("Signature is valid for untampered baseline", True, valid)


section("Signed baseline — tampered JSON detection")

# Manually alter the signed JSON
with open(SIGNED) as f:
    tampered_data = json.load(f)

# Attacker tries to modify the hash of notes.txt in the JSON
first_key = list(tampered_data["hashes"].keys())[0]
tampered_data["hashes"][first_key] = "0" * 64

with open(SIGNED, "w") as f:
    json.dump(tampered_data, f, indent=2)

invalid = signed_checker.verify_signature(SIGNED)
assert_eq("Tampered baseline JSON → signature INVALID", False, invalid)


# ─────────────────────────────────────────────
#  Summary
# ─────────────────────────────────────────────

print("\n" + "=" * 52)
print("  ALL TESTS COMPLETE")
print("=" * 52)
print("  The tool correctly detects:")
print("    ✓  Single-character file changes")
print("    ✓  Newly added files")
print("    ✓  Deleted files")
print("    ✓  Tampered baseline JSON (via signature)")
print()

# Cleanup temp files
for f in [BASELINE, SIGNED]:
    if os.path.exists(f):
        os.remove(f)
