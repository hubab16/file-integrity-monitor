"""
============================================================
  File Integrity Monitor Using SHA-256 Hashing
  IA Project - Information Assurance
============================================================
  Author  : [Your Name]
  Purpose : Detects unauthorized file modifications using
            SHA-256 cryptographic hashing.
============================================================
"""

import hashlib
import json
import os
import hmac
import hashlib
from datetime import datetime


# ─────────────────────────────────────────────
#  CORE CLASS
# ─────────────────────────────────────────────

class FileIntegrityChecker:
    """
    Scans a folder, computes SHA-256 hashes for every file,
    saves them as a baseline JSON, and later verifies files
    against that baseline to detect tampering.
    """

    def __init__(self, folder_path: str, baseline_file: str = "file_hashes.json"):
        self.folder_path   = folder_path
        self.baseline_file = baseline_file

    # ── Hash one file ──────────────────────────────────────
    def compute_sha256(self, filepath: str) -> str:
        """
        Read file in 8 KB chunks and compute SHA-256.
        Chunked reading works correctly even for large files.
        Returns a 64-character hex digest string.
        """
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    # ── Scan entire folder ────────────────────────────────
    def scan_folder(self) -> dict:
        """
        Walk self.folder_path recursively.
        Returns {relative_path: sha256_hex, ...}
        """
        hashes = {}
        for root, _dirs, files in os.walk(self.folder_path):
            for filename in sorted(files):
                full_path = os.path.join(root, filename)
                rel_path  = os.path.relpath(full_path, self.folder_path)
                try:
                    hashes[rel_path] = self.compute_sha256(full_path)
                except PermissionError:
                    print(f"  [!] Cannot read: {rel_path} (permission denied)")
        return hashes

    # ── Save baseline ─────────────────────────────────────
    def save_baseline(self) -> None:
        """
        Scan the folder and write hashes to baseline_file.
        JSON structure:
          {
            "timestamp": "2025-06-01T10:30:00",
            "folder":    "test_files",
            "hashes":    { "notes.txt": "abc123...", ... }
          }
        """
        print(f"\n[*] Scanning folder: {self.folder_path}")
        hashes = self.scan_folder()
        data = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "folder":    self.folder_path,
            "hashes":    hashes
        }
        with open(self.baseline_file, "w") as f:
            json.dump(data, f, indent=2)

        print(f"[+] Baseline saved  : {self.baseline_file}")
        print(f"[+] Files hashed    : {len(hashes)}")
        for path, h in hashes.items():
            print(f"    {h[:16]}...  {path}")

    # ── Load baseline ─────────────────────────────────────
    def load_baseline(self) -> dict:
        """Load and return hashes dict from baseline file."""
        if not os.path.exists(self.baseline_file):
            raise FileNotFoundError(
                f"Baseline not found: {self.baseline_file}\n"
                "Run save_baseline() first."
            )
        with open(self.baseline_file) as f:
            data = json.load(f)
        print(f"[*] Baseline loaded : {self.baseline_file}")
        print(f"    Created at       : {data.get('timestamp', 'unknown')}")
        return data["hashes"]

    # ── Verify integrity ──────────────────────────────────
    def verify_integrity(self) -> dict:
        """
        Compare current file hashes against baseline.

        Returns a report dict:
          {
            "ok":       [list of unchanged files],
            "modified": [list of changed files],
            "new":      [files not in baseline],
            "deleted":  [baseline files now missing]
          }
        """
        baseline = self.load_baseline()
        current  = self.scan_folder()

        report = {"ok": [], "modified": [], "new": [], "deleted": []}

        # Check every current file against baseline
        for path, current_hash in current.items():
            if path not in baseline:
                report["new"].append(path)
            elif baseline[path] != current_hash:
                report["modified"].append({
                    "file":     path,
                    "expected": baseline[path],
                    "actual":   current_hash
                })
            else:
                report["ok"].append(path)

        # Check for files that were deleted since baseline
        for path in baseline:
            if path not in current:
                report["deleted"].append(path)

        return report

    # ── Pretty-print report ───────────────────────────────
    def print_report(self, report: dict) -> None:
        """Display a colour-coded integrity report."""
        print("\n" + "=" * 52)
        print("  INTEGRITY VERIFICATION REPORT")
        print("=" * 52)

        if report["ok"]:
            print(f"\n  [OK]       {len(report['ok'])} file(s) intact")
            for f in report["ok"]:
                print(f"             ✓  {f}")

        if report["modified"]:
            print(f"\n  [MODIFIED] {len(report['modified'])} file(s) TAMPERED")
            for item in report["modified"]:
                print(f"             ✗  {item['file']}")
                print(f"                Expected : {item['expected'][:32]}...")
                print(f"                Found    : {item['actual'][:32]}...")

        if report["new"]:
            print(f"\n  [NEW]      {len(report['new'])} file(s) added since baseline")
            for f in report["new"]:
                print(f"             +  {f}")

        if report["deleted"]:
            print(f"\n  [DELETED]  {len(report['deleted'])} file(s) removed since baseline")
            for f in report["deleted"]:
                print(f"             -  {f}")

        total_issues = len(report["modified"]) + len(report["new"]) + len(report["deleted"])
        print("\n" + "─" * 52)
        if total_issues == 0:
            print("  STATUS: ALL FILES INTACT  ✓")
        else:
            print(f"  STATUS: {total_issues} VIOLATION(S) DETECTED  ✗")
        print("=" * 52 + "\n")


# ─────────────────────────────────────────────
#  EXTENSION: Digital Signature Simulation
# ─────────────────────────────────────────────

class SignedIntegrityChecker(FileIntegrityChecker):
    """
    Extension of FileIntegrityChecker that adds a simulated
    digital signature using HMAC-SHA256 with a dummy private key.

    In a real system this would use RSA/ECDSA private keys.
    Here we use HMAC to demonstrate the concept.
    """

    DUMMY_PRIVATE_KEY = b"IA_PROJECT_DUMMY_KEY_2025_DO_NOT_USE_IN_PRODUCTION"

    def _sign(self, data: str) -> str:
        """Generate HMAC-SHA256 signature of data string."""
        return hmac.new(
            self.DUMMY_PRIVATE_KEY,
            data.encode(),
            hashlib.sha256
        ).hexdigest()

    def save_signed_baseline(self, signed_file: str = "signed_hashes.json") -> None:
        """Save baseline with an HMAC signature attached."""
        hashes  = self.scan_folder()
        payload = json.dumps(hashes, sort_keys=True)
        sig     = self._sign(payload)

        data = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "folder":    self.folder_path,
            "signature": sig,
            "hashes":    hashes
        }
        with open(signed_file, "w") as f:
            json.dump(data, f, indent=2)

        print(f"[+] Signed baseline saved : {signed_file}")
        print(f"    Signature (first 32)  : {sig[:32]}...")

    def verify_signature(self, signed_file: str = "signed_hashes.json") -> bool:
        """
        Re-compute signature and compare.
        Returns True if the baseline JSON itself has not been tampered.
        """
        with open(signed_file) as f:
            data = json.load(f)

        payload       = json.dumps(data["hashes"], sort_keys=True)
        expected_sig  = self._sign(payload)
        actual_sig    = data.get("signature", "")

        if hmac.compare_digest(expected_sig, actual_sig):
            print("[+] Signature VALID — baseline file not tampered.")
            return True
        else:
            print("[!] Signature INVALID — baseline file may have been altered!")
            return False


# ─────────────────────────────────────────────
#  Quick demo when run directly
# ─────────────────────────────────────────────

if __name__ == "__main__":
    FOLDER = "test_files"

    checker = FileIntegrityChecker(FOLDER)

    print("\n--- STEP 1: Create baseline ---")
    checker.save_baseline()

    print("\n--- STEP 2: Verify (should be all OK) ---")
    report = checker.verify_integrity()
    checker.print_report(report)

    print("\n--- EXTENSION: Signed baseline ---")
    signed = SignedIntegrityChecker(FOLDER)
    signed.save_signed_baseline()
    signed.verify_signature()
