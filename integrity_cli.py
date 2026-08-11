"""
============================================================
  integrity_cli.py  —  Command-Line Interface
  IA Project - Information Assurance
============================================================
  Usage:
    python integrity_cli.py
  
  Commands available in the menu:
    1  — Create baseline  (scan folder, save hashes)
    2  — Verify integrity (compare current files vs baseline)
    3  — Show baseline    (print stored hashes)
    4  — Create signed baseline
    5  — Verify signature
    6  — Change folder
    Q  — Quit
============================================================
"""

import os
import json
from file_integrity import FileIntegrityChecker, SignedIntegrityChecker


# ─────────────────────────────────────────────
#  Banner
# ─────────────────────────────────────────────

BANNER = r"""
  ╔══════════════════════════════════════════╗
  ║   File Integrity Monitor  v1.0           ║
  ║   SHA-256 Hash Verification System       ║
  ║   IA Project — Information Assurance     ║
  ╚══════════════════════════════════════════╝
"""


# ─────────────────────────────────────────────
#  Menu helpers
# ─────────────────────────────────────────────

def menu(folder: str, baseline: str) -> None:
    print(f"""
  ┌─ Current Settings ───────────────────────┐
  │  Folder   : {folder:<30}│
  │  Baseline : {baseline:<30}│
  └──────────────────────────────────────────┘

  [1] Create baseline (scan & save hashes)
  [2] Verify integrity
  [3] Show stored baseline
  [4] Create SIGNED baseline  (extension)
  [5] Verify signature        (extension)
  [6] Change folder / baseline file
  [Q] Quit
""")


def ask(prompt: str) -> str:
    return input(f"  {prompt} › ").strip()


# ─────────────────────────────────────────────
#  Action functions
# ─────────────────────────────────────────────

def do_create_baseline(checker: FileIntegrityChecker) -> None:
    if not os.path.isdir(checker.folder_path):
        print(f"\n  [!] Folder not found: {checker.folder_path}")
        return
    checker.save_baseline()
    print("\n  [+] Done. You can now run option 2 to verify at any time.")


def do_verify(checker: FileIntegrityChecker) -> None:
    try:
        report = checker.verify_integrity()
        checker.print_report(report)
    except FileNotFoundError as e:
        print(f"\n  [!] {e}")


def do_show_baseline(checker: FileIntegrityChecker) -> None:
    if not os.path.exists(checker.baseline_file):
        print(f"\n  [!] No baseline file found: {checker.baseline_file}")
        return
    with open(checker.baseline_file) as f:
        data = json.load(f)

    print(f"\n  Baseline created : {data.get('timestamp', 'unknown')}")
    print(f"  Folder           : {data.get('folder', 'unknown')}")
    print(f"  Files stored     : {len(data['hashes'])}\n")
    print(f"  {'File':<35}  SHA-256 (first 32 chars)")
    print(f"  {'─'*35}  {'─'*32}")
    for path, h in data["hashes"].items():
        print(f"  {path:<35}  {h[:32]}...")


def do_signed(folder: str, baseline: str) -> None:
    signed_file = baseline.replace(".json", "_signed.json")
    sc = SignedIntegrityChecker(folder, baseline)
    sc.save_signed_baseline(signed_file)
    print(f"\n  [+] Signed baseline written to: {signed_file}")


def do_verify_sig(folder: str, baseline: str) -> None:
    signed_file = baseline.replace(".json", "_signed.json")
    if not os.path.exists(signed_file):
        print(f"\n  [!] Signed file not found: {signed_file}")
        print(   "       Run option 4 first.")
        return
    sc = SignedIntegrityChecker(folder, baseline)
    sc.verify_signature(signed_file)


# ─────────────────────────────────────────────
#  Main loop
# ─────────────────────────────────────────────

def main() -> None:
    print(BANNER)

    folder   = ask("Enter folder to monitor (default: test_files)") or "test_files"
    baseline = ask("Baseline filename       (default: file_hashes.json)") or "file_hashes.json"

    while True:
        checker = FileIntegrityChecker(folder, baseline)
        menu(folder, baseline)

        choice = ask("Choose an option").upper()

        if choice == "1":
            do_create_baseline(checker)

        elif choice == "2":
            do_verify(checker)

        elif choice == "3":
            do_show_baseline(checker)

        elif choice == "4":
            do_signed(folder, baseline)

        elif choice == "5":
            do_verify_sig(folder, baseline)

        elif choice == "6":
            folder   = ask("New folder path") or folder
            baseline = ask("New baseline filename") or baseline
            print(f"\n  [*] Switched to folder={folder}, baseline={baseline}")

        elif choice == "Q":
            print("\n  [*] Exiting File Integrity Monitor. Goodbye.\n")
            break

        else:
            print("\n  [!] Invalid option. Please choose 1–6 or Q.")

        input("\n  Press Enter to continue...")


if __name__ == "__main__":
    main()
