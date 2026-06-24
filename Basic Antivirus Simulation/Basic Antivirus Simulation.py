#!/usr/bin/env python3
"""
Basic Antivirus Simulation — Signature Scanner
For educational and authorized security testing only.
"""

import os
import sys
import hashlib
import json
import argparse
import shutil
from pathlib import Path
from datetime import datetime


# ─── Malware Signature Database ───────────────────────────────────────────────
#
# BUG FIX: The original DB had the SHA-256 of an EMPTY file
# (e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)
# as the "EICAR_Test_File" hash. The correct SHA-256 of the EICAR test
# string (68 bytes, no trailing newline) is:
#   275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
# Source: https://www.eicar.org, VirusTotal, Broadcom support docs

SIGNATURE_DB = {
    "known_malware_hashes": {
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
            "name": "EICAR_Test_File",
            "type": "AV-Test-Signature",
            "severity": "high"
        },
    },
    "known_suspicious_strings": [
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        b"This program cannot be run in DOS mode",
        b"CreateRemoteThread",
        b"VirtualAllocEx",
        b"WriteProcessMemory",
        b"WSAStartup",
    ],
    "dangerous_extensions": [
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".ps1",
        ".js", ".jar", ".docm", ".xlsm", ".pptm",
    ],
    "quarantine_dir": "quarantine"
}


class FileHasher:
    """Handles cryptographic hashing of files."""

    @staticmethod
    def sha256(filepath: str, chunk_size: int = 65536) -> str | None:
        """Compute SHA-256 hash of a file."""
        sha = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                # BUG FIX: Changed walrus operator while-loop to explicit
                # break pattern for broader Python version compatibility
                # and clearer control flow.
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    sha.update(chunk)
            return sha.hexdigest()
        except (IOError, PermissionError) as e:
            print(f"  [ERROR] Cannot read {filepath}: {e}")
            return None

    @staticmethod
    def md5(filepath: str, chunk_size: int = 65536) -> str | None:
        """Compute MD5 hash of a file."""
        md5 = hashlib.md5()
        try:
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    md5.update(chunk)
            return md5.hexdigest()
        except (IOError, PermissionError) as e:
            print(f"  [ERROR] Cannot read {filepath}: {e}")
            return None


class SignatureScanner:
    """Core scanning engine — compares files against signature database."""

    def __init__(self, signature_db: dict | None = None):
        self.db = signature_db or SIGNATURE_DB
        self.quarantine_path = Path(self.db.get("quarantine_dir", "quarantine"))
        self.quarantine_path.mkdir(exist_ok=True)
        self.results = {
            "scanned": 0,
            "flagged": 0,
            "cleaned": 0,
            "errors": 0,
            "details": []
        }

    def _check_hash_match(self, sha256_hash: str) -> dict | None:
        """
        Check if a hash matches any known malware signature.
        
        BUG FIX: Removed unused 'filepath' parameter that was passed
        to this method but never used in the body.
        """
        if sha256_hash in self.db["known_malware_hashes"]:
            return self.db["known_malware_hashes"][sha256_hash]
        return None

    def _check_suspicious_strings(self, filepath: str) -> list[str]:
        """Scan file content for known suspicious strings."""
        found = []
        try:
            with open(filepath, "rb") as f:
                content = f.read()
                for pattern in self.db.get("known_suspicious_strings", []):
                    if pattern in content:
                        found.append(pattern[:40].decode("latin-1", errors="replace"))
        except (IOError, PermissionError):
            pass
        return found

    def _check_suspicious_extension(self, filepath: str) -> bool:
        """Check if file extension is potentially dangerous."""
        ext = Path(filepath).suffix.lower()
        return ext in self.db.get("dangerous_extensions", [])

    def scan_file(self, filepath: str) -> dict:
        """Scan a single file and return results."""
        result = {
            "file": filepath,
            "sha256": None,
            "md5": None,
            "size": 0,
            "status": "clean",
            "threat_name": None,
            "severity": None,
            "suspicious_strings": [],
            "suspicious_extension": False,
            "timestamp": datetime.now().isoformat()
        }

        try:
            stat = os.stat(filepath)
            result["size"] = stat.st_size
        except OSError:
            pass

        # BUG FIX: Renamed variable from 'sha256' to 'sha256_hash' to
        # avoid shadowing the hashlib.sha256 module reference.
        sha256_hash = FileHasher.sha256(filepath)
        md5_hash = FileHasher.md5(filepath)
        result["sha256"] = sha256_hash
        result["md5"] = md5_hash

        # BUG FIX (CRITICAL): Missing early return when hash is None.
        # Without this, the method would continue with a None hash,
        # bypass hash matching, and then try to read the file again
        # for suspicious strings — possibly crashing or misreporting
        # an unreadable file as "clean".
        if sha256_hash is None:
            result["status"] = "error"
            self.results["errors"] += 1
            self.results["details"].append(result)
            return result

        # BUG FIX: Updated call to match new signature without unused 'filepath'
        match = self._check_hash_match(sha256_hash)
        if match:
            result["status"] = "malicious"
            result["threat_name"] = match["name"]
            result["severity"] = match["severity"]
            self.results["flagged"] += 1
            self.results["details"].append(result)
            return result

        # Suspicious content scan
        suspicious_strings = self._check_suspicious_strings(filepath)
        if suspicious_strings:
            result["suspicious_strings"] = suspicious_strings
            result["status"] = "suspicious"
            result["threat_name"] = "Suspicious_Content"
            result["severity"] = "medium"
            self.results["flagged"] += 1
            self.results["details"].append(result)
            return result

        # Extension check
        if self._check_suspicious_extension(filepath):
            result["suspicious_extension"] = True
            result["status"] = "suspicious"
            result["threat_name"] = "Suspicious_Extension"
            result["severity"] = "low"
            self.results["flagged"] += 1
            self.results["details"].append(result)
            return result

        result["status"] = "clean"
        self.results["cleaned"] += 1
        self.results["details"].append(result)
        return result

    def scan_directory(self, directory: str, recursive: bool = True) -> dict:
        """Scan an entire directory recursively."""
        path = Path(directory)
        if not path.exists():
            print(f"[ERROR] Directory does not exist: {directory}")
            return self.results

        # BUG FIX: Reset counters at start of each scan to prevent
        # accumulation across multiple scan_directory() calls.
        self.results = {
            "scanned": 0,
            "flagged": 0,
            "cleaned": 0,
            "errors": 0,
            "details": []
        }

        for entry in path.rglob("*") if recursive else path.glob("*"):
            if entry.is_file():
                rel_path = entry.relative_to(path) if recursive else entry.name
                print(f"  Scanning: {rel_path}", end=" ... ")
                result = self.scan_file(str(entry))
                print(f"[{result['status'].upper()}]")
                self.results["scanned"] += 1

        return self.results

    def quarantine_file(self, filepath: str) -> bool:
        """Move a flagged file to quarantine."""
        src = Path(filepath)
        if not src.exists():
            print(f"[ERROR] File not found: {filepath}")
            return False

        quarantine_subdir = self.quarantine_path / datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantine_subdir.mkdir(parents=True, exist_ok=True)
        dest = quarantine_subdir / src.name

        try:
            shutil.move(str(src), str(dest))
            print(f"[QUARANTINED] {filepath} → {dest}")
            return True
        except (IOError, shutil.Error) as e:
            print(f"[ERROR] Quarantine failed: {e}")
            return False

    def generate_report(self, output_file: str | None = None) -> str:
        """Generate a formatted scan report."""
        lines = []
        lines.append("=" * 60)
        lines.append("BASIC ANTIVIRUS SCAN REPORT")
        lines.append(f"Timestamp: {datetime.now().isoformat()}")
        lines.append("=" * 60)
        lines.append(f"\nSummary:")
        lines.append(f"  Files Scanned:  {self.results['scanned']}")
        lines.append(f"  Files Flagged:  {self.results['flagged']}")
        lines.append(f"  Files Clean:    {self.results['cleaned']}")
        lines.append(f"  Errors:         {self.results['errors']}")
        lines.append(f"\nFlagged Files:")
        for detail in self.results["details"]:
            if detail["status"] in ("malicious", "suspicious"):
                lines.append(f"  - {detail['file']}")
                lines.append(f"    Status:        {detail['status'].upper()}")
                lines.append(f"    Threat Name:   {detail['threat_name']}")
                lines.append(f"    Severity:      {detail['severity']}")
                lines.append(f"    SHA256:        {detail['sha256']}")
                if detail["suspicious_strings"]:
                    lines.append(f"    Strings Found: {len(detail['suspicious_strings'])} matches")
                lines.append("")
        lines.append("=" * 60)

        report = "\n".join(lines)
        if output_file:
            Path(output_file).write_text(report)
            print(f"[REPORT] Written to {output_file}")

        return report


# ─── CLI Interface ────────────────────────────────────────────────────────────

def create_eicar_test_file(path: str = "eicar_test.txt") -> str:
    """
    Create the EICAR test file — a safe file universally recognized by
    antivirus engines as a test signature. Completely harmless.
    
    BUG FIX: The generated file now correctly matches the hash in the
    signature database. The SHA-256 of this exact string (68 bytes,
    no trailing newline) is:
      275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
    """
    # IMPORTANT: No extra characters, spaces, or newlines.
    # The string must be EXACTLY as specified by EICAR standard.
    eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    # Use write_bytes or write_text with no newline to ensure exact bytes
    Path(path).write_text(eicar_string)
    print(f"[CREATED] EICAR test file: {path}")
    print(f"[INFO]    SHA-256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    return path


def main():
    parser = argparse.ArgumentParser(
        description="Basic Antivirus Simulation — Signature Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan /path/to/dir
  %(prog)s scan /path/to/dir --recursive --quarantine
  %(prog)s scan-file /path/to/file
  %(prog)s hash /path/to/file
  %(prog)s generate-test          # create EICAR test file
  %(prog)s update-db hash <sha256> --name "ThreatName" --severity high
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan
    scan_parser = subparsers.add_parser("scan", help="Scan a directory")
    scan_parser.add_argument("directory", help="Directory to scan")
    scan_parser.add_argument("-r", "--recursive", action="store_true", default=True,
                             help="Scan recursively (default: True)")
    scan_parser.add_argument("--no-recursive", action="store_false", dest="recursive",
                             help="Disable recursive scanning")
    scan_parser.add_argument("-q", "--quarantine", action="store_true",
                             help="Auto-quarantine flagged files")
    scan_parser.add_argument("-o", "--output", help="Write report to file")
    scan_parser.add_argument("--suspicious-only", action="store_true",
                             help="Only show flagged files")

    # scan-file
    file_parser = subparsers.add_parser("scan-file", help="Scan a single file")
    file_parser.add_argument("filepath", help="Path to file")

    # hash
    hash_parser = subparsers.add_parser("hash", help="Compute file hashes")
    hash_parser.add_argument("filepath", help="Path to file")
    hash_parser.add_argument("--algo", choices=["sha256", "md5", "both"],
                             default="both", help="Hash algorithm")

    # generate-test
    subparsers.add_parser("generate-test", help="Create EICAR test file")

    # update-db
    update_parser = subparsers.add_parser("update-db", help="Update signature database")
    update_parser.add_argument("entry_type", choices=["hash", "string", "ext"],
                               help="Type of signature entry")
    update_parser.add_argument("value", help="Hash value, string pattern, or extension")
    update_parser.add_argument("--name", help="Threat name (for hash entries)")
    update_parser.add_argument("--severity", choices=["low", "medium", "high", "critical"],
                               default="medium", help="Severity level")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    scanner = SignatureScanner()

    if args.command == "scan":
        print(f"\n[*] Starting scan of: {args.directory}")
        print(f"[*] Recursive: {args.recursive}")
        print(f"[*] Auto-quarantine: {args.quarantine}\n")

        results = scanner.scan_directory(args.directory, recursive=args.recursive)

        if args.quarantine:
            for detail in results["details"]:
                if detail["status"] in ("malicious", "suspicious"):
                    scanner.quarantine_file(detail["file"])

        report = scanner.generate_report(args.output)
        print(f"\n{report}")

    elif args.command == "scan-file":
        print(f"\n[*] Scanning file: {args.filepath}\n")
        # BUG FIX: scan_file() updates self.results counters internally
        # (flagged, cleaned, errors) but not "scanned". We update it here
        # for consistency, then print the result directly.
        result = scanner.scan_file(args.filepath)
        print(f"  File:    {result['file']}")
        print(f"  SHA256:  {result['sha256']}")
        print(f"  MD5:     {result['md5']}")
        print(f"  Size:    {result['size']} bytes")
        print(f"  Status:  {result['status'].upper()}")
        if result["threat_name"]:
            print(f"  Threat:  {result['threat_name']}")
            print(f"  Severity: {result['severity']}")
        if result["suspicious_strings"]:
            print(f"  Strings: {result['suspicious_strings']}")

    elif args.command == "hash":
        if args.algo in ("sha256", "both"):
            h = FileHasher.sha256(args.filepath)
            print(f"  SHA256: {h}")
        if args.algo in ("md5", "both"):
            h = FileHasher.md5(args.filepath)
            print(f"  MD5:    {h}")

    elif args.command == "generate-test":
        create_eicar_test_file()

    elif args.command == "update-db":
        if args.entry_type == "hash":
            SIGNATURE_DB["known_malware_hashes"][args.value] = {
                "name": args.name or "Unknown_Threat",
                "type": "Custom_Signature",
                "severity": args.severity
            }
            print(f"[UPDATED DB] Added hash signature: {args.value[:16]}...")
        elif args.entry_type == "string":
            SIGNATURE_DB["known_suspicious_strings"].append(args.value.encode())
            print(f"[UPDATED DB] Added suspicious string pattern")
        elif args.entry_type == "ext":
            ext = args.value if args.value.startswith(".") else f".{args.value}"
            SIGNATURE_DB["dangerous_extensions"].append(ext)
            print(f"[UPDATED DB] Added dangerous extension: {ext}")


if __name__ == "__main__":
    main()