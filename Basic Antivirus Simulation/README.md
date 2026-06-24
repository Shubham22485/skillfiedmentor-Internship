# Basic Antivirus Simulation — Signature Scanner

![Python](https://img.shields.io/badge/Python-3.7%2B-5BA8FF?style=flat-square&logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-none-3DDC84?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-8B98A3?style=flat-square)
![License](https://img.shields.io/badge/license-Educational-FFB454?style=flat-square)

A Python-based signature antivirus engine that scans files, computes cryptographic hashes, and flags threats using hash matching, suspicious string detection, and extension blacklisting.

## Overview

Traditional antivirus engines detect malware by scanning files and comparing their content against known threat signatures. This project simulates that core workflow:

```
File Path
   └─ Read File → Compute SHA-256
        ├─ Hash matches known malware?        → FLAGGED (malicious)
        ├─ Contains suspicious strings?        → FLAGGED (suspicious)
        ├─ Dangerous file extension?            → FLAGGED (suspicious/low)
        └─ None of the above                    → CLEAN
```

## Features

- **Hash-based detection** — SHA-256 matching against a known malware hash database
- **Suspicious string scanning** — Content-based pattern matching for known malicious strings
- **Extension blacklisting** — Flags potentially dangerous file types (`.exe`, `.dll`, `.ps1`, etc.)
- **Quarantine system** — Isolates flagged files into a timestamped quarantine directory
- **Report generation** — Produces formatted scan reports (stdout or file output)
- **EICAR test file creation** — Generate the universally recognized AV test file with one command
- **Signature database management** — Add custom hashes, strings, and extensions at runtime
- **Recursive and non-recursive scanning** — Scan single directories or entire directory trees
- **Zero external dependencies** — Pure Python 3.7+, standard library only

## Requirements

- **Python 3.7+** (tested on 3.8–3.12)
- **Operating system**: Linux (primary), macOS, Windows
- **No external packages required** — all modules are from the standard library

## Installation

### Quick Start (No Install)

```bash
# Save the script as basic_av.py, then:
python3 basic_av.py --help
```

### Make It Executable (Linux/macOS)

```bash
chmod +x basic_av.py
./basic_av.py --help
```

### System-Wide Install

```bash
sudo cp basic_av.py /usr/local/bin/basic-av
basic-av --help
```

### Pip Install (Editable/Development)

```bash
# From the directory containing basic_av.py:
python3 -m pip install --user -e .
basic-av --help
```

## Usage

### Quick Demo

```bash
# 1. Create an EICAR test file
python3 basic_av.py generate-test

# 2. Scan it
python3 basic_av.py scan-file eicar_test.txt
```

### Commands

| Command | Description |
|---|---|
| `scan <directory>` | Scan a directory for threats |
| `scan-file <file>` | Scan a single file |
| `hash <file>` | Compute SHA-256 and MD5 hashes |
| `generate-test` | Create EICAR test file |
| `update-db hash <hash> --name <name>` | Add a malware hash signature |
| `update-db string <pattern>` | Add a suspicious string pattern |
| `update-db ext <extension>` | Add a dangerous file extension |

### Scan Options

| Flag | Description |
|---|---|
| `--recursive` / `--no-recursive` | Enable/disable recursive scanning (default: recursive) |
| `-q`, `--quarantine` | Auto-quarantine flagged files |
| `-o`, `--output <file>` | Write scan report to file |
| `--suspicious-only` | Show only flagged files in output |

### Examples

Scan a directory recursively:

```bash
python3 basic_av.py scan /tmp/downloads
```

Scan a single directory (non-recursive):

```bash
python3 basic_av.py scan /var/www/html --no-recursive
```

Scan with auto-quarantine and report file:

```bash
python3 basic_av.py scan /shared/folder --quarantine --output scan_report.txt
```

Scan a single file:

```bash
python3 basic_av.py scan-file suspicious.bin
```

Compute file hashes:

```bash
python3 basic_av.py hash eicar_test.txt
python3 basic_av.py hash eicar_test.txt --algo sha256
python3 basic_av.py hash eicar_test.txt --algo md5
```

Add a custom malware signature:

```bash
python3 basic_av.py update-db hash \
    a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2 \
    --name "My_Custom_Threat" --severity critical
```

## Detection Methods

### Layer 1: Hash Matching

Computes the SHA-256 hash of each file and checks it against a database of known malware hashes. This is the most reliable detection method but only catches exact file matches — any modification changes the hash.

Database entry example:

```python
"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
    "name": "EICAR_Test_File",
    "type": "AV-Test-Signature",
    "severity": "high"
}
```

### Layer 2: Suspicious String Scanning

Scans file content for known suspicious byte patterns — simulating heuristic analysis used by real AV engines.

Patterns include:

- EICAR test string
- `CreateRemoteThread` (process injection indicator)
- `VirtualAllocEx` (memory allocation for shellcode)
- `WriteProcessMemory` (code injection primitive)
- `WSAStartup` (network socket initialization indicator)
- `This program cannot be run in DOS mode` (PE executable detection)

### Layer 3: Extension Blacklisting

Flags files with potentially dangerous extensions regardless of content:

`.exe`, `.dll`, `.scr`, `.bat`, `.cmd`, `.vbs`, `.ps1`, `.js`, `.jar`, `.docm`, `.xlsm`, `.pptm`

## Architecture

```
basic_av.py
├── FileHasher                  # Static methods for SHA-256 and MD5 hashing
│   ├── sha256(filepath)        # Compute SHA-256 with chunked reading
│   └── md5(filepath)           # Compute MD5 with chunked reading
│
├── SignatureScanner            # Core scanning engine
│   ├── scan_file()             # Single file scan (all 3 detection layers)
│   ├── scan_directory()        # Recursive directory traversal
│   ├── quarantine_file()       # Move to quarantine with timestamp
│   └── generate_report()       # Formatted text report
│
├── SIGNATURE_DB                # JSON-like malware signature dictionary
│
└── main()                      # CLI argument parser and command dispatch
```

## Quarantine Structure

```
quarantine/
└── 20260621_143052/
    ├── eicar_test.txt
    └── suspicious_file.exe
```

Each quarantine batch is stored in a timestamped subdirectory to preserve context and prevent naming conflicts.

## Educational Purpose

This tool demonstrates core cybersecurity concepts:

| Concept | How It's Demonstrated |
|---|---|
| Signature-based detection | Hash matching against a known-bad database |
| Hashing integrity | SHA-256 guarantees — any byte change produces a completely different hash |
| Heuristic scanning | String pattern matching simulates behavioral detection |
| Quarantine | Isolation preserves evidence while preventing execution |
| False positives | Extension-only detection is noisy — teaches why real AV uses multiple layers |
| Signature database management | Adding/removing signatures dynamically |

It will not detect real malware unless you add real signatures. It is designed to teach how signature-based antivirus systems work at their core.

## Extending the Tool

| Enhancement | How to Implement |
|---|---|
| Real hash database | Import from MalwareBazaar or VirusShare |
| YARA rules | Integrate `yara-python` for advanced pattern matching |
| PE file parsing | Use `pefile` to analyze PE headers, sections, imports, and exports |
| Memory scanning | Hook `psutil` to scan running processes for known signatures |
| Real-time monitoring | Use `watchdog` to monitor filesystem events reactively |
| VirusTotal API | Submit hashes for reputation scoring |
| Machine learning | Add feature extraction and a classifier for unknown samples |
| GUI | Build a Tkinter/PyQt frontend for interactive use |

## Android / Mobile

This tool is designed for Linux desktop/server environments. For Android usage:

- **Termux**: Install Python via Termux and run the script directly — fully functional
- **Native APK**: Rewrite the core logic in Kotlin/Java for a proper Android app (Python-wrapped APKs via Kivy/Buildozer are technically possible but produce large, slow APKs)

## Limitations

- **Signature-dependent** — Only detects files with known hashes or patterns
- **No heuristics** — Cannot detect novel/zero-day malware based on behavior
- **No archive scanning** — Will not unpack ZIP, RAR, or other archives (but will flag them by extension)
- **No memory scanning** — Only scans files on disk
- **No real-time protection** — Scan is on-demand only
- **No polymorphic detection** — Cannot detect self-modifying or encrypted malware
- **No network monitoring** — Does not inspect network traffic

## License

This project is provided for **educational and authorized security testing purposes only**.

Users are responsible for ensuring they have explicit authorization to scan any systems or files they test with this tool. Unauthorized scanning of systems you do not own or have written permission to test may violate applicable laws.

## Acknowledgments

- **EICAR** — For the standardized antivirus test file
- **MITRE ATT&CK** — For reference on TTPs and detection methodologies
- **The open-source security community** — For ongoing education and research
