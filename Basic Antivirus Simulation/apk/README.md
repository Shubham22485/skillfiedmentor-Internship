# Antivirus Sim

![Platform](https://img.shields.io/badge/platform-Android-3DDC84?style=flat-square&logo=android&logoColor=white)
![Language](https://img.shields.io/badge/Kotlin-1.9.24-5BA8FF?style=flat-square&logo=kotlin&logoColor=white)
![UI](https://img.shields.io/badge/UI-Jetpack%20Compose-5BA8FF?style=flat-square)
![License](https://img.shields.io/badge/license-Educational-FFB454?style=flat-square)

**A signature-based file scanner for Android — a GUI port of the original
`Basic_Antivirus_Simulation.py` command-line tool.**

---

## Overview

Antivirus Sim brings the original Python scanner's logic to a native Android
app. Pick a file or folder through the system file picker, and the app
hashes, pattern-matches, and reports on every file inside — with the same
detection order as the CLI tool it's based on.

| | |
|---|---|
| **Scan a folder** | Recursively check every file inside a chosen directory |
| **Scan a single file** | Check one file on demand |
| **EICAR self-test** | Generate the industry-standard harmless test file and confirm detection works |

> This is a learning tool. It only recognizes the public EICAR test
> signature and a handful of generic byte patterns — it is **not** a real
> antivirus and won't detect actual malware.

## What a scan looks like

| Status | Meaning |
|---|---|
| 🟢 `CLEAN` | No signature, suspicious string, or risky extension matched |
| 🟡 `SUSPICIOUS` | A generic suspicious byte pattern or risky extension (`.exe`, `.scr`, `.bat`, …) was found |
| 🔴 `MALICIOUS` | The file's SHA-256 matched a known signature (e.g. the EICAR test file) |
| ⚪ `ERROR` | The file couldn't be read |

Results show the matched threat name, severity, and both SHA-256/MD5 hashes,
sorted with the most severe findings first.

## Architecture

The app follows a straightforward unidirectional layering — Compose screens
read state from a `ViewModel`, which drives a plain-Kotlin scanner engine
that knows nothing about Android UI at all:

```
app/src/main/java/com/example/antivirussim/
├── MainActivity.kt              # entry point — wires the SAF file/folder pickers
├── scanner/
│   ├── SignatureDatabase.kt     # known hashes, suspicious strings, dangerous extensions
│   ├── SignatureScanner.kt      # FileHasher + SignatureScanner — the actual scan logic
│   └── EicarTestFile.kt         # generates the EICAR self-test sample
└── ui/
    ├── AntivirusViewModel.kt    # scan state management (StateFlow)
    ├── components/              # status pill, stat block, result row
    ├── screens/                 # Home · Scanning · Results
    └── theme/                   # dark "security console" color & type tokens
```

## Toolchain

| | |
|---|---|
| Android Gradle Plugin | `8.9.2` |
| Gradle | `8.11.1` |
| Kotlin | `1.9.24` |
| Compose compiler | `1.5.14` |
| `compileSdk` / `targetSdk` | `35` |
| `minSdk` | `24` |

## Building from source

1. Open the `AntivirusSim` folder in **Android Studio**.
2. Let Gradle sync (downloads the toolchain above on first run).
3. **Build → Build Bundle(s) / APK(s) → Build APK(s)**, or press **Run ▶**
   with a device/emulator selected.
4. The installable file lands at `app/build/outputs/apk/debug/app-debug.apk`.

## Notes on the port

- The EICAR test file's SHA-256
  (`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`) was
  verified by hand against the real 68-byte EICAR string.
- File access uses Android's **Storage Access Framework** (the system
  file/folder picker) instead of raw file paths — the standard,
  permission-safe way to read user files on modern Android. No storage
  permission is requested.
- The original CLI's `quarantine` and `update-db` subcommands aren't exposed
  in this app's UI yet — quarantining arbitrary files doesn't fit Android's
  sandboxed storage model the way it does on desktop. The signature-database
  update functions (`addHashSignature`, `addSuspiciousString`,
  `addDangerousExtension`) already exist in `SignatureDatabase.kt` for anyone
  who wants to wire up a settings screen for them.

---

*Educational project — not a substitute for a real antivirus.*
