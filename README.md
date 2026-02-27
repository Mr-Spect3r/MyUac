# 🔓 UAC Bypass & Persistence Toolkit

<div align="center">

[![Windows](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)](https://microsoft.com)
[![C++](https://img.shields.io/badge/C++-Native-00599C?logo=c%2B%2B&logoColor=white)](https://isocpp.org)
[![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Native Windows UAC Evasion & Persistence Detection Framework**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage)
</div>

---

## 🎯 Overview

A professional-grade **native Windows** security testing toolkit designed for **red team operations** and **penetration testing**. Built with pure Win32 API for maximum compatibility and minimal footprint.

> ⚠️ **Educational & Authorized Testing Purposes Only**

## Screenshot|Scan Persistence

<img src="https://github.com/user-attachments/assets/dfa86ceb-99bb-4adb-97fb-2a2f0ea40a72">

---

## ✨ Features

| Category | Capabilities |
|----------|-------------|
| **🔍 Reconnaissance** | Native system fingerprinting (UAC level, build number, elevation status) |
| **🛡️ Vulnerability Assessment** | 15+ UAC bypass method compatibility detection |
| **💀 Persistence Analysis** | 11 persistence technique viability scanning |
| **⚡ Execution Engine** | Pure Win32 API implementation (no external dependencies) |
| **🎨 User Experience** | Color-coded Python wrapper with detailed tabular reporting |

---

## Screenshot|Scan Uac

<img src="https://github.com/user-attachments/assets/c270ba15-c314-4538-89b7-f68c308d82dd">

## 🚀 Installation

### Prerequisites
- Windows 7/10/11 (x64/x86)
- Python 3.7+ (for wrapper only)
- Visual Studio / MinGW (for compilation)

### Build from Source

```bash
# Clone repository
git clone https://github.com/Mr-Spect3r/MyUac
cd MyUac

# Compile native DLL (MSVC)
cl /LD /O2 myuac.cpp /Fe:dll/myuac.dll /link shell32.lib advapi32.lib ole32.lib

# Or using MinGW
g++ -shared -O2 -o myuac.dll dll/myuac.cpp -lshell32 -ladvapi32 -lole32
```

## Python Wrapper Setup

```
pip install colorama tabulate
```

# 📖 usage

### Scanning Mode

```
# Scan UAC Bypass Methods:

python MyUac.py --scan
```

### Scan Persistence Techniques:

```
python MyUac.py --scan-per
```

# ⚡ Exploitation Mode

```
# Execute UAC Bypass:

python MyUac.py -m <method_id> <path_to_executable>

# Example:

python MyUac.py -m 2 C:\Windows\System32\cmd.exe
```

```
# Execute UAC Bypass

python MyUac.py -p <method_id> <path_to_executable>
# Example:
python MyUac.py -p 5 C:\Windows\System32\cmd.exe

```
