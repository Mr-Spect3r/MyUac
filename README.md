# 🔓 UAC Bypass & Persistence Toolkit

<div align="center">

[![Windows](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)](https://microsoft.com)
[![C++](https://img.shields.io/badge/C++-Native-00599C?logo=c%2B%2B&logoColor=white)](https://isocpp.org)
[![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Native Windows UAC Evasion & Persistence Detection Framework**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Methods](#-methods) • [Disclaimer](#-disclaimer)

</div>

---

## 🎯 Overview

A professional-grade **native Windows** security testing toolkit designed for **red team operations** and **penetration testing**. Built with pure Win32 API for maximum compatibility and minimal footprint.

> ⚠️ **Educational & Authorized Testing Purposes Only**

## Screenshot|Scan Uac

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

## 🚀 Installation

### Prerequisites
- Windows 7/10/11 (x64/x86)
- Python 3.7+ (for wrapper only)
- Visual Studio / MinGW (for compilation)

### Build from Source

```bash
# Clone repository
git clone https://github.com/Mr-Spect3r/UAC-Toolkit.git
cd UAC-Toolkit

# Compile native DLL (MSVC)
cl /LD /O2 myuac.cpp /Fe:dll/myuac.dll /link shell32.lib advapi32.lib ole32.lib

# Or using MinGW
g++ -shared -O2 -o myuac.dll dll/myuac.cpp -lshell32 -ladvapi32 -lole32
```

