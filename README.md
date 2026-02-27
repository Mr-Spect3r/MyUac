### 🔓 UAC Bypass & Persistence Toolkit

<div align="center">

[![Windows](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)](https://microsoft.com)
[![C++](https://img.shields.io/badge/C++-Native-00599C?logo=c%2B%2B&logoColor=white)](https://isocpp.org)
[![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Advanced UAC Evasion & Persistence Detection Framework**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Methods](#-methods) • [Disclaimer](#-disclaimer)

</div>

---

## 🎯 Overview

A professional-grade security testing toolkit designed for **red team operations** and **penetration testing**. This tool provides comprehensive scanning and exploitation capabilities for Windows UAC bypass techniques and persistence mechanisms.

> ⚠️ **Educational & Authorized Testing Purposes Only**

---

## ✨ Features

| Category | Capabilities |
|----------|-------------|
| **🔍 Reconnaissance** | Automated system fingerprinting (UAC level, build number, elevation status) |
| **🛡️ Vulnerability Assessment** | 15+ UAC bypass method compatibility detection |
| **💀 Persistence Analysis** | 11 persistence technique viability scanning |
| **⚡ Execution Engine** | Native DLL integration for reliable exploitation |
| **🎨 User Experience** | Color-coded output with detailed tabular reporting |

---

## 🚀 Installation

### Prerequisites
- Windows 7/10/11 (x64 recommended)
- Python 3.7+
- Visual C++ Redistributable

### Setup

```bash
# Clone repository
git clone https://github.com/Mr-Spect3r/UAC-Toolkit.git
cd UAC-Toolkit

# Install Python dependencies
pip install colorama tabulate

# Build native DLL (Visual Studio)
cl /LD myuac.cpp /Fe:myuac.dll /link shell32.lib advapi32.lib
