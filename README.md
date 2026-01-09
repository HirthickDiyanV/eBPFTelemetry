# 🛡️ eBPF Ransomware Behaviour Analyzer

![Platform](https://img.shields.io/badge/Platform-Linux-linux?style=for-the-badge&logo=linux)
![Language](https://img.shields.io/badge/Language-Python%203%20%7C%20C-blue?style=for-the-badge&logo=python)
![Tech](https://img.shields.io/badge/Technology-eBPF%20(BCC)-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

> **A zero-overhead, kernel-level behavioral analysis tool designed to detect ransomware encryption patterns in real-time.**

---

## 📖 Abstract

Traditional antivirus solutions often rely on static file signatures, which are easily bypassed by new malware variants. This project takes a different approach: **Behavioral Profiling**.

Using **eBPF (Extended Berkeley Packet Filter)**, this tool hooks directly into the Linux kernel's `vfs_write` syscall. It analyzes the **velocity** and **volume** of filesystem writes to identify malicious actors. By performing in-kernel aggregation using BPF Hash Maps, we filter out ~95% of benign system noise (logs, flag updates) to focus purely on high-throughput anomalies characteristic of ransomware encryption.

---

## 🛠️ Key Features

* **⚡ Zero-Copy Profiling:** Uses `BPF_HASH` maps to count syscalls in kernel space, avoiding expensive context switches.
* **🔍 Noise Filtering:** Automatically ignores tiny system writes (logs, GUI updates), isolating "heavy" I/O operations.
* **📊 Live TUI Dashboard:** A terminal-based UI that visualizes write intensity in real-time.
* **🛡️ Evasion Resistant:** Since it hooks the kernel syscall interface, it catches activity even if the malware tries to hide its process name or use unbuffered I/O.

---

## 🚀 Installation

### Prerequisites
You need a Linux kernel with eBPF support (4.4+) and the BCC tools installed.

**Ubuntu / Debian**
```bash
sudo apt-get update
sudo apt-get install bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
pip3 install rich
```
---

## 🕹️ Usage

### Step 1: Start the Detector
```bash
sudo python3 main.py
```
### Step 2: Simulate an Attack
```bash
sudo python3 test.py
```
