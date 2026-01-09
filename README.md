# 🛡️ eBPF Telemetry

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

## 🏗️ Architecture

The system avoids the performance penalty of traditional monitoring agents by keeping the heavy lifting inside the Kernel.

```mermaid
graph LR
    A[App/Malware] -- "vfs_write()" --> B((Linux Kernel))
    B -- "eBPF Hook" --> C{Size Filter}
    C -- "< 64 Bytes" --> D[Discard (Noise)]
    C -- ">= 64 Bytes" --> E[BPF_HASH Map]
    E -- "Aggregation" --> F[Count & Volume]
    F -- "1 sec interval" --> G[Python Userspace]
    G --> H[TUI Dashboard]
