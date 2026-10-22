# Known Limitations & Boundaries

To preserve scientific rigor and transparency, this document records the current technical limitations, format boundaries, and edge cases of the JARVIS Reverse Engineering Workbench v1.0.

---

## 1. Deep Binary Analysis & Decompilation

- **Ghidra Analysis Latency on Very Large Binaries:**
  - Files larger than 50 MB (such as Electron wrappers, large game engines, or monolithic installers) can take several minutes to analyze in headless batch mode.
  - *Recommendation:* Run initial triage with radare2 and DIE first; invoke Ghidra on-demand only for target functions or small unpacked payloads.

- **Angr State Space Explosion:**
  - Symbolic execution via angr is computationally intensive. On complex binaries with deep loops, cryptography routines, or opaque predicates, symbolic path exploration can encounter state space explosions.
  - *Mitigation:* The adapter enforces a strict 120-second timeout and bounds CFG recovery depth.

- **Non-Standard Bytecode Formats:**
  - Decompilation for Python `.pyc`, Golang binaries, and WebAssembly (`.wasm`) currently relies on string extraction and disassembler heuristics. Dedicated Golang symbol recovery (pclntab parser) is scheduled for future minor releases.

---

## 2. Sandbox Isolation & Dynamic Analysis

- **Native Windows Sandbox vs Hypervisor Virtualization:**
  - The built-in controlled sandbox operates at the user-space process boundary via proxy redirection and process termination. It does not provide hypervisor-grade ring-0 kernel isolation.
  - *Security Mandate:* Severe malware or rootkits must only be executed inside a dedicated VirtualBox / VMware / Hyper-V VM with snapshot rollback capabilities, or via Windows Sandbox (`.wsb`).

- **Anti-Analysis & Evasion Techniques:**
  - Binaries implementing advanced anti-debugging (e.g., `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, timing checks via `RDTSC`) may alter their behavior or terminate prematurely during dynamic execution or Frida hooking.

---

## 3. Toolchain & Platform Requirements

- **Windows Host Dependency:**
  - While radare2, Ghidra, and Python run cross-platform, certain adapters (`x64dbg`, specific DIE Windows paths, Windows Sandbox `.wsb`) are Windows-specific.
  - Linux and macOS environments require updating tool paths in `app/core/tools.py` to POSIX defaults (`/usr/bin/radare2`, etc.).

- **Memory Constraints for Headless Ghidra:**
  - Ghidra's JVM requires at least 2 GB of available heap memory. Systems with less than 8 GB total system RAM may experience JVM out-of-memory errors on large executables.
