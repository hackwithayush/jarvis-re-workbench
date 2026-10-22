# JARVIS RE Workbench — Architecture Specification v1.0

## 1. System Overview

JARVIS RE Workbench is a modular, evidence-grounded reverse-engineering platform engineered for binary inspection, static forensics, deep disassembly, decompiler recovery, capability detection, and controlled dynamic observation.

```
+-----------------------------------------------------------------------------------+
|                           Web UI & Interactive Dashboard                           |
|        File Intake  |  Disassembly  |  Decompilation  |  CFG  |  Sandbox  |  AI     |
+-----------------------------------------+-----------------------------------------+
                                          | REST API / WebSockets
+-----------------------------------------v-----------------------------------------+
|                              FastAPI Service Layer                                |
|  - Asynchronous background job queue (JobManager) with progress & status polling   |
|  - Multi-stage dispatch pipeline (BinaryAnalyzer)                                  |
|  - Evidence correlation & deduplication engine (EvidenceCorrelationEngine)         |
|  - Multi-format report synthesizer (ReportGenerator: Markdown, JSON, HTML)        |
+-------------------+---------------------+---------------------+-------------------+
                    |                     |                     |
+-------------------v---+   +-------------v-------+   +---------v---------+
|    Static Parsers     |   |   Tool Adapters     |   | Dynamic Sandbox   |
| - PE32 / PE+ / .NET   |   | - Ghidra Headless   |   | - Isolated Jail   |
| - ELF (x86/x64/ARM)   |   | - radare2 (r2/agj)  |   | - Token Gate      |
| - Mach-O 32/64-bit    |   | - Detect It Easy    |   | - Network Block   |
| - Android DEX / APK   |   | - JADX (APK/DEX)    |   | - Process Tree    |
| - Nested Archives     |   | - ILSpy (ilspycmd)  |   | - Telemetry Log   |
| - Shannon Entropy     |   | - angr (CFGFast)    |   +-------------------+
| - String Forensics    |   | - Mandiant capa     |
+-----------------------+   | - YARA Signatures   |
                            | - x64dbg / Frida    |
                            | - LIEF / ImHex      |
                            +---------------------+
```

## 2. Core Subsystems

### A. Intake & Identification Pipeline
1. **Cryptographic Integrity**: SHA-256, MD5, SHA-1 calculated in 64 KB chunks.
2. **Format Recognition**: Magic byte signatures (MZ, \x7fELF, 0xfeedface, 0xcafebabe, PK\x03\x04, ustar) independent of file extension.
3. **PE/COFF Extraction**: Machine type, sections, entropy distribution, imports (with imphash), exports, and entry point.
4. **ELF / Mach-O Parsing**: Class (32/64), endianness, program headers, section tables.
5. **Archive Recursion Limits**: Max recursion depth: 3, Max member count: 500, Max decompressed volume: 1 GB.

### B. Deep Decompilation & Reverse Engineering
1. **radare2**:
   - Instruction disassembly with opcodes and mnemonic operands (`pdfj`).
   - Control-Flow Graph (CFG) basic block recovery with jump and fail targets (`agj`).
   - Pseudo-C decompiler representation (`pdc`).
2. **Ghidra Headless**:
   - Headless SRE execution (`analyzeHeadless.bat`).
   - Post-analysis script exporting function signatures, calling conventions, cross-references, and symbols.
3. **ILSpy (.NET)**:
   - Recovers high-level C# source code files from .NET assemblies using `ilspycmd`.
4. **JADX (Android)**:
   - Full Java decompilation from DEX bytecode and APK packages with `AndroidManifest.xml` permissions parsing.
5. **angr**:
   - Static `CFGFast()` recovery and constraint solving.

### C. Capability Detection & Heuristics
1. **Mandiant capa**: High-level rule matching mapped to MITRE ATT&CK tactics.
2. **YARA**: Automated rule matching for process injection, crypto ransomware, and debugger evasion.
3. **Shannon Entropy**: Per-section entropy calculations flagging packed or encrypted overlays.

### D. Controlled Dynamic Analysis
- Isolated disposable temporary jail directory.
- Strictly gated: **Never executed automatically during static triage**.
- Requires explicit analyst confirmation token.
- Environmental network isolation (`HTTP_PROXY=127.0.0.1:0`).
- Process execution duration, exit code, and stdout/stderr capture.

### E. Unified Evidence & AI Analyst Engine
- Standardized finding schema with stable ID, tool provenance, confidence, and verification status.
- Deduplication pass combining multi-tool corroborated observations.
- AI Analyst generating evidence-grounded hypotheses citing function addresses and finding IDs.
