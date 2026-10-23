# JARVIS Reverse Engineering Workbench v1.0
**Autonomous Software Reconstruction, Binary Forensics & Original Software Creation Platform**

A professional, modular, evidence-backed reverse engineering and clean-room software creation workbench integrating deep static parsing, multi-engine decompilation, control-flow recovery, controlled dynamic observation, cross-tool correlation, grounded AI reasoning, and an end-to-end **Autonomous Software Reconstruction & Creation Engine**.

---

## 🏛️ Platform Architecture

```
c:\AI\jarvis-re-workbench\
├── app\                          # FastAPI Web Application & API Layer
│   ├── core\                     # Core Intelligence & Analysis Engines
│   │   ├── parsers\              # Deep Pure-Python Structural Parsers
│   │   │   ├── pe_parser.py      # PE32/PE32+ (Headers, Sections, Imports, Exports, PDB, CLR)
│   │   │   ├── elf_parser.py     # ELF32/ELF64 (Headers, Segments, GNU_STACK NX)
│   │   │   ├── macho_parser.py   # Mach-O (32/64/Fat, LC_MAIN, LC_LOAD_DYLIB)
│   │   │   ├── archive_parser.py # Bounded Archive Inspector (Anti-Zip Bomb)
│   │   │   └── string_extractor.py # ASCII & UTF-16LE Classified Strings
│   │   ├── knowledge_graph.py    # Software Knowledge Graph & Mermaid Architecture Maps
│   │   ├── reconstruction_planner.py # 10-Section Clean-Room Specification Generator
│   │   ├── software_generator.py # Clean-Room Original Software Synthesizer
│   │   ├── build_agent.py        # Isolated Compilation, Test Battery & Packaging Agent
│   │   ├── differential_tester.py# Behavioral Conformance & Differential Analysis Engine
│   │   ├── disassembler.py       # Function Disassembly, CFG & C/C# Decompiler
│   │   ├── sandbox.py            # Controlled Isolated Dynamic Execution Jail
│   │   ├── evidence_engine.py    # Cross-Tool Normalization & Correlation Engine
│   │   ├── ai_analyst.py         # Grounded AI Explainer & Hypothesis Generator
│   │   ├── job_manager.py        # Asynchronous Background Analysis Worker
│   │   ├── analyzer.py           # Multi-Engine Analysis Orchestrator
│   │   ├── reporter.py           # Technical Reporting (Markdown, JSON, HTML)
│   │   ├── schema.py             # Shared Evidence Schema & Pydantic Models
│   │   ├── tools.py              # Tool Ecosystem Auditor
│   │   └── utils.py              # Hashes, Entropy & Architecture Helpers
│   ├── static\                   # Dark Stark HUD UI, CSS & Frontend Controller
│   ├── templates\                # Jinja2 Interactive Dashboard
│   └── main.py                   # REST API & Job Polling Endpoints
├── adapters\                     # Canonical Tool Adapters
│   ├── die_adapter.py            # Detect It Easy (DIE 3.21) Compiler/Packer Signatures
│   ├── radare2_adapter.py        # radare2 6.2.4 (Disassembly, CFG, Security Mitigations)
│   ├── ghidra_adapter.py         # Ghidra 12.1.4 Headless Decompiler & OpenJDK 21
│   ├── dnspy_adapter.py          # ILSpy CLI (.NET C# Decompilation)
│   ├── angr_adapter.py           # angr 9.2.213 Symbolic Execution & CFGFast
│   ├── frida_adapter.py          # Frida 17.24.3 Dynamic Instrumentation
│   ├── imhex_adapter.py          # ImHex 1.38.1 Pattern Engine
│   ├── jadx_adapter.py           # JADX 1.5.6 (Android APK / DEX Decompiler)
│   ├── capa_adapter.py           # Mandiant capa 10.0 (Capability Mapping)
│   ├── yara_adapter.py           # YARA 4.5.0 (Rule Matching Engine)
│   └── x64dbg_adapter.py         # x64dbg Debugger Workflow Integration
├── tests\                        # Comprehensive Automated Test Suite (62 Tests)
│   ├── test_mvp.py               # Baseline MVP Regression Tests
│   ├── test_phase2_parsers.py    # PE, ELF, Mach-O, Archives, Strings, Malformed
│   ├── test_phase3_adapters.py   # Real DIE, radare2, Versioning, Subprocess Timeouts
│   ├── test_phase4_disassembly.py# Disassembly, CFG Blocks, Pseudo-C Decompiler
│   ├── test_phase5_sandbox.py    # Sandbox Containment & Authorization Gates
│   ├── test_phase6_evidence.py   # Correlation, Deduplication, Memory/Network Rules
│   ├── test_phase7_ai.py         # Grounded AI Explanations & Briefings
│   ├── test_phase8_api.py        # Async Jobs, Endpoints, Report Exports (MD, JSON, HTML)
│   ├── test_phase9_specialist_tools.py # Specialist Adapters (JADX, capa, YARA)
│   ├── test_regression_pipeline.py     # End-to-End Regression Matrix
│   └── test_software_reconstruction.py # Knowledge Graph, Spec Planner, Builder & Diff Tests
├── run.bat                       # 1-Click Windows Launcher
└── pytest.ini                    # Automated Test Runner Configuration
```

---

## ⚡ Key Capabilities in v1.0

1. **Autonomous Software Reconstruction & Creation Engine**:
   - **Software Knowledge Graph**: Persistent graph representing modules, classes, functions, storage, network endpoints, and external APIs with strict evidence status tracking (`OBSERVED`, `INFERRED`, `HYPOTHESIS`).
   - **10-Section Clean-Room Specification**: Produces structured specifications classifying requirements (`VERIFIED_FROM_EVIDENCE`, `STRONGLY_INFERRED`, `PROPOSED_REPLACEMENT`, `UNKNOWN_REQUIRING_INPUT`).
   - **Original Software Generator**: Generates clean-room independent software projects (code, config, storage models, API endpoints, tests, and documentation) with zero copied proprietary code.
   - **Isolated Build & Validation Agent**: Automatically compiles code, runs test suites with isolated environments, records execution logs, and packages distributable `.zip` bundles.
   - **Differential Behavior Engine**: Evaluates behavioral conformance between reference applications and the clean-room implementation, reporting matching behaviors, discrepancies, and conformance scores.
   - **8-Stage Analyst Workbench**: Step-by-step pipeline in the UI (`Analyze` -> `Map` -> `Spec` -> `Approve` -> `Generate` -> `Build` -> `Diff` -> `Export`).

2. **Deep Format Parsing**:
   - **PE/COFF (32-bit & 64-bit)**: DOS/COFF headers, sections, per-section Shannon entropy, AddressOfEntryPoint, COFF TimeDateStamp, imports directory (DLLs and API functions with suspicious heuristic flagging), export directory, CodeView RSDS PDB debug paths, .NET CLR runtime header (COR20), and imphash.
   - **ELF**: 32/64-bit, little/big endian, headers, section tables, and `PT_GNU_STACK` executable stack (NX/DEP) detection.
   - **Mach-O**: 32-bit, 64-bit, and Fat/Universal binaries with `LC_MAIN` entry points and `LC_LOAD_DYLIB` dynamic library dependencies.
   - **Bounded Archive Inspection**: ZIP, TAR, APK, and JAR parsing with member inventory, executable payload identification, and anti-zip-bomb safeguards (100:1 ratio limit, 100 MB max uncompressed limit).
   - **String Engine**: Printable ASCII and UTF-16LE wide string extraction with heuristic classification for URLs, IPv4 addresses, Windows Registry keys, suspicious Win32 APIs, GUIDs, and file paths.

3. **Multi-Engine Tool Ecosystem**:
   - **Detect It Easy (DIE)**: Identifies compilers, linkers, packers, protectors, and installers via CLI.
   - **radare2 / rabin2**: Extracts security mitigations (NX, Stack Canary, ASLR/PIC) and function metadata with cyclomatic complexity, sizes, and addresses.
   - **ILSpy**: Decompiles managed .NET assemblies into recovered C# source code files.
   - **Ghidra Headless**: Batch decompilation and symbol recovery integrated with OpenJDK 21.
   - **angr**: Symbolic execution and CFGFast graph analysis.
   - **JADX**: Decompilation of Android APK and DEX bytecode into Java source trees.
   - **Mandiant capa**: High-level capability detection and MITRE ATT&CK technique mapping.
   - **YARA**: Rule-based signature and pattern matching engine.

4. **Controlled Isolated Sandbox**:
   - Optional, containment-isolated dynamic execution workflow.
   - Explicit analyst confirmation gate: static triage never automatically runs untrusted binaries.
   - Network isolation by default, process execution duration, exit codes, and stdout/stderr capture.

5. **Unified Evidence Correlation**:
   - Multi-source deduplication preserving full tool provenance.
   - Correlates cross-domain evidence with transparent confidence scores.
   - Grounded AI reasoning explaining functions and generating technical briefs.

---

## 🚀 Quickstart (Windows PC)

### Option 1: One-Click Windows Launcher
Double-click `run.bat` in this folder. It launches the FastAPI server on `http://127.0.0.1:8000`.

### Option 2: PowerShell / Terminal
```powershell
cd C:\AI\jarvis-re-workbench
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser.

---

## 🧪 Running Automated Tests

Run the complete test suite across all 11 modules (62 tests):
```powershell
python -m pytest tests/
```
All 62 tests verify parsers, tool adapters, disassembly, sandbox safety gates, evidence correlation, AI analyst, API endpoints, knowledge graphs, software synthesis, build agents, and differential testing.
