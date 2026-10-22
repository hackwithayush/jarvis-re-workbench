# JARVIS Reverse Engineering Workbench v1.0
**Unified AI-Assisted Reverse Engineering, Forensics & Binary Analysis Platform**

A professional, modular, evidence-backed reverse engineering workbench integrating deep static parsing, multi-engine decompilation, control-flow recovery, controlled dynamic observation, cross-tool correlation, and grounded AI reasoning across 10 specialized reverse-engineering engines.

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
│   └── x64dbg_adapter.py         # x64dbg Debugger Workflow Integration
├── tests\                        # Comprehensive Automated Test Suite (38 Tests)
│   ├── test_mvp.py               # Baseline MVP Regression Tests
│   ├── test_phase2_parsers.py    # PE, ELF, Mach-O, Archives, Strings, Malformed
│   ├── test_phase3_adapters.py   # Real DIE, radare2, Versioning, Subprocess Timeouts
│   ├── test_phase4_disassembly.py# Disassembly, CFG Blocks, Pseudo-C Decompiler
│   ├── test_phase5_sandbox.py    # Sandbox Containment & Authorization Gates
│   ├── test_phase6_evidence.py   # Correlation, Deduplication, Memory/Network Rules
│   ├── test_phase7_ai.py         # Grounded AI Explanations & Briefings
│   └── test_phase8_api.py        # Async Jobs, Endpoints, Report Exports (MD, JSON, HTML)
├── run.bat                       # 1-Click Windows Launcher
└── pytest.ini                    # Automated Test Runner Configuration
```

---

## ⚡ Key Capabilities in v1.0

1. **Deep Format Parsing**:
   - **PE/COFF (32-bit & 64-bit)**: DOS/COFF headers, sections, per-section Shannon entropy, AddressOfEntryPoint, COFF TimeDateStamp, imports directory (DLLs and API functions with suspicious heuristic flagging), export directory, CodeView RSDS PDB debug paths, .NET CLR runtime header (COR20), and imphash.
   - **ELF**: 32/64-bit, little/big endian, headers, section tables, and `PT_GNU_STACK` executable stack (NX/DEP) detection.
   - **Mach-O**: 32-bit, 64-bit, and Fat/Universal binaries with `LC_MAIN` entry points and `LC_LOAD_DYLIB` dynamic library dependencies.
   - **Bounded Archive Inspection**: ZIP, TAR, APK, and JAR parsing with member inventory, executable payload identification, and anti-zip-bomb safeguards (100:1 ratio limit, 100 MB max uncompressed limit).
   - **String Engine**: Printable ASCII and UTF-16LE wide string extraction with heuristic classification for URLs, IPv4 addresses, Windows Registry keys, suspicious Win32 APIs, GUIDs, and file paths.

2. **Real Tool Integration**:
   - **Detect It Easy (DIE)**: Identifies compilers, linkers, packers, protectors, and installers via CLI.
   - **radare2 / rabin2**: Extracts security mitigations (NX, Stack Canary, ASLR/PIC) and function metadata with cyclomatic complexity, sizes, and addresses.
   - **ILSpy**: Decompiles managed .NET assemblies into recovered C# source code files.
   - **Ghidra Headless**: Batch decompilation and symbol recovery integrated with OpenJDK 21.
   - **angr**: Symbolic execution and CFGFast graph analysis.

3. **Disassembly & Decompilation**:
   - Function disassembly listings with addresses, raw bytes, opcodes, and cross-references.
   - Control-Flow Graph (CFG) basic blocks with jump and fallthrough branch targets.
   - Interactive decompiler views: pseudo-C code for native binaries and C# for .NET binaries.

4. **Controlled Isolated Sandbox**:
   - Optional, containment-isolated dynamic execution workflow.
   - Explicit analyst confirmation gate: static triage never automatically runs untrusted binaries.
   - Network isolation by default, process execution duration, exit codes, and stdout/stderr capture.
   - Transparently labels events as `OBSERVED`, `INFERRED`, or `NOT_OBSERVED`.

5. **Unified Evidence Correlation**:
   - Multi-source deduplication preserving full tool provenance.
   - Correlates cross-domain evidence (e.g. memory manipulation APIs + high section entropy -> Unpacking/Injection hypothesis).
   - Transparent confidence scores with documented reasoning.
   - Explicitly separates benign indicators from suspicious anomalies.

6. **Grounded AI Analyst**:
   - Explains recovered function instructions and pseudo-C code in context.
   - Maps imported APIs to operational capabilities.
   - Generates investigation briefs tied strictly to verified finding IDs and addresses.

7. **Asynchronous Job Management**:
   - Multi-worker background job queue (`/api/jobs`).
   - Real-time progress polling without blocking web or API requests.

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

Run the complete test suite across all 8 modules (38 tests):
```powershell
python -m pytest tests/
```
All 38 tests verify parsers, tool adapters, disassembly, sandbox safety gates, evidence correlation, AI analyst, and API endpoints.
