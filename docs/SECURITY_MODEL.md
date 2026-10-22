# Security Model & Threat Mitigation

Binary reverse engineering presents intrinsic security risks: untrusted files may attempt to exploit analysis tools, achieve code execution on the analyst's workstation, or connect to adversary infrastructure.

JARVIS RE Workbench implements a defense-in-depth security model to safeguard analyst environments.

---

## 1. Core Security Axioms

1. **Zero Automatic Dynamic Execution:**
   - Static analysis is strictly passive. Binaries are parsed, inspected, disassembled, and decompiled using safe file parsers and memory-isolated tools.
   - Files are NEVER executed automatically during ingestion, triage, or report generation.

2. **Mandatory Explicit Analyst Consent:**
   - Any dynamic execution or live debugging requires explicit consent via API headers and an exact payload token (`CONFIRMED_ANALYST_EXECUTION`).
   - UI interfaces display high-visibility warning prompts requiring intentional opt-in before launching sandbox sessions.

3. **Sample Quarantine:**
   - Uploaded files are copied into a designated workspace directory (`workspace/samples/{report_id}/`) where executable permissions can be restricted.
   - Filenames are sanitized via secure filename sanitizers (`secure_filename` / regex alphanumeric filtering) to prevent path traversal attacks (`../../evil.exe`).

---

## 2. Controlled Sandbox Isolation

The dynamic execution engine ([`app/core/sandbox.py`](file:///c:/AI/jarvis-re-workbench/app/core/sandbox.py)) enforces the following controls on Windows:

### A. Network Isolation
- Sandboxed processes run with non-routable proxy variables injected:
  - `HTTP_PROXY = http://127.0.0.1:0`
  - `HTTPS_PROXY = http://127.0.0.1:0`
  - `ALL_PROXY = http://127.0.0.1:0`
- Prevents direct command-and-control (C2) beaconing, outbound payload downloads, and local network lateral movement.

### B. Clean Environment Scoping
- Sensitive environment variables (e.g., analyst API tokens, AWS/GCP credentials, user profile paths, browser cookies) are stripped from child process environments.
- Child processes receive only minimal system variables (`SystemRoot`, `PATH` restricted to system32).

### C. Hard Execution Deadlines & Resource Quotas
- Hard process timeouts (default 10–15 seconds) terminate stalled or stalling processes via `process.kill()`.
- Process tree termination kills orphaned child processes spawned by loaders or droppers.

### D. Ephemeral Working Directories
- Each sandbox run executes within an isolated, temporary folder.
- Dropped artifacts, temp files, and registry traces are recorded and isolated, preventing workstation persistence.

---

## 3. Toolchain Vulnerability Hardening

Reverse engineering tools (e.g., disassemblers, decompilers, parser libraries) can themselves be targeted by parser exploits (e.g., malformed ELF/PE headers, zip bombs, buffer overflows).

- **Decompression Bombs:** Zip/archive intake limits total uncompressed size (capped at 500 MB) and recursion depth (maximum 3 nested layers).
- **Process Sandboxing:** Radare2 and DIE execute as short-lived, unprivileged child processes with strict stdout/stderr size truncation (max 10 MB per stream).
- **Ghidra Isolation:** Ghidra runs in headless batch mode without GUI rendering components, mitigating UI-related scripting or clickjacking attacks.

---

## 4. Evidence Provenance & Integrity

- Every finding is tagged with:
  - Source tool name and exact version (e.g., `ghidra:12.1.4_PUBLIC`, `capa:10.0.0`)
  - Verification state (`verified`, `hypothesis`, `heuristic`, `unverified`)
  - Exact target file SHA-256 digest
- AI models are never allowed to fabricate binary facts. All AI explanations are anchored to verifiable assembly instructions, recovered pseudocode, or parsed strings.
