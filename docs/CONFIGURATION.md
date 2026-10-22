# Configuration & Environment Reference

The JARVIS Reverse Engineering Workbench uses environment variables and Python configuration files to control analysis constraints, tool resolution paths, sandbox security profiles, and AI model backends.

---

## 1. Primary Configuration Files

- **Application Settings:** [`app/core/config.py`](file:///c:/AI/jarvis-re-workbench/app/core/config.py)
- **Tool Autodiscovery:** [`app/core/tools.py`](file:///c:/AI/jarvis-re-workbench/app/core/tools.py)
- **Controlled Sandbox:** [`app/core/sandbox.py`](file:///c:/AI/jarvis-re-workbench/app/core/sandbox.py)

---

## 2. Environment Variables

Set these environment variables before starting the workbench or define them in a `.env` file in the repository root:

| Variable | Default Value | Description |
|---|---|---|
| `JARVIS_HOST` | `127.0.0.1` | Binding IP address for the FastAPI web server. |
| `JARVIS_PORT` | `8000` | HTTP port for the API and frontend dashboard. |
| `JARVIS_MAX_UPLOAD_MB` | `500` | Maximum file size allowed for intake upload (in Megabytes). |
| `JARVIS_WORKSPACE_DIR` | `workspace` | Root directory for reports, quarantined samples, and temporary artifacts. |
| `JAVA_HOME` | Auto-detected | Path to Java JDK 21+ installation directory. |
| `GHIDRA_HOME` | Auto-detected | Path to Ghidra root directory containing `support/analyzeHeadless.bat`. |
| `SANDBOX_TIMEOUT_SEC` | `15` | Default maximum execution time for dynamic sandbox sessions. |
| `SANDBOX_ENABLE_NETWORK` | `False` | Boolean flag. When `False`, enforces loopback null-routing for sandboxed processes. |
| `OPENAI_API_KEY` | None | Optional key for external LLM-assisted function explanation. |
| `GEMINI_API_KEY` | None | Optional Google Gemini API key for automated summary generation. |

---

## 3. Directory Layout

The workbench structures its filesystem workspaces predictably:

```
C:\AI\jarvis-re-workbench\
├── workspace/
│   ├── samples/
│   │   └── {report_id}/
│   │       └── {filename}         <-- Quarantined, non-executable sample storage
│   ├── reports/
│   │   └── report_{filename}.json <-- Persisted JSON report artifacts
│   ├── ghidra_projects/           <-- Headless Ghidra project storage
│   └── sandbox/                   <-- Disposable temporary sandbox directories
```

---

## 4. Execution Timeouts & Limits

To prevent denial-of-service from malformed or obfuscated binaries, strict execution timeouts are enforced per adapter:

| Subsystem | Maximum Timeout | Enforcement Mechanism |
|---|---|---|
| Detect It Easy (DIE) | 30 seconds | `subprocess.run(timeout=30)` |
| radare2 Inspection | 60 seconds | `subprocess.run(timeout=60)` |
| Ghidra Headless Analyzer | 300 seconds | `subprocess.run(timeout=300)` |
| angr Symbolic CFG | 120 seconds | Thread / Subprocess timeout |
| JADX Decompiler | 180 seconds | `subprocess.run(timeout=180)` |
| Controlled Sandbox | 15 seconds | `process.wait(timeout=timeout)` + terminate & kill |

---

## 5. Security & Isolation Tuning

By default:
1. Binaries are never executed during static triage.
2. Dynamic sandbox execution requires an explicit Analyst Authorization Token:
   - Header: `X-Analyst-Consent: True`
   - Payload: `{"consent_token": "CONFIRMED_ANALYST_EXECUTION"}`
3. Sandbox child processes are launched with clean environment variables (`clean_env`), network proxies set to non-routable interfaces (`http_proxy=http://127.0.0.1:0`), and disposable temporary working folders deleted upon completion.
