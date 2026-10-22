# REST API Reference & Specification

The JARVIS Reverse Engineering Workbench exposes a comprehensive RESTful API built on FastAPI. Interactive Swagger UI is accessible at `/docs` and ReDoc at `/redoc`.

---

## Base URL
```
http://127.0.0.1:8000
```

---

## Endpoints Overview

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Web Workbench UI dashboard. |
| `GET` | `/api/status` | Global system status, host information, and active jobs count. |
| `GET` | `/api/tools` | Status and paths for all 14 reverse-engineering tools. |
| `POST` | `/api/analyze` | Upload a binary file and execute automated static triage. |
| `POST` | `/api/analyze/async` | Asynchronous file analysis submission returning a `job_id`. |
| `GET` | `/api/jobs/{job_id}` | Poll progress and retrieve results for an asynchronous job. |
| `GET` | `/api/reports` | List all historical analysis reports in storage. |
| `GET` | `/api/reports/{report_id}` | Retrieve full JSON report for a specific analysis run. |
| `POST` | `/api/deep/ghidra/{report_id}` | Trigger Ghidra Headless decompilation and function recovery on sample. |
| `POST` | `/api/deep/angr/{report_id}` | Trigger angr CFG recovery and symbolic control-flow analysis. |
| `POST` | `/api/dynamic/execute` | Execute sample in isolated controlled sandbox (Requires Consent Token). |
| `POST` | `/api/ai/explain` | AI explanation and semantic summary of disassembled/decompiled code. |

---

## Detailed Endpoint Specifications

### 1. System Status
`GET /api/status`

**Response Example:**
```json
{
  "system": "JARVIS Reverse Engineering Workbench",
  "version": "1.0.0",
  "status": "online",
  "active_jobs": 0,
  "supported_formats": ["PE", "ELF", "Mach-O", "DEX", "ZIP", "Raw"]
}
```

---

### 2. Tool Ecosystem Status
`GET /api/tools`

**Response Example:**
```json
{
  "tools": {
    "ghidra": {"available": true, "path": "C:\\Tools\\ghidra\\...\\analyzeHeadless.bat", "version": "12.1.4_PUBLIC"},
    "radare2": {"available": true, "path": "C:\\Tools\\radare2\\bin\\radare2.exe", "version": "6.2.4"},
    "die": {"available": true, "path": "C:\\Tools\\die\\diec.exe", "version": "3.21"},
    "jadx": {"available": true, "path": "C:\\Tools\\jadx\\bin\\jadx.bat", "version": "1.5.6"},
    "ilspy": {"available": true, "path": "C:\\Users\\...\\.dotnet\\tools\\ilspycmd.exe", "version": "11.1"},
    "capa": {"available": true, "path": "flare-capa", "version": "10.0.0"},
    "yara": {"available": true, "path": "yara-python", "version": "4.5.0"},
    "frida": {"available": true, "path": "frida", "version": "17.24.3"},
    "angr": {"available": true, "path": "angr", "version": "9.2.213"}
  }
}
```

---

### 3. Binary Static Analysis (Synchronous)
`POST /api/analyze`

**Request:** `multipart/form-data`
- `file`: Executable or binary file payload (up to 500 MB).

**Response (Summary):**
```json
{
  "id": "e84f2c99-a1d2-4309-8b01-57d42cf3b08e",
  "filename": "sample.exe",
  "file_size": 204800,
  "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
  "format": "PE",
  "architecture": "x86_64",
  "entropy": 6.84,
  "die": {"filetype": "PE64", "detects": [{"type": "compiler", "name": "Microsoft Visual C/C++"}]},
  "capa": {"rules_matched": 12, "capabilities": ["connect to C2 server", "create process"]},
  "yara": {"matches": []},
  "findings": [
    {
      "id": "find_001",
      "type": "capability",
      "source_tool": "capa",
      "confidence": 0.95,
      "description": "Binary contains logic to initiate outbound HTTP connections"
    }
  ]
}
```

---

### 4. Controlled Dynamic Sandbox Execution
`POST /api/dynamic/execute`

**Headers:**
- `Content-Type: application/json`
- `X-Analyst-Consent: True`

**Request Body:**
```json
{
  "report_id": "e84f2c99-a1d2-4309-8b01-57d42cf3b08e",
  "consent_token": "CONFIRMED_ANALYST_EXECUTION",
  "timeout_sec": 10,
  "allow_network": false,
  "arguments": ["--test-arg"]
}
```

**Security Enforcement:**
If `consent_token` does not match `"CONFIRMED_ANALYST_EXECUTION"`, the request is rejected with `HTTP 403 Forbidden` (`{"error": "Dynamic execution rejected: explicit analyst confirmation required."}`).

**Response Example:**
```json
{
  "status": "completed",
  "exit_code": 0,
  "duration_sec": 0.84,
  "timed_out": false,
  "network_blocked": true,
  "stdout": "Sample started...\nInitializing modules...\nTerminating cleanly.\n",
  "stderr": "",
  "created_files": [],
  "network_attempts": []
}
```

---

### 5. On-Demand Deep Ghidra Decompilation
`POST /api/deep/ghidra/{report_id}`

Runs NSA Ghidra in headless batch mode (`analyzeHeadless.bat`) against the quarantined sample and extracts recovered C pseudocode, imports, cross-references, and symbols.

**Response Example:**
```json
{
  "status": "success",
  "functions_count": 84,
  "functions": [
    {
      "name": "entry",
      "address": "0x140001000",
      "decompiled_c": "void entry(void) {\n    __security_init_cookie();\n    main();\n}"
    }
  ]
}
```

---

### 6. AI Code Understanding
`POST /api/ai/explain`

**Request Body:**
```json
{
  "code": "int sub_140001000(char *dst, char *src) {\n    while(*src) *dst++ = *src ^ 0x5A;\n    return 0;\n}",
  "context": "Function located at offset 0x1000"
}
```

**Response Example:**
```json
{
  "analysis": "This function is an XOR decryption routine with a single-byte rolling or static key of 0x5A. It decodes string constants or config buffers in memory.",
  "risk_assessment": "Suspicious (Obfuscation / Evasion)",
  "confidence": 0.89
}
```
