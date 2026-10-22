# Windows Installation & Setup Guide

This guide details the complete installation procedure for the **JARVIS Reverse Engineering Workbench v1.0** on Microsoft Windows (Windows 10 / 11 / Server 2019+ x64).

---

## 1. Prerequisites & Base System Requirements

- **Operating System:** Windows 10/11 x64 or Windows Server 2019+ x64
- **Python:** Python 3.10+ (x64) with `pip`
- **Memory (RAM):** 8 GB minimum (16 GB+ recommended for Ghidra and angr symbolic execution)
- **Disk Space:** 5 GB free for tools, JDK, and temporary analysis workspaces

---

## 2. Python Environment Setup

From an elevated PowerShell prompt or standard user terminal:

```powershell
cd C:\AI\jarvis-re-workbench

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Upgrade pip & install core dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Verify that primary Python binary analysis libraries are available:
```powershell
python -c "import angr, frida, capa, yara, lief; print('Python binary analysis dependencies verified.')"
```

---

## 3. Toolchain Installation

The workbench features 14 integrated tools. Below are the verified installation paths and Chocolatey/manual instructions for each tool:

| Tool | Recommended Path / Method | Verification Command |
|---|---|---|
| **OpenJDK 21** | `C:\Tools\jdk-21\jdk-21.0.12.1+1\bin\java.exe` or `choco install openjdk --version=21.0.2 -y` | `java -version` |
| **Ghidra 12.1+** | `C:\Tools\ghidra\ghidra_12.1.4_PUBLIC\support\analyzeHeadless.bat` | `analyzeHeadless.bat -help` |
| **Detect It Easy (DIE)** | `C:\Tools\die\diec.exe` or `choco install die -y` | `diec -v` |
| **radare2** | `C:\Tools\radare2\bin\radare2.exe` or `choco install radare2 -y` | `radare2 -v` |
| **JADX (APK/DEX)** | `C:\Tools\jadx\bin\jadx.bat` or GitHub Release | `jadx --version` |
| **ILSpy / dnSpyEx** | `C:\Users\<USER>\.dotnet\tools\ilspycmd.exe` (`dotnet tool install -g ilspycmd`) | `ilspycmd --version` |
| **Cutter / Rizin** | `C:\Tools\cutter\Cutter-v2.5.0-Windows-x86_64\cutter.exe` | GUI Application |
| **x64dbg** | `C:\Tools\x64dbg\release\x64\x64dbg.exe` | GUI Application |
| **ImHex** | `C:\Tools\imhex\imhex.exe` or `choco install imhex -y` | GUI Application |
| **Mandiant capa** | Python pip: `flare-capa` | `capa --version` |
| **YARA** | Python pip: `yara-python` | Python import |
| **LIEF** | Python pip: `lief` | Python import |
| **Frida** | Python pip: `frida` & `frida-tools` | `frida --version` |
| **angr** | Python pip: `angr` | Python import |

### Automated PATH Configuration

If external binaries are installed in `C:\Tools\...`, JARVIS RE Workbench automatically scans common tool locations and sets temporary process environments (`JAVA_HOME`, `PATH`) upon initialization in `app/core/tools.py`.

To persist global paths manually in PowerShell:
```powershell
[Environment]::SetEnvironmentVariable("JAVA_HOME", "C:\Tools\jdk-21\jdk-21.0.12.1+1", "Machine")
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Tools\radare2\bin;C:\Tools\die;C:\Tools\jadx\bin", "Machine")
```

---

## 4. Verification

Run the test suite to ensure all adapters and core engines execute cleanly:

```powershell
python -m pytest -v
```

Expected result:
```
============================= 43 passed in 40s ==============================
```

---

## 5. Starting the Workbench Service

Start the FastAPI application via Uvicorn:

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Open your browser to:
- **Interactive UI:** `http://127.0.0.1:8000`
- **Swagger / OpenAPI Documentation:** `http://127.0.0.1:8000/docs`
- **Alternative ReDoc UI:** `http://127.0.0.1:8000/redoc`
