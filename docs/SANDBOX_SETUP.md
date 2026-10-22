# Sandbox Configuration & Deployment Guide

This document describes how to configure, operate, and enhance dynamic sandbox isolation for the JARVIS Reverse Engineering Workbench on Windows.

---

## 1. Built-in Controlled Sandbox (Default)

The workbench includes a built-in process sandbox implemented in [`app/core/sandbox.py`](file:///c:/AI/jarvis-re-workbench/app/core/sandbox.py).

### How It Works:
- **Zero Configuration Required:** Works out-of-the-box on standard Windows installations.
- **Null Proxy Injection:** Overrides `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` with an invalid loopback address (`http://127.0.0.1:0`) to intercept socket connections.
- **Process Isolation:** Runs samples in a dedicated ephemeral folder under `workspace/sandbox/{execution_id}/`.
- **Termination Guarantee:** Uses Windows process handles to enforce execution timeout limits (typically 5 to 30 seconds), automatically terminating both the primary process and any spawned child processes.

### Running a Controlled Dynamic Session:

Using `curl` or PowerShell:
```powershell
$headers = @{
    "Content-Type" = "application/json"
    "X-Analyst-Consent" = "True"
}
$body = @{
    "report_id" = "e84f2c99-a1d2-4309-8b01-57d42cf3b08e"
    "consent_token" = "CONFIRMED_ANALYST_EXECUTION"
    "timeout_sec" = 10
    "allow_network" = $false
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/dynamic/execute" -Method Post -Headers $headers -Body $body
```

---

## 2. Advanced Sandbox Options: Windows Sandbox (WSB)

For untrusted binaries or suspected live malware, operating within the built-in process sandbox is insufficient against zero-day kernel exploits or user-level file tampering. We strongly recommend configuring **Windows Sandbox**.

### Enabling Windows Sandbox:
Run in an elevated PowerShell:
```powershell
Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -All
Restart-Computer
```

### Automated WSB Configuration File (`jarvis_sandbox.wsb`):
Create a disposable `.wsb` profile mapping the sample quarantine folder as read-only:

```xml
<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Disable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>C:\AI\jarvis-re-workbench\workspace\samples</HostFolder>
      <SandboxFolder>C:\AnalysisSamples</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -NoExit -Command "Write-Host 'JARVIS Sandbox Ready. Samples located in C:\AnalysisSamples' -ForegroundColor Cyan"</Command>
  </LogonCommand>
</Configuration>
```

Launching the sandbox:
```powershell
Start-Process "jarvis_sandbox.wsb"
```

---

## 3. Dynamic Instrumentation with Frida

For API tracing without executing full payloads to completion:

1. Ensure `frida` and `frida-tools` are installed in your Python environment:
   ```powershell
   pip install frida frida-tools
   ```
2. Spawn the target binary suspended:
   ```powershell
   frida -f sample.exe --no-pause
   ```
3. Use JARVIS runtime hooks to log API calls (`CreateFileW`, `RegOpenKeyExW`, `VirtualAlloc`, `WriteProcessMemory`, `InternetOpenA`).

---

## 4. Safety Checklist Prior to Execution

- [ ] Verify sample SHA-256 matches the reported static triage hash.
- [ ] Ensure host system network connection is disabled OR host is behind an isolated analysis VLAN if testing network malware.
- [ ] Ensure all file shares / mapped network drives are disconnected.
- [ ] For high-risk samples, always use a dedicated hypervisor VM with clean baseline snapshots rather than running directly on the host OS.
