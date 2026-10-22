# JARVIS RE — Tool & Repository Capability Matrix

| Tool | Upstream Repository | Version Detected | Primary Role | Integration Mode | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **JARVIS Native Engine** | Built-in | v1.0.0 | Static Header, Entropy, & String Forensics | In-process Python | **ACTIVE** |
| **Ghidra (NSA SRE)** | [ghidra](https://github.com/NationalSecurityAgency/ghidra) | 12.1.4 | Deep Disassembly, Cross-References, & Decompilation | Headless CLI + Jython | **ACTIVE** |
| **radare2** | [radare2](https://github.com/radareorg/radare2) | 6.2.4 | Disassembly, Functions, Pseudo-C, & CFG | CLI (`r2 -qc`) | **ACTIVE** |
| **Detect It Easy (DIE)** | [DIE-engine](https://github.com/horsicq/Detect-It-Easy) | 3.21 | Compiler, Packer, & Protector Identification | CLI (`diec -j`) | **ACTIVE** |
| **JADX** | [jadx](https://github.com/skylot/jadx) | 1.5.6 | Android APK & DEX Java Decompilation | CLI (`jadx -d`) | **ACTIVE** |
| **ILSpy / dnSpyEx** | [ILSpy](https://github.com/icsharpcode/ILSpy) | 11.1 | Managed .NET C# Source Recovery | CLI (`ilspycmd -p`) | **ACTIVE** |
| **Mandiant capa** | [capa](https://github.com/mandiant/capa) | 10.0.0 | Capability Detection & MITRE ATT&CK Mapping | Python API (`flare-capa`) | **ACTIVE** |
| **YARA** | [yara](https://github.com/VirusTotal/yara) | 4.5.0 | Signature & Pattern Rule Matching | Python API (`yara-python`) | **ACTIVE** |
| **angr** | [angr](https://github.com/angr/angr) | 9.2.213 | Symbolic Execution & Control-Flow Graph (`CFGFast`) | Python API (`angr`) | **ACTIVE** |
| **LIEF** | [lief](https://github.com/lief-project/LIEF) | 1.0.0 | Multi-Format Binary Instrumenter & Parser | Python API (`lief`) | **ACTIVE** |
| **ImHex** | [ImHex](https://github.com/WerWolv/ImHex) | 1.38.1 | Pattern Language & Hex Data Inspection | Standalone / CLI | **ACTIVE** |
| **Cutter / Rizin** | [cutter](https://github.com/rizinorg/cutter) | 2.5.0 | Interactive Visual Reverse Engineering UI | GUI / CLI | **ACTIVE** |
| **x64dbg** | [x64dbg](https://github.com/x64dbg/x64dbg) | Snapshot | Windows x64/x32 Dynamic Debugging | GUI / Scriptable | **ACTIVE** |
| **Frida** | [frida](https://github.com/frida/frida) | 17.24.3 | Dynamic Runtime API Hooking & Instrumentation | Python API (`frida`) | **ACTIVE** |
| **Controlled Sandbox**| Built-in | v1.0.0 | Isolated Disposable Jail Execution with Network Block | Isolated Subprocess | **ACTIVE** |
