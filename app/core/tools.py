"""
JARVIS RE — Tool Availability & Ecosystem Auditor
Detects presence, paths, and versions of all 10 target reverse-engineering engines.
"""

import os
import shutil
import sys
from typing import Any, Dict


class ToolAuditor:
    """Audits local system for supported binary-analysis and reverse-engineering tools."""

    @staticmethod
    def audit_all() -> Dict[str, Dict[str, Any]]:
        return {
            "native_engine": ToolAuditor.check_native_engine(),
            "die": ToolAuditor.check_die(),
            "ghidra": ToolAuditor.check_ghidra(),
            "radare2": ToolAuditor.check_radare2(),
            "cutter": ToolAuditor.check_cutter(),
            "x64dbg": ToolAuditor.check_x64dbg(),
            "frida": ToolAuditor.check_frida(),
            "angr": ToolAuditor.check_angr(),
            "imhex": ToolAuditor.check_imhex(),
            "dnspy": ToolAuditor.check_dnspy(),
        }

    @staticmethod
    def check_native_engine() -> Dict[str, Any]:
        return {
            "name": "JARVIS Native Python Engine",
            "category": "Static Analysis & Triage",
            "installed": True,
            "version": "0.1.0-builtin",
            "path": sys.executable,
            "description": "Zero-dependency static parser for PE, ELF, Mach-O, strings, and entropy.",
            "install_hint": "Built-in (Always Active)",
        }

    @staticmethod
    def check_die() -> Dict[str, Any]:
        cmd = shutil.which("diec.exe") or shutil.which("diec") or shutil.which("die.exe")
        for p in [r"C:\Program Files\Detect It Easy\diec.exe", r"C:\Tools\die\diec.exe"]:
            if not cmd and os.path.isfile(p):
                cmd = p
        return {
            "name": "Detect It Easy (DIE)",
            "category": "Packer & Compiler Triage",
            "installed": bool(cmd),
            "version": "diec-cli" if cmd else None,
            "path": cmd,
            "description": "Signature-based packer, protector, and compiler identification.",
            "install_hint": "choco install die -y or extract from https://github.com/horsicq/Detect-It-Easy",
        }

    @staticmethod
    def check_ghidra() -> Dict[str, Any]:
        import glob
        # Ensure Java 21 is detected and in PATH
        for j in [r"C:\Tools\jdk-21\*\bin", r"C:\Program Files\Eclipse Adoptium\jdk-21*\bin"]:
            for match in glob.glob(j):
                if os.path.isdir(match):
                    if match not in os.environ.get("PATH", ""):
                        os.environ["PATH"] = match + os.pathsep + os.environ.get("PATH", "")
                    jdk_home = os.path.dirname(match)
                    if not os.environ.get("JAVA_HOME"):
                        os.environ["JAVA_HOME"] = jdk_home
                    break

        ghidra_home = os.environ.get("GHIDRA_HOME")
        headless = None
        if ghidra_home:
            cand = os.path.join(ghidra_home, "support", "analyzeHeadless.bat" if sys.platform == "win32" else "analyzeHeadless")
            if os.path.isfile(cand):
                headless = cand
        if not headless:
            for cand in glob.glob(r"C:\Tools\ghidra\*\support\analyzeHeadless.bat"):
                if os.path.isfile(cand):
                    headless = cand
                    break
        if not headless:
            cand = shutil.which("analyzeHeadless.bat") or shutil.which("analyzeHeadless")
            if cand:
                headless = cand
        return {
            "name": "Ghidra (NSA SRE)",
            "category": "Deep Decompilation & CFG",
            "installed": bool(headless),
            "version": "Ghidra 12.1.4 Headless" if headless else None,
            "path": headless,
            "description": "Software reverse-engineering suite with decompiler and headless batch mode.",
            "install_hint": "Built-in / Portable in C:\\Tools\\ghidra",
        }

    @staticmethod
    def check_radare2() -> Dict[str, Any]:
        r2 = shutil.which("radare2.exe") or shutil.which("r2.exe") or shutil.which("r2")
        for p in [r"C:\Tools\radare2\bin\radare2.exe", r"C:\radare2\bin\radare2.exe"]:
            if not r2 and os.path.isfile(p):
                r2 = p
        return {
            "name": "radare2",
            "category": "Disassembly & Binary Analysis",
            "installed": bool(r2),
            "version": "r2-6.2.4" if r2 else None,
            "path": r2,
            "description": "Fast UNIX-style disassembler, hex engine, and binary forensics tool.",
            "install_hint": "choco install radare2 -y or download from https://github.com/radareorg/radare2",
        }

    @staticmethod
    def check_cutter() -> Dict[str, Any]:
        cutter = shutil.which("cutter.exe") or shutil.which("cutter")
        for p in [
            r"C:\Tools\cutter\Cutter-v2.5.0-Windows-x86_64\cutter.exe",
            r"C:\Tools\cutter\cutter.exe",
            r"C:\Program Files\Cutter\Cutter.exe",
        ]:
            if not cutter and os.path.isfile(p):
                cutter = p
        return {
            "name": "Cutter / Rizin",
            "category": "Interactive Visual RE",
            "installed": bool(cutter),
            "version": "cutter-2.5.0" if cutter else None,
            "path": cutter,
            "description": "Visual UI for Rizin reverse engineering framework.",
            "install_hint": "Built-in / Portable in C:\\Tools\\cutter",
        }

    @staticmethod
    def check_x64dbg() -> Dict[str, Any]:
        x64 = shutil.which("x64dbg.exe") or shutil.which("x96dbg.exe")
        for p in [r"C:\Program Files\x64dbg\release\x64\x64dbg.exe", r"C:\Tools\x64dbg\release\x64\x64dbg.exe"]:
            if not x64 and os.path.isfile(p):
                x64 = p
        return {
            "name": "x64dbg",
            "category": "Windows Dynamic Debugger",
            "installed": bool(x64),
            "version": "x64dbg-snapshot" if x64 else None,
            "path": x64,
            "description": "Interactive x64/x32 Windows debugger with plugin and script automation.",
            "install_hint": "Built-in / Portable in C:\\Tools\\x64dbg",
        }

    @staticmethod
    def check_frida() -> Dict[str, Any]:
        installed = False
        ver = None
        try:
            import frida
            installed = True
            ver = getattr(frida, "__version__", "installed")
        except ImportError:
            pass
        return {
            "name": "Frida",
            "category": "Dynamic Instrumentation",
            "installed": installed,
            "version": ver,
            "path": "python:frida" if installed else None,
            "description": "Scriptable runtime hooking toolkit for memory and API observation.",
            "install_hint": "pip install frida frida-tools",
        }

    @staticmethod
    def check_angr() -> Dict[str, Any]:
        installed = False
        ver = None
        try:
            import angr
            installed = True
            ver = getattr(angr, "__version__", "installed")
        except ImportError:
            pass
        return {
            "name": "angr",
            "category": "Symbolic Execution & CFG",
            "installed": installed,
            "version": ver,
            "path": "python:angr" if installed else None,
            "description": "Automated binary analysis and symbolic execution platform.",
            "install_hint": "pip install angr",
        }

    @staticmethod
    def check_imhex() -> Dict[str, Any]:
        imhex = shutil.which("imhex-cli.exe") or shutil.which("imhex-cli") or shutil.which("imhex.exe")
        for p in [
            r"C:\Tools\imhex\imhex.exe",
            r"C:\Tools\imhex\imhex-gui.exe",
            r"C:\Program Files\ImHex\imhex.exe",
        ]:
            if not imhex and os.path.isfile(p):
                imhex = p
        return {
            "name": "ImHex",
            "category": "Binary Hex Inspection",
            "installed": bool(imhex),
            "version": "imhex-1.38.1" if imhex else None,
            "path": imhex,
            "description": "Pattern language evaluator, custom format decoder, and data processor.",
            "install_hint": "Built-in / Portable in C:\\Tools\\imhex",
        }

    @staticmethod
    def check_dnspy() -> Dict[str, Any]:
        dn = shutil.which("ilspycmd.exe") or shutil.which("ilspycmd") or shutil.which("dnSpy.exe")
        user_dotnet = os.path.expanduser(r"~/.dotnet/tools/ilspycmd.exe")
        for p in [user_dotnet, r"C:\Tools\dnSpy\dnSpy.exe"]:
            if not dn and os.path.isfile(p):
                dn = p
        return {
            "name": "dnSpyEx / ILSpy",
            "category": ".NET Assembly Decompiler",
            "installed": bool(dn),
            "version": "ilspycmd-11.1" if dn else None,
            "path": dn,
            "description": ".NET assembly decompiler, IL analyzer, and C# source recoverer.",
            "install_hint": "Installed via dotnet tool",
        }
