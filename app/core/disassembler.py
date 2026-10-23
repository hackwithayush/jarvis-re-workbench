"""
JARVIS RE — Disassembly & Decompilation Engine v1.0
Orchestrates deep binary reverse-engineering:
- Function discovery and assembly listings with addresses and cross-references (radare2 / Ghidra)
- Control-Flow Graph (CFG) basic block recovery (radare2 `agj` / angr)
- Native C decompiler output (radare2 `pdc` / Ghidra)
- Managed .NET C# source code decompilation (ILSpy `ilspycmd`)
- String cross-references and API call association
"""

import json
import logging
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from app.core.schema import CFGBlock, FunctionDetails
from app.core.utils import format_address

logger = logging.getLogger("jarvis.re.disassembler")


class DisassemblyEngine:
    """Recovers assembly listings, CFG structures, and decompiled source code."""

    def __init__(self, r2_path: Optional[str] = None, ilspy_path: Optional[str] = None):
        self.r2_path = r2_path or shutil.which("radare2") or self._find_radare2()
        self.ilspy_path = ilspy_path or shutil.which("ilspycmd") or self._find_ilspy()

    def _find_radare2(self) -> Optional[str]:
        for p in [r"C:\Tools\radare2\bin\radare2.exe", r"C:\radare2\bin\radare2.exe"]:
            if os.path.isfile(p):
                return p
        return None

    def _find_ilspy(self) -> Optional[str]:
        candidate = os.path.expanduser("~/.dotnet/tools/ilspycmd.exe")
        if os.path.isfile(candidate):
            return candidate
        for p in [r"C:\Tools\ilspycmd\ilspycmd.exe"]:
            if os.path.isfile(p):
                return p
        return None

    def disassemble_function(
        self,
        sample_path: str,
        function_target: str,
        timeout: int = 30,
    ) -> Optional[Dict[str, Any]]:
        """Extract disassembly listing and metadata for a specific function."""
        if not self.r2_path or not os.path.isfile(sample_path):
            return None

        cmd = [self.r2_path, "-qc", f"s {function_target}; af; pdfj", sample_path]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if res.stdout.strip().startswith("{") and res.stdout.strip().endswith("}"):
                return json.loads(res.stdout)
        except Exception as e:
            logger.warning("Disassembly failed for %s: %s", function_target, e)
        return None

    def extract_cfg(
        self,
        sample_path: str,
        function_target: str,
        timeout: int = 30,
    ) -> List[CFGBlock]:
        """Extract Control-Flow Graph (CFG) basic blocks and jump edges."""
        if not self.r2_path or not os.path.isfile(sample_path):
            return []

        cmd = [self.r2_path, "-qc", f"s {function_target}; af; agj", sample_path]
        cfg_blocks: List[CFGBlock] = []

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            out = res.stdout.strip()
            if out.startswith("[") and out.endswith("]"):
                data = json.loads(out)
                if data and isinstance(data, list) and "blocks" in data[0]:
                    raw_blocks = data[0]["blocks"]
                    for idx, b in enumerate(raw_blocks):
                        addr = b.get("addr", 0)
                        size = b.get("size", 0)
                        jump = b.get("jump")
                        fail = b.get("fail")
                        instrs = [op.get("disasm", "") for op in b.get("ops", [])]

                        cfg_blocks.append(
                            CFGBlock(
                                id=f"block_{idx}",
                                address=format_address(addr),
                                size=size,
                                instructions=instrs,
                                jump_target=format_address(jump) if jump else None,
                                fail_target=format_address(fail) if fail else None,
                            )
                        )
        except Exception as e:
            logger.warning("CFG extraction failed for %s: %s", function_target, e)

        return cfg_blocks

    def decompile_native_c(
        self,
        sample_path: str,
        function_target: str,
        timeout: int = 30,
    ) -> Optional[str]:
        """Generate high-level C-like pseudocode representation for a function."""
        if not self.r2_path or not os.path.isfile(sample_path):
            return None

        cmd = [self.r2_path, "-qc", f"s {function_target}; af; pdc", sample_path]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except Exception as e:
            logger.warning("Pseudo-C decompilation failed for %s: %s", function_target, e)
        return None

    def decompile_dotnet(
        self,
        sample_path: str,
        output_dir: str,
        timeout: int = 60,
    ) -> Dict[str, str]:
        """Decompile .NET assembly into C# source files using ilspycmd."""
        if not self.ilspy_path or not os.path.isfile(sample_path):
            return {}

        os.makedirs(output_dir, exist_ok=True)
        cmd = [self.ilspy_path, "-p", "-o", output_dir, sample_path]
        recovered_sources: Dict[str, str] = {}

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if res.returncode == 0:
                for root, _, files in os.walk(output_dir):
                    for f in files:
                        if f.endswith(".cs"):
                            rel_path = os.path.relpath(os.path.join(root, f), output_dir)
                            full_path = os.path.join(root, f)
                            try:
                                with open(full_path, "r", encoding="utf-8", errors="replace") as cs_f:
                                    recovered_sources[rel_path] = cs_f.read()
                            except Exception:
                                pass
        except Exception as e:
            logger.warning(".NET decompilation error: %s", e)

        return recovered_sources

    def enrich_functions(
        self,
        sample_path: str,
        functions: List[FunctionDetails],
        limit: int = 10,
    ) -> List[FunctionDetails]:
        """Enrich top recovered functions with disassembly, CFG, and decompiler output."""
        if not self.r2_path or not os.path.isfile(sample_path):
            return functions

        enriched: List[FunctionDetails] = []
        for idx, func in enumerate(functions[:limit]):
            target = func.name or func.address
            # 1. Disassembly listing
            disasm_data = self.disassemble_function(sample_path, target)
            instructions = []
            xrefs = []
            api_calls = []

            if disasm_data and "ops" in disasm_data:
                for op in disasm_data["ops"]:
                    op_str = f"{format_address(op.get('addr', 0))}:  {op.get('bytes', '').ljust(12)}  {op.get('opcode', '')}"
                    instructions.append(op_str)
                    if op.get("type") == "call":
                        api_calls.append(op.get("disasm", "").replace("call ", ""))
                    for xr in op.get("xrefs", []):
                        xrefs.append(f"{xr.get('type')} from {format_address(xr.get('addr', 0))}")

            # 2. CFG Blocks
            cfg_blocks = self.extract_cfg(sample_path, target)

            # 3. Decompiled C code
            c_code = self.decompile_native_c(sample_path, target)

            enriched_func = FunctionDetails(
                name=func.name,
                address=func.address,
                size=func.size,
                source_tool="radare2_enhanced",
                calling_convention=func.calling_convention,
                parameter_count=func.parameter_count,
                instructions=instructions,
                decompiled_c=c_code,
                cfg_blocks=cfg_blocks,
                cross_references=list(set(xrefs)),
                api_calls=list(set(api_calls)),
            )
            enriched.append(enriched_func)

        # Append remaining functions without deep enrichment
        enriched.extend(functions[limit:])
        return enriched
