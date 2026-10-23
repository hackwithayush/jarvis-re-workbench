"""
Jarvis RE — Radare2 Adapter
Wraps radare2 / r2pipe / rabin2 for fast command-line static analysis,
function listing, cross-references, and symbols extraction.
"""

import json
import logging
import os
import shutil
import time
from typing import Any, Dict, List, Optional

from .base_adapter import BaseAdapter

logger = logging.getLogger("jarvis.re.adapters.radare2")


class Radare2Adapter(BaseAdapter):
    """Adapter for radare2 reverse-engineering framework."""

    TOOL_NAME: str = "radare2"

    def __init__(self, tool_path: Optional[str] = None, timeout: int = 45):
        super().__init__(tool_path=tool_path, timeout=timeout)
        if not self.tool_path:
            self.tool_path = self._find_radare2()
        self.last_execution: Optional[Dict[str, Any]] = None

    def _find_radare2(self) -> Optional[str]:
        cmd = shutil.which("radare2") or shutil.which("r2")
        if cmd:
            return cmd
        # Common locations on Windows
        for p in [r"C:\radare2\bin\radare2.exe", r"C:\Tools\radare2\bin\radare2.exe"]:
            if os.path.isfile(p):
                return p
        return None

    def is_available(self) -> bool:
        return bool(self.tool_path and os.path.isfile(self.tool_path))

    def get_version(self) -> Optional[str]:
        if not self.is_available():
            return None
        try:
            res = self._run_process([self.tool_path, "-v"], timeout=10)
            for line in res.stdout.splitlines():
                if "radare2" in line.lower():
                    return line.strip()
            return res.stdout.strip()[:60]
        except Exception as e:
            logger.debug(f"Failed to get r2 version: {e}")
            return None

    def get_supported_types(self) -> List[str]:
        return ["PE", "ELF", "Mach-O", "raw", "binary", "DEX"]

    def analyze(
        self,
        sample_path: str,
        workspace_path: str,
        options: Optional[dict] = None,
    ) -> List[Dict[str, Any]]:
        if not self.is_available():
            raise RuntimeError("radare2 is not installed or not in PATH.")

        findings: List[Dict[str, Any]] = []

        # 1. Run rabin2 -I (binary info JSON)
        rabin2_path = shutil.which("rabin2") or os.path.join(os.path.dirname(self.tool_path or ""), "rabin2.exe")
        if os.path.isfile(rabin2_path):
            try:
                res = self._run_process([rabin2_path, "-j", "-I", sample_path], timeout=self.timeout)
                data = json.loads(res.stdout)
                core_info = data.get("info") or data.get("core", {})
                bintype = core_info.get("bintype") or core_info.get("format")
                arch = core_info.get("arch")
                bits = core_info.get("bits")
                subsys = core_info.get("subsys", "")
                canary = core_info.get("canary", False)
                nx = core_info.get("nx", False)
                pic = core_info.get("pic", False)

                desc = f"Format: {bintype} ({core_info.get('class', '')}), Arch: {arch} ({bits}-bit), Subsystem: {subsys}. Mitigations: NX={'Enabled' if nx else 'Disabled'}, Canary={'Enabled' if canary else 'None'}, ASLR={'Enabled' if pic else 'None'}"
                findings.append(
                    self._make_finding(
                        finding_type="metadata",
                        name="rabin2_security_info",
                        description=desc,
                        confidence=0.95,
                        raw_data=core_info,
                    )
                )
            except Exception as err:
                logger.warning(f"rabin2 info extraction failed: {err}")

        # 2. Extract functions: fast rabin2 symbols/exports first (<0.3s), fallback to r2 batch analysis
        r2_cmd = [self.tool_path, "-qc", "aa; aflj", sample_path]
        t0 = time.time()
        funcs_recovered = 0
        zero_reason = None
        exit_code = 0
        stdout_snip = ""
        stderr_snip = ""
        parsing_status = "unparsed"

        # Fast path: Extract functions via rabin2 symbols/exports if binary contains symbols
        if os.path.isfile(rabin2_path):
            try:
                res_sym = self._run_process([rabin2_path, "-j", "-s", sample_path], timeout=min(self.timeout, 5))
                if res_sym.returncode == 0 and res_sym.stdout.strip():
                    sym_data = json.loads(res_sym.stdout)
                    symbols = sym_data.get("symbols", [])
                    func_syms = [
                        s for s in symbols
                        if s.get("type") in ("FUNC", "METH") or (s.get("name", "").startswith("sym.") and not s.get("is_imported", False))
                    ]
                    if func_syms:
                        funcs_recovered = len(func_syms)
                        parsing_status = "success"
                        exit_code = 0
                        stdout_snip = f"rabin2 fast symbols recovered {funcs_recovered} functions"
                        for s in func_syms[:100]:
                            vaddr = s.get("vaddr") or s.get("paddr", 0)
                            name = s.get("name") or s.get("realname", f"fcn_{vaddr:x}")
                            size = s.get("size", 0)
                            findings.append(
                                self._make_finding(
                                    finding_type="function",
                                    address=f"0x{vaddr:08X}",
                                    name=name,
                                    description=f"Function {name} (size: {size} bytes)",
                                    confidence=0.92,
                                    raw_data=s,
                                )
                            )
            except Exception as e:
                logger.debug(f"Fast symbol extraction skipped: {e}")

        # Targeted entrypoint recovery (<0.8s) if symbols weren't available
        if funcs_recovered == 0:
            fast_entry_cmd = [self.tool_path, "-qc", "af @ entry0; aflj", sample_path]
            try:
                res = self._run_process(fast_entry_cmd, timeout=min(self.timeout, 6))
                raw_out = res.stdout.strip()
                s_idx = raw_out.find("[")
                e_idx = raw_out.rfind("]")
                if s_idx != -1 and e_idx != -1 and e_idx > s_idx:
                    funcs = json.loads(raw_out[s_idx : e_idx + 1])
                    if funcs:
                        funcs_recovered = len(funcs)
                        parsing_status = "success"
                        exit_code = 0
                        stdout_snip = f"radare2 entrypoint analysis recovered {funcs_recovered} function(s)"
                        r2_cmd = fast_entry_cmd
                        for f in funcs:
                            addr = f.get("addr") if f.get("addr") is not None else f.get("offset", 0)
                            name = f.get("name", f"fcn_{addr:x}")
                            size = f.get("size", 0)
                            ninstrs = f.get("ninstrs", 0)
                            nbbs = f.get("nbbs", 0)
                            cc = f.get("cc", 0)
                            findings.append(
                                self._make_finding(
                                    finding_type="function",
                                    address=f"0x{addr:08X}",
                                    name=name,
                                    description=f"Function {name} (size: {size} bytes, instructions: {ninstrs}, basic blocks: {nbbs}, cyclomatic complexity: {cc})",
                                    confidence=0.90,
                                    raw_data=f,
                                )
                            )
            except Exception as err:
                logger.debug(f"Targeted entrypoint analysis skipped: {err}")

        # Fallback to r2 batch auto-analysis if fast paths did not recover any functions
        if funcs_recovered == 0:
            try:
                res = self._run_process(r2_cmd, timeout=min(self.timeout, 10))
                exit_code = res.returncode
                stdout_snip = (res.stdout or "")[:500]
                stderr_snip = (res.stderr or "")[:500]
                raw_out = res.stdout.strip()
                s_idx = raw_out.find("[")
                e_idx = raw_out.rfind("]")

                if s_idx != -1 and e_idx != -1 and e_idx > s_idx:
                    funcs = json.loads(raw_out[s_idx : e_idx + 1])
                    parsing_status = "success"
                    funcs_recovered = len(funcs)
                    for f in funcs[:100]:  # Cap at 100 for summary
                        addr = f.get("addr") if f.get("addr") is not None else f.get("offset", 0)
                        name = f.get("name", f"fcn_{addr:x}")
                        size = f.get("size", 0)
                        ninstrs = f.get("ninstrs", 0)
                        nbbs = f.get("nbbs", 0)
                        cc = f.get("cc", 0)
                        findings.append(
                            self._make_finding(
                                finding_type="function",
                                address=f"0x{addr:08X}",
                                name=name,
                                description=f"Function {name} (size: {size} bytes, instructions: {ninstrs}, basic blocks: {nbbs}, cyclomatic complexity: {cc})",
                                confidence=0.90,
                                raw_data=f,
                            )
                        )
                else:
                    parsing_status = "unexpected_format"
                    zero_reason = f"Output did not match expected JSON array: '{raw_out[:120]}'"

                if funcs_recovered == 0 and not zero_reason:
                    zero_reason = "Zero functions discovered: binary may be a managed .NET assembly, stripped, packed, or pure data."

            except Exception as err:
                logger.warning(f"radare2 function extraction failed: {err}")
                parsing_status = "error"
                zero_reason = str(err)
                stderr_snip = str(err)

        duration = round(time.time() - t0, 3)

        self.last_execution = {
            "tool_name": "radare2",
            "tool_version": self.get_version() or "radare2",
            "command": " ".join(r2_cmd),
            "exit_code": exit_code,
            "duration_seconds": duration,
            "stdout_snippet": stdout_snip,
            "stderr_snippet": stderr_snip,
            "functions_recovered": funcs_recovered,
            "zero_functions_reason": zero_reason,
            "parsing_status": parsing_status,
            "findings_count": len(findings),
        }

        # If zero functions were recovered, report an explicit, truthful diagnostic finding
        if funcs_recovered == 0:
            findings.append(
                self._make_finding(
                    finding_type="metadata",
                    name="radare2_function_analysis_result",
                    description=(
                        f"radare2 function analysis finished (duration: {duration}s, exit code: {exit_code}): "
                        f"0 functions recovered ({zero_reason})"
                    ),
                    confidence=0.90,
                    raw_data=self.last_execution,
                )
            )

        return findings
