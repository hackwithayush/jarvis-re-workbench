"""
Jarvis RE — angr Symbolic Execution Adapter
Provides automated control-flow graph (CFG) recovery, path exploration,
and constraint solving for compiled binaries.
"""

import logging
import os
from typing import Any, Dict, List, Optional

from .base_adapter import BaseAdapter

logger = logging.getLogger("jarvis.re.adapters.angr")


class AngrAdapter(BaseAdapter):
    """Adapter for symbolic execution and binary analysis with angr."""

    TOOL_NAME: str = "angr"

    def is_available(self) -> bool:
        try:
            import angr
            return True
        except ImportError:
            return False

    def get_version(self) -> Optional[str]:
        if not self.is_available():
            return None
        try:
            import angr
            return getattr(angr, "__version__", "unknown")
        except Exception:
            return None

    def get_supported_types(self) -> List[str]:
        return ["PE", "ELF", "Mach-O", "raw"]

    def analyze(
        self,
        sample_path: str,
        workspace_path: str,
        options: Optional[dict] = None,
    ) -> List[Dict[str, Any]]:
        if not self.is_available():
            raise RuntimeError("angr is not installed. Install with `pip install angr`.")

        import angr

        findings: List[Dict[str, Any]] = []
        options = options or {}
        max_funcs = options.get("max_functions", 50)

        try:
            proj = angr.Project(sample_path, auto_load_libs=False)
            findings.append(
                self._make_finding(
                    finding_type="metadata",
                    name="angr_project_info",
                    description=f"Loaded in angr. Arch: {proj.arch.name}, Entry: 0x{proj.entry:x}",
                    confidence=0.95,
                    raw_data={"arch": proj.arch.name, "entry": proj.entry, "bits": proj.arch.bits},
                )
            )

            # Fast CFG recovery
            try:
                cfg = proj.analyses.CFGFast()
                func_count = 0
                for addr, func in cfg.kb.functions.items():
                    if func_count >= max_funcs:
                        break
                    block_count = len(list(func.blocks)) if hasattr(func, "blocks") else 0
                    findings.append(
                        self._make_finding(
                            finding_type="function",
                            address=f"0x{addr:08X}",
                            name=func.name,
                            description=f"Recovered function {func.name} (blocks: {block_count})",
                            confidence=0.85,
                            raw_data={"address": addr, "name": func.name, "block_count": block_count},
                        )
                    )
                    func_count += 1
            except Exception as cfg_err:
                logger.warning(f"angr CFGFast was unable to recover control-flow graph: {cfg_err}")
                findings.append(
                    self._make_finding(
                        finding_type="anomaly",
                        name="angr_cfg_notice",
                        description=f"CFG recovery skipped or incomplete: {cfg_err}",
                        confidence=0.70,
                    )
                )
        except Exception as err:
            logger.error(f"angr analysis failed: {err}")
            raise

        return findings
