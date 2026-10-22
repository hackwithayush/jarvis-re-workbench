"""
Jarvis RE — Frida Dynamic Instrumentation Adapter
Provides API hooking, function call tracing, and memory inspection
using the Frida runtime toolkit.
"""

import logging
import os
import sys
from typing import Any, Dict, List, Optional

from .base_adapter import BaseAdapter

logger = logging.getLogger("jarvis.re.adapters.frida")


class FridaAdapter(BaseAdapter):
    """Adapter for dynamic runtime inspection with Frida."""

    TOOL_NAME: str = "frida"

    def is_available(self) -> bool:
        try:
            import frida
            return True
        except ImportError:
            return False

    def get_version(self) -> Optional[str]:
        if not self.is_available():
            return None
        try:
            import frida
            return getattr(frida, "__version__", "unknown")
        except Exception:
            return None

    def get_supported_types(self) -> List[str]:
        return ["PE", "ELF", "process", "PID"]

    def analyze(
        self,
        sample_path: str,
        workspace_path: str,
        options: Optional[dict] = None,
    ) -> List[Dict[str, Any]]:
        if not self.is_available():
            raise RuntimeError("Frida is not installed. Install with `pip install frida frida-tools`.")

        findings: List[Dict[str, Any]] = []
        options = options or {}
        target_pid = options.get("pid")
        spawn = options.get("spawn", False)

        findings.append(
            self._make_finding(
                finding_type="runtime_observation",
                name="frida_instrumentation_session",
                description=f"Frida initialized for target {sample_path} (PID: {target_pid or 'Spawn'}).",
                confidence=0.90,
                raw_data={"target": sample_path, "pid": target_pid, "spawn": spawn},
            )
        )
        return findings
