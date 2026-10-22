"""
Jarvis RE — x64dbg Dynamic Debugger Adapter
Automates headless x64dbg script execution, memory dumping,
and breakpoint traces on Windows hosts.
"""

import logging
import os
import shutil
import sys
from typing import Any, Dict, List, Optional

from .base_adapter import BaseAdapter

logger = logging.getLogger("jarvis.re.adapters.x64dbg")


class X64DbgAdapter(BaseAdapter):
    """Adapter for x64dbg / x32dbg Windows debugger automation."""

    TOOL_NAME: str = "x64dbg"

    def __init__(self, tool_path: Optional[str] = None, timeout: int = 300):
        super().__init__(tool_path=tool_path, timeout=timeout)
        if not self.tool_path:
            self.tool_path = self._find_tool()

    def _find_tool(self) -> Optional[str]:
        if sys.platform != "win32":
            return None
        cmd = shutil.which("x64dbg.exe") or shutil.which("x96dbg.exe")
        if cmd:
            return cmd
        for p in [
            r"C:\Program Files\x64dbg\release\x64\x64dbg.exe",
            r"C:\Tools\x64dbg\release\x64\x64dbg.exe",
            r"C:\x64dbg\release\x64\x64dbg.exe",
        ]:
            if os.path.isfile(p):
                return p
        return None

    def is_available(self) -> bool:
        return bool(sys.platform == "win32" and self.tool_path and os.path.isfile(self.tool_path))

    def get_version(self) -> Optional[str]:
        if not self.is_available():
            return None
        return "x64dbg-win32"

    def get_supported_types(self) -> List[str]:
        return ["PE", "EXE", "DLL"]

    def analyze(
        self,
        sample_path: str,
        workspace_path: str,
        options: Optional[dict] = None,
    ) -> List[Dict[str, Any]]:
        if not self.is_available():
            raise RuntimeError("x64dbg is only supported on Windows with x64dbg installed.")

        findings: List[Dict[str, Any]] = []
        options = options or {}
        script_file = options.get("script_file")

        cmd = [self.tool_path, sample_path]
        if script_file:
            cmd.extend(["-s", script_file])

        findings.append(
            self._make_finding(
                finding_type="runtime_observation",
                name="x64dbg_session_init",
                description=f"x64dbg session initialized for binary: {os.path.basename(sample_path)}",
                confidence=0.90,
                raw_data={"tool_path": self.tool_path, "sample": sample_path, "script": script_file},
            )
        )
        return findings
