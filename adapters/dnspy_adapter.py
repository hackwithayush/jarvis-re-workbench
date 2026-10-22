"""
Jarvis RE — dnSpyEx / ILSpy .NET Decompiler Adapter
Automates headless .NET assembly decompilation and metadata extraction
via ILSpy CLI (`ilspycmd`) or dnSpy CLI.
"""

import json
import logging
import os
import shutil
from typing import Any, Dict, List, Optional

from .base_adapter import BaseAdapter

logger = logging.getLogger("jarvis.re.adapters.dnspy")


class DnSpyAdapter(BaseAdapter):
    """Adapter for .NET decompilation with dnSpyEx / ilspycmd."""

    TOOL_NAME: str = "dnspy"

    def __init__(self, tool_path: Optional[str] = None, timeout: int = 300):
        super().__init__(tool_path=tool_path, timeout=timeout)
        if not self.tool_path:
            self.tool_path = self._find_tool()

    def _find_tool(self) -> Optional[str]:
        cmd = shutil.which("ilspycmd") or shutil.which("dnSpy.Console")
        if cmd:
            return cmd
        dotnet_tool = os.path.expanduser("~/.dotnet/tools/ilspycmd.exe")
        if os.path.isfile(dotnet_tool):
            return dotnet_tool
        for p in [r"C:\Tools\ilspycmd\ilspycmd.exe", r"C:\Tools\dnSpy\dnSpy.Console.exe"]:
            if os.path.isfile(p):
                return p
        return None

    def is_available(self) -> bool:
        return bool(self.tool_path and os.path.isfile(self.tool_path))

    def get_version(self) -> Optional[str]:
        if not self.is_available():
            return None
        try:
            res = self._run_process([self.tool_path, "--version"], timeout=10)
            return res.stdout.strip()[:60]
        except Exception:
            return None

    def get_supported_types(self) -> List[str]:
        return ["PE/.NET", "DLL", "EXE"]

    def analyze(
        self,
        sample_path: str,
        workspace_path: str,
        options: Optional[dict] = None,
    ) -> List[Dict[str, Any]]:
        if not self.is_available():
            raise RuntimeError("dnSpy / ilspycmd CLI is not installed.")

        findings: List[Dict[str, Any]] = []
        out_dir = os.path.join(workspace_path, "decompiled_dotnet")
        os.makedirs(out_dir, exist_ok=True)

        # Run decompilation: ilspycmd -p -o <out_dir> <sample_path>
        cmd = [self.tool_path, "-p", "-o", out_dir, sample_path]
        res = self._run_process(cmd, timeout=self.timeout)

        decompiled_files = []
        for root, _, files in os.walk(out_dir):
            for f in files:
                if f.endswith(".cs"):
                    decompiled_files.append(os.path.relpath(os.path.join(root, f), out_dir))

        findings.append(
            self._make_finding(
                finding_type="compiler_info",
                name="dotnet_decompilation",
                description=f".NET assembly decompiled successfully into {len(decompiled_files)} C# source files.",
                confidence=0.95,
                raw_data={"decompiled_files_count": len(decompiled_files), "sample_files": decompiled_files[:20]},
            )
        )
        return findings
