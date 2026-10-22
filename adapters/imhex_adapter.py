"""
Jarvis RE — ImHex Adapter
Integrates ImHex CLI (`imhex-cli`) for custom pattern language parsing,
format decoding, and data inspection.
"""

import logging
import os
import shutil
from typing import Any, Dict, List, Optional

from .base_adapter import BaseAdapter

logger = logging.getLogger("jarvis.re.adapters.imhex")


class ImHexAdapter(BaseAdapter):
    """Adapter for ImHex hex editor and CLI pattern engine."""

    TOOL_NAME: str = "imhex"

    def __init__(self, tool_path: Optional[str] = None, timeout: int = 180):
        super().__init__(tool_path=tool_path, timeout=timeout)
        if not self.tool_path:
            self.tool_path = self._find_imhex()

    def _find_imhex(self) -> Optional[str]:
        cmd = shutil.which("imhex-cli") or shutil.which("imhex")
        if cmd:
            return cmd
        for p in [
            r"C:\Tools\imhex\imhex.exe",
            r"C:\Tools\ImHex\imhex.exe",
            r"C:\Program Files\ImHex\imhex-cli.exe",
            r"C:\Program Files\ImHex\imhex.exe",
            r"C:\Tools\ImHex\imhex-cli.exe",
        ]:
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
        return ["raw", "binary", "ROM", "PE", "ELF"]

    def analyze(
        self,
        sample_path: str,
        workspace_path: str,
        options: Optional[dict] = None,
    ) -> List[Dict[str, Any]]:
        if not self.is_available():
            raise RuntimeError("ImHex CLI is not installed.")

        findings: List[Dict[str, Any]] = []
        options = options or {}
        pattern_file = options.get("pattern")

        cmd = [self.tool_path]
        if pattern_file:
            cmd.extend(["--pattern", pattern_file])
        cmd.append(sample_path)

        res = self._run_process(cmd, timeout=self.timeout)
        findings.append(
            self._make_finding(
                finding_type="metadata",
                name="imhex_pattern_evaluation",
                description=f"ImHex inspection completed. Pattern: {pattern_file or 'None'}",
                confidence=0.85,
                raw_data={"output": res.stdout[:2000]},
            )
        )
        return findings
