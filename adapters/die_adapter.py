"""
Jarvis RE — Detect It Easy (DIE) Adapter
Primary Phase 01 adapter for fast static identification of compilers,
packers, protectors, and file-type metadata.
"""

import json
import logging
import os
import shutil
from typing import Any, Dict, List, Optional

from .base_adapter import BaseAdapter

logger = logging.getLogger("jarvis.re.adapters.die")

# Common install locations for Detect It Easy CLI (diec).
_COMMON_PATHS: List[str] = [
    # Windows typical installs
    r"C:\Program Files\Detect It Easy\diec.exe",
    r"C:\Program Files (x86)\Detect It Easy\diec.exe",
    r"C:\Tools\die\diec.exe",
    r"C:\Tools\Detect It Easy\diec.exe",
    # Linux / macOS
    "/usr/local/bin/diec",
    "/usr/bin/diec",
    "/opt/die/diec",
]

# Mapping from DIE detection *type* → normalised finding_type.
_TYPE_MAP: Dict[str, str] = {
    "compiler": "compiler_info",
    "linker": "compiler_info",
    "packer": "packer_info",
    "protector": "packer_info",
    "overlay": "anomaly",
    "installer": "metadata",
    "sfx": "metadata",
    "archive": "metadata",
    "library": "library",
    "tool": "compiler_info",
    "sign": "metadata",
    "format": "metadata",
}

# Confidence modifiers per detection type.
_CONFIDENCE: Dict[str, float] = {
    "compiler": 0.80,
    "linker": 0.75,
    "packer": 0.85,
    "protector": 0.90,
    "overlay": 0.70,
    "installer": 0.80,
    "sfx": 0.75,
    "archive": 0.80,
    "library": 0.70,
    "tool": 0.70,
    "sign": 0.65,
    "format": 0.75,
}


class DIEAdapter(BaseAdapter):
    """Adapter for *Detect It Easy* (``diec`` CLI).

    DIE performs fast static analysis to identify compilers, packers,
    protectors and basic file metadata.  It is the primary triage tool
    used in Phase 01 of Jarvis RE.
    """

    TOOL_NAME: str = "die"

    def __init__(self, tool_path: Optional[str] = None, timeout: int = 120):
        super().__init__(tool_path=tool_path, timeout=timeout)
        # Resolve the actual binary path once at init time.
        if self.tool_path is None:
            self.tool_path = self._find_diec()

    # ------------------------------------------------------------------
    # BaseAdapter interface
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return *True* if ``diec`` can be found and executed."""
        if self.tool_path is None:
            return False
        return os.path.isfile(self.tool_path)

    def get_version(self) -> Optional[str]:
        """Query ``diec --version`` and return the version string."""
        if not self.is_available():
            return None
        try:
            result = self._run_process([self.tool_path, "--version"], timeout=15)
            if result.returncode == 0 and result.stdout:
                return result.stdout.strip().splitlines()[0]
            return None
        except Exception:
            self.logger.debug("Failed to retrieve DIE version", exc_info=True)
            return None

    def get_supported_types(self) -> List[str]:
        """DIE supports most common binary formats."""
        return ["PE", "PE+", "ELF", "Mach-O", "DEX", "APK", "MSI", "ZIP", "RAR", "JAR"]

    def analyze(
        self,
        sample_path: str,
        workspace_path: str,
        options: Optional[dict] = None,
    ) -> List[Dict[str, Any]]:
        """Run DIE against *sample_path* and return normalised findings.

        Args:
            sample_path:    Path to the binary to scan.
            workspace_path: Working directory (unused by DIE but kept for
                            interface consistency).
            options:        Optional dict.  Recognised keys:
                            - ``deep_scan`` (bool): pass ``-d`` for deep scan.

        Returns:
            List of normalised finding dicts.
        """
        if not self.is_available():
            raise RuntimeError("diec is not available — cannot run DIE analysis")

        if not os.path.isfile(sample_path):
            raise FileNotFoundError(f"Sample not found: {sample_path}")

        options = options or {}
        findings: List[Dict[str, Any]] = []

        # ----- build command -----
        cmd = [self.tool_path, "-j"]  # JSON output
        if options.get("deep_scan", False):
            cmd.append("-d")
        cmd.append(sample_path)

        # ----- execute -----
        self.logger.info("Running DIE on %s", sample_path)
        tool_dir = os.path.dirname(self.tool_path) if self.tool_path else workspace_path
        result = self._run_process(cmd, cwd=tool_dir)

        if result.returncode != 0:
            self.logger.warning(
                "diec exited with code %d: %s",
                result.returncode,
                (result.stderr or "").strip()[:500],
            )
            # Still try to parse — DIE sometimes returns non-zero but valid JSON.

        # ----- parse JSON output -----
        raw_output = result.stdout or ""
        die_data = self._parse_die_output(raw_output)
        if die_data is None:
            self.logger.error("Failed to parse DIE JSON output")
            return findings

        # ----- file-type / metadata finding -----
        findings.extend(self._extract_metadata(die_data, sample_path))

        # ----- per-detection findings -----
        detects = die_data.get("detects", [])
        for det in detects:
            if isinstance(det, dict) and "values" in det and isinstance(det["values"], list):
                for val in det["values"]:
                    finding = self._detection_to_finding(val)
                    if finding is not None:
                        findings.append(finding)
            else:
                finding = self._detection_to_finding(det)
                if finding is not None:
                    findings.append(finding)

        self.logger.info(
            "DIE produced %d finding(s) for %s", len(findings), sample_path
        )
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_diec() -> Optional[str]:
        """Attempt to locate ``diec`` on the current system."""
        # 1. Check PATH via shutil.which
        which = shutil.which("diec")
        if which is not None:
            return which

        # 2. Check common install directories
        for path in _COMMON_PATHS:
            if os.path.isfile(path):
                return path

        # 3. Check DIE_HOME environment variable
        die_home = os.environ.get("DIE_HOME")
        if die_home:
            candidate = os.path.join(die_home, "diec.exe" if os.name == "nt" else "diec")
            if os.path.isfile(candidate):
                return candidate

        return None

    def _parse_die_output(self, raw: str) -> Optional[Dict[str, Any]]:
        """Parse the raw JSON string emitted by ``diec -j``.

        DIE sometimes wraps the output in an array or prepends non-JSON
        preamble, so we attempt a few strategies.
        """
        raw = raw.strip()
        if not raw:
            return None

        # Strategy 1: direct parse
        try:
            data = json.loads(raw)
            if isinstance(data, list) and len(data) > 0:
                # diec sometimes returns a JSON array with a single element
                return data[0] if isinstance(data[0], dict) else None
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass

        # Strategy 2: find the first '{' and try from there (skip preamble)
        brace = raw.find("{")
        if brace != -1:
            try:
                data = json.loads(raw[brace:])
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                pass

        # Strategy 3: find array start
        bracket = raw.find("[")
        if bracket != -1:
            try:
                data = json.loads(raw[bracket:])
                if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                    return data[0]
            except json.JSONDecodeError:
                pass

        self.logger.debug("Unparseable DIE output (first 300 chars): %s", raw[:300])
        return None

    def _extract_metadata(
        self, die_data: Dict[str, Any], sample_path: str
    ) -> List[Dict[str, Any]]:
        """Create metadata findings from the top-level DIE fields."""
        findings: List[Dict[str, Any]] = []

        filetype = die_data.get("filetype", "unknown")
        mode = die_data.get("mode", "")

        description_parts = [f"File type: {filetype}"]
        if mode:
            description_parts.append(f"Mode: {mode}-bit")

        findings.append(
            self._make_finding(
                finding_type="metadata",
                name=f"File identification: {filetype}",
                description="; ".join(description_parts),
                confidence=0.90,
                raw_data={
                    "filetype": filetype,
                    "mode": mode,
                    "sample_path": sample_path,
                },
            )
        )

        return findings

    def _detection_to_finding(self, det: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Convert a single DIE detection entry to a normalised finding."""
        det_type = det.get("type", "").lower().strip()
        det_name = det.get("name", "unknown")
        det_version = det.get("version", "")
        det_info = det.get("info", "")
        det_string = det.get("string", "")
        det_filetype = det.get("filetype", "")

        finding_type = _TYPE_MAP.get(det_type, "metadata")
        confidence = _CONFIDENCE.get(det_type, 0.50)

        # Build human-readable description
        desc = det_string if det_string else f"{det_type}: {det_name}"
        if det_version:
            desc = f"{det_name} v{det_version}"
        if det_info:
            desc += f" ({det_info})"

        evidence = [det_string] if det_string else []

        return self._make_finding(
            finding_type=finding_type,
            name=f"{det_type.title()}: {det_name}",
            description=desc,
            confidence=confidence,
            evidence=evidence,
            raw_data={
                "die_type": det_type,
                "die_name": det_name,
                "die_version": det_version,
                "die_info": det_info,
                "die_string": det_string,
                "die_filetype": det_filetype,
            },
        )
