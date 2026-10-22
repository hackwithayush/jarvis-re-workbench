"""
JARVIS RE — YARA Signature & Malware Rule Evaluation Adapter v1.0
Applies rule signatures, packer detectors, and indicator matching
against binary targets using yara-python.
"""

import logging
import os
from typing import Any, Dict, List, Optional

from .base_adapter import BaseAdapter

logger = logging.getLogger("jarvis.re.adapters.yara")

DEFAULT_YARA_RULES = """
rule Suspicious_Process_Injection {
    strings:
        $s1 = "VirtualAllocEx" ascii wide
        $s2 = "WriteProcessMemory" ascii wide
        $s3 = "CreateRemoteThread" ascii wide
    condition:
        2 of them
}

rule Suspicious_Crypto_Ransom {
    strings:
        $c1 = "CryptEncrypt" ascii wide
        $c2 = "CryptAcquireContext" ascii wide
        $c3 = "CryptGenKey" ascii wide
    condition:
        all of them
}

rule Anti_Debug_PE {
    strings:
        $ad1 = "IsDebuggerPresent" ascii wide
        $ad2 = "CheckRemoteDebuggerPresent" ascii wide
    condition:
        any of them
}
"""


class YaraAdapter(BaseAdapter):
    """Adapter for YARA signature matching."""

    TOOL_NAME: str = "yara"

    def is_available(self) -> bool:
        try:
            import yara
            return True
        except ImportError:
            return False

    def get_version(self) -> Optional[str]:
        if not self.is_available():
            return None
        try:
            import yara
            return getattr(yara, "__version__", "4.5.0")
        except Exception:
            return "yara"

    def get_supported_types(self) -> List[str]:
        return ["PE", "ELF", "Mach-O", "raw", "DEX", "all"]

    def analyze(
        self,
        sample_path: str,
        workspace_path: str,
        options: Optional[dict] = None,
    ) -> List[Dict[str, Any]]:
        if not self.is_available():
            raise RuntimeError("yara is not installed.")

        import yara

        findings: List[Dict[str, Any]] = []
        rules_source = options.get("yara_rules") if options else None
        rules_source = rules_source or DEFAULT_YARA_RULES

        try:
            compiled = yara.compile(source=rules_source)
            matches = compiled.match(sample_path)

            for m in matches:
                matched_strings = [s.identifier for s in getattr(m, "strings", [])[:5]]
                findings.append(
                    self._make_finding(
                        finding_type="signature",
                        name=f"yara_{m.rule}",
                        description=f"YARA rule matched: {m.rule} (Matched tags: {', '.join(m.tags) if m.tags else 'None'})",
                        confidence=0.92,
                        raw_data={"rule": m.rule, "tags": m.tags, "matched_strings": matched_strings},
                    )
                )
        except Exception as e:
            logger.warning("YARA matching error: %s", e)

        return findings
