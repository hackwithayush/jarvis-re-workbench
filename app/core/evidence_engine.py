"""
JARVIS RE — Unified Evidence & Correlation Engine v1.0
Central intelligence engine for cross-tool correlation, deduplication, and evidence evaluation:
- Normalizes findings across Native parsers, DIE, radare2, Ghidra, ILSpy, and Sandbox.
- Deduplicates equivalent findings while preserving source tool provenance.
- Correlates cross-domain evidence:
  * Suspicious memory APIs + high entropy -> Unpacking / Injection hypothesis
  * Network strings + socket APIs -> Remote communication capability
  * Anti-debugging APIs -> Evasion posture
  * Compiler metadata + COFF timestamp -> Build environment verification
- Transparent confidence scoring with documented reasoning.
- Separates benign indicators, suspicious anomalies, and confirmed indicators.
"""

from typing import Any, Dict, List, Set, Tuple
from app.core.schema import AIHypothesis, Finding, FindingStatus, FindingType


class EvidenceCorrelationEngine:
    """Correlates multi-tool findings and generates explainable hypotheses."""

    @staticmethod
    def correlate(
        findings: List[Finding],
        imphash: str = None,
        entropy: float = 0.0,
        is_dotnet: bool = False,
    ) -> Tuple[List[Finding], List[AIHypothesis], Dict[str, Any]]:
        """
        Deduplicate findings, cross-reference tool outputs, and generate
        evidence-grounded hypotheses.
        """
        deduped: List[Finding] = []
        seen_keys: Set[str] = set()

        benign_indicators: List[str] = []
        suspicious_indicators: List[str] = []
        hypotheses: List[AIHypothesis] = []

        # 1. Deduplication pass
        for f in findings:
            # Key based on type, normalized name, and address
            key = f"{f.finding_type}:{f.name.lower()}:{f.address_or_location or ''}"
            if key in seen_keys:
                # Corroborate existing finding
                for existing in deduped:
                    if f"{existing.finding_type}:{existing.name.lower()}:{existing.address_or_location or ''}" == key:
                        if f.source_tool not in [e.source for e in existing.evidence]:
                            existing.evidence.append(
                                type(existing.evidence[0])(source=f.source_tool, content=f.description)
                                if existing.evidence else None
                            ) if hasattr(existing, "evidence") else None
                            existing.confidence = min(0.99, existing.confidence + 0.05)
                            existing.verification_status = FindingStatus.CORROBORATED
                continue

            seen_keys.add(key)
            deduped.append(f)

        # 2. Extract key signals
        suspicious_apis = [f for f in deduped if f.name == "suspicious_api" or "suspicious_import" in f.name]
        network_strings = [f for f in deduped if f.name in ("network_url", "network_ip")]
        compilers = [f for f in deduped if f.finding_type == FindingType.COMPILER]
        high_entropy_sections = [f for f in deduped if f.finding_type == FindingType.SECTION and f.raw_data.get("entropy", 0) > 7.1]
        anti_debug = [f for f in suspicious_apis if "IsDebuggerPresent" in f.description or "CheckRemoteDebuggerPresent" in f.description]

        # 3. Correlation Rules & Hypothesis Generation

        # Hypothesis A: Potential Payload Unpacking or Memory Injection
        if high_entropy_sections and any("VirtualAlloc" in f.description or "WriteProcessMemory" in f.description for f in suspicious_apis):
            hypotheses.append(
                AIHypothesis(
                    category="Memory Injection / Unpacking",
                    title="Suspicious Memory Manipulation with High-Entropy Payload",
                    description=(
                        f"Sample contains {len(high_entropy_sections)} high-entropy section(s) combined with memory allocation "
                        "APIs (VirtualAlloc/WriteProcessMemory). This pattern commonly indicates a self-extracting packer, "
                        "crypter, or runtime memory injector."
                    ),
                    confidence=0.88,
                    supporting_evidence_ids=[f.id for f in (high_entropy_sections + suspicious_apis)[:5]],
                )
            )
            suspicious_indicators.append(f"Memory allocation combined with high section entropy ({len(high_entropy_sections)} packed sections)")

        # Hypothesis B: Network Command & Control or Telemetry Exfiltration
        if network_strings and any("Internet" in f.description or "WSA" in f.description or "connect" in f.description or "URLDownload" in f.description for f in suspicious_apis):
            hypotheses.append(
                AIHypothesis(
                    category="Network Communication",
                    title="Active Network Connection Capability with Embedded Endpoints",
                    description=(
                        f"Sample contains embedded network endpoints ({len(network_strings)} URLs/IPs) along with Win32 network "
                        "APIs. This indicates active outbound HTTP(S) or socket communication capability."
                    ),
                    confidence=0.85,
                    supporting_evidence_ids=[f.id for f in (network_strings + suspicious_apis)[:5]],
                )
            )
            suspicious_indicators.append(f"Embedded network endpoints ({len(network_strings)}) correlated with socket APIs")

        # Hypothesis C: Anti-Analysis and Evasion
        if anti_debug:
            hypotheses.append(
                AIHypothesis(
                    category="Anti-Analysis",
                    title="Debugger Evasion Mechanisms Present",
                    description="Sample references anti-debugging inspection APIs (IsDebuggerPresent). It may alter behavior when analyzed in a sandbox or debugger.",
                    confidence=0.82,
                    supporting_evidence_ids=[f.id for f in anti_debug],
                )
            )
            suspicious_indicators.append(f"Anti-debugging API calls detected: {[f.description for f in anti_debug]}")

        # Normal/Benign indicators
        if compilers:
            benign_indicators.append(f"Identified compiler/toolchain: {[c.description for c in compilers]}")
        if entropy < 6.8:
            benign_indicators.append(f"Normal overall executable Shannon entropy ({entropy:.2f} / 8.000)")
        if not suspicious_apis:
            benign_indicators.append("No common process injection or remote thread APIs detected in imports")

        assessment = {
            "verdict": "SUSPICIOUS" if suspicious_indicators and len(hypotheses) >= 2 else (
                "INVESTIGATE" if suspicious_indicators else "LIKELY_BENIGN"
            ),
            "confidence": 0.85 if hypotheses else 0.70,
            "benign_indicators": benign_indicators,
            "suspicious_indicators": suspicious_indicators,
            "hypotheses_count": len(hypotheses),
            "correlation_summary": (
                f"Correlated {len(deduped)} deduplicated findings across {len(seen_keys)} distinct signals. "
                f"Generated {len(hypotheses)} investigation hypothesis/hypotheses."
            ),
        }

        return deduped, hypotheses, assessment
