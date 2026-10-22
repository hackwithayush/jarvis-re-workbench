"""
JARVIS RE — Phase 6 Unified Evidence Correlation Test Suite
Automated regression tests covering:
1. Multi-tool finding deduplication and corroboration.
2. Cross-domain correlation (Memory APIs + High Entropy -> Unpacking hypothesis).
3. Network string + Socket API correlation.
4. Transparent confidence scoring and explainable assessment.
"""

import pytest

from app.core.evidence_engine import EvidenceCorrelationEngine
from app.core.schema import Finding, FindingStatus, FindingType


def test_01_evidence_deduplication():
    """Verify deduplication of identical findings from multiple tools with status corroboration."""
    f1 = Finding(
        sample_sha256="test_hash",
        source_tool="tool_a",
        finding_type=FindingType.METADATA,
        name="compiler_id",
        description="Microsoft Visual C++ v19",
        confidence=0.8,
    )
    f2 = Finding(
        sample_sha256="test_hash",
        source_tool="tool_b",
        finding_type=FindingType.METADATA,
        name="compiler_id",
        description="Microsoft Visual C++ v19",
        confidence=0.85,
    )

    deduped, hypotheses, assessment = EvidenceCorrelationEngine.correlate([f1, f2])

    assert len(deduped) == 1
    assert deduped[0].verification_status == FindingStatus.CORROBORATED
    assert deduped[0].confidence > 0.8


def test_02_memory_injection_hypothesis():
    """Verify cross-tool correlation between high-entropy sections and memory APIs."""
    f_sec = Finding(
        sample_sha256="test_hash",
        source_tool="pe_parser",
        finding_type=FindingType.SECTION,
        name=".packed",
        description="Section .packed with entropy 7.85",
        raw_data={"entropy": 7.85},
    )
    f_api = Finding(
        sample_sha256="test_hash",
        source_tool="pe_parser",
        finding_type=FindingType.IMPORT,
        name="suspicious_api",
        description="Imported VirtualAlloc: Process Memory Allocation",
    )

    deduped, hypotheses, assessment = EvidenceCorrelationEngine.correlate([f_sec, f_api], entropy=7.8)

    assert len(hypotheses) >= 1
    hyp = hypotheses[0]
    assert "Memory Manipulation" in hyp.title or "Memory Injection" in hyp.category
    assert hyp.confidence >= 0.85
    assert f_sec.id in hyp.supporting_evidence_ids or f_api.id in hyp.supporting_evidence_ids


def test_03_network_correlation():
    """Verify correlation between embedded network strings and socket APIs."""
    f_str = Finding(
        sample_sha256="test_hash",
        source_tool="string_extractor",
        finding_type=FindingType.STRING,
        name="network_url",
        description="[network_url] 'https://c2.evil-corp.com/beacon'",
    )
    f_net = Finding(
        sample_sha256="test_hash",
        source_tool="pe_parser",
        finding_type=FindingType.IMPORT,
        name="suspicious_api",
        description="Imported InternetOpenA: WinINet HTTP Connection",
    )

    deduped, hypotheses, assessment = EvidenceCorrelationEngine.correlate([f_str, f_net])

    assert any(h.category == "Network Communication" for h in hypotheses)
    assert assessment["verdict"] in ("SUSPICIOUS", "INVESTIGATE")
