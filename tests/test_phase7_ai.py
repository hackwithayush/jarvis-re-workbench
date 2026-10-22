"""
JARVIS RE — Phase 7 AI Reverse Engineering Analyst Test Suite
Automated regression tests covering:
1. Grounded function and assembly explanation.
2. API import capability summarization.
3. Evidence-referenced investigation briefing generation.
"""

from datetime import datetime, timezone
import pytest

from app.core.ai_analyst import AIAnalyst
from app.core.schema import (
    AnalysisReport,
    Finding,
    FindingType,
    FunctionDetails,
    ImportFunction,
    ImportModule,
    SampleInfo,
)


def test_01_explain_function():
    """Verify grounded explanation of function instructions, calling convention, and APIs."""
    func = FunctionDetails(
        name="crypto_worker",
        address="0x00401200",
        size=150,
        calling_convention="__stdcall",
        parameter_count=2,
        instructions=[
            "0x00401200:  55            push ebp",
            "0x00401201:  89e5          mov ebp, esp",
            "0x00401203:  e820000000    call VirtualAlloc",
        ],
        api_calls=["VirtualAlloc"],
    )

    res = AIAnalyst.explain_function(func)

    assert res["function_name"] == "crypto_worker"
    assert res["address"] == "0x00401200"
    assert "Dynamic memory management" in res["inferred_behaviors"]
    assert "VirtualAlloc" in res["technical_summary"]
    assert res["analyst_hypothesis"] is not None


def test_02_explain_api_imports():
    """Verify categorization of binary capabilities derived from imported APIs."""
    imports = [
        ImportModule(
            module_name="KERNEL32.dll",
            functions=[
                ImportFunction(name="VirtualAlloc", is_suspicious=True),
                ImportFunction(name="WriteProcessMemory", is_suspicious=True),
            ],
        ),
        ImportModule(
            module_name="WS2_32.dll",
            functions=[
                ImportFunction(name="WSAStartup", is_suspicious=False),
                ImportFunction(name="connect", is_suspicious=False),
            ],
        ),
    ]

    res = AIAnalyst.explain_api_imports(imports)

    caps = res["capabilities"]
    assert "Memory & Injection" in caps
    assert "Network & Web" in caps
    assert "KERNEL32.dll!VirtualAlloc" in caps["Memory & Injection"]


def test_03_generate_investigation_brief():
    """Verify synthesis of evidence report into structured analyst briefing."""
    sample = SampleInfo(
        filename="malware_sample.exe",
        sha256="a" * 64,
        md5="b" * 32,
        sha1="c" * 40,
        file_size=102400,
        file_type="PE (Portable Executable)",
        architecture="x86 (32-bit)",
        entropy=7.45,
    )
    findings = [
        Finding(
            sample_sha256="a" * 64,
            source_tool="pe_parser",
            finding_type=FindingType.SECTION,
            name=".packed",
            description="High entropy section detected",
            confidence=0.9,
        )
    ]
    report = AnalysisReport(
        report_id="test_rpt_1",
        sample=sample,
        summary={"is_packed_suspect": True, "tools_actually_executed": ["pe_parser", "die"]},
        findings=findings,
        tools_audited={},
        limitations=[],
        generated_at=datetime.now(timezone.utc),
    )

    brief = AIAnalyst.generate_investigation_brief(report)

    assert brief["target"] == "malware_sample.exe"
    assert brief["is_packed_suspect"] is True
    assert len(brief["key_evidence"]) >= 1
    assert "packed" in brief["assessment"].lower()
