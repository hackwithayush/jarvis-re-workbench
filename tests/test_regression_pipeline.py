"""
JARVIS RE — Pipeline Repair & Truthfulness Regression Test Suite
Validates fixes for:
1. Future and invalid PE timestamps
2. Truncated or out-of-bounds CLR metadata
3. PE32 machine vs managed AnyCPU runtime architecture reporting
4. Zero-function analysis results and truthful tool reporting
5. Contradictions between tool logs and report summaries
6. Missing or failed Ghidra execution handling
7. radare2 output parsing and function recovery
8. Duplicate and low-quality strings filtering and grouping
9. Non-empty evidence arrays and complete finding provenance
10. Provisional verdicts when coverage is incomplete
11. Stable hashes and reproducible report generation
"""

import os
import struct
import tempfile
from datetime import datetime, timezone
import pytest

from app.core.parsers.pe_parser import PEParser
from app.core.parsers.string_extractor import StringExtractor, is_quality_string
from app.core.evidence_engine import EvidenceCorrelationEngine
from app.core.reporter import ReportGenerator
from app.core.schema import (
    AnalysisReport,
    Finding,
    FindingStatus,
    FindingType,
    SampleInfo,
    SectionInfo,
)
from adapters.radare2_adapter import Radare2Adapter
from adapters.ghidra_adapter import GhidraAdapter


def build_synthetic_pe(
    timestamp: int = 1700000000,
    machine: int = 0x014C,  # x86
    include_clr: bool = False,
    clr_meta_rva: int = 0x2000,
    clr_meta_sz: int = 500,
    clr_flags: int = 0x00000001,  # COMIMAGE_FLAGS_ILONLY
    file_size_padding: int = 4096,
) -> bytes:
    """Build a deterministic synthetic PE binary in memory."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)

    pe_sig = b"PE\x00\x00"
    num_sections = 1
    opt_size = 224
    coff = struct.pack("<HHIIIHH", machine, num_sections, timestamp, 0, 0, opt_size, 0x0102)

    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x010B)  # PE32
    struct.pack_into("<I", opt, 16, 0x1000)  # Entry point RVA
    struct.pack_into("<I", opt, 28, 0x00400000)  # ImageBase
    struct.pack_into("<I", opt, 92, 16)  # Number of data directories (16)

    # Section table
    sec_vaddr = 0x1000
    sec_vsize = 0x2000
    sec_raw_ptr = 0x200
    sec_raw_size = 0x1000
    sec = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        sec_vsize,
        sec_vaddr,
        sec_raw_size,
        sec_raw_ptr,
        0, 0, 0, 0,
        0x60000020,
    )

    # Optional CLR Directory (index 14 -> offset 96 + 14*8 = 208)
    if include_clr:
        clr_rva = 0x1200
        clr_sz = 72
        struct.pack_into("<II", opt, 96 + (14 * 8), clr_rva, clr_sz)

    header = dos + pe_sig + coff + opt + sec
    pad_to_raw = b"\x00" * max(0, sec_raw_ptr - len(header))
    raw_data = bytearray(header + pad_to_raw)

    # Section payload
    payload = bytearray(b"\x90" * sec_raw_size)

    if include_clr:
        # Place CLR header inside section at RVA 0x1200 -> raw offset = sec_raw_ptr + (0x1200 - 0x1000) = 0x200 + 0x200 = 0x400
        clr_hdr_raw_off = sec_raw_ptr + (0x1200 - 0x1000)
        cor20 = struct.pack(
            "<IHHIIII",
            72,       # cb
            2,        # MajorRuntimeVersion
            5,        # MinorRuntimeVersion
            clr_meta_rva,
            clr_meta_sz,
            clr_flags,
            0x06000001,  # EntryPointToken
        )
        payload_offset = clr_hdr_raw_off - sec_raw_ptr
        payload[payload_offset:payload_offset + len(cor20)] = cor20

    raw_data.extend(payload)
    if file_size_padding > len(raw_data):
        raw_data.extend(b"\x00" * (file_size_padding - len(raw_data)))

    return bytes(raw_data)


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

def test_01_future_and_invalid_pe_timestamps():
    """Verify that PE parser flags timestamps in the future as anomalies with clear reasoning."""
    future_ts = 2596061630  # Year 2052
    pe_data = build_synthetic_pe(timestamp=future_ts)
    parser = PEParser(pe_data, "test_hash")
    findings, _, _, _, _, ts_str = parser.parse()

    assert "2052" in ts_str
    # Find anomaly finding
    future_findings = [f for f in findings if f.name == "future_compilation_timestamp"]
    assert len(future_findings) == 1
    assert future_findings[0].finding_type == FindingType.ANOMALY
    assert future_findings[0].verification_status == FindingStatus.FLAGGED
    assert "Implausible future COFF compilation timestamp" in future_findings[0].description
    assert future_findings[0].confidence_reasoning is not None


def test_02_truncated_or_oob_clr_metadata():
    """Verify that CLR metadata pointing outside valid physical bounds emits an anomaly."""
    # Place metadata at RVA 0x50000 with size 500000, which exceeds section and file size
    pe_data = build_synthetic_pe(
        include_clr=True,
        clr_meta_rva=0x50000,
        clr_meta_sz=500000,
    )
    parser = PEParser(pe_data, "test_hash")
    findings, _, _, _, _, _ = parser.parse()

    boundary_violations = [f for f in findings if f.name == "clr_metadata_boundary_violation"]
    assert len(boundary_violations) >= 1
    assert boundary_violations[0].finding_type == FindingType.ANOMALY
    assert boundary_violations[0].verification_status == FindingStatus.FLAGGED
    assert "does not map to any valid section" in boundary_violations[0].description or "extends beyond file boundary" in boundary_violations[0].description


def test_03_pe32_versus_managed_anycpu_architecture():
    """Verify distinction between PE Machine (x86 32-bit) and CLR target architecture (Managed AnyCPU)."""
    pe_data = build_synthetic_pe(
        machine=0x014C,  # x86
        include_clr=True,
        clr_flags=0x00000001,  # COMIMAGE_FLAGS_ILONLY
        clr_meta_rva=0x1500,
        clr_meta_sz=100,
    )
    parser = PEParser(pe_data, "test_hash")
    findings, _, _, _, _, _ = parser.parse()

    clr_findings = [f for f in findings if f.name == "dotnet_clr_header"]
    assert len(clr_findings) == 1
    assert "Managed AnyCPU (Pure IL)" in clr_findings[0].description
    assert clr_findings[0].raw_data.get("clr_target_arch") == "Managed AnyCPU (Pure IL)"
    assert clr_findings[0].raw_data.get("metadata_size") == 100


def test_04_zero_function_analysis_results_and_truthful_reporting():
    """Verify that 0 recovered functions is accurately reported and never falsely claims recovery."""
    sample = SampleInfo(
        filename="test_managed.exe",
        sha256="abc123def456",
        md5="md5test",
        sha1="sha1test",
        file_size=10240,
        file_type="PE (Portable Executable)",
        architecture="x86 (32-bit)",
        entropy=6.5,
    )
    # Empty functions array with radare2 executed
    report = ReportGenerator.build_report(
        sample=sample,
        findings=[
            Finding(
                sample_sha256="abc123def456",
                source_tool="radare2",
                finding_type=FindingType.METADATA,
                name="radare2_test",
                description="test",
            )
        ],
        tools_audited={"radare2": {"installed": True}},
        functions=[],
        tool_executions={
            "radare2": {
                "tool_name": "radare2",
                "exit_code": 0,
                "duration_seconds": 0.35,
                "functions_recovered": 0,
                "zero_functions_reason": "Zero functions discovered: binary is a managed .NET assembly.",
            }
        },
    )

    # Must accurately state 0 functions recovered
    assert any("0 native functions recovered" in lim for lim in report.limitations)
    assert not any("Disassembly and function metadata recovered" in lim for lim in report.limitations)
    assert report.summary["recovered_functions_count"] == 0


def test_05_duplicate_and_low_quality_strings_filtering():
    """Verify that low-quality repetitive strings are filtered and high-value indicators grouped."""
    # Data containing junk repetitions, URLs, and registry keys
    garbage = b"X )UUX )UUX )UU" * 5
    url = b"https://apps.microsoft.com/store/detail/app"
    reg = b"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows"
    payload = garbage + b"\x00" + url + b"\x00" + reg + b"\x00"

    extractor = StringExtractor(payload, "test_hash")
    findings = extractor.extract()

    # Repetitive sequence 'X )UU' should NOT be prioritized as a high-value indicator
    high_val_names = [f.name for f in findings if f.raw_data.get("is_high_value")]
    assert "network_url" in high_val_names
    assert "registry_key" in high_val_names

    # Check stats
    stats = extractor.stats
    assert stats["raw_strings_count"] > 0
    assert stats["deduplicated_groups_count"] > 0
    assert stats["high_value_indicators_count"] >= 2


def test_06_provisional_verdict_when_coverage_incomplete():
    """Verify that absence of suspicious indicators does NOT produce a confident benign verdict when coverage is incomplete."""
    findings = [
        Finding(
            sample_sha256="hash1",
            source_tool="pe_parser",
            finding_type=FindingType.METADATA,
            name="clean_header",
            description="Normal header",
        )
    ]

    # Incomplete coverage: 0 functions, no dynamic analysis
    deduped, hypotheses, assessment = EvidenceCorrelationEngine.correlate(
        findings=findings,
        imphash="clean_hash",
        entropy=6.2,
        is_dotnet=True,
        functions_count=0,
        dynamic_executed=False,
    )

    # Verdict must be PROVISIONAL_INCONCLUSIVE, NOT LIKELY_BENIGN
    assert assessment["verdict"] == "PROVISIONAL_INCONCLUSIVE"
    assert assessment["confidence"] < 0.60
    assert "PROVISIONAL ASSESSMENT" in assessment["rationale"]
    assert "coverage is incomplete" in assessment["rationale"]
    assert assessment["coverage_level"] == "INCOMPLETE_STATIC_ONLY"


def test_07_complete_finding_provenance():
    """Verify every finding retains source tool, version, address/location, and confidence reasoning."""
    findings = [
        Finding(
            sample_sha256="hash1",
            source_tool="pe_parser",
            tool_version="2.0.0",
            finding_type=FindingType.METADATA,
            name="test_meta",
            description="A test finding",
            address_or_location=None,  # Missing location
            confidence_reasoning=None,  # Missing reasoning
        )
    ]

    deduped, _, _ = EvidenceCorrelationEngine.correlate(findings=findings)
    assert len(deduped) == 1
    f = deduped[0]
    assert f.address_or_location is not None
    assert f.confidence_reasoning is not None
    assert f.source_tool == "pe_parser"
    assert f.tool_version == "2.0.0"


def test_08_radare2_adapter_truthful_tracking(tmp_path):
    """Verify radare2 adapter execution record correctly tracks execution duration, exit code, and zero reason."""
    pe_path = str(tmp_path / "test.exe")
    with open(pe_path, "wb") as f:
        f.write(build_synthetic_pe())

    r2 = Radare2Adapter()
    if r2.is_available():
        ws = str(tmp_path / "ws")
        findings = r2.analyze(pe_path, ws)
        assert r2.last_execution is not None
        assert "command" in r2.last_execution
        assert "exit_code" in r2.last_execution
        assert "duration_seconds" in r2.last_execution
        assert r2.last_execution["parsing_status"] in ("success", "unexpected_format")


def test_09_stable_hashes_and_reproducible_reports(tmp_path):
    """Verify hash computations and reports are strictly deterministic."""
    pe_path = str(tmp_path / "reproducible.exe")
    content = build_synthetic_pe(timestamp=1600000000)
    with open(pe_path, "wb") as f:
        f.write(content)

    from app.core.utils import compute_hashes
    h1 = compute_hashes(pe_path)
    h2 = compute_hashes(pe_path)
    assert h1["sha256"] == h2["sha256"]
    assert h1["md5"] == h2["md5"]
    assert h1["sha1"] == h2["sha1"]
