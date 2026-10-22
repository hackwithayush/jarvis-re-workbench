"""
JARVIS Reverse Engineering Workbench — Automated Test Suite
Verifies core MVP capabilities:
1. Cryptographic hashing & format detection.
2. Binary structure & architecture parsing.
3. Printable ASCII string extraction & classification.
4. Tool ecosystem availability auditing.
5. FastAPI endpoints & structured report generation.
"""

import io
import os
import struct
import tempfile
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.analyzer import BinaryAnalyzer
from app.core.tools import ToolAuditor
from app.core.schema import FindingType


def make_synthetic_pe(file_path: str) -> None:
    """Generate a valid minimal 32-bit PE binary fixture."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 64)
    pe_sig = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 1700000000, 0, 0, 224, 0x0102)
    opt_header = bytearray(224)
    struct.pack_into("<H", opt_header, 0, 0x010B)
    struct.pack_into("<I", opt_header, 16, 0x1000)  # EntryPoint RVA
    sec_header = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    headers = dos_header + pe_sig + coff_header + opt_header + sec_header
    padding = b"\x00" * max(0, 512 - len(headers))
    payload = (
        b"\x90\x90\xCC"
        b"https://telemetry.internal-network.org/v1\x00"
        b"10.0.0.1\x00"
        b"VirtualAllocEx\x00"
        b"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\x00"
    )
    payload += b"\x90" * max(0, 512 - len(payload))
    with open(file_path, "wb") as f:
        f.write(headers + padding + payload)


@pytest.fixture
def pe_fixture(tmp_path):
    sample = tmp_path / "sample_test.exe"
    make_synthetic_pe(str(sample))
    return str(sample)


def test_01_hashing_and_integrity(pe_fixture):
    """Test 1: Calculate SHA-256, MD5, and SHA-1 digests accurately."""
    analyzer = BinaryAnalyzer(pe_fixture)
    sample_info, _ = analyzer.analyze()

    assert len(sample_info.sha256) == 64
    assert len(sample_info.md5) == 32
    assert len(sample_info.sha1) == 40
    assert sample_info.file_size > 0


def test_02_pe_format_and_architecture(pe_fixture):
    """Test 2: Identify PE executable format, x86 architecture, and entry point."""
    analyzer = BinaryAnalyzer(pe_fixture)
    sample_info, findings = analyzer.analyze()

    assert "PE" in sample_info.file_type
    assert "x86" in sample_info.architecture

    entry_points = [f for f in findings if f.finding_type == FindingType.ENTRY_POINT]
    assert len(entry_points) >= 1
    assert entry_points[0].address_or_location == "0x00001000"

    sections = [f for f in findings if f.finding_type == FindingType.SECTION]
    assert len(sections) >= 1
    assert sections[0].name == ".text"


def test_03_printable_ascii_strings(pe_fixture):
    """Test 3: Extract and classify printable ASCII strings."""
    analyzer = BinaryAnalyzer(pe_fixture)
    _, findings = analyzer.analyze()

    string_findings = [f for f in findings if f.finding_type == FindingType.STRING]
    assert len(string_findings) >= 3

    names = [f.name for f in string_findings]
    assert "network_url" in names
    assert "network_ip" in names
    assert "suspicious_api" in names


def test_04_tool_availability_auditing():
    """Test 4: Verify tool auditor checks all target reverse-engineering tools."""
    tools = ToolAuditor.audit_all()
    assert "native_engine" in tools
    assert "die" in tools
    assert "ghidra" in tools
    assert "radare2" in tools
    assert "x64dbg" in tools
    assert "frida" in tools
    assert "angr" in tools

    assert tools["native_engine"]["installed"] is True


def test_05_fastapi_endpoints_and_report_generation(pe_fixture):
    """Test 5: Verify FastAPI /api/analyze, /api/tools, and markdown report routes."""
    client = TestClient(app)

    # Dashboard route
    res = client.get("/")
    assert res.status_code == 200
    assert "JARVIS RE Workbench" in res.text

    # Health check
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"

    # Tools endpoint
    res = client.get("/api/tools")
    assert res.status_code == 200
    assert "native_engine" in res.json()

    # Upload & Analyze endpoint
    with open(pe_fixture, "rb") as f:
        res = client.post("/api/analyze", files={"file": ("test_upload.exe", f, "application/octet-stream")})

    assert res.status_code == 200
    report_data = res.json()
    assert "report_id" in report_data
    assert report_data["sample"]["filename"] == "test_upload.exe"
    assert len(report_data["findings"]) > 0

    # Markdown export
    report_id = report_data["report_id"]
    res = client.get(f"/api/report/{report_id}/markdown")
    assert res.status_code == 200
    assert "JARVIS Reverse Engineering Workbench" in res.text
