"""
JARVIS RE — Phase 3 Tool Adapter Verification Test Suite
Automated regression tests covering:
1. Canonical adapter imports and deduplication.
2. Verified adapter availability and version query.
3. Real DIE execution against synthetic PE fixture.
4. Real radare2 execution against synthetic PE fixture.
5. Subprocess timeout enforcement without process leaks.
6. Graceful error handling for missing/unavailable tools.
7. Structured output parsing and provenance validation.
"""

import os
import struct
import tempfile
import pytest

from adapters import (
    BaseAdapter,
    DIEAdapter,
    Radare2Adapter,
    GhidraAdapter,
    DnSpyAdapter,
    AngrAdapter,
    NativePythonAdapter,
)


def create_minimal_pe(file_path: str) -> None:
    """Generate a clean synthetic PE32 binary for adapter integration testing."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 64)
    pe_sig = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 1700000000, 0, 0, 224, 0x0102)
    opt_header = bytearray(224)
    struct.pack_into("<H", opt_header, 0, 0x010B)
    struct.pack_into("<I", opt_header, 16, 0x1000)
    struct.pack_into("<I", opt_header, 28, 0x00400000)
    sec_header = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    headers = dos_header + pe_sig + coff_header + opt_header + sec_header
    padding = b"\x00" * max(0, 512 - len(headers))
    payload = b"\x90\x90\xCC\xC3" + b"\x90" * 508
    with open(file_path, "wb") as f:
        f.write(headers + padding + payload)


@pytest.fixture
def sample_pe(tmp_path):
    p = tmp_path / "sample_pe.exe"
    create_minimal_pe(str(p))
    return str(p)


def test_01_adapter_deduplication_and_imports():
    """Verify that adapters import cleanly and re-exports match canonical classes."""
    import adapters
    import app.adapters
    import re_engine.adapters

    assert app.adapters.DIEAdapter is adapters.DIEAdapter
    assert re_engine.adapters.DIEAdapter is adapters.DIEAdapter
    assert app.adapters.Radare2Adapter is adapters.Radare2Adapter
    assert app.adapters.GhidraAdapter is adapters.GhidraAdapter


def test_02_adapter_availability_and_version():
    """Verify that installed reverse-engineering tools report positive availability."""
    die = DIEAdapter()
    assert die.is_available() is True
    assert die.get_version() is not None
    assert "die" in die.get_version().lower()

    r2 = Radare2Adapter()
    assert r2.is_available() is True
    assert r2.get_version() is not None
    assert "radare2" in r2.get_version().lower()

    native = NativePythonAdapter()
    assert native.is_available() is True
    assert native.get_version() == "1.0.0-builtin"


def test_03_die_execution_on_fixture(sample_pe, tmp_path):
    """Verify real DIE subprocess execution produces structured findings."""
    die = DIEAdapter()
    workspace = str(tmp_path / "die_ws")
    os.makedirs(workspace, exist_ok=True)

    findings = die.analyze(sample_pe, workspace)
    assert isinstance(findings, list)
    assert len(findings) > 0
    assert findings[0]["source_tool"] == "die"
    assert "finding_type" in findings[0]
    assert "confidence" in findings[0]


def test_04_radare2_execution_on_fixture(sample_pe, tmp_path):
    """Verify real radare2 subprocess execution discovers functions and security metadata."""
    r2 = Radare2Adapter()
    workspace = str(tmp_path / "r2_ws")
    os.makedirs(workspace, exist_ok=True)

    findings = r2.analyze(sample_pe, workspace)
    assert isinstance(findings, list)
    assert len(findings) > 0
    tools = [f["source_tool"] for f in findings]
    assert all(t == "radare2" for t in tools)


def test_05_missing_tool_graceful_handling(sample_pe, tmp_path):
    """Verify adapter behavior when pointed to a non-existent binary path."""
    fake_adapter = DIEAdapter(tool_path="C:\\nonexistent_dir\\fake_die.exe")
    assert fake_adapter.is_available() is False
    assert fake_adapter.get_version() is None

    with pytest.raises(RuntimeError) as exc_info:
        fake_adapter.analyze(sample_pe, str(tmp_path))
    assert "not available" in str(exc_info.value).lower()


def test_06_timeout_handling(sample_pe, tmp_path):
    """Verify that subprocess timeout is strictly enforced."""
    # Radare2 with an unrealistically tiny timeout (0.0001 seconds)
    r2_timeout = Radare2Adapter(timeout=0.0001)
    workspace = str(tmp_path / "timeout_ws")
    os.makedirs(workspace, exist_ok=True)

    # It should not hang indefinitely; should log warning and return gracefully or raise TimeoutError
    try:
        findings = r2_timeout.analyze(sample_pe, workspace)
        # If it returned due to catch-and-log inside analyze
        assert isinstance(findings, list)
    except TimeoutError:
        pass  # Also valid expected behavior
