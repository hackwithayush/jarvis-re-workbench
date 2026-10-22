"""
JARVIS RE — Phase 9 Specialist Tools Test Suite
Automated regression tests covering:
1. JADX Android APK/DEX decompiler adapter.
2. YARA signature rule evaluation.
3. Mandiant capa capability detection.
4. LIEF multi-format parser integration.
5. Ghidra & angr deep analysis endpoints.
"""

import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from app.main import app
from adapters.jadx_adapter import JadxAdapter
from adapters.yara_adapter import YaraAdapter
from adapters.capa_adapter import CapaAdapter
from app.core.tools import ToolAuditor


def test_01_jadx_availability_and_version():
    """Verify JADX decompiler is installed and returns valid version."""
    adapter = JadxAdapter()
    assert adapter.is_available() is True
    version = adapter.get_version()
    assert version is not None
    assert "jadx" in version.lower() or "1.5" in version


def test_02_yara_rule_matching():
    """Verify YARA signature rule evaluation on a test sample."""
    adapter = YaraAdapter()
    assert adapter.is_available() is True

    # Create temporary binary with known pattern
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"\x90\x90VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00")
        sample_path = f.name

    try:
        findings = adapter.analyze(sample_path, os.path.dirname(sample_path))
        assert len(findings) >= 1
        rule_names = [f["name"] for f in findings]
        assert "yara_Suspicious_Process_Injection" in rule_names
    finally:
        if os.path.isfile(sample_path):
            os.remove(sample_path)


def test_03_capa_capability_detection():
    """Verify Mandiant capa capability engine is installed and responsive."""
    adapter = CapaAdapter()
    assert adapter.is_available() is True
    assert adapter.get_version() is not None


def test_04_lief_parser_integration():
    """Verify LIEF parser is available and can parse binary headers."""
    import lief
    assert lief.__version__ is not None
    tool_status = ToolAuditor.check_lief()
    assert tool_status["installed"] is True


def test_05_deep_endpoints_validation():
    """Verify /api/deep/ghidra and /api/deep/angr endpoints exist and enforce error handling."""
    client = TestClient(app)

    # Calling with nonexistent report ID should return 404
    res_gh = client.post("/api/deep/ghidra/nonexistent_id")
    assert res_gh.status_code == 404

    res_angr = client.post("/api/deep/angr/nonexistent_id")
    assert res_angr.status_code == 404
