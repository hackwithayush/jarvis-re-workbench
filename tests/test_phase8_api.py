"""
JARVIS RE — Phase 8 API Endpoints & Job Management Test Suite
Automated regression tests covering:
1. Asynchronous job creation (`POST /api/jobs`) and polling (`GET /api/jobs/{id}`).
2. Report export endpoints (Markdown, JSON, HTML).
3. AI explanation endpoints (`/api/ai/*`).
4. Controlled dynamic sandbox authorization enforcement.
5. Service health and capability manifest.
"""

import io
import time
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.job_manager import job_manager


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def pe_payload():
    """Minimal PE payload buffer."""
    import struct
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x014C, 1, 1700000000, 0, 0, 224, 0x0102)
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x010B)
    struct.pack_into("<I", opt, 16, 0x1000)
    sec = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    data = dos + pe_sig + coff + opt + sec + (b"\x90" * 512)
    return io.BytesIO(data)


def test_01_health_and_capabilities(client):
    """Verify health endpoint returns status and full capability list."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["version"] == "1.0.0"
    assert "pe_coff_parsing" in data["capabilities"]
    assert "controlled_dynamic_sandbox" in data["capabilities"]


def test_02_async_job_lifecycle(client, pe_payload):
    """Verify queuing an asynchronous background analysis job and polling status."""
    res = client.post("/api/jobs", files={"file": ("test_async.exe", pe_payload, "application/octet-stream")})
    assert res.status_code == 200
    job_data = res.json()
    job_id = job_data["job_id"]
    assert job_id is not None
    assert job_data["status"] in ("queued", "running", "completed")

    # Poll until completed (capped at 15s)
    for _ in range(15):
        poll = client.get(f"/api/jobs/{job_id}")
        assert poll.status_code == 200
        pdata = poll.json()
        if pdata["status"] == "completed":
            break
        time.sleep(0.5)

    assert pdata["status"] == "completed"
    assert pdata["progress_pct"] == 100

    # Retrieve result
    res_report = client.get(f"/api/jobs/{job_id}/result")
    assert res_report.status_code == 200
    report = res_report.json()
    assert report["sample"]["filename"] == "test_async.exe"


def test_03_report_export_formats(client, pe_payload):
    """Verify Markdown, JSON, and HTML report exports."""
    # First run synchronous analysis to generate a report
    res = client.post("/api/analyze", files={"file": ("export_test.exe", pe_payload, "application/octet-stream")})
    assert res.status_code == 200
    report_id = res.json()["report_id"]

    # Markdown export
    md_res = client.get(f"/api/report/{report_id}/markdown")
    assert md_res.status_code == 200
    assert "JARVIS Reverse Engineering Workbench" in md_res.text

    # JSON export
    json_res = client.get(f"/api/report/{report_id}/json")
    assert json_res.status_code == 200
    assert json_res.json()["report_id"] == report_id

    # HTML export
    html_res = client.get(f"/api/report/{report_id}/html")
    assert html_res.status_code == 200
    assert "<!DOCTYPE html>" in html_res.text
    assert "export_test.exe" in html_res.text


def test_04_dynamic_sandbox_endpoint_safety(client):
    """Verify that unauthorized dynamic execution requests return HTTP 403 Forbidden."""
    res = client.post("/api/dynamic/execute", json={
        "sample_path": "C:\\fake\\sample.exe",
        "authorized": False,
        "confirmation_token": "",
    })
    assert res.status_code == 403
    assert "Authorization required" in res.json()["detail"]


def test_05_ai_explain_function_endpoint(client):
    """Verify AI function explanation endpoint."""
    res = client.post("/api/ai/explain_function", json={
        "name": "test_fcn",
        "address": "0x00401000",
        "size": 64,
        "instructions": ["0x00401000: ret"],
        "api_calls": [],
        "cfg_blocks": [],
        "cross_references": [],
    })
    assert res.status_code == 200
    data = res.json()
    assert data["function_name"] == "test_fcn"
    assert "technical_summary" in data
