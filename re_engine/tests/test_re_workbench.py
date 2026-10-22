"""
Jarvis RE — Automated Test Suite
Verifies:
1. Pydantic schema validation & model integrity
2. Hashing, architecture detection, and file type classification
3. Native Python static analysis engine (PE parsing, entropy, string classification)
4. Tool routing & adapter status audit
5. Full pipeline execution on synthetic PE binary fixture
6. Report generation (JSON, Markdown, HTML)
7. Flask REST API routes (/api/re/*)
"""

import json
import os
import shutil
import struct
import tempfile
import unittest

from app import app
from models import db
from REVERSE_ENGINEERING.models import REProject, RESample, REFinding, REJob
from REVERSE_ENGINEERING.schema import Finding, FindingStatus, FindingType, SourceTool
from REVERSE_ENGINEERING.utils import compute_hashes, detect_architecture, detect_file_type
from REVERSE_ENGINEERING.adapters.native_adapter import NativePythonAdapter
from REVERSE_ENGINEERING.pipeline import AnalysisPipeline
from REVERSE_ENGINEERING.report_generator import ReportGenerator


def _create_synthetic_pe(file_path: str) -> None:
    """Generate a valid minimal synthetic 32-bit PE binary for testing."""
    # DOS Header (64 bytes)
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    # e_lfanew offset to PE signature at offset 0x3C = 64 (0x40)
    struct.pack_into("<I", dos_header, 0x3C, 64)

    # PE Signature (4 bytes)
    pe_sig = b"PE\x00\x00"

    # COFF File Header (20 bytes)
    machine_x86 = 0x014C
    num_sections = 1
    timestamp = 1700000000
    opt_hdr_size = 224
    chars = 0x0102  # EXECUTABLE_IMAGE | 32BIT_MACHINE
    coff_header = struct.pack("<HHIIIHH", machine_x86, num_sections, timestamp, 0, 0, opt_hdr_size, chars)

    # Optional Header (Standard 28 bytes + Windows specific fields)
    magic_pe32 = 0x010B
    entry_point_rva = 0x1000
    opt_header = bytearray(opt_hdr_size)
    struct.pack_into("<H", opt_header, 0, magic_pe32)
    struct.pack_into("<I", opt_header, 16, entry_point_rva)

    # Section Header (.text, 40 bytes)
    sec_name = b".text\x00\x00\x00"
    vsize = 0x200
    vaddr = 0x1000
    raw_size = 0x200
    raw_ptr = 0x200  # Offset in file
    sec_chars = 0x60000020  # CODE | EXECUTE | READ
    sec_header = struct.pack("<8sIIIIIIHHI", sec_name, vsize, vaddr, raw_size, raw_ptr, 0, 0, 0, 0, sec_chars)

    # Pad until section raw_ptr (0x200 = 512 bytes)
    headers_blob = dos_header + pe_sig + coff_header + opt_header + sec_header
    padding = b"\x00" * max(0, 512 - len(headers_blob))

    # Section payload with code and strings
    payload = (
        b"\x90\x90\xCC"  # NOPs and INT3
        b"https://api.internal-telemetry.org/v1/ping\x00"
        b"192.168.1.100\x00"
        b"VirtualAllocEx\x00"
        b"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
    )
    payload += b"\x90" * max(0, 512 - len(payload))

    with open(file_path, "wb") as fh:
        fh.write(headers_blob + padding + payload)


class TestReverseEngineeringWorkbench(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()
        cls.temp_dir = tempfile.mkdtemp(prefix="jarvis_re_test_")
        cls.test_pe = os.path.join(cls.temp_dir, "test_synthetic.exe")
        _create_synthetic_pe(cls.test_pe)

        with app.app_context():
            db.create_all()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_01_schema_validation(self):
        """Verify Pydantic finding schema enforces types and constraints."""
        finding = Finding(
            sample_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            source_tool=SourceTool.PYTHON,
            finding_type=FindingType.METADATA,
            name="test_item",
            confidence=0.85,
            status=FindingStatus.UNVERIFIED,
        )
        self.assertEqual(finding.source_tool, "python")
        self.assertEqual(finding.confidence, 0.85)

    def test_02_utils_hashing_and_architecture(self):
        """Verify binary format identification, hashing, and architecture parser."""
        hashes = compute_hashes(self.test_pe)
        self.assertEqual(len(hashes["sha256"]), 64)
        self.assertEqual(len(hashes["md5"]), 32)

        arch = detect_architecture(self.test_pe)
        self.assertEqual(arch, "x86")

        fmt = detect_file_type(self.test_pe)
        self.assertEqual(fmt, "PE")

    def test_03_native_static_analyzer(self):
        """Verify pure Python static analyzer extracts entry points, sections, and strings."""
        adapter = NativePythonAdapter()
        self.assertTrue(adapter.is_available())

        findings = adapter.analyze(self.test_pe, self.temp_dir)
        self.assertGreater(len(findings), 3)

        finding_types = [f["finding_type"] for f in findings]
        self.assertIn("metadata", finding_types)
        self.assertIn("entry_point", finding_types)
        self.assertIn("section", finding_types)
        self.assertIn("string", finding_types)

        # Check detected classified strings
        string_findings = [f for f in findings if f["finding_type"] == "string"]
        string_names = [f["name"] for f in string_findings]
        self.assertTrue(any(x in string_names for x in ["network_url", "network_ip", "registry_key", "suspicious_api"]))

    def test_04_pipeline_execution(self):
        """Verify complete pipeline ingestion, job tracking, and evidence persistence."""
        pipeline = AnalysisPipeline(app=app)
        with app.app_context():
            # Create project
            proj = REProject(name="Test Suite RE Project")
            db.session.add(proj)
            db.session.commit()
            proj_id = proj.id

            # Register sample
            sample = pipeline.register_sample(self.test_pe, proj_id)
            sample_id = sample.id
            self.assertIsNotNone(sample_id)
            self.assertEqual(sample.architecture, "x86")

            # Run analysis
            job_id = pipeline.run_analysis(sample_id, job_type="full")
            self.assertIsNotNone(job_id)

            job = db.session.get(REJob, job_id)
            self.assertEqual(job.status, "completed")
            self.assertEqual(job.progress, 100)

            findings = REFinding.query.filter_by(sample_id=sample_id).all()
            self.assertGreater(len(findings), 0)

    def test_05_report_generation(self):
        """Verify report generator produces valid JSON, Markdown, and HTML."""
        reporter = ReportGenerator()
        sample_meta = {
            "filename": "test_synthetic.exe",
            "sha256": "abcdef1234567890",
            "file_size": 1024,
            "file_type": "PE",
            "architecture": "x86",
        }
        findings = [
            {
                "finding_type": "entry_point",
                "name": "main_entry",
                "source_tool": "python",
                "confidence": 0.95,
                "address": "0x00001000",
                "description": "Main entry point",
            }
        ]

        json_rep = reporter.generate_report(sample_meta, findings, report_format="json")
        data = json.loads(json_rep)
        self.assertIn("sample", data)

        md_rep = reporter.generate_report(sample_meta, findings, report_format="markdown")
        self.assertIn("# Binary Analysis Report", md_rep)

        html_rep = reporter.generate_report(sample_meta, findings, report_format="html")
        self.assertIn("<!DOCTYPE html>", html_rep)
        self.assertIn("test_synthetic.exe", html_rep)

    def test_06_rest_api_endpoints(self):
        """Verify REST API: /api/re/projects, /tools/status, and report endpoints."""
        # Check tools status
        res = self.client.get("/api/re/tools/status")
        self.assertEqual(res.status_code, 200)
        tools = res.get_json()["tools"]
        self.assertIn("python", tools)
        self.assertTrue(tools["python"]["available"])

        # Create project via API
        res = self.client.post("/api/re/projects", json={"name": "API Test Project"})
        self.assertEqual(res.status_code, 201)
        p_id = res.get_json()["project"]["id"]

        # Register sample via local path
        res = self.client.post(f"/api/re/projects/{p_id}/samples", json={"file_path": self.test_pe})
        self.assertEqual(res.status_code, 201)
        s_id = res.get_json()["sample"]["id"]

        # Trigger analysis via API
        res = self.client.post(f"/api/re/samples/{s_id}/analyze", json={"job_type": "full"})
        self.assertEqual(res.status_code, 200)

        # Retrieve findings
        res = self.client.get(f"/api/re/samples/{s_id}/findings")
        self.assertEqual(res.status_code, 200)
        self.assertGreater(res.get_json()["total"], 0)

        # Retrieve HTML report
        res = self.client.get(f"/api/re/samples/{s_id}/report?format=html")
        self.assertEqual(res.status_code, 200)
        self.assertIn("<!DOCTYPE html>", res.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
