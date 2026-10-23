"""
Tests for Autonomous Software Reconstruction & Creation Module
Validates Knowledge Graph, Specification Planning, Software Generation,
Build & Automated Test Agent, Differential Testing, and FastAPI Endpoints.
"""

import os
import shutil
import tempfile
import pytest
from fastapi.testclient import TestClient

from app.core.schema import (
    AnalysisReport,
    Finding,
    FindingType,
    FindingStatus,
    SampleInfo,
    EvidenceStatus,
    RequirementClassification,
    KnowledgeGraphData,
    ReconstructionSpecification,
    GeneratedProject,
    BuildReport,
    DifferentialTestResult,
)
from app.core.knowledge_graph import KnowledgeGraphEngine
from app.core.reconstruction_planner import ReconstructionPlanner
from app.core.software_generator import SoftwareGenerator
from app.core.build_agent import BuildAgent
from app.core.differential_tester import DifferentialTester
from app.main import app, REPORTS_CACHE, SPECS_CACHE, PROJECTS_CACHE


@pytest.fixture
def mock_report() -> AnalysisReport:
    """Fixture creating a realistic analyzed sample report for reconstruction."""
    sample = SampleInfo(
        filename="WallpaperDaemonService.exe",
        sha256="d41d8cd98f00b204e9800998ecf8427e1234567890abcdef1234567890abcdef",
        md5="d41d8cd98f00b204e9800998ecf8427e",
        sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
        file_size=1048576,
        file_type="PE32+ (x86-64)",
        architecture="x86-64",
        entropy=6.25,
        imphash="1234567890abcdef1234567890abcdef",
    )
    findings = [
        Finding(
            id="f-01",
            sample_sha256=sample.sha256,
            source_tool="radare2",
            finding_type=FindingType.FUNCTION,
            name="InitializeDaemonCore",
            address_or_location="0x140001000",
            description="Daemon core initializer setting up event loop",
            confidence=0.95,
            verification_status=FindingStatus.CORROBORATED,
            raw_data={"subsystem": "DaemonCore", "signature": "int InitializeDaemonCore(void)"},
        ),
        Finding(
            id="f-02",
            sample_sha256=sample.sha256,
            source_tool="radare2",
            finding_type=FindingType.FUNCTION,
            name="SyncAssetStore",
            address_or_location="0x140001200",
            description="Synchronizes wallpapers from remote repository",
            confidence=0.90,
            verification_status=FindingStatus.CORROBORATED,
            raw_data={"subsystem": "AssetSync", "signature": "bool SyncAssetStore(const char* url)"},
        ),
        Finding(
            id="f-03",
            sample_sha256=sample.sha256,
            source_tool="string_analyzer",
            finding_type=FindingType.STRING,
            name="API_ENDPOINT",
            address_or_location="0x140005010",
            description="Extracted network URL endpoint",
            confidence=0.99,
            verification_status=FindingStatus.CORROBORATED,
            raw_data={"string": "https://api.wallpaper-daemon.internal/v1/assets"},
        ),
        Finding(
            id="f-04",
            sample_sha256=sample.sha256,
            source_tool="string_analyzer",
            finding_type=FindingType.STRING,
            name="CONFIG_PATH",
            address_or_location="0x140005080",
            description="Extracted storage configuration file path",
            confidence=0.95,
            verification_status=FindingStatus.CORROBORATED,
            raw_data={"string": "settings.json"},
        ),
        Finding(
            id="f-05",
            sample_sha256=sample.sha256,
            source_tool="pe_parser",
            finding_type=FindingType.IMPORT,
            name="CreateFileW",
            address_or_location="0x140008000",
            description="Windows filesystem API import",
            confidence=1.0,
            verification_status=FindingStatus.CORROBORATED,
            raw_data={"library": "KERNEL32.dll"},
        ),
    ]

    return AnalysisReport(
        report_id="test-rep-001",
        sample=sample,
        summary={"total_findings": len(findings)},
        findings=findings,
        tools_audited={"pe_parser": True, "radare2": True, "string_analyzer": True},
        sections=[],
        imports=[],
        exports=[],
        functions=[],
        verdict="LIKELY_BENIGN",
        verdict_confidence=0.90,
    )


def test_knowledge_graph_extraction(mock_report):
    """Test extracting Knowledge Graph nodes, edges, subsystems, and Mermaid export."""
    kg_engine = KnowledgeGraphEngine()
    graph_data = kg_engine.build_graph(mock_report)

    assert isinstance(graph_data, KnowledgeGraphData)
    assert graph_data.sample_sha256 == mock_report.sample.sha256
    assert graph_data.node_count > 0
    assert graph_data.edge_count > 0

    # Verify node types
    node_types = {n.node_type.lower() for n in graph_data.nodes}
    assert "module" in node_types
    assert "function" in node_types
    assert "endpoint" in node_types
    assert "storage" in node_types

    # Verify Mermaid generation
    mermaid_diag = kg_engine.to_mermaid(graph_data)
    assert mermaid_diag.startswith("flowchart TD")
    assert "WallpaperDaemonService.exe" in mermaid_diag
    assert "InitializeDaemonCore" in mermaid_diag


def test_reconstruction_specification_generation(mock_report):
    """Test generating a clean-room specification with all 10 required sections and evidence classifications."""
    kg_engine = KnowledgeGraphEngine()
    graph_data = kg_engine.build_graph(mock_report)

    planner = ReconstructionPlanner()
    spec = planner.generate_specification(mock_report, graph_data)

    assert isinstance(spec, ReconstructionSpecification)
    assert spec.sample_sha256 == mock_report.sample.sha256
    assert spec.approved is False

    # Check 10 required sections
    assert "1. Executive Summary & Software Intent" in spec.sections
    assert "2. Observable Behaviors vs Replaced Capabilities" in spec.sections
    assert "3. Component Architecture & Subsystems" in spec.sections
    assert "4. Data Models, Storage & State Flow" in spec.sections
    assert "5. Interfaces, Endpoints & Data Contracts" in spec.sections
    assert "6. External Dependencies & Clean-Room Replacements" in spec.sections
    assert "7. Verification & Behavioral Conformance Criteria" in spec.sections
    assert "8. Non-functional, Performance & Scalability Requirements" in spec.sections
    assert "9. Ethical, Safety, Privacy & Clean-Room Boundaries" in spec.sections
    assert "10. Step-by-Step Construction Roadmap" in spec.sections

    # Check requirement classifications
    req_classes = {r.classification for r in spec.requirements}
    assert RequirementClassification.VERIFIED_FROM_EVIDENCE in req_classes
    assert RequirementClassification.PROPOSED_REPLACEMENT in req_classes


def test_software_project_generation(mock_report):
    """Test clean-room generation of an independent, working software project."""
    kg_engine = KnowledgeGraphEngine()
    graph_data = kg_engine.build_graph(mock_report)
    planner = ReconstructionPlanner()
    spec = planner.generate_specification(mock_report, graph_data)

    generator = SoftwareGenerator()
    project = generator.generate_project(spec)

    assert isinstance(project, GeneratedProject)
    assert os.path.isdir(project.project_path)
    assert len(project.files_generated) >= 6

    # Verify essential files exist
    expected_files = [
        "requirements.txt",
        "README.md",
        "config.py",
        "models.py",
        "storage.py",
        "engine.py",
        "main.py",
        "tests/test_application.py",
    ]
    for rel_path in expected_files:
        full_path = os.path.join(project.project_path, rel_path)
        assert os.path.isfile(full_path), f"Expected file {rel_path} was not created"

    # Verify clean-room implementation
    with open(os.path.join(project.project_path, "engine.py"), "r", encoding="utf-8") as f:
        engine_code = f.read()
        assert "class CoreEngine" in engine_code
        assert "execute_operation" in engine_code
        assert "get_status" in engine_code


def test_build_agent_and_packaging(mock_report):
    """Test compiling, running automated tests, and packaging the generated software."""
    kg_engine = KnowledgeGraphEngine()
    graph_data = kg_engine.build_graph(mock_report)
    planner = ReconstructionPlanner()
    spec = planner.generate_specification(mock_report, graph_data)
    generator = SoftwareGenerator()
    project = generator.generate_project(spec)

    build_agent = BuildAgent()
    build_report = build_agent.build_and_validate(project)

    assert isinstance(build_report, BuildReport)
    assert build_report.project_id == project.project_id
    assert build_report.compilation_success is True
    assert build_report.tests_passed > 0
    assert build_report.tests_failed == 0
    assert build_report.overall_success is True
    assert build_report.artifact_path is not None
    assert os.path.isfile(build_report.artifact_path)
    assert build_report.artifact_path.endswith(".zip")


def test_differential_tester(mock_report):
    """Test running differential behavior validation against reference sample observations."""
    kg_engine = KnowledgeGraphEngine()
    graph_data = kg_engine.build_graph(mock_report)
    planner = ReconstructionPlanner()
    spec = planner.generate_specification(mock_report, graph_data)
    generator = SoftwareGenerator()
    project = generator.generate_project(spec)

    tester = DifferentialTester()
    diff_result = tester.run_differential_test(project, mock_report)

    assert isinstance(diff_result, DifferentialTestResult)
    assert diff_result.project_id == project.project_id
    assert diff_result.total_checks >= 3
    assert diff_result.passed_checks >= 3
    assert diff_result.conformance_score >= 0.80
    assert diff_result.status in ("PASS", "CONFORMANT_WITH_TOLERANCES")


def test_fastapi_reconstruction_workflow(mock_report):
    """Test end-to-end reconstruction workflow through FastAPI REST API endpoints."""
    client = TestClient(app)

    # Prime cache with mock report
    REPORTS_CACHE[mock_report.report_id] = mock_report

    # 1. Generate Knowledge Graph
    resp = client.post(f"/api/reconstruct/graph/{mock_report.report_id}")
    assert resp.status_code == 200
    graph_payload = resp.json()
    assert graph_payload["sample_sha256"] == mock_report.sample.sha256
    assert graph_payload["node_count"] > 0

    # 2. Get Mermaid diagram
    resp_mermaid = client.get(f"/api/reconstruct/graph/{mock_report.report_id}/mermaid")
    assert resp_mermaid.status_code == 200
    assert resp_mermaid.headers["content-type"].startswith("text/plain")
    assert "flowchart TD" in resp_mermaid.text

    # 3. Generate Specification
    resp_spec = client.post(f"/api/reconstruct/spec/{mock_report.report_id}")
    assert resp_spec.status_code == 200
    spec_payload = resp_spec.json()
    spec_id = spec_payload["spec_id"]
    assert spec_payload["approved"] is False

    # 4. Approve Specification
    resp_appr = client.post(f"/api/reconstruct/approve/{spec_id}")
    assert resp_appr.status_code == 200
    assert resp_appr.json()["approved"] is True

    # 5. Generate Project
    resp_gen = client.post("/api/reconstruct/generate", json={"spec_id": spec_id})
    assert resp_gen.status_code == 200
    proj_payload = resp_gen.json()
    project_id = proj_payload["project_id"]
    assert len(proj_payload["files_generated"]) >= 6

    # 6. Build Project
    resp_build = client.post(f"/api/reconstruct/build/{project_id}")
    assert resp_build.status_code == 200
    build_payload = resp_build.json()
    assert build_payload["compilation_passed"] is True
    assert build_payload["tests_passed"] > 0
    assert build_payload["status"] == "success"

    # 7. Run Differential Tests
    resp_diff = client.post(f"/api/reconstruct/diff/{project_id}")
    assert resp_diff.status_code == 200
    diff_payload = resp_diff.json()
    assert diff_payload["overall_conformance_score"] >= 0.80

    # 8. List Projects
    resp_list = client.get("/api/reconstruct/projects")
    assert resp_list.status_code == 200
    projects = resp_list.json()
    assert any(p["project_id"] == project_id for p in projects)

    # 9. Export Distribution Zip
    resp_export = client.get(f"/api/reconstruct/export/{project_id}")
    assert resp_export.status_code == 200
    assert resp_export.headers["content-type"] == "application/zip"
    assert len(resp_export.content) > 100


def test_knowledge_graph_minimal_report():
    """Verify KnowledgeGraphEngine handles minimal/empty analysis reports gracefully."""
    sample = SampleInfo(
        filename="minimal_elf",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        md5="d41d8cd98f00b204e9800998ecf8427e",
        sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
        file_size=128,
        file_type="ELF 64-bit LSB executable",
        architecture="x86-64",
        entropy=1.2,
    )
    report = AnalysisReport(
        report_id="rep-min-01",
        sample=sample,
        summary={},
        findings=[],
        tools_audited={},
        sections=[],
        imports=[],
        exports=[],
        functions=[],
        verdict="BENIGN",
        verdict_confidence=0.99,
    )

    kg_engine = KnowledgeGraphEngine()
    graph_data = kg_engine.build_graph(report)

    assert graph_data.node_count == 1
    assert graph_data.nodes[0].id == "app_root"
    assert "minimal_elf" in graph_data.nodes[0].label
    assert graph_data.entry_points == ["app_root"]

    mermaid_diag = kg_engine.to_mermaid(graph_data)
    assert "flowchart TD" in mermaid_diag
    assert "minimal_elf" in mermaid_diag


def test_reconstruction_planner_non_pe_format():
    """Verify ReconstructionPlanner handles non-PE targets (e.g. Android APK/DEX or ELF)."""
    sample = SampleInfo(
        filename="MobileApp.apk",
        sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        md5="1234567890abcdef1234567890abcdef",
        sha1="1234567890abcdef1234567890abcdef12345678",
        file_size=5242880,
        file_type="Android package (APK)",
        architecture="Dalvik/ART",
        entropy=7.4,
    )
    findings = [
        Finding(
            id="apk-f1",
            sample_sha256=sample.sha256,
            source_tool="jadx",
            finding_type=FindingType.DECOMPILED_CODE,
            name="MainActivity.java",
            description="Main activity decompiled source",
            confidence=0.95,
            verification_status=FindingStatus.CONFIRMED,
        )
    ]
    report = AnalysisReport(
        report_id="rep-apk-01",
        sample=sample,
        summary={},
        findings=findings,
        tools_audited={"jadx": True},
        sections=[],
        imports=[],
        exports=[],
        functions=[],
        verdict="LIKELY_BENIGN",
        verdict_confidence=0.90,
    )

    planner = ReconstructionPlanner()
    spec = planner.generate_specification(report, target_framework="python_fastapi")

    assert spec.sample_sha256 == sample.sha256
    assert "MobileApp" in spec.project_name
    assert len(spec.functional_requirements) > 0
    assert len(spec.sections) == 10


def test_build_agent_syntax_error_resilience():
    """Verify BuildAgent catches static syntax errors and reports failure accurately."""
    temp_dir = tempfile.mkdtemp(prefix="jarvis_err_proj_")
    bad_file = os.path.join(temp_dir, "broken_syntax.py")
    with open(bad_file, "w", encoding="utf-8") as f:
        f.write("def broken_func(:\n    return 42\n")

    proj = GeneratedProject(
        project_id="proj_bad_syntax",
        spec_id="spec_test",
        name="BrokenApp",
        target_framework="python_fastapi",
        workspace_dir=temp_dir,
        source_files={"broken_syntax.py": "def broken_func(:\n    return 42\n"},
        test_files={},
        config_files={},
        manifest_file="requirements.txt",
        documentation={},
        clean_room_verified=False,
    )

    agent = BuildAgent(timeout_sec=10)
    report = agent.build_and_validate(proj)

    assert report.compilation_passed is False
    assert report.status == "failed"
    assert any("Syntax error" in log or "ERROR" in log for log in report.build_logs)

    shutil.rmtree(temp_dir, ignore_errors=True)


def test_differential_tester_non_conforming_project():
    """Verify DifferentialTester identifies discrepancies when required behaviors are absent."""
    temp_dir = tempfile.mkdtemp(prefix="jarvis_nonconform_proj_")
    empty_file = os.path.join(temp_dir, "empty_dummy.py")
    with open(empty_file, "w", encoding="utf-8") as f:
        f.write("# Empty stub without expected behaviors\npass\n")

    proj = GeneratedProject(
        project_id="proj_nonconform",
        spec_id="spec_test",
        name="EmptyApp",
        target_framework="python_fastapi",
        workspace_dir=temp_dir,
        source_files={"empty_dummy.py": "pass"},
        test_files={},
        config_files={},
        manifest_file="requirements.txt",
        documentation={},
        clean_room_verified=False,
    )

    tester = DifferentialTester()
    result = tester.run_differential_test(proj, "reference_binary.exe")

    assert result.overall_conformance_score < 0.50
    assert len(result.discrepancies) > 0
    assert len(result.failed_acceptance_criteria) > 0

    shutil.rmtree(temp_dir, ignore_errors=True)


def test_software_project_generation_nodejs(mock_report):
    """Test clean-room generation, build, test, and packaging of a Node.js project."""
    kg_engine = KnowledgeGraphEngine()
    graph_data = kg_engine.build_graph(mock_report)
    planner = ReconstructionPlanner()
    spec = planner.generate_specification(mock_report, graph_data, target_framework="nodejs_typescript")

    generator = SoftwareGenerator()
    project = generator.generate_project(spec, target_framework="nodejs_typescript")

    assert project.target_framework == "nodejs_typescript"
    assert os.path.isdir(project.workspace_dir)

    # Check Node.js files
    expected_files = [
        "package.json",
        "README.md",
        "config.js",
        "models.js",
        "storage.js",
        "engine.js",
        "server.js",
        "tests/application.test.js",
    ]
    for rel_path in expected_files:
        full_path = os.path.join(project.workspace_dir, rel_path)
        assert os.path.isfile(full_path), f"Expected Node file {rel_path} was not created"

    # Build and test with BuildAgent
    build_agent = BuildAgent(timeout_sec=30)
    build_report = build_agent.build_and_validate(project)

    assert build_report.compilation_passed is True
    assert build_report.tests_passed > 0
    assert build_report.tests_failed == 0
    assert build_report.status == "success"
    assert build_report.packaged_artifact_path is not None
    assert os.path.isfile(build_report.packaged_artifact_path)

    # Check Differential Tester
    diff_tester = DifferentialTester()
    diff_res = diff_tester.run_differential_test(project, mock_report)
    assert diff_res.overall_conformance_score >= 0.80


def test_software_project_generation_go(mock_report):
    """Test clean-room generation, build, test, and packaging of a Go project."""
    kg_engine = KnowledgeGraphEngine()
    graph_data = kg_engine.build_graph(mock_report)
    planner = ReconstructionPlanner()
    spec = planner.generate_specification(mock_report, graph_data, target_framework="go")

    generator = SoftwareGenerator()
    project = generator.generate_project(spec, target_framework="go")

    assert project.target_framework == "go"
    assert os.path.isdir(project.workspace_dir)

    # Check Go files
    expected_files = [
        "go.mod",
        "README.md",
        "config.go",
        "models.go",
        "storage.go",
        "engine.go",
        "main.go",
        "main_test.go",
    ]
    for rel_path in expected_files:
        full_path = os.path.join(project.workspace_dir, rel_path)
        assert os.path.isfile(full_path), f"Expected Go file {rel_path} was not created"

    # Build and test with BuildAgent
    build_agent = BuildAgent(timeout_sec=45)
    build_report = build_agent.build_and_validate(project)

    assert build_report.compilation_passed is True
    assert build_report.tests_passed > 0
    assert build_report.tests_failed == 0
    assert build_report.status == "success"
    assert build_report.packaged_artifact_path is not None
    assert os.path.isfile(build_report.packaged_artifact_path)

    # Check Differential Tester
    diff_tester = DifferentialTester()
    diff_res = diff_tester.run_differential_test(project, mock_report)
    assert diff_res.overall_conformance_score >= 0.80
