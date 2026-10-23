"""
Test Suite: Phase 6 — Structured Differential Verification
Tests scenario comparison, linked requirements, comparison methods, and conformance scoring.
"""

from app.core.differential_tester import DifferentialTester
from app.core.schema import GeneratedProject


def test_differential_tester_scenarios_and_scoring():
    """Verify structured scenarios execution against a generated project."""
    project = GeneratedProject(
        spec_id="spec_diff_test",
        name="TelemetryDaemon",
        target_framework="python_fastapi",
        workspace_dir="/tmp/test_ws",
        source_files={
            "main.py": """
import os
from fastapi import FastAPI, HTTPException

app = FastAPI(title="TelemetryDaemon")

@app.get("/health")
def get_status():
    return {"status": "healthy", "version": "1.0.0", "uptime_seconds": 120}

@app.post("/execute")
def execute_operation(payload: dict):
    return {"id": "op_1", "status": "COMPLETED", "result": "processed"}

@app.get("/records/{item_id}")
def query_record(item_id: str):
    if item_id == "nonexistent_id":
        raise HTTPException(status_code=404, detail="Item not found")
    return {"id": item_id}

config_port = int(os.getenv("PORT", "8080"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=config_port)
"""
        },
        test_files={"test_app.py": "def test_noop(): pass"},
        config_files={"config.env": "PORT=8080"},
    )

    result = DifferentialTester.run_differential_test(
        project=project,
        reference_name="service_daemon.exe",
    )

    assert result.reference_sample == "service_daemon.exe"
    assert result.project_id == project.project_id
    assert len(result.scenarios) == 5

    # Check scenarios content
    scenario_ids = [s["scenario_id"] for s in result.scenarios]
    assert "SCEN-001" in scenario_ids
    assert "SCEN-002" in scenario_ids
    assert "SCEN-003" in scenario_ids
    assert "SCEN-004" in scenario_ids
    assert "SCEN-005" in scenario_ids

    for sc in result.scenarios:
        assert "linked_requirement" in sc
        assert "comparison_method" in sc
        assert "inputs" in sc
        assert sc["status"] in ("PASS", "FAIL", "BLOCKED")

    # All 5 scenarios should pass given the comprehensive source code
    assert result.overall_conformance_score >= 0.8
    assert result.status == "PASS"
    assert len(result.matching_behaviors) >= 4
    assert len(result.uncovered_workflows) >= 1


def test_differential_tester_detects_discrepancies():
    """Verify differential tester correctly flags missing endpoints and records discrepancies."""
    incomplete_project = GeneratedProject(
        spec_id="spec_diff_incomplete",
        name="EmptyService",
        target_framework="python_fastapi",
        workspace_dir="/tmp/empty_ws",
        source_files={"main.py": "# Bare minimal code\nprint('hello')\n"},
        test_files={},
        config_files={},
    )

    result = DifferentialTester.run_differential_test(
        project=incomplete_project,
        reference_name="service_daemon.exe",
    )

    assert result.overall_conformance_score < 0.5
    assert result.status == "FAIL"
    assert len(result.discrepancies) >= 3
    assert len(result.failed_acceptance_criteria) >= 3
