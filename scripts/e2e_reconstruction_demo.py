"""
JARVIS RE Workbench — End-to-End Autonomous Software Reconstruction Demonstration
Performs a complete live verification across all 8 pipeline stages on a real Windows PE binary:
1. Analyze Binary Sample
2. Build Knowledge Graph & Mermaid Diagram
3. Synthesize Clean-Room 10-Section Specification
4. Analyst Architecture Approval
5. Generate Clean-Room Original Software Project
6. Build, Compile & Automated Test Battery
7. Differential Behavior Testing
8. Export Distribution ZIP Bundle
"""

import os
import sys

# Ensure UTF-8 output on Windows terminals
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient

from app.main import app, REPORTS_CACHE, SPECS_CACHE, PROJECTS_CACHE


def run_e2e_reconstruction():
    sample_path = r"C:\AI\jarvis-re-workbench\workspace\samples\service_daemon.exe"
    if not os.path.isfile(sample_path):
        print(f"Sample binary not found at {sample_path}")
        return False

    client = TestClient(app)
    print("=" * 70, flush=True)
    print("JARVIS RE WORKBENCH — FULL END-TO-END RECONSTRUCTION PIPELINE", flush=True)
    print("=" * 70, flush=True)
    print(f"Target Binary: {sample_path}", flush=True)
    print(f"Binary Size: {os.path.getsize(sample_path):,} bytes", flush=True)

    # -------------------------------------------------------------
    # Stage 1: Analyze Binary Sample
    # -------------------------------------------------------------
    print("\n[STAGE 1] Analyzing executable binary structures, entropy, strings, and APIs...", flush=True)
    with open(sample_path, "rb") as f:
        resp = client.post("/api/analyze", files={"file": ("service_daemon.exe", f, "application/octet-stream")})

    if resp.status_code != 200:
        print(f"Stage 1 failed: {resp.status_code} - {resp.text}", flush=True)
        return False

    report = resp.json()
    report_id = report["report_id"]
    sample_info = report["sample"]
    findings_count = len(report["findings"])
    print(f"  [PASS] Analysis Complete (Report ID: {report_id})", flush=True)
    print(f"  [PASS] Format: {sample_info['file_type']} | Arch: {sample_info['architecture']} | Entropy: {sample_info['entropy']}", flush=True)
    print(f"  [PASS] Total Evidence Findings: {findings_count}", flush=True)

    # -------------------------------------------------------------
    # Stage 2: Build Software Knowledge Graph
    # -------------------------------------------------------------
    print("\n[STAGE 2] Building persistent Software Knowledge Graph...", flush=True)
    resp_kg = client.post(f"/api/reconstruct/graph/{report_id}")
    if resp_kg.status_code != 200:
        print(f"Stage 2 failed: {resp_kg.text}", flush=True)
        return False

    kg_data = resp_kg.json()
    print(f"  [PASS] Graph Extracted: {kg_data['node_count']} nodes, {kg_data['edge_count']} edges", flush=True)
    print(f"  [PASS] Subsystems: {', '.join(kg_data['subsystems'])}", flush=True)
    print(f"  [PASS] Entry Points: {', '.join(kg_data['entry_points'])}", flush=True)

    resp_mermaid = client.get(f"/api/reconstruct/graph/{report_id}/mermaid")
    assert resp_mermaid.status_code == 200
    mermaid_lines = resp_mermaid.text.splitlines()
    print(f"  [PASS] Mermaid Diagram Generated ({len(mermaid_lines)} lines, starting '{mermaid_lines[0]}')", flush=True)

    # -------------------------------------------------------------
    # Test Generation across Multi-Language Frameworks: Python, Node.js, Go
    # -------------------------------------------------------------
    frameworks = ["python_fastapi", "nodejs_typescript", "go"]

    for fw in frameworks:
        print(f"\n" + "-" * 60, flush=True)
        print(f"EXERCISING PIPELINE FOR TARGET STACK: {fw.upper()}", flush=True)
        print("-" * 60, flush=True)

        # Stage 3: Generate Specification
        print(f"\n[STAGE 3 - {fw}] Synthesizing 10-Section Clean-Room Specification...", flush=True)
        resp_spec = client.post(f"/api/reconstruct/spec/{report_id}?target_framework={fw}")
        if resp_spec.status_code != 200:
            print(f"Specification generation failed for {fw}: {resp_spec.text}", flush=True)
            return False

        spec = resp_spec.json()
        spec_id = spec["spec_id"]
        print(f"  [PASS] Specification ID: {spec_id}", flush=True)
        print(f"  [PASS] Purpose: {spec['product_purpose'][:80]}...", flush=True)
        print(f"  [PASS] Requirements count: {len(spec['functional_requirements'])} functional, {len(spec['features_and_workflows'])} workflows", flush=True)

        # Stage 4: Analyst Approval Gate
        print(f"\n[STAGE 4 - {fw}] Analyst Architectural Review & Approval...", flush=True)
        resp_appr = client.post(f"/api/reconstruct/approve/{spec_id}")
        assert resp_appr.status_code == 200
        assert resp_appr.json()["approved"] is True
        print(f"  [PASS] Architecture approved for {fw} by analyst.", flush=True)

        # Stage 5: Clean-Room Code Generation
        print(f"\n[STAGE 5 - {fw}] Generating clean-room software project...", flush=True)
        resp_gen = client.post("/api/reconstruct/generate", json={"spec_id": spec_id, "target_framework": fw})
        if resp_gen.status_code != 200:
            print(f"Project generation failed for {fw}: {resp_gen.text}", flush=True)
            return False

        project = resp_gen.json()
        project_id = project["project_id"]
        print(f"  [PASS] Project Generated: {project['name']} (ID: {project_id})", flush=True)
        print(f"  [PASS] Workspace: {project['workspace_dir']}", flush=True)
        print(f"  [PASS] Source Modules: {list(project['source_files'].keys())}", flush=True)
        print(f"  [PASS] Test Modules: {list(project['test_files'].keys())}", flush=True)

        # Stage 6: Build, Compile & Automated Test Battery
        print(f"\n[STAGE 6 - {fw}] Build Agent compiling source & running test battery...", flush=True)
        resp_build = client.post(f"/api/reconstruct/build/{project_id}")
        if resp_build.status_code != 200:
            print(f"Build failed for {fw}: {resp_build.text}", flush=True)
            return False

        build_report = resp_build.json()
        print(f"  [PASS] Compilation Status: {'PASSED' if build_report['compilation_passed'] else 'FAILED'}", flush=True)
        print(f"  [PASS] Tests Total: {build_report['tests_total']} | Passed: {build_report['tests_passed']} | Failed: {build_report['tests_failed']}", flush=True)
        print(f"  [PASS] Build Status: {build_report['status'].upper()}", flush=True)
        print(f"  [PASS] Distribution Archive: {build_report['packaged_artifact_path']}", flush=True)

        if not build_report["compilation_passed"] or build_report["tests_failed"] > 0:
            print(f"  [ERROR] Tests failed for {fw}!\n{build_report['test_output']}", flush=True)
            return False

        # Stage 7: Differential Behavior Testing
        print(f"\n[STAGE 7 - {fw}] Executing Differential Behavioral Conformance Matrix...", flush=True)
        resp_diff = client.post(f"/api/reconstruct/diff/{project_id}")
        assert resp_diff.status_code == 200
        diff_res = resp_diff.json()
        print(f"  [PASS] Conformance Score: {int(diff_res['overall_conformance_score'] * 100)}%", flush=True)
        print(f"  [PASS] Matching Behaviors: {len(diff_res['matching_behaviors'])}", flush=True)
        for m in diff_res['matching_behaviors']:
            print(f"    - {m}", flush=True)

        # Stage 8: Export Distribution Archive
        print(f"\n[STAGE 8 - {fw}] Exporting Distributable ZIP...", flush=True)
        resp_export = client.get(f"/api/reconstruct/export/{project_id}")
        assert resp_export.status_code == 200
        assert resp_export.headers["content-type"] == "application/zip"
        zip_size = len(resp_export.content)
        print(f"  [PASS] Downloadable Distribution Archive Ready: {zip_size:,} bytes", flush=True)

    print("\n" + "=" * 70, flush=True)
    print("SUCCESS: ALL 8 RECONSTRUCTION STAGES VERIFIED ACROSS ALL 3 TARGET STACKS!", flush=True)
    print("=" * 70, flush=True)
    return True


if __name__ == "__main__":
    success = run_e2e_reconstruction()
    sys.exit(0 if success else 1)
