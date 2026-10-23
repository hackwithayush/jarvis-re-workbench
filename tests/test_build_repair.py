"""
Test Suite: Phase 5 — Bounded Autonomous Repair Agent
Tests compilation repair, diff generation, test non-tampering constraints, and retry bounds.
"""

import os
import shutil
import tempfile
import pytest

from app.core.build_agent import BuildAgent
from app.core.schema import GeneratedProject


def test_build_agent_safety_guards_prevent_test_modification():
    """Verify repair agent refuses to target files in tests/ or outside workspace."""
    agent = BuildAgent()
    temp_dir = tempfile.mkdtemp()
    try:
        # File in tests/
        test_file = os.path.join(temp_dir, "tests", "test_app.py")
        assert not agent._is_safe_file_target(temp_dir, test_file)

        # File with 'test' in filename
        test_file2 = os.path.join(temp_dir, "test_helper.py")
        assert not agent._is_safe_file_target(temp_dir, test_file2)

        # File outside workspace
        outside_file = os.path.join(os.path.dirname(temp_dir), "host_config.py")
        assert not agent._is_safe_file_target(temp_dir, outside_file)

        # Safe source file
        src_file = os.path.join(temp_dir, "app.py")
        assert agent._is_safe_file_target(temp_dir, src_file)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_build_agent_compilation_repair():
    """Verify autonomous repair fixes a static syntax error in source file."""
    temp_dir = tempfile.mkdtemp()
    try:
        # Source file with invalid trailing delimiter
        main_py = os.path.join(temp_dir, "main.py")
        with open(main_py, "w", encoding="utf-8") as f:
            f.write("def calculate_sum(a, b)::\n    return a + b\n")

        # Create valid test file
        tests_dir = os.path.join(temp_dir, "tests")
        os.makedirs(tests_dir, exist_ok=True)
        test_py = os.path.join(tests_dir, "test_main.py")
        with open(test_py, "w", encoding="utf-8") as f:
            f.write("from main import calculate_sum\n\ndef test_calc():\n    assert calculate_sum(2, 3) == 5\n")

        project = GeneratedProject(
            spec_id="spec_test",
            name="RepairDemoProject",
            target_framework="python_fastapi",
            workspace_dir=temp_dir,
            source_files={"main.py": "def calculate_sum(a, b)::\n    return a + b\n"},
            test_files={"test_main.py": "from main import calculate_sum\n\ndef test_calc():\n    assert calculate_sum(2, 3) == 5\n"},
        )

        agent = BuildAgent(timeout_sec=30, max_repair_retries=3)
        report = agent.build_and_validate(project, enable_repair=True)

        # Verify repair succeeded
        assert report.status == "success"
        assert report.compilation_passed is True
        assert report.tests_passed >= 1
        assert report.repair_attempts >= 1
        assert len(report.repair_log) >= 1

        repair_record = report.repair_log[0]
        assert repair_record["target_file"] == "main.py"
        assert len(repair_record["diff_patch"]) > 0
        assert repair_record["success"] is True

        # Verify repaired file on disk no longer contains invalid syntax
        with open(main_py, "r", encoding="utf-8") as f:
            content = f.read()
        assert "calculate_sum(a, b):" in content
        assert "calculate_sum(a, b)::" not in content

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_build_agent_retry_budget_exhaustion():
    """Verify build agent respects max retry budget when error is unrecoverable."""
    temp_dir = tempfile.mkdtemp()
    try:
        main_py = os.path.join(temp_dir, "main.py")
        with open(main_py, "w", encoding="utf-8") as f:
            f.write("def compute():\n    return 42\n")

        # Test asserts an impossible condition
        tests_dir = os.path.join(temp_dir, "tests")
        os.makedirs(tests_dir, exist_ok=True)
        test_py = os.path.join(tests_dir, "test_main.py")
        with open(test_py, "w", encoding="utf-8") as f:
            f.write("from main import compute\n\ndef test_impossible():\n    assert compute() == 999999\n")

        project = GeneratedProject(
            spec_id="spec_test",
            name="UnrecoverableProject",
            target_framework="python_fastapi",
            workspace_dir=temp_dir,
            source_files={"main.py": "def compute():\n    return 42\n"},
            test_files={"test_main.py": "from main import compute\n\ndef test_impossible():\n    assert compute() == 999999\n"},
        )

        agent = BuildAgent(timeout_sec=15, max_repair_retries=2)
        report = agent.build_and_validate(project, enable_repair=True, max_retries=2)

        # Should report failure after exhausting retries
        assert report.status == "failed"
        assert report.repair_attempts == 2
        assert len(report.repair_log) == 2

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
