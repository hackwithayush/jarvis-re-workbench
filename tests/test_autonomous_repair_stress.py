"""
Test Suite: Stress-Testing Autonomous Bounded Repair Agent
Validates:
1. Repair of legitimate syntax defects while keeping acceptance tests immutable.
2. Repair of contract/KeyError defects with surgical diff tracking.
3. Strict defense preventing test file tampering or acceptance criteria weakening.
4. Strict enforcement of maximum retry budget (3 attempts) on unresolvable defects.
5. Path traversal defense preventing writes outside project workspace.
"""

import hashlib
import os
import shutil
import tempfile
import pytest

from app.core.build_agent import BuildAgent
from app.core.schema import GeneratedProject


def _file_hash(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def test_repair_syntax_defect_preserves_acceptance_tests():
    """Verify autonomous repair fixes a real syntax error without altering acceptance tests."""
    temp_dir = tempfile.mkdtemp(prefix="stress_repair_syntax_")
    try:
        # Reconstructed source with legitimate syntax defect (extra colon)
        src_file = os.path.join(temp_dir, "calculator.py")
        with open(src_file, "w", encoding="utf-8") as f:
            f.write("def add_numbers(x, y)::\n    return x + y\n")

        # Acceptance test
        tests_dir = os.path.join(temp_dir, "tests")
        os.makedirs(tests_dir, exist_ok=True)
        test_file = os.path.join(tests_dir, "test_calculator.py")
        test_content = "from calculator import add_numbers\n\ndef test_add():\n    assert add_numbers(10, 20) == 30\n"
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(test_content)

        test_hash_before = _file_hash(test_file)

        proj = GeneratedProject(
            spec_id="spec_stress_1",
            name="CalculatorProject",
            target_framework="python_fastapi",
            workspace_dir=temp_dir,
            source_files={"calculator.py": "def add_numbers(x, y)::\n    return x + y\n"},
            test_files={"test_calculator.py": test_content},
        )

        agent = BuildAgent(timeout_sec=20, max_repair_retries=3)
        report = agent.build_and_validate(proj, enable_repair=True)

        # 1. Build and test must succeed after repair
        assert report.status == "success"
        assert report.compilation_passed is True
        assert report.tests_passed == 1
        assert report.repair_attempts >= 1
        assert len(report.repair_log) >= 1

        # 2. Acceptance test file must NOT have been modified (immutable criteria)
        test_hash_after = _file_hash(test_file)
        assert test_hash_before == test_hash_after

        # 3. Diff must be captured
        repair_record = report.repair_log[0]
        assert repair_record["target_file"] == "calculator.py"
        assert len(repair_record["diff_patch"]) > 0
        assert repair_record["success"] is True

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_repair_contract_defect_key_error():
    """Verify autonomous repair resolves missing contract fields in response dictionary."""
    temp_dir = tempfile.mkdtemp(prefix="stress_repair_contract_")
    try:
        # Reconstructed service returning dictionary missing 'status'
        src_file = os.path.join(temp_dir, "service.py")
        with open(src_file, "w", encoding="utf-8") as f:
            f.write("def get_telemetry():\n    return {'healthy': True}\n")

        # Test asserts presence of 'status'
        tests_dir = os.path.join(temp_dir, "tests")
        os.makedirs(tests_dir, exist_ok=True)
        test_file = os.path.join(tests_dir, "test_service.py")
        test_content = "from service import get_telemetry\n\ndef test_contract():\n    data = get_telemetry()\n    assert 'status' in data\n"
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(test_content)

        test_hash_before = _file_hash(test_file)

        proj = GeneratedProject(
            spec_id="spec_stress_2",
            name="ContractService",
            target_framework="python_fastapi",
            workspace_dir=temp_dir,
            source_files={"service.py": "def get_telemetry():\n    return {'healthy': True}\n"},
            test_files={"test_service.py": test_content},
        )

        agent = BuildAgent(timeout_sec=20, max_repair_retries=3)
        report = agent.build_and_validate(proj, enable_repair=True)

        assert report.status == "success"
        assert report.tests_passed == 1
        assert report.repair_attempts >= 1
        assert _file_hash(test_file) == test_hash_before

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_repair_strictly_rejects_test_weakening_attempts():
    """Verify safety guard strictly rejects targeting test files even if error log points to them."""
    agent = BuildAgent()
    temp_dir = tempfile.mkdtemp(prefix="stress_repair_guard_")
    try:
        tests_dir = os.path.join(temp_dir, "tests")
        os.makedirs(tests_dir, exist_ok=True)

        forbidden_targets = [
            os.path.join(tests_dir, "test_app.py"),
            os.path.join(tests_dir, "test_security.py"),
            os.path.join(tests_dir, "acceptance_suite.py"),
            os.path.join(temp_dir, "test_helper.py"),
            os.path.join(temp_dir, "tests.py"),
        ]

        for target in forbidden_targets:
            assert not agent._is_safe_file_target(temp_dir, target)

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_repair_bounded_retry_budget_enforcement():
    """Verify repair terminates cleanly after exactly max_retries without infinite loop or crash."""
    temp_dir = tempfile.mkdtemp(prefix="stress_repair_budget_")
    try:
        src_file = os.path.join(temp_dir, "core.py")
        with open(src_file, "w", encoding="utf-8") as f:
            f.write("def value():\n    return 1\n")

        # Test with impossible assertion
        tests_dir = os.path.join(temp_dir, "tests")
        os.makedirs(tests_dir, exist_ok=True)
        test_file = os.path.join(tests_dir, "test_core.py")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("from core import value\n\ndef test_impossible():\n    assert value() == 999999999\n")

        proj = GeneratedProject(
            spec_id="spec_stress_budget",
            name="UnresolvableProject",
            target_framework="python_fastapi",
            workspace_dir=temp_dir,
            source_files={"core.py": "def value():\n    return 1\n"},
            test_files={"test_core.py": "from core import value\n\ndef test_impossible():\n    assert value() == 999999999\n"},
        )

        agent = BuildAgent(timeout_sec=15, max_repair_retries=3)
        report = agent.build_and_validate(proj, enable_repair=True, max_retries=3)

        assert report.status == "failed"
        assert report.repair_attempts == 3
        assert len(report.repair_log) == 3
        for idx, attempt in enumerate(report.repair_log, 1):
            assert attempt["attempt"] == idx
            assert attempt["success"] is False

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_repair_directory_traversal_prevention():
    """Verify safety guard rejects modifying files outside workspace via path traversal."""
    agent = BuildAgent()
    temp_dir = tempfile.mkdtemp(prefix="stress_traversal_")
    try:
        outside_targets = [
            os.path.join(temp_dir, "..", "outside_config.py"),
            os.path.join(temp_dir, "..", "..", "system.ini"),
            r"C:\Windows\System32\drivers\etc\hosts",
            r"C:\AI\jarvis-re-workbench\app\main.py",
        ]
        for target in outside_targets:
            assert not agent._is_safe_file_target(temp_dir, target)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
