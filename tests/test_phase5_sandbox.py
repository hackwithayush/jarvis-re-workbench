"""
JARVIS RE — Phase 5 Controlled Dynamic Sandbox Test Suite
Automated regression tests covering:
1. Strict authorization gate (rejection when authorization is missing).
2. Isolated sandbox execution of safe binaries.
3. Timeout enforcement and telemetry capture.
4. Behavior labeling (OBSERVED vs NOT_OBSERVED).
"""

import os
import pytest

from app.core.sandbox import ControlledSandbox


def test_01_sandbox_authorization_gate():
    """Verify that execution is blocked without explicit analyst confirmation."""
    sandbox = ControlledSandbox()
    trace = sandbox.execute_sample("C:\\Windows\\notepad.exe", authorized=False)

    assert trace.executed is False
    assert trace.sandbox_mode == "none"
    assert any("NOT_OBSERVED" in obs for obs in trace.observations)


def test_02_sandbox_controlled_execution(tmp_path):
    """Verify execution of a benign script in isolated sandbox jail."""
    # Create safe Python script that prints and exits
    script = tmp_path / "safe_test.bat"
    script.write_text("@echo off\necho Sandbox containment verified\nexit 0\n")

    sandbox = ControlledSandbox(timeout=5)
    trace = sandbox.execute_sample(
        sample_path=str(script),
        authorized=True,
        analyst_confirmation_token="TEST_TOKEN_123",
    )

    assert trace.executed is True
    assert trace.exit_code == 0
    assert any("Sandbox containment verified" in obs for obs in trace.observations)
    assert any("OBSERVED" in obs for obs in trace.observations)
    assert any("NOT_OBSERVED" in obs for obs in trace.observations)


def test_03_sandbox_timeout_enforcement(tmp_path):
    """Verify that long-running samples are cleanly terminated at timeout."""
    script = tmp_path / "hang_test.bat"
    script.write_text("@echo off\npowershell -Command Start-Sleep -Seconds 10\n")

    sandbox = ControlledSandbox(timeout=1)
    trace = sandbox.execute_sample(
        sample_path=str(script),
        authorized=True,
        analyst_confirmation_token="TEST_TIMEOUT_TOKEN",
    )

    assert trace.executed is True
    assert any("timeout" in obs.lower() for obs in trace.observations)
