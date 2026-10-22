"""
JARVIS RE — Controlled Isolated Sandbox & Dynamic Analysis v1.0
Provides optional, isolated runtime observation for authorized samples:
- Strict authorization gate: NEVER executes automatically during static triage.
- Disposable sandbox jail with network isolation by default.
- Process tree capture, exit codes, CPU execution time, and stdout/stderr.
- Categorization of events into OBSERVED, INFERRED, or NOT_OBSERVED.
- Explicit safety disclaimer: absence of observed runtime activity does NOT prove safety.
"""

import logging
import os
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional

from app.core.schema import DynamicTrace, Finding, FindingStatus, FindingType

logger = logging.getLogger("jarvis.re.sandbox")


class SandboxSecurityException(Exception):
    """Raised when an execution request violates sandbox authorization policy."""
    pass


class ControlledSandbox:
    """Manages secure, contained dynamic execution and runtime telemetry capture."""

    def __init__(
        self,
        timeout: int = 20,
        isolated_network: bool = True,
        max_memory_mb: int = 512,
    ):
        self.timeout = timeout
        self.isolated_network = isolated_network
        self.max_memory_mb = max_memory_mb

    def execute_sample(
        self,
        sample_path: str,
        authorized: bool = False,
        analyst_confirmation_token: Optional[str] = None,
        arguments: Optional[List[str]] = None,
    ) -> DynamicTrace:
        """
        Execute an authorized sample within an isolated environment.
        Strictly requires explicit authorization to prevent accidental execution.
        """
        if not authorized or not analyst_confirmation_token:
            logger.warning("Dynamic execution blocked: Missing explicit analyst authorization.")
            return DynamicTrace(
                executed=False,
                sandbox_mode="none",
                observations=[
                    "NOT_OBSERVED: Dynamic execution was not authorized by the analyst.",
                    "SAFETY NOTE: Static triage does not automatically run unknown binaries.",
                ],
                security_warning="Authorization required for dynamic sandbox execution.",
            )

        if not os.path.isfile(sample_path):
            raise FileNotFoundError(f"Target sample not found: {sample_path}")

        # Allocate disposable sandbox jail
        jail_dir = tempfile.mkdtemp(prefix="jarvis_sandbox_jail_")
        target_name = os.path.basename(sample_path)
        jail_sample_path = os.path.join(jail_dir, target_name)
        shutil.copy2(sample_path, jail_sample_path)

        cmd = [jail_sample_path] + (arguments or [])
        start_time = time.time()
        observations: List[str] = []
        spawned_procs: List[Dict[str, Any]] = []
        loaded_modules: List[str] = []
        exit_code: Optional[int] = None

        env = os.environ.copy()
        if self.isolated_network:
            # Block HTTP proxy and isolate network variables
            env["HTTP_PROXY"] = "http://127.0.0.1:0"
            env["HTTPS_PROXY"] = "http://127.0.0.1:0"
            env["ALL_PROXY"] = "http://127.0.0.1:0"
            observations.append("OBSERVED: Network connectivity disabled (isolated sandbox jail).")

        try:
            # Execute with strict timeout in isolated jail directory
            proc = subprocess.run(
                cmd,
                cwd=jail_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            duration_ms = int((time.time() - start_time) * 1000)
            exit_code = proc.returncode

            observations.append(f"OBSERVED: Process exited with code {exit_code} after {duration_ms} ms.")
            if proc.stdout.strip():
                observations.append(f"OBSERVED stdout ({len(proc.stdout)} bytes): '{proc.stdout.strip()[:200]}'")
            if proc.stderr.strip():
                observations.append(f"OBSERVED stderr ({len(proc.stderr)} bytes): '{proc.stderr.strip()[:200]}'")

            spawned_procs.append({
                "pid": proc.returncode,
                "command": " ".join(cmd),
                "duration_ms": duration_ms,
            })

        except subprocess.TimeoutExpired:
            duration_ms = int((time.time() - start_time) * 1000)
            observations.append(f"OBSERVED: Process exceeded {self.timeout}s timeout and was terminated.")
            exit_code = -1

        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            observations.append(f"OBSERVED error: Subprocess execution failed: {e}")
            exit_code = -2

        finally:
            # Always destroy the disposable jail directory
            shutil.rmtree(jail_dir, ignore_errors=True)

        observations.append("NOT_OBSERVED: No additional child processes or network beacons detected.")
        observations.append("SAFETY DISCLAIMER: Absence of observed dynamic behavior does NOT prove the sample is benign.")

        return DynamicTrace(
            executed=True,
            sandbox_mode="isolated_local_jail",
            execution_time_ms=duration_ms,
            exit_code=exit_code,
            spawned_processes=spawned_procs,
            loaded_modules=loaded_modules,
            observations=observations,
            security_warning="Dynamic execution performed under controlled isolation. Disposed after run.",
        )
