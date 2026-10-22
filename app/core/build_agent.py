"""
JARVIS RE — Build and Validation Agent v1.0
Automates the build, static validation, test execution, bounded repair, and packaging lifecycle
for clean-room reconstructed projects in isolated workspaces.
"""

import logging
import os
import py_compile
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional
import uuid
import zipfile

from app.core.schema import BuildReport, GeneratedProject

logger = logging.getLogger("jarvis.re.build_agent")


class BuildAgent:
    """Orchestrates isolated compilation, test execution, and deployment packaging."""

    def __init__(self, timeout_sec: int = 60):
        self.timeout_sec = timeout_sec

    def build_and_validate(self, project: GeneratedProject) -> BuildReport:
        """Run compilation check, pytest suite, and packaging in project workspace."""
        build_id = f"bld_{uuid.uuid4().hex[:10]}"
        logs: List[str] = []
        workspace = project.workspace_dir

        logs.append(f"[{time.strftime('%H:%M:%S')}] Initializing build agent for project '{project.name}' in {workspace}")

        if not os.path.isdir(workspace):
            return BuildReport(
                build_id=build_id,
                project_id=project.project_id,
                status="failed",
                compilation_passed=False,
                build_logs=[f"Workspace directory not found: {workspace}"],
                limitations=["Workspace directory does not exist on disk."],
            )

        # ---------------------------------------------------------
        # 1. Static Syntax & Compilation Validation
        # ---------------------------------------------------------
        logs.append(f"[{time.strftime('%H:%M:%S')}] Stage 1: Running static syntax and compilation validation...")
        compilation_passed = True
        compilation_errors: List[str] = []

        for root, _, files in os.walk(workspace):
            for f in files:
                if f.endswith(".py"):
                    full_p = os.path.join(root, f)
                    try:
                        py_compile.compile(full_p, doraise=True)
                        logs.append(f"  Compiled successfully: {os.path.relpath(full_p, workspace)}")
                    except py_compile.PyCompileError as err:
                        compilation_passed = False
                        msg = f"Syntax error in {os.path.relpath(full_p, workspace)}: {err.msg}"
                        compilation_errors.append(msg)
                        logs.append(f"  [ERROR] {msg}")

        if not compilation_passed:
            logs.append(f"[{time.strftime('%H:%M:%S')}] Build failed at static compilation stage.")
            return BuildReport(
                build_id=build_id,
                project_id=project.project_id,
                status="failed",
                compilation_passed=False,
                test_output="\n".join(compilation_errors),
                build_logs=logs,
                limitations=["Static compilation check failed with syntax errors."],
            )

        # ---------------------------------------------------------
        # 2. Automated Test Execution
        # ---------------------------------------------------------
        logs.append(f"[{time.strftime('%H:%M:%S')}] Stage 2: Executing automated test suite via pytest...")
        test_output = ""
        tests_total = 0
        tests_passed = 0
        tests_failed = 0
        tests_success = False

        # Build python environment with project dir on PYTHONPATH
        env = os.environ.copy()
        current_pythonpath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{workspace};{current_pythonpath}"

        test_cmd = [sys.executable, "-m", "pytest", "tests", "-v", "--tb=short"]
        t0 = time.time()

        try:
            res = subprocess.run(
                test_cmd,
                cwd=workspace,
                capture_output=True,
                text=True,
                timeout=self.timeout_sec,
                env=env,
            )
            duration = round(time.time() - t0, 2)
            test_output = (res.stdout or "") + "\n" + (res.stderr or "")
            tests_success = res.returncode == 0
            logs.append(f"[{time.strftime('%H:%M:%S')}] pytest finished in {duration}s (exit code {res.returncode})")

            # Parse test counts from output
            for line in test_output.splitlines():
                if "collected " in line:
                    try:
                        tests_total = int(line.split("collected ")[1].split(" item")[0])
                    except Exception:
                        pass
                if " passed" in line or " failed" in line:
                    if " passed" in line:
                        try:
                            tests_passed = int(line.split(" passed")[0].split()[-1])
                        except Exception:
                            pass
                    if " failed" in line:
                        try:
                            tests_failed = int(line.split(" failed")[0].split()[-1])
                        except Exception:
                            pass

            if tests_success and tests_total == 0 and tests_passed > 0:
                tests_total = tests_passed

        except subprocess.TimeoutExpired:
            logs.append(f"[{time.strftime('%H:%M:%S')}] [ERROR] Test run timed out after {self.timeout_sec}s.")
            test_output = f"Execution timed out after {self.timeout_sec}s"
        except Exception as e:
            logs.append(f"[{time.strftime('%H:%M:%S')}] [ERROR] Subprocess error running tests: {e}")
            test_output = str(e)

        # ---------------------------------------------------------
        # 3. Packaging into Distributable Archive (.zip)
        # ---------------------------------------------------------
        packaged_zip: Optional[str] = None
        if compilation_passed and tests_success:
            logs.append(f"[{time.strftime('%H:%M:%S')}] Stage 3: Packaging clean distribution bundle...")
            zip_filename = f"{project.name}_v1.0.0.zip"
            packaged_zip = os.path.join(workspace, zip_filename)

            try:
                with zipfile.ZipFile(packaged_zip, "w", zipfile.ZIP_DEFLATED) as zf:
                    for root, _, files in os.walk(workspace):
                        for f in files:
                            if f == zip_filename or f.endswith((".pyc", ".pyo")):
                                continue
                            if "__pycache__" in root or ".pytest_cache" in root:
                                continue
                            fpath = os.path.join(root, f)
                            arcname = os.path.relpath(fpath, workspace)
                            zf.write(fpath, arcname)

                logs.append(f"[{time.strftime('%H:%M:%S')}] Distribution archive created at {packaged_zip} ({os.path.getsize(packaged_zip):,} bytes)")
            except Exception as zip_err:
                logs.append(f"[{time.strftime('%H:%M:%S')}] [WARNING] Packaging error: {zip_err}")

        # ---------------------------------------------------------
        # 4. Synthesize Final Report
        # ---------------------------------------------------------
        overall_status = "success" if compilation_passed and tests_success else "failed"
        limitations = []
        if not tests_success:
            limitations.append("Automated test suite reported failures; see test output logs.")
        if tests_total == 0:
            limitations.append("No automated test cases were collected.")
        if not packaged_zip:
            limitations.append("Packaging stage did not execute due to test or build failures.")

        logs.append(f"[{time.strftime('%H:%M:%S')}] Build lifecycle completed with status: {overall_status.upper()}")

        return BuildReport(
            build_id=build_id,
            project_id=project.project_id,
            status=overall_status,
            compilation_passed=compilation_passed,
            tests_total=tests_total,
            tests_passed=tests_passed,
            tests_failed=tests_failed,
            test_output=test_output,
            build_logs=logs,
            packaged_artifact_path=packaged_zip,
            repair_attempts=0,
            limitations=limitations,
        )
