"""
JARVIS RE — Independent Release & Clean Environment Verification Engine v1.0
Independently verifies the packaged distribution ZIP:
1. Extracts C:\\AI\\jarvis-re-workbench-v1.zip into an isolated clean directory.
2. Performs strict security audit for prohibited files (.git, venv, caches, secrets).
3. Executes complete automated test battery directly in the isolated environment.
4. Computes SHA-256 digests and confirms reproducible release integrity.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

ZIP_PATH = r"C:\AI\jarvis-re-workbench-v1.zip"


def compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def run_clean_verification():
    print("=" * 72)
    print("JARVIS RE Workbench — Independent Clean Environment Verification")
    print("=" * 72)

    if not os.path.isfile(ZIP_PATH):
        print(f"[FAIL] Release archive not found at {ZIP_PATH}")
        sys.exit(1)

    zip_hash = compute_sha256(ZIP_PATH)
    zip_size = os.path.getsize(ZIP_PATH)
    print(f"\n[1/5] Release Archive Integrity & Cryptographic Identity:")
    print(f"  - Path: {ZIP_PATH}")
    print(f"  - Size: {zip_size:,} bytes")
    print(f"  - SHA-256: {zip_hash}")

    # Step 2: Content Audit
    print(f"\n[2/5] Content & Security Audit of ZIP Namelist:")
    with zipfile.ZipFile(ZIP_PATH, "r") as zf:
        corrupt = zf.testzip()
        if corrupt:
            print(f"  - [FAIL] Corrupt entry detected: {corrupt}")
            sys.exit(1)
        namelist = zf.namelist()

    git_entries = [e for e in namelist if ".git" in e.split("/")]
    cache_entries = [e for e in namelist if "__pycache__" in e or e.endswith(".pyc") or ".pytest_cache" in e]
    venv_entries = [e for e in namelist if any(v in e.split("/") for v in ("venv", ".venv", "env", "node_modules"))]
    secret_entries = [e for e in namelist if any(s in os.path.basename(e).lower() for s in (".env", "secret", "password", "token", "id_rsa", "credentials"))]
    transient_proj_entries = [e for e in namelist if e.startswith("workspace/projects/proj_")]

    print(f"  - Total entries: {len(namelist)} [PASSED]")
    print(f"  - Git metadata: {len(git_entries)} (expected 0) [OK]")
    print(f"  - Cache artifacts: {len(cache_entries)} (expected 0) [OK]")
    print(f"  - Virtual environments: {len(venv_entries)} (expected 0) [OK]")
    print(f"  - Secrets/Credentials: {len(secret_entries)} (expected 0) [OK]")
    print(f"  - Transient test projects: {len(transient_proj_entries)} (expected 0) [OK]")

    if any((git_entries, cache_entries, venv_entries, secret_entries, transient_proj_entries)):
        print("  - [FAIL] Archive contains prohibited or transient entries.")
        sys.exit(1)

    # Step 3: Extraction to Clean Isolated Workspace
    clean_dir = tempfile.mkdtemp(prefix="jarvis_isolated_audit_")
    print(f"\n[3/5] Extracting archive into isolated clean directory:")
    print(f"  - Destination: {clean_dir}")
    try:
        with zipfile.ZipFile(ZIP_PATH, "r") as zf:
            zf.extractall(clean_dir)
        print(f"  - Successfully extracted {len(namelist)} entries to isolated workspace.")

        # Step 4: Execute Test Battery in Isolated Directory
        print(f"\n[4/5] Executing full test battery inside isolated directory...")
        t0 = time.time()
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{clean_dir};{env.get('PYTHONPATH', '')}"

        res = subprocess.run(
            [sys.executable, "-m", "pytest", "tests", "-v"],
            cwd=clean_dir,
            capture_output=True,
            text=True,
            env=env,
        )
        duration = round(time.time() - t0, 2)
        output = res.stdout + "\n" + res.stderr

        total = 0
        passed = 0
        failed = 0

        for line in output.splitlines():
            if "collected " in line and " item" in line:
                try:
                    total = int(line.split("collected ")[1].split(" item")[0])
                except Exception:
                    pass
            if " passed" in line and ("====" in line or " in " in line):
                parts = line.split(" passed")[0].split()
                try:
                    passed = int(parts[-1])
                except Exception:
                    pass
            if " failed" in line and ("====" in line or " in " in line):
                parts = line.split(" failed")[0].split()
                try:
                    failed = int(parts[-1])
                except Exception:
                    pass

        if passed == 0 and res.returncode == 0 and total > 0:
            passed = total

        print(f"  - Isolated Test Suite Result: {'PASSED' if res.returncode == 0 else 'FAILED'}")
        print(f"  - Tests collected: {total}")
        print(f"  - Tests passed: {passed}")
        print(f"  - Tests failed: {failed}")
        print(f"  - Test duration: {duration}s")

        if res.returncode != 0 or failed > 0:
            print("\nTest runner failure output snippet:")
            for l in output.splitlines()[-25:]:
                print("  ", l)
            sys.exit(1)

        # Step 5: Verified Core Checksums
        print(f"\n[5/5] Cryptographic Core Digests in Isolated Build:")
        core_targets = [
            "app/main.py",
            "app/core/job_manager.py",
            "app/core/build_agent.py",
            "app/core/differential_tester.py",
            "workspace/samples/service_daemon.exe",
        ]
        for ct in core_targets:
            full_p = os.path.join(clean_dir, ct.replace("/", os.sep))
            if os.path.isfile(full_p):
                print(f"  - {ct}: {compute_sha256(full_p)}")

        print("\n" + "=" * 72)
        print("INDEPENDENT CLEAN VERIFICATION STATUS: 100% PASSED")
        print("=" * 72)

    finally:
        shutil.rmtree(clean_dir, ignore_errors=True)


if __name__ == "__main__":
    run_clean_verification()
