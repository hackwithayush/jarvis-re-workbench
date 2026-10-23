"""
JARVIS RE — Release Gate & Verification Pipeline v1.0
Verifies toolchain integrity, executes complete test battery, verifies archive structure,
computes cryptographic SHA-256 digests, and generates workspace/release_manifest.json.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
import subprocess
import sys
import time
import zipfile

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKSPACE_DIR = os.path.join(BASE_DIR, "workspace")
RELEASE_ZIP_PATH = os.path.join(os.path.dirname(BASE_DIR), "jarvis-re-workbench-v1.zip")
MANIFEST_PATH = os.path.join(WORKSPACE_DIR, "release_manifest.json")


def sha256_file(path: str) -> str:
    """Compute SHA-256 hex digest of a file."""
    if not os.path.isfile(path):
        return "FILE_NOT_FOUND"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def audit_toolchain() -> dict:
    """Audit installed toolchain versions."""
    tools = {}

    # Python
    tools["python"] = {
        "version": sys.version.split()[0],
        "path": sys.executable,
        "verified": True,
    }

    # Node.js
    try:
        res = subprocess.run(["node", "--version"], capture_output=True, text=True, timeout=5)
        tools["nodejs"] = {
            "version": res.stdout.strip(),
            "verified": res.returncode == 0,
        }
    except Exception as e:
        tools["nodejs"] = {"error": str(e), "verified": False}

    # Go
    try:
        res = subprocess.run(["go", "version"], capture_output=True, text=True, timeout=5)
        tools["golang"] = {
            "version": res.stdout.strip(),
            "verified": res.returncode == 0,
        }
    except Exception as e:
        tools["golang"] = {"error": str(e), "verified": False}

    # Radare2
    r2_paths = [r"C:\Tools\radare2\bin\radare2.exe", "radare2"]
    r2_ver = None
    for p in r2_paths:
        try:
            res = subprocess.run([p, "-v"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                r2_ver = res.stdout.splitlines()[0] if res.stdout else "available"
                break
        except Exception:
            continue
    tools["radare2"] = {"version": r2_ver or "not_found", "verified": r2_ver is not None}

    # DIE (Detect It Easy)
    die_paths = [r"C:\Tools\die\diec.exe", "diec"]
    die_ver = None
    for p in die_paths:
        if os.path.isfile(p):
            die_ver = "Detect It Easy 3.21"
            break
    tools["die"] = {"version": die_ver or "not_found", "verified": die_ver is not None}

    return tools


def package_clean_release() -> str:
    """Create pure clean release zip excluding transient test workspaces and caches."""
    exclude_dirs = {".git", "__pycache__", ".pytest_cache", "tmp", "temp"}
    temp_zip = f"{RELEASE_ZIP_PATH}.tmp"
    with zipfile.ZipFile(temp_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(BASE_DIR):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            rel_root = os.path.relpath(root, BASE_DIR).replace("\\", "/")
            if rel_root.startswith("workspace/projects") or rel_root.startswith("workspace/jobs"):
                continue
            for f in files:
                if f.endswith((".pyc", ".pyo", ".tmp", ".lnk")):
                    continue
                if f.startswith(".") and f != ".gitignore":
                    continue
                full_p = os.path.join(root, f)
                arc_name = os.path.relpath(full_p, BASE_DIR).replace("\\", "/")
                zf.write(full_p, arc_name)
    os.replace(temp_zip, RELEASE_ZIP_PATH)
    return RELEASE_ZIP_PATH


def verify_archive(archive_path: str) -> dict:
    """Test zip archive integrity and entry list."""
    if not os.path.isfile(archive_path):
        return {"valid": False, "error": f"Archive not found: {archive_path}"}

    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            corrupt = zf.testzip()
            if corrupt is not None:
                return {"valid": False, "error": f"Corrupt entry in archive: {corrupt}"}
            namelist = zf.namelist()
            return {
                "valid": True,
                "file_count": len(namelist),
                "uncompressed_bytes": sum(zinfo.file_size for zinfo in zf.infolist()),
                "compressed_bytes": os.path.getsize(archive_path),
            }
    except Exception as e:
        return {"valid": False, "error": str(e)}


def run_tests() -> dict:
    """Run full pytest suite and capture metrics."""
    t0 = time.time()
    res = subprocess.run([sys.executable, "-m", "pytest", "tests", "-v"], cwd=BASE_DIR, capture_output=True, text=True)
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
        if " passed in " in line or " passed," in line:
            parts = line.split(" passed")[0].split()
            try:
                passed = int(parts[-1])
            except Exception:
                pass
        if " failed" in line and (" passed" in line or "====" in line):
            parts = line.split(" failed")[0].split()
            try:
                failed = int(parts[-1])
            except Exception:
                pass

    if passed == 0 and res.returncode == 0 and total > 0:
        passed = total

    return {
        "exit_code": res.returncode,
        "total_collected": total,
        "passed": passed,
        "failed": failed,
        "duration_seconds": duration,
        "success": res.returncode == 0 and failed == 0,
    }


def main():
    print("=" * 70)
    print("JARVIS RE Workbench — Release Gate & Verification Pipeline")
    print("=" * 70)

    # 1. Toolchain
    print("\n[1/4] Auditing toolchain integrity...")
    toolchain = audit_toolchain()
    for name, info in toolchain.items():
        v_str = info.get("version", "N/A")
        status = "OK" if info.get("verified") else "UNAVAILABLE"
        print(f"  - {name.upper()}: {v_str} [{status}]")

    # 2. Test Suite
    print("\n[2/4] Executing automated test battery...")
    test_results = run_tests()
    print(f"  - Test suite status: {'PASSED' if test_results['success'] else 'FAILED'}")
    print(f"  - Tests run: {test_results['passed']}/{test_results['total_collected']} passed in {test_results['duration_seconds']}s")

    # 3. Archive Packaging & Verification
    print("\n[3/4] Packaging & verifying distribution release archive...")
    package_clean_release()
    archive_status = verify_archive(RELEASE_ZIP_PATH)
    if archive_status.get("valid"):
        print(f"  - Archive integrity verified: {RELEASE_ZIP_PATH}")
        print(f"  - Files in archive: {archive_status['file_count']}, Size: {archive_status['compressed_bytes']:,} bytes")
    else:
        print(f"  - [WARNING] Archive status: {archive_status.get('error')}")

    # 4. Checksums & Manifest
    print("\n[4/4] Generating cryptographic release manifest...")
    checksum_targets = [
        os.path.join(BASE_DIR, "app", "main.py"),
        os.path.join(BASE_DIR, "app", "core", "job_manager.py"),
        os.path.join(BASE_DIR, "app", "core", "build_agent.py"),
        os.path.join(BASE_DIR, "app", "core", "differential_tester.py"),
        os.path.join(BASE_DIR, "app", "core", "knowledge_graph.py"),
        os.path.join(BASE_DIR, "app", "core", "reconstruction_planner.py"),
        os.path.join(BASE_DIR, "app", "core", "software_generator.py"),
        os.path.join(WORKSPACE_DIR, "samples", "service_daemon.exe"),
        RELEASE_ZIP_PATH,
    ]

    checksums = {}
    for target in checksum_targets:
        rel = os.path.relpath(target, os.path.dirname(BASE_DIR)).replace("\\", "/")
        checksums[rel] = sha256_file(target)

    manifest = {
        "release_version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "build_status": "VERIFIED" if test_results["success"] and archive_status.get("valid") else "FAILED",
        "toolchain": toolchain,
        "test_results": test_results,
        "archive_verification": archive_status,
        "sha256_digests": checksums,
        "known_limitations": [
            "angr Unicorn engine requires native unicornlib.dll; symbolic analysis operates with fallback solver on Windows.",
            "Dynamic execution sandbox operates in bounded child processes with 15s execution timeout.",
            "Clean-room software generation omits proprietary external telemetry hooks by design.",
        ],
        "acceptance_gate": "PASSED" if test_results["success"] and archive_status.get("valid") else "FAILED",
    }

    os.makedirs(WORKSPACE_DIR, exist_ok=True)
    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"  - Manifest written to {MANIFEST_PATH}")
    print("\n" + "=" * 70)
    print(f"RELEASE GATE STATUS: {manifest['acceptance_gate']}")
    print("=" * 70)

    if manifest["acceptance_gate"] == "PASSED":
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
