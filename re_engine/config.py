"""
Jarvis RE — Configuration and tool auto-discovery.

Auto-detects installed reverse-engineering tools on Windows, defines
execution timeouts / memory limits, and maps file formats to recommended
tool chains.
"""

import glob
import importlib
import logging
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger("jarvis.re.config")

# ---------------------------------------------------------------------------
# Path constants
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKSPACE_ROOT = os.path.join(BASE_DIR, "REVERSE_ENGINEERING", "workspace")

# ---------------------------------------------------------------------------
# Execution limits
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT: int = 300          # seconds
MAX_FILE_SIZE: int = 500 * 1024 * 1024   # 500 MB

# ---------------------------------------------------------------------------
# Format → tool routing
# ---------------------------------------------------------------------------

SUPPORTED_FORMATS: Dict[str, Dict[str, Any]] = {
    "pe_native": {
        "extensions": [".exe", ".dll", ".sys", ".drv", ".ocx", ".scr"],
        "magic": b"MZ",
        "recommended_tools": ["die", "ghidra", "radare2", "x64dbg"],
        "description": "Windows PE native binary",
    },
    "pe_dotnet": {
        "extensions": [".exe", ".dll"],
        "magic": b"MZ",
        "recommended_tools": ["die", "dnspy", "ghidra"],
        "description": "Windows .NET managed binary",
    },
    "elf": {
        "extensions": [".so", ".o", ".elf", ""],
        "magic": b"\x7fELF",
        "recommended_tools": ["ghidra", "radare2"],
        "description": "Linux ELF binary",
    },
    "macho": {
        "extensions": [".dylib", ".bundle", ""],
        "magic": None,  # multiple magic values — checked at runtime
        "recommended_tools": ["ghidra", "radare2"],
        "description": "macOS Mach-O binary",
    },
    "dex": {
        "extensions": [".dex"],
        "magic": b"dex\n",
        "recommended_tools": ["ghidra", "radare2"],
        "description": "Android Dalvik Executable",
    },
    "java_class": {
        "extensions": [".class"],
        "magic": b"\xca\xfe\xba\xbe",
        "recommended_tools": ["ghidra"],
        "description": "Java class file",
    },
    "apk": {
        "extensions": [".apk"],
        "magic": b"PK",
        "recommended_tools": ["ghidra", "radare2"],
        "description": "Android APK archive",
    },
    "raw_binary": {
        "extensions": [".bin", ".rom", ".fw", ".img"],
        "magic": None,
        "recommended_tools": ["ghidra", "radare2", "imhex"],
        "description": "Raw / firmware binary blob",
    },
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _glob_first(*patterns: str) -> Optional[str]:
    """Return the first matching path from one or more glob patterns."""
    for pattern in patterns:
        matches = sorted(glob.glob(pattern))
        if matches:
            return matches[-1]   # prefer the newest / highest-versioned dir
    return None


def _find_on_path(executable: str) -> Optional[str]:
    """Return absolute path if *executable* exists on ``%PATH%``."""
    return shutil.which(executable)


def _probe_version(exe_path: str, args: List[str], timeout: int = 10) -> Optional[str]:
    """
    Run ``exe_path *args`` and return the first non-empty stdout line.

    Returns ``None`` on any error.
    """
    try:
        result = subprocess.run(
            [exe_path, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped:
                return stripped
        # Fall back to stderr (some tools print version info there)
        for line in result.stderr.splitlines():
            stripped = line.strip()
            if stripped:
                return stripped
    except Exception:
        pass
    return None


def _is_package_importable(package_name: str) -> bool:
    """Check whether a Python package can be imported without side-effects."""
    try:
        spec = importlib.util.find_spec(package_name)
        return spec is not None
    except (ModuleNotFoundError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Individual tool discovery
# ---------------------------------------------------------------------------

def _find_ghidra() -> Dict[str, Any]:
    """Locate a Ghidra installation and its ``analyzeHeadless`` script."""
    info: Dict[str, Any] = {"available": False, "path": None, "version": None}

    # 1. Environment variable
    ghidra_home = os.environ.get("GHIDRA_HOME")
    if ghidra_home and os.path.isdir(ghidra_home):
        info["path"] = ghidra_home
    else:
        # 2. Common installation globs
        candidate = _glob_first(
            r"C:\ghidra*",
            r"C:\Program Files\ghidra*",
            r"C:\Tools\ghidra*",
        )
        if candidate:
            info["path"] = candidate

    if info["path"]:
        # Look for analyzeHeadless launcher
        headless = os.path.join(info["path"], "support", "analyzeHeadless.bat")
        if os.path.isfile(headless):
            info["available"] = True
            # Try to extract version from the directory name or application.properties
            props = os.path.join(info["path"], "Ghidra", "application.properties")
            if os.path.isfile(props):
                try:
                    with open(props, "r", encoding="utf-8") as fh:
                        for line in fh:
                            if line.startswith("application.version="):
                                info["version"] = line.split("=", 1)[1].strip()
                                break
                except OSError:
                    pass

    logger.debug("Ghidra discovery: %s", info)
    return info


def _find_die() -> Dict[str, Any]:
    """Locate Detect It Easy (DIE) command-line interface."""
    info: Dict[str, Any] = {"available": False, "path": None, "version": None}

    # Check PATH first
    for exe in ("diec.exe", "die.exe"):
        found = _find_on_path(exe)
        if found:
            info["path"] = found
            break

    if not info["path"]:
        candidate = _glob_first(
            r"C:\Program Files\Detect It Easy*",
            r"C:\Tools\die*",
            r"C:\Tools\Detect*",
        )
        if candidate:
            for exe in ("diec.exe", "die.exe"):
                exe_path = os.path.join(candidate, exe)
                if os.path.isfile(exe_path):
                    info["path"] = exe_path
                    break

    if info["path"] and os.path.isfile(info["path"]):
        info["available"] = True
        ver = _probe_version(info["path"], ["--version"])
        if ver:
            info["version"] = ver

    logger.debug("DIE discovery: %s", info)
    return info


def _find_radare2() -> Dict[str, Any]:
    """Locate radare2."""
    info: Dict[str, Any] = {"available": False, "path": None, "version": None}

    for exe in ("radare2.exe", "r2.exe"):
        found = _find_on_path(exe)
        if found:
            info["path"] = found
            break

    if not info["path"]:
        candidate = _glob_first(r"C:\Tools\radare2*")
        if candidate:
            for exe in ("radare2.exe", "r2.exe"):
                exe_path = os.path.join(candidate, exe)
                if os.path.isfile(exe_path):
                    info["path"] = exe_path
                    break

    if info["path"] and os.path.isfile(info["path"]):
        info["available"] = True
        ver = _probe_version(info["path"], ["-v"])
        if ver:
            info["version"] = ver

    logger.debug("radare2 discovery: %s", info)
    return info


def _find_imhex() -> Dict[str, Any]:
    """Locate ImHex hex editor."""
    info: Dict[str, Any] = {"available": False, "path": None, "version": None}

    found = _find_on_path("imhex.exe")
    if found:
        info["path"] = found
    else:
        candidate = _glob_first(r"C:\Program Files\ImHex*")
        if candidate:
            exe_path = os.path.join(candidate, "imhex.exe")
            if os.path.isfile(exe_path):
                info["path"] = exe_path

    if info["path"] and os.path.isfile(info["path"]):
        info["available"] = True
        ver = _probe_version(info["path"], ["--version"])
        if ver:
            info["version"] = ver

    logger.debug("ImHex discovery: %s", info)
    return info


def _find_dnspy() -> Dict[str, Any]:
    """Locate dnSpyEx."""
    info: Dict[str, Any] = {"available": False, "path": None, "version": None}

    found = _find_on_path("dnSpy.exe")
    if found:
        info["path"] = found
    else:
        candidate = _glob_first(
            r"C:\Tools\dnSpy*",
            r"C:\dnSpy*",
        )
        if candidate:
            exe_path = os.path.join(candidate, "dnSpy.exe")
            if os.path.isfile(exe_path):
                info["path"] = exe_path

    if info["path"] and os.path.isfile(info["path"]):
        info["available"] = True
        # dnSpy does not have a simple --version CLI flag; version is embedded in path or about dialog
        info["version"] = None

    logger.debug("dnSpy discovery: %s", info)
    return info


def _find_x64dbg() -> Dict[str, Any]:
    """Locate x64dbg."""
    info: Dict[str, Any] = {"available": False, "path": None, "version": None}

    found = _find_on_path("x64dbg.exe")
    if found:
        info["path"] = found
    else:
        candidate = _glob_first(
            r"C:\Program Files\x64dbg*",
            r"C:\Tools\x64dbg*",
        )
        if candidate:
            exe_path = os.path.join(candidate, "release", "x96dbg.exe")
            if os.path.isfile(exe_path):
                info["path"] = exe_path
            else:
                exe_path = os.path.join(candidate, "x64dbg.exe")
                if os.path.isfile(exe_path):
                    info["path"] = exe_path

    if info["path"] and os.path.isfile(info["path"]):
        info["available"] = True

    logger.debug("x64dbg discovery: %s", info)
    return info


def _find_frida() -> Dict[str, Any]:
    """Check whether the ``frida`` Python package is importable."""
    info: Dict[str, Any] = {"available": False, "path": None, "version": None}
    if _is_package_importable("frida"):
        info["available"] = True
        info["path"] = "python-package"
        try:
            import frida  # type: ignore[import-untyped]
            info["version"] = frida.__version__
        except Exception:
            pass
    logger.debug("Frida discovery: %s", info)
    return info


def _find_angr() -> Dict[str, Any]:
    """Check whether the ``angr`` Python package is importable."""
    info: Dict[str, Any] = {"available": False, "path": None, "version": None}
    if _is_package_importable("angr"):
        info["available"] = True
        info["path"] = "python-package"
        try:
            import angr  # type: ignore[import-untyped]
            info["version"] = angr.__version__
        except Exception:
            pass
    logger.debug("angr discovery: %s", info)
    return info


def _find_java() -> Dict[str, Any]:
    """Locate a JRE/JDK (needed for Ghidra headless analysis)."""
    info: Dict[str, Any] = {"available": False, "path": None, "version": None}

    found = _find_on_path("java.exe")
    if found:
        info["path"] = found
        info["available"] = True
        ver = _probe_version(found, ["-version"])
        if ver:
            info["version"] = ver

    logger.debug("Java discovery: %s", info)
    return info


# ---------------------------------------------------------------------------
# REConfig — public configuration façade
# ---------------------------------------------------------------------------

class REConfig:
    """
    Central configuration singleton for the Reverse Engineering module.

    All paths, limits, and tool availability are accessible through class
    attributes and classmethods so that no instantiation is required.
    """

    BASE_DIR: str = BASE_DIR
    WORKSPACE_ROOT: str = WORKSPACE_ROOT
    DEFAULT_TIMEOUT: int = DEFAULT_TIMEOUT
    MAX_FILE_SIZE: int = MAX_FILE_SIZE
    SUPPORTED_FORMATS: Dict[str, Dict[str, Any]] = SUPPORTED_FORMATS

    # Discovery functions keyed by canonical tool name
    _TOOL_DISCOVERERS: Dict[str, Any] = {
        "ghidra": _find_ghidra,
        "die": _find_die,
        "radare2": _find_radare2,
        "imhex": _find_imhex,
        "dnspy": _find_dnspy,
        "x64dbg": _find_x64dbg,
        "frida": _find_frida,
        "angr": _find_angr,
        "java": _find_java,
    }

    # Cached result — populated lazily
    _tool_cache: Optional[Dict[str, Dict[str, Any]]] = None

    @classmethod
    def get_tool_status(cls, *, refresh: bool = False) -> Dict[str, Dict[str, Any]]:
        """
        Return a dict mapping tool names to their availability info.

        Each value is ``{"available": bool, "path": str | None, "version": str | None}``.

        Results are cached across calls unless *refresh* is ``True``.
        """
        if cls._tool_cache is not None and not refresh:
            return dict(cls._tool_cache)

        status: Dict[str, Dict[str, Any]] = {}
        for name, discover_fn in cls._TOOL_DISCOVERERS.items():
            try:
                status[name] = discover_fn()
            except Exception:
                logger.exception("Error discovering tool '%s'", name)
                status[name] = {"available": False, "path": None, "version": None}

        cls._tool_cache = status
        logger.info(
            "Tool discovery complete — available: %s",
            [t for t, v in status.items() if v["available"]],
        )
        return dict(status)

    @classmethod
    def ensure_workspace(cls) -> str:
        """Create the workspace root directory if it does not exist and return its path."""
        os.makedirs(cls.WORKSPACE_ROOT, exist_ok=True)
        return cls.WORKSPACE_ROOT

    @classmethod
    def get_tool_path(cls, tool_name: str) -> Optional[str]:
        """
        Convenience accessor: return the resolved path for *tool_name*,
        or ``None`` if the tool is not available.
        """
        status = cls.get_tool_status()
        entry = status.get(tool_name)
        if entry and entry["available"]:
            return entry["path"]
        return None

    @classmethod
    def is_tool_available(cls, tool_name: str) -> bool:
        """Return ``True`` when *tool_name* was found during discovery."""
        status = cls.get_tool_status()
        entry = status.get(tool_name)
        return bool(entry and entry["available"])
