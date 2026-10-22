"""
Jarvis RE — Utility functions for binary analysis workflows.

These are pure helpers with no dependency on Flask or SQLAlchemy so they
can be used freely in subprocesses, CLI scripts, and tool adapters.
"""

import hashlib
import json
import logging
import os
import re
import struct
from datetime import datetime
from typing import Any, Dict, Optional

from REVERSE_ENGINEERING.config import MAX_FILE_SIZE, WORKSPACE_ROOT

logger = logging.getLogger("jarvis.re.utils")

# ---------------------------------------------------------------------------
# Chunk size used when reading files (8 KB)
# ---------------------------------------------------------------------------

_CHUNK_SIZE: int = 8 * 1024

# ---------------------------------------------------------------------------
# Architecture constants for header parsing
# ---------------------------------------------------------------------------

# PE IMAGE_FILE_HEADER Machine field values
_PE_MACHINES: Dict[int, str] = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "ARM",
    0x01C4: "ARM",        # ARMv7 Thumb-2
    0xAA64: "ARM64",
    0x0200: "IA64",
}

# ELF e_machine values (from elf.h)
_ELF_MACHINES: Dict[int, str] = {
    0x03: "x86",
    0x3E: "x64",
    0x28: "ARM",
    0xB7: "ARM64",
    0x08: "MIPS",
    0x02: "SPARC",
    0x14: "PowerPC",
    0x15: "PowerPC64",
    0xF3: "RISC-V",
}

# Mach-O CPU types (cputype field)
_MACHO_CPUTYPES: Dict[int, str] = {
    7:          "x86",
    0x01000007: "x64",       # CPU_TYPE_X86_64
    12:         "ARM",
    0x0100000C: "ARM64",     # CPU_TYPE_ARM64
    18:         "PowerPC",
    0x01000012: "PowerPC64",
}


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def compute_hashes(file_path: str) -> Dict[str, str]:
    """
    Compute SHA-256, MD5 and SHA-1 digests for the file at *file_path*.

    The file is read in 8 KB chunks to keep memory usage constant even for
    very large binaries.

    Returns:
        ``{"sha256": "...", "md5": "...", "sha1": "..."}``

    Raises:
        FileNotFoundError: If *file_path* does not exist.
        OSError: On I/O errors.
    """
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()

    logger.debug("Computing hashes for %s", file_path)

    with open(file_path, "rb") as fh:
        while True:
            chunk = fh.read(_CHUNK_SIZE)
            if not chunk:
                break
            sha256.update(chunk)
            md5.update(chunk)
            sha1.update(chunk)

    result = {
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
    }
    logger.debug("Hashes: %s", result)
    return result


# ---------------------------------------------------------------------------
# Architecture detection
# ---------------------------------------------------------------------------

def detect_architecture(file_path: str) -> Optional[str]:
    """
    Read the first bytes of *file_path* and return the CPU architecture
    string (``'x86'``, ``'x64'``, ``'ARM'``, ``'ARM64'``, ``'MIPS'``, …)
    or ``None`` if the format is unrecognised.

    Supports PE, ELF, and Mach-O headers.
    """
    try:
        with open(file_path, "rb") as fh:
            header = fh.read(4096)  # 4 KB is more than enough for any header

        if len(header) < 4:
            return None

        # ----- PE --------------------------------------------------------
        if header[:2] == b"MZ":
            return _pe_architecture(header)

        # ----- ELF -------------------------------------------------------
        if header[:4] == b"\x7fELF":
            return _elf_architecture(header)

        # ----- Mach-O ----------------------------------------------------
        magic32 = struct.unpack_from("<I", header, 0)[0]
        if magic32 in (0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE):
            return _macho_architecture(header, magic32)

        # Universal / Fat Mach-O (big-endian magic 0xCAFEBABE, but also Java!)
        magic32_be = struct.unpack_from(">I", header, 0)[0]
        if magic32_be == 0xCAFEBABE and len(header) >= 8:
            # Distinguish Java class from fat Mach-O: Java has a major version
            # at offset 6 that is usually > 40 whereas fat Mach-O has the arch
            # count at offset 4 which is typically small (< 10).
            arch_count = struct.unpack_from(">I", header, 4)[0]
            if arch_count < 30:
                # Likely fat Mach-O — extract first arch
                if len(header) >= 28:
                    cpu_type = struct.unpack_from(">I", header, 8)[0]
                    return _MACHO_CPUTYPES.get(cpu_type)

        return None
    except Exception:
        logger.debug("Architecture detection failed for %s", file_path, exc_info=True)
        return None


def _pe_architecture(header: bytes) -> Optional[str]:
    """Extract architecture from a PE header."""
    if len(header) < 64:
        return None
    pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
    # Validate PE signature position
    if pe_offset + 6 > len(header):
        return None
    sig = header[pe_offset : pe_offset + 4]
    if sig != b"PE\x00\x00":
        return None
    machine = struct.unpack_from("<H", header, pe_offset + 4)[0]
    return _PE_MACHINES.get(machine)


def _elf_architecture(header: bytes) -> Optional[str]:
    """Extract architecture from an ELF header."""
    if len(header) < 20:
        return None
    ei_data = header[5]  # 1 = little-endian, 2 = big-endian
    if ei_data == 1:
        e_machine = struct.unpack_from("<H", header, 18)[0]
    elif ei_data == 2:
        e_machine = struct.unpack_from(">H", header, 18)[0]
    else:
        return None
    return _ELF_MACHINES.get(e_machine)


def _macho_architecture(header: bytes, magic: int) -> Optional[str]:
    """Extract architecture from a Mach-O header."""
    # Determine byte order from the magic
    if magic in (0xFEEDFACE, 0xFEEDFACF):
        fmt = "<I"  # little-endian
    else:
        fmt = ">I"  # big-endian (0xCEFAEDFE / 0xCFFAEDFE)
    if len(header) < 8:
        return None
    cpu_type = struct.unpack_from(fmt, header, 4)[0]
    return _MACHO_CPUTYPES.get(cpu_type)


# ---------------------------------------------------------------------------
# File-type detection
# ---------------------------------------------------------------------------

def detect_file_type(file_path: str) -> Optional[str]:
    """
    Identify the binary format by reading magic bytes from *file_path*.

    Returns a human-readable string such as ``'PE'``, ``'ELF'``,
    ``'Mach-O'``, ``'DEX'``, ``'Java class'``, ``'ZIP/APK'``, etc.
    Returns ``None`` when the format is not recognised.
    """
    try:
        with open(file_path, "rb") as fh:
            header = fh.read(4096)

        if len(header) < 4:
            return None

        # ---- PE / DOS ----
        if header[:2] == b"MZ":
            # Check for .NET: presence of CLI header in the PE optional header
            if _is_dotnet_pe(header):
                return "PE/.NET"
            return "PE"

        # ---- ELF ----
        if header[:4] == b"\x7fELF":
            return "ELF"

        # ---- Mach-O ----
        magic32 = struct.unpack_from("<I", header, 0)[0]
        if magic32 in (0xFEEDFACE, 0xCEFAEDFE):
            return "Mach-O (32-bit)"
        if magic32 in (0xFEEDFACF, 0xCFFAEDFE):
            return "Mach-O (64-bit)"

        # ---- DEX ----
        if header[:4] == b"dex\n":
            return "DEX"

        # ---- Java class vs Fat Mach-O ----
        magic32_be = struct.unpack_from(">I", header, 0)[0]
        if magic32_be == 0xCAFEBABE:
            if len(header) >= 8:
                arch_count = struct.unpack_from(">I", header, 4)[0]
                if arch_count < 30:
                    return "Mach-O (Universal/Fat)"
            return "Java class"

        # ---- ZIP / APK / JAR ----
        if header[:2] == b"PK":
            # Attempt to distinguish APK from regular ZIP
            lower = os.path.splitext(file_path)[1].lower()
            if lower == ".apk":
                return "APK"
            if lower == ".jar":
                return "JAR"
            return "ZIP"

        # ---- RAR ----
        if header[:7] == b"Rar!\x1a\x07\x00" or header[:7] == b"Rar!\x1a\x07\x01":
            return "RAR"

        # ---- 7z ----
        if header[:6] == b"7z\xbc\xaf\x27\x1c":
            return "7z"

        # ---- PDF ----
        if header[:5] == b"%PDF-":
            return "PDF"

        # ---- Shebang scripts ----
        if header[:2] == b"#!":
            return "Script"

        return None
    except Exception:
        logger.debug("File-type detection failed for %s", file_path, exc_info=True)
        return None


def _is_dotnet_pe(header: bytes) -> bool:
    """
    Heuristic check for a .NET (managed) PE binary.

    A .NET assembly has a CLI header whose RVA is stored in the 15th
    data-directory entry (index 14, COM descriptor / CLR Runtime Header).
    """
    try:
        if len(header) < 0x80:
            return False
        pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
        if pe_offset + 24 > len(header):
            return False
        sig = header[pe_offset : pe_offset + 4]
        if sig != b"PE\x00\x00":
            return False

        # COFF header size = 20 bytes, starts right after PE\0\0
        # Optional header starts at pe_offset + 24
        optional_magic = struct.unpack_from("<H", header, pe_offset + 24)[0]
        if optional_magic == 0x10B:
            # PE32
            data_dir_offset = pe_offset + 24 + 96
        elif optional_magic == 0x20B:
            # PE32+
            data_dir_offset = pe_offset + 24 + 112
        else:
            return False

        # COM descriptor (CLR header) is index 14 → offset 14 * 8
        clr_rva_offset = data_dir_offset + 14 * 8
        if clr_rva_offset + 8 > len(header):
            return False

        clr_rva, clr_size = struct.unpack_from("<II", header, clr_rva_offset)
        return clr_rva != 0 and clr_size != 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Workspace management
# ---------------------------------------------------------------------------

def create_workspace(sample_sha256: str) -> str:
    """
    Create an isolated workspace directory for a sample.

    Layout::

        WORKSPACE_ROOT / {sha256[:8]} / {sha256} /

    Returns the absolute path to the created directory.
    """
    prefix = sample_sha256[:8]
    workspace = os.path.join(WORKSPACE_ROOT, prefix, sample_sha256)
    os.makedirs(workspace, exist_ok=True)
    logger.info("Workspace created: %s", workspace)
    return workspace


# ---------------------------------------------------------------------------
# Filename sanitisation
# ---------------------------------------------------------------------------

# Characters forbidden in Windows filenames
_UNSAFE_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def sanitize_filename(name: str) -> str:
    """
    Strip dangerous characters from *name* to produce a safe filename.

    * Removes ``<>:\"/\\|?*`` and control characters.
    * Collapses whitespace runs into a single underscore.
    * Truncates to 200 characters.
    * Falls back to ``'unnamed'`` if the result is empty.
    """
    cleaned = _UNSAFE_RE.sub("", name)
    cleaned = re.sub(r"\s+", "_", cleaned).strip("_. ")
    cleaned = cleaned[:200]
    if not cleaned:
        cleaned = "unnamed"
    return cleaned


# ---------------------------------------------------------------------------
# File-size validation
# ---------------------------------------------------------------------------

def validate_file_size(file_path: str, max_size: int = MAX_FILE_SIZE) -> bool:
    """
    Return ``True`` if *file_path* exists and does not exceed *max_size* bytes.
    """
    try:
        size = os.path.getsize(file_path)
        if size > max_size:
            logger.warning(
                "File %s is %d bytes, exceeds limit of %d bytes",
                file_path,
                size,
                max_size,
            )
            return False
        return True
    except OSError:
        logger.warning("Cannot stat file: %s", file_path, exc_info=True)
        return False


# ---------------------------------------------------------------------------
# Address formatting
# ---------------------------------------------------------------------------

def format_address(addr: int) -> str:
    """
    Format an integer address as a hex string.

    * Addresses fitting in 32 bits → ``'0x00000000'``
    * Addresses exceeding 32 bits → ``'0x0000000000000000'``
    """
    if addr <= 0xFFFFFFFF:
        return f"0x{addr:08X}"
    return f"0x{addr:016X}"


# ---------------------------------------------------------------------------
# JSON serialisation helpers
# ---------------------------------------------------------------------------

class _DateTimeEncoder(json.JSONEncoder):
    """JSON encoder that converts :class:`datetime` objects to ISO-8601."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def safe_json_serialize(obj: Any) -> str:
    """
    Serialize *obj* to a JSON string, handling :class:`datetime` objects
    and falling back to ``str()`` for unknown types.
    """
    try:
        return json.dumps(obj, cls=_DateTimeEncoder, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        logger.warning("JSON serialisation fell back to str() for %r", type(obj))
        return json.dumps(str(obj))
