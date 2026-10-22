"""
JARVIS RE — Core Utilities v1.0
High-performance helpers for cryptographic hashing, format triage, architecture
detection, Shannon entropy calculation, address formatting, and workspace management.
"""

import hashlib
import json
import logging
import math
import os
import re
import struct
import tempfile
from typing import Any, Dict, List, Optional

logger = logging.getLogger("jarvis.re.utils")

_CHUNK_SIZE: int = 8 * 1024

_PE_MACHINES: Dict[int, str] = {
    0x014C: "x86 (32-bit)",
    0x8664: "x64 (AMD64 / Intel 64)",
    0x01C0: "ARM (Thumb)",
    0x01C4: "ARMv7 Thumb-2",
    0xAA64: "ARM64 (AArch64)",
    0x0200: "Intel Itanium (IA-64)",
}

_ELF_MACHINES: Dict[int, str] = {
    0x03: "x86 (32-bit)",
    0x3E: "x64 (AMD64)",
    0x28: "ARM (32-bit)",
    0xB7: "ARM64 (AArch64)",
    0x08: "MIPS",
    0x02: "SPARC",
    0x14: "PowerPC",
    0x15: "PowerPC64",
    0xF3: "RISC-V",
}

_MACHO_CPUTYPES: Dict[int, str] = {
    7: "x86 (32-bit)",
    0x01000007: "x64 (AMD64)",
    12: "ARM (32-bit)",
    0x0100000C: "ARM64 (AArch64)",
    18: "PowerPC",
    0x01000012: "PowerPC64",
}


def compute_hashes(file_path: str) -> Dict[str, str]:
    """Compute SHA-256, MD5, and SHA-1 digests using constant chunk memory."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Target binary not found: {file_path}")

    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()

    with open(file_path, "rb") as fh:
        while True:
            chunk = fh.read(_CHUNK_SIZE)
            if not chunk:
                break
            sha256.update(chunk)
            md5.update(chunk)
            sha1.update(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
    }


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (0.000 to 8.000) for a byte sequence."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return float(entropy)


def detect_file_type(file_path: str) -> str:
    """Detect binary container format from signature magic bytes."""
    try:
        with open(file_path, "rb") as fh:
            header = fh.read(4096)
    except Exception as e:
        logger.debug("Failed to read header from %s: %e", file_path, e)
        return "Unknown"

    if len(header) < 4:
        return "Raw Data (<4 bytes)"

    if header[:2] == b"MZ":
        if _is_dotnet_pe(header):
            return "PE (Portable Executable / .NET Assembly)"
        return "PE (Portable Executable)"

    if header[:4] == b"\x7fELF":
        return "ELF (Executable and Linkable Format)"

    magic32 = struct.unpack_from("<I", header, 0)[0]
    if magic32 in (0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE):
        return "Mach-O (macOS / iOS)"

    magic32_be = struct.unpack_from(">I", header, 0)[0]
    if magic32_be == 0xCAFEBABE:
        if len(header) >= 8:
            arch_count = struct.unpack_from(">I", header, 4)[0]
            if arch_count < 30:
                return "Mach-O (Fat / Universal Binary)"
            return "Java Class File"

    if header[:4] == b"dex\n":
        return "DEX (Android Dalvik Executable)"

    if header[:4] == b"PK\x03\x04":
        return "ZIP / APK / JAR Archive"

    if header[:3] == b"BZh":
        return "BZIP2 Archive"

    if header[:2] == b"\x1f\x8b":
        return "GZIP Archive"

    if len(header) >= 262 and header[257:262] == b"ustar":
        return "TAR Archive"

    return "Raw Binary"


def detect_architecture(file_path: str) -> str:
    """Detect CPU instruction set architecture from file header."""
    try:
        with open(file_path, "rb") as fh:
            header = fh.read(4096)
    except Exception:
        return "Unknown Architecture"

    if len(header) < 4:
        return "Unknown Architecture"

    if header[:2] == b"MZ":
        return _pe_architecture(header) or "Unknown PE Machine"

    if header[:4] == b"\x7fELF":
        return _elf_architecture(header) or "Unknown ELF Machine"

    magic32 = struct.unpack_from("<I", header, 0)[0]
    if magic32 in (0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE):
        return _macho_architecture(header, magic32) or "Unknown Mach-O CPU"

    return "Unknown Architecture"


def _pe_architecture(header: bytes) -> Optional[str]:
    if len(header) < 64:
        return None
    pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
    if pe_offset + 6 > len(header):
        return None
    sig = header[pe_offset:pe_offset + 4]
    if sig != b"PE\x00\x00":
        return None
    machine = struct.unpack_from("<H", header, pe_offset + 4)[0]
    return _PE_MACHINES.get(machine, f"Unknown PE Machine (0x{machine:04X})")


def _elf_architecture(header: bytes) -> Optional[str]:
    if len(header) < 20:
        return None
    ei_data = header[5]
    if ei_data == 1:
        e_machine = struct.unpack_from("<H", header, 18)[0]
    elif ei_data == 2:
        e_machine = struct.unpack_from(">H", header, 18)[0]
    else:
        return None
    return _ELF_MACHINES.get(e_machine, f"Unknown ELF Machine (0x{e_machine:04X})")


def _macho_architecture(header: bytes, magic: int) -> Optional[str]:
    fmt = "<I" if magic in (0xFEEDFACE, 0xFEEDFACF) else ">I"
    if len(header) < 8:
        return None
    cpu_type = struct.unpack_from(fmt, header, 4)[0]
    return _MACHO_CPUTYPES.get(cpu_type, f"Unknown Mach-O CPU (0x{cpu_type:08X})")


def _is_dotnet_pe(header: bytes) -> bool:
    try:
        pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
        if header[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return False
        opt_offset = pe_offset + 24
        magic = struct.unpack_from("<H", header, opt_offset)[0]
        is_64 = magic == 0x20B
        cli_data_dir_offset = opt_offset + (224 if not is_64 else 240) + (14 * 8)
        if cli_data_dir_offset + 8 <= len(header):
            clr_rva, clr_size = struct.unpack_from("<II", header, cli_data_dir_offset)
            return clr_rva > 0 and clr_size > 0
    except Exception:
        pass
    return False


def format_address(addr: int, bits: int = 32) -> str:
    """Format an integer address into a standardized hex string."""
    if bits == 64:
        return f"0x{addr:016X}"
    return f"0x{addr:08X}"


def validate_file_size(file_path: str, max_size_bytes: int = 500 * 1024 * 1024) -> bool:
    """Verify that file exists and does not exceed maximum allowable size."""
    if not os.path.isfile(file_path):
        return False
    return os.path.getsize(file_path) <= max_size_bytes


def create_workspace(sample_sha256: str, base_dir: Optional[str] = None) -> str:
    """Create an isolated workspace folder for temporary analysis artifacts."""
    if not base_dir:
        base_dir = os.path.join(tempfile.gettempdir(), "jarvis_re_workspace")
    workspace_dir = os.path.join(base_dir, sample_sha256[:16])
    os.makedirs(workspace_dir, exist_ok=True)
    return workspace_dir


def safe_json_serialize(obj: Any) -> str:
    """Safely serialize an object to JSON, handling bytes and unknown types."""
    def _default(o):
        if isinstance(o, bytes):
            return o.decode("latin-1", errors="replace")
        if hasattr(o, "isoformat"):
            return o.isoformat()
        if hasattr(o, "__dict__"):
            return o.__dict__
        return str(o)
    return json.dumps(obj, default=_default, indent=2)
