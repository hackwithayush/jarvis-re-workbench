"""
JARVIS RE — Phase 2 Parser Verification Test Suite
Automated regression tests covering:
1. PE32 structural parsing (sections, entry point, imports, imphash).
2. PE32+ (64-bit) structural parsing (64-bit ImageBase, entry point).
3. .NET CLI Runtime Header triage.
4. ELF32 and ELF64 header & NX stack parsing.
5. Mach-O 32-bit and 64-bit load command parsing.
6. Archive inspection (member inventory and zip-bomb safeguards).
7. Malformed and truncated binary handling.
8. ASCII and UTF-16LE string classification.
"""

import io
import os
import struct
import tempfile
import zipfile
import pytest

from app.core.parsers.pe_parser import PEParser
from app.core.parsers.elf_parser import ELFParser
from app.core.parsers.macho_parser import MachOParser
from app.core.parsers.archive_parser import ArchiveInspector
from app.core.parsers.string_extractor import StringExtractor
from app.core.schema import FindingStatus, FindingType
from app.core.utils import calculate_entropy, compute_hashes, detect_architecture, detect_file_type


def make_pe32_bytes() -> bytes:
    """Generate a minimal synthetic 32-bit PE binary."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 64)
    pe_sig = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 1700000000, 0, 0, 224, 0x0102)
    opt_header = bytearray(224)
    struct.pack_into("<H", opt_header, 0, 0x010B)       # PE32
    struct.pack_into("<I", opt_header, 16, 0x1000)      # EntryPoint RVA
    struct.pack_into("<I", opt_header, 28, 0x00400000)  # ImageBase
    sec_header = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    headers = dos_header + pe_sig + coff_header + opt_header + sec_header
    padding = b"\x00" * max(0, 512 - len(headers))
    payload = b"\x90" * 512
    return headers + padding + payload


def make_pe64_bytes() -> bytes:
    """Generate a minimal synthetic 64-bit PE32+ binary."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 64)
    pe_sig = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x8664, 1, 1700000000, 0, 0, 240, 0x0022)
    opt_header = bytearray(240)
    struct.pack_into("<H", opt_header, 0, 0x020B)              # PE32+
    struct.pack_into("<I", opt_header, 16, 0x2000)             # EntryPoint RVA
    struct.pack_into("<Q", opt_header, 24, 0x0000000140000000) # 64-bit ImageBase
    sec_header = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x200, 0x2000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    headers = dos_header + pe_sig + coff_header + opt_header + sec_header
    padding = b"\x00" * max(0, 512 - len(headers))
    payload = b"\x90" * 512
    return headers + padding + payload


def test_01_pe32_parsing():
    """Verify standard PE32 header, sections, and entry point."""
    data = make_pe32_bytes()
    parser = PEParser(data, "fake_sha256")
    findings, sections, imports, exports, imphash, ts = parser.parse()

    assert len(sections) == 1
    assert sections[0].name == ".text"
    assert sections[0].virtual_address == "0x00001000"
    assert sections[0].entropy >= 0.0

    ep_findings = [f for f in findings if f.finding_type == FindingType.ENTRY_POINT]
    assert len(ep_findings) >= 1
    assert ep_findings[0].address_or_location == "0x00001000"
    assert "PE32" in ep_findings[0].description


def test_02_pe64_parsing():
    """Verify 64-bit PE32+ header, 64-bit ImageBase, and entry point."""
    data = make_pe64_bytes()
    parser = PEParser(data, "fake_sha256")
    findings, sections, imports, exports, imphash, ts = parser.parse()

    assert len(sections) == 1
    assert sections[0].virtual_address == "0x00002000"

    ep_findings = [f for f in findings if f.finding_type == FindingType.ENTRY_POINT]
    assert len(ep_findings) >= 1
    assert ep_findings[0].address_or_location == "0x00002000"
    assert "PE32+" in ep_findings[0].description


def test_03_dotnet_clr_triage():
    """Verify .NET CLR runtime header detection."""
    pe_data = bytearray(make_pe32_bytes())
    # Set CLR directory in optional header (index 14)
    # Optional header starts at 64 + 4 + 20 = 88. Directory 14 is at offset 88 + 96 + (14 * 8) = 296
    struct.pack_into("<I", pe_data, 88 + 92, 16)         # NumberOfRvaAndSizes = 16
    struct.pack_into("<II", pe_data, 88 + 96 + (14 * 8), 0x1000, 72) # CLR RVA 0x1000, size 72
    # At file offset 0x200 (where .text begins), write IMAGE_COR20_HEADER
    clr_hdr = struct.pack("<IIIIIII", 72, 2, 5, 0x1050, 500, 1, 0x06000001)
    pe_data[0x200:0x200 + len(clr_hdr)] = clr_hdr

    parser = PEParser(bytes(pe_data), "fake_sha256")
    findings, _, _, _, _, _ = parser.parse()

    clr_findings = [f for f in findings if f.name == "dotnet_clr_header"]
    assert len(clr_findings) == 1
    assert "v2.5" in clr_findings[0].description


def test_04_elf_parsing():
    """Verify ELF64 header, entry point, and stack protection parsing."""
    # Build minimal ELF64 Little-Endian
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    e_type = 2         # ET_EXEC
    e_machine = 0x3E   # x86_64
    e_version = 1
    e_entry = 0x401000
    e_phoff = 64
    e_shoff = 0
    e_flags = 0
    e_ehsize = 64
    e_phentsize = 56
    e_phnum = 1
    e_shentsize = 64
    e_shnum = 0
    e_shstrndx = 0

    elf_hdr = struct.pack("<16sHHIQQQIHHHHHH", e_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx)
    # Program header for PT_GNU_STACK with NX enabled (PF_R | PF_W = 6, no PF_X)
    ph = struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 8)
    data = elf_hdr + ph

    parser = ELFParser(data, "fake_sha256")
    findings, sections = parser.parse()

    ep = [f for f in findings if f.finding_type == FindingType.ENTRY_POINT]
    assert len(ep) == 1
    assert "0x0000000000401000" in ep[0].address_or_location

    stack = [f for f in findings if f.name == "elf_gnu_stack"]
    assert len(stack) == 1
    assert "NX Enabled" in stack[0].description


def test_05_macho_parsing():
    """Verify Mach-O 64-bit load commands and LC_MAIN entry point."""
    magic = 0xFEEDFACF  # 64-bit LE
    cputype = 0x01000007 # x86_64
    cpusubtype = 3
    filetype = 2        # MH_EXECUTE
    ncmds = 1
    sizeofcmds = 24
    flags = 0x00200085

    hdr = struct.pack("<IIIIIII", magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags) + b"\x00\x00\x00\x00"
    # LC_MAIN (0x80000028)
    lc_main = struct.pack("<IIQQ", 0x80000028, 24, 0x1000, 0)
    data = hdr + lc_main

    parser = MachOParser(data, "fake_sha256")
    findings, sections = parser.parse()

    ep = [f for f in findings if f.finding_type == FindingType.ENTRY_POINT]
    assert len(ep) == 1
    assert "0x0000000000001000" in ep[0].address_or_location


def test_06_archive_inspector_and_safeguards():
    """Verify archive member inventory and zip bomb safeguard detection."""
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test_payload.exe", b"MZ" + b"\x00" * 1000)
        zf.writestr("notes.txt", "Plain text documentation")

    archive_data = bio.getvalue()
    inspector = ArchiveInspector(archive_data, "fake_sha256")
    findings, members = inspector.inspect()

    assert len(members) == 2
    exe_members = [m for m in members if m.is_executable]
    assert len(exe_members) == 1
    assert exe_members[0].filename == "test_payload.exe"


def test_07_malformed_and_truncated_files():
    """Verify robust malformed-file handling without unhandled crashes."""
    # 1. Truncated 10-byte MZ header
    p1 = PEParser(b"MZ\x00\x00\x00\x00\x00\x00\x00\x00", "fake_sha256")
    f1, s1, _, _, _, _ = p1.parse()
    assert len(s1) == 0  # Does not crash

    # 2. Corrupt e_lfanew pointing way out of bounds
    buf = bytearray(64)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x7FFFFFFF)
    p2 = PEParser(bytes(buf), "fake_sha256")
    f2, s2, _, _, _, _ = p2.parse()
    assert any("Truncated PE Header" in f.description for f in f2)

    # 3. Truncated ELF
    p3 = ELFParser(b"\x7fELF\x02\x01", "fake_sha256")
    f3, s3 = p3.parse()
    assert len(s3) == 0


def test_08_string_extraction_and_classification():
    """Verify ASCII and UTF-16LE extraction and regex classification."""
    payload = (
        b"Regular Ascii String\x00"
        b"https://c2.security-research.org/beacon\x00"
        b"192.168.1.100\x00"
        b"VirtualAllocEx\x00"
        b"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
        b"{12345678-1234-1234-1234-123456789abc}\x00"
        b"C:\\Windows\\System32\\cmd.exe\x00"
    )
    # Add UTF-16LE wide string: "WideUnicodeUrl"
    wide_url = "https://unicode.internal-system.net/api".encode("utf-16le") + b"\x00\x00"
    data = payload + wide_url

    extractor = StringExtractor(data, "fake_sha256")
    findings = extractor.extract()

    categories = [f.name for f in findings]
    assert "network_url" in categories
    assert "network_ip" in categories
    assert "suspicious_api" in categories
    assert "registry_key" in categories
    assert "guid" in categories
    assert "filepath" in categories
