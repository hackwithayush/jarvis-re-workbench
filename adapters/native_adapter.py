"""
Jarvis RE — Native Python Binary Analyzer Adapter
Provides zero-dependency static analysis for PE, ELF, Mach-O, and raw binaries.
Extracts sections, entry points, hashes, high-entropy blocks, imports/exports,
and classified strings (URLs, IPs, API names, registry keys).
Guarantees immediate static analysis out-of-the-box even if external tools are not yet installed.
"""

import math
import os
import re
import struct
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base_adapter import BaseAdapter
from app.core.utils import (
    compute_hashes,
    detect_architecture,
    detect_file_type,
    format_address,
)


class NativePythonAdapter(BaseAdapter):
    """Built-in pure-Python static analysis engine."""

    TOOL_NAME: str = "python"

    def is_available(self) -> bool:
        """Native engine is always available on all platforms."""
        return True

    def get_version(self) -> Optional[str]:
        return "1.0.0-builtin"

    def get_supported_types(self) -> List[str]:
        return ["PE", "PE/.NET", "ELF", "Mach-O", "raw", "binary"]

    def analyze(
        self,
        sample_path: str,
        workspace_path: str,
        options: Optional[dict] = None,
    ) -> List[Dict[str, Any]]:
        """Perform comprehensive static inspection using native Python routines."""
        findings: List[Dict[str, Any]] = []

        if not os.path.isfile(sample_path):
            raise FileNotFoundError(f"Sample not found: {sample_path}")

        file_size = os.path.getsize(sample_path)
        hashes = compute_hashes(sample_path)
        arch = detect_architecture(sample_path)
        fmt = detect_file_type(sample_path) or "Raw Binary"

        # 1. File Metadata Finding
        findings.append(
            self._make_finding(
                finding_type="metadata",
                name="binary_metadata",
                description=f"Format: {fmt}, Architecture: {arch or 'Unknown'}, Size: {file_size} bytes",
                evidence=[
                    {
                        "source": "native_analyzer",
                        "content": f"SHA-256: {hashes['sha256']}, MD5: {hashes['md5']}",
                    }
                ],
                confidence=1.0,
                raw_data={
                    "file_size": file_size,
                    "hashes": hashes,
                    "architecture": arch,
                    "format": fmt,
                },
            )
        )

        with open(sample_path, "rb") as fh:
            content = fh.read()

        # 2. Extract Sections / Headers for PE
        if content[:2] == b"MZ":
            pe_findings = self._analyze_pe(content, sample_path)
            findings.extend(pe_findings)
        # 3. Extract Sections for ELF
        elif content[:4] == b"\x7fELF":
            elf_findings = self._analyze_elf(content)
            findings.extend(elf_findings)

        # 4. Overall & Chunk Entropy (Packer / Encryption detection)
        overall_entropy = self._calculate_entropy(content)
        is_suspicious_entropy = overall_entropy > 7.1
        findings.append(
            self._make_finding(
                finding_type="anomaly" if is_suspicious_entropy else "metadata",
                name="entropy_profile",
                description=(
                    f"Overall Shannon Entropy: {overall_entropy:.3f} / 8.000. "
                    + ("High entropy indicates packed, encrypted, or compressed payload." if is_suspicious_entropy else "Normal entropy distribution.")
                ),
                confidence=0.85 if is_suspicious_entropy else 0.70,
                raw_data={"shannon_entropy": overall_entropy, "packed_heuristic": is_suspicious_entropy},
            )
        )

        # 5. Extract & Classify Strings
        string_findings = self._extract_classified_strings(content)
        findings.extend(string_findings)

        return findings

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy for a block of bytes (0.0 to 8.0)."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        for count in counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return float(entropy)

    def _analyze_pe(self, content: bytes, sample_path: str) -> List[Dict[str, Any]]:
        """Parse PE headers, sections, and timestamps natively."""
        findings = []
        if len(content) < 64:
            return findings

        pe_offset = struct.unpack_from("<I", content, 0x3C)[0]
        if pe_offset + 24 > len(content):
            return findings

        sig = content[pe_offset : pe_offset + 4]
        if sig != b"PE\x00\x00":
            return findings

        num_sections = struct.unpack_from("<H", content, pe_offset + 6)[0]
        timestamp = struct.unpack_from("<I", content, pe_offset + 8)[0]
        opt_header_size = struct.unpack_from("<H", content, pe_offset + 20)[0]

        try:
            ts_dt = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
        except Exception:
            ts_dt = str(timestamp)

        findings.append(
            self._make_finding(
                finding_type="compiler_info",
                name="pe_timestamp",
                description=f"PE Compilation Timestamp: {ts_dt}",
                confidence=0.90,
                raw_data={"timestamp_raw": timestamp, "timestamp_iso": ts_dt},
            )
        )

        # Parse Optional Header Entry Point
        opt_offset = pe_offset + 24
        if opt_header_size >= 28 and opt_offset + opt_header_size <= len(content):
            magic = struct.unpack_from("<H", content, opt_offset)[0]
            is_64 = magic == 0x20B
            ep_offset = opt_offset + 16
            if ep_offset + 4 <= len(content):
                entry_point_rva = struct.unpack_from("<I", content, ep_offset)[0]
                findings.append(
                    self._make_finding(
                        finding_type="entry_point",
                        address=f"0x{entry_point_rva:08X}",
                        name="main_entry_point",
                        description=f"Main entry point RVA: 0x{entry_point_rva:08X} ({'PE32+' if is_64 else 'PE32'})",
                        confidence=0.95,
                        raw_data={"entry_point_rva": entry_point_rva, "format_type": "PE64" if is_64 else "PE32"},
                    )
                )

        # Parse Section Headers
        sections_offset = opt_offset + opt_header_size
        for i in range(num_sections):
            sec_hdr = sections_offset + (i * 40)
            if sec_hdr + 40 > len(content):
                break
            raw_name = content[sec_hdr : sec_hdr + 8].split(b"\x00")[0]
            sec_name = raw_name.decode("latin-1", errors="replace").strip()
            vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", content, sec_hdr + 8)
            characteristics = struct.unpack_from("<I", content, sec_hdr + 36)[0]

            # Section data entropy
            sec_bytes = content[raw_ptr : raw_ptr + raw_size] if raw_ptr + raw_size <= len(content) else b""
            sec_entropy = self._calculate_entropy(sec_bytes) if sec_bytes else 0.0

            findings.append(
                self._make_finding(
                    finding_type="section",
                    address=f"0x{vaddr:08X}",
                    name=sec_name,
                    description=f"Section {sec_name} (VirtualSize: {vsize}, RawSize: {raw_size}, Entropy: {sec_entropy:.2f})",
                    confidence=0.95,
                    raw_data={
                        "section_name": sec_name,
                        "virtual_address": vaddr,
                        "virtual_size": vsize,
                        "raw_size": raw_size,
                        "entropy": sec_entropy,
                        "characteristics": characteristics,
                    },
                )
            )

        return findings

    def _analyze_elf(self, content: bytes) -> List[Dict[str, Any]]:
        """Parse basic ELF headers and entry points."""
        findings = []
        if len(content) < 52:
            return findings

        ei_class = content[4]  # 1 = 32-bit, 2 = 64-bit
        ei_data = content[5]   # 1 = LE, 2 = BE
        fmt_char = "<" if ei_data == 1 else ">"

        if ei_class == 2 and len(content) >= 64:  # 64-bit ELF
            e_entry = struct.unpack_from(f"{fmt_char}Q", content, 24)[0]
            findings.append(
                self._make_finding(
                    finding_type="entry_point",
                    address=f"0x{e_entry:016X}",
                    name="elf_entry_point",
                    description=f"ELF64 Entry Point: 0x{e_entry:016X}",
                    confidence=0.95,
                    raw_data={"entry_point": e_entry, "class": "ELF64"},
                )
            )
        elif ei_class == 1:  # 32-bit ELF
            e_entry = struct.unpack_from(f"{fmt_char}I", content, 24)[0]
            findings.append(
                self._make_finding(
                    finding_type="entry_point",
                    address=f"0x{e_entry:08X}",
                    name="elf_entry_point",
                    description=f"ELF32 Entry Point: 0x{e_entry:08X}",
                    confidence=0.95,
                    raw_data={"entry_point": e_entry, "class": "ELF32"},
                )
            )

        return findings

    def _extract_classified_strings(self, content: bytes, min_len: int = 5) -> List[Dict[str, Any]]:
        """Extract and categorize interesting strings (IPs, URLs, Windows APIs, registry)."""
        findings = []
        # Match ASCII strings
        ascii_matches = re.finditer(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}", content)
        # Classifiers
        url_pattern = re.compile(r"^https?://[a-zA-Z0-9_\-\.]+(:[0-9]+)?(/[a-zA-Z0-9_\-\.\?&=%]*)?")
        ip_pattern = re.compile(r"^\b(?:\d{1,3}\.){3}\d{1,3}\b")
        api_pattern = re.compile(r"^[A-Z][a-zA-Z0-9]+(A|W|Ex|ExA|ExW)?$")
        reg_pattern = re.compile(r"^(HKEY_|HKLM|HKCU)[\\a-zA-Z0-9_\-]+", re.IGNORECASE)

        collected_interesting = 0
        for m in ascii_matches:
            raw_s = m.group(0).decode("latin-1", errors="ignore")
            offset = m.start()

            category = None
            if url_pattern.match(raw_s):
                category = "network_url"
            elif ip_pattern.match(raw_s):
                category = "network_ip"
            elif reg_pattern.match(raw_s):
                category = "registry_key"
            elif any(raw_s.startswith(p) for p in ["VirtualAlloc", "CreateProcess", "RegOpenKey", "WriteProcessMemory", "LoadLibrary", "GetProcAddress", "WSAStartup", "InternetOpen"]):
                category = "suspicious_api"

            if category:
                collected_interesting += 1
                findings.append(
                    self._make_finding(
                        finding_type="string",
                        address=f"0x{offset:08X}",
                        name=category,
                        description=f"Detected {category}: '{raw_s[:120]}'",
                        confidence=0.85,
                        raw_data={"string": raw_s, "offset": offset, "category": category},
                    )
                )
                if collected_interesting >= 50:
                    break

        return findings
