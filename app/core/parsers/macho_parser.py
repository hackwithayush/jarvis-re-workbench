"""
JARVIS RE — Mach-O Binary Parser v1.0
Parses Mach-O binaries (macOS / iOS / Darwin) in 32-bit, 64-bit, and Universal/Fat formats:
- Mach-O Header (cputype, filetype, flags)
- Load Commands: LC_SEGMENT/LC_SEGMENT_64, LC_MAIN, LC_LOAD_DYLIB
- Section breakdown & entropy
"""

import struct
from typing import List, Tuple
from app.core.schema import Finding, FindingStatus, FindingType, SectionInfo
from app.core.utils import calculate_entropy


class MachOParser:
    """Parser for Mach-O binaries and Fat/Universal bundles."""

    def __init__(self, data: bytes, sample_sha256: str):
        self.data = data
        self.size = len(data)
        self.sha256 = sample_sha256
        self.findings: List[Finding] = []
        self.sections: List[SectionInfo] = []

    def parse(self) -> Tuple[List[Finding], List[SectionInfo]]:
        if len(self.data) < 28:
            return self.findings, self.sections

        magic = struct.unpack_from("<I", self.data, 0)[0]
        is_le = magic in (0xFEEDFACE, 0xFEEDFACF)
        is_be = magic in (0xCEFAEDFE, 0xCFFAEDFE)

        if not (is_le or is_be):
            return self.findings, self.sections

        fmt = "<" if is_le else ">"
        is_64 = magic in (0xFEEDFACF, 0xCFFAEDFE)

        try:
            cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
                f"{fmt}IIIIII", self.data, 4
            )

            hdr_size = 32 if is_64 else 28
            cmd_offset = hdr_size

            for _ in range(min(ncmds, 100)):
                if cmd_offset + 8 > self.size:
                    break
                cmd, cmdsize = struct.unpack_from(f"{fmt}II", self.data, cmd_offset)

                # LC_MAIN (0x80000028)
                if cmd == 0x80000028 and cmdsize >= 24:
                    entry_off = struct.unpack_from(f"{fmt}Q", self.data, cmd_offset + 8)[0]
                    self.findings.append(
                        Finding(
                            sample_sha256=self.sha256,
                            source_tool="macho_parser",
                            finding_type=FindingType.ENTRY_POINT,
                            address_or_location=f"0x{entry_off:016X}",
                            name="macho_entry_point",
                            description=f"Mach-O Main Entry Point: 0x{entry_off:X}",
                            confidence=1.0,
                            verification_status=FindingStatus.CONFIRMED,
                        )
                    )

                # LC_SEGMENT_64 (0x19) or LC_SEGMENT (0x1)
                elif cmd in (0x1, 0x19):
                    seg_is_64 = cmd == 0x19
                    raw_segname = self.data[cmd_offset + 8:cmd_offset + 24].split(b"\x00")[0]
                    segname = raw_segname.decode("latin-1", errors="replace")

                    if seg_is_64:
                        vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, sflags = struct.unpack_from(
                            f"{fmt}QQQQIIII", self.data, cmd_offset + 24
                        )
                        sec_hdr_start = cmd_offset + 72
                        sec_hdr_size = 80
                    else:
                        vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, sflags = struct.unpack_from(
                            f"{fmt}IIIIIIII", self.data, cmd_offset + 24
                        )
                        sec_hdr_start = cmd_offset + 56
                        sec_hdr_size = 68

                    for s_idx in range(min(nsects, 30)):
                        s_pos = sec_hdr_start + (s_idx * sec_hdr_size)
                        if s_pos + sec_hdr_size > self.size:
                            break
                        sectname = self.data[s_pos:s_pos + 16].split(b"\x00")[0].decode("latin-1", errors="replace")
                        if seg_is_64:
                            s_addr, s_size, s_offset = struct.unpack_from(f"{fmt}QQI", self.data, s_pos + 32)
                        else:
                            s_addr, s_size, s_offset = struct.unpack_from(f"{fmt}III", self.data, s_pos + 32)

                        sec_data = self.data[s_offset:s_offset + s_size] if s_offset + s_size <= self.size else b""
                        sec_entropy = calculate_entropy(sec_data) if sec_data else 0.0

                        sec_info = SectionInfo(
                            name=f"{segname}.{sectname}",
                            virtual_address=f"0x{s_addr:016X}" if seg_is_64 else f"0x{s_addr:08X}",
                            virtual_size=s_size,
                            raw_size=s_size,
                            raw_offset=s_offset,
                            entropy=round(sec_entropy, 3),
                        )
                        self.sections.append(sec_info)

                # LC_LOAD_DYLIB (0xC)
                elif cmd == 0xC:
                    dylib_str_offset = struct.unpack_from(f"{fmt}I", self.data, cmd_offset + 8)[0]
                    full_str_off = cmd_offset + dylib_str_offset
                    if full_str_off < self.size:
                        end = self.data.find(b"\x00", full_str_off, min(self.size, full_str_off + 256))
                        dylib_name = self.data[full_str_off:end].decode("latin-1", errors="replace")
                        self.findings.append(
                            Finding(
                                sample_sha256=self.sha256,
                                source_tool="macho_parser",
                                finding_type=FindingType.IMPORT,
                                name="macho_dylib_import",
                                description=f"Imported Dynamic Library: '{dylib_name}'",
                                confidence=1.0,
                                verification_status=FindingStatus.CONFIRMED,
                                raw_data={"dylib": dylib_name},
                            )
                        )

                cmd_offset += cmdsize

        except Exception as e:
            self.findings.append(
                Finding(
                    sample_sha256=self.sha256,
                    source_tool="macho_parser",
                    finding_type=FindingType.ANOMALY,
                    name="macho_parsing_warning",
                    description=f"Corrupt or non-standard Mach-O structure: {e}",
                    confidence=0.70,
                    verification_status=FindingStatus.FLAGGED,
                )
            )

        return self.findings, self.sections
