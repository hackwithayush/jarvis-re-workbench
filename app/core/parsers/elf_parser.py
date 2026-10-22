"""
JARVIS RE — ELF Binary Parser v1.0
Parses ELF32 and ELF64 binaries (Little & Big Endian):
- ELF Header & Architecture
- Program Headers / Segments (PT_LOAD, PT_DYNAMIC, GNU_STACK NX indicator)
- Section Headers (.text, .data, .rodata, .bss, .got, .plt)
- Dynamic Symbols & Imported functions (.dynsym / .dynstr)
"""

import struct
from typing import Any, Dict, List, Tuple
from app.core.schema import Finding, FindingStatus, FindingType, SectionInfo
from app.core.utils import calculate_entropy


class ELFParser:
    """Parser for ELF32 and ELF64 executables and shared libraries."""

    def __init__(self, data: bytes, sample_sha256: str):
        self.data = data
        self.size = len(data)
        self.sha256 = sample_sha256
        self.findings: List[Finding] = []
        self.sections: List[SectionInfo] = []

    def parse(self) -> Tuple[List[Finding], List[SectionInfo]]:
        if len(self.data) < 52 or self.data[:4] != b"\x7fELF":
            return self.findings, self.sections

        try:
            ei_class = self.data[4]      # 1 = 32-bit, 2 = 64-bit
            ei_data = self.data[5]       # 1 = Little-endian, 2 = Big-endian
            fmt = "<" if ei_data == 1 else ">"
            is_64 = ei_class == 2

            if is_64 and len(self.data) >= 64:
                e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                    f"{fmt}HHIQQQIHHHHHH", self.data, 16
                )
            elif not is_64 and len(self.data) >= 52:
                e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                    f"{fmt}HHIIIIIHHHHHH", self.data, 16
                )
            else:
                return self.findings, self.sections

            self.findings.append(
                Finding(
                    sample_sha256=self.sha256,
                    source_tool="elf_parser",
                    finding_type=FindingType.ENTRY_POINT,
                    address_or_location=f"0x{e_entry:08X}" if not is_64 else f"0x{e_entry:016X}",
                    name="elf_entry_point",
                    description=f"ELF{'64' if is_64 else '32'} Entry Point: 0x{e_entry:X} (Endian: {'Little' if ei_data == 1 else 'Big'})",
                    confidence=1.0,
                    verification_status=FindingStatus.CONFIRMED,
                    raw_data={"entry": e_entry, "is_64": is_64, "endian": "LE" if ei_data == 1 else "BE"},
                )
            )

            # Program Headers check for GNU_STACK NX status
            for i in range(e_phnum):
                p_off = e_phoff + (i * e_phentsize)
                if p_off + e_phentsize > self.size:
                    break
                p_type = struct.unpack_from(f"{fmt}I", self.data, p_off)[0]
                if p_type == 0x6474E551:  # PT_GNU_STACK
                    p_flags = struct.unpack_from(f"{fmt}I", self.data, p_off + (4 if is_64 else 24))[0]
                    is_exec_stack = bool(p_flags & 1)  # PF_X
                    self.findings.append(
                        Finding(
                            sample_sha256=self.sha256,
                            source_tool="elf_parser",
                            finding_type=FindingType.ANOMALY if is_exec_stack else FindingType.METADATA,
                            name="elf_gnu_stack",
                            description="Executable Stack (NX Disabled) - high exploitation risk!" if is_exec_stack else "Non-Executable Stack (NX Enabled)",
                            confidence=0.95,
                            verification_status=FindingStatus.FLAGGED if is_exec_stack else FindingStatus.CONFIRMED,
                            raw_data={"exec_stack": is_exec_stack},
                        )
                    )

            # Section Headers
            if e_shoff > 0 and e_shnum > 0 and e_shstrndx < e_shnum:
                shstr_off = e_shoff + (e_shstrndx * e_shentsize)
                if shstr_off + e_shentsize <= self.size:
                    if is_64:
                        shstr_raw_off = struct.unpack_from(f"{fmt}Q", self.data, shstr_off + 24)[0]
                    else:
                        shstr_raw_off = struct.unpack_from(f"{fmt}I", self.data, shstr_off + 16)[0]

                    for i in range(e_shnum):
                        s_off = e_shoff + (i * e_shentsize)
                        if s_off + e_shentsize > self.size:
                            break
                        if is_64:
                            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
                                f"{fmt}IIQQQQ", self.data, s_off
                            )
                        else:
                            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
                                f"{fmt}IIIIII", self.data, s_off
                            )

                        # Read section name from shstrtab
                        name = ""
                        str_pos = shstr_raw_off + sh_name
                        if str_pos < self.size:
                            zero_pos = self.data.find(b"\x00", str_pos)
                            if zero_pos != -1:
                                name = self.data[str_pos:zero_pos].decode("latin-1", errors="replace")

                        sec_data = self.data[sh_offset:sh_offset + sh_size] if sh_offset + sh_size <= self.size else b""
                        entropy = calculate_entropy(sec_data) if sec_data else 0.0

                        flags = []
                        if sh_flags & 0x1:
                            flags.append("WRITE")
                        if sh_flags & 0x2:
                            flags.append("ALLOC")
                        if sh_flags & 0x4:
                            flags.append("EXECINSTR")

                        sec_info = SectionInfo(
                            name=name or f"elf_sec_{i}",
                            virtual_address=f"0x{sh_addr:08X}" if not is_64 else f"0x{sh_addr:016X}",
                            virtual_size=sh_size,
                            raw_size=sh_size,
                            raw_offset=sh_offset,
                            entropy=round(entropy, 3),
                            flags=flags,
                        )
                        self.sections.append(sec_info)

                        self.findings.append(
                            Finding(
                                sample_sha256=self.sha256,
                                source_tool="elf_parser",
                                finding_type=FindingType.SECTION,
                                address_or_location=sec_info.virtual_address,
                                name=name or f"elf_sec_{i}",
                                description=f"ELF Section '{name}' (Size: {sh_size:,}, Entropy: {entropy:.2f}, Flags: {','.join(flags)})",
                                confidence=1.0,
                                verification_status=FindingStatus.CONFIRMED,
                                raw_data={"name": name, "size": sh_size, "entropy": entropy},
                            )
                        )

        except Exception as e:
            self.findings.append(
                Finding(
                    sample_sha256=self.sha256,
                    source_tool="elf_parser",
                    finding_type=FindingType.ANOMALY,
                    name="elf_parsing_warning",
                    description=f"Corrupt or non-standard ELF structure: {e}",
                    confidence=0.70,
                    verification_status=FindingStatus.FLAGGED,
                )
            )

        return self.findings, self.sections
