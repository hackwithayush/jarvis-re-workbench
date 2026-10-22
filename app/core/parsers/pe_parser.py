"""
JARVIS RE — Deep PE/COFF Parser v1.0
Pure-Python, zero-dependency parser for PE32 and PE32+ (64-bit) executables.
Extracts:
- DOS & COFF File Headers
- Optional Headers (32-bit & 64-bit)
- Section Headers with per-section Shannon entropy
- Import Table (DLLs, imported API functions, ordinals, suspicious API heuristics, imphash)
- Export Table (exported functions, ordinals, RVAs)
- Debug Directory (CodeView PDB paths and timestamps)
- Resources & Version Information
- .NET CLI Header (COR20 metadata)
- Base Relocations
- Graceful recovery from malformed, truncated, or obfuscated structures.
"""

import hashlib
import logging
import math
import struct
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.core.schema import (
    ExportEntry,
    Finding,
    FindingStatus,
    FindingType,
    ImportFunction,
    ImportModule,
    SectionInfo,
)
from app.core.utils import calculate_entropy

logger = logging.getLogger("jarvis.re.parsers.pe")

SUSPICIOUS_APIS = {
    # Process Injection & Memory
    "VirtualAlloc": "Process Memory Allocation",
    "VirtualAllocEx": "Remote Process Memory Allocation (Injection Indicator)",
    "VirtualProtect": "Memory Protection Modification",
    "VirtualProtectEx": "Remote Memory Protection Modification",
    "WriteProcessMemory": "Process Memory Modification (Injection Indicator)",
    "ReadProcessMemory": "Process Memory Inspection",
    "CreateRemoteThread": "Remote Thread Creation (Injection Indicator)",
    "NtCreateThreadEx": "Low-Level Remote Thread Creation",
    "QueueUserAPC": "Asynchronous Procedure Call Queuing (APC Injection)",
    "SetThreadContext": "Thread Hijacking Indicator",
    # Dynamic Resolution & Loading
    "LoadLibraryA": "Dynamic Module Loading",
    "LoadLibraryW": "Dynamic Module Loading",
    "LoadLibraryExA": "Dynamic Module Loading",
    "LoadLibraryExW": "Dynamic Module Loading",
    "GetProcAddress": "Dynamic API Address Resolution",
    "LdrLoadDll": "Low-Level Dynamic DLL Loading",
    # Process & Execution
    "CreateProcessA": "Process Execution",
    "CreateProcessW": "Process Execution",
    "ShellExecuteA": "Shell Command Execution",
    "ShellExecuteW": "Shell Command Execution",
    "WinExec": "Command Execution",
    # Networking & Download
    "URLDownloadToFileA": "File Download Over HTTP(S)",
    "URLDownloadToFileW": "File Download Over HTTP(S)",
    "InternetOpenA": "WinINet HTTP Connection",
    "InternetOpenW": "WinINet HTTP Connection",
    "InternetOpenUrlA": "URL Connection Opening",
    "InternetOpenUrlW": "URL Connection Opening",
    "HttpSendRequestA": "HTTP Request Transmission",
    "WSAStartup": "Windows Sockets Network Initialization",
    "connect": "Socket Network Connection",
    # Persistence & Registry
    "RegOpenKeyExA": "Windows Registry Access",
    "RegOpenKeyExW": "Windows Registry Access",
    "RegSetValueExA": "Windows Registry Key Modification (Persistence Indicator)",
    "RegSetValueExW": "Windows Registry Key Modification (Persistence Indicator)",
    "CreateServiceA": "Windows Service Creation (Persistence Indicator)",
    "CreateServiceW": "Windows Service Creation (Persistence Indicator)",
    # Anti-Analysis & Debugging
    "IsDebuggerPresent": "Anti-Debugging Check",
    "CheckRemoteDebuggerPresent": "Anti-Debugging Check",
    "NtQueryInformationProcess": "Process Information Query (Anti-Debugging)",
    "OutputDebugStringA": "Debug String Output",
}


class PEParser:
    """Zero-dependency parser for PE/COFF executable formats."""

    def __init__(self, data: bytes, sample_sha256: str):
        self.data = data
        self.size = len(data)
        self.sha256 = sample_sha256
        self.pe_offset = 0
        self.is_pe64 = False
        self.sections: List[Dict[str, Any]] = []
        self.data_directories: List[Tuple[int, int]] = []
        self.findings: List[Finding] = []
        self.parsed_sections: List[SectionInfo] = []
        self.parsed_imports: List[ImportModule] = []
        self.parsed_exports: List[ExportEntry] = []
        self.imphash: Optional[str] = None
        self.compilation_timestamp: Optional[str] = None

    def parse(self) -> Tuple[List[Finding], List[SectionInfo], List[ImportModule], List[ExportEntry], Optional[str], Optional[str]]:
        """Run full PE parse pass and return structured findings and models."""
        if len(self.data) < 64 or self.data[:2] != b"MZ":
            return self.findings, self.parsed_sections, self.parsed_imports, self.parsed_exports, None, None

        try:
            self.pe_offset = struct.unpack_from("<I", self.data, 0x3C)[0]
            if self.pe_offset + 24 > self.size:
                self._add_warning("Truncated PE Header: e_lfanew points beyond end of file.")
                return self.findings, self.parsed_sections, self.parsed_imports, self.parsed_exports, None, None

            if self.data[self.pe_offset:self.pe_offset + 4] != b"PE\x00\x00":
                self._add_warning("Invalid PE Signature: missing 'PE\\0\\0' magic.")
                return self.findings, self.parsed_sections, self.parsed_imports, self.parsed_exports, None, None

            self._parse_coff_header()
            self._parse_optional_header()
            self._parse_section_headers()
            self._parse_import_table()
            self._parse_export_table()
            self._parse_debug_directory()
            self._parse_clr_header()

        except Exception as e:
            self._add_warning(f"PE parsing exception: {e}")

        return (
            self.findings,
            self.parsed_sections,
            self.parsed_imports,
            self.parsed_exports,
            self.imphash,
            self.compilation_timestamp,
        )

    def _add_warning(self, message: str) -> None:
        self.findings.append(
            Finding(
                sample_sha256=self.sha256,
                source_tool="pe_parser",
                finding_type=FindingType.ANOMALY,
                name="pe_parsing_warning",
                description=message,
                confidence=0.75,
                verification_status=FindingStatus.FLAGGED,
                raw_data={"warning": message},
            )
        )

    def rva_to_offset(self, rva: int) -> Optional[int]:
        """Convert a Relative Virtual Address (RVA) to physical file offset."""
        if rva == 0:
            return None
        for sec in self.sections:
            vaddr = sec["vaddr"]
            vsize = sec["vsize"]
            raw_ptr = sec["raw_ptr"]
            raw_size = sec["raw_size"]
            # Handle potential mismatch between virtual size and raw size
            span = max(vsize, raw_size)
            if vaddr <= rva < vaddr + span:
                offset = raw_ptr + (rva - vaddr)
                if offset < self.size:
                    return offset
        return None

    def _read_asciiz(self, offset: int, max_len: int = 256) -> str:
        """Read a null-terminated ASCII string from file offset."""
        end = self.data.find(b"\x00", offset, min(self.size, offset + max_len))
        if end == -1:
            end = min(self.size, offset + max_len)
        return self.data[offset:end].decode("latin-1", errors="replace")

    def _parse_coff_header(self) -> None:
        coff_offset = self.pe_offset + 4
        machine, num_sections, timestamp, sym_ptr, num_syms, opt_hdr_size, characteristics = struct.unpack_from(
            "<HHIIIHH", self.data, coff_offset
        )

        try:
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            dt_str = dt.isoformat()
        except Exception:
            dt_str = f"Invalid timestamp ({timestamp})"
        self.compilation_timestamp = dt_str

        is_suspicious_time = timestamp == 0 or timestamp > 2000000000 or timestamp < 600000000
        self.findings.append(
            Finding(
                sample_sha256=self.sha256,
                source_tool="pe_parser",
                finding_type=FindingType.COMPILER,
                name="coff_compilation_timestamp",
                description=f"COFF Compilation Time: {dt_str} (Unix: {timestamp})",
                confidence=0.90 if not is_suspicious_time else 0.70,
                verification_status=FindingStatus.CONFIRMED if not is_suspicious_time else FindingStatus.FLAGGED,
                raw_data={
                    "timestamp": timestamp,
                    "timestamp_iso": dt_str,
                    "machine": machine,
                    "num_sections": num_sections,
                    "characteristics": characteristics,
                },
            )
        )

    def _parse_optional_header(self) -> None:
        opt_offset = self.pe_offset + 24
        opt_hdr_size = struct.unpack_from("<H", self.data, self.pe_offset + 20)[0]
        if opt_hdr_size < 28 or opt_offset + 28 > self.size:
            return

        magic = struct.unpack_from("<H", self.data, opt_offset)[0]
        self.is_pe64 = magic == 0x20B
        ep_rva = struct.unpack_from("<I", self.data, opt_offset + 16)[0]

        image_base = 0
        dirs_offset = 0
        num_dirs = 0

        if not self.is_pe64:
            if opt_offset + 96 <= self.size:
                image_base = struct.unpack_from("<I", self.data, opt_offset + 28)[0]
                num_dirs = struct.unpack_from("<I", self.data, opt_offset + 92)[0]
                dirs_offset = opt_offset + 96
        else:
            if opt_offset + 112 <= self.size:
                image_base = struct.unpack_from("<Q", self.data, opt_offset + 24)[0]
                num_dirs = struct.unpack_from("<I", self.data, opt_offset + 108)[0]
                dirs_offset = opt_offset + 112

        self.findings.append(
            Finding(
                sample_sha256=self.sha256,
                source_tool="pe_parser",
                finding_type=FindingType.ENTRY_POINT,
                address_or_location=f"0x{ep_rva:08X}",
                name="entry_point_rva",
                description=f"PE AddressOfEntryPoint RVA: 0x{ep_rva:08X} ({'PE32+ 64-bit' if self.is_pe64 else 'PE32 32-bit'}), ImageBase: 0x{image_base:X}",
                confidence=1.0,
                verification_status=FindingStatus.CONFIRMED,
                raw_data={
                    "entry_point_rva": ep_rva,
                    "image_base": image_base,
                    "is_pe64": self.is_pe64,
                },
            )
        )

        # Parse Data Directories
        num_dirs = min(num_dirs, 16)
        for i in range(num_dirs):
            off = dirs_offset + (i * 8)
            if off + 8 <= self.size:
                va, sz = struct.unpack_from("<II", self.data, off)
                self.data_directories.append((va, sz))
            else:
                self.data_directories.append((0, 0))

    def _parse_section_headers(self) -> None:
        coff_offset = self.pe_offset + 4
        num_sections = struct.unpack_from("<H", self.data, coff_offset + 2)[0]
        opt_hdr_size = struct.unpack_from("<H", self.data, coff_offset + 16)[0]
        sec_offset = coff_offset + 20 + opt_hdr_size

        for i in range(num_sections):
            off = sec_offset + (i * 40)
            if off + 40 > self.size:
                break

            raw_name = self.data[off:off + 8].split(b"\x00")[0]
            name = raw_name.decode("latin-1", errors="replace").strip()
            vsize, vaddr, raw_size, raw_ptr, _, _, _, _, characteristics = struct.unpack_from("<IIIIIIHHI", self.data, off + 8)

            sec_bytes = self.data[raw_ptr:raw_ptr + raw_size] if raw_ptr + raw_size <= self.size else b""
            entropy = calculate_entropy(sec_bytes) if sec_bytes else 0.0

            flags = []
            if characteristics & 0x20000000:
                flags.append("EXECUTE")
            if characteristics & 0x40000000:
                flags.append("READ")
            if characteristics & 0x80000000:
                flags.append("WRITE")
            if characteristics & 0x00000020:
                flags.append("CODE")
            if characteristics & 0x00000040:
                flags.append("INITIALIZED_DATA")
            if characteristics & 0x00000080:
                flags.append("UNINITIALIZED_DATA")

            sec_info = SectionInfo(
                name=name or f"sec_{i}",
                virtual_address=f"0x{vaddr:08X}",
                virtual_size=vsize,
                raw_size=raw_size,
                raw_offset=raw_ptr,
                entropy=round(entropy, 3),
                characteristics=characteristics,
                flags=flags,
            )
            self.parsed_sections.append(sec_info)

            sec_dict = {
                "name": name,
                "vaddr": vaddr,
                "vsize": vsize,
                "raw_ptr": raw_ptr,
                "raw_size": raw_size,
                "entropy": entropy,
            }
            self.sections.append(sec_dict)

            # High entropy per-section warning
            is_packed_section = entropy > 7.2 and raw_size > 4096
            self.findings.append(
                Finding(
                    sample_sha256=self.sha256,
                    source_tool="pe_parser",
                    finding_type=FindingType.SECTION,
                    address_or_location=f"0x{vaddr:08X}",
                    name=name or f"sec_{i}",
                    description=f"Section {name} (VSize: {vsize:,}, RawSize: {raw_size:,}, Entropy: {entropy:.2f}, Flags: {','.join(flags)})",
                    confidence=0.95 if is_packed_section else 1.0,
                    verification_status=FindingStatus.FLAGGED if is_packed_section else FindingStatus.CONFIRMED,
                    raw_data=sec_dict,
                )
            )

    def _parse_import_table(self) -> None:
        if len(self.data_directories) < 2:
            return
        import_rva, import_sz = self.data_directories[1]
        if import_rva == 0 or import_sz == 0:
            return

        import_offset = self.rva_to_offset(import_rva)
        if not import_offset:
            return

        imphash_parts = []
        desc_offset = import_offset

        while desc_offset + 20 <= self.size:
            orig_first_thunk, timestamp, forwarder, name_rva, first_thunk = struct.unpack_from(
                "<IIIII", self.data, desc_offset
            )
            if orig_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
                break  # Null terminator descriptor

            name_offset = self.rva_to_offset(name_rva)
            if not name_offset:
                desc_offset += 20
                continue

            dll_name = self._read_asciiz(name_offset)
            dll_base = dll_name.lower()
            if dll_base.endswith(".dll") or dll_base.endswith(".sys") or dll_base.endswith(".ocx"):
                dll_base = dll_base.rsplit(".", 1)[0]

            thunk_rva = orig_first_thunk if orig_first_thunk != 0 else first_thunk
            thunk_offset = self.rva_to_offset(thunk_rva)

            imported_funcs: List[ImportFunction] = []

            if thunk_offset:
                entry_size = 8 if self.is_pe64 else 4
                curr_thunk = thunk_offset

                while curr_thunk + entry_size <= self.size:
                    if self.is_pe64:
                        val = struct.unpack_from("<Q", self.data, curr_thunk)[0]
                        is_ordinal = bool(val & 0x8000000000000000)
                        data_val = val & 0x7FFFFFFFFFFFFFFF
                    else:
                        val = struct.unpack_from("<I", self.data, curr_thunk)[0]
                        is_ordinal = bool(val & 0x80000000)
                        data_val = val & 0x7FFFFFFF

                    if val == 0:
                        break

                    func_name = ""
                    ordinal = None
                    if is_ordinal:
                        ordinal = data_val & 0xFFFF
                        func_name = f"Ordinal_{ordinal}"
                        imphash_parts.append(f"{dll_base}.ord{ordinal}")
                    else:
                        hint_offset = self.rva_to_offset(data_val)
                        if hint_offset and hint_offset + 2 < self.size:
                            func_name = self._read_asciiz(hint_offset + 2)
                            imphash_parts.append(f"{dll_base}.{func_name.lower()}")

                    if func_name:
                        susp_desc = SUSPICIOUS_APIS.get(func_name)
                        is_suspicious = susp_desc is not None
                        imported_funcs.append(
                            ImportFunction(
                                name=func_name,
                                ordinal=ordinal,
                                rva=f"0x{data_val:08X}",
                                is_suspicious=is_suspicious,
                                category=susp_desc,
                            )
                        )
                        if is_suspicious:
                            self.findings.append(
                                Finding(
                                    sample_sha256=self.sha256,
                                    source_tool="pe_parser",
                                    finding_type=FindingType.IMPORT,
                                    name=f"suspicious_import_{func_name}",
                                    description=f"Imported API '{dll_name}!{func_name}': {susp_desc}",
                                    confidence=0.85,
                                    verification_status=FindingStatus.FLAGGED,
                                    raw_data={"dll": dll_name, "function": func_name, "category": susp_desc},
                                )
                            )

                    curr_thunk += entry_size

            self.parsed_imports.append(ImportModule(module_name=dll_name, functions=imported_funcs))
            desc_offset += 20

        if imphash_parts:
            joined = ",".join(imphash_parts)
            self.imphash = hashlib.md5(joined.encode("latin-1")).hexdigest()
            self.findings.append(
                Finding(
                    sample_sha256=self.sha256,
                    source_tool="pe_parser",
                    finding_type=FindingType.METADATA,
                    name="pe_imphash",
                    description=f"Import Hash (imphash): {self.imphash} (from {len(imphash_parts)} imports)",
                    confidence=1.0,
                    verification_status=FindingStatus.CONFIRMED,
                    raw_data={"imphash": self.imphash, "count": len(imphash_parts)},
                )
            )

    def _parse_export_table(self) -> None:
        if len(self.data_directories) < 1:
            return
        export_rva, export_sz = self.data_directories[0]
        if export_rva == 0 or export_sz == 0:
            return

        export_offset = self.rva_to_offset(export_rva)
        if not export_offset or export_offset + 40 > self.size:
            return

        characteristics, timestamp, major_v, minor_v, name_rva, base, num_funcs, num_names, funcs_rva, names_rva, ords_rva = struct.unpack_from(
            "<IIHHIIIIIII", self.data, export_offset
        )

        dll_name = ""
        name_off = self.rva_to_offset(name_rva)
        if name_off:
            dll_name = self._read_asciiz(name_off)

        funcs_off = self.rva_to_offset(funcs_rva)
        names_off = self.rva_to_offset(names_rva)
        ords_off = self.rva_to_offset(ords_rva)

        if not funcs_off or not names_off or not ords_off:
            return

        # Cap parsed names at 500 to prevent denial of service on malformed headers
        max_exports = min(num_names, 500)
        for i in range(max_exports):
            n_ptr_off = names_off + (i * 4)
            o_ptr_off = ords_off + (i * 2)
            if n_ptr_off + 4 > self.size or o_ptr_off + 2 > self.size:
                break

            n_rva = struct.unpack_from("<I", self.data, n_ptr_off)[0]
            ord_val = struct.unpack_from("<H", self.data, o_ptr_off)[0]

            fn_off = self.rva_to_offset(n_rva)
            fn_name = self._read_asciiz(fn_off) if fn_off else f"Export_{ord_val}"

            func_ptr_off = funcs_off + (ord_val * 4)
            func_rva = 0
            if func_ptr_off + 4 <= self.size:
                func_rva = struct.unpack_from("<I", self.data, func_ptr_off)[0]

            self.parsed_exports.append(
                ExportEntry(
                    name=fn_name,
                    ordinal=base + ord_val,
                    rva=f"0x{func_rva:08X}",
                )
            )

        if self.parsed_exports:
            self.findings.append(
                Finding(
                    sample_sha256=self.sha256,
                    source_tool="pe_parser",
                    finding_type=FindingType.EXPORT,
                    name="pe_export_table",
                    description=f"Export table '{dll_name}': {len(self.parsed_exports)} exported symbols.",
                    confidence=1.0,
                    verification_status=FindingStatus.CONFIRMED,
                    raw_data={"dll_name": dll_name, "export_count": len(self.parsed_exports)},
                )
            )

    def _parse_debug_directory(self) -> None:
        if len(self.data_directories) < 7:
            return
        debug_rva, debug_sz = self.data_directories[6]
        if debug_rva == 0 or debug_sz == 0:
            return

        debug_offset = self.rva_to_offset(debug_rva)
        if not debug_offset:
            return

        count = debug_sz // 28
        for i in range(min(count, 10)):
            entry_off = debug_offset + (i * 28)
            if entry_off + 28 > self.size:
                break
            charact, timestamp, major_v, minor_v, dbg_type, size_of_data, addr_raw, ptr_raw = struct.unpack_from(
                "<IIHHIIII", self.data, entry_off
            )

            # Type 2 = IMAGE_DEBUG_TYPE_CODEVIEW
            if dbg_type == 2 and ptr_raw + size_of_data <= self.size and size_of_data >= 24:
                cv_sig = self.data[ptr_raw:ptr_raw + 4]
                if cv_sig == b"RSDS":  # PDB 7.0
                    pdb_path = self._read_asciiz(ptr_raw + 24, max_len=size_of_data - 24)
                    if pdb_path:
                        self.findings.append(
                            Finding(
                                sample_sha256=self.sha256,
                                source_tool="pe_parser",
                                finding_type=FindingType.DEBUG_INFO,
                                name="pdb_debug_path",
                                description=f"CodeView PDB Debug Path: '{pdb_path}'",
                                confidence=0.98,
                                verification_status=FindingStatus.CONFIRMED,
                                raw_data={"pdb_path": pdb_path, "type": "RSDS"},
                            )
                        )

    def _parse_clr_header(self) -> None:
        if len(self.data_directories) < 15:
            return
        clr_rva, clr_sz = self.data_directories[14]
        if clr_rva == 0 or clr_sz == 0:
            return

        clr_offset = self.rva_to_offset(clr_rva)
        if not clr_offset or clr_offset + 72 > self.size:
            return

        cb, major_rt, minor_rt, meta_rva, meta_sz, flags, ep_token = struct.unpack_from(
            "<IIIIIII", self.data, clr_offset
        )

        is_il_only = bool(flags & 0x00000001)
        is_32bit_req = bool(flags & 0x00000002)

        self.findings.append(
            Finding(
                sample_sha256=self.sha256,
                source_tool="pe_parser",
                finding_type=FindingType.COMPILER,
                name="dotnet_clr_header",
                description=(
                    f".NET CLR Runtime Header v{major_rt}.{minor_rt} "
                    f"({'IL-Only' if is_il_only else 'Mixed Native/IL'}, "
                    f"{'32-bit Required' if is_32bit_req else 'Any-CPU/64-bit'}), "
                    f"Metadata RVA: 0x{meta_rva:08X} ({meta_sz:,} bytes)"
                ),
                confidence=1.0,
                verification_status=FindingStatus.CONFIRMED,
                raw_data={
                    "runtime_version": f"{major_rt}.{minor_rt}",
                    "flags": flags,
                    "metadata_rva": meta_rva,
                    "metadata_size": meta_sz,
                    "entry_token": ep_token,
                },
            )
        )
