"""
JARVIS RE — Binary Static Analyzer v1.0
Orchestrates multi-engine static reverse engineering:
- Deep PE32/PE32+ parser (Headers, Sections, Imports, Exports, Debug PDB, CLR, Imphash)
- ELF32/ELF64 parser (Headers, Segments, Sections, NX/GNU_STACK)
- Mach-O 32/64 parser (Load commands, Segments, Dylibs)
- Bounded Archive Inspector (ZIP, APK, JAR, TAR)
- High-performance ASCII & UTF-16LE Classified String Extractor
- Real tool integration: Detect It Easy (DIE), radare2 / rabin2, ILSpy / dnSpy, angr, Ghidra
"""

import logging
import os
import shutil
import tempfile
import uuid
from typing import Any, Dict, List, Optional, Tuple

from app.core.parsers.pe_parser import PEParser
from app.core.parsers.elf_parser import ELFParser
from app.core.parsers.macho_parser import MachOParser
from app.core.parsers.archive_parser import ArchiveInspector
from app.core.parsers.string_extractor import StringExtractor
from app.core.schema import (
    ArchiveMember,
    ExportEntry,
    Finding,
    FindingStatus,
    FindingType,
    FunctionDetails,
    ImportModule,
    SampleInfo,
    SectionInfo,
)
from app.core.utils import (
    calculate_entropy,
    compute_hashes,
    detect_architecture,
    detect_file_type,
)
from adapters import (
    DIEAdapter,
    Radare2Adapter,
    DnSpyAdapter,
    AngrAdapter,
    GhidraAdapter,
    JadxAdapter,
    CapaAdapter,
    YaraAdapter,
)

logger = logging.getLogger("jarvis.re.analyzer")


class BinaryAnalyzer:
    """Core static analyzer orchestrating format-specific parsers and tool adapters."""

    def __init__(self, file_path: str):
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Target binary not found: {file_path}")
        self.file_path = file_path
        self.file_size = os.path.getsize(file_path)
        self.sections: List[SectionInfo] = []
        self.imports: List[ImportModule] = []
        self.exports: List[ExportEntry] = []
        self.archive_members: List[ArchiveMember] = []
        self.functions: List[FunctionDetails] = []
        self.imphash: Optional[str] = None
        self.compilation_timestamp: Optional[str] = None
        self.tool_executions: Dict[str, Any] = {}
        self.ai_hypotheses: List[Any] = []
        self.assessment: Dict[str, Any] = {}
        self.string_stats: Dict[str, Any] = {}

    def analyze(self, options: Optional[Dict[str, Any]] = None) -> Tuple[SampleInfo, List[Finding]]:
        """Run complete static analysis pass on the sample."""
        options = options or {}
        run_id = options.get("run_id") or str(uuid.uuid4())[:8]

        with open(self.file_path, "rb") as f:
            data = f.read()

        hashes = compute_hashes(self.file_path)
        file_type = detect_file_type(self.file_path)
        architecture = detect_architecture(self.file_path)
        overall_entropy = calculate_entropy(data)

        sample_info = SampleInfo(
            filename=os.path.basename(self.file_path),
            sha256=hashes["sha256"],
            md5=hashes["md5"],
            sha1=hashes["sha1"],
            file_size=self.file_size,
            file_type=file_type,
            architecture=architecture,
            entropy=round(overall_entropy, 3),
        )

        findings: List[Finding] = []

        # 1. Base Metadata finding
        findings.append(
            Finding(
                run_id=run_id,
                sample_sha256=hashes["sha256"],
                source_tool="jarvis_analyzer",
                finding_type=FindingType.METADATA,
                name="binary_identity",
                description=f"Format: {file_type}, Arch: {architecture}, Size: {self.file_size:,} bytes",
                confidence=1.0,
                verification_status=FindingStatus.CONFIRMED,
                raw_data={"hashes": hashes, "format": file_type, "arch": architecture},
            )
        )

        # 2. Shannon Entropy / Packing heuristic
        is_packed = overall_entropy > 7.1
        findings.append(
            Finding(
                run_id=run_id,
                sample_sha256=hashes["sha256"],
                source_tool="jarvis_analyzer",
                finding_type=FindingType.ANOMALY if is_packed else FindingType.METADATA,
                name="entropy_distribution",
                description=(
                    f"Overall Shannon Entropy: {overall_entropy:.3f} / 8.000. "
                    + ("High entropy indicates packed, encrypted, or compressed payload." if is_packed else "Normal executable entropy distribution.")
                ),
                confidence=0.90 if is_packed else 0.75,
                verification_status=FindingStatus.FLAGGED if is_packed else FindingStatus.CONFIRMED,
                raw_data={"entropy": overall_entropy, "packed_suspect": is_packed},
            )
        )

        # 3. Format-specific deep parsing
        is_dotnet = False
        if data[:2] == b"MZ":
            pe_parser = PEParser(data, hashes["sha256"])
            pe_findings, self.sections, self.imports, self.exports, self.imphash, self.compilation_timestamp = pe_parser.parse()
            findings.extend(pe_findings)
            if self.imphash:
                sample_info.imphash = self.imphash
            if self.compilation_timestamp:
                sample_info.compilation_timestamp = self.compilation_timestamp
            is_dotnet = "NET" in file_type

        elif data[:4] == b"\x7fELF":
            elf_parser = ELFParser(data, hashes["sha256"])
            elf_findings, self.sections = elf_parser.parse()
            findings.extend(elf_findings)

        elif len(data) >= 4 and (data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") or struct.unpack_from(">I", data, 0)[0] == 0xCAFEBABE):
            macho_parser = MachOParser(data, hashes["sha256"])
            macho_findings, self.sections = macho_parser.parse()
            findings.extend(macho_findings)

        elif data[:4] == b"PK\x03\x04" or (len(data) >= 262 and data[257:262] == b"ustar"):
            archive_inspector = ArchiveInspector(data, hashes["sha256"])
            arch_findings, self.archive_members = archive_inspector.inspect()
            findings.extend(arch_findings)

        # 4. Printable ASCII & UTF-16LE String Extraction
        string_extractor = StringExtractor(data, hashes["sha256"])
        string_findings = string_extractor.extract()
        self.string_stats = string_extractor.stats
        findings.extend(string_findings)

        # 5. External Tool Adapters Integration
        temp_ws = tempfile.mkdtemp(prefix="jarvis_re_ws_")
        try:
            # Detect It Easy (DIE) triage
            die_adapter = DIEAdapter()
            if die_adapter.is_available():
                try:
                    die_raw = die_adapter.analyze(self.file_path, temp_ws)
                    self.tool_executions["die"] = {
                        "tool_name": "die",
                        "tool_version": die_adapter.get_version() or "diec-cli",
                        "exit_code": 0,
                        "findings_count": len(die_raw),
                        "parsing_status": "success",
                    }
                    for item in die_raw:
                        ft = item.get("finding_type", "metadata")
                        mapped_type = FindingType.COMPILER if "compiler" in ft else (
                            FindingType.ANOMALY if "anomaly" in ft or "packer" in ft else FindingType.METADATA
                        )
                        findings.append(
                            Finding(
                                run_id=run_id,
                                sample_sha256=hashes["sha256"],
                                source_tool="die",
                                tool_version=die_adapter.get_version() or "diec",
                                finding_type=mapped_type,
                                address_or_location="pe_header:signatures",
                                name=item.get("name", "die_detect"),
                                description=item.get("description", "DIE Detection"),
                                confidence=item.get("confidence", 0.85),
                                confidence_reasoning="Detect It Easy signature match against compiler/packer database.",
                                verification_status=FindingStatus.CONFIRMED,
                                raw_data=item.get("raw_data", {}),
                            )
                        )
                except Exception as e:
                    logger.warning("DIE analysis execution error: %s", e)
                    self.tool_executions["die"] = {"tool_name": "die", "error_message": str(e), "parsing_status": "error"}

            # radare2 disassembly & functions
            r2_adapter = Radare2Adapter()
            if r2_adapter.is_available():
                try:
                    r2_raw = r2_adapter.analyze(self.file_path, temp_ws)
                    if r2_adapter.last_execution:
                        self.tool_executions["radare2"] = r2_adapter.last_execution

                    for item in r2_raw:
                        ft_str = item.get("finding_type", "function")
                        mapped_type = FindingType.FUNCTION if ft_str == "function" else FindingType.METADATA
                        addr = item.get("address")
                        f_name = item.get("name", "func")
                        raw_d = item.get("raw_data", {})

                        if mapped_type == FindingType.FUNCTION and addr:
                            self.functions.append(
                                FunctionDetails(
                                    name=f_name,
                                    address=addr,
                                    size=raw_d.get("size", 0),
                                    source_tool="radare2",
                                    calling_convention=raw_d.get("calltype"),
                                    parameter_count=raw_d.get("nargs"),
                                )
                            )

                        findings.append(
                            Finding(
                                run_id=run_id,
                                sample_sha256=hashes["sha256"],
                                source_tool="radare2",
                                tool_version=r2_adapter.get_version() or "r2",
                                finding_type=mapped_type,
                                address_or_location=addr or "binary:metadata",
                                name=f_name,
                                description=item.get("description", "radare2 artifact"),
                                confidence=item.get("confidence", 0.88),
                                confidence_reasoning="Disassembly and binary analysis derived from radare2 / rabin2 engine.",
                                verification_status=FindingStatus.CONFIRMED,
                                raw_data=raw_d,
                            )
                        )

                    # Enrich functions with real disassembly, CFG, and pseudo-C decompilation
                    if self.functions:
                        try:
                            from app.core.disassembler import DisassemblyEngine
                            disasm_engine = DisassemblyEngine()
                            self.functions = disasm_engine.enrich_functions(self.file_path, self.functions, limit=10)
                        except Exception as enrich_err:
                            logger.warning("radare2 function enrichment failed: %s", enrich_err)
                except Exception as e:
                    logger.warning("radare2 analysis execution error: %s", e)
                    self.tool_executions["radare2"] = {"tool_name": "radare2", "error_message": str(e), "parsing_status": "error"}
                    logger.warning("radare2 analysis execution error: %s", e)

            # ILSpy / dnSpy for .NET Assemblies
            if is_dotnet:
                dnspy_adapter = DnSpyAdapter()
                if dnspy_adapter.is_available():
                    try:
                        dnspy_raw = dnspy_adapter.analyze(self.file_path, temp_ws)
                        for item in dnspy_raw:
                            findings.append(
                                Finding(
                                    run_id=run_id,
                                    sample_sha256=hashes["sha256"],
                                    source_tool="dnspy",
                                    tool_version=dnspy_adapter.get_version() or "ilspycmd",
                                    finding_type=FindingType.DECOMPILED_CODE,
                                    name=item.get("name", "dotnet_decompilation"),
                                    description=item.get("description", ".NET Decompiled Source"),
                                    confidence=item.get("confidence", 0.95),
                                    verification_status=FindingStatus.CONFIRMED,
                                    raw_data=item.get("raw_data", {}),
                                )
                            )
                    except Exception as e:
                        logger.warning("ILSpy analysis execution error: %s", e)

            # Deep Ghidra / angr execution if requested in options
            if options.get("enable_ghidra", False):
                ghidra_adapter = GhidraAdapter()
                if ghidra_adapter.is_available():
                    try:
                        gh_raw = ghidra_adapter.analyze(self.file_path, temp_ws, options=options)
                        for item in gh_raw:
                            ftype = FindingType.FUNCTION if item.get("finding_type") == "function" else FindingType.METADATA
                            f_addr = item.get("address")
                            f_name = item.get("name", "ghidra_finding")
                            raw_gh = item.get("raw_data", {})
                            findings.append(
                                Finding(
                                    run_id=run_id,
                                    sample_sha256=hashes["sha256"],
                                    source_tool="ghidra",
                                    tool_version=ghidra_adapter.get_version() or "Ghidra",
                                    finding_type=ftype,
                                    address_or_location=f_addr,
                                    name=f_name,
                                    description=item.get("description", "Ghidra Headless artifact"),
                                    confidence=item.get("confidence", 0.90),
                                    verification_status=FindingStatus.CONFIRMED,
                                    raw_data=raw_gh,
                                )
                            )
                            if ftype == FindingType.FUNCTION and f_addr:
                                self.functions.append(
                                    FunctionDetails(
                                        name=f_name,
                                        address=f_addr,
                                        size=raw_gh.get("size", 0),
                                        source_tool="ghidra",
                                        calling_convention=raw_gh.get("calling_convention"),
                                        parameter_count=raw_gh.get("parameter_count"),
                                    )
                                )
                    except Exception as e:
                        logger.warning("Ghidra analysis execution error: %s", e)

            if options.get("enable_angr", False):
                angr_adapter = AngrAdapter()
                if angr_adapter.is_available():
                    try:
                        angr_raw = angr_adapter.analyze(self.file_path, temp_ws, options=options)
                        for item in angr_raw:
                            findings.append(
                                Finding(
                                    run_id=run_id,
                                    sample_sha256=hashes["sha256"],
                                    source_tool="angr",
                                    tool_version=angr_adapter.get_version() or "angr",
                                    finding_type=FindingType.CFG if "cfg" in item.get("name", "") else FindingType.FUNCTION,
                                    address_or_location=item.get("address"),
                                    name=item.get("name", "angr_finding"),
                                    description=item.get("description", "angr CFG artifact"),
                                    confidence=item.get("confidence", 0.85),
                                    verification_status=FindingStatus.CONFIRMED,
                                    raw_data=item.get("raw_data", {}),
                                )
                            )
                    except Exception as e:
                        logger.warning("angr analysis execution error: %s", e)

            # YARA signature matching
            yara_adapter = YaraAdapter()
            if yara_adapter.is_available():
                try:
                    yara_raw = yara_adapter.analyze(self.file_path, temp_ws, options=options)
                    for item in yara_raw:
                        findings.append(
                            Finding(
                                run_id=run_id,
                                sample_sha256=hashes["sha256"],
                                source_tool="yara",
                                tool_version=yara_adapter.get_version() or "4.5.0",
                                finding_type=FindingType.ANOMALY,
                                name=item.get("name", "yara_match"),
                                description=item.get("description", "YARA Rule Match"),
                                confidence=item.get("confidence", 0.92),
                                verification_status=FindingStatus.FLAGGED,
                                raw_data=item.get("raw_data", {}),
                            )
                        )
                except Exception as yara_err:
                    logger.warning("YARA analysis error: %s", yara_err)

            # JADX Android APK / DEX Decompilation
            is_android = "DEX" in file_type or "APK" in file_type or self.file_path.lower().endswith((".apk", ".dex"))
            if is_android:
                jadx_adapter = JadxAdapter()
                if jadx_adapter.is_available():
                    try:
                        jadx_raw = jadx_adapter.analyze(self.file_path, temp_ws, options=options)
                        for item in jadx_raw:
                            findings.append(
                                Finding(
                                    run_id=run_id,
                                    sample_sha256=hashes["sha256"],
                                    source_tool="jadx",
                                    tool_version=jadx_adapter.get_version() or "1.5.6",
                                    finding_type=FindingType.DECOMPILED_CODE if "decompil" in item.get("name", "") else FindingType.METADATA,
                                    name=item.get("name", "jadx_artifact"),
                                    description=item.get("description", "JADX Decompilation"),
                                    confidence=item.get("confidence", 0.95),
                                    verification_status=FindingStatus.CONFIRMED,
                                    raw_data=item.get("raw_data", {}),
                                )
                            )
                    except Exception as jadx_err:
                        logger.warning("JADX decompilation error: %s", jadx_err)

            # Mandiant capa capability analysis
            if options.get("enable_capa", False) or "PE" in file_type or "ELF" in file_type:
                capa_adapter = CapaAdapter()
                if capa_adapter.is_available():
                    try:
                        capa_raw = capa_adapter.analyze(self.file_path, temp_ws, options=options)
                        for item in capa_raw:
                            findings.append(
                                Finding(
                                    run_id=run_id,
                                    sample_sha256=hashes["sha256"],
                                    source_tool="capa",
                                    tool_version=capa_adapter.get_version() or "10.0.0",
                                    finding_type=FindingType.METADATA,
                                    name=item.get("name", "capa_capability"),
                                    description=item.get("description", "Program capability"),
                                    confidence=item.get("confidence", 0.90),
                                    verification_status=FindingStatus.CONFIRMED,
                                    raw_data=item.get("raw_data", {}),
                                )
                            )
                    except Exception as capa_err:
                        logger.warning("capa analysis error: %s", capa_err)

        finally:
            shutil.rmtree(temp_ws, ignore_errors=True)

        # Correlate findings and generate coverage-calibrated assessment
        from app.core.evidence_engine import EvidenceCorrelationEngine
        deduped_findings, self.ai_hypotheses, self.assessment = EvidenceCorrelationEngine.correlate(
            findings=findings,
            imphash=self.imphash,
            entropy=overall_entropy,
            is_dotnet=is_dotnet,
            functions_count=len(self.functions),
            dynamic_executed=False,
            tool_executions=self.tool_executions,
        )

        return sample_info, deduped_findings
