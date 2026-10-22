"""
JARVIS RE — Shared Evidence & Analysis Schema v1.0
Type-safe models for findings, evidence provenance, sample metadata, and reports.
Fully backward-compatible with v0.1 while adding deep reverse-engineering structures:
sections, imports, exports, functions, disassembly, decompilation, CFG, dynamic traces,
and AI-assisted analytical summaries.
"""

from datetime import datetime, timezone
from enum import Enum
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ToolExecutionState(str, Enum):
    DISCOVERED = "discovered"
    INSTALLED = "installed"
    VERSION_VERIFIED = "version_verified"
    CAPABILITY_VERIFIED = "capability_verified"
    EXECUTION_REQUESTED = "execution_requested"
    EXECUTION_STARTED = "execution_started"
    EXECUTION_COMPLETED = "execution_completed"
    OUTPUT_PARSED = "output_parsed"
    ARTIFACTS_VALIDATED = "artifacts_validated"
    RESULTS_PERSISTED = "results_persisted"
    FAILED = "failed"
    SKIPPED = "skipped"


class ToolExecutionRecord(BaseModel):
    tool_name: str = "unknown"
    tool_version: Optional[str] = None
    state: ToolExecutionState = ToolExecutionState.DISCOVERED
    command: Optional[str] = None
    exit_code: Optional[int] = None
    duration_seconds: float = 0.0
    stdout_snippet: Optional[str] = None
    stderr_snippet: Optional[str] = None
    artifact_paths: List[str] = Field(default_factory=list)
    functions_recovered: int = 0
    zero_functions_reason: Optional[str] = None
    findings_count: int = 0
    parsing_status: str = "pending"
    error_message: Optional[str] = None


class FindingType(str, Enum):
    METADATA = "metadata"
    HEADER = "header"
    SECTION = "section"
    ENTRY_POINT = "entry_point"
    STRING = "string"
    ANOMALY = "anomaly"
    COMPILER = "compiler"
    TOOL_STATUS = "tool_status"
    IMPORT = "import"
    EXPORT = "export"
    RESOURCE = "resource"
    DEBUG_INFO = "debug_info"
    RELOCATION = "relocation"
    FUNCTION = "function"
    DISASSEMBLY = "disassembly"
    DECOMPILED_CODE = "decompiled_code"
    CFG = "cfg"
    ARCHIVE_MEMBER = "archive_member"
    DYNAMIC_EVENT = "dynamic_event"
    AI_SUMMARY = "ai_summary"
    CORRELATION = "correlation"


class FindingStatus(str, Enum):
    UNVERIFIED = "unverified"
    CORROBORATED = "corroborated"
    CONFIRMED = "confirmed"
    FLAGGED = "flagged"
    REJECTED = "rejected"


class EvidenceItem(BaseModel):
    source: str
    content: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    run_id: Optional[str] = None
    sample_sha256: str
    source_tool: str = "jarvis_analyzer"
    tool_version: str = "1.0.0"
    finding_type: FindingType
    address_or_location: Optional[str] = None
    name: str
    description: str
    evidence: List[EvidenceItem] = Field(default_factory=list)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    confidence_reasoning: Optional[str] = None
    verification_status: FindingStatus = FindingStatus.UNVERIFIED
    tags: List[str] = Field(default_factory=list)
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SectionInfo(BaseModel):
    name: str
    virtual_address: str
    virtual_size: int
    raw_size: int
    raw_offset: int
    entropy: float
    characteristics: int = 0
    flags: List[str] = Field(default_factory=list)


class ImportFunction(BaseModel):
    name: str
    ordinal: Optional[int] = None
    rva: Optional[str] = None
    is_suspicious: bool = False
    category: Optional[str] = None


class ImportModule(BaseModel):
    module_name: str
    functions: List[ImportFunction] = Field(default_factory=list)


class ExportEntry(BaseModel):
    name: Optional[str] = None
    ordinal: int
    rva: str
    forwarder: Optional[str] = None


class CFGBlock(BaseModel):
    id: str
    address: str
    size: int
    instructions: List[str] = Field(default_factory=list)
    jump_target: Optional[str] = None
    fail_target: Optional[str] = None


class FunctionDetails(BaseModel):
    name: str
    address: str
    size: int
    source_tool: str = "builtin"
    calling_convention: Optional[str] = None
    parameter_count: Optional[int] = None
    instructions: List[str] = Field(default_factory=list)
    decompiled_c: Optional[str] = None
    decompiled_csharp: Optional[str] = None
    cfg_blocks: List[CFGBlock] = Field(default_factory=list)
    cross_references: List[str] = Field(default_factory=list)
    api_calls: List[str] = Field(default_factory=list)


class ArchiveMember(BaseModel):
    filename: str
    file_size: int
    compressed_size: int
    entropy: float = 0.0
    file_type: str = "Unknown"
    is_executable: bool = False


class DynamicTrace(BaseModel):
    executed: bool = False
    sandbox_mode: str = "none"
    execution_time_ms: int = 0
    exit_code: Optional[int] = None
    spawned_processes: List[Dict[str, Any]] = Field(default_factory=list)
    loaded_modules: List[str] = Field(default_factory=list)
    file_operations: List[Dict[str, Any]] = Field(default_factory=list)
    registry_operations: List[Dict[str, Any]] = Field(default_factory=list)
    network_events: List[Dict[str, Any]] = Field(default_factory=list)
    api_calls: List[Dict[str, Any]] = Field(default_factory=list)
    observations: List[str] = Field(default_factory=list)
    security_warning: Optional[str] = None


class AIHypothesis(BaseModel):
    category: str
    title: str
    description: str
    confidence: float
    supporting_evidence_ids: List[str] = Field(default_factory=list)


class SampleInfo(BaseModel):
    filename: str
    sha256: str
    md5: str
    sha1: str
    file_size: int
    file_type: str
    architecture: str
    endianness: str = "Little Endian"
    subsystem: Optional[str] = None
    entropy: float
    compilation_timestamp: Optional[str] = None
    imphash: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AnalysisReport(BaseModel):
    report_id: str
    sample: SampleInfo
    summary: Dict[str, Any]
    sections: List[SectionInfo] = Field(default_factory=list)
    imports: List[ImportModule] = Field(default_factory=list)
    exports: List[ExportEntry] = Field(default_factory=list)
    functions: List[FunctionDetails] = Field(default_factory=list)
    archive_members: List[ArchiveMember] = Field(default_factory=list)
    dynamic_trace: Optional[DynamicTrace] = None
    findings: List[Finding]
    tools_audited: Dict[str, Any]
    tool_executions: Dict[str, ToolExecutionRecord] = Field(default_factory=dict)
    ai_hypotheses: List[AIHypothesis] = Field(default_factory=list)
    assessment: Optional[Dict[str, Any]] = None
    limitations: List[str]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
