"""
Jarvis RE — Pydantic schema models for the shared evidence schema.

All inter-tool communication and API payloads are validated through these
models so that every consumer (database layer, REST endpoints, AI reasoner)
speaks the same language.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class FindingType(str, Enum):
    """Categories of artefacts that a reverse-engineering tool can report."""

    FUNCTION = "function"
    STRING = "string"
    IMPORT = "import"
    EXPORT = "export"
    SECTION = "section"
    METADATA = "metadata"
    CROSS_REFERENCE = "cross_reference"
    SYMBOL = "symbol"
    ENTRY_POINT = "entry_point"
    LIBRARY = "library"
    COMPILER_INFO = "compiler_info"
    PACKER_INFO = "packer_info"
    ANOMALY = "anomaly"
    API_CALL = "api_call"
    RUNTIME_OBSERVATION = "runtime_observation"


class FindingStatus(str, Enum):
    """Lifecycle status of a :class:`Finding`."""

    UNVERIFIED = "unverified"
    CORROBORATED = "corroborated"
    REJECTED = "rejected"
    REVIEWED = "reviewed"


class SourceTool(str, Enum):
    """Canonical identifiers for every tool the RE module can invoke."""

    DIE = "die"
    GHIDRA = "ghidra"
    RADARE2 = "radare2"
    CUTTER = "cutter"
    IMHEX = "imhex"
    DNSPY = "dnspy"
    X64DBG = "x64dbg"
    FRIDA = "frida"
    ANGR = "angr"
    PYTHON = "python"       # built-in Python analysis
    AI = "ai"               # AI-generated inference


# ---------------------------------------------------------------------------
# Evidence & Finding models
# ---------------------------------------------------------------------------

class EvidenceItem(BaseModel):
    """A single piece of supporting evidence attached to a :class:`Finding`."""

    source: str
    content: str
    timestamp: Optional[datetime] = None
    artifact_path: Optional[str] = None


class Finding(BaseModel):
    """
    One discrete observation produced by a tool (or AI reasoner).

    Findings are the universal currency of the RE module — every adapter
    emits them, the orchestrator stores them, and the AI reasoner consumes
    them.
    """

    sample_sha256: str
    source_tool: SourceTool
    finding_type: FindingType
    address: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    evidence: List[EvidenceItem] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    status: FindingStatus = FindingStatus.UNVERIFIED
    raw_data: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Sample & Job models
# ---------------------------------------------------------------------------

class SampleInfo(BaseModel):
    """Metadata envelope for a binary sample under analysis."""

    filename: str
    sha256: str
    md5: Optional[str] = None
    sha1: Optional[str] = None
    file_size: int
    file_type: Optional[str] = None
    architecture: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class JobRequest(BaseModel):
    """Describes *what* work the caller wants performed on a sample."""

    job_type: str = "full"                      # identify, disassemble, decompile, trace, full
    tools: Optional[List[str]] = None           # specific tools to use, or None for auto
    options: Dict[str, Any] = Field(default_factory=dict)   # tool-specific options


class JobStatus(BaseModel):
    """Progress snapshot of a running or completed analysis job."""

    id: str
    sample_id: str
    job_type: str
    status: str
    progress: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    findings_count: int = 0


# ---------------------------------------------------------------------------
# Report model
# ---------------------------------------------------------------------------

class AnalysisReport(BaseModel):
    """
    Top-level aggregate returned to the caller after analysis completes.

    Contains all findings, job history, and the AI-generated summary.
    """

    project_name: str
    sample: SampleInfo
    findings: List[Finding]
    jobs: List[JobStatus]
    tools_used: List[str]
    generated_at: datetime
    summary: Dict[str, Any] = Field(default_factory=dict)
