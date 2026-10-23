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
from pydantic import BaseModel, Field, computed_field


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
    BEHAVIOR_EVENT = "behavior_event"
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
    limitations: List[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Software Knowledge Graph & Reconstruction Models
# ---------------------------------------------------------------------------

class EvidenceStatus(str, Enum):
    OBSERVED = "observed"
    STATICALLY_INFERRED = "statically_inferred"
    DYNAMICALLY_OBSERVED = "dynamically_observed"
    UNVERIFIED = "unverified"


class RequirementClassification(str, Enum):
    VERIFIED_FROM_EVIDENCE = "verified_from_evidence"
    STRONGLY_INFERRED = "strongly_inferred"
    PROPOSED_REPLACEMENT = "proposed_replacement"
    UNKNOWN_REQUIRING_INPUT = "unknown_requiring_input"


class GraphNode(BaseModel):
    id: str
    label: str
    node_type: str  # module, component, class, function, endpoint, storage, workflow, external_api
    subsystem: Optional[str] = "core"
    description: Optional[str] = None
    source_tool: str = "reconstruction_engine"
    source_location: Optional[str] = None
    evidence_status: EvidenceStatus = EvidenceStatus.STATICALLY_INFERRED
    confidence: float = 0.85
    properties: Dict[str, Any] = Field(default_factory=dict)

    @property
    def type(self) -> str:
        return self.node_type


class GraphEdge(BaseModel):
    source_id: str
    target_id: str
    relation: str  # calls, depends_on, instantiates, writes_to, reads_from, invokes_api, triggers_transition
    evidence_reference: Optional[str] = None
    confidence: float = 0.85


class KnowledgeGraphData(BaseModel):
    graph_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    sample_sha256: str
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    subsystems: List[str] = Field(default_factory=list)
    entry_points: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @computed_field
    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @computed_field
    @property
    def edge_count(self) -> int:
        return len(self.edges)


class ReconstructionRequirement(BaseModel):
    id: str = Field(default_factory=lambda: f"req_{uuid.uuid4().hex[:8]}")
    section: str
    title: str
    description: str
    classification: RequirementClassification = RequirementClassification.VERIFIED_FROM_EVIDENCE
    evidence_sources: List[str] = Field(default_factory=list)
    confidence: float = 0.90


class ReconstructionSpecification(BaseModel):
    spec_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    sample_sha256: str
    project_name: str
    product_purpose: str
    functional_requirements: List[ReconstructionRequirement] = Field(default_factory=list)
    features_and_workflows: List[ReconstructionRequirement] = Field(default_factory=list)
    system_architecture: List[ReconstructionRequirement] = Field(default_factory=list)
    api_contracts_and_data_models: List[ReconstructionRequirement] = Field(default_factory=list)
    ui_behavior_specs: List[ReconstructionRequirement] = Field(default_factory=list)
    storage_and_config: List[ReconstructionRequirement] = Field(default_factory=list)
    error_handling_and_performance: List[ReconstructionRequirement] = Field(default_factory=list)
    security_and_privacy: List[ReconstructionRequirement] = Field(default_factory=list)
    acceptance_criteria: List[ReconstructionRequirement] = Field(default_factory=list)
    known_unknowns: List[ReconstructionRequirement] = Field(default_factory=list)
    target_framework: str = "python_fastapi"
    approved: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @computed_field
    @property
    def sections(self) -> Dict[str, List[ReconstructionRequirement]]:
        return {
            "1. Executive Summary & Software Intent": self.functional_requirements,
            "2. Observable Behaviors vs Replaced Capabilities": self.features_and_workflows,
            "3. Component Architecture & Subsystems": self.system_architecture,
            "4. Data Models, Storage & State Flow": self.api_contracts_and_data_models,
            "5. Interfaces, Endpoints & Data Contracts": self.ui_behavior_specs,
            "6. External Dependencies & Clean-Room Replacements": self.storage_and_config,
            "7. Verification & Behavioral Conformance Criteria": self.acceptance_criteria,
            "8. Non-functional, Performance & Scalability Requirements": self.error_handling_and_performance,
            "9. Ethical, Safety, Privacy & Clean-Room Boundaries": self.security_and_privacy,
            "10. Step-by-Step Construction Roadmap": self.known_unknowns,
        }

    @property
    def requirements(self) -> List[ReconstructionRequirement]:
        return (
            self.functional_requirements
            + self.features_and_workflows
            + self.system_architecture
            + self.api_contracts_and_data_models
            + self.ui_behavior_specs
            + self.storage_and_config
            + self.error_handling_and_performance
            + self.security_and_privacy
            + self.acceptance_criteria
            + self.known_unknowns
        )


class GeneratedProject(BaseModel):
    project_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:10])
    spec_id: str
    name: str
    target_framework: str
    workspace_dir: str
    source_files: Dict[str, str] = Field(default_factory=dict)
    test_files: Dict[str, str] = Field(default_factory=dict)
    config_files: Dict[str, str] = Field(default_factory=dict)
    manifest_file: str = "requirements.txt"
    documentation: Dict[str, str] = Field(default_factory=dict)
    clean_room_verified: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def project_path(self) -> str:
        return self.workspace_dir

    @computed_field
    @property
    def files_generated(self) -> List[str]:
        return (
            list(self.source_files.keys())
            + [f"tests/{f}" for f in self.test_files.keys()]
            + list(self.config_files.keys())
            + list(self.documentation.keys())
        )


class BuildReport(BaseModel):
    build_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:10])
    project_id: str
    status: str = "pending"  # success, failed, in_progress, repairing
    compilation_passed: bool = False
    tests_total: int = 0
    tests_passed: int = 0
    tests_failed: int = 0
    test_output: str = ""
    build_logs: List[str] = Field(default_factory=list)
    packaged_artifact_path: Optional[str] = None
    repair_attempts: int = 0
    repair_log: List[Dict[str, Any]] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def compilation_success(self) -> bool:
        return self.compilation_passed

    @property
    def overall_success(self) -> bool:
        return self.status == "success"

    @property
    def artifact_path(self) -> Optional[str]:
        return self.packaged_artifact_path


class DifferentialScenario(BaseModel):
    scenario_id: str
    name: str
    linked_requirement: Optional[str] = None
    inputs: Dict[str, Any] = Field(default_factory=dict)
    original_observation: str
    reconstructed_observation: str
    comparison_method: str = "semantic_and_contract"
    status: str = "PASS"  # PASS, FAIL, BLOCKED


class DifferentialTestResult(BaseModel):
    test_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:10])
    project_id: str
    reference_sample: str
    matching_behaviors: List[str] = Field(default_factory=list)
    discrepancies: List[str] = Field(default_factory=list)
    uncovered_workflows: List[str] = Field(default_factory=list)
    failed_acceptance_criteria: List[str] = Field(default_factory=list)
    scenarios: List[Dict[str, Any]] = Field(default_factory=list)
    overall_conformance_score: float = 0.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def total_checks(self) -> int:
        return len(self.matching_behaviors) + len(self.discrepancies)

    @property
    def passed_checks(self) -> int:
        return len(self.matching_behaviors)

    @property
    def conformance_score(self) -> float:
        return self.overall_conformance_score

    @property
    def status(self) -> str:
        if self.overall_conformance_score >= 0.8:
            return "PASS"
        return "CONFORMANT_WITH_TOLERANCES" if self.overall_conformance_score >= 0.5 else "FAIL"
