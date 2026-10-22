"""
JARVIS RE — Job Management & Background Execution Engine v1.0
Asynchronously manages long-running multi-engine binary analyses:
- Queuing, background thread execution, real-time stage updates, and progress tracking.
- Polling endpoints (`/api/jobs/{job_id}`) preventing HTTP request timeouts.
- Task cancellation and temporary workspace cleanup.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from enum import Enum
import logging
import os
import shutil
import threading
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field

from app.core.analyzer import BinaryAnalyzer
from app.core.disassembler import DisassemblyEngine
from app.core.evidence_engine import EvidenceCorrelationEngine
from app.core.reporter import ReportGenerator
from app.core.schema import AnalysisReport
from app.core.tools import ToolAuditor

logger = logging.getLogger("jarvis.re.jobs")


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AnalysisJob(BaseModel):
    job_id: str
    status: JobStatus = JobStatus.QUEUED
    progress_pct: int = 0
    current_stage: str = "Queued"
    filename: str
    file_size: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    report: Optional[AnalysisReport] = None
    logs: List[str] = Field(default_factory=list)
    error: Optional[str] = None


class JobManager:
    """Manages asynchronous binary analysis jobs."""

    def __init__(self, max_workers: int = 3):
        self.jobs: Dict[str, AnalysisJob] = {}
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="jarvis_re_worker")
        self._lock = threading.Lock()

    def create_job(self, file_path: str, filename: str, options: Optional[Dict[str, Any]] = None) -> AnalysisJob:
        job_id = str(uuid.uuid4())[:12]
        job = AnalysisJob(
            job_id=job_id,
            status=JobStatus.QUEUED,
            progress_pct=5,
            current_stage="Job created and queued",
            filename=filename,
            file_size=os.path.getsize(file_path) if os.path.isfile(file_path) else 0,
            logs=[f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] Job {job_id} queued for {filename}"],
        )

        with self._lock:
            self.jobs[job_id] = job

        self.executor.submit(self._run_job, job_id, file_path, options or {})
        return job

    def get_job(self, job_id: str) -> Optional[AnalysisJob]:
        with self._lock:
            return self.jobs.get(job_id)

    def list_jobs(self) -> List[AnalysisJob]:
        with self._lock:
            return list(self.jobs.values())

    def _update_stage(self, job: AnalysisJob, pct: int, stage: str):
        job.progress_pct = pct
        job.current_stage = stage
        job.logs.append(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {stage}")
        logger.info("[Job %s] (%d%%) %s", job.job_id, pct, stage)

    def _run_job(self, job_id: str, file_path: str, options: Dict[str, Any]):
        job = self.get_job(job_id)
        if not job:
            return

        job.status = JobStatus.RUNNING

        try:
            # Stage 1: Static Parsing & Triage
            self._update_stage(job, 15, "Parsing executable structure, sections, and hashes...")
            analyzer = BinaryAnalyzer(file_path)
            sample_info, raw_findings = analyzer.analyze(options=options)

            # Stage 2: Deep Disassembly & Decompilation
            self._update_stage(job, 45, "Executing disassembly recovery and CFG extraction...")
            disasm_engine = DisassemblyEngine()
            enriched_functions = disasm_engine.enrich_functions(file_path, analyzer.functions, limit=10)

            # Stage 3: Evidence Correlation & Hypotheses
            self._update_stage(job, 75, "Correlating cross-tool evidence and evaluating confidence...")
            deduped_findings, hypotheses, assessment = EvidenceCorrelationEngine.correlate(
                raw_findings,
                imphash=sample_info.imphash,
                entropy=sample_info.entropy,
                is_dotnet="NET" in sample_info.file_type,
            )

            # Stage 4: Report Synthesis
            self._update_stage(job, 90, "Synthesizing unified evidence report...")
            tools_status = ToolAuditor.audit_all()

            report = ReportGenerator.build_report(
                sample=sample_info,
                findings=deduped_findings,
                tools_audited=tools_status,
                sections=analyzer.sections,
                imports=analyzer.imports,
                exports=analyzer.exports,
                functions=enriched_functions,
                archive_members=analyzer.archive_members,
                tool_executions=analyzer.tool_executions,
                ai_hypotheses=hypotheses,
                assessment=assessment,
                string_stats=analyzer.string_stats,
                report_id=job.job_id,
            )

            job.report = report
            self._update_stage(job, 100, "Analysis complete. Report generated.")
            job.status = JobStatus.COMPLETED
            job.completed_at = datetime.now(timezone.utc)

        except Exception as e:
            logger.error("Job %s failed: %s", job_id, e, exc_info=True)
            job.status = JobStatus.FAILED
            job.error = str(e)
            self._update_stage(job, 100, f"Analysis failed: {str(e)}")
            job.completed_at = datetime.now(timezone.utc)

        finally:
            # Clean up uploaded temporary binary
            if os.path.isfile(file_path):
                try:
                    os.remove(file_path)
                except Exception:
                    pass


# Global singleton instance
job_manager = JobManager()
