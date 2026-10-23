"""
JARVIS RE — Job Management & Workflow Orchestration Engine v2.0
Asynchronously manages multi-engine binary analyses and reconstruction workflows:
- State machine lifecycle (QUEUED, ANALYZING, SPEC_REVIEW, GENERATING, BUILDING, TESTING, REPAIRING, BLOCKED, FAILED, CANCELLED, VERIFIED, COMPLETED).
- Job persistence to disk (workspace/jobs/<job_id>.json) surviving server restarts.
- Graceful cancellation, retry budgets, progress telemetry, and thread pool workers.
- Safe sample retention avoiding accidental removal of reference binaries.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from enum import Enum
import json
import logging
import os
import shutil
import threading
from typing import Any, Dict, List, Optional, Set
import uuid

from pydantic import BaseModel, Field

from app.core.analyzer import BinaryAnalyzer
from app.core.evidence_engine import EvidenceCorrelationEngine
from app.core.reporter import ReportGenerator
from app.core.schema import AnalysisReport
from app.core.tools import ToolAuditor

logger = logging.getLogger("jarvis.re.jobs")


class JobStatus(str, Enum):
    """
    JARVIS RE Workflow Lifecycle States:
    - QUEUED: Job accepted and awaiting worker allocation.
    - RUNNING: Active execution in progress.
    - ANALYZING: Deep multi-engine reverse-engineering pass active.
    - SPEC_REVIEW: Awaiting or undergoing analyst specification review.
    - GENERATING: Synthesizing independent clean-room software project.
    - BUILDING: Isolated compilation and build verification active.
    - TESTING: Running automated test battery in sandbox.
    - REPAIRING: Bounded autonomous repair loop active (max 3 retries).
    - BLOCKED: Suspended awaiting external dependency or intervention.
    - FAILED: Terminal execution failure.
    - CANCELLED: Operator cancelled workflow.
    - VERIFIED: Quality gates passed: compilation, 100% tests, and differential equivalence criteria met.
    - COMPLETED: Terminal workflow execution finished (reports generated, artifacts persisted).
    """
    QUEUED = "queued"
    RUNNING = "running"
    ANALYZING = "analyzing"
    SPEC_REVIEW = "spec_review"
    GENERATING = "generating"
    BUILDING = "building"
    TESTING = "testing"
    REPAIRING = "repairing"
    BLOCKED = "blocked"
    FAILED = "failed"
    CANCELLED = "cancelled"
    VERIFIED = "verified"
    COMPLETED = "completed"


VALID_TRANSITIONS: Dict[JobStatus, Set[JobStatus]] = {
    JobStatus.QUEUED: {JobStatus.RUNNING, JobStatus.ANALYZING, JobStatus.CANCELLED, JobStatus.FAILED},
    JobStatus.RUNNING: {
        JobStatus.ANALYZING,
        JobStatus.SPEC_REVIEW,
        JobStatus.GENERATING,
        JobStatus.BUILDING,
        JobStatus.TESTING,
        JobStatus.REPAIRING,
        JobStatus.VERIFIED,
        JobStatus.COMPLETED,
        JobStatus.BLOCKED,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
    },
    JobStatus.ANALYZING: {
        JobStatus.RUNNING,
        JobStatus.SPEC_REVIEW,
        JobStatus.GENERATING,
        JobStatus.BUILDING,
        JobStatus.TESTING,
        JobStatus.VERIFIED,
        JobStatus.COMPLETED,
        JobStatus.BLOCKED,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
    },
    JobStatus.SPEC_REVIEW: {JobStatus.GENERATING, JobStatus.BLOCKED, JobStatus.FAILED, JobStatus.CANCELLED},
    JobStatus.GENERATING: {JobStatus.BUILDING, JobStatus.BLOCKED, JobStatus.FAILED, JobStatus.CANCELLED},
    JobStatus.BUILDING: {JobStatus.TESTING, JobStatus.REPAIRING, JobStatus.BLOCKED, JobStatus.FAILED, JobStatus.CANCELLED},
    JobStatus.TESTING: {JobStatus.VERIFIED, JobStatus.REPAIRING, JobStatus.COMPLETED, JobStatus.BLOCKED, JobStatus.FAILED, JobStatus.CANCELLED},
    JobStatus.REPAIRING: {JobStatus.BUILDING, JobStatus.TESTING, JobStatus.BLOCKED, JobStatus.FAILED, JobStatus.CANCELLED},
    JobStatus.BLOCKED: {
        JobStatus.ANALYZING,
        JobStatus.SPEC_REVIEW,
        JobStatus.GENERATING,
        JobStatus.BUILDING,
        JobStatus.TESTING,
        JobStatus.REPAIRING,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
    },
    JobStatus.VERIFIED: {JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED},
    JobStatus.COMPLETED: set(),
    JobStatus.FAILED: set(),
    JobStatus.CANCELLED: set(),
}


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
    retry_budget: int = 3
    retry_count: int = 0
    cancellation_requested: bool = False

    def can_transition_to(self, target: JobStatus) -> bool:
        if self.status == target:
            return True
        allowed = VALID_TRANSITIONS.get(self.status, set())
        return target in allowed

    def transition_to(self, target: JobStatus, stage_desc: Optional[str] = None):
        if not self.can_transition_to(target):
            raise ValueError(f"Illegal workflow transition from '{self.status}' to '{target}' for job {self.job_id}")
        self.status = target
        if stage_desc:
            self.current_stage = stage_desc
            self.logs.append(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {stage_desc}")

    @property
    def is_verified(self) -> bool:
        """Indicates whether all verification and quality gates passed (static compilation, unit tests, differential equivalence)."""
        return self.status == JobStatus.VERIFIED or (self.report is not None and getattr(self.report, "clean_room_verified", False))

    @property
    def is_terminal(self) -> bool:
        """Indicates whether the workflow execution lifecycle has terminated."""
        return self.status in {JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED}


class JobManager:
    """Manages asynchronous binary analysis and reconstruction jobs with disk persistence."""

    def __init__(self, max_workers: int = 3, jobs_dir: Optional[str] = None):
        self.jobs: Dict[str, AnalysisJob] = {}
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="jarvis_re_worker")
        self._lock = threading.Lock()

        if jobs_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            self.jobs_dir = os.path.join(base_dir, "workspace", "jobs")
        else:
            self.jobs_dir = jobs_dir

        os.makedirs(self.jobs_dir, exist_ok=True)
        self._load_persisted_jobs()

    def _persist_job(self, job: AnalysisJob):
        """Serialize job state to disk for restart durability."""
        if not self.jobs_dir:
            return
        try:
            os.makedirs(self.jobs_dir, exist_ok=True)
            job_file = os.path.join(self.jobs_dir, f"{job.job_id}.json")
            temp_file = f"{job_file}.tmp"
            with open(temp_file, "w", encoding="utf-8") as f:
                f.write(job.model_dump_json(indent=2))
            os.replace(temp_file, job_file)
        except Exception as e:
            logger.debug("Failed to persist job %s to disk: %s", job.job_id, e)

    def _load_persisted_jobs(self):
        """Reload historical jobs from disk on engine initialization."""
        if not os.path.isdir(self.jobs_dir):
            return
        count = 0
        for entry in os.listdir(self.jobs_dir):
            if entry.endswith(".json") and not entry.endswith(".tmp"):
                fpath = os.path.join(self.jobs_dir, entry)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        raw = f.read()
                        job = AnalysisJob.model_validate_json(raw)
                        self.jobs[job.job_id] = job
                        count += 1
                except Exception as e:
                    logger.debug("Could not parse saved job file %s: %s", entry, e)
        if count > 0:
            logger.info("Loaded %d persisted analysis jobs from %s", count, self.jobs_dir)

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
            self._persist_job(job)

        self.executor.submit(self._run_job, job_id, file_path, options or {})
        return job

    def get_job(self, job_id: str) -> Optional[AnalysisJob]:
        with self._lock:
            return self.jobs.get(job_id)

    def list_jobs(self) -> List[AnalysisJob]:
        with self._lock:
            return list(self.jobs.values())

    def cancel_job(self, job_id: str) -> bool:
        """Gracefully cancel an active job."""
        with self._lock:
            job = self.jobs.get(job_id)
            if not job:
                return False
            if job.status in {JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED}:
                return False
            job.cancellation_requested = True
            job.status = JobStatus.CANCELLED
            self._update_stage(job, job.progress_pct, "Analysis cancelled by operator.")
            job.completed_at = datetime.now(timezone.utc)
            self._persist_job(job)
            return True

    def _update_stage(self, job: AnalysisJob, pct: int, stage: str):
        job.progress_pct = pct
        job.current_stage = stage
        job.logs.append(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {stage}")
        logger.info("[Job %s] (%d%%) %s", job.job_id, pct, stage)
        self._persist_job(job)

    def _run_job(self, job_id: str, file_path: str, options: Dict[str, Any]):
        job = self.get_job(job_id)
        if not job:
            return

        job.status = JobStatus.RUNNING
        self._persist_job(job)

        try:
            if job.cancellation_requested or job.status == JobStatus.CANCELLED:
                return

            # Stage 1: Static Parsing & Triage
            self._update_stage(job, 15, "Parsing executable structure, sections, and hashes...")
            analyzer = BinaryAnalyzer(file_path)
            sample_info, raw_findings = analyzer.analyze(options=options)

            if job.cancellation_requested or job.status == JobStatus.CANCELLED:
                return

            # Stage 2: Disassembly & Function Extraction
            self._update_stage(job, 55, "Disassembly recovery and CFG extraction complete...")
            enriched_functions = analyzer.functions

            if job.cancellation_requested or job.status == JobStatus.CANCELLED:
                return

            # Stage 3: Evidence Correlation & Hypotheses
            self._update_stage(job, 75, "Correlating cross-tool evidence and evaluating confidence...")
            deduped_findings, hypotheses, assessment = EvidenceCorrelationEngine.correlate(
                raw_findings,
                imphash=sample_info.imphash,
                entropy=sample_info.entropy,
                is_dotnet="NET" in sample_info.file_type,
            )

            if job.cancellation_requested or job.status == JobStatus.CANCELLED:
                return

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
            self._update_stage(job, 100, f"Analysis complete. Generated report ID: {job.job_id}")
            job.status = JobStatus.COMPLETED
            job.completed_at = datetime.now(timezone.utc)
            self._persist_job(job)

            # Store in report cache and sample storage for instant sandbox & deep RE access
            try:
                import app.main as app_main
                app_main.REPORTS_CACHE[job.job_id] = report
                app_main.REPORTS_CACHE[report.report_id] = report
                app_main.SAMPLES_STORAGE[job.job_id] = file_path
                app_main.SAMPLES_STORAGE[report.report_id] = file_path
                app_main.SAMPLES_STORAGE[job.filename] = file_path
            except Exception:
                pass

        except Exception as e:
            logger.error("Job %s failed: %s", job_id, e, exc_info=True)
            job.status = JobStatus.FAILED
            job.error = str(e)
            self._update_stage(job, 100, f"Analysis failed: {str(e)}")
            job.completed_at = datetime.now(timezone.utc)
            self._persist_job(job)

        finally:
            # Clean up only ephemeral temporary files, preserving workspace and reference samples
            if os.path.isfile(file_path):
                norm_p = os.path.abspath(file_path).lower()
                if "workspace" not in norm_p and "samples" not in norm_p and ("tmp" in norm_p or "temp" in norm_p):
                    try:
                        os.remove(file_path)
                    except Exception:
                        pass


# Global singleton instance
job_manager = JobManager()
