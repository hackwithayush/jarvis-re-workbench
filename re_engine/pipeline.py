"""
Jarvis RE — Analysis Pipeline Manager
Orchestrates sample ingestion, sandbox workspace creation, tool routing,
sequential/parallel analysis execution, finding normalization, and persistent storage.
"""

import json
import logging
import os
import shutil
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from REVERSE_ENGINEERING.adapters import (
    BaseAdapter,
    NativePythonAdapter,
    DIEAdapter,
    GhidraAdapter,
    Radare2Adapter,
    FridaAdapter,
    AngrAdapter,
    ImHexAdapter,
    DnSpyAdapter,
    X64DbgAdapter,
)
from REVERSE_ENGINEERING.config import REConfig, WORKSPACE_ROOT, MAX_FILE_SIZE
from REVERSE_ENGINEERING.models import db, REProject, RESample, REFinding, REJob, RERuntimeTrace
from REVERSE_ENGINEERING.schema import Finding, FindingStatus, FindingType, SourceTool
from REVERSE_ENGINEERING.utils import (
    compute_hashes,
    detect_architecture,
    detect_file_type,
    create_workspace,
    validate_file_size,
    safe_json_serialize,
)

logger = logging.getLogger("jarvis.re.pipeline")


class AnalysisPipeline:
    """Core analysis orchestrator for the Reverse Engineering workbench."""

    def __init__(self, app=None):
        self.app = app
        self.adapters: Dict[str, BaseAdapter] = {}
        self._init_adapters()

    def _init_adapters(self) -> None:
        """Instantiate and register all known tool adapters."""
        all_adapters = [
            NativePythonAdapter(),
            DIEAdapter(),
            GhidraAdapter(),
            Radare2Adapter(),
            FridaAdapter(),
            AngrAdapter(),
            ImHexAdapter(),
            DnSpyAdapter(),
            X64DbgAdapter(),
        ]
        for adapter in all_adapters:
            self.adapters[adapter.TOOL_NAME] = adapter

        logger.info(
            f"Initialized RE Pipeline with {len(self.adapters)} adapters. "
            f"Available engines: {[k for k, v in self.adapters.items() if v.is_available()]}"
        )

    def get_tool_status(self) -> Dict[str, Any]:
        """Return availability, version, and supported formats for all adapters."""
        status_map = {}
        for name, adapter in self.adapters.items():
            status_map[name] = adapter.get_status()
        return status_map

    def _db_op(self, func):
        """Execute a function within Flask application context if app is configured."""
        if self.app:
            with self.app.app_context():
                return func()
        return func()

    def register_sample(
        self,
        file_path: str,
        project_id: str,
        filename: Optional[str] = None,
    ) -> RESample:
        """
        Ingest and register a sample binary:
        1. Validates existence and file size limits.
        2. Computes SHA-256, MD5, and SHA-1 hashes.
        3. Identifies file format and CPU architecture.
        4. Allocates an isolated workspace jail.
        5. Copies sample securely to workspace.
        6. Persists sample metadata to the database.
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Target sample not found: {file_path}")

        if not validate_file_size(file_path, MAX_FILE_SIZE):
            raise ValueError(f"File size exceeds safety limit of {MAX_FILE_SIZE} bytes.")

        hashes = compute_hashes(file_path)
        sha256 = hashes["sha256"]
        file_size = os.path.getsize(file_path)
        arch = detect_architecture(file_path)
        fmt = detect_file_type(file_path) or "Unknown/Raw"
        orig_name = filename or os.path.basename(file_path)

        # Allocate workspace
        ws_path = create_workspace(sha256)
        dest_sample_path = os.path.join(ws_path, orig_name)
        if not os.path.exists(dest_sample_path):
            shutil.copy2(file_path, dest_sample_path)

        metadata = {
            "hashes": hashes,
            "original_path": file_path,
            "architecture": arch,
            "format": fmt,
            "file_size": file_size,
            "registered_at": datetime.now(timezone.utc).isoformat(),
        }

        def _create_sample():
            # Check if project exists
            project = db.session.get(REProject, project_id)
            if not project:
                raise ValueError(f"RE Project {project_id} does not exist.")

            # Check if sample already registered in this project
            existing = RESample.query.filter_by(project_id=project_id, sha256=sha256).first()
            if existing:
                db.session.refresh(existing)
                db.session.expunge(existing)
                return existing

            sample = RESample(
                id=str(uuid.uuid4()),
                project_id=project_id,
                filename=orig_name,
                sha256=sha256,
                md5=hashes["md5"],
                sha1=hashes["sha1"],
                file_size=file_size,
                file_type=fmt,
                architecture=arch,
                workspace_path=ws_path,
                metadata_json=metadata,
            )
            db.session.add(sample)
            db.session.commit()
            db.session.refresh(sample)
            db.session.expunge(sample)
            return sample

        return self._db_op(_create_sample)

    def route_tools(self, file_type: str, requested_tools: Optional[List[str]] = None) -> List[str]:
        """
        Deterministically select analysis engines based on binary format and tool availability.
        """
        available = {k: v for k, v in self.adapters.items() if v.is_available()}
        chosen: List[str] = []

        if requested_tools:
            for t in requested_tools:
                if t in available:
                    chosen.append(t)
                else:
                    logger.warning(f"Requested tool '{t}' is not available on this host.")
            if chosen:
                return chosen

        # Standard automated routing policy:
        # 1. Native Python analyzer is ALWAYS run (extracts strings, entropy, sections, entry points).
        if "python" in available:
            chosen.append("python")

        # 2. DIE for fast compiler/packer triage
        if "die" in available:
            chosen.append("die")

        # 3. .NET Assemblies -> dnSpy / ILSpy
        if "PE/.NET" in file_type and "dnspy" in available:
            chosen.append("dnspy")

        # 4. Native Executables -> Ghidra or radare2
        if any(x in file_type for x in ["PE", "ELF", "Mach-O"]):
            if "ghidra" in available:
                chosen.append("ghidra")
            elif "radare2" in available:
                chosen.append("radare2")

        # 5. Raw or custom binary -> ImHex
        if file_type in ["raw", "binary", "Unknown/Raw"] and "imhex" in available:
            chosen.append("imhex")

        return chosen

    def run_analysis(
        self,
        sample_id: str,
        job_type: str = "full",
        tools_requested: Optional[List[str]] = None,
        options: Optional[dict] = None,
    ) -> str:
        """
        Execute an analysis pipeline run for the given sample.
        Returns the job UUID.
        """
        options = options or {}

        def _init_job():
            sample = db.session.get(RESample, sample_id)
            if not sample:
                raise ValueError(f"Sample not found: {sample_id}")

            active_tools = self.route_tools(sample.file_type or "", tools_requested)
            job = REJob(
                id=str(uuid.uuid4()),
                sample_id=sample_id,
                job_type=job_type,
                tools_requested=active_tools,
                status="running",
                progress=5,
                started_at=datetime.now(timezone.utc),
            )
            db.session.add(job)
            db.session.commit()
            return job.id, sample.id, sample.filename, sample.workspace_path, sample.sha256, active_tools

        job_id, s_id, s_name, ws_path, s_sha256, active_tools = self._db_op(_init_job)

        sample_file_path = os.path.join(ws_path, s_name)
        total_tools = len(active_tools)
        collected_findings: List[Dict[str, Any]] = []
        execution_log: List[str] = [f"Analysis pipeline started with engines: {active_tools}"]

        try:
            for idx, tool_name in enumerate(active_tools):
                adapter = self.adapters.get(tool_name)
                if not adapter:
                    continue

                execution_log.append(f"Executing {tool_name} engine...")
                try:
                    tool_findings = adapter.analyze(sample_file_path, ws_path, options)
                    execution_log.append(f"{tool_name} returned {len(tool_findings)} findings.")
                    for f in tool_findings:
                        f["sample_sha256"] = s_sha256
                        collected_findings.append(f)
                except Exception as err:
                    logger.error(f"Engine {tool_name} encountered an error: {err}", exc_info=True)
                    execution_log.append(f"Engine {tool_name} failed: {str(err)}")

                # Update intermediate progress
                curr_prog = int(10 + ((idx + 1) / max(total_tools, 1)) * 80)
                self._update_job_progress(job_id, curr_prog, "\n".join(execution_log))

            # Persist findings to database
            def _save_findings():
                for f_data in collected_findings:
                    finding = REFinding(
                        sample_id=s_id,
                        sample_sha256=s_sha256,
                        source_tool=f_data.get("source_tool", "python"),
                        finding_type=f_data.get("finding_type", "metadata"),
                        address=f_data.get("address"),
                        name=f_data.get("name"),
                        description=f_data.get("description"),
                        evidence=f_data.get("evidence", []),
                        confidence=float(f_data.get("confidence", 0.5)),
                        status=f_data.get("status", "unverified"),
                        raw_data=f_data.get("raw_data", {}),
                    )
                    db.session.add(finding)

                job = db.session.get(REJob, job_id)
                if job:
                    job.status = "completed"
                    job.progress = 100
                    job.completed_at = datetime.now(timezone.utc)
                    job.result_summary = {
                        "total_findings": len(collected_findings),
                        "tools_executed": active_tools,
                    }
                    job.log = "\n".join(execution_log)
                db.session.commit()

            self._db_op(_save_findings)
            logger.info(f"Analysis job {job_id} successfully completed with {len(collected_findings)} findings.")
            return job_id

        except Exception as exc:
            logger.critical(f"Analysis pipeline crashed for job {job_id}: {exc}", exc_info=True)
            def _fail_job():
                job = db.session.get(REJob, job_id)
                if job:
                    job.status = "failed"
                    job.completed_at = datetime.now(timezone.utc)
                    job.error_message = str(exc)
                    job.log = "\n".join(execution_log) + f"\nFATAL: {exc}"
                    db.session.commit()
            self._db_op(_fail_job)
            raise

    def _update_job_progress(self, job_id: str, progress: int, log_text: str) -> None:
        def _update():
            job = db.session.get(REJob, job_id)
            if job:
                job.progress = progress
                job.log = log_text
                db.session.commit()
        self._db_op(_update)
