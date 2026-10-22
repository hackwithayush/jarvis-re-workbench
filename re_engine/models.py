"""
Jarvis RE — SQLAlchemy ORM models for the Reverse Engineering module.

All models share the existing Flask-SQLAlchemy ``db`` instance from
``models.py`` so they live in the same SQLite database (``data/jarvis.db``).
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from models import db

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _uuid() -> str:
    """Generate a new UUID4 string."""
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    """Timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def _isoformat(dt: Optional[datetime]) -> Optional[str]:
    """Safely convert a datetime to ISO-8601 string."""
    return dt.isoformat() if dt else None


# ---------------------------------------------------------------------------
# REProject
# ---------------------------------------------------------------------------

class REProject(db.Model):  # type: ignore[name-defined]
    """Top-level container grouping related binary samples."""

    __tablename__ = "re_projects"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, default="")
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    status = db.Column(db.String(32), default="active")  # active / archived / deleted
    created_at = db.Column(db.DateTime, default=_utcnow)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow)

    # Relationships
    samples = db.relationship(
        "RESample",
        backref="project",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable dictionary of this project."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "user_id": self.user_id,
            "status": self.status,
            "created_at": _isoformat(self.created_at),
            "updated_at": _isoformat(self.updated_at),
            "sample_count": self.samples.count() if self.samples else 0,
        }


# ---------------------------------------------------------------------------
# RESample
# ---------------------------------------------------------------------------

class RESample(db.Model):  # type: ignore[name-defined]
    """A single binary sample ingested for analysis."""

    __tablename__ = "re_samples"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    project_id = db.Column(
        db.String(36), db.ForeignKey("re_projects.id"), nullable=False
    )
    filename = db.Column(db.String(512), nullable=False)
    sha256 = db.Column(db.String(64), nullable=False, index=True)
    md5 = db.Column(db.String(32), nullable=True)
    sha1 = db.Column(db.String(40), nullable=True)
    file_size = db.Column(db.BigInteger, nullable=False, default=0)
    file_type = db.Column(db.String(128), nullable=True)
    architecture = db.Column(db.String(32), nullable=True)
    workspace_path = db.Column(db.String(1024), nullable=True)
    metadata_json = db.Column(db.JSON, default=dict)
    created_at = db.Column(db.DateTime, default=_utcnow)

    # Relationships
    findings = db.relationship(
        "REFinding",
        backref="sample",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    jobs = db.relationship(
        "REJob",
        backref="sample",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    traces = db.relationship(
        "RERuntimeTrace",
        backref="sample",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable dictionary of this sample."""
        return {
            "id": self.id,
            "project_id": self.project_id,
            "filename": self.filename,
            "sha256": self.sha256,
            "md5": self.md5,
            "sha1": self.sha1,
            "file_size": self.file_size,
            "file_type": self.file_type,
            "architecture": self.architecture,
            "workspace_path": self.workspace_path,
            "metadata": self.metadata_json or {},
            "created_at": _isoformat(self.created_at),
        }


# ---------------------------------------------------------------------------
# REFinding
# ---------------------------------------------------------------------------

class REFinding(db.Model):  # type: ignore[name-defined]
    """An individual finding (function, string, import, etc.) from a tool run."""

    __tablename__ = "re_findings"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    sample_id = db.Column(
        db.String(36), db.ForeignKey("re_samples.id"), nullable=False
    )
    sample_sha256 = db.Column(db.String(64), nullable=False, index=True)
    source_tool = db.Column(db.String(32), nullable=False)
    finding_type = db.Column(db.String(32), nullable=False)
    address = db.Column(db.String(32), nullable=True)
    name = db.Column(db.String(512), nullable=True)
    description = db.Column(db.Text, nullable=True)
    evidence = db.Column(db.JSON, default=list)
    confidence = db.Column(db.Float, default=0.5)
    status = db.Column(db.String(32), default="unverified")
    raw_data = db.Column(db.JSON, default=dict)
    created_at = db.Column(db.DateTime, default=_utcnow)

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable dictionary of this finding."""
        return {
            "id": self.id,
            "sample_id": self.sample_id,
            "sample_sha256": self.sample_sha256,
            "source_tool": self.source_tool,
            "finding_type": self.finding_type,
            "address": self.address,
            "name": self.name,
            "description": self.description,
            "evidence": self.evidence or [],
            "confidence": self.confidence,
            "status": self.status,
            "raw_data": self.raw_data or {},
            "created_at": _isoformat(self.created_at),
        }


# ---------------------------------------------------------------------------
# REJob
# ---------------------------------------------------------------------------

class REJob(db.Model):  # type: ignore[name-defined]
    """Tracks the lifecycle of a single analysis job."""

    __tablename__ = "re_jobs"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    sample_id = db.Column(
        db.String(36), db.ForeignKey("re_samples.id"), nullable=False
    )
    job_type = db.Column(db.String(64), nullable=False)
    tools_requested = db.Column(db.JSON, default=list)
    status = db.Column(db.String(32), default="pending")  # pending/running/completed/failed/cancelled
    progress = db.Column(db.Integer, default=0)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    result_summary = db.Column(db.JSON, default=dict)
    log = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=_utcnow)

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable dictionary of this job."""
        return {
            "id": self.id,
            "sample_id": self.sample_id,
            "job_type": self.job_type,
            "tools_requested": self.tools_requested or [],
            "status": self.status,
            "progress": self.progress,
            "started_at": _isoformat(self.started_at),
            "completed_at": _isoformat(self.completed_at),
            "error_message": self.error_message,
            "result_summary": self.result_summary or {},
            "log": self.log,
            "created_at": _isoformat(self.created_at),
        }


# ---------------------------------------------------------------------------
# RERuntimeTrace
# ---------------------------------------------------------------------------

class RERuntimeTrace(db.Model):  # type: ignore[name-defined]
    """A single event captured during dynamic / runtime analysis."""

    __tablename__ = "re_runtime_traces"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    sample_id = db.Column(
        db.String(36), db.ForeignKey("re_samples.id"), nullable=False
    )
    source_tool = db.Column(db.String(32), nullable=False)
    trace_type = db.Column(db.String(64), nullable=False)
    address = db.Column(db.String(32), nullable=True)
    data = db.Column(db.JSON, default=dict)
    timestamp_ns = db.Column(db.BigInteger, nullable=True)
    created_at = db.Column(db.DateTime, default=_utcnow)

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable dictionary of this trace event."""
        return {
            "id": self.id,
            "sample_id": self.sample_id,
            "source_tool": self.source_tool,
            "trace_type": self.trace_type,
            "address": self.address,
            "data": self.data or {},
            "timestamp_ns": self.timestamp_ns,
            "created_at": _isoformat(self.created_at),
        }
