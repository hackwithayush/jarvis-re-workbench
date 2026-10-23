"""
Test Suite: Phase 1 — Durable Workflow Orchestration & Persistence
Tests state machine transitions, disk persistence across restarts, and job cancellation.
"""

from datetime import datetime, timezone
import json
import os
import shutil
import tempfile
import pytest

from app.core.job_manager import AnalysisJob, JobManager, JobStatus, VALID_TRANSITIONS


def test_job_status_enum_values():
    """Verify all required lifecycle states exist in JobStatus."""
    expected_states = [
        "queued",
        "running",
        "analyzing",
        "spec_review",
        "generating",
        "building",
        "testing",
        "repairing",
        "blocked",
        "failed",
        "cancelled",
        "verified",
        "completed",
    ]
    for st in expected_states:
        assert st in [e.value for e in JobStatus]


def test_valid_state_transitions():
    """Verify valid transitions execute without error."""
    job = AnalysisJob(job_id="test_job_1", filename="sample.exe", status=JobStatus.QUEUED)
    assert job.can_transition_to(JobStatus.ANALYZING)
    job.transition_to(JobStatus.ANALYZING, "Beginning deep binary analysis")
    assert job.status == JobStatus.ANALYZING
    assert "Beginning deep binary analysis" in job.current_stage

    assert job.can_transition_to(JobStatus.SPEC_REVIEW)
    job.transition_to(JobStatus.SPEC_REVIEW, "Awaiting analyst specification review")
    assert job.status == JobStatus.SPEC_REVIEW

    assert job.can_transition_to(JobStatus.GENERATING)
    job.transition_to(JobStatus.GENERATING, "Generating independent project")
    assert job.status == JobStatus.GENERATING

    assert job.can_transition_to(JobStatus.BUILDING)
    job.transition_to(JobStatus.BUILDING, "Building in sandbox")
    assert job.status == JobStatus.BUILDING

    assert job.can_transition_to(JobStatus.TESTING)
    job.transition_to(JobStatus.TESTING, "Running tests")
    assert job.status == JobStatus.TESTING

    assert job.can_transition_to(JobStatus.VERIFIED)
    job.transition_to(JobStatus.VERIFIED, "Differential verification passed")
    assert job.status == JobStatus.VERIFIED

    assert job.can_transition_to(JobStatus.COMPLETED)
    job.transition_to(JobStatus.COMPLETED, "Workflow complete")
    assert job.status == JobStatus.COMPLETED


def test_invalid_state_transitions_raise_value_error():
    """Verify illegal transitions are rejected with ValueError."""
    job = AnalysisJob(job_id="test_job_2", filename="sample.exe", status=JobStatus.COMPLETED)
    # Cannot transition from completed to analyzing
    assert not job.can_transition_to(JobStatus.ANALYZING)
    with pytest.raises(ValueError, match="Illegal workflow transition"):
        job.transition_to(JobStatus.ANALYZING)


def test_job_persistence_survives_restarts():
    """Verify jobs written to disk can be completely restored by a new JobManager instance."""
    temp_dir = tempfile.mkdtemp()
    try:
        manager1 = JobManager(jobs_dir=temp_dir)
        job = AnalysisJob(
            job_id="job_persist_test_123",
            filename="test_binary.bin",
            status=JobStatus.SPEC_REVIEW,
            current_stage="Awaiting approval",
            progress_pct=60,
        )
        manager1.jobs[job.job_id] = job
        manager1._persist_job(job)

        # Confirm JSON exists on disk
        persisted_file = os.path.join(temp_dir, f"{job.job_id}.json")
        assert os.path.isfile(persisted_file)

        # Create a second JobManager pointing to the same directory
        manager2 = JobManager(jobs_dir=temp_dir)
        restored_job = manager2.get_job(job.job_id)
        assert restored_job is not None
        assert restored_job.job_id == job.job_id
        assert restored_job.status == JobStatus.SPEC_REVIEW
        assert restored_job.filename == "test_binary.bin"
        assert restored_job.progress_pct == 60
        assert "Awaiting approval" in restored_job.current_stage

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_job_cancellation():
    """Verify active jobs can be gracefully cancelled."""
    temp_dir = tempfile.mkdtemp()
    try:
        manager = JobManager(jobs_dir=temp_dir)
        dummy_file = os.path.join(temp_dir, "cancel_test.bin")
        with open(dummy_file, "wb") as f:
            f.write(b"SAMPLE")

        job = manager.create_job(dummy_file, "cancel_test.bin")
        assert job.status in (JobStatus.QUEUED, JobStatus.ANALYZING, JobStatus.RUNNING)

        # Cancel job
        cancelled = manager.cancel_job(job.job_id)
        assert cancelled is True

        refetched = manager.get_job(job.job_id)
        assert refetched.status == JobStatus.CANCELLED
        assert refetched.cancellation_requested is True

        # Second cancel should return False since already cancelled
        second_cancel = manager.cancel_job(job.job_id)
        assert second_cancel is False

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
