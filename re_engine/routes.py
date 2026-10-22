"""
Jarvis RE — REST API Routes
Flask Blueprint exposing endpoints for project management, sample registration,
job dispatching, evidence query, report generation, and tool status auditing.
"""

import logging
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from flask import Blueprint, jsonify, request, send_file, Response
from werkzeug.utils import secure_filename

from REVERSE_ENGINEERING.models import db, REProject, RESample, REFinding, REJob
from REVERSE_ENGINEERING.pipeline import AnalysisPipeline
from REVERSE_ENGINEERING.report_generator import ReportGenerator

logger = logging.getLogger("jarvis.re.routes")

re_blueprint = Blueprint("reverse_engineering", __name__, url_prefix="/api/re")
_pipeline: AnalysisPipeline = None
_reporter: ReportGenerator = ReportGenerator()


def get_pipeline():
    global _pipeline
    if _pipeline is None:
        _pipeline = AnalysisPipeline()
    return _pipeline


# ---------------------------------------------------------------------------
# Project Management
# ---------------------------------------------------------------------------

@re_blueprint.route("/projects", methods=["POST"])
def create_project():
    """Create a new reverse engineering analysis project."""
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"status": "error", "message": "Project name is required"}), 400

    desc = data.get("description", "")
    project = REProject(
        id=str(uuid.uuid4()),
        name=name,
        description=desc,
        status="active",
    )
    db.session.add(project)
    db.session.commit()
    return jsonify({"status": "ok", "project": project.to_dict()}), 201


@re_blueprint.route("/projects", methods=["GET"])
def list_projects():
    """List all projects."""
    status_filter = request.args.get("status")
    q = REProject.query
    if status_filter:
        q = q.filter_by(status=status_filter)
    projects = q.order_by(REProject.created_at.desc()).all()
    return jsonify({"status": "ok", "projects": [p.to_dict() for p in projects]})


@re_blueprint.route("/projects/<project_id>", methods=["GET"])
def get_project(project_id: str):
    """Retrieve project details with its registered samples."""
    project = db.session.get(REProject, project_id)
    if not project:
        return jsonify({"status": "error", "message": "Project not found"}), 404

    samples = [s.to_dict() for s in project.samples.all()]
    p_dict = project.to_dict()
    p_dict["samples"] = samples
    p_dict["sample_count"] = len(samples)
    return jsonify({"status": "ok", "project": p_dict})


# ---------------------------------------------------------------------------
# Sample Registration & Ingestion
# ---------------------------------------------------------------------------

@re_blueprint.route("/projects/<project_id>/samples", methods=["POST"])
def register_sample_endpoint(project_id: str):
    """Upload or register an authorized sample binary for analysis."""
    project = db.session.get(REProject, project_id)
    if not project:
        return jsonify({"status": "error", "message": "Project not found"}), 404

    # 1. Check if multipart file upload
    if "file" in request.files:
        upload = request.files["file"]
        if not upload.filename:
            return jsonify({"status": "error", "message": "No selected file"}), 400

        filename = secure_filename(upload.filename) or "sample.bin"
        temp_dir = tempfile.mkdtemp(prefix="jarvis_re_upload_")
        temp_file_path = os.path.join(temp_dir, filename)
        upload.save(temp_file_path)

        try:
            pipeline = get_pipeline()
            sample = pipeline.register_sample(temp_file_path, project_id, filename=filename)
            return jsonify({"status": "ok", "sample": sample.to_dict()}), 201
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    # 2. Check if JSON with local file_path provided
    data = request.get_json() or {}
    local_path = data.get("file_path")
    if local_path and os.path.isfile(local_path):
        pipeline = get_pipeline()
        sample = pipeline.register_sample(local_path, project_id, filename=data.get("filename"))
        return jsonify({"status": "ok", "sample": sample.to_dict()}), 201

    return jsonify({"status": "error", "message": "Provide either a file upload or valid 'file_path'"}), 400


@re_blueprint.route("/samples/<sample_id>", methods=["GET"])
def get_sample(sample_id: str):
    """Retrieve sample details and summary statistics."""
    sample = db.session.get(RESample, sample_id)
    if not sample:
        return jsonify({"status": "error", "message": "Sample not found"}), 404

    s_dict = sample.to_dict()
    s_dict["findings_count"] = sample.findings.count()
    s_dict["jobs_count"] = sample.jobs.count()
    return jsonify({"status": "ok", "sample": s_dict})


# ---------------------------------------------------------------------------
# Job Execution & Progress
# ---------------------------------------------------------------------------

@re_blueprint.route("/samples/<sample_id>/analyze", methods=["POST"])
def trigger_analysis(sample_id: str):
    """Trigger an analysis pipeline run on an existing sample."""
    sample = db.session.get(RESample, sample_id)
    if not sample:
        return jsonify({"status": "error", "message": "Sample not found"}), 404

    data = request.get_json() or {}
    job_type = data.get("job_type", "full")
    tools = data.get("tools")
    options = data.get("options", {})

    pipeline = get_pipeline()
    try:
        job_id = pipeline.run_analysis(
            sample_id=sample_id,
            job_type=job_type,
            tools_requested=tools,
            options=options,
        )
        job = db.session.get(REJob, job_id)
        return jsonify({"status": "ok", "job": job.to_dict() if job else {"id": job_id}}), 200
    except Exception as err:
        logger.error(f"Analysis trigger failed: {err}", exc_info=True)
        return jsonify({"status": "error", "message": str(err)}), 500


@re_blueprint.route("/jobs/<job_id>", methods=["GET"])
def get_job(job_id: str):
    """Get the live status and execution logs of an analysis job."""
    job = db.session.get(REJob, job_id)
    if not job:
        return jsonify({"status": "error", "message": "Job not found"}), 404
    return jsonify({"status": "ok", "job": job.to_dict()})


# ---------------------------------------------------------------------------
# Findings & Reports
# ---------------------------------------------------------------------------

@re_blueprint.route("/samples/<sample_id>/findings", methods=["GET"])
def list_findings(sample_id: str):
    """Retrieve normalized evidence findings for a sample."""
    sample = db.session.get(RESample, sample_id)
    if not sample:
        return jsonify({"status": "error", "message": "Sample not found"}), 404

    tool = request.args.get("tool")
    ftype = request.args.get("type")
    min_conf = request.args.get("min_confidence", type=float)

    q = sample.findings
    if tool:
        q = q.filter_by(source_tool=tool)
    if ftype:
        q = q.filter_by(finding_type=ftype)
    if min_conf is not None:
        q = q.filter(REFinding.confidence >= min_conf)

    findings = q.order_by(REFinding.created_at.desc()).all()
    return jsonify({
        "status": "ok",
        "sample_id": sample_id,
        "total": len(findings),
        "findings": [f.to_dict() for f in findings],
    })


@re_blueprint.route("/samples/<sample_id>/report", methods=["GET"])
def generate_sample_report(sample_id: str):
    """Generate an evidence-backed technical report (json, markdown, or html)."""
    sample = db.session.get(RESample, sample_id)
    if not sample:
        return jsonify({"status": "error", "message": "Sample not found"}), 404

    fmt = request.args.get("format", "json").lower()
    findings = [f.to_dict() for f in sample.findings.all()]
    jobs = [j.to_dict() for j in sample.jobs.all()]

    try:
        report_text = _reporter.generate_report(
            sample_info=sample.to_dict(),
            findings=findings,
            jobs=jobs,
            report_format=fmt,
        )

        if fmt == "html":
            return Response(report_text, mimetype="text/html")
        elif fmt in ["markdown", "md"]:
            return Response(report_text, mimetype="text/markdown")
        else:
            return Response(report_text, mimetype="application/json")
    except Exception as err:
        return jsonify({"status": "error", "message": str(err)}), 500


# ---------------------------------------------------------------------------
# Tools Status Audit
# ---------------------------------------------------------------------------

@re_blueprint.route("/tools/status", methods=["GET"])
def tools_status():
    """Audit installed status and availability of all 10 reverse engineering engines."""
    pipeline = get_pipeline()
    return jsonify({"status": "ok", "tools": pipeline.get_tool_status()})
