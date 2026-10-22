"""
Jarvis Skill — Reverse Engineering Analysis (reverse_engineering)
Provides AI-assisted binary analysis, executable identification,
decompilation, entropy calculation, and technical report generation.
"""

import os
import uuid
from typing import Any, Dict, Optional

from REVERSE_ENGINEERING.models import db, REProject, RESample, REFinding, REJob
from REVERSE_ENGINEERING.pipeline import AnalysisPipeline
from REVERSE_ENGINEERING.report_generator import ReportGenerator

MANIFEST = {
    "skill_id": "reverse_engineering",
    "name": "Reverse Engineering & Binary Analysis",
    "description": (
        "Inspects executable binaries, recovers program structure, calculates entropy, "
        "identifies compilers/packers, extracts strings, and produces evidence-backed reports."
    ),
    "required_clearance": "HIGH",
    "required_capabilities": [
        "filesystem.read",
        "binary_analysis",
    ],
    "parameters": {
        "file_path": {
            "type": "string",
            "description": "Absolute path to the binary sample to analyze.",
            "required": True,
        },
        "project_name": {
            "type": "string",
            "description": "Optional name for the analysis project. Defaults to 'Auto_RE_Investigation'.",
            "required": False,
        },
        "job_type": {
            "type": "string",
            "description": "Analysis depth: 'full' or 'identify'. Default: 'full'.",
            "required": False,
        },
        "report_format": {
            "type": "string",
            "description": "Format for output report: 'markdown', 'json', or 'html'. Default: 'markdown'.",
            "required": False,
        },
    },
}

_pipeline = None
_reporter = ReportGenerator()


def _get_pipeline():
    global _pipeline
    if _pipeline is None:
        _pipeline = AnalysisPipeline()
    return _pipeline


def execute(args: dict, clearance_tokens: Optional[dict] = None) -> dict:
    """Execute autonomous reverse engineering workflow."""
    file_path = args.get("file_path")
    if not file_path or not os.path.isfile(file_path):
        return {
            "status": "ERROR",
            "error": f"Target file does not exist or invalid path: {file_path}",
        }

    proj_name = args.get("project_name") or f"Investigation_{os.path.basename(file_path)}"
    job_type = args.get("job_type", "full")
    report_format = args.get("report_format", "markdown")

    pipeline = _get_pipeline()

    # 1. Ensure project exists
    project = REProject.query.filter_by(name=proj_name, status="active").first()
    if not project:
        project = REProject(id=str(uuid.uuid4()), name=proj_name, status="active")
        db.session.add(project)
        db.session.commit()

    # 2. Register sample
    sample = pipeline.register_sample(file_path, project.id)

    # 3. Run analysis
    job_id = pipeline.run_analysis(sample.id, job_type=job_type)

    # 4. Generate report
    findings = [f.to_dict() for f in REFinding.query.filter_by(sample_id=sample.id).order_by(REFinding.created_at.desc()).all()]
    jobs = [j.to_dict() for j in REJob.query.filter_by(sample_id=sample.id).all()]

    report = _reporter.generate_report(
        sample_info=sample.to_dict(),
        findings=findings,
        jobs=jobs,
        report_format=report_format,
    )

    return {
        "status": "COMPLETED",
        "project_id": project.id,
        "sample_id": sample.id,
        "job_id": job_id,
        "sha256": sample.sha256,
        "format": sample.file_type,
        "architecture": sample.architecture,
        "total_findings": len(findings),
        "report": report,
    }
