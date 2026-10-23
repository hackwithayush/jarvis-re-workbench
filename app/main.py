"""
JARVIS Reverse Engineering Workbench — FastAPI Application
Version 1.0.0 — Complete Multi-Engine Reverse Engineering Platform
"""

import json
import os
import shutil
import tempfile
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

from fastapi import Body, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.core.ai_analyst import AIAnalyst
from app.core.analyzer import BinaryAnalyzer
from app.core.job_manager import AnalysisJob, JobStatus, job_manager
from app.core.reporter import ReportGenerator
from app.core.sandbox import ControlledSandbox
from app.core.schema import (
    AnalysisReport,
    BuildReport,
    DifferentialTestResult,
    Finding,
    FindingStatus,
    FindingType,
    FunctionDetails,
    GeneratedProject,
    ImportModule,
    KnowledgeGraphData,
    ReconstructionSpecification,
)
from app.core.tools import ToolAuditor
from app.core.knowledge_graph import KnowledgeGraphEngine
from app.core.reconstruction_planner import ReconstructionPlanner
from app.core.software_generator import SoftwareGenerator
from app.core.build_agent import BuildAgent
from app.core.differential_tester import DifferentialTester
from adapters.ghidra_adapter import GhidraAdapter
from adapters.angr_adapter import AngrAdapter

import logging
# Suppress noisy angr Unicorn missing DLL warnings on Windows
logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)
logging.getLogger("angr").setLevel(logging.ERROR)

app = FastAPI(
    title="JARVIS Reverse Engineering Workbench",
    description="Unified AI-assisted reverse-engineering, disassembly, decompilation, and forensics platform.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
SAMPLES_DIR = os.path.join(os.path.dirname(BASE_DIR), "workspace", "samples")
os.makedirs(SAMPLES_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# In-memory report cache and sample path storage for current session
REPORTS_CACHE: Dict[str, AnalysisReport] = {}
SAMPLES_STORAGE: Dict[str, str] = {}
GRAPHS_CACHE: Dict[str, KnowledgeGraphData] = {}
SPECS_CACHE: Dict[str, ReconstructionSpecification] = {}
PROJECTS_CACHE: Dict[str, GeneratedProject] = {}
BUILDS_CACHE: Dict[str, BuildReport] = {}
DIFFS_CACHE: Dict[str, DifferentialTestResult] = {}


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    """Serve the JARVIS RE Workbench HTML dashboard."""
    try:
        return templates.TemplateResponse(request=request, name="index.html")
    except TypeError:
        return templates.TemplateResponse("index.html", {"request": request})


@app.get("/favicon.ico", include_in_schema=False)
async def get_favicon():
    """Serve embedded vector favicon to eliminate 404 console noise."""
    svg_icon = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <defs>
    <linearGradient id="jarvisGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00f5ff"/>
      <stop offset="50%" stop-color="#4f8cff"/>
      <stop offset="100%" stop-color="#7928ca"/>
    </linearGradient>
  </defs>
  <rect width="100" height="100" rx="22" fill="#080c18"/>
  <polygon points="50,14 84,33 84,72 50,91 16,72 16,33" fill="none" stroke="url(#jarvisGrad)" stroke-width="5"/>
  <circle cx="50" cy="52" r="16" fill="none" stroke="#00f5ff" stroke-width="3"/>
  <circle cx="50" cy="52" r="6" fill="#00f5ff"/>
  <line x1="50" y1="20" x2="50" y2="36" stroke="#00f5ff" stroke-width="2"/>
  <line x1="50" y1="68" x2="50" y2="84" stroke="#00f5ff" stroke-width="2"/>
  <line x1="22" y1="52" x2="34" y2="52" stroke="#00f5ff" stroke-width="2"/>
  <line x1="66" y1="52" x2="78" y2="52" stroke="#00f5ff" stroke-width="2"/>
</svg>"""
    return Response(content=svg_icon, media_type="image/svg+xml")


@app.get("/api/health")
async def health_check():
    """Service health and version indicator."""
    return {
        "status": "healthy",
        "service": "JARVIS Reverse Engineering Workbench",
        "version": "1.0.0",
        "capabilities": [
            "pe_coff_parsing",
            "elf_parsing",
            "macho_parsing",
            "archive_inspection",
            "strings_heuristic_classification",
            "detect_it_easy_integration",
            "radare2_disassembly_and_cfg",
            "ilspy_dotnet_decompilation",
            "ghidra_headless_integration",
            "angr_symbolic_cfg",
            "controlled_dynamic_sandbox",
            "unified_evidence_correlation",
            "ai_assisted_function_explanation",
            "background_job_management",
        ],
    }


@app.get("/api/tools")
async def get_tool_ecosystem():
    """Audit and return local availability for all reverse engineering tools."""
    return ToolAuditor.audit_all()


# ---------------------------------------------------------------------------
# Asynchronous Background Job Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/jobs", response_model=AnalysisJob)
async def create_analysis_job(
    file: UploadFile = File(...),
    enable_ghidra: bool = Query(False, description="Enable deep Ghidra headless analysis"),
    enable_angr: bool = Query(False, description="Enable angr symbolic execution"),
):
    """
    Queue an asynchronous analysis job for long-running deep reverse engineering.
    Returns immediately with a job_id for status polling.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    job_uid = str(uuid.uuid4())[:12]
    job_sample_dir = os.path.join(SAMPLES_DIR, job_uid)
    os.makedirs(job_sample_dir, exist_ok=True)
    temp_file_path = os.path.join(job_sample_dir, file.filename)

    with open(temp_file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    options = {
        "enable_ghidra": enable_ghidra,
        "enable_angr": enable_angr,
    }

    job = job_manager.create_job(temp_file_path, file.filename, options=options)
    # Register paths immediately in storage for early lookup
    SAMPLES_STORAGE[job.job_id] = temp_file_path
    SAMPLES_STORAGE[file.filename] = temp_file_path
    return job


@app.get("/api/jobs/{job_id}", response_model=AnalysisJob)
async def get_job_status(job_id: str):
    """Poll progress, current stage, and logs for an ongoing analysis job."""
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job ID not found")
    if job.report:
        REPORTS_CACHE[job.report.report_id] = job.report
    return job


@app.get("/api/jobs/{job_id}/result", response_model=AnalysisReport)
async def get_job_result(job_id: str):
    """Retrieve the completed AnalysisReport from an analysis job."""
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job ID not found")
    if job.status != JobStatus.COMPLETED or not job.report:
        raise HTTPException(status_code=400, detail=f"Job not completed. Current status: {job.status}")
    REPORTS_CACHE[job.report.report_id] = job.report
    return job.report


@app.get("/api/jobs", response_model=List[AnalysisJob])
async def list_analysis_jobs():
    """List all current and past analysis jobs."""
    return job_manager.list_jobs()


# ---------------------------------------------------------------------------
# Synchronous Analysis Endpoint (Backward Compatible)
# ---------------------------------------------------------------------------

@app.post("/api/analyze", response_model=AnalysisReport)
async def analyze_sample(file: UploadFile = File(...)):
    """
    Accept an authorized binary sample, compute SHA-256, detect format & architecture,
    calculate Shannon entropy, extract printable strings, and produce an evidence report.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    # Allocate persistent workspace directory for this session's sample
    sample_uid = str(uuid.uuid4())[:12] if "uuid" in globals() else os.urandom(6).hex()
    sample_dir = os.path.join(SAMPLES_DIR, sample_uid)
    os.makedirs(sample_dir, exist_ok=True)
    stored_file_path = os.path.join(sample_dir, file.filename)

    try:
        with open(stored_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        analyzer = BinaryAnalyzer(stored_file_path)
        sample_info, findings = analyzer.analyze()
        tools_status = ToolAuditor.audit_all()

        report = ReportGenerator.build_report(
            sample=sample_info,
            findings=findings,
            tools_audited=tools_status,
            sections=analyzer.sections,
            imports=analyzer.imports,
            exports=analyzer.exports,
            functions=analyzer.functions,
            archive_members=analyzer.archive_members,
            tool_executions=analyzer.tool_executions,
            ai_hypotheses=analyzer.ai_hypotheses,
            assessment=analyzer.assessment,
            string_stats=analyzer.string_stats,
            report_id=sample_uid,
        )

        REPORTS_CACHE[report.report_id] = report
        SAMPLES_STORAGE[report.report_id] = stored_file_path
        SAMPLES_STORAGE[file.filename] = stored_file_path
        return report

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis pipeline error: {str(e)}")


# ---------------------------------------------------------------------------
# Controlled Dynamic Sandbox Execution
# ---------------------------------------------------------------------------

class SandboxExecutionRequest(BaseModel):
    sample_path: Optional[str] = ""
    report_id: Optional[str] = None
    authorized: bool = False
    confirmation_token: str = ""
    timeout: int = 20


@app.post("/api/dynamic/execute")
async def execute_in_sandbox(payload: SandboxExecutionRequest):
    """
    Trigger controlled execution of an authorized sample inside the isolated sandbox jail.
    Requires explicit analyst authorization token to prevent accidental execution.
    """
    if not payload.authorized or not payload.confirmation_token:
        raise HTTPException(
            status_code=403,
            detail="Authorization required: Dynamic execution blocked without explicit analyst confirmation.",
        )

    # Resolve target binary from storage or direct path
    target = None
    if payload.report_id and payload.report_id in SAMPLES_STORAGE:
        target = SAMPLES_STORAGE[payload.report_id]
    elif payload.sample_path and payload.sample_path in SAMPLES_STORAGE:
        target = SAMPLES_STORAGE[payload.sample_path]
    elif payload.sample_path and os.path.isfile(payload.sample_path):
        target = payload.sample_path

    # Workspace directory search fallback
    if not target or not os.path.isfile(target):
        for root, dirs, files in os.walk(SAMPLES_DIR):
            if payload.report_id and payload.report_id in root:
                if files:
                    target = os.path.join(root, files[0])
                    break
            if payload.sample_path and os.path.basename(payload.sample_path) in files:
                target = os.path.join(root, os.path.basename(payload.sample_path))
                break

    # Temp dir fallback
    if not target or not os.path.isfile(target):
        temp_base = tempfile.gettempdir()
        try:
            for item in os.listdir(temp_base):
                if item.startswith("jarvis_job_"):
                    candidate_dir = os.path.join(temp_base, item)
                    if os.path.isdir(candidate_dir):
                        if payload.sample_path and os.path.isfile(os.path.join(candidate_dir, os.path.basename(payload.sample_path))):
                            target = os.path.join(candidate_dir, os.path.basename(payload.sample_path))
                            break
        except Exception:
            pass

    if not target or not os.path.isfile(target):
        raise HTTPException(
            status_code=404,
            detail=f"Target binary '{payload.sample_path or payload.report_id}' not found in active workspace or sample storage.",
        )

    sandbox = ControlledSandbox(timeout=payload.timeout)
    trace = sandbox.execute_sample(
        sample_path=target,
        authorized=payload.authorized,
        analyst_confirmation_token=payload.confirmation_token,
    )

    # Attach dynamic findings and trace to active report if present
    if payload.report_id and payload.report_id in REPORTS_CACHE:
        rep = REPORTS_CACHE[payload.report_id]
        rep.dynamic_trace = trace
        rep.findings.append(
            Finding(
                run_id=payload.report_id,
                sample_sha256=rep.sample.sha256,
                source_tool="sandbox",
                tool_version="1.0.0",
                finding_type=FindingType.BEHAVIOR_EVENT,
                name="sandbox_execution_trace",
                description=f"Isolated sandbox execution exited code {trace.exit_code} in {trace.execution_time_ms}ms.",
                confidence=0.99,
                verification_status=FindingStatus.CONFIRMED,
                raw_data={"exit_code": trace.exit_code, "execution_time_ms": trace.execution_time_ms},
            )
        )
        rep.summary["tools_actually_executed"] = sorted(list(set(rep.summary.get("tools_actually_executed", []) + ["sandbox"])))

    return trace


# ---------------------------------------------------------------------------
# Deep Decompilation & Symbolic Execution Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/deep/ghidra/{report_id}", response_model=AnalysisReport)
async def run_deep_ghidra(report_id: str):
    """Execute deep Ghidra headless decompilation and symbol recovery on an active sample."""
    report = REPORTS_CACHE.get(report_id)
    target_path = SAMPLES_STORAGE.get(report_id)
    if not report or not target_path or not os.path.isfile(target_path):
        raise HTTPException(status_code=404, detail="Active report or binary sample not found in workspace.")

    ghidra_adapter = GhidraAdapter()
    if not ghidra_adapter.is_available():
        raise HTTPException(status_code=503, detail="Ghidra Headless engine or Java is not available on host.")

    temp_ws = tempfile.mkdtemp(prefix="jarvis_ghidra_ws_")
    try:
        gh_findings = ghidra_adapter.analyze(target_path, temp_ws)
        for f in gh_findings:
            ftype = FindingType.FUNCTION if f.get("finding_type") == "function" else FindingType.METADATA
            f_addr = f.get("address")
            f_name = f.get("name", "ghidra_decompilation")
            raw_gh = f.get("raw_data", {})
            report.findings.append(
                Finding(
                    run_id=report_id,
                    sample_sha256=report.sample.sha256,
                    source_tool="ghidra",
                    tool_version=ghidra_adapter.get_version() or "12.1.4",
                    finding_type=ftype,
                    address_or_location=f_addr,
                    name=f_name,
                    description=f.get("description", "Ghidra headless output"),
                    confidence=0.92,
                    verification_status=FindingStatus.CONFIRMED,
                    raw_data=raw_gh,
                )
            )
            if ftype == FindingType.FUNCTION and f_addr:
                report.functions.append(
                    FunctionDetails(
                        name=f_name,
                        address=f_addr,
                        size=raw_gh.get("size", 0),
                        source_tool="ghidra",
                        calling_convention=raw_gh.get("calling_convention"),
                        parameter_count=raw_gh.get("parameter_count"),
                    )
                )

        report.summary["tools_actually_executed"] = sorted(list(set(report.summary.get("tools_actually_executed", []) + ["ghidra"])))
        report.summary["total_findings"] = len(report.findings)
        report.summary["recovered_functions_count"] = len(report.functions)
        report.limitations.append("GHIDRA HEADLESS EXECUTED: Deep decompilation and symbols integrated into report.")
        return report
    finally:
        shutil.rmtree(temp_ws, ignore_errors=True)


@app.post("/api/deep/angr/{report_id}", response_model=AnalysisReport)
async def run_deep_angr(report_id: str):
    """Execute angr symbolic execution and CFGFast graph extraction on an active sample."""
    report = REPORTS_CACHE.get(report_id)
    target_path = SAMPLES_STORAGE.get(report_id)
    if not report or not target_path or not os.path.isfile(target_path):
        raise HTTPException(status_code=404, detail="Active report or binary sample not found in workspace.")

    angr_adapter = AngrAdapter()
    if not angr_adapter.is_available():
        raise HTTPException(status_code=503, detail="angr symbolic engine is not available on host.")

    temp_ws = tempfile.mkdtemp(prefix="jarvis_angr_ws_")
    try:
        angr_findings = angr_adapter.analyze(target_path, temp_ws)
        for f in angr_findings:
            report.findings.append(
                Finding(
                    run_id=report_id,
                    sample_sha256=report.sample.sha256,
                    source_tool="angr",
                    tool_version=angr_adapter.get_version() or "9.2",
                    finding_type=FindingType.CFG if "cfg" in f.get("name", "") else FindingType.FUNCTION,
                    address_or_location=f.get("address"),
                    name=f.get("name", "angr_symbolic"),
                    description=f.get("description", "angr symbolic CFG"),
                    confidence=0.88,
                    verification_status=FindingStatus.CONFIRMED,
                    raw_data=f.get("raw_data", {}),
                )
            )
        report.summary["tools_actually_executed"] = sorted(list(set(report.summary.get("tools_actually_executed", []) + ["angr"])))
        report.summary["total_findings"] = len(report.findings)
        report.limitations.append("ANGR EXECUTED: Symbolic execution & CFGFast graph recovered.")
        return report
    finally:
        shutil.rmtree(temp_ws, ignore_errors=True)


# ---------------------------------------------------------------------------
# AI Analyst Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/ai/explain_function")
async def ai_explain_function(function_data: FunctionDetails = Body(...)):
    """Grounded AI explanation of recovered function instructions and pseudo-C code."""
    return AIAnalyst.explain_function(function_data)


@app.post("/api/ai/explain_imports")
async def ai_explain_imports(imports_data: List[ImportModule] = Body(...)):
    """Categorize and explain binary capabilities derived from imported APIs."""
    return AIAnalyst.explain_api_imports(imports_data)


@app.get("/api/ai/brief/{report_id}")
async def ai_generate_brief(report_id: str):
    """Generate an evidence-backed technical brief for an existing analysis report."""
    report = REPORTS_CACHE.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report ID not found")
    return AIAnalyst.generate_investigation_brief(report)


# ---------------------------------------------------------------------------
# Report Exporters (Markdown, JSON, HTML)
# ---------------------------------------------------------------------------

@app.get("/api/report/{report_id}/markdown", response_class=PlainTextResponse)
async def get_report_markdown(report_id: str):
    """Retrieve the generated technical report in formatted Markdown."""
    report = REPORTS_CACHE.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report ID not found in active session cache")
    return ReportGenerator.to_markdown(report)


@app.get("/api/report/{report_id}/json")
async def get_report_json(report_id: str):
    """Retrieve the full raw technical report in JSON."""
    report = REPORTS_CACHE.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report ID not found in active session cache")
    return Response(content=ReportGenerator.to_json(report), media_type="application/json")


@app.get("/api/report/{report_id}/html", response_class=HTMLResponse)
async def get_report_html(report_id: str):
    """Retrieve a self-contained standalone HTML report."""
    report = REPORTS_CACHE.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report ID not found in active session cache")

    # Generate standalone HTML document
    md_content = ReportGenerator.to_markdown(report)
    html_doc = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>JARVIS RE Report — {report.sample.filename}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0c0e14; color: #e1e4ea; margin: 0; padding: 40px; line-height: 1.6; }}
    .container {{ max-width: 960px; margin: 0 auto; background: #141721; padding: 32px; border-radius: 8px; border: 1px solid #2d3348; }}
    h1 {{ color: #00d2ff; border-bottom: 2px solid #00d2ff; padding-bottom: 8px; }}
    h2 {{ color: #7928ca; margin-top: 24px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
    th, td {{ border: 1px solid #2d3348; padding: 8px 12px; text-align: left; font-size: 13px; }}
    th {{ background: #1c2132; color: #00d2ff; }}
    code {{ background: #0c0e14; color: #00ff88; padding: 2px 6px; border-radius: 4px; font-family: 'Consolas', monospace; font-size: 12px; }}
    pre {{ background: #0c0e14; padding: 12px; border-radius: 6px; overflow-x: auto; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>JARVIS Reverse Engineering Report</h1>
    <p><strong>Sample:</strong> {report.sample.filename} &bull; <strong>Format:</strong> {report.sample.file_type} &bull; <strong>Report ID:</strong> {report.report_id}</p>
    <pre>{md_content}</pre>
  </div>
</body>
</html>"""
    return HTMLResponse(content=html_doc)


# ---------------------------------------------------------------------------
# Autonomous Software Reconstruction & Creation Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/reconstruct/graph/{report_id}", response_model=KnowledgeGraphData)
async def generate_knowledge_graph(report_id: str):
    """
    Construct a persistent, queryable Software Knowledge Graph from an existing AnalysisReport.
    Represents modules, components, functions, endpoints, and storage with evidence grounding.
    """
    report = REPORTS_CACHE.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Analysis report ID not found in session cache")

    graph = KnowledgeGraphEngine.build_graph(report)
    GRAPHS_CACHE[graph.graph_id] = graph
    GRAPHS_CACHE[report_id] = graph
    return graph


@app.get("/api/reconstruct/graph/{report_id}/mermaid", response_class=PlainTextResponse)
async def get_graph_mermaid(report_id: str):
    """Retrieve Mermaid diagram flowchart representing the Software Knowledge Graph."""
    graph = GRAPHS_CACHE.get(report_id)
    if not graph:
        report = REPORTS_CACHE.get(report_id)
        if not report:
            raise HTTPException(status_code=404, detail="Report ID not found")
        graph = KnowledgeGraphEngine.build_graph(report)
        GRAPHS_CACHE[report_id] = graph

    mermaid_code = KnowledgeGraphEngine.to_mermaid(graph)
    return PlainTextResponse(content=mermaid_code)


@app.post("/api/reconstruct/spec/{report_id}", response_model=ReconstructionSpecification)
async def generate_reconstruction_spec(
    report_id: str,
    target_framework: str = Query("python_fastapi", description="Target language / framework"),
):
    """
    Synthesize an evidence-backed 10-section clean-room Reconstruction Specification.
    Classifies every requirement with verified, inferred, proposed, or unknown states.
    """
    report = REPORTS_CACHE.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Analysis report ID not found in session cache")

    graph = GRAPHS_CACHE.get(report_id)
    spec = ReconstructionPlanner.generate_specification(report, graph=graph, target_framework=target_framework)
    SPECS_CACHE[spec.spec_id] = spec
    SPECS_CACHE[report_id] = spec
    return spec


@app.post("/api/reconstruct/approve/{spec_id}", response_model=ReconstructionSpecification)
async def approve_reconstruction_spec(spec_id: str):
    """Explicit analyst approval of the architectural reconstruction specification."""
    spec = SPECS_CACHE.get(spec_id)
    if not spec:
        raise HTTPException(status_code=404, detail="Specification ID not found")
    spec.approved = True
    return spec


class ProjectGenerationRequest(BaseModel):
    spec_id: str
    target_framework: Optional[str] = "python_fastapi"


@app.post("/api/reconstruct/generate", response_model=GeneratedProject)
async def generate_original_software(req: ProjectGenerationRequest):
    """
    Generate an independent, clean-room original software project based on an approved specification.
    Produces real source files, dependency manifests, configuration, tests, and documentation.
    """
    spec = SPECS_CACHE.get(req.spec_id)
    if not spec:
        raise HTTPException(status_code=404, detail="Specification ID not found. Generate specification first.")

    generator = SoftwareGenerator()
    project = generator.generate_project(spec=spec, target_framework=req.target_framework)
    PROJECTS_CACHE[project.project_id] = project
    return project


@app.post("/api/reconstruct/build/{project_id}", response_model=BuildReport)
async def build_and_validate_project(project_id: str):
    """
    Execute static compilation, automated test battery, and packaging in an isolated project workspace.
    """
    project = PROJECTS_CACHE.get(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project ID not found")

    agent = BuildAgent(timeout_sec=60)
    report = agent.build_and_validate(project)
    BUILDS_CACHE[report.build_id] = report
    BUILDS_CACHE[project_id] = report
    return report


@app.post("/api/reconstruct/diff/{project_id}", response_model=DifferentialTestResult)
async def run_differential_testing(project_id: str):
    """
    Execute differential behavior testing comparing reference observations with the reconstructed software.
    """
    project = PROJECTS_CACHE.get(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project ID not found")

    spec = SPECS_CACHE.get(project.spec_id)
    ref_name = spec.project_name if spec else "reference_sample"

    tester = DifferentialTester()
    result = tester.run_differential_test(project=project, reference_name=ref_name)
    DIFFS_CACHE[result.test_id] = result
    DIFFS_CACHE[project_id] = result
    return result


@app.get("/api/reconstruct/projects", response_model=List[GeneratedProject])
async def list_generated_projects():
    """List all clean-room projects generated in the current workbench session."""
    return list(PROJECTS_CACHE.values())


@app.get("/api/reconstruct/projects/{project_id}", response_model=GeneratedProject)
async def get_generated_project(project_id: str):
    """Retrieve details, source code tree, and manifest for a generated project."""
    project = PROJECTS_CACHE.get(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project ID not found")
    return project


@app.get("/api/reconstruct/export/{project_id}")
async def export_project_archive(project_id: str):
    """Download the packaged distribution ZIP archive for a clean-room project."""
    project = PROJECTS_CACHE.get(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project ID not found")

    build = BUILDS_CACHE.get(project_id)
    zip_path = build.packaged_artifact_path if build and build.packaged_artifact_path else None

    # Fallback to creating a zip on-the-fly if not already packaged
    if not zip_path or not os.path.isfile(zip_path):
        import zipfile
        zip_path = os.path.join(project.workspace_dir, f"{project.name}_export.zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(project.workspace_dir):
                for f in files:
                    if f.endswith(".zip") or "__pycache__" in root or ".pytest_cache" in root:
                        continue
                    full_p = os.path.join(root, f)
                    arcname = os.path.relpath(full_p, project.workspace_dir)
                    zf.write(full_p, arcname)

    return FileResponse(
        path=zip_path,
        filename=os.path.basename(zip_path),
        media_type="application/zip",
    )
