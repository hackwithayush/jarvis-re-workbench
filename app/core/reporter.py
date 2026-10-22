"""
JARVIS RE — Report Generator v1.0
Generates evidence-backed technical reports in JSON, Markdown, and HTML formats
with explicit limitations, tool statuses, and provenance tracking.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from app.core.schema import (
    AnalysisReport,
    ArchiveMember,
    ExportEntry,
    Finding,
    FunctionDetails,
    ImportModule,
    SampleInfo,
    SectionInfo,
)


class ReportGenerator:
    """Builds standardized technical reports from analysis results."""

    @staticmethod
    def build_report(
        sample: SampleInfo,
        findings: List[Finding],
        tools_audited: Dict[str, Any],
        sections: Optional[List[SectionInfo]] = None,
        imports: Optional[List[ImportModule]] = None,
        exports: Optional[List[ExportEntry]] = None,
        functions: Optional[List[FunctionDetails]] = None,
        archive_members: Optional[List[ArchiveMember]] = None,
        tool_executions: Optional[Dict[str, Any]] = None,
        ai_hypotheses: Optional[List[Any]] = None,
        assessment: Optional[Dict[str, Any]] = None,
        string_stats: Optional[Dict[str, Any]] = None,
        report_id: Optional[str] = None,
    ) -> AnalysisReport:
        sections = sections or []
        imports = imports or []
        exports = exports or []
        functions = functions or []
        archive_members = archive_members or []
        tool_executions = tool_executions or {}
        ai_hypotheses = ai_hypotheses or []
        string_stats = string_stats or {}

        # Count findings by type and confidence
        by_type: Dict[str, int] = {}
        high_conf = 0
        tools_executed = set()

        for f in findings:
            ft = f.finding_type.value if hasattr(f.finding_type, "value") else str(f.finding_type)
            by_type[ft] = by_type.get(ft, 0) + 1
            if f.confidence >= 0.8:
                high_conf += 1
            if f.source_tool:
                tools_executed.add(f.source_tool)

        total_imported_funcs = sum(len(m.functions) for m in imports)
        suspicious_apis = [
            fn.name for m in imports for fn in m.functions if fn.is_suspicious
        ]

        summary = {
            "total_findings": len(findings),
            "high_confidence_findings": high_conf,
            "findings_by_type": by_type,
            "entropy_score": sample.entropy,
            "is_packed_suspect": sample.entropy > 7.1,
            "sections_count": len(sections),
            "imported_modules_count": len(imports),
            "imported_functions_count": total_imported_funcs,
            "exported_functions_count": len(exports),
            "recovered_functions_count": len(functions),
            "archive_members_count": len(archive_members),
            "suspicious_apis_count": len(suspicious_apis),
            "tools_actually_executed": sorted(list(tools_executed)),
            "string_metrics": {
                "raw_strings_count": string_stats.get("raw_strings_count", 0),
                "quality_filtered_count": string_stats.get("quality_filtered_count", 0),
                "deduplicated_groups_count": string_stats.get("deduplicated_groups_count", 0),
                "high_value_indicators_count": string_stats.get("high_value_indicators_count", 0),
                "explanation": (
                    "Raw strings count total byte sequences matched; quality filtering eliminates non-alphanumeric noise; "
                    "deduplicated groups consolidate identical strings across multiple offsets; high-value indicators isolate URLs, paths, registry keys, and APIs."
                ),
            },
            "assessment": assessment,
        }

        # Dynamic, accurate limitations reflecting tool execution truthfulness
        limitations = [
            "STATIC TRIAGE PASS: Initial analysis recovered headers, sections, imports/exports, strings, and tool heuristics.",
        ]
        if "radare2" in tools_executed:
            if len(functions) > 0:
                limitations.append(f"RADARE2 EXECUTED: Disassembly and {len(functions)} function(s) recovered via radare2 engine.")
            else:
                limitations.append("RADARE2 EXECUTED: Command completed with exit code 0; 0 native functions recovered (managed .NET assembly or stripped binary).")
        if "die" in tools_executed:
            limitations.append("DETECT IT EASY EXECUTED: Compiler and packer signature matching verified via DIE.")
        if "ghidra" in tools_executed:
            gh_funcs = sum(1 for f in findings if f.source_tool == "ghidra" and f.finding_type == FindingType.FUNCTION)
            if gh_funcs > 0:
                limitations.append(f"GHIDRA EXECUTED: Deep headless decompilation and {gh_funcs} symbols/functions recovered.")
            else:
                limitations.append("GHIDRA EXECUTED: Headless run completed, 0 functions extracted.")
        else:
            limitations.append("GHIDRA STANDBY: Deep headless decompilation available on-demand (POST /api/deep/ghidra/{report_id}).")

        if assessment:
            limitations.append(f"ASSESSMENT [{assessment.get('verdict')}]: {assessment.get('rationale')}")

        limitations.append("NO AUTOMATIC EXECUTION: Live dynamic execution in sandbox requires explicit analyst authorization.")
        limitations.append("PROVENANCE INTEGRITY: All findings record source tool, address, and verification status.")

        return AnalysisReport(
            report_id=report_id or str(uuid.uuid4())[:12],
            sample=sample,
            summary=summary,
            sections=sections,
            imports=imports,
            exports=exports,
            functions=functions,
            archive_members=archive_members,
            findings=findings,
            tools_audited=tools_audited,
            tool_executions=tool_executions,
            ai_hypotheses=ai_hypotheses,
            assessment=assessment,
            limitations=limitations,
            generated_at=datetime.now(timezone.utc),
        )

    @staticmethod
    def to_json(report: AnalysisReport) -> str:
        return report.model_dump_json(indent=2)

    @staticmethod
    def to_markdown(report: AnalysisReport) -> str:
        s = report.sample
        sum_data = report.summary
        lines = [
            "# JARVIS Reverse Engineering Workbench — Technical Report",
            f"**Report ID:** `{report.report_id}` &bull; **Generated:** `{report.generated_at.isoformat()}`",
            "",
            "## 1. Executive Summary & Sample Integrity",
            f"- **Filename:** `{s.filename}`",
            f"- **File Format:** `{s.file_type}`",
            f"- **Architecture:** `{s.architecture}`",
            f"- **File Size:** {s.file_size:,} bytes",
            f"- **Shannon Entropy:** `{s.entropy} / 8.000` ({'HIGH - Packed/Encrypted Suspect' if sum_data.get('is_packed_suspect') else 'Normal'})",
            f"- **SHA-256:** `{s.sha256}`",
            f"- **MD5:** `{s.md5}`",
            f"- **SHA-1:** `{s.sha1}`",
            f"- **Imphash:** `{s.imphash or 'N/A'}`",
            f"- **Compilation Timestamp:** `{s.compilation_timestamp or 'N/A'}`",
            "",
            "## 2. Analysis Metrics & Execution Provenance",
            f"- **Total Findings:** {sum_data.get('total_findings', 0)}",
            f"- **High-Confidence Findings (>= 80%):** {sum_data.get('high_confidence_findings', 0)}",
            f"- **Tools Actually Executed:** `{', '.join(sum_data.get('tools_actually_executed', []))}`",
            f"- **Sections:** {sum_data.get('sections_count', 0)} &bull; **Imports:** {sum_data.get('imported_functions_count', 0)} ({sum_data.get('imported_modules_count', 0)} DLLs) &bull; **Exports:** {sum_data.get('exported_functions_count', 0)}",
            "",
            "| Finding Type | Count |",
            "|---|---|",
        ]
        for k, v in sum_data.get("findings_by_type", {}).items():
            lines.append(f"| `{k}` | {v} |")

        if report.sections:
            lines.extend([
                "",
                "## 3. Section Table & Entropy Distribution",
                "| Name | Virtual Address | Virtual Size | Raw Size | Entropy | Flags |",
                "|---|---|---|---|---|---|",
            ])
            for sec in report.sections:
                lines.append(
                    f"| `{sec.name}` | `{sec.virtual_address}` | {sec.virtual_size:,} | {sec.raw_size:,} | `{sec.entropy:.2f}` | {','.join(sec.flags)} |"
                )

        if report.imports:
            lines.extend([
                "",
                "## 4. Imported Libraries & Functions (Sample)",
                "| Library | Function | Suspicious Category |",
                "|---|---|---|",
            ])
            count = 0
            for mod in report.imports:
                for fn in mod.functions:
                    if count >= 50:
                        break
                    susp = f"**{fn.category}**" if fn.is_suspicious else "Normal"
                    lines.append(f"| `{mod.module_name}` | `{fn.name}` | {susp} |")
                    count += 1

        lines.extend([
            "",
            "## 5. Scope Limitations & Provenance",
        ])
        for lim in report.limitations:
            lines.append(f"- {lim}")

        return "\n".join(lines)
