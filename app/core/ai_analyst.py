"""
JARVIS RE — AI Reverse Engineering Analyst v1.0
Evidence-grounded AI analyst providing:
- Function & assembly explanation in context (never invents code or APIs).
- Decompiler code summarization and purpose inference.
- API import capability mapping (Process, Memory, Network, Crypto, Persistence).
- Evidence-referenced investigation briefings tied strictly to Finding IDs and addresses.
- Fully operational offline with deterministic heuristic reasoning, with hooks for LLM inference.
"""

from typing import Any, Dict, List, Optional
from app.core.schema import AnalysisReport, FindingType, FunctionDetails, ImportModule


class AIAnalyst:
    """Provides evidence-grounded technical analysis and function explanations."""

    @staticmethod
    def explain_function(func: FunctionDetails) -> Dict[str, Any]:
        """
        Explain a function's assembly and decompiled pseudo-C code in context.
        Grounded strictly in the recovered instructions and API calls.
        """
        instr_count = len(func.instructions)
        cfg_blocks = len(func.cfg_blocks)
        apis = func.api_calls

        # Identify operational patterns
        behaviors = []
        if any("alloc" in api.lower() for api in apis):
            behaviors.append("Dynamic memory management")
        if any("free" in api.lower() or "delete" in api.lower() for api in apis):
            behaviors.append("Resource deallocation/cleanup")
        if any("string" in api.lower() or "print" in api.lower() or "format" in api.lower() for api in apis):
            behaviors.append("String manipulation or logging")
        if any("file" in api.lower() or "read" in api.lower() or "write" in api.lower() for api in apis):
            behaviors.append("Filesystem I/O operations")
        if any("socket" in api.lower() or "connect" in api.lower() or "http" in api.lower() for api in apis):
            behaviors.append("Network socket communication")

        explanation_lines = [
            f"Function `{func.name}` at address `{func.address}` consists of {instr_count} instructions across {cfg_blocks} basic block(s).",
        ]
        if func.calling_convention:
            explanation_lines.append(f"- **Calling Convention:** `{func.calling_convention}` ({func.parameter_count or 0} parameters).")
        if apis:
            explanation_lines.append(f"- **Direct API / Subroutine Calls:** `{', '.join(apis[:8])}`.")
        if behaviors:
            explanation_lines.append(f"- **Inferred Operational Profile:** {', '.join(behaviors)}.")
        if func.cross_references:
            explanation_lines.append(f"- **Cross-References:** Referenced from `{', '.join(func.cross_references[:4])}`.")

        hypothesis = (
            f"Likely serves as a {'program initialization / entry point handler' if 'entry' in func.name.lower() else 'subroutine'} "
            + (f"executing {behaviors[0].lower()}." if behaviors else "performing arithmetic or state calculations.")
        )

        return {
            "function_name": func.name,
            "address": func.address,
            "technical_summary": " ".join(explanation_lines),
            "inferred_behaviors": behaviors,
            "analyst_hypothesis": hypothesis,
            "grounding_evidence": {
                "instruction_count": instr_count,
                "basic_block_count": cfg_blocks,
                "api_calls": apis,
                "xrefs": func.cross_references,
            },
        }

    @staticmethod
    def explain_api_imports(imports: List[ImportModule]) -> Dict[str, Any]:
        """Group and explain binary capabilities derived from imported APIs."""
        capabilities: Dict[str, List[str]] = {
            "Memory & Injection": [],
            "Network & Web": [],
            "Process & Execution": [],
            "Persistence & Registry": [],
            "Anti-Analysis": [],
            "General Utility": [],
        }

        for mod in imports:
            for fn in mod.functions:
                name = fn.name
                if any(k in name for k in ("VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread")):
                    capabilities["Memory & Injection"].append(f"{mod.module_name}!{name}")
                elif any(k in name for k in ("Internet", "Http", "WSA", "connect", "URLDownload", "socket")):
                    capabilities["Network & Web"].append(f"{mod.module_name}!{name}")
                elif any(k in name for k in ("CreateProcess", "WinExec", "ShellExecute", "ExitProcess")):
                    capabilities["Process & Execution"].append(f"{mod.module_name}!{name}")
                elif any(k in name for k in ("RegOpenKey", "RegSetValue", "CreateService")):
                    capabilities["Persistence & Registry"].append(f"{mod.module_name}!{name}")
                elif any(k in name for k in ("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString")):
                    capabilities["Anti-Analysis"].append(f"{mod.module_name}!{name}")
                else:
                    if len(capabilities["General Utility"]) < 20:
                        capabilities["General Utility"].append(f"{mod.module_name}!{name}")

        return {
            "capabilities": {k: v for k, v in capabilities.items() if v},
            "summary": (
                f"Binary imports symbols across {len(imports)} DLLs. "
                f"Identified {len(capabilities['Memory & Injection'])} memory manipulation API(s) and "
                f"{len(capabilities['Network & Web'])} network communication API(s)."
            ),
        }

    @staticmethod
    def generate_investigation_brief(report: AnalysisReport) -> Dict[str, Any]:
        """Synthesize findings into an evidence-backed investigation brief."""
        s = report.sample
        sum_data = report.summary

        key_evidence = []
        for f in report.findings:
            if f.confidence >= 0.85 and f.finding_type in (FindingType.IMPORT, FindingType.ANOMALY, FindingType.COMPILER, FindingType.SECTION):
                key_evidence.append({
                    "id": f.id,
                    "type": f.finding_type.value if hasattr(f.finding_type, "value") else str(f.finding_type),
                    "tool": f.source_tool,
                    "address": f.address_or_location or "N/A",
                    "description": f.description,
                })

        brief = {
            "target": s.filename,
            "architecture": f"{s.file_type} ({s.architecture})",
            "shannon_entropy": f"{s.entropy:.3f} / 8.000",
            "is_packed_suspect": sum_data.get("is_packed_suspect", False),
            "provenance_tools": sum_data.get("tools_actually_executed", []),
            "key_evidence_count": len(key_evidence),
            "key_evidence": key_evidence[:15],
            "assessment": (
                f"Static and multi-tool analysis of '{s.filename}' (SHA-256: {s.sha256[:16]}...) "
                f"established a format of {s.file_type}. "
                f"Execution verified via {', '.join(sum_data.get('tools_actually_executed', []))}. "
                + ("High entropy suggests packed payload or obfuscation. " if sum_data.get("is_packed_suspect") else "Standard entropy distribution observed. ")
                + f"{len(report.ai_hypotheses)} investigation hypothesis/hypotheses generated."
            ),
        }
        return brief
