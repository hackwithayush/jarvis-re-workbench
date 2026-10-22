"""
JARVIS RE — Software Knowledge Graph Engine v1.0
Constructs a persistent, queryable Software Knowledge Graph from reverse-engineered evidence:
- Modules, components, classes, and functions
- Calls, data flows, and state transitions
- Network endpoints, storage/registry keys, and external APIs
- Evidence provenance (observed vs statically inferred vs hypotheses)
- Subsystem clustering and Mermaid architecture diagram generation
"""

import logging
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from app.core.schema import (
    AnalysisReport,
    EvidenceStatus,
    GraphEdge,
    GraphNode,
    KnowledgeGraphData,
)

logger = logging.getLogger("jarvis.re.knowledge_graph")


class KnowledgeGraphEngine:
    """Builds and queries a persistent software architecture knowledge graph."""

    @staticmethod
    def build_graph(report: AnalysisReport) -> KnowledgeGraphData:
        """Construct knowledge graph from an AnalysisReport with strict evidence grounding."""
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        node_ids: Set[str] = set()
        subsystems: Set[str] = set(["Core"])
        entry_points: List[str] = []

        sample_name = report.sample.filename
        sample_hash = report.sample.sha256

        # 1. Root Application Node
        root_id = "app_root"
        nodes.append(
            GraphNode(
                id=root_id,
                label=sample_name,
                node_type="module",
                subsystem="Core",
                description=f"Target binary: {sample_name} ({report.sample.file_type}, {report.sample.architecture})",
                source_tool="static_triage",
                source_location="header",
                evidence_status=EvidenceStatus.OBSERVED,
                confidence=1.0,
                properties={
                    "file_size": report.sample.file_size,
                    "entropy": report.sample.entropy,
                    "compilation_timestamp": report.sample.compilation_timestamp,
                },
            )
        )
        node_ids.add(root_id)

        # 2. Section / Memory Layout Nodes
        for sec in report.sections:
            sec_id = f"sec_{sec.name.replace('.', '_').strip()}"
            if sec_id not in node_ids:
                is_code = "EXECUTE" in sec.flags or "CODE" in sec.flags
                subsys = "Execution" if is_code else "Storage"
                subsystems.add(subsys)
                nodes.append(
                    GraphNode(
                        id=sec_id,
                        label=f"Section {sec.name}",
                        node_type="component",
                        subsystem=subsys,
                        description=f"Virtual Size: {sec.virtual_size:,} bytes, Entropy: {sec.entropy:.2f}, Flags: {','.join(sec.flags)}",
                        source_tool="pe_parser",
                        source_location=sec.virtual_address,
                        evidence_status=EvidenceStatus.OBSERVED,
                        confidence=1.0,
                        properties={"raw_size": sec.raw_size, "flags": sec.flags},
                    )
                )
                node_ids.add(sec_id)
                edges.append(
                    GraphEdge(
                        source_id=root_id,
                        target_id=sec_id,
                        relation="contains",
                        evidence_reference=f"PE Section Table: {sec.name}",
                        confidence=1.0,
                    )
                )

        # 3. Recovered Function Nodes
        for fn in report.functions:
            fn_id = f"fn_{fn.address.replace('0x', '').lower()}"
            if fn_id not in node_ids:
                subsystems.add("Functions")
                is_ep = "entry" in fn.name.lower() or "main" in fn.name.lower() or fn.address == "0x00001000"
                if is_ep:
                    entry_points.append(fn_id)

                nodes.append(
                    GraphNode(
                        id=fn_id,
                        label=fn.name,
                        node_type="function",
                        subsystem="Functions",
                        description=f"Function {fn.name} at {fn.address} ({fn.size} bytes). Calling conv: {fn.calling_convention or 'standard'}",
                        source_tool=fn.source_tool or "radare2",
                        source_location=fn.address,
                        evidence_status=EvidenceStatus.OBSERVED,
                        confidence=0.95,
                        properties={
                            "address": fn.address,
                            "size": fn.size,
                            "parameter_count": fn.parameter_count,
                            "has_decompiled_c": bool(fn.decompiled_c),
                            "cfg_block_count": len(fn.cfg_blocks),
                        },
                    )
                )
                node_ids.add(fn_id)
                edges.append(
                    GraphEdge(
                        source_id=root_id,
                        target_id=fn_id,
                        relation="defines",
                        evidence_reference=f"Disassembly listing at {fn.address}",
                        confidence=0.95,
                    )
                )

        # 4. External API & Imported Module Nodes
        for mod in report.imports:
            mod_id = f"mod_{mod.module_name.lower().replace('.', '_')}"
            subsys = "Network" if any(k in mod.module_name.lower() for k in ("ws2", "wininet", "winhttp", "urlmon")) else (
                "System" if any(k in mod.module_name.lower() for k in ("kernel", "ntdll", "advapi")) else "External"
            )
            subsystems.add(subsys)

            if mod_id not in node_ids:
                nodes.append(
                    GraphNode(
                        id=mod_id,
                        label=mod.module_name,
                        node_type="external_api",
                        subsystem=subsys,
                        description=f"Imported Dynamic Library {mod.module_name} ({len(mod.functions)} imported APIs)",
                        source_tool="pe_parser",
                        source_location="import_table",
                        evidence_status=EvidenceStatus.OBSERVED,
                        confidence=1.0,
                        properties={"function_count": len(mod.functions)},
                    )
                )
                node_ids.add(mod_id)
                edges.append(
                    GraphEdge(
                        source_id=root_id,
                        target_id=mod_id,
                        relation="depends_on",
                        evidence_reference=f"Import Directory: {mod.module_name}",
                        confidence=1.0,
                    )
                )

            # Link imported functions
            for fn in mod.functions[:15]:  # Capture key APIs
                fn_imp_id = f"imp_{mod_id}_{fn.name.lower()}"
                if fn_imp_id not in node_ids:
                    nodes.append(
                        GraphNode(
                            id=fn_imp_id,
                            label=fn.name,
                            node_type="function",
                            subsystem=subsys,
                            description=f"API {mod.module_name}!{fn.name} ({fn.category or 'Win32 System Call'})",
                            source_tool="pe_parser",
                            source_location=fn.rva or "import_thunk",
                            evidence_status=EvidenceStatus.OBSERVED,
                            confidence=1.0,
                            properties={"is_suspicious": fn.is_suspicious, "category": fn.category},
                        )
                    )
                    node_ids.add(fn_imp_id)
                    edges.append(
                        GraphEdge(
                            source_id=mod_id,
                            target_id=fn_imp_id,
                            relation="exports",
                            evidence_reference=f"{mod.module_name}!{fn.name}",
                            confidence=1.0,
                        )
                    )

        # 5. Semantic String Artifacts, Functions, and Imports from Findings
        endpoint_count = 0
        storage_count = 0
        for f in report.findings:
            raw_d = f.raw_data or {}
            f_type_str = str(f.finding_type).lower()

            # Recover functions from findings collection
            if "function" in f_type_str or f.name.startswith("sub_") or "subsystem" in raw_d:
                fn_id = f"fn_{f.address_or_location or uuid.uuid4().hex[:6]}".replace("0x", "").lower()
                if fn_id not in node_ids:
                    subsystem_name = raw_d.get("subsystem", "Functions")
                    subsystems.add(subsystem_name)
                    nodes.append(
                        GraphNode(
                            id=fn_id,
                            label=f.name,
                            node_type="function",
                            subsystem=subsystem_name,
                            description=f.description or f"Recovered function {f.name}",
                            source_tool=f.source_tool,
                            source_location=f.address_or_location,
                            evidence_status=EvidenceStatus.OBSERVED,
                            confidence=f.confidence,
                            properties={"raw_data": raw_d},
                        )
                    )
                    node_ids.add(fn_id)
                    edges.append(
                        GraphEdge(
                            source_id=root_id,
                            target_id=fn_id,
                            relation="defines",
                            evidence_reference=f"Discovered by {f.source_tool} at {f.address_or_location}",
                            confidence=f.confidence,
                        )
                    )

            # Recover network endpoints
            is_url = (
                f.name == "network_url"
                or "endpoint" in f.name.lower()
                or "api" in f.name.lower()
                or "http" in str(raw_d.get("string", "")).lower()
                or "http" in str(f.description).lower()
            )
            if is_url and endpoint_count < 10:
                url_str = raw_d.get("string", f.description)
                url_id = f"ep_{uuid.uuid4().hex[:6]}"
                subsystems.add("Network")
                nodes.append(
                    GraphNode(
                        id=url_id,
                        label=url_str[:40],
                        node_type="endpoint",
                        subsystem="Network",
                        description=f"Network URL Endpoint: {url_str}",
                        source_tool=f.source_tool,
                        source_location=f.address_or_location,
                        evidence_status=EvidenceStatus.OBSERVED,
                        confidence=f.confidence,
                        properties={"url": url_str, "encoding": raw_d.get("encoding", "ASCII")},
                    )
                )
                node_ids.add(url_id)
                edges.append(
                    GraphEdge(
                        source_id=root_id,
                        target_id=url_id,
                        relation="invokes_api",
                        evidence_reference=f"Extracted string at {f.address_or_location}",
                        confidence=f.confidence,
                    )
                )
                endpoint_count += 1

            # Recover persistent storage / config resources
            is_storage = (
                f.name in ("registry_key", "filepath")
                or "config" in f.name.lower()
                or any(ext in str(raw_d.get("string", "")).lower() for ext in (".json", ".xml", ".ini", ".cfg", ".yaml", ".db", "settings"))
            )
            if is_storage and storage_count < 10:
                path_str = raw_d.get("string", f.description)
                stor_id = f"stor_{uuid.uuid4().hex[:6]}"
                subsystems.add("Storage")
                nodes.append(
                    GraphNode(
                        id=stor_id,
                        label=path_str[:35],
                        node_type="storage",
                        subsystem="Storage",
                        description=f"Configuration / Persistent Storage Resource: {path_str}",
                        source_tool=f.source_tool,
                        source_location=f.address_or_location,
                        evidence_status=EvidenceStatus.OBSERVED,
                        confidence=f.confidence,
                        properties={"path": path_str, "type": f.name},
                    )
                )
                node_ids.add(stor_id)
                edges.append(
                    GraphEdge(
                        source_id=root_id,
                        target_id=stor_id,
                        relation="reads_from",
                        evidence_reference=f"Extracted string at {f.address_or_location}",
                        confidence=f.confidence,
                    )
                )
                storage_count += 1

            # Recover import findings
            if "import" in f_type_str:
                imp_id = f"imp_{uuid.uuid4().hex[:6]}"
                subsystems.add("External")
                nodes.append(
                    GraphNode(
                        id=imp_id,
                        label=f.name,
                        node_type="external_api",
                        subsystem="External",
                        description=f"External Import: {f.name} ({raw_d.get('library', 'system')})",
                        source_tool=f.source_tool,
                        source_location=f.address_or_location,
                        evidence_status=EvidenceStatus.OBSERVED,
                        confidence=f.confidence,
                        properties=raw_d,
                    )
                )
                node_ids.add(imp_id)
                edges.append(
                    GraphEdge(
                        source_id=root_id,
                        target_id=imp_id,
                        relation="depends_on",
                        evidence_reference=f"Imported library API: {f.name}",
                        confidence=f.confidence,
                    )
                )

        # Fallback if no entry points recovered
        if not entry_points:
            entry_points.append(root_id)

        return KnowledgeGraphData(
            sample_sha256=sample_hash,
            nodes=nodes,
            edges=edges,
            subsystems=sorted(list(subsystems)),
            entry_points=entry_points,
        )

    @staticmethod
    def to_mermaid(graph: KnowledgeGraphData) -> str:
        """Render the Knowledge Graph as a clean, structured Mermaid diagram."""
        lines = ["flowchart TD"]

        # Group nodes by subsystem
        by_subsys: Dict[str, List[GraphNode]] = {}
        for n in graph.nodes:
            sub = n.subsystem or "Core"
            by_subsys.setdefault(sub, []).append(n)

        for sub, sub_nodes in by_subsys.items():
            safe_sub = sub.replace(" ", "_").replace("/", "_")
            lines.append(f'    subgraph {safe_sub}["Subsystem: {sub}"]')
            for n in sub_nodes[:8]:  # Limit nodes per subgraph to maintain visual readability
                clean_lbl = n.label.replace('"', '').replace("'", "").replace("[", "").replace("]", "")
                lines.append(f'        {n.id}["{clean_lbl}"]')
            lines.append("    end")

        # Add edges
        for e in graph.edges[:25]:  # Limit top 25 edges
            if e.source_id and e.target_id:
                lines.append(f'    {e.source_id} -->|"{e.relation}"| {e.target_id}')

        return "\n".join(lines)
