"""
Jarvis RE — Ghidra Headless Adapter
Wraps Ghidra's ``analyzeHeadless`` for automated static analysis:
function enumeration, import/export tables, strings, cross-references, and
entry-point discovery.
"""

import json
import logging
import os
import shutil
import textwrap
import uuid
from typing import Any, Dict, List, Optional

from .base_adapter import BaseAdapter

logger = logging.getLogger("jarvis.re.adapters.ghidra")

# --------------------------------------------------------------------- #
# Ghidra Jython post-analysis script                                     #
# Written out to a temp file and passed to analyzeHeadless via           #
# ``-postScript``.  The script dumps analysis artefacts as JSON to a     #
# results file whose path is received via the ``JARVIS_OUTPUT``          #
# environment variable (or a script property).                           #
# --------------------------------------------------------------------- #

_GHIDRA_JYTHON_SCRIPT: str = textwrap.dedent(r'''
# @category Jarvis
# @description Export analysis artefacts as JSON for Jarvis RE.

import json
import os
import sys

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.listing import CodeUnit


def get_output_path():
    """Resolve the JSON output file path."""
    # Prefer the script property set by the adapter.
    try:
        p = askString("OutputPath", "Path for JSON output")
        if p:
            return p
    except Exception:
        pass
    # Fallback to environment variable.
    return os.environ.get("JARVIS_OUTPUT", "jarvis_ghidra_output.json")


def collect_functions(fm):
    """Collect all functions in the programme."""
    results = []
    func = fm.getFirstFunction()
    while func is not None:
        entry = func.getEntryPoint()
        results.append({
            "address": str(entry),
            "name": func.getName(),
            "size": int(func.getBody().getNumAddresses()),
            "calling_convention": str(func.getCallingConventionName()),
            "is_thunk": func.isThunk(),
            "is_external": func.isExternal(),
            "parameter_count": func.getParameterCount(),
        })
        func = fm.getFunctionAfter(func)
    return results


def collect_imports(st):
    """Collect imported symbols."""
    results = []
    for sym in st.getExternalSymbols():
        results.append({
            "address": str(sym.getAddress()),
            "name": sym.getName(),
            "namespace": str(sym.getParentNamespace()),
            "type": str(sym.getSymbolType()),
        })
    return results


def collect_exports(st):
    """Collect exported symbols."""
    results = []
    si = st.getSymbolIterator()
    while si.hasNext():
        sym = si.next()
        if sym.isExternalEntryPoint() and not sym.isExternal():
            results.append({
                "address": str(sym.getAddress()),
                "name": sym.getName(),
                "namespace": str(sym.getParentNamespace()),
                "type": str(sym.getSymbolType()),
            })
    return results


def collect_strings(listing, mem):
    """Collect defined string data from the listing."""
    results = []
    data_iter = listing.getDefinedData(True)
    while data_iter.hasNext():
        d = data_iter.next()
        dt = d.getDataType()
        if dt is not None and ("string" in dt.getName().lower() or "unicode" in dt.getName().lower()):
            val = d.getValue()
            if val is not None:
                s = str(val)
                if len(s) >= 4:  # skip trivially short strings
                    results.append({
                        "address": str(d.getAddress()),
                        "value": s[:2048],  # cap length
                        "type": dt.getName(),
                        "length": len(s),
                    })
    return results


def collect_entry_points(st):
    """Collect programme entry points."""
    results = []
    si = st.getSymbolIterator()
    while si.hasNext():
        sym = si.next()
        if sym.isExternalEntryPoint():
            results.append({
                "address": str(sym.getAddress()),
                "name": sym.getName(),
            })
    return results


def collect_xrefs(rm, fm):
    """Collect cross-references for the first N functions (bounded)."""
    MAX_FUNCS = 500
    MAX_REFS_PER_FUNC = 50
    results = []
    count = 0
    func = fm.getFirstFunction()
    while func is not None and count < MAX_FUNCS:
        entry = func.getEntryPoint()
        refs = rm.getReferencesTo(entry)
        refs_list = []
        for i, ref in enumerate(refs):
            if i >= MAX_REFS_PER_FUNC:
                break
            refs_list.append({
                "from_address": str(ref.getFromAddress()),
                "type": str(ref.getReferenceType()),
            })
        if refs_list:
            results.append({
                "target_address": str(entry),
                "target_name": func.getName(),
                "references": refs_list,
            })
        func = fm.getFunctionAfter(func)
        count += 1
    return results


def main():
    output_path = get_output_path()

    program = currentProgram
    fm = program.getFunctionManager()
    st = program.getSymbolTable()
    listing = program.getListing()
    mem = program.getMemory()
    rm = program.getReferenceManager()

    payload = {
        "program_name": program.getName(),
        "language": str(program.getLanguage().getLanguageID()),
        "compiler_spec": str(program.getCompilerSpec().getCompilerSpecID()),
        "image_base": str(program.getImageBase()),
        "executable_format": program.getExecutableFormat(),
        "functions": collect_functions(fm),
        "imports": collect_imports(st),
        "exports": collect_exports(st),
        "strings": collect_strings(listing, mem),
        "entry_points": collect_entry_points(st),
        "cross_references": collect_xrefs(rm, fm),
    }

    with open(output_path, "w") as fh:
        json.dump(payload, fh, indent=2)

    println("Jarvis: wrote %d functions, %d imports, %d exports, %d strings, %d entry points, %d xref groups to %s" % (
        len(payload["functions"]),
        len(payload["imports"]),
        len(payload["exports"]),
        len(payload["strings"]),
        len(payload["entry_points"]),
        len(payload["cross_references"]),
        output_path,
    ))


main()
''').lstrip()

# --------------------------------------------------------------------- #
# Common install locations                                                #
# --------------------------------------------------------------------- #

_COMMON_GHIDRA_PATHS: List[str] = [
    r"C:\Program Files\Ghidra",
    r"C:\Tools\ghidra",
    r"C:\ghidra",
    os.path.expanduser("~/ghidra"),
    "/opt/ghidra",
    "/usr/local/share/ghidra",
    "/usr/share/ghidra",
]


class GhidraAdapter(BaseAdapter):
    """Adapter for Ghidra headless analysis (``analyzeHeadless``).

    The adapter creates a temporary Ghidra project in *workspace_path*,
    imports the target binary, runs auto-analysis, and then executes a
    Jython post-script that dumps functions, imports, exports, strings,
    entry-points and cross-references as JSON.
    """

    TOOL_NAME: str = "ghidra"

    def __init__(
        self,
        tool_path: Optional[str] = None,
        timeout: int = 600,
        java_path: Optional[str] = None,
    ):
        """
        Args:
            tool_path: Path to the Ghidra install directory (``GHIDRA_HOME``).
            timeout:   Maximum seconds for the headless run.
            java_path: Explicit path to ``java`` if not on PATH.
        """
        super().__init__(tool_path=tool_path, timeout=timeout)
        self.java_path = java_path
        if self.tool_path is None:
            self.tool_path = self._find_ghidra_home()

    # ------------------------------------------------------------------
    # BaseAdapter interface
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Ghidra requires both its own install *and* a working JDK."""
        return self._ghidra_headless_path() is not None and self._java_available()

    def get_version(self) -> Optional[str]:
        """Extract version from ``application.properties`` inside the
        Ghidra install directory."""
        if self.tool_path is None:
            return None
        props = os.path.join(self.tool_path, "Ghidra", "application.properties")
        if not os.path.isfile(props):
            # Alternate location in some distributions
            props = os.path.join(self.tool_path, "application.properties")
        if not os.path.isfile(props):
            return None
        try:
            with open(props, "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("application.version="):
                        return line.split("=", 1)[1].strip()
        except OSError:
            pass
        return None

    def get_supported_types(self) -> List[str]:
        return ["PE", "PE+", "ELF", "Mach-O", "COFF", "RAW", "DEX"]

    def analyze(
        self,
        sample_path: str,
        workspace_path: str,
        options: Optional[dict] = None,
    ) -> List[Dict[str, Any]]:
        """Run Ghidra headless analysis and return normalised findings.

        Args:
            sample_path:    Binary to analyse.
            workspace_path: Directory for the Ghidra project and outputs.
            options:        Optional dict.  Recognised keys:
                            - ``analysis_timeout`` (int): override timeout.
                            - ``max_cpu`` (int): ``-max-cpu`` flag value.
        """
        if not self.is_available():
            raise RuntimeError("Ghidra (or Java) is not available")
        if not os.path.isfile(sample_path):
            raise FileNotFoundError(f"Sample not found: {sample_path}")

        options = options or {}
        os.makedirs(workspace_path, exist_ok=True)

        project_name = f"jarvis_{uuid.uuid4().hex[:8]}"
        output_file = os.path.join(workspace_path, f"{project_name}_results.json")
        script_file = os.path.join(workspace_path, "jarvis_ghidra_export.py")

        # Write Jython script to disk
        self._write_ghidra_script(script_file, output_file)

        # Build analyzeHeadless command
        cmd = self._build_headless_cmd(
            project_dir=workspace_path,
            project_name=project_name,
            sample_path=sample_path,
            script_file=script_file,
            output_file=output_file,
            options=options,
        )

        self.logger.info("Starting Ghidra headless analysis on %s", sample_path)
        analysis_timeout = options.get("analysis_timeout", self.timeout)

        env = {}
        if self.java_path:
            java_bin_dir = os.path.dirname(self.java_path)
            java_home = os.path.dirname(java_bin_dir)
            env["JAVA_HOME"] = java_home
            env["PATH"] = f"{java_bin_dir};{os.environ.get('PATH', '')}"

        result = self._run_process(cmd, cwd=workspace_path, timeout=analysis_timeout, env=env)

        if result.returncode != 0:
            self.logger.warning(
                "Ghidra exited with code %d. stderr (last 1000 chars): %s",
                result.returncode,
                (result.stderr or "")[-1000:],
            )
            # Non-zero does not always mean failure — the script may have
            # still produced output.

        # Parse script output
        findings = self._parse_results(output_file, sample_path)
        self.logger.info(
            "Ghidra produced %d finding(s) for %s", len(findings), sample_path
        )
        return findings

    # ------------------------------------------------------------------
    # Helpers — Ghidra location
    # ------------------------------------------------------------------

    @staticmethod
    def _find_ghidra_home() -> Optional[str]:
        """Try to locate ``GHIDRA_HOME`` on the system."""
        # 1. Environment variable
        env = os.environ.get("GHIDRA_HOME") or os.environ.get("GHIDRA_INSTALL_DIR")
        if env and os.path.isdir(env):
            return env

        # 2. Common paths — look for the *support* sub-directory which
        #    contains ``analyzeHeadless``.
        for base in _COMMON_GHIDRA_PATHS:
            if os.path.isdir(base):
                # Ghidra may be directly here or one level deeper (versioned dir)
                if os.path.isdir(os.path.join(base, "support")):
                    return base
                # Check versioned sub-dirs like ghidra_11.0
                try:
                    for child in os.listdir(base):
                        candidate = os.path.join(base, child)
                        if os.path.isdir(os.path.join(candidate, "support")):
                            return candidate
                except OSError:
                    pass

        # 3. ``analyzeHeadless`` on PATH (derive home from it)
        which = shutil.which("analyzeHeadless") or shutil.which("analyzeHeadless.bat")
        if which:
            # analyzeHeadless lives in <GHIDRA_HOME>/support/
            return os.path.dirname(os.path.dirname(os.path.abspath(which)))

        return None

    def _ghidra_headless_path(self) -> Optional[str]:
        """Return the path to ``analyzeHeadless`` (or ``.bat`` on Win)."""
        if self.tool_path is None:
            return None
        support = os.path.join(self.tool_path, "support")
        if os.name == "nt":
            candidate = os.path.join(support, "analyzeHeadless.bat")
        else:
            candidate = os.path.join(support, "analyzeHeadless")
        return candidate if os.path.isfile(candidate) else None

    def _find_java(self) -> Optional[str]:
        """Locate a working Java executable."""
        if self.java_path and os.path.isfile(self.java_path):
            return self.java_path

        env_home = os.environ.get("JAVA_HOME")
        if env_home:
            cand = os.path.join(env_home, "bin", "java.exe" if os.name == "nt" else "java")
            if os.path.isfile(cand):
                return cand

        which = shutil.which("java") or shutil.which("java.exe")
        if which:
            return which

        # Search common directories on Windows
        import glob
        for pattern in [
            r"C:\Tools\jdk-21\*\bin\java.exe",
            r"C:\Tools\jdk*\bin\java.exe",
            r"C:\Tools\jdk*\*\bin\java.exe",
            r"C:\Program Files\Eclipse Adoptium\*\bin\java.exe",
            r"C:\Program Files\Java\*\bin\java.exe",
        ]:
            matches = glob.glob(pattern)
            if matches and os.path.isfile(matches[0]):
                return matches[0]

        return None

    def _java_available(self) -> bool:
        """Return *True* if a usable ``java`` binary is reachable."""
        java = self._find_java()
        if java is None:
            return False
        try:
            self.java_path = java
            result = self._run_process([java, "-version"], timeout=15)
            return result.returncode == 0
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Helpers — command building
    # ------------------------------------------------------------------

    def _build_headless_cmd(
        self,
        project_dir: str,
        project_name: str,
        sample_path: str,
        script_file: str,
        output_file: str,
        options: dict,
    ) -> List[str]:
        """Assemble the ``analyzeHeadless`` command line."""
        headless = self._ghidra_headless_path()
        if headless is None:
            raise RuntimeError("Cannot locate analyzeHeadless")

        cmd = [
            headless,
            project_dir,
            project_name,
            "-import", sample_path,
            "-postScript", script_file,
            "-scriptPath", os.path.dirname(script_file),
            "-deleteProject",   # clean up after ourselves
            "-noanalysis",      # we enable specific analysers below
            "-analysisTimeoutPerFile", str(options.get("analysis_timeout", self.timeout)),
        ]

        # Re-enable auto-analysis (the -noanalysis flag above is so we can
        # add the -postScript *after* analysis; Ghidra still runs analysis
        # when -postScript is present unless we explicitly skip).
        # Actually, analyzeHeadless runs analysis by default; -noanalysis
        # skips it.  We want analysis, so remove the flag:
        cmd.remove("-noanalysis")

        max_cpu = options.get("max_cpu")
        if max_cpu:
            cmd.extend(["-max-cpu", str(max_cpu)])

        return cmd

    # ------------------------------------------------------------------
    # Helpers — script generation
    # ------------------------------------------------------------------

    def _write_ghidra_script(self, script_path: str, output_path: str) -> None:
        """Write the Jython post-analysis script to *script_path*.

        The output path is baked directly into the script so that no
        environment variable plumbing is required.
        """
        # Replace the dynamic output-path resolution in the template with a
        # hard-coded path for this run.
        patched = _GHIDRA_JYTHON_SCRIPT.replace(
            'os.environ.get("JARVIS_OUTPUT", "jarvis_ghidra_output.json")',
            f'r"{output_path}"',
        )
        with open(script_path, "w", encoding="utf-8") as fh:
            fh.write(patched)
        self.logger.debug("Wrote Ghidra post-script to %s", script_path)

    # ------------------------------------------------------------------
    # Helpers — result parsing
    # ------------------------------------------------------------------

    def _parse_results(
        self, output_file: str, sample_path: str
    ) -> List[Dict[str, Any]]:
        """Read the JSON produced by the post-script and convert to
        normalised findings."""
        findings: List[Dict[str, Any]] = []

        if not os.path.isfile(output_file):
            self.logger.error("Ghidra output file not found: %s", output_file)
            return findings

        try:
            with open(output_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            self.logger.error("Failed to read Ghidra output: %s", exc)
            return findings

        # -- Programme metadata --
        findings.append(
            self._make_finding(
                finding_type="metadata",
                name=f"Ghidra analysis: {data.get('program_name', 'unknown')}",
                description=(
                    f"Language: {data.get('language', '?')}, "
                    f"Compiler spec: {data.get('compiler_spec', '?')}, "
                    f"Format: {data.get('executable_format', '?')}, "
                    f"Image base: {data.get('image_base', '?')}"
                ),
                confidence=0.95,
                raw_data={
                    "program_name": data.get("program_name"),
                    "language": data.get("language"),
                    "compiler_spec": data.get("compiler_spec"),
                    "image_base": data.get("image_base"),
                    "executable_format": data.get("executable_format"),
                },
            )
        )

        # -- Functions --
        for func in data.get("functions", []):
            findings.append(
                self._make_finding(
                    finding_type="function",
                    address=func.get("address"),
                    name=func.get("name"),
                    description=(
                        f"Size: {func.get('size')} bytes, "
                        f"CC: {func.get('calling_convention', '?')}, "
                        f"Params: {func.get('parameter_count', '?')}"
                    ),
                    confidence=0.85,
                    raw_data=func,
                )
            )

        # -- Imports --
        for imp in data.get("imports", []):
            findings.append(
                self._make_finding(
                    finding_type="import",
                    address=imp.get("address"),
                    name=imp.get("name"),
                    description=f"Namespace: {imp.get('namespace', '?')}",
                    confidence=0.90,
                    raw_data=imp,
                )
            )

        # -- Exports --
        for exp in data.get("exports", []):
            findings.append(
                self._make_finding(
                    finding_type="export",
                    address=exp.get("address"),
                    name=exp.get("name"),
                    description=f"Namespace: {exp.get('namespace', '?')}",
                    confidence=0.90,
                    raw_data=exp,
                )
            )

        # -- Strings --
        for s in data.get("strings", []):
            findings.append(
                self._make_finding(
                    finding_type="string",
                    address=s.get("address"),
                    name=s.get("value", "")[:120],
                    description=f"Type: {s.get('type', '?')}, length: {s.get('length', '?')}",
                    confidence=0.80,
                    raw_data=s,
                )
            )

        # -- Entry points --
        for ep in data.get("entry_points", []):
            findings.append(
                self._make_finding(
                    finding_type="entry_point",
                    address=ep.get("address"),
                    name=ep.get("name"),
                    description="Programme entry point",
                    confidence=0.95,
                    raw_data=ep,
                )
            )

        # -- Cross-references --
        for xref_group in data.get("cross_references", []):
            for ref in xref_group.get("references", []):
                findings.append(
                    self._make_finding(
                        finding_type="cross_reference",
                        address=ref.get("from_address"),
                        name=(
                            f"xref → {xref_group.get('target_name', '?')} "
                            f"@ {xref_group.get('target_address', '?')}"
                        ),
                        description=f"Ref type: {ref.get('type', '?')}",
                        confidence=0.85,
                        raw_data={
                            "from_address": ref.get("from_address"),
                            "target_address": xref_group.get("target_address"),
                            "target_name": xref_group.get("target_name"),
                            "reference_type": ref.get("type"),
                        },
                    )
                )

        return findings
