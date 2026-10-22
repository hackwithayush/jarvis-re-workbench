"""
JARVIS RE — JADX Android Decompiler Adapter v1.0
Automates decompilation of Android APK, DEX, and Java JAR/class binaries
into readable Java source code and extracts AndroidManifest.xml metadata.
"""

import logging
import os
import shutil
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree

from .base_adapter import BaseAdapter

logger = logging.getLogger("jarvis.re.adapters.jadx")


class JadxAdapter(BaseAdapter):
    """Adapter for JADX Android APK and DEX decompiler."""

    TOOL_NAME: str = "jadx"

    def __init__(self, tool_path: Optional[str] = None, timeout: int = 300):
        super().__init__(tool_path=tool_path, timeout=timeout)
        if not self.tool_path:
            self.tool_path = self._find_jadx()

    def _find_jadx(self) -> Optional[str]:
        cmd = shutil.which("jadx.bat") or shutil.which("jadx")
        if cmd:
            return cmd
        for p in [r"C:\Tools\jadx\bin\jadx.bat", r"C:\Tools\jadx\bin\jadx"]:
            if os.path.isfile(p):
                return p
        return None

    def is_available(self) -> bool:
        return bool(self.tool_path and os.path.isfile(self.tool_path))

    def _get_java_env(self) -> Dict[str, str]:
        import glob
        env = os.environ.copy()
        for j in [r"C:\Tools\jdk-21\*\bin", r"C:\Program Files\Eclipse Adoptium\jdk-21*\bin"]:
            for match in glob.glob(j):
                if os.path.isdir(match):
                    env["PATH"] = match + os.pathsep + env.get("PATH", "")
                    env["JAVA_HOME"] = os.path.dirname(match)
                    if not os.environ.get("JAVA_HOME"):
                        os.environ["JAVA_HOME"] = os.path.dirname(match)
                    return env
        return env

    def get_version(self) -> Optional[str]:
        if not self.is_available():
            return None
        try:
            res = self._run_process([self.tool_path, "--version"], timeout=10, env=self._get_java_env())
            for line in res.stdout.splitlines():
                if "jadx" in line.lower() or "." in line:
                    return line.strip()
            return "jadx-1.5.6"
        except Exception:
            return "jadx-1.5.6"

    def get_supported_types(self) -> List[str]:
        return ["APK", "DEX", "JAR", "AAR", "CLASS"]

    def analyze(
        self,
        sample_path: str,
        workspace_path: str,
        options: Optional[dict] = None,
    ) -> List[Dict[str, Any]]:
        if not self.is_available():
            raise RuntimeError("JADX is not installed or not found on path.")

        findings: List[Dict[str, Any]] = []
        out_dir = os.path.join(workspace_path, "jadx_decompiled")
        os.makedirs(out_dir, exist_ok=True)

        # Decompile: jadx -d <out_dir> <sample_path>
        cmd = [self.tool_path, "-d", out_dir, "--no-debug-info", sample_path]
        res = self._run_process(cmd, timeout=self.timeout, env=self._get_java_env())

        # Parse AndroidManifest.xml if present
        manifest_path = os.path.join(out_dir, "resources", "AndroidManifest.xml")
        if os.path.isfile(manifest_path):
            try:
                tree = ElementTree.parse(manifest_path)
                root = tree.getroot()
                pkg_name = root.attrib.get("package", "unknown")
                permissions = []
                for elem in root.findall("uses-permission"):
                    name = elem.attrib.get("{http://schemas.android.com/apk/res/android}name") or elem.attrib.get("android:name")
                    if name:
                        permissions.append(name.split(".")[-1])

                findings.append(
                    self._make_finding(
                        finding_type="metadata",
                        name="android_manifest",
                        description=f"Android Package: {pkg_name}. Permissions: {', '.join(permissions[:8])}",
                        confidence=1.0,
                        raw_data={"package": pkg_name, "permissions": permissions},
                    )
                )
            except Exception as e:
                logger.warning("Manifest parsing error: %s", e)

        # Inventory recovered Java classes
        java_sources: List[str] = []
        sources_root = os.path.join(out_dir, "sources")
        if os.path.isdir(sources_root):
            for r, _, files in os.walk(sources_root):
                for f in files:
                    if f.endswith(".java"):
                        java_sources.append(os.path.relpath(os.path.join(r, f), sources_root))

        findings.append(
            self._make_finding(
                finding_type="decompiled_code",
                name="jadx_java_decompilation",
                description=f"Decompiled {len(java_sources)} Java source files from Android bytecode.",
                confidence=0.95,
                raw_data={"java_classes_count": len(java_sources), "sample_classes": java_sources[:20]},
            )
        )

        return findings
