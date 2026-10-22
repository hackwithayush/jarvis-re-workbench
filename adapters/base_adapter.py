"""
Jarvis RE — Base Adapter
Abstract base class for all reverse-engineering tool adapters.
"""

import abc
import subprocess
import logging
import os
import json
import shlex
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone


class BaseAdapter(abc.ABC):
    """Abstract base for all RE tool adapters.

    Every concrete adapter wraps a single external reverse-engineering tool
    (Ghidra, radare2, DIE, etc.) and communicates with it exclusively via
    subprocess calls.  Findings are returned in a normalised schema so the
    rest of Jarvis can consume them uniformly.
    """

    TOOL_NAME: str = "unknown"  # Override in every subclass

    def __init__(self, tool_path: Optional[str] = None, timeout: int = 300):
        """Initialise the adapter.

        Args:
            tool_path: Explicit path to the tool binary.  If *None* the
                       adapter will try to locate the tool automatically.
            timeout:   Default timeout in seconds for subprocess calls.
        """
        self.tool_path = tool_path
        self.timeout = timeout
        self.logger = logging.getLogger(f"jarvis.re.adapters.{self.TOOL_NAME}")

    # ------------------------------------------------------------------
    # Abstract interface — every adapter MUST implement these
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Check if the tool is installed and accessible."""
        ...

    @abc.abstractmethod
    def get_version(self) -> Optional[str]:
        """Return the tool version string, or *None* if unavailable."""
        ...

    @abc.abstractmethod
    def analyze(
        self,
        sample_path: str,
        workspace_path: str,
        options: Optional[dict] = None,
    ) -> List[Dict[str, Any]]:
        """Run analysis on *sample_path* and return normalised findings.

        Args:
            sample_path:    Absolute path to the binary / sample to analyse.
            workspace_path: Directory where the adapter may store temporary
                            artefacts (projects, databases, script output …).
            options:        Adapter-specific options (may be *None*).

        Returns:
            A list of finding dicts that conform to the schema defined in
            ``REVERSE_ENGINEERING/schema.py``.
        """
        ...

    # ------------------------------------------------------------------
    # Optional overrides
    # ------------------------------------------------------------------

    def get_supported_types(self) -> List[str]:
        """Return list of file types this adapter can handle."""
        return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _run_process(
        self,
        cmd: List[str],
        cwd: Optional[str] = None,
        timeout: Optional[int] = None,
        env: Optional[dict] = None,
        input_data: Optional[str] = None,
    ) -> subprocess.CompletedProcess:
        """Run a subprocess with timeout and robust error handling.

        Args:
            cmd:        Command + arguments list.
            cwd:        Working directory for the child process.
            timeout:    Per-call timeout in seconds (falls back to
                        ``self.timeout``).
            env:        Extra environment variables merged on top of
                        ``os.environ``.
            input_data: Optional string piped to the process's *stdin*.

        Returns:
            ``subprocess.CompletedProcess`` on success.

        Raises:
            TimeoutError:               If the process exceeds *timeout*.
            subprocess.SubprocessError: On any other subprocess failure.
        """
        effective_timeout = timeout if timeout is not None else self.timeout

        # Build environment — start from the current environment and layer
        # any adapter-specific variables on top.
        run_env = os.environ.copy()
        if env:
            run_env.update(env)

        # Log the command (mask anything that looks like a secret/token).
        sanitised_cmd = " ".join(
            ("***" if any(s in part.lower() for s in ("token", "secret", "password", "key=")) else part)
            for part in cmd
        )
        self.logger.debug("Running: %s (timeout=%ss, cwd=%s)", sanitised_cmd, effective_timeout, cwd)

        try:
            result = subprocess.run(
                cmd,
                cwd=cwd,
                env=run_env,
                input=input_data,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
            )
            self.logger.debug(
                "Process exited with code %d (stdout=%d bytes, stderr=%d bytes)",
                result.returncode,
                len(result.stdout) if result.stdout else 0,
                len(result.stderr) if result.stderr else 0,
            )
            return result

        except subprocess.TimeoutExpired as exc:
            self.logger.error("Process timed out after %ds: %s", effective_timeout, sanitised_cmd)
            raise TimeoutError(
                f"{self.TOOL_NAME} process timed out after {effective_timeout}s"
            ) from exc

        except FileNotFoundError as exc:
            self.logger.error("Executable not found: %s", cmd[0])
            raise subprocess.SubprocessError(
                f"Executable not found: {cmd[0]}"
            ) from exc

        except subprocess.SubprocessError as exc:
            self.logger.error("Subprocess error: %s", exc)
            raise

    def _make_finding(self, finding_type: str, **kwargs: Any) -> Dict[str, Any]:
        """Create a normalised finding dict.

        The returned dict matches the schema expected by
        ``REVERSE_ENGINEERING/schema.py``.
        """
        finding: Dict[str, Any] = {
            "source_tool": self.TOOL_NAME,
            "finding_type": finding_type,
            "address": kwargs.get("address"),
            "name": kwargs.get("name"),
            "description": kwargs.get("description"),
            "evidence": kwargs.get("evidence", []),
            "confidence": kwargs.get("confidence", 0.5),
            "status": "unverified",
            "raw_data": kwargs.get("raw_data", {}),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        return finding

    def get_status(self) -> Dict[str, Any]:
        """Return a status snapshot for this adapter."""
        available = self.is_available()
        return {
            "tool": self.TOOL_NAME,
            "available": available,
            "version": self.get_version() if available else None,
            "path": self.tool_path,
            "supported_types": self.get_supported_types(),
        }
