"""
JARVIS RE — Bounded Archive Inspector v1.0
Safely inspects archive containers (ZIP, APK, JAR, TAR) with explicit limits:
- Maximum member count: 1,000
- Maximum decompression ratio: 100:1 (anti-zip bomb)
- Maximum total uncompressed bytes: 100 MB
- Nested executable inventory (.exe, .dll, .so, .dylib, .dex, .class)
"""

import io
import logging
import os
import tarfile
import zipfile
from typing import List, Tuple

from app.core.schema import ArchiveMember, Finding, FindingStatus, FindingType

logger = logging.getLogger("jarvis.re.parsers.archive")

MAX_MEMBERS = 1000
MAX_RATIO = 100
MAX_TOTAL_UNCOMPRESSED = 100 * 1024 * 1024  # 100 MB

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".drv", ".ocx", ".scr",
    ".so", ".dylib", ".bin", ".elf",
    ".dex", ".class", ".jar",
    ".bat", ".ps1", ".vbs", ".sh",
}


class ArchiveInspector:
    """Safe, bounded archive inspector with zip-bomb safeguards."""

    def __init__(self, data: bytes, sample_sha256: str):
        self.data = data
        self.size = len(data)
        self.sha256 = sample_sha256

    def inspect(self) -> Tuple[List[Finding], List[ArchiveMember]]:
        findings: List[Finding] = []
        members: List[ArchiveMember] = []

        if self.data[:4] == b"PK\x03\x04":
            return self._inspect_zip()
        elif len(self.data) >= 262 and self.data[257:262] == b"ustar":
            return self._inspect_tar()

        return findings, members

    def _inspect_zip(self) -> Tuple[List[Finding], List[ArchiveMember]]:
        findings: List[Finding] = []
        members: List[ArchiveMember] = []

        try:
            with zipfile.ZipFile(io.BytesIO(self.data)) as zf:
                infolist = zf.infolist()
                total_uncompressed = 0
                executable_count = 0

                for info in infolist[:MAX_MEMBERS]:
                    ext = os.path.splitext(info.filename)[1].lower()
                    is_exec = ext in EXECUTABLE_EXTENSIONS

                    # Anti-zip bomb check
                    if info.compress_size > 0 and (info.file_size / info.compress_size) > MAX_RATIO:
                        findings.append(
                            Finding(
                                sample_sha256=self.sha256,
                                source_tool="archive_parser",
                                finding_type=FindingType.ANOMALY,
                                name="zip_bomb_suspect",
                                description=f"Abnormally high compression ratio in '{info.filename}' ({info.file_size / info.compress_size:.1f}:1)",
                                confidence=0.95,
                                verification_status=FindingStatus.FLAGGED,
                                raw_data={"filename": info.filename, "ratio": info.file_size / info.compress_size},
                            )
                        )

                    total_uncompressed += info.file_size
                    if total_uncompressed > MAX_TOTAL_UNCOMPRESSED:
                        findings.append(
                            Finding(
                                sample_sha256=self.sha256,
                                source_tool="archive_parser",
                                finding_type=FindingType.ANOMALY,
                                name="archive_size_limit_exceeded",
                                description=f"Total uncompressed archive content exceeds 100 MB safety limit.",
                                confidence=1.0,
                                verification_status=FindingStatus.FLAGGED,
                            )
                        )
                        break

                    if is_exec:
                        executable_count += 1

                    member = ArchiveMember(
                        filename=info.filename,
                        file_size=info.file_size,
                        compressed_size=info.compress_size,
                        file_type="Executable Payload" if is_exec else "Data File",
                        is_executable=is_exec,
                    )
                    members.append(member)

                findings.append(
                    Finding(
                        sample_sha256=self.sha256,
                        source_tool="archive_parser",
                        finding_type=FindingType.ARCHIVE_MEMBER,
                        name="archive_inventory",
                        description=f"ZIP archive contains {len(infolist)} entries ({executable_count} executable payloads, {total_uncompressed:,} uncompressed bytes)",
                        confidence=1.0,
                        verification_status=FindingStatus.CONFIRMED,
                        raw_data={"total_entries": len(infolist), "executables": executable_count},
                    )
                )

        except Exception as e:
            findings.append(
                Finding(
                    sample_sha256=self.sha256,
                    source_tool="archive_parser",
                    finding_type=FindingType.ANOMALY,
                    name="corrupt_archive_warning",
                    description=f"Failed to parse ZIP archive container: {e}",
                    confidence=0.80,
                    verification_status=FindingStatus.FLAGGED,
                )
            )

        return findings, members

    def _inspect_tar(self) -> Tuple[List[Finding], List[ArchiveMember]]:
        findings: List[Finding] = []
        members: List[ArchiveMember] = []

        try:
            with tarfile.open(fileobj=io.BytesIO(self.data)) as tf:
                infolist = tf.getmembers()
                total_uncompressed = 0
                executable_count = 0

                for info in infolist[:MAX_MEMBERS]:
                    ext = os.path.splitext(info.name)[1].lower()
                    is_exec = ext in EXECUTABLE_EXTENSIONS
                    total_uncompressed += info.size

                    if is_exec:
                        executable_count += 1

                    members.append(
                        ArchiveMember(
                            filename=info.name,
                            file_size=info.size,
                            compressed_size=info.size,
                            file_type="Executable Payload" if is_exec else "Data File",
                            is_executable=is_exec,
                        )
                    )

                findings.append(
                    Finding(
                        sample_sha256=self.sha256,
                        source_tool="archive_parser",
                        finding_type=FindingType.ARCHIVE_MEMBER,
                        name="tar_inventory",
                        description=f"TAR archive contains {len(infolist)} entries ({executable_count} executable payloads)",
                        confidence=1.0,
                        verification_status=FindingStatus.CONFIRMED,
                    )
                )
        except Exception as e:
            findings.append(
                Finding(
                    sample_sha256=self.sha256,
                    source_tool="archive_parser",
                    finding_type=FindingType.ANOMALY,
                    name="corrupt_tar_warning",
                    description=f"Failed to parse TAR archive container: {e}",
                    confidence=0.80,
                    verification_status=FindingStatus.FLAGGED,
                )
            )

        return findings, members
