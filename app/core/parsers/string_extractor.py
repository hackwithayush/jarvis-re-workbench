"""
JARVIS RE — Printable String Engine v2.0
Evidence-aware ASCII and UTF-16LE string extractor with:
- Noise reduction & character quality heuristics
- Exact deduplication with duplicate grouping & offset tracking
- Semantically prioritized categorization:
  * Network URLs (strict RFC syntax without trailing garbage)
  * IP addresses (differentiating IP addresses from .NET assembly version numbers)
  * Windows Registry keys & COM GUIDs
  * Suspicious Win32/Native APIs
  * File paths (Windows drive & Unix root)
  * Shell commands & execution invocations
  * Diagnostics & Error messages
- Full provenance retaining encoding and original file offsets.
"""

import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from app.core.schema import Finding, FindingStatus, FindingType

# Refined regex patterns
_URL_REGEX = re.compile(
    r"\bhttps?://[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+(?::\d{1,5})?(?:/[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*)?",
    re.IGNORECASE,
)
_IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b"
)
_REG_REGEX = re.compile(
    r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKLM|HKCU)\\[a-zA-Z0-9_\-\\]+",
    re.IGNORECASE,
)
_API_REGEX = re.compile(
    r"\b(?:VirtualAlloc[A-Za-z0-9]*|VirtualProtect[A-Za-z0-9]*|CreateProcess[A-Za-z0-9]*|WriteProcessMemory[A-Za-z0-9]*|ReadProcessMemory[A-Za-z0-9]*|"
    r"CreateRemoteThread[A-Za-z0-9]*|NtCreateThreadEx|QueueUserAPC|SetThreadContext|LoadLibrary[A-Za-z0-9]*|GetProcAddress|"
    r"WinExec|ShellExecute[A-Za-z0-9]*|URLDownloadToFile[A-Za-z0-9]*|InternetOpen[A-Za-z0-9]*|HttpSendRequest[A-Za-z0-9]*|"
    r"RegOpenKey[A-Za-z0-9]*|RegSetValue[A-Za-z0-9]*|CreateService[A-Za-z0-9]*|IsDebuggerPresent|"
    r"CheckRemoteDebuggerPresent|NtQueryInformationProcess|WSAStartup|connect)\b"
)
_FILEPATH_REGEX = re.compile(
    r"\b(?:[a-zA-Z]:\\(?:[^\s<>:\"/\\|?*]+\\)*[^\s<>:\"/\\|?*]+|/(?:usr|etc|bin|lib|tmp|var|opt)/[^\s\"\'<>]+)",
    re.IGNORECASE,
)
_CMD_REGEX = re.compile(
    r"\b(?:cmd\.exe|powershell(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|rundll32(?:\.exe)?|"
    r"mshta(?:\.exe)?|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|schtasks(?:\.exe)?)\b",
    re.IGNORECASE,
)
_ERROR_REGEX = re.compile(
    r"\b(?:exception|fatal error|access violation|failed to |error code|assertion failed|runtime error)\b",
    re.IGNORECASE,
)
_GUID_REGEX = re.compile(r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?")
_BASE64_REGEX = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")


def is_quality_string(s: str) -> bool:
    """Filter out repetitive sequences, low-alphanumeric noise, and garbled byte runs."""
    trimmed = s.strip()
    length = len(trimmed)
    if length < 4:
        return False

    # Check for excessive character repetition (e.g., 'X )UU' or 'AAAAAAAA')
    char_counts = {}
    for c in trimmed:
        char_counts[c] = char_counts.get(c, 0) + 1
    max_char_count = max(char_counts.values())
    if max_char_count / length > 0.65 and length > 4:
        return False

    # Check alphanumeric ratio for short strings
    alphanumeric_count = sum(1 for c in trimmed if c.isalnum() or c in " .-_/\\:")
    ratio = alphanumeric_count / length
    if ratio < 0.70:
        return False

    # Discard non-printable or control-character bleed
    if any(ord(c) < 32 and c not in "\t\r\n" for c in trimmed):
        return False

    return True


class StringExtractor:
    """Extracts, categorizes, deduplicates, and groups ASCII and UTF-16 printable strings."""

    def __init__(
        self,
        data: bytes,
        sample_sha256: str,
        min_len: int = 4,
        max_scan_strings: int = 5000,
        max_report_findings: int = 250,
    ):
        self.data = data
        self.sha256 = sample_sha256
        self.min_len = min_len
        self.max_scan_strings = max_scan_strings
        self.max_report_findings = max_report_findings
        self.stats: Dict[str, Any] = {
            "raw_strings_count": 0,
            "quality_filtered_count": 0,
            "deduplicated_groups_count": 0,
            "high_value_indicators_count": 0,
        }

    def extract(self) -> List[Finding]:
        """Run two-pass extraction (ASCII + UTF-16LE), quality filtering, and deduplication."""
        # raw_entry: (text, offset, encoding)
        raw_entries: List[Tuple[str, int, str]] = []

        # 1. ASCII extraction pass
        ascii_pattern = re.compile(rb"[\x20-\x7e]{" + str(self.min_len).encode() + rb",}")
        for m in ascii_pattern.finditer(self.data):
            try:
                raw_text = m.group(0).decode("latin-1", errors="ignore")
                raw_entries.append((raw_text, m.start(), "ASCII"))
            except Exception:
                continue
            if len(raw_entries) >= self.max_scan_strings // 2:
                break

        # 2. UTF-16LE extraction pass (always executed regardless of ASCII count)
        utf16_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(self.min_len).encode() + rb",}")
        for m in utf16_pattern.finditer(self.data):
            try:
                raw_text = m.group(0).decode("utf-16le", errors="ignore")
                raw_entries.append((raw_text, m.start(), "UTF-16LE"))
            except Exception:
                continue
            if len(raw_entries) >= self.max_scan_strings:
                break

        self.stats["raw_strings_count"] = len(raw_entries)

        # 3. Deduplication and Grouping
        # grouped: text -> {"encoding": enc, "offsets": [int, ...], "category": str, "confidence": float, "is_high_value": bool}
        grouped: Dict[str, Dict[str, Any]] = {}

        for text, offset, encoding in raw_entries:
            trimmed = text.strip()
            if not is_quality_string(trimmed):
                continue

            self.stats["quality_filtered_count"] += 1

            if trimmed in grouped:
                grouped[trimmed]["offsets"].append(offset)
                grouped[trimmed]["occurrences"] += 1
            else:
                cat, conf, status, high_val = self._categorize_string(trimmed)
                grouped[trimmed] = {
                    "text": trimmed,
                    "encoding": encoding,
                    "offsets": [offset],
                    "occurrences": 1,
                    "category": cat,
                    "confidence": conf,
                    "status": status,
                    "is_high_value": high_val,
                }
                if high_val:
                    self.stats["high_value_indicators_count"] += 1

        self.stats["deduplicated_groups_count"] = len(grouped)

        # 4. Prioritize high-value indicators first, followed by unique meaningful strings
        high_value_items = [item for item in grouped.values() if item["is_high_value"]]
        generic_items = [item for item in grouped.values() if not item["is_high_value"]]

        # Sort high-value by confidence descending, then occurrences
        high_value_items.sort(key=lambda x: (x["confidence"], x["occurrences"]), reverse=True)
        generic_items.sort(key=lambda x: (len(x["text"]) >= 8, x["occurrences"]), reverse=True)

        selected_items = high_value_items + generic_items
        selected_items = selected_items[:self.max_report_findings]

        findings: List[Finding] = []
        for item in selected_items:
            primary_offset = item["offsets"][0]
            occ = item["occurrences"]
            loc_str = f"0x{primary_offset:08X}"
            occ_note = f" (occurs {occ}x)" if occ > 1 else ""

            findings.append(
                Finding(
                    sample_sha256=self.sha256,
                    source_tool="string_extractor",
                    tool_version="2.0.0",
                    finding_type=FindingType.STRING,
                    address_or_location=loc_str,
                    name=item["category"],
                    description=f"[{item['category']}|{item['encoding']}] '{item['text'][:120]}'{occ_note}",
                    confidence=item["confidence"],
                    confidence_reasoning=(
                        f"Heuristic pattern match: category '{item['category']}' in {item['encoding']} encoding."
                    ),
                    verification_status=item["status"],
                    tags=[item["category"], item["encoding"].lower()],
                    raw_data={
                        "string": item["text"],
                        "file_offset": primary_offset,
                        "all_offsets": item["offsets"][:20],
                        "occurrences": occ,
                        "encoding": item["encoding"],
                        "category": item["category"],
                        "is_high_value": item["is_high_value"],
                    },
                )
            )

        return findings

    def _categorize_string(self, trimmed: str) -> Tuple[str, float, FindingStatus, bool]:
        """Classify a quality string into a semantic category."""
        # 1. URL
        if _URL_REGEX.search(trimmed):
            # Clean trailing punctuation
            clean_url = _URL_REGEX.search(trimmed).group(0).rstrip(".,;)\"'>")
            return "network_url", 0.95, FindingStatus.CONFIRMED, True

        # 2. IP Address (filter out version strings like 1.0.0.0, 10.0.12.0 when preceded by AssemblyVersion)
        ip_match = _IPV4_REGEX.search(trimmed)
        if ip_match:
            ip_str = ip_match.group(0)
            octets = [int(o) for o in ip_str.split(".")]
            # Assembly versions often have 0 for 2nd/4th octet or resemble 1.0.0.0
            is_assembly_ver = (octets[0] in (1, 2, 3, 4, 10) and octets[1] == 0 and octets[3] == 0)
            if not is_assembly_ver and not ip_str.startswith("0.") and not ip_str.startswith("127."):
                return "network_ip", 0.90, FindingStatus.CONFIRMED, True

        # 3. Registry
        if _REG_REGEX.search(trimmed):
            return "registry_key", 0.92, FindingStatus.CONFIRMED, True

        # 4. Suspicious API
        if _API_REGEX.search(trimmed):
            return "suspicious_api", 0.88, FindingStatus.FLAGGED, True

        # 5. File Path
        if _FILEPATH_REGEX.search(trimmed):
            return "filepath", 0.82, FindingStatus.CONFIRMED, True

        # 6. GUID
        if _GUID_REGEX.search(trimmed):
            return "guid", 0.85, FindingStatus.CONFIRMED, True

        # 7. Command Line / Process Spawning
        if _CMD_REGEX.search(trimmed):
            return "command_line", 0.90, FindingStatus.FLAGGED, True

        # 7. Error / Diagnostic
        if _ERROR_REGEX.search(trimmed):
            return "diagnostic_error", 0.78, FindingStatus.CONFIRMED, True

        # 8. GUID
        if _GUID_REGEX.search(trimmed):
            return "guid", 0.85, FindingStatus.CONFIRMED, False

        # 9. Base64
        if len(trimmed) >= 32 and _BASE64_REGEX.search(trimmed):
            return "base64_payload", 0.75, FindingStatus.FLAGGED, True

        # Generic quality string
        return "ascii_string", 0.50, FindingStatus.UNVERIFIED, False
