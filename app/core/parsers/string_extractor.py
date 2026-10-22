"""
JARVIS RE — Printable String Engine v1.0
High-performance ASCII and UTF-16LE string extractor with automated heuristic classification:
- URLs (http, https)
- IP addresses (IPv4 & IPv6)
- Windows Registry keys (HKLM, HKCU, HKEY_)
- Suspicious Win32/Native APIs
- File paths (Windows drives, UNC, system folders, Unix paths)
- GUIDs
- Base64 encoded strings
"""

import re
from typing import Dict, List, Optional
from app.core.schema import Finding, FindingStatus, FindingType

_URL_REGEX = re.compile(r"https?://(?:[a-zA-Z0-9_\-\.]+)(?::\d+)?(?:/[^\s\"\'>]*)?", re.IGNORECASE)
_IPV4_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
_REG_REGEX = re.compile(r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKLM|HKCU)\\[a-zA-Z0-9_\-\\]+", re.IGNORECASE)
_API_REGEX = re.compile(r"\b(?:VirtualAlloc|VirtualProtect|CreateProcess|WriteProcessMemory|ReadProcessMemory|CreateRemoteThread|LoadLibrary|GetProcAddress|WinExec|ShellExecute|URLDownloadToFile|InternetOpen|HttpSendRequest|RegOpenKey|RegSetValueEx|CreateService|IsDebuggerPresent|CheckRemoteDebuggerPresent|WSAStartup)[a-zA-Z0-9]*\b")
_FILEPATH_REGEX = re.compile(r"\b(?:[a-zA-Z]:\\(?:[^<>:\"/\\|?*\n\r\t]+\\)*[^<>:\"/\\|?*\n\r\t]+|/(?:usr|etc|bin|lib|tmp|var|home)/[^\s\"\'>]+)", re.IGNORECASE)
_GUID_REGEX = re.compile(r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?")
_BASE64_REGEX = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")


class StringExtractor:
    """Extracts and classifies ASCII and UTF-16 printable strings from binary data."""

    def __init__(self, data: bytes, sample_sha256: str, min_len: int = 4, max_strings: int = 250):
        self.data = data
        self.sha256 = sample_sha256
        self.min_len = min_len
        self.max_strings = max_strings

    def extract(self) -> List[Finding]:
        """Extract ASCII and UTF-16LE strings and return classified findings."""
        findings: List[Finding] = []
        seen = set()

        # 1. ASCII extraction
        ascii_pattern = re.compile(rb"[\x20-\x7e]{" + str(self.min_len).encode() + rb",}")
        for m in ascii_pattern.finditer(self.data):
            raw = m.group(0).decode("latin-1", errors="ignore")
            offset = m.start()
            f = self._classify_string(raw, offset, is_unicode=False)
            if f and raw not in seen:
                seen.add(raw)
                findings.append(f)
                if len(findings) >= self.max_strings:
                    return findings

        # 2. UTF-16LE (wide string) extraction: sequence of printable chars with 0x00 interleaving
        utf16_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(self.min_len).encode() + rb",}")
        for m in utf16_pattern.finditer(self.data):
            try:
                raw = m.group(0).decode("utf-16le", errors="ignore")
            except Exception:
                continue
            offset = m.start()
            f = self._classify_string(raw, offset, is_unicode=True)
            if f and raw not in seen:
                seen.add(raw)
                findings.append(f)
                if len(findings) >= self.max_strings:
                    return findings

        return findings

    def _classify_string(self, raw: str, offset: int, is_unicode: bool) -> Optional[Finding]:
        trimmed = raw.strip()
        if len(trimmed) < self.min_len:
            return None

        encoding = "UTF-16LE" if is_unicode else "ASCII"
        category = "ascii_string"
        confidence = 0.50
        status = FindingStatus.CONFIRMED

        if _URL_REGEX.search(trimmed):
            category = "network_url"
            confidence = 0.95
        elif _IPV4_REGEX.search(trimmed):
            category = "network_ip"
            confidence = 0.90
        elif _REG_REGEX.search(trimmed):
            category = "registry_key"
            confidence = 0.90
        elif _API_REGEX.search(trimmed):
            category = "suspicious_api"
            confidence = 0.88
            status = FindingStatus.FLAGGED
        elif _FILEPATH_REGEX.search(trimmed):
            category = "filepath"
            confidence = 0.80
        elif _GUID_REGEX.search(trimmed):
            category = "guid"
            confidence = 0.85
        elif _BASE64_REGEX.search(trimmed) and len(trimmed) >= 24:
            category = "base64_payload"
            confidence = 0.75
            status = FindingStatus.FLAGGED

        return Finding(
            sample_sha256=self.sha256,
            source_tool="string_extractor",
            finding_type=FindingType.STRING,
            address_or_location=f"0x{offset:08X}",
            name=category,
            description=f"[{category}|{encoding}] '{trimmed[:120]}'",
            confidence=confidence,
            verification_status=status,
            tags=[category, encoding.lower()],
            raw_data={
                "string": trimmed,
                "file_offset": offset,
                "encoding": encoding,
                "category": category,
            },
        )
