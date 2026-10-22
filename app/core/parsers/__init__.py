"""
JARVIS RE — Dedicated Parsers Module v1.0
Pure-Python, zero-dependency structural parsers for executable formats and payloads.
"""

from .pe_parser import PEParser
from .elf_parser import ELFParser
from .macho_parser import MachOParser
from .archive_parser import ArchiveInspector
from .string_extractor import StringExtractor

__all__ = [
    "PEParser",
    "ELFParser",
    "MachOParser",
    "ArchiveInspector",
    "StringExtractor",
]
