"""
Jarvis RE — Analysis Tool Adapters
Unified adapters wrapping all static, dynamic, and automated RE engines.
"""

from .base_adapter import BaseAdapter
from .native_adapter import NativePythonAdapter
from .die_adapter import DIEAdapter
from .ghidra_adapter import GhidraAdapter
from .radare2_adapter import Radare2Adapter
from .frida_adapter import FridaAdapter
from .angr_adapter import AngrAdapter
from .imhex_adapter import ImHexAdapter
from .dnspy_adapter import DnSpyAdapter
from .x64dbg_adapter import X64DbgAdapter
from .jadx_adapter import JadxAdapter
from .capa_adapter import CapaAdapter
from .yara_adapter import YaraAdapter

__all__ = [
    "BaseAdapter",
    "NativePythonAdapter",
    "DIEAdapter",
    "GhidraAdapter",
    "Radare2Adapter",
    "FridaAdapter",
    "AngrAdapter",
    "ImHexAdapter",
    "DnSpyAdapter",
    "X64DbgAdapter",
    "JadxAdapter",
    "CapaAdapter",
    "YaraAdapter",
]
