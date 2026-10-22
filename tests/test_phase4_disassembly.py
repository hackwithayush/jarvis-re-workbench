"""
JARVIS RE — Phase 4 Disassembly & Decompilation Test Suite
Automated regression tests covering:
1. Disassembly instruction extraction and xrefs.
2. Control-Flow Graph (CFG) basic block recovery.
3. Native C-like pseudocode generation.
4. Function enrichment pipeline.
"""

import os
import pytest

from app.core.disassembler import DisassemblyEngine
from app.core.schema import FunctionDetails


@pytest.fixture
def target_sample():
    notepad = r"C:\Windows\notepad.exe"
    if os.path.isfile(notepad):
        return notepad
    pytest.skip("System binary C:\\Windows\\notepad.exe not available for live disassembly test.")


def test_01_disassembly_engine_init():
    """Verify disassembler engine locates installed reverse-engineering tools."""
    engine = DisassemblyEngine()
    assert engine.r2_path is not None
    assert os.path.isfile(engine.r2_path)


def test_02_disassemble_function(target_sample):
    """Verify instruction opcode recovery for binary entry point."""
    engine = DisassemblyEngine()
    disasm = engine.disassemble_function(target_sample, "entry0")

    assert disasm is not None
    assert "ops" in disasm
    assert len(disasm["ops"]) > 0
    first_op = disasm["ops"][0]
    assert "opcode" in first_op
    assert "addr" in first_op


def test_03_extract_cfg_blocks(target_sample):
    """Verify Control-Flow Graph basic blocks and branch jump targets."""
    engine = DisassemblyEngine()
    blocks = engine.extract_cfg(target_sample, "entry0")

    assert len(blocks) > 0
    assert blocks[0].address.startswith("0x")
    assert blocks[0].size > 0
    assert len(blocks[0].instructions) > 0


def test_04_decompile_native_c(target_sample):
    """Verify high-level C pseudocode decompilation."""
    engine = DisassemblyEngine()
    c_code = engine.decompile_native_c(target_sample, "entry0")

    assert c_code is not None
    assert len(c_code) > 20
    assert "entry0" in c_code or "void" in c_code or "rsp" in c_code


def test_05_enrich_functions(target_sample):
    """Verify multi-function batch enrichment with disassembly, CFG, and pseudo-C."""
    engine = DisassemblyEngine()
    funcs = [FunctionDetails(name="entry0", address="0x140001000", size=400)]
    enriched = engine.enrich_functions(target_sample, funcs, limit=1)

    assert len(enriched) == 1
    f = enriched[0]
    assert len(f.instructions) > 0
    assert len(f.cfg_blocks) > 0
    assert f.decompiled_c is not None
