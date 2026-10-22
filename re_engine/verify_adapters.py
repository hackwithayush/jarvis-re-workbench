"""
Jarvis RE — Individual Adapter Verification Script
Systematically verifies every adapter individually to establish exact live capabilities,
availability, version detection, error handling, and output fidelity.
"""

import os
import sys
import tempfile
import struct
import traceback
from datetime import datetime

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from REVERSE_ENGINEERING.adapters import (
    NativePythonAdapter,
    DIEAdapter,
    GhidraAdapter,
    Radare2Adapter,
    FridaAdapter,
    AngrAdapter,
    ImHexAdapter,
    DnSpyAdapter,
    X64DbgAdapter,
)

def create_synthetic_pe(file_path: str) -> None:
    """Generate a minimal valid 32-bit PE binary."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 64)
    pe_sig = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 1700000000, 0, 0, 224, 0x0102)
    opt_header = bytearray(224)
    struct.pack_into("<H", opt_header, 0, 0x010B)
    struct.pack_into("<I", opt_header, 16, 0x1000)
    sec_header = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    headers = dos_header + pe_sig + coff_header + opt_header + sec_header
    padding = b"\x00" * max(0, 512 - len(headers))
    payload = b"\x90\x90\xCC" + b"https://api.internal.net/check\x00" + b"VirtualAlloc\x00"
    payload += b"\x90" * max(0, 512 - len(payload))
    with open(file_path, "wb") as f:
        f.write(headers + padding + payload)

def verify_all_adapters():
    temp_dir = tempfile.mkdtemp(prefix="re_verify_")
    # Prefer system binary for full real-world validation
    notepad_path = r"C:\Windows\notepad.exe"
    if os.path.isfile(notepad_path):
        test_sample = notepad_path
    else:
        test_sample = os.path.join(temp_dir, "verify_test.exe")
        create_synthetic_pe(test_sample)
    
    adapters = [
        ("Native Python Static Engine", NativePythonAdapter()),
        ("Detect It Easy (DIE)", DIEAdapter()),
        ("Ghidra Headless", GhidraAdapter()),
        ("Radare2 / Rabin2", Radare2Adapter()),
        ("Frida Dynamic Instrumentation", FridaAdapter()),
        ("angr Symbolic Execution", AngrAdapter()),
        ("ImHex CLI Pattern Engine", ImHexAdapter()),
        ("dnSpyEx / ILSpy CLI", DnSpyAdapter()),
        ("x64dbg Windows Debugger", X64DbgAdapter()),
    ]
    
    results = []
    
    print("=" * 80)
    print("JARVIS RE WORKBENCH — ADAPTER-BY-ADAPTER VERIFICATION REPORT")
    print("Timestamp:", datetime.now().isoformat())
    print("Target test sample:", test_sample)
    print("=" * 80)
    
    for name, adapter in adapters:
        print(f"\n[*] Testing Adapter: {name} (Tool ID: '{adapter.TOOL_NAME}')")
        
        # 1. Availability check
        try:
            available = adapter.is_available()
        except Exception as e:
            available = False
            print(f"    [!] Error during is_available(): {e}")
            
        print(f"    Available on host : {'YES (Ready)' if available else 'NO (Tool not found)'}")
        
        # 2. Version check
        version = None
        if available:
            try:
                version = adapter.get_version()
                print(f"    Version detected  : {version}")
            except Exception as e:
                print(f"    Version error     : {e}")
        else:
            print(f"    Version detected  : None (Unavailable)")
            
        # 3. Path / Execution Info
        tool_path = getattr(adapter, "tool_path", None)
        print(f"    Resolved Path     : {tool_path or 'N/A'}")
        print(f"    Supported Types   : {adapter.get_supported_types()}")
        
        # 4. Analysis Execution / Error Handling Test
        findings_count = 0
        execution_status = "N/A"
        error_msg = None
        
        if available:
            try:
                findings = adapter.analyze(test_sample, temp_dir)
                findings_count = len(findings)
                execution_status = f"SUCCESS ({findings_count} findings produced)"
                print(f"    Execution Test    : {execution_status}")
                if findings:
                    sample_finding = findings[0]
                    print(f"    Sample Finding    : [{sample_finding.get('finding_type')}] {sample_finding.get('name')} (Conf: {sample_finding.get('confidence')})")
            except Exception as e:
                execution_status = f"FAILED: {e}"
                error_msg = str(e)
                print(f"    Execution Test    : FAILED -> {e}")
        else:
            # Test that calling analyze on an unavailable adapter fails gracefully
            try:
                adapter.analyze(test_sample, temp_dir)
                execution_status = "UNEXPECTED SUCCESS (Should have failed when unavailable)"
            except Exception as e:
                execution_status = f"CLEAN GRACEFUL REJECTION ({type(e).__name__}: {str(e)[:60]}...)"
                print(f"    Graceful Failure  : PASS (Raises: {type(e).__name__})")
                
        results.append({
            "name": name,
            "tool_id": adapter.TOOL_NAME,
            "available": available,
            "version": version,
            "path": tool_path,
            "findings_count": findings_count,
            "status": execution_status,
        })
        
    print("\n" + "=" * 80)
    print("SUMMARY MATRIX")
    print("=" * 80)
    print(f"{'Engine Name':<32} | {'Available':<10} | {'Findings':<9} | {'Runtime Status'}")
    print("-" * 80)
    for r in results:
        avail_str = "YES" if r['available'] else "NO"
        print(f"{r['name']:<32} | {avail_str:<10} | {r['findings_count']:<9} | {r['status'][:25]}")
    print("=" * 80)

if __name__ == "__main__":
    verify_all_adapters()
