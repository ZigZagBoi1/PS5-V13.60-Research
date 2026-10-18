#!/usr/bin/env python3
"""
PS5 13.60 Kernel Dump — Targeted Disassembly
Uses Capstone to disassemble vulnerability-relevant functions.
Outputs full disassembly + xref map + symbol table.
"""

import struct
import json
import sys
from collections import defaultdict
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP

TEXT_BASE = 0xFFFFFFFF9E3F0000
TEXT_SIZE = 13369344
DATA_BASE = 0xFFFFFFFF9F0B0000
DATA_SIZE = 90177536

# ── Load binary ──────────────────────────────────────────────────────
print("[*] Loading kernel-13.60-live.bin ...")
with open("kernel-13.60-live.bin", "rb") as f:
    raw = f.read()

text = raw[:TEXT_SIZE]
data = raw[TEXT_SIZE:TEXT_SIZE + DATA_SIZE]

# ── Initialize Capstone ──────────────────────────────────────────────
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# ── Known strings (from prior analysis) ──────────────────────────────
KNOWN_STRINGS = {}
cur = b""
start = 0
for i in range(len(data)):
    if 32 <= data[i] < 127:
        if not cur:
            start = i
        cur += bytes([data[i]])
    else:
        if len(cur) >= 6:
            KNOWN_STRINGS[DATA_BASE + start] = cur.decode("ascii", errors="replace")
        cur = b""

print(f"[+] Indexed {len(KNOWN_STRINGS)} strings in data section")

# ── Function finder ──────────────────────────────────────────────────
def find_func_bounds(offset):
    """Find function start (scan back for prologue) and end (ret)."""
    # Scan backwards for push rbp; mov rbp, rsp
    func_start = offset
    for back in range(offset, max(0, offset - 16384), -1):
        if text[back:back + 4] == b"\x55\x48\x89\xe5":
            if back == 0 or text[back - 1] in (0xC3, 0xCC, 0x90):
                func_start = back
                break

    # Scan forward for ret followed by padding/next func
    func_end = offset + 256
    for fwd in range(offset, min(offset + 32768, len(text))):
        if text[fwd] == 0xC3:
            # Check if next byte is padding or another prologue
            if fwd + 1 < len(text) and text[fwd + 1] in (0xCC, 0x90, 0x55):
                func_end = fwd + 1
                break
            # Also accept ret at end of text
            if fwd + 1 >= len(text):
                func_end = fwd + 1
                break

    return func_start, func_end


def disassemble_function(func_offset, func_name="unknown"):
    """Disassemble a function and return structured output."""
    start, end = find_func_bounds(func_offset)
    func_bytes = text[start:end]
    base_va = TEXT_BASE + start
    size = end - start

    lines = []
    calls = []
    string_refs = []
    branch_targets = set()

    lines.append(f"\n{'='*80}")
    lines.append(f"FUNCTION: {func_name}")
    lines.append(f"  VA: 0x{base_va:x} — 0x{base_va + size:x}  ({size} bytes)")
    lines.append(f"{'='*80}")

    for insn in md.disasm(func_bytes, base_va):
        annotation = ""

        # Resolve RIP-relative addresses
        if insn.op_str and "rip" in insn.op_str:
            # Try to extract the target address
            for op in insn.operands:
                if op.type == 3 and hasattr(op, "mem"):  # X86_OP_MEM
                    if op.mem.base == 0 or op.mem.base == 41:  # RIP
                        target = insn.address + insn.size + op.mem.disp
                        # Check if it's a known string
                        if target in KNOWN_STRINGS:
                            s = KNOWN_STRINGS[target]
                            annotation = f'  ; "{s[:60]}"'
                            string_refs.append((insn.address, target, s))
                        else:
                            annotation = f"  ; -> 0x{target:x}"

        # Track calls
        if insn.group(CS_GRP_CALL):
            # Extract target
            if insn.op_str.startswith("0x"):
                try:
                    target = int(insn.op_str, 16)
                    calls.append((insn.address, target))
                    # Check if target is a known function
                    if target in TARGET_FUNCTIONS:
                        annotation = f"  ; {TARGET_FUNCTIONS[target]}"
                except ValueError:
                    pass

        # Track jumps for branch targets
        if insn.group(CS_GRP_JUMP) and insn.op_str.startswith("0x"):
            try:
                target = int(insn.op_str, 16)
                branch_targets.add(target)
            except ValueError:
                pass

        # Format with labels for branch targets
        prefix = ""
        if insn.address in branch_targets:
            prefix = f"\n.L{insn.address & 0xFFFF:04x}:\n"

        lines.append(f"{prefix}  0x{insn.address:x}:  {insn.mnemonic:8s} {insn.op_str}{annotation}")

    return {
        "name": func_name,
        "va": base_va,
        "size": size,
        "lines": lines,
        "calls": calls,
        "string_refs": string_refs,
    }


# ── Target functions ─────────────────────────────────────────────────
TARGET_FUNCTIONS = {
    # IPv6
    0xFFFFFFFF9ECBAAC0: "ip6_process_hbhopt",
    0xFFFFFFFF9ECBAC10: "ip6_next_func",
    0xFFFFFFFF9E841A0E: "ip6_caller_1",
    0xFFFFFFFF9EF31732: "ip6_caller_2",
    # AIO
    0xFFFFFFFF9EF70060: "vfs_aio_func",
    # EVF
    0xFFFFFFFF9EC1C800: "evf_trywait_handler",
    # Trampolines -> real
    0xFFFFFFFF9E79DCF0: "nosys_impl",
    0xFFFFFFFF9E9520E0: "common_handler_607",
    0xFFFFFFFF9E947540: "common_handler_524",
    0xFFFFFFFF9EFF90B0: "common_handler_511",
    # Utilities
    0xFFFFFFFF9EBE18A0: "panic_or_log",
    0xFFFFFFFF9F08AA10: "printf_or_kassert",
}

# ── Disassemble all targets ──────────────────────────────────────────
print("[*] Disassembling target functions ...")

all_results = []
output_lines = []
output_lines.append("# PS5 13.60 Kernel — Vulnerability Target Disassembly")
output_lines.append(f"# Generated by disassemble_targets.py")
output_lines.append(f"# Text base: 0x{TEXT_BASE:x}, Data base: 0x{DATA_BASE:x}")
output_lines.append("")

for va, name in sorted(TARGET_FUNCTIONS.items()):
    rva = va - TEXT_BASE
    if 0 <= rva < TEXT_SIZE:
        print(f"  [+] {name} at 0x{va:x}")
        result = disassemble_function(rva, name)
        all_results.append(result)
        output_lines.extend(result["lines"])
    else:
        print(f"  [-] {name} at 0x{va:x} — outside text section")

# ── Cross-reference summary ──────────────────────────────────────────
output_lines.append(f"\n\n{'='*80}")
output_lines.append("CROSS-REFERENCE SUMMARY")
output_lines.append(f"{'='*80}")

for result in all_results:
    if result["calls"] or result["string_refs"]:
        output_lines.append(f"\n--- {result['name']} (0x{result['va']:x}) ---")
        if result["calls"]:
            output_lines.append("  Calls:")
            for caller, target in result["calls"]:
                tname = TARGET_FUNCTIONS.get(target, f"sub_{target:x}")
                output_lines.append(f"    0x{caller:x} -> {tname}")
        if result["string_refs"]:
            output_lines.append("  String references:")
            for addr, target, s in result["string_refs"]:
                output_lines.append(f'    0x{addr:x}: "{s[:80]}"')

# ── Write output ─────────────────────────────────────────────────────
output_text = "\n".join(output_lines)
with open("disassembly_targets.txt", "w") as f:
    f.write(output_text)

print(f"\n[+] Wrote disassembly to disassembly_targets.txt ({len(output_lines)} lines)")

# ── Also generate a symbol map JSON ──────────────────────────────────
symbol_map = {
    "text_base": f"0x{TEXT_BASE:x}",
    "data_base": f"0x{DATA_BASE:x}",
    "functions": {f"0x{va:x}": name for va, name in TARGET_FUNCTIONS.items()},
    "strings": {f"0x{va:x}": s[:200] for va, s in list(KNOWN_STRINGS.items())[:5000]},
    "xrefs": [],
}

for result in all_results:
    for caller, target in result["calls"]:
        symbol_map["xrefs"].append({
            "from": f"0x{caller:x}",
            "to": f"0x{target:x}",
            "type": "call",
            "from_func": result["name"],
        })
    for addr, target, s in result["string_refs"]:
        symbol_map["xrefs"].append({
            "from": f"0x{addr:x}",
            "to": f"0x{target:x}",
            "type": "string_ref",
            "from_func": result["name"],
            "string": s[:200],
        })

with open("symbol_map.json", "w") as f:
    json.dump(symbol_map, f, indent=2)

print(f"[+] Wrote symbol_map.json")
print("[+] Done!")
