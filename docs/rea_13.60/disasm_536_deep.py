#!/usr/bin/env python3
"""Deep disassembly of syscall 536 (dl_get_sdk_version / dldbg) inner function."""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP

TEXT_BASE = 0xFFFFFFFF9E3F0000
TEXT_SIZE = 13369344
DATA_BASE = 0xFFFFFFFF9F0B0000
DATA_SIZE = 90177536

with open("kernel-13.60-live.bin", "rb") as f:
    raw = f.read()
text = raw[:TEXT_SIZE]
data = raw[TEXT_SIZE:TEXT_SIZE + DATA_SIZE]

STRINGS = {}
cur, start = b"", 0
for i in range(len(data)):
    if 32 <= data[i] < 127:
        if not cur: start = i
        cur += bytes([data[i]])
    else:
        if len(cur) >= 4:
            STRINGS[DATA_BASE + start] = cur.decode("ascii", errors="replace")
        cur = b""

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def va_to_off(va): return va - TEXT_BASE if TEXT_BASE <= va < TEXT_BASE + TEXT_SIZE else None

def disasm_range(start_va, end_va):
    off = va_to_off(start_va)
    sz = end_va - start_va
    code = text[off:off+sz]
    lines = []
    for insn in md.disasm(code, start_va):
        ann = ""
        for op in insn.operands:
            if op.type == 3 and hasattr(op, "mem") and op.mem.base == 41:
                target = insn.address + insn.size + op.mem.disp
                if target in STRINGS:
                    ann = f'  ; "{STRINGS[target][:80]}"'
                else:
                    ann = f"  ; -> 0x{target:x}"
        if insn.group(CS_GRP_CALL) and insn.op_str.startswith("0x"):
            try:
                t = int(insn.op_str, 16)
                ann += f"  ; CALL"
            except: pass
        lines.append(f"  0x{insn.address:x}:  {insn.mnemonic:8s} {insn.op_str}{ann}")
    return lines

# The real syscall 536 entry is at 0xffffffff9e8e6a70
# It calls the inner worker at 0xffffffff9e8e6b70 which does the heavy lifting
# Let's disassemble the entire range 0x9e8e6a70 to 0x9e8e7b00 (the full cluster)
print("=== SYSCALL 536 (dl_get_sdk_version / dldbg) FULL DISASSEMBLY ===")
print(f"Range: 0xffffffff9e8e6a70 — 0xffffffff9e8e7b00")
print()

lines = disasm_range(0xffffffff9e8e6a70, 0xffffffff9e8e7b00)
for l in lines:
    print(l)

# Also look at the gate functions
print("\n\n=== PRIVILEGE CHECK GATES ===")
# 0xffffffff9e65d0a8, 0xffffffff9e9f9040, 0xffffffff9e9f9110
for gate_va, name in [(0xffffffff9e65d0a8, "gate1"), (0xffffffff9e9f9040, "gate2"), (0xffffffff9e9f9110, "gate3")]:
    off = va_to_off(gate_va)
    if off is None:
        print(f"\n{name} at 0x{gate_va:x}: outside text")
        continue
    # Follow if trampoline
    if text[off:off+2] == b"\xff\x25":
        disp = struct.unpack_from("<i", text, off + 2)[0]
        ptr_va = gate_va + 6 + disp
        ptr_off = ptr_va - DATA_BASE
        if 0 <= ptr_off < len(data) - 8:
            real = struct.unpack_from("<Q", data, ptr_off)[0]
            print(f"\n{name} at 0x{gate_va:x} -> trampoline -> 0x{real:x}")
            gate_va = real
            off = va_to_off(gate_va)

    print(f"\n{name} at 0x{gate_va:x}:")
    lines = disasm_range(gate_va, gate_va + 256)
    for l in lines[:40]:
        print(l)
