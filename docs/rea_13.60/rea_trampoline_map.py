#!/usr/bin/env python3
"""
REA pass: resolve syscall trampoline stubs (0xffffffff9e655xxx page) to real
handlers, then disassemble the real handlers for Sony custom syscalls 586-599.
Also verifies the syscall table for gaps (589/590/597 absent on 13.60).
"""

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

TEXT_BASE = 0xFFFFFFFF9E3F0000
TEXT_SIZE = 13369344

with open("kernel-13.60-live.bin", "rb") as f:
    raw = f.read()
text = raw[:TEXT_SIZE]

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def off(va):
    o = va - TEXT_BASE
    return o if 0 <= o < TEXT_SIZE else None

def disasm_range(va, n=48, label=""):
    o = off(va)
    if o is None:
        print(f"  !! {label} 0x{va:x} outside captured text")
        return []
    out = []
    for insn in md.disasm(text[o:o + 200], va):
        out.append(insn)
        if len(out) >= n:
            break
    return out

# Trampoline addresses from syscall_table_1360.txt for the 586-599 window
TRAMPS = {
    586: 0xffffffff9e655790,
    587: 0xffffffff9e655e00,
    588: 0xffffffff9e655e08,
    591: 0xffffffff9e655570,
    592: 0xffffffff9e655578,
    593: 0xffffffff9e655588,
    594: 0xffffffff9e655560,
    595: 0xffffffff9e655568,
    596: 0xffffffff9e6555b0,
    598: 0xffffffff9e6555d0,
    599: 0xffffffff9e6555d8,
    585: 0xffffffff9e655df8,
    548: 0xffffffff9e655d60,
}

print("=" * 78)
print("SYSCALL TRAMPOLINE RESOLUTION (13.60 dump)")
print("=" * 78)

real_handlers = {}
for num, va in sorted(TRAMPS.items()):
    insns = disasm_range(va, n=8, label=f"sys{num}")
    if not insns:
        continue
    print(f"\nsyscall {num} stub @ 0x{va:x}:")
    real = None
    for insn in insns:
        print(f"    0x{insn.address:x}: {insn.mnemonic:8s} {insn.op_str}")
        if insn.mnemonic == "jmp" and insn.op_str.startswith("0x"):
            real = int(insn.op_str, 16)
            break
        if insn.mnemonic == "mov" and "rip" in insn.op_str:
            # rip-relative load then jmp — resolve
            for op in insn.operands:
                if op.type == 3:
                    t = insn.address + insn.size + op.mem.disp
                    print(f"          ; rip -> 0x{t:x}")
                    break
    if real:
        real_handlers[num] = real
        print(f"  => real handler: 0x{real:x}")

print("\n" + "=" * 78)
print("REAL HANDLER PROLOGUES")
print("=" * 78)
for num, va in sorted(real_handlers.items()):
    insns = disasm_range(va, n=20, label=f"handler{num}")
    print(f"\nsyscall {num} handler @ 0x{va:x}:")
    for insn in insns[:20]:
        print(f"    0x{insn.address:x}: {insn.mnemonic:8s} {insn.op_str}")
