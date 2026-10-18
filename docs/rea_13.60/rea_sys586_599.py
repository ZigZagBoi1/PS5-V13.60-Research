#!/usr/bin/env python3
"""
REA pass 2: full disassembly of the syscall 591-599 handler cluster
(0xffffffff9e73a470 - 0xffffffff9e73cc00) plus syscall 588, with
string-reference resolution to identify each handler's role and spot
missing validation (copyin without size checks, unchecked user pointers).
"""

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

TEXT_BASE = 0xFFFFFFFF9E3F0000
TEXT_SIZE = 13369344
DATA_BASE = 0xFFFFFFFF9F0B0000
DATA_SIZE = 90177536

with open("kernel-13.60-live.bin", "rb") as f:
    raw = f.read()
text = raw[:TEXT_SIZE]
data = raw[TEXT_SIZE:TEXT_SIZE + DATA_SIZE]

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# index strings in data
STRINGS = {}
cur = b""
start = 0
for i in range(len(data)):
    if 32 <= data[i] < 127:
        if not cur:
            start = i
        cur += bytes([data[i]])
    else:
        if len(cur) >= 5:
            STRINGS[DATA_BASE + start] = cur.decode("ascii", errors="replace")
        cur = b""

def disasm_func(va, max_insns=400):
    o = va - TEXT_BASE
    if not (0 <= o < TEXT_SIZE):
        return []
    out = []
    for insn in md.disasm(text[o:o + 8192], va):
        out.append(insn)
        # stop at ret followed by padding (likely function end)
        if insn.mnemonic == "ret" and len(out) > 3:
            nxt = text[o + insn.address - va + 1] if o + insn.address - va + 1 < len(text) else 0xCC
            if nxt in (0xCC, 0x90, 0x55):
                break
        if len(out) >= max_insns:
            break
    return out

HANDLERS = {
    594: ("sys_594", 0xffffffff9e73a470),
    595: ("sys_595", 0xffffffff9e73ad30),
    591: ("sys_591", 0xffffffff9e73ae90),
    592: ("sys_592", 0xffffffff9e73b510),
    593: ("sys_593", 0xffffffff9e73b7b0),
    596: ("sys_596", 0xffffffff9e73c750),
    598: ("sys_598", 0xffffffff9e73c990),
    599: ("sys_599", 0xffffffff9e73caa0),
    588: ("sys_588", 0xffffffff9eeac5f0),
}

with open("rea_sys586_599_full.txt", "w") as f:
    for num, (name, va) in sorted(HANDLERS.items()):
        insns = disasm_func(va)
        f.write(f"\n{'='*78}\nFUNCTION {name} (syscall {num}) @ 0x{va:x}  [{len(insns)} insns]\n{'='*78}\n")
        for insn in insns:
            ann = ""
            if "rip" in insn.op_str:
                for op in insn.operands:
                    if op.type == 3:
                        t = insn.address + insn.size + op.mem.disp
                        if t in STRINGS:
                            ann = f'  ; "{STRINGS[t][:70]}"'
                        break
            f.write(f"  0x{insn.address:x}: {insn.mnemonic:8s} {insn.op_str}{ann}\n")

print("[+] wrote rea_sys586_599_full.txt")

# quick stats: count copyin/copyout-like calls and string refs per handler
for num, (name, va) in sorted(HANDLERS.items()):
    insns = disasm_func(va)
    calls = [i for i in insns if i.mnemonic == "call"]
    strs = set()
    for insn in insns:
        if "rip" in insn.op_str:
            for op in insn.operands:
                if op.type == 3:
                    t = insn.address + insn.size + op.mem.disp
                    if t in STRINGS:
                        strs.add(STRINGS[t][:60])
    print(f"sys{num} @{hex(va)}: {len(insns)} insns, {len(calls)} calls")
    for s in sorted(strs)[:8]:
        print(f"    str: {s!r}")
