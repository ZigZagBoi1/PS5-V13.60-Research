#!/usr/bin/env python3
"""REA: sys_dynlib_get_obj_member (next handler after syscall 599 cluster)."""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

TEXT_BASE = 0xFFFFFFFF9E3F0000
TEXT_SIZE = 13369344
DATA_BASE = 0xFFFFFFFF9F0B0000

with open("kernel-13.60-live.bin", "rb") as f:
    raw = f.read()
text = raw[:TEXT_SIZE]
data = raw[TEXT_SIZE:]

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

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

# scan back from 0x9e73d044 for function prologue
va_end = 0xffffffff9e73d044
o = va_end - TEXT_BASE
fstart = None
for back in range(o, max(0, o - 4096), -1):
    if text[back:back+4] == b"\x55\x48\x89\xe5" and text[back-1] in (0xC3, 0xCC, 0x90):
        fstart = back
        break

va = TEXT_BASE + fstart
print(f"get_obj_member prologue @ 0x{va:x}")

count = 0
with open("rea_get_obj_member.txt", "w") as f:
    for insn in md.disasm(text[fstart:fstart+4096], va):
        ann = ""
        if "rip" in insn.op_str:
            for op in insn.operands:
                if op.type == 3:
                    t = insn.address + insn.size + op.mem.disp
                    if t in STRINGS:
                        ann = f'  ; "{STRINGS[t][:70]}"'
                    break
        f.write(f"  0x{insn.address:x}: {insn.mnemonic:8s} {insn.op_str}{ann}\n")
        count += 1
        if insn.mnemonic == "ret" and count > 5:
            nxt = text[fstart + insn.address - va + 1]
            if nxt in (0xCC, 0x90, 0x55):
                break
        if count > 500:
            break
print(f"[+] {count} insns -> rea_get_obj_member.txt")
