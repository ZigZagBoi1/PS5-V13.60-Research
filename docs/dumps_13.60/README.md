# PS5 Firmware 13.60 - Kernel Dumps

Raw kernel data dumps extracted from a jailbroken PS5 on firmware **13.60** using **Relapse + Byepervisor**.

> **Goal:** Map the Sony syscall table and handler code, then diff against **14.10** to find exploitable changes.

## Extraction Method

The native ELF is loaded through `elfldr` on TCP port **9021** after Relapse + Byepervisor. It uses `kernel_copyout()` to read kernel memory and sends dump files over TCP to a receiver on the local network.

## Kernel Layout

| Property | Value |
|----------|-------|
| Firmware | 13.60 |
| Kernel base | `0xffffffff94480000` |
| Sysent RVA | `+0xe6e5c0` |
| Sysent entries | 679, with a 48-byte stride |
| Active handlers | 311 (368 entries are `nosys` stubs) |
| Sony syscalls (532-676) | 145 entries; 115 have non-`nosys` handlers |

## Files

| File | Size | Contents |
|------|------|----------|
| `kernel_text.bin` | 15 MB | Full kernel .text section |
| `kernel_data.bin` | 4 MB | Kernel .data section |
| `sysent_area.bin` | 64 KB | Raw sysent table region from kernel memory |
| `sysent_raw.bin` | 32,592 B | Complete raw sysent table: 679 entries, 48-byte stride |
| `sysent_index.json` | 79 KB | Parsed sysent entries with syscall number, arg count, `sy_call`, and handler RVA |
| `kernel_base.json` | 55 B | Firmware version and kernel base recorded during extraction |
| `handler_NNN.bin` | 4 KB each | 145 Sony syscall handler binaries (syscalls 532-676) |
| `ucred.bin` | 176 B | Process credential structure |

## JSON Format

`sysent_index.json` contains a top-level `kernel_base` hexadecimal string, a numeric `sysent_rva` (`15132096`, or `0xe6e5c0`), and an `entries` array. Example entry for syscall **532**:

```json
{
  "num": 532,
  "narg": 5,
  "sy_call": "0xffffffff946e5ce8",
  "sy_call_off": "0x265ce8"
}
```

| Field | Meaning |
|-------|---------|
| `num` | Syscall number and zero-based sysent entry index |
| `narg` | Number of syscall arguments |
| `sy_call` | Absolute kernel virtual address of the handler |
| `sy_call_off` | Handler RVA relative to `kernel_base` |

Keep addresses as strings or use integer types that preserve all 64 bits when parsing.

## Handler Disassembly

```bash
objdump -D -b binary -m i386:x86-64 handler_532.bin
```

This disassembles the raw bytes as x86-64 code. Use the matching `sy_call` and `sy_call_off` values to relate offsets to kernel addresses. Follow any entry jump stubs in the full `.text` dump when the target falls outside the 4 KB window.

## Cross-Firmware Diffing

The sysent RVA **`+0xe6e5c0` matches across 13.60 and 14.10**, providing a common starting point. Match entries by syscall number, normalize addresses relative to each firmware's kernel base, then compare handler code.

| Change to look for | Research significance |
|--------------------|-----------------------|
| New bounds checks | May identify patched vulnerabilities in the older handler |
| Removed code paths | May reveal disabled or replaced functionality |
| Changed argument validation | Altered input handling (counts, pointer checks, lengths, signedness) |

Prioritize semantic changes after accounting for relocated addresses and compiler differences.

## Known Offsets (13.60)

| Symbol | RVA | Notes |
|--------|-----|-------|
| Sysent table | `+0xe6e5c0` | 679 entries, 48-byte stride |
| `nosys` handler | `+0x265760` | Shared by 368 entries |

## Links

| Document | Contents |
|----------|----------|
| [Main README](../../README.md) | Project overview and research status |
| [Related 14.10 research](../RELATED_V14_10_RESEARCH.md) | Companion repository and cross-firmware pointers |
