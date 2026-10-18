# PS5 Firmware 13.60 - Kernel Dumps

Raw kernel data dumps extracted from a jailbroken PS5 on firmware **13.60** using **Relapse + Byepervisor**.

> **Goal:** Map the Sony syscall table and handler code, then diff against **14.10** to find exploitable changes.

## Extraction Method

The native ELF is loaded through `elfldr` on TCP port **9021** after Relapse + Byepervisor. It uses `kernel_copyout()` to read kernel memory and sends dump files over TCP to a receiver on the local network.

## Kernel Layout

| Property | Value |
|----------|-------|
| Firmware | 13.60 |
| Kernel base | `0xffffffff8a9c0000` (this capture; session-specific under KASLR) |
| Sysent RVA | `+0xe6e5c0` |
| Sysent entries | 679, with a 48-byte stride |
| Active handlers | 311 (368 entries are `nosys` stubs) |
| Sony syscalls (532-676) | 145 entries; 115 have non-`nosys` handlers |

## Files

| File | Size | Contents |
|------|------|----------|
| `kernel_text.bin` | 15,132,096 B | Requested range from base `+0x0`; it crosses from `.text` into `.data` |
| `kernel_data.bin` | 4,194,304 B | 4 MiB sample from base `+0x1000000`; not a complete `.data` section |
| `sysent_area.bin` | 64 KB | Raw sysent table region from kernel memory |
| `sysent_raw.bin` | 32,592 B | Complete raw sysent table: 679 entries, 48-byte stride |
| `sysent_index.json` | 84,874 B | Parsed sysent entries with syscall number, arg count, `sy_call`, and handler RVA |
| `kernel_base.json` | 55 B | Firmware version and kernel base recorded during extraction |
| `handler_NNN.bin` | 4,096 B each | First 4 KiB at each of 145 Sony handler addresses (syscalls 532-676); not necessarily a complete function |
| `ucred.bin` | 256 B | Captured credential-structure bytes |

## JSON Format

`sysent_index.json` contains a top-level `kernel_base` hexadecimal string, a numeric `sysent_rva` (`15132096`, or `0xe6e5c0`), and an `entries` array. Example entry for syscall **532**:

```json
{
  "num": 532,
  "narg": 5,
  "sy_call": "0xffffffff8ac25ce8",
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

The sysent RVA `+0xe6e5c0` is present in this 13.60 capture. The companion repository has no verified 14.10 kernel/sysent image, so a matching 14.10 RVA is **not established**. A 13.60 table can guide hypotheses, but only an authenticated 14.10 artifact can support a firmware-to-firmware handler diff.

| Change to look for | Research significance |
|--------------------|-----------------------|
| New bounds checks | May identify patched vulnerabilities in the older handler |
| Removed code paths | May reveal disabled or replaced functionality |
| Changed argument validation | Altered input handling (counts, pointer checks, lengths, signedness) |

Prioritize semantic changes after accounting for relocated addresses and compiler differences.

## Capture ranges and integrity limits

The manifest records the requested ranges:

| File | Start relative to this capture's base | Size | Coverage |
|---|---:|---:|---|
| `kernel_text.bin` | `0x0` | `0xe6e5c0` | Requested prefix; the local layout reference places the `.text`/`.data` boundary at `0xcc0000`, so this range crosses into `.data`. |
| `kernel_data.bin` | `0x1000000` | `0x400000` | 4 MiB sample beginning partway into `.data`; not the full section. |
| `sysent_area.bin` | `0xe6d5c0` | `0x10000` | 64 KiB window; its bytes at `+0x1000` match `sysent_raw.bin` exactly. |

`kernel_dump_manifest.json` and `sysent_index.json` agree on base `0xffffffff8a9c0000`. The prior `kernel_base.json` value (`0xffffffff94480000`) did not match those files and has been corrected to the manifest/index base; no other artifact in this directory is tied to that older value. The repository has no `.failmap` sidecars for `kernel_text.bin` or `kernel_data.bin`, so exact file size is verified but zero-filled/failed-read status for those two ranges cannot be independently established from the committed files. `dump_progress.json` records only `sysent_area.bin` as 4/4 chunks with zero zero-filled chunks.

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
| [Capture reconciliation audit](../audits/2026-10-18-dump-reconciliation.md) | Verified base, hashes, range limits, failmap gap, and receiver requirements |
