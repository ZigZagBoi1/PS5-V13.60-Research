# REA Findings — PS5 Firmware 13.60 Kernel (Session Archive, committed 2026-10-18)

Files in this folder are copied verbatim from the REA analysis workspace
(`Desktop\PS5Emul\Kimi Research\ps5-13.60-kernel-dump`, 2026-10-14/15 session).
Original filenames are preserved for traceability; provenance page for the
particular capture is in `DUMP_CAPTURE_README.md` (renamed from the
workspace's `README.md`).

**Honest status up front:** no decompiled C output exists in this archive.
The decompile pass (PyGhidra bridge, drafted but not yet implemented) has not
been run. What is committed here is the REA session's analysis, disassembly,
audit, and tooling corpus — plus the Ghidra 12.1.4 auto-analysis function
census exported on 2026-10-18 (renamed to `ghidra_function_census.txt`).

## Capture basics

- Total size 103,546,880 bytes; kernel text 13,369,344 bytes at VA
  `0xffffffff9e3f0000`; kernel data 90,177,536 bytes at VA `0xffffffff9f0b0000`
- 688 zeroed missing pages in the data span (partial live capture; text range complete)
- SHA-256 of `kernel-13.60-live.bin`:
  `c3f745e25dc25ee7afef89eb418b295b6334bbefe8aa17e6886483c35d78cddd`
- Layout / VA / hash metadata (1 KB) is committed as `kernel-13.60-live.bin.json`
- Build path string `W:/Build/J03950001/sys/freebsd/sys/` confirms a
  Sony FreeBSD-derived kernel

## Census snapshot

- 25,890 functions identified in kernel text via prologue scanning (see `ANALYSIS.md`)
- Ghidra 12.1.4 headless auto-analysis census exported to
  `ghidra_function_census.txt` (1.55 MB; JSON list of `{name, entry}` pairs)
- FreeBSD base confirmed via jail / sysctl / uma_zone / VFS subsystem strings
- Orbis extensions visible: `orbis_cpumode.c`, `orbis_hw_status_on_crash`,
  custom EVF/AIO subsystems

## Key findings snapshot

### IPv6 hop-by-hop processing (Bug #40 sister)

| Item | Value |
| --- | --- |
| Function VA | `0xffffffff9ecbaac0` |
| Size | ~928 bytes |
| Key string xref | `%s: off < sizeof(struct ip6_hdr)` at `0xffffffff9f73b227` |
| Callers | `0xffffffff9e841a0e`, `0xffffffff9ef31732` |
| Related strings | `ip6_get_prevhdr`, `ip6_clearpktopts`, `ip6_output`, `ip6_nexthdr`, `ip6opt` |

### AIO subsystem (syscalls 661–670 + 688)

- AIO calling-thread side appears clean: 29 wait / 23 cancel / 32 delete
  call patterns audited
- Primary remaining dig direction: **async completion path (backend helpers)** —
  not covered by the audit or any decompile pass yet
- `get_aio_debug_request_info` is NOT present in the Relapse exploit source —
  likely a kernel-internal helper; locate during the decompile pass
- `aio_*_63X` filenames in this archive carry a −30 label offset mislabel
  inherited from the source workspace; per-file contents map individually
  (treat filename numbers as approximate)

### Dynlib cluster / sys 599

- CFI "log-and-continue" path found at `0x9e73cc05`

### CVE candidates to verify (reachability unconfirmed)

- CVE-2026-58098 (SysV), CVE-2026-49418, CVE-2026-58087

## Session work log (2026-10-18 wrap-up)

- Established 13.60 AIO-cluster syscall identity ground truth
  (cross-validated: `upstream/Relapse-Exploit` syscalls.js + sysent nargs +
  orbis audit results)
- Exported the Ghidra 12.1.4 function census (this archive's
  `ghidra_function_census.txt`)
- Drafted the PyGhidra decompile bridge for `tools/ps5_ghidra_tool.py` —
  implementation pending (plan task 4.1); decompile stage not yet runnable
- Recorded the static review of prepared retests 53a–53d in the sibling
  repo `PS5-14.10-Research` (commit `f7f433a`, already pushed); console-side
  probe execution remains user-side and has not run yet
- No console hardware was touched by this session

## Planned decompile targets (draft list, not yet run)

Live-space VAs (live image base `0xffffffff9e3f0000`):

- AIO `real=` VAs: 661 `0x9e79f8f0`, 662 `0x9e79f900`, 663 `0x9e7a01f0`,
  664 `0x9e7a0fb0`, 665 `0x9e7a1670`, 666 `0x9e7a1680`, 668 `0x9e79f8e0`,
  669 `0x9e7a2060`, 670 `0x9e7a28d0`; wrappers +0x20 for 662/663/664/666
- Secondaries: 622 `0x9ebccd40`, 624 `0x9eead4f0`, 596 `0x9e73c750`,
  593 `0x9e73b7b0`
- Dynlib: 649 `0x9e73cfa0`, 599 `0x9e73caa0`, 592 `0x9e73b510`,
  608 `0x9e73bdc0`
- Mystery starts: `0x9e829070`, `0x9eaae5c0`, `0x9ed0c740`
- Resolve + decompile 619 (`SYS_TEST_DEBUG_RWMEM`)

## File index

| Group | Files | What they are |
| --- | --- | --- |
| Analysis write-ups | `ANALYSIS.md`, `REA_DYNLIB_CLUSTER_FINDINGS.md`, `REA_COVERAGE_AND_14.10_TEST_MATRIX.md`, `BROAD_KERNEL_SECURITY_REVIEW_2026-10-14.md`, `DUMP_CAPTURE_README.md` | Session findings: recovery method, dynlib/AIO cluster, coverage & 14.10 test matrix, broad security review, capture provenance |
| Review evidence | `BROAD_REVIEW_STATIC_EVIDENCE_2026-10-14.json` | Machine-readable evidence backing the broad review |
| Capture metadata | `kernel-13.60-live.bin.json` | Capture layout, VAs, hashes, missing-page info (1 KB) |
| Symbol + census data | `symbol_map.json`, `ghidra_function_census.txt` | Kernel symbol → address map; Ghidra function census export |
| Syscall tables | `syscall_table_1360.txt`, `disassembly_targets.txt` | 13.60 syscall table; disassembly target address list used by the REA tooling |
| Syscall-cluster analyses | `syscall_536_full.txt`, `rea_sys586_599_full.txt`, `rea_get_obj_member.txt`, `orbis_637.txt` | Full disassembly/analysis exports for sys 536, the 586/599 wrappers, obj/member helpers, and sys 637 |
| Ioctl analyses | `dmem_ioctl.txt`, `gc_ioctl_core.txt` | dmem and gc ioctl handler analyses |
| ICMPv6 / MLD cluster | `icmp6_full.txt`, `icmp6_disasm.txt`, `icmp6_cluster2.txt`, `icmp6_notify_candidates.txt`, `icmp6_notify_inline.txt`, `mld_input.txt` | IPv6 hop-by-hop / MLD cluster analysis outputs |
| AIO analyses | `aio639_table.txt`, `aio_create_638.txt`, `aio_init_640.txt`, `aio_multi_cancel_636.txt`, `aio_multi_delete_632.txt`, `aio_multi_wait_633.txt`, `aio_submit_631.txt`, `aio_submit_cmd_639.txt`, `aio_submit_core.txt` | Per-syscall AIO analyses (aio639_table is the current best table of 669/688 family) |
| Audit | `orbis_custom_audit.py`, `orbis_custom_audit_results.txt` | REA custom audit tool and its full results |
| REA tooling | `build_rea_analysis_elf.py`, `build_rea_attack_surface_carrier.py`, `build_rea_pe_carrier.py`, `build_rea_prologue_roots_carrier.py`, `build_rea_syscall_entry_carrier.py`, `disassemble_targets.py`, `disasm_536_deep.py`, `rea_obj_member.py`, `rea_sys586_599.py`, `rea_trampoline_map.py` | Carrier builders and analysis scripts (method provenance; reproducibility) |

## Not included in this commit

The raw decrypted kernel capture itself remains outside version control
(kept in the local REA workspace; see `DUMP_CAPTURE_README.md`):

- `kernel-13.60-live.bin` (103,546,880 bytes)
- `kernel-13.60-live.bin.gz` (compressed copy of the same capture)

See `../RELATED_V14_10_RESEARCH.md` for downstream 14.10 work and
`../dumps_13.60/` for the static handler-chunk set.
