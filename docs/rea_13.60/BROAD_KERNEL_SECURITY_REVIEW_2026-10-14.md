# Bounded PS5 kernel security review — retained 13.60 artifact

Review date: 2026-10-14. Offline static work only. No console contact, live probe, trigger, or exploit was performed.

**Result:** No confirmed new kernel vulnerability was established. This is a broad evidence and coverage review with selected byte checks, not a whole-kernel audit. A prior unconditional CFI “log-and-continue” claim is contradicted by inspection of the failure helper and captured configuration. No 13.60 result establishes applicability to 14.10.

## Exact artifacts and provenance

The input is `kernel-13.60-live.bin`, 103,546,880 bytes, SHA-256 `c3f745e25dc25ee7afef89eb418b295b6334bbefe8aa17e6886483c35d78cddd`. The local capture manifest labels it firmware 13.60 and a flat live RAM reconstruction; firmware provenance is retained metadata, not independent signature verification. This pass recomputed the whole-file and both section hashes successfully.

| Captured region | File offset | Bytes | Virtual base | SHA-256 |
|---|---:|---:|---|---|
| Text | 0 | 13,369,344 | `0xffffffff9e3f0000` | `20da45a0910c990153fbfb7c94e16356867e0bd84f7c9fbf754a45a5dd129673` |
| Data | 13,369,344 | 90,177,536 | `0xffffffff9f0b0000` | `3b3f41fb54d1ab7e4bc3555c3eb176336afc5d42898d7538701f10281aa75e13` |

688 missing 4 KiB data pages (2,818,048 bytes) occupy `[0xffffffffa4400000, 0xffffffffa46b0000)` and are represented by zeroes. Those bytes are absent evidence; no conclusion here depends on treating them as real data. The artifact is neither a complete decrypted firmware kernel nor a bootable executable.

The workspace search found one original kernel binary plus its analysis ELF/PE carriers. **No decrypted 14.10 kernel was found.** The retained ledger refers to an operator-supplied 14.10 recovery PUP outside this workspace and records opaque inner headers; an update container is not a decrypted kernel. PUP decryption status documents do not establish successful 14.10 decryption.

| Derived carrier in `rea_import/` | Bytes | SHA-256 |
|---|---:|---|
| `ps5_1360_live_memory_analysis.elf` | 103,550,976 | `f1c10593d8f1954179a53a749bbc455f53d690b53f7b2b5ef1b6385ee796ea1b` |
| `ps5_1360_live_memory_analysis.exe` | 103,547,392 | `53f184967ab9968a02198dae4524fa15ce8edcd0a5b1ddc270871bba33b231cf` |
| `ps5_1360_prologue_roots_analysis.exe` | 103,665,664 | `27211115698ed2fa4486d1f12e52220bb091e3fe01cf6354ecdfc7751228fb2d` |
| `ps5_1360_attack_surface_analysis.exe` | 284,160 | `08c090080366fd6877f72b4d0378f084e11a698ddef0819d7c8916aadf9dd67f` |
| `ps5_1360_syscall220_analysis.exe` | 111,616 | `312f443ccbfe345d70b9ff09fc91d17e24081ab25598e5d4e28247e41221cec2` |

The PE section bytes were compared against their source ranges, with synthetic root sections recorded separately in `BROAD_REVIEW_STATIC_EVIDENCE_2026-10-14.json`. Carrier headers and synthetic root calls are analysis scaffolding, never PS5 instructions. The text contains 25,890 raw prologue-pattern matches; the prologue-root builder's additional preceding-byte filter reduces this to 23,512 possible starts. Neither is a validated function inventory or semantic review count.

## REA state and coverage

The REA session initially had no open target and no retained evidence records. Existing markdown reports and disassembly files were reused; historical Evidence IDs below were not replayed as live session results. The full prologue-root carrier was opened and broad provider inventory requested. It did not return a completed inventory within this bounded pass; cancellation of the orchestration wait does not prove provider completion. A close request was issued but did not acknowledge completion before the bounded wait ended. No full-image function count or coverage claim is derived from that attempt.

The retained earlier targeted REA report describes 44 recognized procedures and decompilation of 11 networking/AIO/EVF procedures plus two ICMPv6 procedures in the small carrier. Recognition, inclusion in a carrier, and decompilation are distinct from security review. The builder currently lists 13 mapped sections including synthetic `.roots`, so the old prose “14 selected regions” is not a reliable coverage denominator.

| Subsystem / boundary | Available evidence examined | Bounded conclusion | Major gap |
|---|---|---|---|
| Artifact layout / missing pages | Manifest, recomputed hashes, carrier builders and PE section checks | Identity and missing-data boundary verified locally | Original capture provenance / unrecorded memory |
| Syscall dispatch / SysV IPC | Retained slot 220–222 REA report; bounded-table corrections | Observed route returns 0x4e; generated syscall names do not prove functionality | Full dispatcher, true table bound, alternate IPC paths |
| Sony dynlib | `REA_DYNLIB_CLUSTER_FINDINGS.md`, raw `rea_sys586_599_full.txt`, `rea_get_obj_member.txt` | Selected size/index checks present; 8-byte selected-field copyout is not a demonstrated sensitive leak | Field provenance, mutation/lifetime paths, unload races |
| CFI failure handling | Fresh direct-byte disassembly of helper and configuration predicate | Failure path can terminate with UD2; captured mode selects fatal branch | Global writers, mode semantics, all CFI sites |
| IPv6 hop-by-hop | Retained small-carrier REA / disassembly | Relevant functions located; no confirmed new UAF | Ownership across all callers, option parsers and error exits |
| ICMPv6 error parsing | `icmp6_notify_inline.txt`, retained REA summary | Saved review shows post-pullup refresh and by-value destination copy; stale-pointer candidate demoted for 13.60 | Other parsers and paths; no 14.10 comparison |
| AIO / Sony multi operations | Retained `aio_*.txt`, selected lock/state observations | No confirmed double-free in this artifact; wait-side locking observed | Backend completion/cancellation ownership and all teardown interleavings |
| EVF / synchronization | Retained selected EVF REA summary and disassembly | Some list operations have locking; no confirmed race | Entire create/delete/cancel lifecycle and UMTX implementation |
| Direct memory device | `dmem_ioctl.txt` entry/lifecycle windows spot-checked | Calls, refcount operations, callback checks visible; no substantiated bug | Command-specific lengths, mapping ownership, async device behavior |
| GPU / GC ioctl | `gc_ioctl_core.txt` dispatch and tail windows spot-checked | Large command dispatch exists; no substantiated bug | Complete callees, DMA/GPU semantics, validation of each command |
| VM / device pager / mmap | Primarily upstream-source leads and saved notes | No binary-bound bug candidate established | Locate and review actual Sony pager/VM handlers |
| UNIX sockets / sendfile / rights | Retained source-audit findings only | Upstream-source defects cannot be promoted to PS5 binary findings | Locate exact PS5 functions and compare ownership/error paths |
| VFS / PFS / DevPFS | Symbol/string hints and project notes | Presence hints provide no authorization or memory-safety conclusion | Exact entry points, parsers, privilege checks and lifetime analysis |
| SBL / SELF authentication / secure processor | String-derived locations in earlier analysis | No bypass established | Actual validation dataflow, secure-world boundary, signed-image handling |
| kqueue / fd lifecycle / scheduler / signals / credentials / networking remainder | Source-audit hypotheses and metadata | No new artifact-bound vulnerability established | Substantive implementation review remains open |

## Prioritized outcomes

1. **Correct the unconditional CFI fail-open claim — high confidence in observed bytes, no vulnerability claim.** The dynlib caller at `0xffffffff9e73cc1a–0xffffffff9e73cc41` invokes helper `0xffffffff9e83f8c0` on an invalid callback and has a continuation if it returns. Inspecting only that continuation was insufficient. The helper contains conditional return paths but also a diagnostic path ending in `ud2` at `0xffffffff9e83f941`. Predicate `0xffffffff9eef7920` returns whether the DWORD at `0xffffffff9fcd446c` equals 4. Its captured value is 1, selecting the fatal branch (assuming unchanged global value). The helper references the string `cfi_check_fail: data %p, caller %p, callee %p`. Runtime global changes and configuration meanings remain unknown. This rules out stating that the retained 13.60 snapshot simply logs and continues on this path. It does not prove CFI is universally sound.
2. **Retain bounded negative findings — moderate confidence, exact reviewed paths only.** The ICMPv6 stale-pointer candidate is demoted by the saved instruction review; dynlib member selectors are bounded; selected info-size checks and AIO/EVF locking exist. None proves subsystem-wide safety. Historical REA references: syscall table `ev_b2e3e35a8439228abf1cb62a4dd54694b7e5abae2c2279ab89de24e9a4633d72`, generic handler `ev_b3c533bfde2cb74c7417c7d98036909bbf0a7a97e6d421c3faa7f2169c903cf9`, ICMPv6 `ev_71b591a2503c74c6836e98a53d6fc2210b3a06c01043fd1f8a259c6385b4e2ed`.
3. **Do not promote unresolved leads — high confidence in the evidence gap.** AIO crash/double-free, event-flag race, dynlib kernel-pointer leak, syscall 590 kernel fault, and source-only VM/IPC/socket findings lack a complete artifact-bound path and demonstrated security impact. There is no evidence-backed priority for exploitability, no proven privilege escalation or kernel read/write, and no established 14.10 applicability.

## Practical offline next work

First reconcile or recover the full-image provider state and retain an evidence bundle/snapshot only after successful completion. Next locate exact per-subsystem entry points and map callees, user-input provenance, privilege gates and ownership transitions. Prioritize AIO completion versus cancellation, dynlib unload/field provenance, device ioctl length handling, and pager/socket error cleanup because these are concrete coverage gaps, not confirmed vulnerabilities. Exclude missing data ranges and synthetic carrier sections from evidence. A decrypted and version-bound 14.10 kernel is required for a direct firmware comparison.

Supporting local evidence: `BROAD_REVIEW_STATIC_EVIDENCE_2026-10-14.json`; `REA_COVERAGE_AND_14.10_TEST_MATRIX.md`; `REA_DYNLIB_CLUSTER_FINDINGS.md`; `rea_import/REA_SYSCALL_220_REVIEW.md`; `../checkpoints/EVIDENCE_LEDGER.md`. Older `ANALYSIS.md` claims that assert a confirmed 14.10 AIO double-free, infer bugs from strings, or assume stable offsets are not accepted as findings.
