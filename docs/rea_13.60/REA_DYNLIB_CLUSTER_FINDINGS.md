# PS5 13.60 REA — Dynlib Syscall Cluster Findings
**Date:** 2026-10-14 (Session 3)
**Method:** Capstone disassembly of trampoline stubs (`0xffffffff9e655xxx` page) resolved to real handlers; handler identity taken from each function's **self-named error string** (`0x9ef12a30` printf pattern, first arg = function name). All addresses are from the 13.60 live dump (text base `0xffffffff9e3f0000`).

## 1. Verified dynlib syscall map (13.60)

| Syscall | Handler VA | Identity (self-named string) | narg |
|---|---|---|---|
| 591 | `0xffffffff9e73ae90` | **sys_dynlib_dlsym** | 3 |
| 592 | `0xffffffff9e73b510` | **sys_dynlib_get_info** | 3 |
| 593 | `0xffffffff9e73b7b0` | **sys_dynlib_get_info2** | 3 |
| 594 | `0xffffffff9e73a470` | small wrapper: lock + call helper `0x9e649b70` | 1 |
| 595 | `0xffffffff9e73ad30` | **sys_dynlib_unload_prx** | 3 |
| 596 | `0xffffffff9e73c750` | **sys_dynlib_do_copy_relocations** | 0 |
| 598 | `0xffffffff9e73c990` | **sys_dynlib_get_proc_param** | 2 |
| 599 | `0xffffffff9e73caa0` | **sys_dynlib_process_needed_and_relocate** | 0 |
| 608 | `0xffffffff9e73bdc0` | **sys_dynlib_get_info_ex** | 3 |
| 612 | `0xffffffff9e73ce50` | copyin/copyout only (helper-class; likely get-meta) | 1 |
| 649 | `0xffffffff9e73cfa0` | **sys_dynlib_get_obj_member** | 3 |
| 656 | `0xffffffff9e73c350` | sys_dynlib_get_info_for_libdbg | 2 |
| 659 | `0xffffffff9e73b790` | sys_dynlib_get_info (2nd entry) | 3 |
| 660 | `0xffffffff9e73bc60` | sys_dynlib_get_info2 (2nd entry) | 2 |
| 672 | `0xffffffff9e73c670` | sys_dynlib_get_list_for_libdbg | 3 |

This matches the public scene numbering (dlsym=591, get_info=592, get_info2=593, unload_prx=595) — cross-validates both our REA and the scene map.

## 2. Corrected finding: 589, 590, and 597 have generic `nosys` records in 13.60

The earlier generated listing showed `…588, 591, 592…` and omitted 589, 590, and 597. Bounded raw reads of the 48-byte sysent records confirm each omitted slot has `narg=0` and handler `0xffffffff9e655760`, the generic `nosys` trampoline named in `syscall_table_1360.txt`. This is not evidence of an absent record or custom handler. Separately, the generated listing's rows 677–699 contain implausible `narg`/handler values, so its claimed 700-entry upper bound and total count are not validated; this caveat does not affect the bounded lower-slot reads cited here.

**Consequence:** the 13.60 table routes these slots to generic `nosys`; the 14.10 mapping remains unavailable. A saved 14.10 note records a game/RPC failure after a syscall 590 attempt, but no kernel fault or handler identity. Do not infer that the slot is new in 14.x or that the failure was a kernel dereference.

The earlier guess "590 = dynlib_dlsym" is disproven for the 13.60 table: dlsym is 591. The 14.10 identity of 590 remains unknown; proximity to the dynlib cluster does not establish its family.

### Current status for 590
Treat it as an identification task only. No live follow-up is justified until exact 14.10 handler/table evidence is available and the RPC service again returns a complete print-only response. Do not probe adjacent unallocated numbers. The saved NULL-argument result is an unidentified process/RPC crash, not a confirmed kernel bug.

## 3. sys_dynlib_get_obj_member (649) — bounded copyout; leak not established

Full disassembly: `rea_get_obj_member.txt`.

- Validates dynamic-linked program (`[rax+0x148] != 0` guard, standard dynlib gate).
- Locks the module list (`0x9f03bb20` on `dynlib+0x70`), walks modules matching `uap->handle` against `[module+0x28]`.
- Member byte: `movzx eax, [uap+8]; dec eax; cmp eax,7; ja → EINVAL` — **member index 1..8 strictly bounded via 8-entry jump table** (`0xffffffff9f851250`-relative). No OOB.
- Each case loads one QWORD from a fixed module-struct field; map all eight case-to-field assignments before interpreting the returned values.
- Unlocks, then `copyout(&qword, uap+0x10, 8)`.

**Verdict:** this is an 8-byte copyout of a selected module field in the 13.60 binary. The disassembly establishes bounded selection, not that any field contains sensitive kernel data, a kernel pointer, or a KASLR disclosure. No 14.10 mapping or live leak is established. Trace the field assignments and pointer provenance offline before making a leak claim.

## 4. sys_dynlib_process_needed_and_relocate (599) — CFI observation

In the per-module loop (`0xffffffff9e73cc05–0x9e73cc41`): the relocation callback pointer `[module+0x28]` is validated against an in-image jump table via the `sub/ror 3/cmp 0x42` pattern **but on validation failure the code only logs (`0x9e83f8c0`) and still calls through `r12`** (`jmp 0x9e73cbe0` → `call r12`). If a future bug lets user data influence `[module+0x28]`, Sony's CFI here is **log-and-continue, not abort** — an indirect-call primitive would survive. No user-controlled path to that field was identified in this pass.

## 5. sys_dynlib_get_info / get_info2 (592/593) — validation present

- 592: module handle bounded (`cmp r12, rax; jae` against the module count) before use; list-copy path re-checks `rbx` against both the user-supplied capacity and the live count (`cmp rbx, rcx; ja` / `cmp rbx, r12; jae`) before `copyout_module_handle_list`.
- 593 (get_info2): `cmp qword ptr [rbp-0x38], 0x160` — requires `size >= 0x160` before filling the info struct; copyin/copyout pairs wrapped with fault-tolerant helpers (`0x9f00a3e0` = "copyin"/"copyout" logger + `0x9e6491d0`).
- No bug confirmed in either. The `0x160` size gate means passing a larger buffer is fine; passing smaller → clean error.

## 6. AIO handlers (633 wait / 636 cancel / 632 delete / 638 / 639 / 640)

Previously decompiled (`aio_*.txt`); this session cross-checked call-pattern counts (wait=29 calls, cancel=23, delete=32). Observation on **aio_multi_wait (633)**: the state-machine loop takes a per-job lock (`0x9e8b78b0` witness-style, `ecx` = file:line) around every state check and transition, and job teardown (`0x9e8b7520` + `0x9e8b6fa0`) happens **inside** the locked region before advancing the user array cursor — no obvious UAF window from the calling thread's side. The Relapse-era double-free would require the async completion path to race the waiter; that path is in the AIO backend helpers not covered by these dumps. **Verdict for 13.60: no new bug; keep as "known-fixed area" unless 14.10 diff shows otherwise.**

## 7. What this changes for the 14.10 ranking

1. **Syscall 590** — low-confidence identification task; no confirmed kernel fault, memory corruption, or reachable handler.
2. CVE-2026-58098 — conditional upstream memory-corruption candidate; 14.10 SysV reachability and worker overlap are unknown.
3. CVE-2026-49418 / 58087 — 49418 is blocked at `MS_INVALIDATE`; 58087 has substantial reachability and scheduling gates.
4. get_obj_member (649) — offline field-provenance audit only; the 13.60 copyout is not yet a demonstrated sensitive-data or KASLR leak.
5. get_info_ex (608) — new to this REA; audit if 590 probes show the family changed shape in 14.10.

## 8. Reproducibility

- `rea_trampoline_map.py` — stub → real-handler resolution for 548/585–588/591–599.
- `rea_sys586_599.py` — full disassembly → `rea_sys586_599_full.txt`.
- `rea_obj_member.py` — get_obj_member disassembly → `rea_get_obj_member.txt`.
- All outputs in `ps5-13.60-kernel-dump/`.
