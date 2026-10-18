# PS5 13.60 Kernel Dump Analysis — Sister Exploit Research for 14.10

**Source:** https://github.com/terrafirma2021/ps5-13.60-kernel-dump
**Captured:** 2026-10-13 from live PS5 running firmware 13.60
**Dump:** 103.5 MB flat binary — 13.4 MB kernel text + 90.2 MB kernel data

## Key Facts

- **25,890 functions** identified in kernel text via prologue scanning
- **Build path:** `W:/Build/J03950001/sys/freebsd/sys/` — confirms Sony internal build
- **FreeBSD base:** confirmed via jail, sysctl, uma_zone, and VFS subsystem strings
- **Orbis extensions:** `orbis_cpumode.c`, `orbis_hw_status_on_crash`, custom EVF/AIO subsystems
- **688 unmapped pages** in data (zeroed) — partial capture, but text section is complete

## Vulnerability Target Functions — Located in 13.60

### 1. IPv6 Hop-by-Hop Processing (Bug #40 sister)

| Item | Value |
|------|-------|
| Function VA | `0xffffffff9ecbaac0` |
| Size | ~928 bytes |
| Key string xref | `%s: off < sizeof(struct ip6_hdr)` at `0xffffffff9f73b227` |
| Callers | `0xffffffff9e841a0e`, `0xffffffff9ef31732` |
| Related strings | `ip6_get_prevhdr`, `ip6_clearpktopts`, `ip6_output`, `ip6_nexthdr`, `ip6opt` |

The ip6 hop-by-hop option processing function is present and callable.
Bug #40 (ip6_input_hbh UAF) was patched in our emulator for 14.10, but the underlying
code structure in 13.60 gives us the exact layout to find sister vulnerabilities:
- Where mbuf chains are manipulated during hop-by-hop option processing
- The relationship between `ip6_get_prevhdr` and the extension header chain
- Error paths where mbufs may be freed without clearing all references

### 2. AIO Subsystem (Double-Free confirmed on 14.10)

| Item | Value |
|------|-------|
| Build source | `W:/Build/J03950001/sys/freebsd/sys/kern/vfs_aio.c` |
| Function at vfs_aio.c xref | `0xffffffff9ef70060` |
| Key syscalls | `aio_submit`, `aio_fsync`, `aio_cancel`, `aio_return`, `aio_suspend` |
| Sony extensions | `SceKernelAioSubmitInfo`, `SceKernelAioRequestInfo`, `aio_submit_cmd`, `aio_multi_wait`, `aio_multi_poll`, `aio_multi_delete`, `aio_multi_cancel` |
| Locking | `Global AIO Lock`, `Global AIO SX`, `AIO req hd lock`, `AIO MWait mutex`, `aiomtx` |

**Critical finding:** Sony has extended FreeBSD's AIO with a `multi_*` API:
- `aio_multi_wait` / `aio_multi_poll` / `aio_multi_delete` / `aio_multi_cancel`
- `aio_submit_cmd` / `_aio_submit_cmd`
- `SceKernelAioSubmitInfo` / `SceKernelAioRequestInfo` structures

The double-free we confirmed via 4-thread race on 14.10 exploits the standard AIO path,
but these Sony-specific multi_* extensions are NEW attack surface. The multi_cancel
path especially is a high-value target — cancelling multiple AIO requests simultaneously
creates race windows between the cancel and completion paths.

### 3. Event Flag (EVF) System

| Item | Value |
|------|-------|
| evf_trywait handler | `0xffffffff9ec1c800` |
| Functions | `evf_create`, `evf_open`, `evf_wait`, `evf_set`, `evf_cancel`, `evf_trywait`, `evf_delete`, `evf_close`, `evf_clear` |
| Syscall wrappers | `syscallWaitEventFlag`, `syscallSetEventFlag`, `syscallPollEventFlag`, `syscallCancelEventFlag` |
| Locking | `evf mtx`, `evf cv` |
| Object management | `gnt_delete(): non-existent entry.name=%s type=ID_EVF evf=0x%p` |

The EVF system uses a mutex + condition variable pair. The `gnt_delete` and `gnt_free`
error strings reveal an object namespace (`gnt` = grant table?) that manages EVF lifecycle.
The `cancelEventFlagAll()` function is particularly interesting — bulk cancellation
across waiters creates TOCTOU windows.

### 4. SBL Auth Manager (Crypto/Security Boundary)

| Function | VA Reference |
|----------|-------------|
| `sceSblAuthMgrFinalize` | `0xffffffff9f65c64d` |
| `sceSblAuthMgrAuthHeader` | → error at `0xffffffff9f65f636` |
| `_sceSblAuthMgrSmUnload` | `0xffffffff9f65ced4` |
| `_sceSblAuthMgrSmLoadMultipleSelfBlocks` | `0xffffffff9f65ceeb` |
| `_sceSblAuthMgrCheckSelfHeader` | `0xffffffff9f66c96e` |
| `sceSblKdfCronosUserPersonalizedKey` | `0xffffffff9f77a926` |
| `sceSblKmsSetKeyId` / `ClearKeyId` | multiple refs |
| `sceSblRngGetRandomNumber` | `0xffffffff9f743d19` |

The SBL (Secure Boot Loader) auth manager is the gate between userspace and the
secure processor. Understanding its error paths from 13.60 tells us exactly which
checks 14.10 performs and where timing/error-path attacks might succeed.

## Trampoline Architecture

The kernel uses a **two-level trampoline** system:
1. First-level JMP stubs clustered at `text+0x261000..0x272000`
2. These jump to the real implementations deeper in the text section

Top referenced trampolines (likely the most-called kernel functions):
- `0xffffffff9e65a7f0` → `0xffffffff9e79dcf0` (646 refs — returns 0x208, likely nosys/EOPNOTSUPP)
- `0xffffffff9e655760` → `0xffffffff9e9520e0` (607 refs — saves callee-saved regs, big function)
- `0xffffffff9e6609e8` → `0xffffffff9e947540` (524 refs)
- `0xffffffff9e651098` → `0xffffffff9eff90b0` (511 refs — checks a magic value 0xe9f85434)

## Attack Surface Summary for 14.10

### High-Value Targets (code confirmed present in 13.60)

1. **AIO multi_cancel race** — Sony's custom `aio_multi_cancel` / `_aio_multi_cancel` extends the standard FreeBSD AIO with batch operations. The existing double-free on the standard path means the multi-path likely shares the same vulnerable pattern.

2. **EVF cancelEventFlagAll TOCTOU** — Bulk cancel of event flag waiters while new waiters are being added. The mutex/CV locking scheme visible in the strings suggests the critical section may not cover the full waiter-list manipulation.

3. **ip6 extension header chain** — The 928-byte function at `0xffffffff9ecbaac0` handles hop-by-hop options. Sister bugs to #40 may exist in the destination options or routing header processing paths (referenced via `ip6_get_prevhdr`, `ip6_nexthdr`).

4. **SBL auth error paths** — `sceSblAuthMgrAuthHeader returned unexpected error %d` suggests the auth manager has error codes that aren't always handled correctly. A malformed SELF header that triggers an unexpected error code could bypass checks.

5. **PFS/DevPFS filesystem** — Extensive error handling strings for `pfs_*` and `devpfs_*` functions, including `devpfs_update_container_reserved()`, `DEVPFS_SEC_CRYPT`, and inode manipulation. The encrypted container filesystem is a complex attack surface.

### What Changed Between 13.60 and 14.10

Since this is a live RAM capture from 13.60 (two firmware versions before our target 14.10):
- **Code structure will be nearly identical** — Sony rarely refactors entire kernel subsystems between minor versions
- **Bug fixes will be targeted patches** — typically single-function changes, not architectural rewrites
- **KASLR slide will differ** — but relative offsets between functions should be stable
- **New mitigations may exist** — check for additional SMAP/SMEP enforcement, new stack canary patterns

## Next Steps

1. Load the text section into Ghidra at base `0xffffffff9e3f0000` as raw x86-64
2. Map data section at `0xffffffff9f0b0000`
3. Define functions at the addresses identified above
4. Compare AIO multi_cancel code path against our 14.10 probe results
5. Write probes for the EVF cancelEventFlagAll race condition
6. Cross-reference SBL auth manager error paths with our emulator's SELF loading code
