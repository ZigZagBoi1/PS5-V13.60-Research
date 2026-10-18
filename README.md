# PS5 V13.60 Research

Open kernel and hypervisor research on a PS5 running firmware **13.60**, jailbroken with **Relapse + Byepervisor-Reborn**.

> **Goal:** Full kernel dumps and reverse engineering to find bugs exploitable on newer firmware (14.10+).

### Progress Update (10-18-2026)

The V13.60 PS5 is jailbroken with kernel R/W and hypervisor bypass. The repository now contains a 679-entry sysent table, 145 Sony handler windows, a 15,132,096-byte kernel range, a 4 MiB kernel range, a 64 KiB sysent window, and a 256-byte credential capture. These are fixed address ranges, **not complete `.text` and `.data` sections**. The raw sysent table matches the bytes at offset `+0x1000` in `sysent_area.bin`. The kernel base and coverage limits are documented in [`docs/dumps_13.60/`](docs/dumps_13.60/); the 13.60 capture does not establish any matching 14.10 layout. This represents 80+ hours of hands-on research between this and the companion [V14.10 project](https://github.com/ZigZagBoi1/PS5-14.10-Research).

The local research site has also received a staged Relapse/HV flow, diagnostics, guarded payload delivery, and rollback-aware installer work. Its 22 Python tests, 9 Node tests, and 88-file release consistency check pass. These changes remain local and have not been deployed; see the [hosting audit](docs/audits/2026-10-17-hosting/README.md). The [capture reconciliation](docs/audits/2026-10-18-dump-reconciliation.md) records the dump base correction, range limits, integrity gaps, and native receiver dependency.

PRs with analysis, disassembly notes, or cross-firmware diffs are welcome.

[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-blue?logo=paypal)](https://www.paypal.me/SalwanStudios) - helps cover AI tooling subscriptions and infrastructure costs

## Repository Layout

| Path | Contents |
|------|----------|
| `docs/dumps_13.60/` | Raw kernel dumps - sysent table, handler binaries, .text, .data |
| `docs/ps5_13.60_sysent.json` | Parsed sysent for tooling |
| `artifacts/` | Built payload artifact (byepervisor_reborn-13.60.elf) |
| `site/` | Local browser-based research server and tooling |
| `upstream/Relapse-Exploit/` | Pinned upstream Relapse source (submodule) |
| `upstream/Byepervisor-Reborn/` | Pinned upstream Byepervisor-Reborn source (submodule) |
| `HV-RELAPSE-13.60.md` | Exploit order, requirements, and observed stage evidence |

## Exploit Chain

1. **Relapse** (kernel stage) - WebKit entry, kernel R/W on firmware 7.00-13.60
2. **Byepervisor-Reborn** (HV stage) - hypervisor bypass, kernel .text becomes R/W
3. **Native ELF via elfldr** (port 9021) - `kernel_copyout()` for dumping kernel memory
4. **TCP transfer** - dump files sent to a receiver on the local network

## Kernel Dumps

| File | Size | Contents |
|------|------|----------|
| `kernel_text.bin` | 15,132,096 B | Requested range from kernel base `+0x0`; crosses from `.text` into `.data` |
| `kernel_data.bin` | 4,194,304 B | 4 MiB sample beginning at kernel base `+0x1000000`; not the complete `.data` section |
| `sysent_area.bin` | 64 KB | Raw sysent table region |
| `sysent_raw.bin` | 32,592 B | Raw sysent table (679 entries, 48-byte stride) |
| `sysent_index.json` | 84,874 B | JSON index with syscall numbers, argument counts, and handler RVAs |
| `handler_NNN.bin` | 4,096 B each | First 4 KiB at each of 145 Sony handler addresses (532-676); not necessarily a complete function |
| `ucred.bin` | 256 B | Captured credential-structure bytes |

See [`docs/dumps_13.60/README.md`](docs/dumps_13.60/README.md) for details on the format and how to disassemble handlers.

## Known Offsets (13.60)

| Symbol | RVA | Notes |
|--------|-----|-------|
| Kernel base | `0xffffffff8a9c0000` | This capture's base; recorded by the manifest and sysent index, varies with KASLR |
| Sysent table | `+0xe6e5c0` | Observed in the 13.60 capture; a matching 14.10 RVA is not established |
| `nosys` handler | `+0x265760` | Shared by 368 of 679 entries |
| .text end | ~`+0xcc0000` | Data section begins here |

## Related Work

- **[PS5 14.10 Research](https://github.com/ZigZagBoi1/PS5-14.10-Research)** - companion project targeting firmware 14.10 via Lua loader probes. Uses the 13.60 dumps for cross-firmware diffing.
- **[Relapse](https://github.com/ntfargo/Relapse-Exploit)** - kernel exploit for 7.00-13.60
- **[Byepervisor-Reborn](https://github.com/PS5Dev/Byepervisor-Reborn)** - hypervisor bypass for 13.60

## Scope

This repository is for research on hardware the owner is authorized to test. Exploit stages can crash or destabilize the console.
