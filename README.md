# PS5 V13.60 Research

Open kernel and hypervisor research on a PS5 running firmware **13.60**, jailbroken with **Relapse + Byepervisor-Reborn**.

> **Goal:** Full kernel dumps and reverse engineering to find bugs exploitable on newer firmware (14.10+).

### Progress Update (10-18-2026)

The V13.60 PS5 is fully jailbroken with kernel R/W and hypervisor bypass. Kernel dumps are captured and publicly available in [`docs/dumps_13.60/`](docs/dumps_13.60/) - sysent table (679 entries), 145 Sony syscall handler binaries, 15MB of kernel .text, 4MB of .data, and the 64KB sysent area. Everything found on this console is shared publicly. This represents 80+ hours of hands-on research between this and the companion [V14.10 project](https://github.com/ZigZagBoi1/PS5-14.10-Research).

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
| `kernel_text.bin` | 15 MB | Full kernel .text section |
| `kernel_data.bin` | 4 MB | Kernel .data section |
| `sysent_area.bin` | 64 KB | Raw sysent table region |
| `sysent_raw.bin` | 32 KB | Parsed sysent (679 entries, 48-byte stride) |
| `sysent_index.json` | 79 KB | JSON index with syscall numbers, arg counts, handler RVAs |
| `handler_NNN.bin` | 4 KB each | 145 Sony syscall handler binaries (532-676) |
| `ucred.bin` | 176 B | Process credential structure |

See [`docs/dumps_13.60/README.md`](docs/dumps_13.60/README.md) for details on the format and how to disassemble handlers.

## Known Offsets (13.60)

| Symbol | RVA | Notes |
|--------|-----|-------|
| Kernel base | `0xffffffff94480000` | Session-specific (varies with KASLR) |
| Sysent table | `+0xe6e5c0` | Stable across 13.60 and 14.10 |
| `nosys` handler | `+0x265760` | Shared by 368 of 679 entries |
| .text end | ~`+0xcc0000` | Data section begins here |

## Related Work

- **[PS5 14.10 Research](https://github.com/ZigZagBoi1/PS5-14.10-Research)** - companion project targeting firmware 14.10 via Lua loader probes. Uses the 13.60 dumps for cross-firmware diffing.
- **[Relapse](https://github.com/ntfargo/Relapse-Exploit)** - kernel exploit for 7.00-13.60
- **[Byepervisor-Reborn](https://github.com/PS5Dev/Byepervisor-Reborn)** - hypervisor bypass for 13.60

## Scope

This repository is for research on hardware the owner is authorized to test. Exploit stages can crash or destabilize the console.
