# 13.60 capture and repository status reconciliation

**Audit date:** 2026-10-18
**Scope:** The checked-in V13.60 dump metadata, the newly added native dumper sources, the hosting workflow, and README claims. No PS5 or external receiver was contacted.

## Capture identity

The current direct-address capture is identified by `kernel_dump_manifest.json` and `sysent_index.json` as firmware 13.60 with kernel base `0xffffffff8a9c0000`. The old `kernel_base.json` in the same directory said `0xffffffff94480000`, which did not match the manifest, index, or absolute syscall addresses. It has been corrected to the current capture's base. This audit found no other artifact in that directory that identifies the older value as a separate capture; do not apply it to the current dump.

Syscall 532 is a consistency check: `sy_call_off` is `0x265ce8`, and adding it to `0xffffffff8a9c0000` gives the stored `sy_call` `0xffffffff8ac25ce8`. The 32,592-byte `sysent_raw.bin` exactly matches the 32,592-byte slice at offset `0x1000` of `sysent_area.bin`. The 679-entry parsed index and raw table therefore agree on the checked table bytes.

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `kernel_text.bin` | 15,132,096 | `406ab210236d4123e06495bcc8da82d8f89dac07266558dc8c0f80cc6cf55cf1` |
| `kernel_data.bin` | 4,194,304 | `e46b98aa2155b29d33de3b11582a31051900f192058acaa10517e934dc2c5e46` |
| `sysent_area.bin` | 65,536 | `a4308ef3987180dcfeec2f8f3aa8680383c736efe0a817e3d1be50edce2633f5` |
| `sysent_raw.bin` | 32,592 | `fa12c87b6eedfee857a6721c2128fdb7406aee8c150dbdfd43983102e9d5f236` |
| `sysent_index.json` | 84,874 | `9db4cf650158355d707b2703f2275acbdc92375fe0b965461c1af3889b878319` |
| `ucred.bin` | 256 | `58ebb419e71a396094018d9dc418dc29273f2629c834ab218401b985aa9f9d82` |

## What the files cover

The files are fixed ranges, not complete `.text` and `.data` sections. The requested `kernel_text.bin` range is base `+0x0` for `0xe6e5c0` bytes. The 13.60 layout reference places the `.text`/`.data` boundary at `+0xcc0000`, so this file crosses into `.data`. `kernel_data.bin` is a 4 MiB sample starting at base `+0x1000000`. `sysent_area.bin` starts at `+0xe6d5c0`; the sysent table begins at `+0x1000` within that buffer.

The repository has no `.failmap` sidecars for `kernel_text.bin` or `kernel_data.bin`. `dump_progress.json` records only `sysent_area.bin` as 4/4 chunks with zero zero-filled chunks. File lengths and the sysent comparison are verified; whether the other two ranges contain zero-filled failed reads cannot be determined from the committed files.

The V14.10 project has no authenticated 14.10 kernel/sysent image. The 13.60 table RVA `+0xe6e5c0` is established for this capture only; a matching 14.10 RVA or handler layout is not established. The public 13.60 reconstructed image discussed in the V14.10 analysis is a separate artifact with a different base and hash; do not combine its absolute addresses with this live capture.

## Native dumper status and receiver dependency

`native-kernel-dumper/full_dump.c` currently reads the same three fixed ranges described above. Despite the legacy `ps5-full-kernel-dumper.elf` name, this source does not enumerate modules or discover complete kernel section bounds. The native dumper README has been corrected to call out this gap.

Both native dumper sources POST to `10.0.0.231:8888/dump`. A compatible receiver for that endpoint is not included in this repository. The audited web server is a separate service; its `/dump` route accepts the session-bound `kernel_base.json` and chunked `sysent_raw.bin` workflow, not the native dumper's arbitrary range files, failmaps, progress records, and manifest. Do not treat the native dump transfer as tested until a compatible receiver is configured and validated.

## Validation and progress reporting

Local checks passed: 22 Python hosting tests, 9 Node control-flow tests, and a release check that verified 88 files against pinned upstream sources and editable overrides. These checks use mocks/local files; they do not build the PS5 native dumper, contact a console or external receiver, or deploy the local site changes. The site changes remain local.

The V14.10 README's `$293.05 / $350` figure is 83.73% (about 84%) of its recorded fundraising target. That is a funding metric, not research completion. The research README now reports evidence-backed milestones rather than inventing an overall percentage: a validated 14.10 kernel primitive and verified 14.10 kernel image remain unavailable.
