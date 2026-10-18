# PS5 13.60 kernel dump

Live RAM reconstruction from a PS5 running firmware 13.60, captured on 13 October 2026. The archive contains one flat binary with kernel text followed by kernel data. It is **not** an ELF file or a bootable kernel image.

## Files

- `kernel-13.60-live.bin.gz` — gzip-compressed raw capture.
- `kernel-13.60-live.bin.json` — capture layout, virtual addresses, hashes, and missing-page information.

After decompression, `kernel-13.60-live.bin` is 103,546,880 bytes (SHA-256 `c3f745e25dc25ee7afef89eb418b295b6334bbefe8aa17e6886483c35d78cddd`). Its layout is:

| Region | File offset | Size | Captured virtual address |
| --- | ---: | ---: | --- |
| Kernel text | `0x0` | 13,369,344 bytes | `0xffffffff9e3f0000` |
| Kernel data | `0xcc0000` | 90,177,536 bytes | `0xffffffff9f0b0000` |

The data span contains **688 unmapped pages represented by zeroes**. See the JSON for their range. This is a partial live memory capture; it is not a complete decrypted firmware image. The text and data were captured from the same boot.

To extract: `gzip -d -k kernel-13.60-live.bin.gz`. To analyze the code, load the first 13,369,344 bytes as raw x86-64 at the text address above in a disassembler such as Ghidra, and map the data at its recorded address. Further reconstruction would need symbols and types, validation of code/data boundaries, and recovery of the missing data pages.
