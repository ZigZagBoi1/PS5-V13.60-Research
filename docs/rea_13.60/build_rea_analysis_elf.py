"""Wrap the documented PS5 13.60 flat RAM capture as a two-segment ELF for REA/Ghidra.

The input capture is not modified. This ELF is only an analysis container: it
maps the exact captured text and data byte ranges at their documented VAs.
"""
import hashlib
import json
import shutil
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "kernel-13.60-live.bin"
META = ROOT / "kernel-13.60-live.bin.json"
OUTPUT = ROOT / "rea_import" / "ps5_1360_live_memory_analysis.elf"
PAGE = 0x1000


def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


def copy_region(src, dst, size: int, expected_hash: str, label: str) -> None:
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        chunk = src.read(min(1024 * 1024, remaining))
        if not chunk:
            raise ValueError(f"unexpected EOF in {label}")
        dst.write(chunk)
        digest.update(chunk)
        remaining -= len(chunk)
    actual = digest.hexdigest()
    if actual != expected_hash:
        raise ValueError(f"{label} SHA-256 mismatch: {actual}")


def main() -> None:
    metadata = json.loads(META.read_text(encoding="utf-8"))
    sections = {item["name"]: item for item in metadata["sections"]}
    text = sections["kernel_text"]
    data = sections["kernel_data"]
    text_off = PAGE
    data_off = align(text_off + text["size"], PAGE)

    ident = bytearray(16)
    ident[:4] = b"\x7fELF"
    ident[4] = 2  # ELFCLASS64
    ident[5] = 1  # little endian
    ident[6] = 1  # ELF version
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        bytes(ident), 2, 62, 1, int(text["virtual_address"], 16),
        64, 0, 0, 64, 56, 2, 0, 0, 0,
    )
    ph_text = struct.pack(
        "<IIQQQQQQ", 1, 5, text_off,
        int(text["virtual_address"], 16), int(text["virtual_address"], 16),
        text["size"], text["size"], PAGE,
    )
    ph_data = struct.pack(
        "<IIQQQQQQ", 1, 6, data_off,
        int(data["virtual_address"], 16), int(data["virtual_address"], 16),
        data["size"], data["size"], PAGE,
    )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with SOURCE.open("rb") as src, OUTPUT.open("wb") as dst:
        dst.write(ehdr + ph_text + ph_data)
        dst.write(bytes(text_off - dst.tell()))
        copy_region(src, dst, text["size"], text["source_sha256"], "kernel_text")
        src.seek(data["file_offset"])
        dst.write(bytes(data_off - dst.tell()))
        copy_region(src, dst, data["size"], data["source_sha256"], "kernel_data")

    if OUTPUT.stat().st_size != data_off + data["size"]:
        raise ValueError("generated ELF size does not match mapped segments")
    print(f"ELF analysis wrapper: {OUTPUT}")
    print(f"ELF SHA-256: {hashlib.sha256(OUTPUT.read_bytes()).hexdigest()}")
    print(f"Input RAM image SHA-256: {metadata['sha256']}")
    print(f"Text: VA 0x{text['virtual_address']}, {text['size']} bytes")
    print(f"Data: VA 0x{data['virtual_address']}, {data['size']} bytes")
    print(f"Zero-filled unmapped data pages preserved: {metadata['unmapped_data_pages']}")


if __name__ == "__main__":
    main()
