"""Build a small PE analysis carrier around the PS5 13.60 syscall-220 path."""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "kernel-13.60-live.bin"
META = ROOT / "kernel-13.60-live.bin.json"
OUTPUT = ROOT / "rea_import" / "ps5_1360_syscall220_analysis.exe"
TEXT_BASE = 0xFFFFFFFF9E3F0000
DATA_BASE = 0xFFFFFFFF9F0B0000
TEXT_SIZE = 13369344
DATA_OFFSET = TEXT_SIZE
FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000
HEADERS_SIZE = 0x400
PE_OFFSET = 0x80

REGIONS = [
    # syscall-table slot 220's executable trampoline
    (b".tramp", 0xFFFFFFFF9E655000, 0x1000, "text"),
    # Shared destination of the table's nosys trampoline
    (b".common", 0xFFFFFFFF9E952000, 0x8000, "text"),
    # Named nosys implementation from the dump's existing symbol map
    (b".nosys", 0xFFFFFFFF9E79D000, 0x4000, "text"),
    # Relative jump target from 0xffffffff9e655a90: 0xffffffff9ecec820
    (b".handler", 0xFFFFFFFF9ECEC000, 0x8000, "text"),
    # Includes syscall-table entries around slots 220-222
    (b".sysent", 0xFFFFFFFF9F25E000, 0x6000, "data"),
]
ENTRY_VA = 0xFFFFFFFF9E655A90


def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


def section_header(name, virtual_size, rva, raw_size, raw_offset, flags):
    return struct.pack("<8sIIIIIIHHI", name.ljust(8, b"\0"), virtual_size,
                       rva, raw_size, raw_offset, 0, 0, 0, 0, flags)


def main():
    meta = json.loads(META.read_text(encoding="utf-8"))
    image_hash = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    if image_hash != meta["sha256"]:
        raise ValueError(f"input image hash mismatch: {image_hash}")

    image_base = min(va for _, va, _, _ in REGIONS) - SECTION_ALIGN
    sections = []
    raw_cursor = HEADERS_SIZE
    for name, va, size, kind in REGIONS:
        raw_size = align(size, FILE_ALIGN)
        rva = va - image_base
        if kind == "text":
            src_offset = va - TEXT_BASE
            flags = 0x60000020  # code, execute, read
        else:
            src_offset = DATA_OFFSET + va - DATA_BASE
            flags = 0xC0000040  # initialized data, read, write
        sections.append({"name": name, "va": va, "size": size,
                         "rva": rva, "raw_size": raw_size,
                         "raw_offset": raw_cursor, "src_offset": src_offset,
                         "flags": flags, "kind": kind})
        raw_cursor += raw_size

    dos = bytearray(PE_OFFSET)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, PE_OFFSET)
    code_size = sum(s["raw_size"] for s in sections if s["kind"] == "text")
    data_size = sum(s["raw_size"] for s in sections if s["kind"] == "data")
    optional = bytearray(0xF0)
    struct.pack_into("<H", optional, 0, 0x20B)
    struct.pack_into("<II", optional, 4, code_size, data_size)
    struct.pack_into("<I", optional, 16, ENTRY_VA - image_base)
    struct.pack_into("<I", optional, 20, min(s["rva"] for s in sections if s["kind"] == "text"))
    struct.pack_into("<Q", optional, 24, image_base)
    struct.pack_into("<II", optional, 32, SECTION_ALIGN, FILE_ALIGN)
    struct.pack_into("<HHHHHH", optional, 40, 6, 0, 0, 0, 6, 0)
    max_end = max(s["rva"] + s["size"] for s in sections)
    struct.pack_into("<II", optional, 56, align(max_end, SECTION_ALIGN), HEADERS_SIZE)
    struct.pack_into("<HH", optional, 68, 1, 0)  # native subsystem
    struct.pack_into("<QQQQ", optional, 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<II", optional, 104, 0, 16)
    coff = struct.pack("<HHIIIHH", 0x8664, len(sections), 0, 0, 0, 0xF0, 0x0022)
    shdrs = b"".join(section_header(s["name"], s["size"], s["rva"],
                                  s["raw_size"], s["raw_offset"], s["flags"])
                    for s in sections)
    headers = bytes(dos) + b"PE\0\0" + coff + bytes(optional) + shdrs
    if len(headers) > HEADERS_SIZE:
        raise ValueError("PE headers exceed configured size")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with SOURCE.open("rb") as src, OUTPUT.open("wb") as dst:
        dst.write(headers)
        dst.write(bytes(HEADERS_SIZE - len(headers)))
        for s in sections:
            src.seek(s["src_offset"])
            payload = src.read(s["size"])
            if len(payload) != s["size"]:
                raise ValueError(f"short read for {s['name'].decode()}")
            dst.write(payload)
            dst.write(bytes(s["raw_size"] - s["size"]))

    print(f"Carrier: {OUTPUT}")
    print(f"Input SHA-256: {image_hash}")
    print(f"Carrier SHA-256: {hashlib.sha256(OUTPUT.read_bytes()).hexdigest()}")
    print(f"Image base: 0x{image_base:x}; entry: 0x{ENTRY_VA:x}")
    for s in sections:
        print(f"{s['name'].decode()}: VA 0x{s['va']:x}, {s['size']} bytes")


if __name__ == "__main__":
    main()
