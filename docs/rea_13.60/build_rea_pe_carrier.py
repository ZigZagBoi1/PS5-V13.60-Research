"""Create a PE-format analysis carrier for REA's Windows Ghidra provider.

This is not a runnable PS5 image. It preserves the captured kernel text/data
bytes in PE sections mapped at the VAs documented by the capture manifest.
"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "kernel-13.60-live.bin"
META = ROOT / "kernel-13.60-live.bin.json"
OUTPUT = ROOT / "rea_import" / "ps5_1360_live_memory_analysis.exe"
FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
HEADERS_SIZE = 0x200
PE_OFFSET = 0x80


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


def section_header(name: bytes, virtual_size: int, rva: int,
                   raw_size: int, raw_offset: int, characteristics: int) -> bytes:
    name_field = name.ljust(8, b"\0")
    return struct.pack(
        "<8sIIIIIIHHI", name_field, virtual_size, rva, raw_size, raw_offset,
        0, 0, 0, 0, characteristics,
    )


def main() -> None:
    metadata = json.loads(META.read_text(encoding="utf-8"))
    sections = {item["name"]: item for item in metadata["sections"]}
    text = sections["kernel_text"]
    data = sections["kernel_data"]
    # Leave the PE headers below the captured text instead of making .text
    # overlap the image header range (which would create a Ghidra overlay).
    text_rva = SECTION_ALIGNMENT
    image_base = int(text["virtual_address"], 16) - text_rva
    data_rva = int(data["virtual_address"], 16) - image_base
    text_raw = align(text["size"], FILE_ALIGNMENT)
    data_raw = align(data["size"], FILE_ALIGNMENT)
    text_offset = HEADERS_SIZE
    data_offset = text_offset + text_raw
    size_of_image = align(data_rva + data["size"], SECTION_ALIGNMENT)

    dos = bytearray(PE_OFFSET)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, PE_OFFSET)
    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 0xF0, 0x0022)

    optional = bytearray(0xF0)
    struct.pack_into("<H", optional, 0, 0x20B)  # PE32+
    struct.pack_into("<I", optional, 4, text_raw)
    struct.pack_into("<I", optional, 8, data_raw)
    struct.pack_into("<I", optional, 16, text_rva)
    struct.pack_into("<I", optional, 20, text_rva)
    struct.pack_into("<Q", optional, 24, image_base)
    struct.pack_into("<II", optional, 32, SECTION_ALIGNMENT, FILE_ALIGNMENT)
    struct.pack_into("<HHHHHH", optional, 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<I", optional, 52, 0)
    struct.pack_into("<II", optional, 56, size_of_image, HEADERS_SIZE)
    struct.pack_into("<I", optional, 64, 0)
    struct.pack_into("<HH", optional, 68, 1, 0)  # IMAGE_SUBSYSTEM_NATIVE
    struct.pack_into("<QQQQ", optional, 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<II", optional, 104, 0, 16)

    sections_header = (
        section_header(b".text", text["size"], text_rva, text_raw,
                       text_offset, 0x60000020)
        + section_header(b".data", data["size"], data_rva, data_raw,
                         data_offset, 0xC0000040)
    )
    headers = bytes(dos) + b"PE\0\0" + coff + bytes(optional) + sections_header
    if len(headers) > HEADERS_SIZE:
        raise ValueError("PE headers exceed configured raw-data start")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with SOURCE.open("rb") as src, OUTPUT.open("wb") as dst:
        dst.write(headers)
        dst.write(bytes(HEADERS_SIZE - len(headers)))
        copy_region(src, dst, text["size"], text["source_sha256"], "kernel_text")
        dst.write(bytes(text_raw - text["size"]))
        src.seek(data["file_offset"])
        copy_region(src, dst, data["size"], data["source_sha256"], "kernel_data")
        dst.write(bytes(data_raw - data["size"]))

    expected_size = data_offset + data_raw
    if OUTPUT.stat().st_size != expected_size:
        raise ValueError("generated PE size does not match mapped sections")
    print(f"PE analysis carrier: {OUTPUT}")
    print(f"Carrier SHA-256: {hashlib.sha256(OUTPUT.read_bytes()).hexdigest()}")
    print(f"Input RAM image SHA-256: {metadata['sha256']}")
    print(f"Image base: 0x{image_base:x}; .text RVA=0x{text_rva:x}; .data RVA=0x{data_rva:x}")
    print(f"Text: {text['size']} bytes; data: {data['size']} bytes")
    print(f"Zero-filled unmapped data pages preserved: {metadata['unmapped_data_pages']}")


if __name__ == "__main__":
    main()
