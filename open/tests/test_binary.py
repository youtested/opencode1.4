from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

from opencode_py.tools import binary

ARM64_TEXT_ADDR = 0x400000

ARM64_TEXT = (
    struct.pack("<I", 0xA9BF7BFD)  # stp x29, x30, [sp, #-0x10]!
    + struct.pack("<I", 0xD10043FF)  # sub sp, sp, #0x10
    + struct.pack("<I", 0xD503201F)  # nop
    + struct.pack("<I", 0xD65F03C0)  # ret
    + struct.pack("<I", 0xD503233F)  # paciasp
    + struct.pack("<I", 0x910003FD)  # mov x29, sp
    + b"MARKER"
    + b"\x00" * 24
)


def _build_elf(path: Path) -> Path:
    text_off = 0x100
    text_size = len(ARM64_TEXT)
    strtab = b"\x00alpha\x00beta\x00"
    shstrtab = b"\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00"
    symtab = (
        b"\x00" * 24
        + struct.pack("<IBBHQQ", 1, 0x12, 0, 1, ARM64_TEXT_ADDR, 0x10)
        + struct.pack("<IBBHQQ", 7, 0x12, 0, 1, ARM64_TEXT_ADDR + 0x10, 0x10)
    )
    strtab_off = text_off + text_size
    symtab_off = strtab_off + len(strtab)
    shstrtab_off = symtab_off + len(symtab)
    shoff = (shstrtab_off + len(shstrtab) + 7) & ~7
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
        2,
        183,
        1,
        ARM64_TEXT_ADDR,
        0,
        shoff,
        0,
        64,
        56,
        0,
        64,
        5,
        4,
    )
    sections = [b"\x00" * 64]
    sections.append(
        struct.pack("<IIQQQQIIQQ", 1, 1, 0x6, ARM64_TEXT_ADDR, text_off, text_size, 0, 0, 4, 0)
    )
    sections.append(
        struct.pack("<IIQQQQIIQQ", 7, 2, 0, 0, symtab_off, len(symtab), 3, 1, 8, 24)
    )
    sections.append(struct.pack("<IIQQQQIIQQ", 15, 3, 0, 0, strtab_off, len(strtab), 0, 0, 1, 0))
    sections.append(struct.pack("<IIQQQQIIQQ", 23, 3, 0, 0, shstrtab_off, len(shstrtab), 0, 0, 1, 0))
    blob = bytearray(header)
    blob.extend(b"\x00" * (text_off - len(blob)))
    blob.extend(ARM64_TEXT)
    blob.extend(strtab)
    blob.extend(symtab)
    blob.extend(shstrtab)
    blob.extend(b"\x00" * (shoff - len(blob)))
    for section in sections:
        blob.extend(section)
    path.write_bytes(bytes(blob))
    return path



ALPHABET = "".join(chr(c) for c in range(0x20, 0x7F))
KERNEL_BASE = 0xFFFFFFC010080000


def _build_kallsyms(symbols: list[tuple[str, int]], base: int = KERNEL_BASE, pad: int = 0x1000) -> bytes:
    """Synthesise the kernel's kallsyms layout: offsets, num, names, markers, tokens, index."""
    tokens = [""] + list(ALPHABET)
    tokens += [""] * (256 - len(tokens))
    table = b""
    index = []
    for token in tokens:
        index.append(len(table))
        table += token.encode() + b"\x00"
    encode = {ALPHABET[i]: i + 1 for i in range(len(ALPHABET))}
    names = b""
    markers = []
    for i, (name, _addr) in enumerate(symbols):
        if i % 256 == 0:
            markers.append(len(names))
        encoded = bytes(encode[ch] for ch in name)
        names += bytes([len(encoded)]) + encoded
    offsets = b"".join(struct.pack("<i", addr - base) for _n, addr in symbols)
    blob = b"\x00" * pad + offsets + struct.pack("<I", len(symbols)) + names
    blob += b"".join(struct.pack("<I", mark) for mark in markers)
    blob += table + struct.pack("<256H", *index)
    return blob


@pytest.fixture()
def elf_file(tmp_path: Path) -> Path:
    return _build_elf(tmp_path / "sample.elf")


@pytest.fixture()
def raw_file(tmp_path: Path) -> Path:
    data = b"hello world\x00" + bytes(range(256)) + b"needle-in-a-haystack" + b"\x00" * 32
    path = tmp_path / "raw.bin"
    path.write_bytes(data)
    return path


def _run(action: str, path: Path, **extra) -> dict:
    result = binary.run({"action": action, "path": str(path), **extra})
    assert isinstance(result, dict)
    assert "output" in result
    return result


def test_info_reads_a_real_elf(elf_file: Path) -> None:
    out = _run("info", elf_file)["output"]
    assert "format: ELF" in out
    assert "aarch64" in out
    assert "64-bit" in out
    assert "0x400000" in out


def test_sections_and_symbols(elf_file: Path) -> None:
    sections = _run("sections", elf_file)["output"]
    assert ".text" in sections
    assert ".symtab" in sections
    symbols = _run("symbols", elf_file, filter="alpha")["output"]
    assert "alpha" in symbols
    assert "0x0000000000400000" in symbols


def test_resolve_both_directions(elf_file: Path) -> None:
    by_name = _run("resolve", elf_file, name="beta")["output"]
    assert "0x400010 (4194320)" in by_name
    by_addr = _run("resolve", elf_file, address="0x400018")["output"]
    assert "beta" in by_addr
    assert "+0x8" in by_addr


def test_disasm_fallback_decodes_arm64(elf_file: Path) -> None:
    out = _run("disasm", elf_file, symbol="alpha", count=4)["output"]
    assert "stp x29, x30" in out
    assert "ret" in out


def test_functions_finds_prologues(elf_file: Path) -> None:
    out = _run("functions", elf_file)["output"]
    assert "prologue candidate" in out
    assert "0x0000000000400000" in out


def test_kallsyms_absent_is_a_message_not_a_crash(raw_file: Path) -> None:
    result = _run("kallsyms", raw_file)
    assert "not found" in result["output"]
    assert not result.get("error")


def test_hex_dump(raw_file: Path) -> None:
    out = _run("hex", raw_file, offset=0, length=16)["output"]
    assert "68 65 6c 6c 6f" in out
    assert "hello" in out


def test_search_hex_and_text(raw_file: Path) -> None:
    text_hit = _run("search", raw_file, pattern="needle", limit=5)["output"]
    assert "file 0x10c" in text_hit
    hex_hit = _run("search", raw_file, pattern="00 01 02 03", limit=5)["output"]
    assert "file 0xc" in hex_hit


def test_strings_with_filter(raw_file: Path) -> None:
    out = _run("strings", raw_file, filter="needle")["output"]
    assert "needle-in-a-haystack" in out


def test_entropy_separates_random_from_text(raw_file: Path) -> None:
    out = _run("entropy", raw_file, block=512, threshold=7.0)["output"]
    assert "overall:" in out


def test_dump_carves_a_slice(raw_file: Path, tmp_path: Path) -> None:
    result = _run("dump", raw_file, offset=0x10C, length=4, out="slice.bin")
    assert "wrote 4 bytes" in result["output"]
    assert (tmp_path / "slice.bin").read_bytes() == b"need"


def test_patch_previews_then_writes_with_backup(raw_file: Path) -> None:
    preview = _run("patch", raw_file, offset=0, bytes="41 41", confirm=False)["output"]
    assert "preview only" in preview
    assert raw_file.read_bytes().startswith(b"hello")
    written = _run("patch", raw_file, offset=0, bytes="41 41", confirm=True)["output"]
    assert "written" in written
    assert raw_file.read_bytes().startswith(b"AAllo")
    assert raw_file.with_suffix(".bin.bak").exists()


def test_diff_reports_changed_blocks(raw_file: Path, tmp_path: Path) -> None:
    other = tmp_path / "other.bin"
    data = bytearray(raw_file.read_bytes())
    data[0:4] = b"JELL"
    other.write_bytes(bytes(data))
    out = _run("diff", raw_file, path2=str(other))["output"]
    assert "changed blocks: 1" in out


def test_garbage_input_never_raises(tmp_path: Path) -> None:
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"\x7fELF" + bytes(range(200)))
    for action in ("info", "sections", "symbols", "kallsyms", "functions", "gadgets", "xrefs"):
        result = binary.run({"action": action, "path": str(junk)})
        assert "output" in result


def test_missing_file_and_unknown_action(tmp_path: Path) -> None:
    missing = binary.run({"action": "info", "path": str(tmp_path / "nope")})
    assert missing.get("error") is True
    unknown = binary.run({"action": "explode", "path": str(tmp_path)})
    assert unknown.get("error") is True
    assert "unknown action" in unknown["output"]


def test_registry_exposes_the_tool() -> None:
    from opencode_py.config import Config
    from opencode_py.tools import TOOL_NAMES, build_registry

    assert "binary" in TOOL_NAMES
    registry = build_registry(Config())
    assert "binary" in registry.names()
    tool = registry.get("binary")
    assert tool is not None
    assert "binary" == tool.name
    assert tool.parameters["properties"]["action"]["enum"]


def test_real_binary_smoke() -> None:
    target = Path(sys.executable)
    header = target.read_bytes()[:4] if target.exists() else b""
    if header != b"\x7fELF":
        pytest.skip("interpreter is not an ELF binary on this platform")
    result = _run("info", target)
    assert "format: ELF" in result["output"]

def test_kallsyms_raw_image_recovers_names_and_addresses(tmp_path: Path) -> None:
    symbols = [
        ("T startup", KERNEL_BASE),
        ("T _text", KERNEL_BASE),
        ("t commit_creds", KERNEL_BASE + 0x21234),
        ("t prepare_kernel_cred", KERNEL_BASE + 0x21A00),
        ("d init_task", KERNEL_BASE + 0x970000),
    ]
    image = tmp_path / "Image"
    image.write_bytes(_build_kallsyms(symbols))
    out = _run("kallsyms", image, base=hex(KERNEL_BASE), limit=10)["output"]
    assert "5 symbols" in out
    assert "0xffffffc010080000  T startup" in out
    assert "0xffffffc0100a1234  t commit_creds" in out
    assert "0xffffffc0109f0000  d init_task" in out


def test_kallsyms_relative_mode_and_filter(tmp_path: Path) -> None:
    symbols = [(f"t func_{i}", KERNEL_BASE + i * 8) for i in range(600)]
    image = tmp_path / "Image.gz"
    image.write_bytes(_build_kallsyms(symbols))
    plain = _run("kallsyms", image, limit=2)["output"]
    assert "600 symbols" in plain
    assert "base: unknown" in plain
    filtered = _run("kallsyms", image, base=hex(KERNEL_BASE), filter="func_599", limit=5)["output"]
    assert "func_599" in filtered


def test_kallsyms_on_random_bytes_is_a_clean_message(tmp_path: Path) -> None:
    junk = tmp_path / "noise.bin"
    junk.write_bytes(bytes((i * 37 + 11) % 256 for i in range(200_000)))
    result = _run("kallsyms", junk)
    assert "not found" in result["output"]
