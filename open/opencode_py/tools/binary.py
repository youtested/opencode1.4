"""binary tool: inspect, disassemble and patch binaries (ELF, kernel images).

Sixteen actions in one lazily imported module. Stdlib only, except an optional
capstone import for real disassembly. Every action degrades to a clear message
instead of raising, and nothing here routes through tools/read.py, which refuses
binary files on purpose.
"""

from __future__ import annotations

import hashlib
import math
import mmap
import os
import re
import shutil
import struct
import sys
from array import array
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from ..util.log import swallow
from .registry import Tool, schema_with

ACTIONS = (
    "info",
    "hex",
    "search",
    "strings",
    "sections",
    "symbols",
    "resolve",
    "entropy",
    "dump",
    "disasm",
    "xrefs",
    "functions",
    "kallsyms",
    "diff",
    "gadgets",
    "patch",
)

MAX_OUTPUT = 24_000
MAX_LIST = 200
MAX_HEX = 4096
MAX_DUMP = 64 * 1024 * 1024
SCAN_LIMIT = 64 * 1024 * 1024

EM_NAMES = {
    2: "sparc",
    3: "x86",
    8: "mips",
    20: "ppc",
    21: "ppc64",
    22: "s390",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
}

SHN_UNDEF = 0
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_NOBITS = 8
SHT_DYNSYM = 11
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
PF_X = 0x1

STT_NAMES = {0: "?", 1: "d", 2: "t", 3: "s", 4: "f", 5: "i", 6: "o", 10: "p"}


def _fail(message: str) -> dict:
    return {"output": message, "error": True}


def _clip(text: str, limit: int) -> str:
    if limit <= 0:
        limit = MAX_OUTPUT
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... truncated at {limit} chars (narrow with offset=/limit=)"


def _int(value, default: int = 0) -> int:
    if value is None or value == "":
        return default
    if isinstance(value, int):
        return value
    text = str(value).strip().lower().replace("_", "")
    try:
        if text.startswith("0x"):
            return int(text, 16)
        return int(text, 0)
    except ValueError:
        return default


def _addr(value: int) -> str:
    if value >= 1 << 32:
        return f"0x{value:x}"
    return f"0x{value:x} ({value})"



class _Blob:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.fh = open(self.path, "rb")
        self.size = os.fstat(self.fh.fileno()).st_size
        self.data = b""
        if self.size:
            self.data = mmap.mmap(self.fh.fileno(), 0, access=mmap.ACCESS_READ)

    def read(self, off: int, length: int) -> bytes:
        off = max(0, min(off, self.size))
        return bytes(self.data[off : off + max(0, length)])

    def close(self) -> None:
        data, self.data = self.data, b""
        try:
            if isinstance(data, mmap.mmap):
                data.close()
        finally:
            self.fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _cstr(blob: _Blob, off: int, limit: int = 256) -> str:
    if off < 0 or off >= blob.size:
        return ""
    end = blob.data.find(b"\x00", off, min(blob.size, off + limit + 1))
    if end < 0:
        end = min(blob.size, off + limit)
    return bytes(blob.data[off:end]).decode("utf-8", "replace")


@dataclass
class _Section:
    index: int
    name: str
    sh_type: int
    flags: int
    addr: int
    off: int
    size: int
    link: int
    entsize: int

    @property
    def is_code(self) -> bool:
        return bool(self.flags & SHF_EXECINSTR)


@dataclass
class _Segment:
    kind: int
    flags: int
    off: int
    vaddr: int
    filesz: int
    memsz: int


@dataclass
class _Sym:
    name: str
    value: int
    size: int
    info: int
    shndx: int
    dynamic: bool = False

    @property
    def kind(self) -> str:
        letter = STT_NAMES.get(self.info & 0xF, "?")
        return letter.upper() if (self.info >> 4) in (1, 2) else letter

    @property
    def defined(self) -> bool:
        return self.shndx != SHN_UNDEF and self.value != 0


@dataclass
class _Elf:
    bits: int
    endian: str
    etype: int
    machine: int
    entry: int
    phoff: int
    shoff: int
    flags: int
    phentsize: int
    phnum: int
    shentsize: int
    shnum: int
    sections: list[_Section] = field(default_factory=list)
    segments: list[_Segment] = field(default_factory=list)
    _symbols: list[_Sym] | None = None

    @property
    def arch(self) -> str:
        return EM_NAMES.get(self.machine, f"machine{self.machine}")

    def code_sections(self) -> list[_Section]:
        found = [s for s in self.sections if s.is_code and s.size and s.sh_type != SHT_NOBITS]
        if found:
            return found
        return [s for s in self.sections if s.flags & SHF_ALLOC and s.sh_type != SHT_NOBITS]

    def section_for_offset(self, off: int) -> _Section | None:
        for section in self.sections:
            if section.sh_type == SHT_NOBITS or not section.size:
                continue
            if section.off <= off < section.off + section.size:
                return section
        return None

    def offset_for_addr(self, addr: int) -> int | None:
        for section in self.sections:
            if section.sh_type == SHT_NOBITS or not section.size:
                continue
            if section.addr and section.addr <= addr < section.addr + section.size:
                return section.off + (addr - section.addr)
        for seg in self.segments:
            if seg.filesz and seg.vaddr <= addr < seg.vaddr + seg.filesz:
                return seg.off + (addr - seg.vaddr)
        return None

    def addr_for_offset(self, off: int) -> int | None:
        section = self.section_for_offset(off)
        if section and section.addr:
            return section.addr + (off - section.off)
        return None


def _parse_elf(blob: _Blob) -> _Elf | None:
    try:
        return _parse_elf_inner(blob)
    except Exception as exc:  # malformed files must never raise upward
        swallow(exc, "tools/binary.py:_parse_elf")
        return None


def _parse_elf_inner(blob: _Blob) -> _Elf | None:
    if blob.size < 52 or blob.read(0, 4) != b"\x7fELF":
        return None
    ident = blob.read(0, 16)
    cls, enc = ident[4], ident[5]
    if cls not in (1, 2) or enc not in (1, 2):
        return None
    endian = "<" if enc == 1 else ">"
    bits = 64 if cls == 2 else 32
    if bits == 64:
        hdr = struct.unpack_from(endian + "HHIQQQIHHHHHH", blob.data, 16)
    else:
        hdr = struct.unpack_from(endian + "HHIIIIIHHHHHH", blob.data, 16)
    (
        etype,
        machine,
        _version,
        entry,
        phoff,
        shoff,
        flags,
        _ehsize,
        phentsize,
        phnum,
        shentsize,
        shnum,
        shstrndx,
    ) = hdr
    elf = _Elf(
        bits=bits,
        endian=endian,
        etype=etype,
        machine=machine,
        entry=entry,
        phoff=phoff,
        shoff=shoff,
        flags=flags,
        phentsize=phentsize,
        phnum=min(max(phnum, 0), 4096),
        shentsize=shentsize,
        shnum=min(max(shnum, 0), 8192),
    )
    min_sh = 40 if bits == 32 else 64
    if elf.shentsize < min_sh or not shoff or not elf.shnum:
        return elf
    if shoff + elf.shentsize > blob.size:
        return elf
    raw = []
    for i in range(elf.shnum):
        pos = shoff + i * elf.shentsize
        if pos + min_sh > blob.size:
            break
        if bits == 64:
            f = struct.unpack_from(endian + "IIQQQQIIQQ", blob.data, pos)
        else:
            f = struct.unpack_from(endian + "IIIIIIIIII", blob.data, pos)
        raw.append(f)
    strtab_off = 0
    if 0 <= shstrndx < len(raw):
        strtab_off = raw[shstrndx][4]
    for i, f in enumerate(raw):
        if bits == 64:
            name_off, stype, sflags, saddr, soff, ssize, link, _info, _align, entsize = f
        else:
            name_off, stype, sflags, saddr, soff, ssize, link, _info, _align, entsize = f
        name = _cstr(blob, strtab_off + name_off) if strtab_off else ""
        elf.sections.append(
            _Section(
                index=i,
                name=name,
                sh_type=stype,
                flags=sflags,
                addr=saddr,
                off=soff,
                size=ssize,
                link=link,
                entsize=entsize,
            )
        )
    min_ph = 32 if bits == 32 else 56
    if elf.phnum and elf.phentsize >= min_ph and phoff and phoff + min_ph <= blob.size:
        for i in range(elf.phnum):
            pos = phoff + i * elf.phentsize
            if pos + min_ph > blob.size:
                break
            if bits == 64:
                p_type, p_flags, p_off, p_vaddr, _paddr, p_filesz, p_memsz, _align = struct.unpack_from(
                    endian + "IIQQQQQQ", blob.data, pos
                )
            else:
                p_type, p_off, p_vaddr, _paddr, p_filesz, p_memsz, p_flags, _align = struct.unpack_from(
                    endian + "IIIIIIII", blob.data, pos
                )
            elf.segments.append(
                _Segment(kind=p_type, flags=p_flags, off=p_off, vaddr=p_vaddr, filesz=p_filesz, memsz=p_memsz)
            )
    return elf


def _elf_symbols(blob: _Blob, elf: _Elf) -> list[_Sym]:
    if elf._symbols is not None:
        return elf._symbols
    out: list[_Sym] = []
    for section in elf.sections:
        if section.sh_type not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if not (0 <= section.link < len(elf.sections)):
            continue
        strtab = elf.sections[section.link]
        entsize = section.entsize or (24 if elf.bits == 64 else 16)
        if entsize <= 0 or not section.size:
            continue
        count = min(section.size // entsize, 400_000)
        for i in range(count):
            pos = section.off + i * entsize
            if pos + entsize > blob.size:
                break
            if elf.bits == 64:
                name_off, info, _other, shndx, value, size = struct.unpack_from(
                    elf.endian + "IBBHQQ", blob.data, pos
                )
            else:
                name_off, value, size, info, _other, shndx = struct.unpack_from(
                    elf.endian + "IIIBBH", blob.data, pos
                )
            if name_off < strtab.size:
                name = _cstr(blob, strtab.off + name_off, 512)
            else:
                name = ""
            out.append(
                _Sym(
                    name=name,
                    value=value,
                    size=size,
                    info=info,
                    shndx=shndx,
                    dynamic=section.sh_type == SHT_DYNSYM,
                )
            )
    elf._symbols = out
    return out


def _container_kind(blob: _Blob) -> str:
    head = blob.read(0, 16)
    if head[:4] == b"\x7fELF":
        return "ELF"
    if head[:2] == b"\x1f\x8b":
        return "gzip (decompress first: gunzip)"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz (decompress first: unxz)"
    if head[:4] == b"\x28\xb5\x2f\xfd":
        return "zstd (decompress first: zstd -d)"
    if head[:2] == b"BZ":
        return "bzip2 (decompress first: bunzip2)"
    if head[:4] == b"PK\x03\x04":
        return "zip/apk (unzip to reach the .so files)"
    if head[:8] == b"dex\n":
        return "Android DEX (no DEX parser here; strings/hex only)"
    if head[:4] == b"\xd0\x0d\xfe\xed":
        return "device tree blob (DTB)"
    if head[:8] == b"ANDROID!":
        return "Android boot image (info/carve only, no unpack)"
    if head[:4] == b"\x3a\xff\x26\xed":
        return "Android sparse image"
    if head[:2] == b"MZ":
        return "Windows PE (unsupported)"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "Mach-O (unsupported)"
    if len(head) >= 60 and head[0x38:0x3C] == b"ARM\x64":
        return "raw ARM64 kernel Image (kallsyms can still work)"
    return "unknown/raw bytes"


def _strip_note(blob: _Blob, elf: _Elf) -> list[str]:
    notes = []
    syms = [s for s in _elf_symbols(blob, elf)]
    named = [s for s in syms if s.defined and s.name]
    if not named:
        notes.append("stripped: yes (no defined symbols; use functions= and xrefs=)")
    if any(s.dynamic for s in syms):
        notes.append("dynamic linking: yes (dynsym present)")
    if elf.sections and all(not s.name for s in elf.sections):
        notes.append("section names: missing (section header string table absent)")
    head = blob.read(0, 1024 * 1024)
    if b"UPX!" in head or any(s.name.startswith("UPX") for s in elf.sections):
        notes.append("packed: UPX markers found (entropy will confirm; no unpacker here)")
    return notes


def _action_info(blob: _Blob, elf: _Elf | None, args: dict) -> str:
    lines = [f"file: {blob.path}", f"size: {blob.size} bytes ({blob.size / 1024:.1f} KiB)"]
    kind = _container_kind(blob)
    lines.append(f"format: {kind}")
    if elf is None:
        head = blob.read(0, 16).hex(" ")
        lines.append(f"first bytes: {head}")
        if kind.startswith("raw ARM64"):
            lines.append("note: run kallsyms to recover the symbol table from this image")
        return "\n".join(lines)
    etypes = {0: "none", 1: "relocatable", 2: "executable", 3: "shared object", 4: "core"}
    etype = etypes.get(elf.etype, f"type{elf.etype}")
    lines.append(f"elf: {elf.bits}-bit {'little' if elf.endian == '<' else 'big'}-endian, {etype}")
    lines.append(f"arch: {elf.arch} (machine={elf.machine})")
    lines.append(f"entry: {_addr(elf.entry)}")
    lines.append(f"sections: {len(elf.sections)}   segments: {len(elf.segments)}")
    syms = _elf_symbols(blob, elf)
    static = sum(1 for s in syms if not s.dynamic)
    dynamic = sum(1 for s in syms if s.dynamic)
    lines.append(f"symbols: {static} static + {dynamic} dynamic")
    for note in _strip_note(blob, elf):
        lines.append(f"note: {note}")
    return "\n".join(lines)


def _action_hex(blob: _Blob, elf: _Elf | None, args: dict) -> str:
    off = _int(args.get("offset"), 0)
    length = min(max(_int(args.get("length"), 256), 1), MAX_HEX)
    off = max(0, min(off, max(0, blob.size - 1)))
    data = blob.read(off, length)
    if not data:
        return f"no bytes at 0x{off:x} (file size {blob.size})"
    out = [f"hex {off:#x}..{off + len(data) - 1:#x} ({len(data)} bytes)"]
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{off + i:08x}  {hex_part:<47}  {text}")
    return "\n".join(out)


def _parse_pattern(args: dict) -> bytes | None:
    raw = args.get("pattern")
    if raw is None or raw == "":
        return None
    text = str(raw)
    mode = str(args.get("mode") or "auto").lower()
    if mode == "text":
        return text.encode("utf-8", "replace")
    cleaned = re.sub(r"[\s,_:]", "", text)
    spaced_hex = bool(re.fullmatch(r"\s*(0x)?[0-9a-fA-F]{1,2}(\s+(0x)?[0-9a-fA-F]{1,2})*\s*", text))
    looks_hex = (
        len(cleaned) >= 2
        and len(cleaned) % 2 == 0
        and re.fullmatch(r"[0-9a-fA-F]+", cleaned) is not None
        and re.search(r"[a-fA-F]", cleaned) is not None
    )
    if mode == "hex" or looks_hex or (spaced_hex and " " in text.strip()):
        try:
            return bytes.fromhex(cleaned)
        except ValueError as exc:
            swallow(exc, "tools/binary.py:_parse_pattern")
            pass
    return text.encode("utf-8", "replace")


def _action_search(blob: _Blob, elf: _Elf | None, args: dict) -> str:
    needle = _parse_pattern(args)
    if not needle:
        return "search needs a pattern (text, or hex like 'de ad be ef')"
    limit = min(max(_int(args.get("limit"), 50), 1), MAX_LIST)
    ignore_case = bool(args.get("ignore_case"))
    haystack = blob.data
    if ignore_case and needle.isascii():
        haystack_search = bytes(blob.read(0, blob.size)).lower()
        needle_search = needle.lower()
    else:
        haystack_search = haystack
        needle_search = needle
    hits: list[int] = []
    pos = 0
    while len(hits) < limit:
        pos = haystack_search.find(needle_search, pos)
        if pos < 0:
            break
        hits.append(pos)
        pos += 1
    if not hits:
        return f"pattern {needle[:32]!r} not found in {blob.path.name}"
    out = [f"search {needle[:32]!r}: {len(hits)} hit(s){' (capped)' if len(hits) >= limit else ''}"]
    for hit in hits:
        where = ""
        if elf is not None:
            section = elf.section_for_offset(hit)
            if section is not None:
                where = f"  in {section.name or f'section{section.index}'}"
                addr = elf.addr_for_offset(hit)
                if addr:
                    where += f" @ {_addr(addr)}"
        out.append(f"  file 0x{hit:x} ({hit}){where}")
    return "\n".join(out)


def _action_strings(blob: _Blob, elf: _Elf | None, args: dict) -> str:
    min_len = min(max(_int(args.get("min_length"), 4), 2), 64)
    limit = min(max(_int(args.get("limit"), 80), 1), MAX_LIST)
    pattern = None
    if args.get("filter"):
        try:
            pattern = re.compile(str(args["filter"]), re.IGNORECASE)
        except re.error:
            pattern = re.compile(re.escape(str(args["filter"])), re.IGNORECASE)
    rx = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    out = [f"strings (min {min_len})"]
    seen = 0
    for match in rx.finditer(blob.data):
        text = match.group().decode("ascii", "replace")
        if pattern is not None and not pattern.search(text):
            continue
        seen += 1
        if seen > limit:
            out.append("  ... more matches (raise limit= or add filter=)")
            break
        out.append(f"  0x{match.start():x}  {text[:160]}")
    if seen == 0:
        out.append("  (none)")
    return "\n".join(out)


def _action_sections(blob: _Blob, elf: _Elf | None, args: dict) -> str:
    if elf is None:
        return "not an ELF file; sections needs ELF headers"
    out = [f"#  {'name':<22} {'type':<12} {'addr':>18} {'offset':>10} {'size':>10}  flags"]
    type_names = {
        0: "NULL",
        1: "PROGBITS",
        2: "SYMTAB",
        3: "STRTAB",
        4: "RELA",
        5: "HASH",
        6: "DYNAMIC",
        7: "NOTE",
        8: "NOBITS",
        9: "REL",
        11: "DYNSYM",
        14: "INIT_ARRAY",
        15: "FINI_ARRAY",
        16: "PREINIT_ARRAY",
    }
    for section in elf.sections:
        flags = "".join(
            [
                "W" if section.flags & SHF_WRITE else "-",
                "A" if section.flags & SHF_ALLOC else "-",
                "X" if section.flags & SHF_EXECINSTR else "-",
            ]
        )
        kind = type_names.get(section.sh_type, str(section.sh_type))
        addr = f"0x{section.addr:x}" if section.addr else "-"
        out.append(
            f"{section.index:<3}{section.name[:22]:<22}{kind:<12}{addr:>18}"
            f"{section.off:>10}{section.size:>10}  {flags}"
        )
    return "\n".join(out)


def _action_symbols(blob: _Blob, elf: _Elf | None, args: dict) -> str:
    if elf is None:
        return "not an ELF file; symbols needs an ELF symbol table"
    limit = min(max(_int(args.get("limit"), 80), 1), 5000)
    match = str(args.get("filter") or "")
    rx = None
    if match:
        try:
            rx = re.compile(match)
        except re.error:
            rx = re.compile(re.escape(match))
    syms = [s for s in _elf_symbols(blob, elf) if s.name and s.defined]
    syms.sort(key=lambda s: (s.value, s.name))
    if rx is not None:
        syms = [s for s in syms if rx.search(s.name)]
    if not syms:
        return f"no defined symbols{' matching ' + match if match else ''} (stripped? try functions=)"
    out = [f"symbols: {len(syms)} shown{' (filtered)' if match else ''}"]
    for sym in syms[:limit]:
        size = f"  size {sym.size}" if sym.size else ""
        out.append(f"  {sym.value:#018x}  {sym.kind}  {sym.name}{size}")
    if len(syms) > limit:
        out.append(f"  ... {len(syms) - limit} more (raise limit= or filter=)")
    return "\n".join(out)


def _action_resolve(blob: _Blob, elf: _Elf | None, args: dict) -> str:
    if elf is None:
        return "not an ELF file; resolve needs ELF headers"
    syms = [s for s in _elf_symbols(blob, elf) if s.name and s.defined]
    name = str(args.get("name") or "").strip()
    address = args.get("address")
    if name:
        exact = [s for s in syms if s.name == name]
        found = exact or [s for s in syms if name.lower() in s.name.lower()]
        if not found:
            return f"no symbol matching {name!r}"
        out = [f"resolve {name!r}: {len(found)} match(es)"]
        for sym in sorted(found, key=lambda s: s.value)[:20]:
            out.append(f"  {_addr(sym.value)}  {sym.kind}  {sym.name}  size {sym.size}  shndx {sym.shndx}")
            off = elf.offset_for_addr(sym.value)
            if off is not None:
                out.append(f"    file offset: {_addr(off)}")
        return "\n".join(out)
    if address is None:
        return "resolve needs name= or address="
    target = _int(address, -1)
    if target < 0:
        return f"unreadable address: {address!r}"
    best = None
    for sym in syms:
        if sym.value <= target and (best is None or sym.value > best.value):
            best = sym
    out = [f"address {_addr(target)}"]
    target_off = elf.offset_for_addr(target)
    section = elf.section_for_offset(target_off) if target_off is not None else None
    if section is not None:
        out.append(f"section: {section.name or f'section{section.index}'} +0x{target - section.addr:x}")
    if best is not None:
        out.append(f"nearest symbol: {best.name} ({best.kind}) at {_addr(best.value)}")
        out.append(f"delta from symbol: +0x{target - best.value:x} ({target - best.value})")
    else:
        out.append("nearest symbol: none (no defined symbols at or below this address)")
    off = elf.offset_for_addr(target)
    if off is not None:
        out.append(f"file offset: {_addr(off)}")
        out.append(f"bytes: {blob.read(off, 16).hex(' ')}")
    return "\n".join(out)


_NUMPY: object = "unset"


def _numpy():
    """Optional numpy, imported once. None when it is not installed."""
    global _NUMPY
    if _NUMPY == "unset":
        try:
            import numpy as module

            _NUMPY = module
        except Exception as exc:
            swallow(exc, "tools/binary.py:_numpy")
            _NUMPY = None
    return _NUMPY


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    np = _numpy()
    if np is not None:
        try:
            counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
            probs = counts[counts > 0] / total
            return float(-(probs * np.log2(probs)).sum())
        except Exception as exc:
            swallow(exc, "tools/binary.py:_entropy")
    return -sum((count / total) * math.log2(count / total) for count in Counter(data).values())


def _action_entropy(blob: _Blob, elf: _Elf | None, args: dict) -> str:
    block = min(max(_int(args.get("block"), 4096), 512), 65536)
    threshold = float(args.get("threshold", 7.0))
    start = max(0, _int(args.get("offset"), 0))
    length = _int(args.get("length"), min(blob.size - start, SCAN_LIMIT))
    length = max(0, min(length, SCAN_LIMIT, blob.size - start))
    if length <= 0:
        return "nothing to scan"
    overall = _entropy(blob.read(start, length))
    out = [f"entropy over {start:#x}..{start + length:#x} (block {block})", f"overall: {overall:.2f} / 8.00"]
    runs: list[list[int]] = []
    pos = start
    while pos < start + length:
        chunk = blob.read(pos, min(block, start + length - pos))
        value = _entropy(chunk)
        if value >= threshold:
            if runs and runs[-1][1] == pos:
                runs[-1][1] = pos + len(chunk)
            else:
                runs.append([pos, pos + len(chunk)])
        pos += block
    if not runs:
        out.append(f"no region above {threshold:.2f} (looks like normal code or text)")
    else:
        out.append(f"{len(runs)} region(s) at or above {threshold:.2f} (likely compressed, encrypted or packed):")
        for begin, end in runs[:40]:
            out.append(f"  {begin:#x}..{end:#x}  {(end - begin) / 1024:.1f} KiB")
        if len(runs) > 40:
            out.append(f"  ... {len(runs) - 40} more")
    return "\n".join(out)


def _action_dump(blob: _Blob, elf: _Elf | None, args: dict) -> str:
    off = max(0, _int(args.get("offset"), 0))
    length = min(max(_int(args.get("length"), 4096), 1), MAX_DUMP)
    if off >= blob.size:
        return f"offset 0x{off:x} is past the end (size {blob.size})"
    if off + length > blob.size:
        length = blob.size - off
    target = args.get("out")
    if target:
        out_path = Path(str(target)).expanduser()
        if not out_path.is_absolute():
            out_path = blob.path.parent / out_path
    else:
        out_path = blob.path.with_name(f"{blob.path.stem}.{off:x}.bin")
    if out_path.exists() and not args.get("force"):
        return f"{out_path} already exists (pass force=true to overwrite)"
    data = blob.read(off, length)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(data)
    except OSError as _oc_exc:
        # `out` may point at a directory that does not exist yet.
        return f"could not write {out_path}: {_oc_exc}"
    digest = hashlib.sha256(data).hexdigest()[:16]
    return (
        f"wrote {len(data)} bytes from {off:#x} to {out_path}\n"
        f"sha256[:16]: {digest}\nnext: binary action=info path={out_path.name}"
    )


def _capstone():
    try:
        import capstone  # type: ignore

        return capstone
    except Exception:
        return None


def _cs_setup(elf: _Elf | None):
    capstone = _capstone()
    if capstone is None:
        return None
    try:
        if elf is None:
            return None
        machine = elf.machine
        if machine == 183:
            return capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        if machine == 40:
            mode = capstone.CS_MODE_ARM
            if elf.endian == ">":
                mode |= capstone.CS_MODE_BIG_ENDIAN
            return capstone.Cs(capstone.CS_ARCH_ARM, mode)
        if machine == 62:
            return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        if machine == 3:
            return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        if machine == 243:
            return capstone.Cs(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64)
    except Exception as exc:
        swallow(exc, "tools/binary.py:_cs_setup")
    return None


def _mini_arm64(word: int, pc: int) -> str:
    if word == 0xD65F03C0:
        return "ret"
    if word == 0xD503201F:
        return "nop"
    if word == 0xD503233F:
        return "paciasp"
    if word == 0xD50323BF:
        return "autiasp"
    if word == 0xD4000001:
        return "svc #0"
    if word & 0xFFFFFC1F == 0xD61F0000:
        return f"br x{word & 0x1F}"
    if word & 0xFFFFFC1F == 0xD63F0000:
        return f"blr x{(word >> 5) & 0x1F}"
    if word & 0xFC000000 == 0x14000000:
        imm = word & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        return f"b 0x{pc + (imm << 2):x}"
    if word & 0xFC000000 == 0x94000000:
        imm = word & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        return f"bl 0x{pc + (imm << 2):x}"
    if word & 0x9F000000 == 0x90000000:
        rd = word & 0x1F
        imm = ((word >> 5) & 0x7FFFF) << 2 | ((word >> 29) & 3)
        if imm & 0x100000:
            imm -= 0x200000
        return f"adrp x{rd}, 0x{(pc & ~0xFFF) + (imm << 12):x}"
    if word & 0xFF000010 == 0x54000000:
        cond = word & 0xF
        imm = (word >> 5) & 0x7FFFF
        if imm & 0x40000:
            imm -= 0x80000
        names = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]
        return f"b.{names[cond]} 0x{pc + (imm << 2):x}"
    if word & 0x7F000000 in (0x11000000, 0x51000000):
        rd, rn = word & 0x1F, (word >> 5) & 0x1F
        imm12 = (word >> 10) & 0xFFF
        shift = 12 if (word >> 22) & 1 else 0
        op = "add" if word & 0x7F000000 == 0x11000000 else "sub"
        if op == "sub" and rd == 31:
            return f"cmp x{rn}, #{imm12 << shift}"
        return f"{op} {'sp' if rd == 31 else f'x{rd}'}, {'sp' if rn == 31 else f'x{rn}'}, #{imm12 << shift}"
    if word & 0x7F800000 in (0x52800000, 0xD2800000):
        rd = word & 0x1F
        imm16 = (word >> 5) & 0xFFFF
        shift = ((word >> 21) & 3) * 16
        return f"movz x{rd}, #0x{imm16 << shift:x}"
    if word & 0x3B000000 == 0x39000000:
        size = (word >> 30) & 3
        load = (word >> 22) & 1
        rn, rt = (word >> 5) & 0x1F, word & 0x1F
        off = ((word >> 10) & 0xFFF) << size
        return f"{'ldr' if load else 'str'} {'x' if size == 3 else 'w'}{rt}, [x{rn}, #{off}]"
    if word & 0x3A000000 == 0x28000000:
        load = (word >> 22) & 1
        rn, rt, rt2 = (word >> 5) & 0x1F, word & 0x1F, (word >> 10) & 0x1F
        imm = (word >> 15) & 0x7F
        if imm & 0x40:
            imm -= 0x80
        return f"{'ldp' if load else 'stp'} x{rt}, x{rt2}, [x{rn}, #{imm * 8}]"
    return f".word 0x{word:08x}"


def _thumb_regs(mask: int, extra: str | None = None) -> str:
    regs = [f"r{i}" for i in range(8) if mask >> i & 1]
    if extra:
        regs.append(extra)
    return ", ".join(regs)


def _mini_thumb(h1: int, h2: int | None, pc: int) -> tuple[str, int]:
    """Decode one Thumb instruction. Returns (text, halfwords consumed)."""
    if h1 == 0x4770:
        return "bx lr", 1
    if h1 & 0xFF87 == 0x4700:
        return f"bx r{(h1 >> 3) & 0xF}", 1
    if h1 == 0xBF00:
        return "nop", 1
    if h1 & 0xFF00 == 0xDF00:
        return f"svc #{h1 & 0xFF}", 1
    if h1 & 0xFE00 == 0xB400:
        return f"push {{{_thumb_regs(h1 & 0xFF, 'lr' if h1 & 0x100 else None)}}}", 1
    if h1 & 0xFE00 == 0xBC00:
        return f"pop {{{_thumb_regs(h1 & 0xFF, 'pc' if h1 & 0x100 else None)}}}", 1
    if h1 & 0xFF80 in (0xB000, 0xB080):
        op = "add sp, #" if h1 & 0xFF80 == 0xB000 else "sub sp, #"
        return f"{op}0x{(h1 & 0x7F) << 2:x}", 1
    if h1 & 0xFF00 == 0x4600:
        rd = (h1 & 7) | ((h1 >> 4) & 8)
        rm = (h1 >> 3) & 0xF
        return f"mov {'r' if rd != 15 else 'pc'}{rd}, r{rm}", 1
    if h1 & 0xF800 in (0xA000, 0xA800):
        rd = (h1 >> 8) & 7
        imm = (h1 & 0xFF) << 2
        return f"add r{rd}, {'pc' if h1 & 0xF800 == 0xA000 else 'sp'}, #0x{imm:x}", 1
    if h1 & 0xF000 == 0x9000:
        load = (h1 >> 11) & 1
        return f"{'ldr' if load else 'str'} r{(h1 >> 8) & 7}, [sp, #0x{(h1 & 0xFF) << 2:x}]", 1
    if h1 & 0xF800 in (0x1800, 0x1A00):
        op = "adds" if h1 & 0xF800 == 0x1800 else "subs"
        return f"{op} r{h1 & 7}, r{(h1 >> 3) & 7}, r{(h1 >> 6) & 7}", 1
    if h1 & 0xF800 in (0x1C00, 0x1E00):
        op = "adds" if h1 & 0xF800 == 0x1C00 else "subs"
        return f"{op} r{h1 & 7}, r{(h1 >> 3) & 7}, #0x{(h1 >> 6) & 7:x}", 1
    if h1 & 0xF800 == 0x2000:
        return f"movs r{(h1 >> 8) & 7}, #0x{h1 & 0xFF:x}", 1
    if h1 & 0xF800 in (0x3000, 0x3800):
        op = "adds" if h1 & 0xF800 == 0x3000 else "subs"
        return f"{op} r{(h1 >> 8) & 7}, #0x{h1 & 0xFF:x}", 1
    if h1 & 0xF800 == 0x2800:
        return f"cmp r{(h1 >> 8) & 7}, #0x{h1 & 0xFF:x}", 1
    if h1 & 0xF000 == 0xD000:
        cond = (h1 >> 8) & 0xF
        imm = h1 & 0xFF
        if imm & 0x80:
            imm -= 0x100
        names = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]
        return f"b.{names[cond]} 0x{pc + 4 + (imm << 1):x}", 1
    if h1 & 0xF800 == 0xE000:
        imm = h1 & 0x7FF
        if imm & 0x400:
            imm -= 0x800
        return f"b 0x{pc + 4 + (imm << 1):x}", 1
    if h1 & 0xF800 == 0x4800:
        rt = (h1 >> 8) & 7
        imm = (h1 & 0xFF) << 2
        return f"ldr r{rt}, [pc, #{imm}] -> 0x{((pc + 4) & ~3) + imm:x}", 1
    if h1 & 0xE000 == 0x6000:
        load = (h1 >> 11) & 1
        rn, rt = (h1 >> 3) & 7, h1 & 7
        imm = ((h1 >> 6) & 0x1F) << 2
        return f"{'ldr' if load else 'str'} r{rt}, [r{rn}, #{imm}]", 1
    if h1 & 0xF800 == 0xF000 and h2 is not None:
        if h2 & 0xF800 == 0xF800:
            s_bit = (h1 >> 10) & 1
            j1 = (h2 >> 13) & 1
            j2 = (h2 >> 11) & 1
            i1 = 1 ^ (j1 ^ s_bit)
            i2 = 1 ^ (j2 ^ s_bit)
            imm = (s_bit << 24) | (i1 << 23) | (i2 << 22) | ((h1 & 0x3FF) << 12) | ((h2 & 0x7FF) << 1)
            if imm & 0x01000000:
                imm -= 0x02000000
            return f"bl 0x{pc + 4 + imm:x}", 2
    return f".hword 0x{h1:04x}", 1


def _mini_arm32(word: int, pc: int) -> str:
    if word == 0xE12FFF1E:
        return "bx lr"
    if word & 0x0FFFFFF0 == 0x012FFF10:
        return f"bx r{word & 0xF}"
    if word & 0x0FFFFFF0 == 0x012FFF30:
        return f"blx r{word & 0xF}"
    if word == 0xEF000000:
        return "svc #0"
    if word & 0x0FFF0000 == 0x092D0000:
        regs = [f"r{i}" for i in range(16) if word >> i & 1]
        return f"push {{{', '.join(regs)}}}"
    if word & 0x0FFF0000 == 0x08BD0000:
        regs = [f"r{i}" for i in range(16) if word >> i & 1]
        return f"pop {{{', '.join(regs)}}}"
    if word & 0x0F000000 in (0x0A000000, 0x0B000000):
        imm = word & 0x00FFFFFF
        if imm & 0x00800000:
            imm -= 0x01000000
        return f"{'bl' if word & 0x0F000000 == 0x0B000000 else 'b'} 0x{pc + 8 + (imm << 2):x}"
    if word & 0x0FE00000 == 0x03A00000:
        rd = (word >> 12) & 0xF
        imm = word & 0xFF
        rotate = ((word >> 8) & 0xF) * 2
        if rotate:
            imm = ((imm >> rotate) | (imm << (32 - rotate))) & 0xFFFFFFFF
        return f"mov {'r' if rd != 15 else 'pc'}{rd}, #0x{imm:x}"
    if word & 0x0FE00000 == 0x02800000 or word & 0x0FE00000 == 0x02400000:
        rd, rn = (word >> 12) & 0xF, (word >> 16) & 0xF
        imm = word & 0xFFF
        op = "add" if word & 0x0FE00000 == 0x02800000 else "sub"
        if rd == 15 and rn == 15 and word & 0x00400000:
            return f"{op} pc, pc, #0x{imm:x}"
        return f"{op} r{rd}, r{rn}, #0x{imm:x}"
    if word & 0x0FF00000 == 0x03500000:
        return f"cmp r{(word >> 16) & 0xF}, #0x{word & 0xFFF:x}"
    if word & 0x0C000000 == 0x04000000:
        load = (word >> 20) & 1
        rn, rd = (word >> 16) & 0xF, (word >> 12) & 0xF
        up = (word >> 23) & 1
        imm = word & 0xFFF
        target = (imm if up else -imm)
        if rn == 15:
            return f"{'ldr' if load else 'str'} r{rd}, [pc, #{target:+}] -> 0x{pc + 8 + target:x}"
        return f"{'ldr' if load else 'str'} r{rd}, [r{rn}, #{target:+}]"
    return f".word 0x{word:08x}"


def _resolve_start(blob: _Blob, elf: _Elf | None, args: dict) -> int:
    if args.get("symbol"):
        name = str(args["symbol"])
        if elf is None:
            return -1
        exact = [s for s in _elf_symbols(blob, elf) if s.name == name and s.defined]
        if not exact:
            exact = [s for s in _elf_symbols(blob, elf) if name.lower() in s.name.lower() and s.defined]
        if not exact:
            return -1
        return exact[0].value
    if args.get("address") not in (None, ""):
        return _int(args.get("address"), -1)
    return _int(args.get("offset"), -1)


def _action_disasm(blob: _Blob, elf: _Elf | None, args: dict) -> str:
    count = min(max(_int(args.get("count"), 40), 1), 600)
    start = _resolve_start(blob, elf, args)
    if start < 0:
        return "disasm needs address=, symbol= or offset="
    off = start
    addr = start
    if args.get("symbol"):
        off = elf.offset_for_addr(start) if elf else None
        if off is None:
            return f"cannot map {args.get('symbol')} to a file offset"
        addr = start
    elif elf is not None and args.get("address") not in (None, ""):
        off = elf.offset_for_addr(start)
        if off is None:
            return f"address {start:#x} is not inside any file-backed section"
    cs = _cs_setup(elf)
    if cs is not None:
        try:
            code = blob.read(off, 4 * count + 64)
            lines = [f"disasm {addr:#x}.. ({count} instructions, capstone)"]
            shown = 0
            for insn in cs.disasm(code, addr):
                lines.append(f"  {insn.address:#010x}  {insn.bytes.hex():<16}  {insn.mnemonic:<8} {insn.op_str}")
                shown += 1
                if shown >= count:
                    break
            if not shown:
                lines.append("  (capstone decoded nothing here)")
            return "\n".join(lines)
        except Exception as exc:
            swallow(exc, "tools/binary.py:disasm")
    if elf is not None and elf.machine not in (183, 40):
        return (
            "capstone is not installed, and the built-in fallback decoder only knows ARM.\n"
            "install it with: pip install capstone"
        )
    arm32 = elf is not None and elf.machine == 40
    thumb = bool(arm32 and addr & 1)
    if thumb:
        addr &= ~1
        off = addr if elf is None else (elf.offset_for_addr(addr) or (off & ~1))
    decode = _mini_arm32 if arm32 else _mini_arm64
    label = "Thumb" if thumb else ("ARM32" if arm32 else "ARM64")
    lines = [f"disasm {addr:#x}.. ({count} instructions, built-in {label} decoder)"]
    if thumb:
        pos = off
        done = 0
        while done < count and pos + 2 <= blob.size:
            h1 = struct.unpack_from("<H", blob.data, pos)[0]
            h2 = struct.unpack_from("<H", blob.data, pos + 2)[0] if pos + 4 <= blob.size else None
            text, used = _mini_thumb(h1, h2 if h1 & 0xF800 == 0xF000 else None, addr + (pos - off))
            raw = f"{h1:04x}" + (f" {h2:04x}" if used == 2 and h2 is not None else "")
            lines.append(f"  {addr + (pos - off):#010x}  {raw:<9}  {text}")
            pos += used * 2
            done += 1
        lines.append("note: built-in decoder covers common Thumb instructions; pip install capstone for full output")
        return "\n".join(lines)
    for i in range(count):
        pos = off + i * 4
        if pos + 4 > blob.size:
            break
        word = struct.unpack_from("<I", blob.data, pos)[0]
        text = decode(word, addr + i * 4)
        lines.append(f"  {addr + i * 4:#010x}  {word:08x}  {text}")
    lines.append("note: built-in decoder covers common instructions only; pip install capstone for full output")
    return "\n".join(lines)


def _find_offsets(data: bytes, needle: bytes, step: int = 1):
    """Offsets of needle whose start is aligned to `step` (C-speed scanning)."""
    pos = data.find(needle)
    while pos >= 0:
        if pos % step == 0:
            yield pos
        pos = data.find(needle, pos + 1)


def _action_functions(blob: _Blob, elf: _Elf | None, args: dict) -> str:
    if elf is None:
        return "not an ELF file; functions needs section headers"
    limit = min(max(_int(args.get("limit"), 60), 1), 1000)
    sections = elf.code_sections()
    starts: list[int] = []
    for section in sections:
        data = blob.read(section.off, section.size)
        if elf.machine == 183:
            for i in _find_offsets(data, b"\xfd\x7b", step=4):  # stp x29, x30, [sp,#-imm]!
                word = struct.unpack_from("<I", data, i)[0]
                if word & 0xFFC07FFF == 0xA9807BFD:
                    starts.append(section.addr + i)
            for pattern in (b"\x3f\x23\x03\xd5", b"\x5f\x24\x03\xd5", b"\xff\x03\x00\xd1"):
                for i in _find_offsets(data, pattern, step=4):
                    starts.append(section.addr + i)
        elif elf.machine == 40:
            for i in _find_offsets(data, b"\xb5", step=2):  # thumb push {...}
                half = struct.unpack_from("<H", data, i)[0]
                if half & 0xFE00 == 0xB400:
                    starts.append(section.addr + i)
            for i in _find_offsets(data, b"\x2d\xe9", step=4):  # ARM push {...}
                starts.append(section.addr + i)
        elif elf.machine in (3, 62):
            for pattern in (b"\x55\x48\x89\xe5", b"\xf3\x0f\x1e\xfa\x55"):
                for i in _find_offsets(data, pattern, step=1):
                    starts.append(section.addr + i)
    starts = sorted(set(starts))
    if not starts:
        return "no function prologues found (unknown arch or unusual compiler output)"
    syms = {}
    if elf is not None:
        syms = {s.value: s for s in _elf_symbols(blob, elf) if s.name and s.defined}
    out = [f"functions: {len(starts)} prologue candidate(s)"]
    for index, start in enumerate(starts[:limit]):
        end = starts[index + 1] if index + 1 < len(starts) else None
        sym = syms.get(start)
        label = sym.name if sym is not None else ""
        size = f"  size {end - start}" if end else ""
        out.append(f"  {start:#018x}  {label}{size}")
    if len(starts) > limit:
        out.append(f"  ... {len(starts) - limit} more (raise limit=)")
    out.append("note: prologue matching is heuristic; names appear only where symbols exist")
    return "\n".join(out)


def _action_gadgets(blob: _Blob, elf: _Elf | None, args: dict) -> str:
    if elf is None:
        return "not an ELF file; gadgets needs section headers"
    limit = min(max(_int(args.get("limit"), 40), 1), 500)
    max_bytes = min(max(_int(args.get("max_bytes"), 8 * 1024 * 1024), 4096), SCAN_LIMIT)
    pattern = str(args.get("pattern") or "").lower()
    cs = _cs_setup(elf)
    if cs is None:
        if elf.machine == 183:
            return _gadgets_arm64_fallback(blob, elf, limit, max_bytes, pattern)
        if elf.machine == 40:
            return _gadgets_arm_fallback(blob, elf, limit, max_bytes, pattern)
        return "gadgets needs capstone for this architecture (pip install capstone)"
    out = [f"gadgets (capstone, window {_int(args.get('window'), 6)} instructions)"]
    window = min(max(_int(args.get("window"), 6), 2), 12)
    total = 0
    for section in elf.code_sections():
        data = blob.read(section.off, min(section.size, max_bytes))
        try:
            insns = list(cs.disasm(data, section.addr, count=max_bytes // 4))
        except Exception as exc:
            swallow(exc, "tools/binary.py:gadgets")
            continue
        for index, insn in enumerate(insns):
            if insn.mnemonic not in ("ret", "br"):
                continue
            group = insns[max(0, index - window + 1) : index + 1]
            text = " ; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in group)
            if pattern and pattern not in text.lower():
                continue
            out.append(f"  {group[0].address:#018x}  {text}")
            total += 1
            if total >= limit:
                break
        if total >= limit:
            break
    if total == 0:
        return f"no gadgets found{' matching ' + pattern if pattern else ''}"
    return "\n".join(out)


def _gadgets_arm64_fallback(blob: _Blob, elf: _Elf, limit: int, max_bytes: int, pattern: str) -> str:
    out = ["gadgets (built-in ARM64 fallback; pip install capstone for full coverage)"]
    total = 0
    for section in elf.code_sections():
        data = blob.read(section.off, min(section.size, max_bytes))
        for pos in range(0, len(data) - 3, 4):
            word = struct.unpack_from("<I", data, pos)[0]
            if word != 0xD65F03C0:
                continue
            window = []
            for back in range(1, 5):
                start = pos - back * 4
                if start < 0:
                    break
                prev = struct.unpack_from("<I", data, start)[0]
                text = _mini_arm64(prev, section.addr + start)
                if text.startswith(".word"):
                    break
                window.insert(0, text)
            text = " ; ".join(window + ["ret"])
            if pattern and pattern not in text.lower():
                continue
            out.append(f"  {section.addr + pos - 4 * len(window):#018x}  {text}")
            total += 1
            if total >= limit:
                break
        if total >= limit:
            break
    if total == 0:
        return "no ret-terminated gadgets found in the scanned range"
    return "\n".join(out)


def _gadgets_arm_fallback(blob: _Blob, elf: _Elf, limit: int, max_bytes: int, pattern: str) -> str:
    out = ["gadgets (built-in ARM32 fallback; pip install capstone for full coverage)"]
    total = 0
    for section in elf.code_sections():
        data = blob.read(section.off, min(section.size, max_bytes))
        for pos in range(0, len(data) - 3, 4):
            word = struct.unpack_from("<I", data, pos)[0]
            terminates = word == 0xE12FFF1E or (word & 0x0FFF8000 == 0x08BD8000)
            if not terminates:
                continue
            window = []
            for back in range(1, 5):
                start = pos - back * 4
                if start < 0:
                    break
                prev = struct.unpack_from("<I", data, start)[0]
                text = _mini_arm32(prev, section.addr + start)
                if text.startswith(".word"):
                    break
                window.insert(0, text)
            text = " ; ".join(window + [_mini_arm32(word, section.addr + pos)])
            if pattern and pattern not in text.lower():
                continue
            out.append(f"  {section.addr + pos - 4 * len(window):#018x}  {text}")
            total += 1
            if total >= limit:
                break
        if total >= limit:
            break
    if total == 0:
        return "no ARM32 gadgets found in the scanned range"
    return "\n".join(out)


def _token_table_start(data, index_off: int, idx: tuple) -> int | None:
    if index_off < 1 or data[index_off - 1] != 0:
        return None
    for last_len in range(0, 40):
        start = index_off - 1 - last_len - idx[255]
        if start < 0:
            break
        if _check_tokens(data, start, idx):
            return start
    return None


def _check_tokens(data, start: int, idx: tuple) -> bool:
    pos = 0
    for i in range(256):
        if idx[i] != pos:
            return False
        end = data.find(b"\x00", start + pos, start + pos + 40)
        if end < 0:
            return False
        token = bytes(data[start + pos : end])
        if any(byte < 0x20 or byte > 0x7E for byte in token):
            return False
        pos += (end - start - pos) + 1
    return True


def _find_token_index(data, size: int) -> tuple[int, int, tuple] | None:
    """Locate kallsyms_token_table/-_index by their shape, not by name."""
    limit = min(size, SCAN_LIMIT)
    pos = 0
    while True:
        pos = data.find(b"\x00\x00", pos)
        if pos < 0 or pos >= limit:
            return None
        if data[pos : pos + 16] == b"\x00" * 16:  # long zero run: nothing to see
            pos += 16
            continue
        for cand in (pos, pos + 1):
            if cand < 1024 or cand + 512 > limit:
                continue
            head = data[cand : cand + 4]
            if head[:2] != b"\x00\x00" or head[2:] == b"\x00\x00":
                continue
            try:
                idx = struct.unpack_from("<256H", data, cand)
            except struct.error as exc:
                swallow(exc, "tools/binary.py:_find_token_index")
                continue
            if idx[0] != 0 or idx[1] == 0 or idx[1] > 12:
                continue
            if idx[255] > 4096 or any(idx[i] > idx[i + 1] for i in range(255)):
                continue
            table = _token_table_start(data, cand, idx)
            if table is not None:
                return table, cand, idx
        pos += 2


def _decode_entries(data, start: int, count: int, table: int, idx: tuple):
    """Decode `count` name entries. Returns (names, end) or (None, 0)."""
    names: list[str] = []
    tokens: dict[int, str] = {}
    pos = start
    for _ in range(count):
        if pos + 1 >= len(data):
            return None, 0
        first = data[pos]
        if first & 0x80:
            length = ((first & 0x7F) << 8) | data[pos + 1]
            pos += 2
        else:
            length = first
            pos += 1
        if length == 0 or length > 400 or pos + length > len(data):
            return None, 0
        chunk = data[pos : pos + length]
        pos += length
        parts = []
        for byte in chunk:
            token = tokens.get(byte)
            if token is None:
                begin = table + idx[byte]
                stop = data.find(b"\x00", begin, begin + 48)
                if stop < 0:
                    return None, 0
                token = bytes(data[begin:stop]).decode("ascii", "replace")
                tokens[byte] = token
            parts.append(token)
        names.append("".join(parts))
    return names, pos


def _decode_names(data, names_off: int, names_end: int, table: int, idx: tuple) -> list[str] | None:
    """Decode every entry in [names_off, names_end) and require an exact landing."""
    names: list[str] = []
    tokens: dict[int, str] = {}
    pos = names_off
    while pos < names_end:
        first = data[pos]
        if first & 0x80:
            if pos + 2 > names_end:
                return None
            length = ((first & 0x7F) << 8) | data[pos + 1]
            pos += 2
        else:
            length = first
            pos += 1
        if length == 0 or pos + length > names_end:
            return None
        chunk = bytes(data[pos : pos + length])
        pos += length
        parts = []
        for byte in chunk:
            token = tokens.get(byte)
            if token is None:
                begin = table + idx[byte]
                stop = data.find(b"\x00", begin, begin + 48)
                if stop < 0:
                    return None
                token = bytes(data[begin:stop]).decode("ascii", "replace")
                tokens[byte] = token
            parts.append(token)
        names.append("".join(parts))
        if len(names) > 4_000_000:
            return None
    return names


def _guess_offsets(data, names_off: int, num: int) -> tuple[int, bool] | None:
    """Where the address/offset array sits: right before kallsyms_num_syms."""
    sample_size = min(num, 64)
    for width, absolute in ((4, False), (8, True)):
        off = names_off - 4 - width * num
        if off < 0:
            continue
        fmt = f"<{sample_size}{'i' if width == 4 else 'q'}"
        try:
            sample = struct.unpack_from(fmt, data, off)
        except struct.error as exc:
            swallow(exc, "tools/binary.py:_guess_offsets")
            continue
        if width == 4:
            if all(0 <= value < (1 << 30) for value in sample):
                return off, absolute
        elif all(value > 0x80000000 for value in sample):
            return off, absolute
    return None


def _scan_kallsyms(blob: _Blob) -> dict | None:
    """Recover kallsyms from a raw image by locating the tables structurally."""
    data = blob.data
    found = _find_token_index(data, blob.size)
    if found is None:
        return None
    table, index_off, idx = found
    for chunks in range(1, 4097):
        marks_off = table - 4 * chunks
        if marks_off < 8:
            break
        if data[marks_off : marks_off + 4] != b"\x00\x00\x00\x00":
            continue
        try:
            marks = struct.unpack_from(f"<{chunks}I", data, marks_off)
        except struct.error as exc:
            swallow(exc, "tools/binary.py:_scan_kallsyms")
            break
        if any(marks[i] > marks[i + 1] for i in range(chunks - 1)):
            continue
        low = max(8, marks_off - marks[-1] - 256 * 64)
        high = marks_off - marks[-1] + 1
        if high <= low:
            continue
        for names_off in range(low, high):
            if names_off >= marks_off:
                break
            num = struct.unpack_from("<I", data, names_off - 4)[0]
            if not (chunks - 1) * 256 < num <= chunks * 256:
                continue
            if chunks > 1:
                _, reached = _decode_entries(data, names_off, 256, table, idx)
                if not reached or reached != names_off + marks[1]:
                    continue
            names = _decode_names(data, names_off, marks_off, table, idx)
            if not names or len(names) != num:
                continue
            guess = _guess_offsets(data, names_off, num)
            return {
                "num": num,
                "names": names,
                "table": table,
                "index": index_off,
                "marks": marks_off,
                "names_off": names_off,
                "offsets_off": guess[0] if guess else None,
                "absolute": bool(guess[1]) if guess else False,
                "base": None,
            }
    return None


def _elf_kallsyms(blob: _Blob, elf: _Elf) -> dict | None:
    """Exact extraction when the symbol table still names the kallsyms tables."""
    syms = {s.name: s for s in _elf_symbols(blob, elf) if s.name and s.defined}
    need = (
        "kallsyms_names",
        "kallsyms_num_syms",
        "kallsyms_markers",
        "kallsyms_token_table",
        "kallsyms_token_index",
    )
    if not all(name in syms for name in need):
        return None
    resolved = {}
    for name in need:
        off = elf.offset_for_addr(syms[name].value)
        if off is None:
            return None
        resolved[name] = off
    names_off = resolved["kallsyms_names"]
    table_off = resolved["kallsyms_token_table"]
    marks_off = resolved["kallsyms_markers"]
    try:
        num = struct.unpack_from("<I", blob.data, resolved["kallsyms_num_syms"])[0]
        idx = struct.unpack_from("<256H", blob.data, resolved["kallsyms_token_index"])
    except struct.error:
        return None
    if num <= 0 or num > 4_000_000 or not (names_off < marks_off <= table_off):
        return None
    names = _decode_names(blob.data, names_off, marks_off, table_off, idx)
    if not names or len(names) != num:
        return None
    result = {
        "num": num,
        "names": names,
        "table": table_off,
        "index": resolved["kallsyms_token_index"],
        "marks": marks_off,
        "names_off": names_off,
        "base": None,
        "absolute": False,
        "offsets_off": None,
    }
    for symbol, absolute in (("kallsyms_offsets", False), ("kallsyms_addresses", True)):
        if symbol in syms:
            off = elf.offset_for_addr(syms[symbol].value)
            if off is not None:
                result["offsets_off"] = off
                result["absolute"] = absolute
                break
    if "kallsyms_relative_base" in syms:
        off = elf.offset_for_addr(syms["kallsyms_relative_base"].value)
        if off is not None:
            fmt = "<Q" if elf.bits == 64 else "<I"
            result["base"] = struct.unpack_from(fmt, blob.data, off)[0]
    if result["base"] is None and not result["absolute"]:
        result["base"] = 0
    return result


def _kallsyms_addresses(blob: _Blob, table: dict, base: int, absolute: bool, bits: int = 64) -> list[int] | None:
    num = table["num"]
    offsets_off = table.get("offsets_off")
    if offsets_off is None:
        return None
    data = blob.data
    out: list[int] = []
    try:
        if absolute:
            fmt = "<Q" if bits == 64 else "<I"
            width = struct.calcsize(fmt)
            for i in range(num):
                out.append(struct.unpack_from(fmt, data, offsets_off + i * width)[0])
            return out
        for i in range(num):
            raw = struct.unpack_from("<i", data, offsets_off + i * 4)[0]
            if raw >= 0:
                out.append(base + raw)
            else:
                out.append(base - 1 - raw)
    except struct.error:
        return out or None
    return out


def _action_kallsyms(blob: _Blob, elf: _Elf | None, args: dict) -> str:
    limit = min(max(_int(args.get("limit"), 60), 1), 5000)
    match = str(args.get("filter") or "")
    table = None
    via = ""
    if elf is not None:
        table = _elf_kallsyms(blob, elf)
        via = "ELF symbols"
    if table is None:
        table = _scan_kallsyms(blob)
        via = "signature scan (heuristic)"
    if table is None:
        return (
            "kallsyms tables not found.\n"
            "works best on a vmlinux with symbols, or on a raw Image where the tables\n"
            "survive compression. decompress first (gunzip Image.gz) and try again."
        )
    base = _int(args.get("base"), table.get("base") or 0)
    bits = elf.bits if elf is not None else 64
    addrs = _kallsyms_addresses(blob, table, base, bool(table.get("absolute")), bits)
    names = table["names"]
    if addrs is None:
        addrs = [0] * len(names)
    out = [f"kallsyms: {table['num']} symbols (via {via})"]
    if base:
        out.append(f"base: {_addr(base)}")
    else:
        out.append("base: unknown, addresses shown relative (pass base= to add the slide)")
    rx = None
    if match:
        try:
            rx = re.compile(match, re.IGNORECASE)
        except re.error:
            rx = re.compile(re.escape(match), re.IGNORECASE)
    shown = 0
    for index, name in enumerate(names):
        if rx is not None and not rx.search(name):
            continue
        if index >= len(addrs):
            break
        value = addrs[index]
        if base:
            out.append(f"  {value:#018x}  {name}")
        else:
            out.append(f"  +0x{value & 0xFFFFFFFF:x}  {name}")
        shown += 1
        if shown >= limit:
            break
    if shown == 0:
        out.append(f"  (no symbol matched {match!r})")
    elif len(names) > shown:
        remaining = len(names) - shown
        out.append(f"  ... {remaining} more (use filter= or limit=)")
    return "\n".join(out)


def _words(data: bytes):
    """(offset, little-endian u32) pairs, decoded in one C call."""
    usable = len(data) - (len(data) % 4)
    if usable <= 0:
        return
    if sys.byteorder != "little":
        for pos in range(0, usable, 4):
            yield pos, _word(data, pos)
        return
    words = array("I")
    words.frombytes(bytes(data[:usable]))
    for index, word in enumerate(words):
        yield index * 4, word


def _word(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos : pos + 4], "little")


def _action_xrefs(blob: _Blob, elf: _Elf | None, args: dict) -> str:
    if elf is None:
        return "not an ELF file; xrefs needs section headers"
    limit = min(max(_int(args.get("limit"), 30), 1), 200)
    target = None
    if args.get("symbol"):
        target = _resolve_start(blob, elf, args)
        if target < 0:
            return f"unknown symbol {args['symbol']!r}"
    elif args.get("address") not in (None, ""):
        target = _int(args.get("address"), -1)
    elif args.get("string"):
        needle = str(args["string"]).encode("utf-8", "replace")
        hits = []
        pos = blob.data.find(needle)
        while pos >= 0 and len(hits) < 8:
            hits.append(pos)
            pos = blob.data.find(needle, pos + 1)
        if not hits:
            return f"string {args['string']!r} not found; use binary action=strings first"
        target = elf.addr_for_offset(hits[0]) or hits[0]
    if target is None or target < 0:
        return "xrefs needs address=, symbol= or string="
    out = [f"xrefs to {_addr(target)}"]
    if elf.machine == 183:
        out.extend(_xrefs_arm64(blob, elf, target, limit))
    elif elf.machine == 40:
        out.extend(_xrefs_arm(blob, elf, target, limit))
    else:
        out.append("  (only ARM64 and ARM32 get instruction-level xrefs)")
    literals = _xrefs_literals(blob, elf, target, limit)
    out.extend(literals)
    if len(out) == 1:
        out.append("  no references found")
    return "\n".join(out)


def _xrefs_arm64(blob: _Blob, elf: _Elf, target: int, limit: int) -> list[str]:
    lines: list[str] = []
    for section in elf.code_sections():
        data = blob.read(section.off, section.size)
        for pos, word in _words(data):
            pc = section.addr + pos
            if word & 0x9F000000 == 0x90000000:
                rd = word & 0x1F
                imm = ((word >> 5) & 0x7FFFF) << 2 | ((word >> 29) & 3)
                if imm & 0x100000:
                    imm -= 0x200000
                page = (pc & ~0xFFF) + (imm << 12)
                for step in range(1, 9):
                    npos = pos + step * 4
                    if npos + 4 > len(data):
                        break
                    nword = _word(data, npos)
                    if nword & 0x7F000000 == 0x11000000 and nword & 0x1F == rd and (nword >> 5) & 0x1F == rd:
                        shift = 12 if (nword >> 22) & 1 else 0
                        value = page + (((nword >> 10) & 0xFFF) << shift)
                        if value == target:
                            lines.append(f"  adrp+add  @ {pc:#018x}  (file {section.off + pos:#x})")
                            if len(lines) >= limit:
                                return lines
                        break
            elif word & 0xFC000000 in (0x14000000, 0x94000000):
                imm26 = word & 0x03FFFFFF
                if imm26 & 0x02000000:
                    imm26 -= 0x04000000
                if pc + (imm26 << 2) == target:
                    kind = "bl" if word & 0xFC000000 == 0x94000000 else "b "
                    lines.append(f"  {kind}        @ {pc:#018x}  (file {section.off + pos:#x})")
                    if len(lines) >= limit:
                        return lines
    return lines


def _xrefs_arm(blob: _Blob, elf: _Elf, target: int, limit: int) -> list[str]:
    lines: list[str] = []
    for section in elf.code_sections():
        data = blob.read(section.off, section.size)
        for pos, word in _words(data):
            pc = section.addr + pos
            if word >> 24 in (0xEA, 0xEB):
                imm = word & 0x00FFFFFF
                if imm & 0x00800000:
                    imm -= 0x01000000
                if pc + 8 + (imm << 2) == target:
                    kind = "bl" if word >> 24 == 0xEB else "b "
                    lines.append(f"  {kind}        @ {pc:#018x}  (file {section.off + pos:#x})")
                    if len(lines) >= limit:
                        return lines
    return lines


def _xrefs_literals(blob: _Blob, elf: _Elf, target: int, limit: int) -> list[str]:
    lines: list[str] = []
    needle = struct.pack("<Q", target & 0xFFFFFFFFFFFFFFFF)
    pos = 0
    while len(lines) < limit:
        pos = blob.data.find(needle, pos)
        if pos < 0:
            break
        section = elf.section_for_offset(pos)
        where = section.name if section is not None else "?"
        if section is not None and not section.is_code:
            lines.append(f"  pointer   @ file {pos:#x}  in {where}")
        pos += 1
    return lines


def _action_diff(blob: _Blob, elf: _Elf | None, args: dict) -> str:
    other = args.get("path2")
    if not other:
        return "diff needs path= and path2="
    other_path = Path(str(other)).expanduser()
    if not other_path.is_absolute():
        other_path = blob.path.parent / other_path
    if not other_path.exists():
        return f"not found: {other_path}"
    limit = min(max(_int(args.get("limit"), 40), 1), 500)
    with _Blob(other_path) as other_blob:
        step = 4096
        blocks = max(blob.size, other_blob.size) // step + 1
        runs: list[list[int]] = []
        for index in range(blocks):
            pos = index * step
            if blob.read(pos, step) != other_blob.read(pos, step):
                if runs and runs[-1][1] == pos:
                    runs[-1][1] = pos + step
                else:
                    runs.append([pos, pos + step])
        out = [
            f"diff {blob.path.name} ({blob.size} bytes) vs {other_path.name} ({other_blob.size} bytes)",
            f"changed blocks: {len(runs)} of {blocks} ({step} bytes each)",
        ]
        for begin, end in runs[:limit]:
            out.append(f"  {begin:#x}..{min(end, max(blob.size, other_blob.size)):#x}")
        if len(runs) > limit:
            out.append(f"  ... {len(runs) - limit} more ranges")
        other_elf = _parse_elf(other_blob)
        if elf is not None and other_elf is not None:
            out.extend(_symbol_diff(blob, elf, other_blob, other_elf, limit))
    return "\n".join(out)


def _symbol_fingerprints(blob: _Blob, elf: _Elf) -> dict[str, str]:
    syms = [s for s in _elf_symbols(blob, elf) if s.name and s.defined and s.size]
    out: dict[str, str] = {}
    for sym in syms:
        off = elf.offset_for_addr(sym.value)
        if off is None:
            continue
        data = blob.read(off, min(sym.size, 1 << 20))
        if data:
            out[sym.name] = hashlib.sha1(data).hexdigest()
    return out


def _symbol_diff(blob: _Blob, elf: _Elf, other: _Blob, other_elf: _Elf, limit: int) -> list[str]:
    left = _symbol_fingerprints(blob, elf)
    right = _symbol_fingerprints(other, other_elf)
    if not left or not right:
        return ["symbol-level diff: skipped (one side has no sized symbols)"]
    changed = sorted(name for name in left.keys() & right.keys() if left[name] != right[name])
    added = sorted(right.keys() - left.keys())
    removed = sorted(left.keys() - right.keys())
    lines = [
        f"symbols: {len(left)} vs {len(right)} (unchanged {len(left.keys() & right.keys()) - len(changed)})",
        f"changed: {len(changed)}  new: {len(added)}  gone: {len(removed)}",
    ]
    for name in changed[:limit]:
        lines.append(f"  ~ {name}")
    for name in added[:limit]:
        lines.append(f"  + {name}")
    for name in removed[:limit]:
        lines.append(f"  - {name}")
    return lines


def _action_patch(blob: _Blob, elf: _Elf | None, args: dict) -> str:
    off = _int(args.get("offset"), -1)
    if off < 0:
        return "patch needs offset="
    raw = _parse_pattern({"pattern": args.get("bytes"), "mode": "hex"})
    if not raw:
        return "patch needs bytes= as hex, e.g. 'd5 03 20 1f'"
    if off + len(raw) > blob.size:
        return f"{len(raw)} bytes at 0x{off:x} would run past the end (size {blob.size})"
    before = blob.read(off, len(raw))
    preview = (
        f"patch {off:#x} ({off})  {len(raw)} byte(s)\n"
        f"before: {before.hex(' ')}\n"
        f"after : {raw.hex(' ')}\n"
        f"file  : {blob.path}"
    )
    if not args.get("confirm"):
        return preview + "\n\npreview only (pass confirm=true to write; a .bak copy is kept)"
    backup = blob.path.with_suffix(blob.path.suffix + ".bak")
    if not backup.exists():
        shutil.copy2(blob.path, backup)
    blob.close()
    with open(blob.path, "r+b") as handle:
        handle.seek(off)
        handle.write(raw)
    return preview + f"\n\nwritten. backup: {backup}"


_HANDLERS = {
    "info": _action_info,
    "hex": _action_hex,
    "search": _action_search,
    "strings": _action_strings,
    "sections": _action_sections,
    "symbols": _action_symbols,
    "resolve": _action_resolve,
    "entropy": _action_entropy,
    "dump": _action_dump,
    "disasm": _action_disasm,
    "xrefs": _action_xrefs,
    "functions": _action_functions,
    "kallsyms": _action_kallsyms,
    "diff": _action_diff,
    "gadgets": _action_gadgets,
    "patch": _action_patch,
}


def _run(input: dict) -> dict:
    action = str(input.get("action") or "info").strip().lower()
    if action not in _HANDLERS:
        return _fail(f"unknown action {action!r}; choose one of: {', '.join(ACTIONS)}")
    raw_path = input.get("path") or input.get("filePath") or ""
    if not raw_path:
        return _fail("binary needs path= pointing at a file")
    path = Path(str(raw_path)).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.exists():
        return _fail(f"not found: {path}")
    if path.is_dir():
        return _fail(f"{path} is a directory")
    with _Blob(path) as blob:
        if blob.size == 0:
            return _fail(f"{path.name} is empty")
        elf = _parse_elf(blob)
        try:
            text = _HANDLERS[action](blob, elf, input)
        except Exception as exc:
            swallow(exc, f"tools/binary.py:{action}")
            return _fail(f"binary {action} failed: {type(exc).__name__}: {exc}")
    metadata = {"action": action, "path": str(path), "elf": elf is not None}
    if elf is not None:
        metadata.update({"arch": elf.arch, "bits": elf.bits, "size": blob.size})
    return {"output": text, "metadata": metadata}


def run(input: dict, limit: int = MAX_OUTPUT) -> dict:
    try:
        result = _run(input)
        text = result.get("output")
        if isinstance(text, str):
            result["output"] = _clip(text, limit=limit)
        return result
    except Exception as exc:
        swallow(exc, "tools/binary.py:run")
        return _fail(f"binary: {type(exc).__name__}: {exc}")


def tool(cfg=None) -> Tool:
    limit = getattr(cfg, "tool_output_max_bytes", MAX_OUTPUT) if cfg is not None else MAX_OUTPUT

    def run_clipped(input: dict) -> dict:
        return run(input, limit=limit)

    return Tool(
        name="binary",
        description=(
            "Inspect, disassemble and patch binaries without leaving the phone: ELF headers, "
            "sections, symbols, strings, xrefs, entropy, function candidates, kernel kallsyms "
            "extraction, two-file diff, ROP gadget search and byte patches. "
            f"Actions: {', '.join(ACTIONS)}. Output is clipped near {limit} chars."
        ),
        parameters=schema_with(
            {
                "action": {
                    "type": "string",
                    "enum": list(ACTIONS),
                    "description": "what to do (default info)",
                },
                "path": {"type": "string", "description": "file to read"},
                "path2": {"type": "string", "description": "second file, for action=diff"},
                "offset": {
                    "type": "integer",
                    "description": "file offset in bytes (hex strings like 0x1a20 are accepted)",
                },
                "length": {"type": "integer", "description": "bytes to read, dump or scan"},
                "count": {"type": "integer", "description": "instructions for disasm (default 40)"},
                "limit": {"type": "integer", "description": "max rows/entries in the output"},
                "address": {"type": "string", "description": "virtual address, hex or decimal"},
                "symbol": {"type": "string", "description": "symbol name to start from or target"},
                "name": {"type": "string", "description": "symbol name for action=resolve"},
                "pattern": {"type": "string", "description": "text, or hex bytes, to find or match"},
                "mode": {"type": "string", "enum": ["auto", "text", "hex"], "description": "pattern mode for search"},
                "ignore_case": {"type": "boolean", "description": "case-insensitive text search"},
                "filter": {"type": "string", "description": "regex filter for strings/symbols/kallsyms"},
                "min_length": {"type": "integer", "description": "shortest string to report (default 4)"},
                "block": {"type": "integer", "description": "entropy block size (default 4096)"},
                "threshold": {"type": "number", "description": "entropy threshold 0-8 (default 7.0)"},
                "base": {"type": "string", "description": "kallsyms relative base address"},
                "out": {"type": "string", "description": "output file for action=dump"},
                "bytes": {"type": "string", "description": "hex bytes to write, for action=patch"},
                "confirm": {"type": "boolean", "description": "really write, for action=patch"},
                "force": {"type": "boolean", "description": "allow overwriting an existing file"},
                "max_bytes": {"type": "integer", "description": "scan budget for gadgets"},
                "window": {"type": "integer", "description": "instructions per gadget window"},
            },
            [],
        ),
        run=run_clipped,
        permission="binary",
    )
