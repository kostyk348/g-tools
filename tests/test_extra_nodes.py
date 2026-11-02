#!/usr/bin/env python3
"""ctypes-тест расширенных C-ABI нод: g_hash, g_hist, g_unicode, g_sections,
g_diff, g_xor, g_bytes. Герметичный: все фикстуры генерируются во временную
директорию, путь к libg-tools передаётся argv[1] (или $GTOOLS_LIB).

Запуск:  python3 tests/test_extra_nodes.py <путь к libg-tools.so>
"""
import ctypes
import struct
import sys
import tempfile
from pathlib import Path


def find_lib() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]
    import os
    if os.environ.get("GTOOLS_LIB"):
        return os.environ["GTOOLS_LIB"]
    for cand in (
        Path(__file__).resolve().parent.parent / "build" / "libg-tools.so",
        Path("build/libg-tools.so"),
    ):
        if cand.exists():
            return str(cand)
    raise SystemExit("libg-tools.so не найдена: передайте путь argv[1] или $GTOOLS_LIB")


class GResult(ctypes.Structure):
    _fields_ = [("owner", ctypes.c_void_p), ("data", ctypes.POINTER(ctypes.c_uint8)),
                ("size", ctypes.c_size_t), ("capacity", ctypes.c_size_t),
                ("count", ctypes.c_size_t)]


class SecRec(ctypes.Structure):
    _fields_ = [("offset", ctypes.c_uint64), ("size", ctypes.c_uint64),
                ("entropy", ctypes.c_double), ("name", ctypes.c_char * 32),
                ("type", ctypes.c_uint32)]


class DiffRec(ctypes.Structure):
    _fields_ = [("offset_a", ctypes.c_uint64), ("offset_b", ctypes.c_uint64),
                ("len", ctypes.c_uint32), ("status", ctypes.c_uint8)]


def main() -> int:
    lib = ctypes.CDLL(find_lib())

    lib.g_result_free.argtypes = [ctypes.POINTER(GResult)]
    for fn in ("g_hash", "g_hist", "g_unicode", "g_sections", "g_diff", "g_xor", "g_bytes"):
        getattr(lib, fn).restype = GResult
    lib.g_hash.argtypes = [ctypes.c_char_p]
    lib.g_hist.argtypes = [ctypes.c_char_p]
    lib.g_unicode.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_double]
    lib.g_sections.argtypes = [ctypes.c_char_p]
    lib.g_diff.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    lib.g_xor.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int]
    lib.g_bytes.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.c_uint64]

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"{chr(80)+chr(65)+chr(83)+chr(83) if cond else chr(70)+chr(65)+chr(73)+chr(76)}  {name} {detail}")
        ok = ok and bool(cond)
        return cond

    tmp = Path(tempfile.mkdtemp(prefix="gtools_py_test_"))

    # ---- фикстуры ----
    csv = tmp / "data.csv"
    lines = ["header,x,y"] + [f"row{i},{i},{'NEEDLE' if i % 50 == 0 else 'x'}" for i in range(2000)]
    csv.write_text("\n".join(lines) + "\n", encoding="utf-8")

    u16 = tmp / "utf16.bin"
    payload = "PACK".encode("utf-16-le") + b"\x01\x00" + "MODE".encode("utf-16-le")
    u16.write_bytes(payload)

    elf = tmp / "mini.elf"
    shstrtab = b"\0.text\0.rodata\0.shstrtab\0"
    shoff = 64
    shentsize, shnum, shstrndx = 64, 4, 1
    text_off = shoff + shnum * shentsize
    text_data = bytes(range(256))[:64]
    rodata_off = text_off + len(text_data)
    rodata = b"CONST DATA \x00\x01\x02"
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2  # ELFCLASS64
    struct.pack_into("<Q", hdr, 0x28, shoff)
    struct.pack_into("<H", hdr, 0x3A, shentsize)
    struct.pack_into("<H", hdr, 0x3C, shnum)
    struct.pack_into("<H", hdr, 0x3E, shstrndx)

    def shdr(name, typ, flags, off, size):
        s = bytearray(64)
        struct.pack_into("<I", s, 0, name)
        struct.pack_into("<I", s, 4, typ)
        struct.pack_into("<Q", s, 8, flags)
        struct.pack_into("<Q", s, 0x18, off)
        struct.pack_into("<Q", s, 0x20, size)
        return bytes(s)

    name_text = shstrtab.index(b".text")
    name_rodata = shstrtab.index(b".rodata")
    name_str = shstrtab.index(b".shstrtab")
    body = (
        shdr(0, 0, 0, 0, 0)
        + shdr(name_str, 3, 0, text_off, len(shstrtab))       # .shstrtab
        + shdr(name_text, 1, 0x6, text_off, len(text_data))   # .text (exec)
        + shdr(name_rodata, 1, 0x2, rodata_off, len(rodata))  # .rodata
    )
    elf.write_bytes(bytes(hdr) + body + shstrtab + text_data + rodata)

    other = tmp / "other.bin"
    other.write_bytes(csv.read_bytes() + b"extra tail\n")

    # ---- g_hash ----
    r = lib.g_hash(str(csv).encode())
    print(f"  g_hash: size={r.size} count={r.count}")
    check("g_hash count==1 size==16", r.count == 1 and r.size == 16)
    lib.g_result_free(ctypes.byref(r))

    # ---- g_hist ----
    r = lib.g_hist(str(csv).encode())
    h = ctypes.cast(r.data, ctypes.POINTER(ctypes.c_uint64 * 256)).contents
    total = sum(h[i] for i in range(256))
    fsize = csv.stat().st_size
    check("g_hist sum==filesize", total == fsize, f"({total} == {fsize})")
    check("g_hist count==256", r.count == 256)
    lib.g_result_free(ctypes.byref(r))

    # ---- g_unicode: UTF-16LE ----
    r = lib.g_unicode(str(u16).encode(), 4, -1.0)
    found = []
    if r.count:
        raw = u16.read_bytes()
        recs = ctypes.cast(r.data, ctypes.POINTER(ctypes.c_uint64 * (r.count * 2))).contents
        for i in range(r.count):
            off, ln = recs[i * 2], recs[i * 2 + 1]
            found.append(raw[off:off + ln].decode("utf-16-le", errors="replace"))
    print(f"  g_unicode: {r.count} UTF-16 строк -> {found}")
    check("g_unicode finds UTF-16 strings", found == ["PACK", "MODE"], str(found))
    lib.g_result_free(ctypes.byref(r))

    # ---- g_sections (синтетический ELF64) ----
    r = lib.g_sections(str(elf).encode())
    secs = ctypes.cast(r.data, ctypes.POINTER(SecRec * r.count)).contents if r.count else []
    print(f"  g_sections: {r.count} секций ELF")
    for s in list(secs):
        print(f"    {s.name.decode(errors='replace'):12s} off={s.offset:5d} size={s.size:4d} type={s.type}")
    names = {s.name.decode(errors="replace") for s in secs}
    check("g_sections count==4", r.count == 4)
    check("g_sections has .text/.rodata", {".text", ".rodata"} <= set(names), f"got {sorted(names)}")
    lib.g_result_free(ctypes.byref(r))

    # ---- g_diff: сам с собой = 0; с другим файлом > 0 ----
    r = lib.g_diff(str(csv).encode(), str(csv).encode(), 4096)
    check("g_diff self==empty", r.count == 0, f"(count={r.count})")
    lib.g_result_free(ctypes.byref(r))
    r = lib.g_diff(str(csv).encode(), str(other).encode(), 4096)
    print(f"  g_diff csv-vs-other: {r.count} диапазонов")
    d = ctypes.cast(r.data, ctypes.POINTER(DiffRec * r.count)).contents if r.count else []
    for x in list(d)[:3]:
        print(f"    off_a={x.offset_a} off_b={x.offset_b} len={x.len} st={x.status}")
    check("g_diff different files -> changes", r.count > 0)
    lib.g_result_free(ctypes.byref(r))

    # ---- g_xor roundtrip + g_bytes ----
    r = lib.g_bytes(str(csv).encode(), 0, 64)
    raw = bytes(ctypes.string_at(r.data, r.size))
    lib.g_result_free(ctypes.byref(r))
    r = lib.g_xor(str(csv).encode(), 0, 64, 0xAA)
    enc = bytes(ctypes.string_at(r.data, r.size))
    lib.g_result_free(ctypes.byref(r))
    check("g_bytes slice 64", len(raw) == 64)
    check("g_xor roundtrip", bytes(b ^ 0xAA for b in enc) == raw,
          f"({enc[:8].hex()} vs {raw[:8].hex()})")

    # ---- numpy-совместимость g_strings_rec (если numpy есть) ----
    try:
        import numpy as np
        dt = np.dtype([("offset", "u8"), ("len", "u4"), ("pad", "u4")])
        check("numpy g_strings_rec itemsize==16", dt.itemsize == 16, f"({dt.itemsize})")
        r = lib.g_unicode(str(u16).encode(), 4, -1.0)
        arr = np.frombuffer(ctypes.string_at(r.data, r.size), dtype=dt)
        check("numpy parse unicode recs", list(arr["offset"]) == [0, 10], str(list(arr["offset"])))
        lib.g_result_free(ctypes.byref(r))
    except ImportError:
        print("SKIP  numpy отсутствует — dtype-совместимость не проверена")

    print()
    print("ALL PASS" if ok else "SOME FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
