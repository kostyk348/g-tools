#!/usr/bin/env python3
"""Прямой ctypes-тест расширенных C-ABI нод: g_hash, g_hist, g_unicode,
g_sections, g_diff, g_xor. Проверка на реальных файлах."""
import ctypes
import os
import sys

LIB = "/home/lain/g-tools/build/libg-tools.so"
WAD = "/home/lain/g-tools/benchmarks/data/freedoom/freedoom-0.13.0/freedoom1.wad"
ELF = "/home/lain/g-tools/build/libg-tools.so"

lib = ctypes.CDLL(LIB)

class GResult(ctypes.Structure):
    _fields_ = [("owner", ctypes.c_void_p), ("data", ctypes.POINTER(ctypes.c_uint8)),
                ("size", ctypes.c_size_t), ("capacity", ctypes.c_size_t),
                ("count", ctypes.c_size_t)]

lib.g_result_free.argtypes = [ctypes.POINTER(GResult)]
for fn in ("g_hash", "g_hist", "g_unicode", "g_sections", "g_diff", "g_xor"):
    getattr(lib, fn).restype = GResult
lib.g_hash.argtypes = [ctypes.c_char_p]
lib.g_hist.argtypes = [ctypes.c_char_p]
lib.g_unicode.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_double]
lib.g_sections.argtypes = [ctypes.c_char_p]
lib.g_diff.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
lib.g_xor.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int]
lib.g_bytes.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.c_uint64]
lib.g_bytes.restype = GResult


def check(name, cond, detail=""):
    print(f"{'PASS' if cond else 'FAIL'}  {name} {detail}")
    return cond


ok = True
wad = WAD.encode()
elf = ELF.encode()

# ---- g_hash ----
r = lib.g_hash(wad)
data = ctypes.string_at(r.data, r.size)
fnv, crc = data[:8], data[8:12]
import binascii
print(f"  fnv1a64={fnv.hex()} crc32c={crc.hex()}")
ok &= check("g_hash count==1", r.count == 1 and r.size == 16)

# ---- g_hist ----
r = lib.g_hist(wad)
h = ctypes.cast(r.data, ctypes.POINTER(ctypes.c_uint64 * 256)).contents
total = sum(h[i] for i in range(256))
fsize = os.path.getsize(WAD)
ok &= check("g_hist sum==filesize", total == fsize, f"({total} == {fsize})")
ok &= check("g_hist count==256", r.count == 256)
# freedoom: MAP данные — не-ASCII байты присутствуют
print(f"  nonzero bins={sum(1 for i in range(256) if h[i])}, zeros={sum(1 for i in range(256) if h[i]==0)}")

# ---- g_unicode: на специальном UTF-16LE файле ----
u16 = "/tmp/opencode/u16_test.bin".encode()
r = lib.g_unicode(u16, 6, -1.0)
recs = ctypes.cast(r.data, ctypes.POINTER(ctypes.c_uint64)) if r.count else None
found = []
if recs:
    raw = open("/tmp/opencode/u16_test.bin", "rb").read()
    for i in range(r.count):
        off = recs[i * 2]
        ln = recs[i * 2 + 1] & 0xFFFFFFFF
        found.append(raw[off:off + ln].decode("utf-16-le", errors="replace"))
print(f"  g_unicode: {r.count} UTF-16 строк -> {found}")
ok &= check("g_unicode finds UTF-16 strings", len(found) >= 2, str(found))
ok &= check("g_unicode min_len filter", all(len(s) >= 6 for s in found))

# ---- g_sections (ELF: libg-tools.so) ----
r = lib.g_sections(elf)
class SecRec(ctypes.Structure):
    _fields_ = [("offset", ctypes.c_uint64), ("size", ctypes.c_uint64),
                ("entropy", ctypes.c_double), ("name", ctypes.c_char * 32),
                ("type", ctypes.c_uint32)]
secs = ctypes.cast(r.data, ctypes.POINTER(SecRec * r.count)).contents if r.count else []
print(f"  g_sections: {r.count} секций ELF")
for s in list(secs)[:8]:
    print(f"    {s.name.decode(errors='replace'):24s} off={s.offset:9d} size={s.size:9d} ent={s.entropy:.2f} type={s.type}")
ok &= check("g_sections found sections", r.count > 3)
names = {s.name.decode(errors="replace") for s in secs}
ok &= check("g_sections has .text/.rodata", {".text", ".rodata", ".data"} <= names, f"got {sorted(names)[:6]}")

# ---- g_diff: файл сам с собой = 0 изменений; против g-grep = есть изменения ----
r = lib.g_diff(elf, elf, 4096)
ok &= check("g_diff self==empty", r.count == 0, f"(count={r.count})")
other = "/home/lain/g-tools/build/g-grep".encode()
r = lib.g_diff(elf, other, 4096)
class DiffRec(ctypes.Structure):
    _fields_ = [("offset_a", ctypes.c_uint64), ("offset_b", ctypes.c_uint64),
                ("len", ctypes.c_uint32), ("status", ctypes.c_uint8)]
diffs = ctypes.cast(r.data, ctypes.POINTER(DiffRec * r.count)).contents if r.count else []
print(f"  g_diff so-vs-grep: {r.count} диапазонов")
for d in list(diffs)[:5]:
    print(f"    off_a={d.offset_a:9d} off_b={d.offset_b:9d} len={d.len:7d} st={d.status}")
ok &= check("g_diff different files -> changes", r.count > 0)

# ---- g_xor: XOR срез с 0xAA и обратно ----
r = lib.g_xor(wad, 0, 64, 0xAA)
enc = bytes(ctypes.string_at(r.data, r.size))
r2 = lib.g_xor(wad, 0, 64, 0xAA)  # снова, чтобы иметь второй буфер
enc2 = bytes(ctypes.string_at(r2.data, r2.size))
r3 = ctypes.cast(r2.data, ctypes.POINTER(ctypes.c_uint8))
dec = bytes(b ^ 0xAA for b in enc)
raw = bytes(ctypes.string_at(lib.g_bytes(wad, 0, 64).data, 64))
ok &= check("g_xor roundtrip", dec == raw, f"({dec[:8].hex()} vs {raw[:8].hex()})")
print(f"  g_xor: head WAD: {raw[:8].hex()} -> xor0xAA: {enc[:8].hex()}")

# ---- g_bytes sanity (используется выше) ----
print()
print("ALL PASS" if ok else "SOME FAILED")
sys.exit(0 if ok else 1)
