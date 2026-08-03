"""Python-биндинг g-tools через ctypes: zero-copy доступ к плоской арене g-grep.

Строки-хиты возвращаются как байты; каждый байт памяти — ровно тот, что в mmap
файла (копии сделаны один раз при сборке арены на C++ стороне, без повторных
аллокаций на Python).
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
from pathlib import Path

_LIB_NAMES = ["g-tools", "libg-tools.so", "g-tools.so"]


class GResult(ctypes.Structure):
    _fields_ = [
        ("owner", ctypes.c_void_p),
        ("data", ctypes.POINTER(ctypes.c_uint8)),
        ("size", ctypes.c_size_t),
        ("capacity", ctypes.c_size_t),
        ("count", ctypes.c_size_t),
    ]


class _Lib:
    def __init__(self) -> None:
        self.lib = None
        candidates = _LIB_NAMES[:]
        # путь к собранной либе относительно этого файла
        repo_root = Path(__file__).resolve().parents[2]
        candidates.append(str(repo_root / "build" / "libg-tools.so"))
        for name in candidates:
            try:
                self.lib = ctypes.CDLL(name)
                break
            except OSError:
                continue
        if self.lib is None:
            raise RuntimeError(
                "libg-tools.so не найден. Соберите проект: cmake -B build && cmake --build build"
            )
        self.lib.g_result_free.argtypes = [ctypes.POINTER(GResult)]
        self.lib.g_result_free.restype = None
        self.lib.g_grep.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.lib.g_grep.restype = GResult
        self.lib.g_grep_count.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self.lib.g_grep_count.restype = ctypes.c_int64

    def grep(self, path: str, needle: str) -> list[bytes]:
        """Возвращает список строк-хитов (bytes, без завершающего \\0)."""
        res = self.lib.g_grep(path.encode(), needle.encode())
        if not res.data:
            return []
        try:
            raw = ctypes.string_at(res.data, res.size)
        finally:
            self.lib.g_result_free(ctypes.byref(res))
        return [s for s in raw.split(b"\0") if s]

    def grep_count(self, path: str, needle: str) -> int:
        return int(self.lib.g_grep_count(path.encode(), needle.encode()))


_lib = None


def _get_lib() -> _Lib:
    global _lib
    if _lib is None:
        _lib = _Lib()
    return _lib


def grep(path: str, needle: str) -> list[bytes]:
    return _get_lib().grep(path, needle)


def grep_count(path: str, needle: str) -> int:
    return _get_lib().grep_count(path, needle)
