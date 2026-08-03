"""Python-биндинг g-strings через ctypes + numpy.

Выход — structured numpy-массив {offset, len} без копий (recs читаются как
один буфер из C-арены). Содержимое строк читается по (offset, len) напрямую
из np.memmap файла — ноль копий до нейронки.
"""
from __future__ import annotations

import ctypes
from pathlib import Path

import numpy as np

from g_grep import GResult, _get_lib  # общий загрузчик libg-tools.so

REC_DTYPE = np.dtype([("offset", "<u8"), ("len", "<u4"), ("pad", "<u4")])


class _LibStrings:
    def __init__(self) -> None:
        self.lib = _get_lib().lib
        self.lib.g_strings.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_double]
        self.lib.g_strings.restype = GResult
        self.lib.g_strings_count.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_double]
        self.lib.g_strings_count.restype = ctypes.c_int64


_lib = None


def _get() -> _LibStrings:
    global _lib
    if _lib is None:
        _lib = _LibStrings()
    return _lib


def strings(path: str, min_len: int = 6, max_entropy: float = -1.0):
    """Возвращает (recs, data) где:
      recs — numpy structured array [('offset','u8'),('len','u4')],
      data — np.memmap файла для чтения строк по offset/len.
    max_entropy < 0 → фильтр выключен.
    """
    res = _get().lib.g_strings(path.encode(), min_len, max_entropy)
    if not res.data or res.count == 0:
        return np.empty(0, dtype=REC_DTYPE), None
    try:
        raw = ctypes.string_at(res.data, res.count * 16)
    finally:
        _get().lib.g_result_free(ctypes.byref(res))
    recs = np.frombuffer(raw, dtype=REC_DTYPE).copy()  # одна копия (16 байт × N)
    data = np.memmap(path, dtype="u1", mode="r")
    return recs, data


def string_texts(path: str, min_len: int = 6, max_entropy: float = -1.0) -> list[bytes]:
    """Удобная обёртка: список строк (bytes), как GNU strings."""
    recs, data = strings(path, min_len, max_entropy)
    if recs.size == 0 or data is None:
        return []
    return [bytes(data[r["offset"] : r["offset"] + r["len"]]) for r in recs]


def strings_count(path: str, min_len: int = 4, max_entropy: float = -1.0) -> int:
    return int(_get().lib.g_strings_count(path.encode(), min_len, max_entropy))
