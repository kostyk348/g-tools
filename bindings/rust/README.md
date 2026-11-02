# gcore — Rust-биндинги к C ABI g-tools

Zero-copy Rust-доступ к конвейеру g-tools: **ядро остаётся C++** (AVX2/AVX-512,
mmap, lock-free chunks), Rust получает плоскую арену через стабильный C ABI
(`core/include/gcore/c_abi.h`) и освобождает её в `Drop`.

```
[file] --mmap--> [chunks] --> [SIMD scan] --> [flat arena] --> [C-ABI] --> [Rust]
                                                                        (эта обёртка)
```

## Почему биндинги, а не порт ядра

Ценность g-tools — ручные SIMD-интринсики, mmap-тюнинг и lock-free аллокация.
Переписывание на Rust дало бы те же `unsafe` + `std::arch` в другом синтаксисе
без выигрыша в безопасности и с риском потерять отлаженные бенчмарки. C ABI —
уже межъязыковая граница: Python ходит через ctypes, Rust — через этот крейт.

## Сборка

`build.rs` вызывает cmake и собирает `libg-tools` (нужны cmake >= 3.20 и
C++20-компилятор; ядро собирается с `-march=native`, поэтому хост x86-64 с AVX2):

```bash
cargo test --manifest-path bindings/rust/Cargo.toml
```

## Использование

```rust
use gcore::{diff, entropy_profile, grep_count, grep_strings, hash, scan, strings, xor_bytes};

// g-grep: подсчёт и строки-хиты
let n = grep_count("/tmp/big.csv", "row1").unwrap_or(0);
let hits = grep_strings("/tmp/big.csv", "row1");

// g-strings: printable-строки (offset, len); None = без энтропийного фильтра
let found = strings("/tmp/firmware.bin", 6, None);

// g-scan: мультипаттернный SIMD-скан сигнатур
let m = scan("/tmp/firmware.bin", &["MZ", "PK\x03\x04"]);

// разведка: хэши, карта энтропии, XOR-декод, diff прошивок
let (fnv, crc) = hash("/tmp/firmware.bin").unwrap();
let ent = entropy_profile("/tmp/firmware.bin", 65536);
let dec = xor_bytes("/tmp/firmware.bin", 0, 0, 0xAA);
let d = diff("/tmp/old.bin", "/tmp/new.bin", 4096);
```

Сырой доступ к арене — `gcore::raw_grep` возвращает `RawResult` с `bytes()` и
`Drop`-освобождением; структуры ABI (`g_strings_rec` и др.) живут в `gcore-sys`
и совместимы с numpy dtype `[('offset','u8'),('len','u4'),('pad','u4')]`.

## Контракты (унаследованы от ABI)

- при ошибке узла `data == NULL` (у count-функций `-1`) — в обёртке это
  `None` / `RawResult::is_error()`;
- пути и needle — C-строки: `'\0'` внутри иглы невозможен;
- `g_hash` FNV — словный (u64 LE + побайтовый хвост), НЕ побайтовый FNV-1a;
- `unicode`: длины в байтах, `min_len` в символах UTF-16.
