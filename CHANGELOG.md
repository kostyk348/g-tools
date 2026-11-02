# Changelog

Все заметные изменения проекта документируются в этом файле.
Формат — [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed

- `g_entropy_profile`: результат теперь отсортирован по offset при любом числе
  воркеров (воркеры писали стридами в отдельные арены, склейка шла в порядке
  воркеров — нарушался задокументированный контракт «возрастание offset»);
- `g_unicode`: строки, доходящие до конца файла, больше не теряются (EOF-раны
  сбрасывались вместе с ранами, обрезанными внутренней границей чанка).

### Added

- `tests/test_analyze.cpp` — герметичные C-тесты всех расширенных C-ABI нод
  (strings/unicode/entropy/bytes/xor/hash/hist/sections ELF64+PE/diff/scan/recon
  + ошибки, границы, free(NULL)); фикстуры генерируются на месте;
- `tests/fuzz_api.cpp` — детерминированный API-фаззер: случайные входы и
  проверка контрактов против reference-реализаций (grep-count по строкам,
  strings-сканер, xor-байты, FNV/CRC, полнота scan-совпадений);
- `tests/test_extra_nodes.py` переписан герметично: был захардкожен на чужие
  пути (`/home/lain/...`) и не запускался нигде, кроме автора; фикстуры теперь
  генерируются, путь к либе — argv/GTOOLS_LIB, тест зарегистрирован в ctest;
- **Rust-биндинги** `bindings/rust/`: `gcore-sys` (raw FFI, build.rs собирает
  libg-tools через cmake) + `gcore` (безопасная обёртка с RAII-Drop арены).
  Ядро остаётся C++ — переписывание SIMD/mmap/atomic-кода на Rust дало бы тот
  же unsafe без выигрыша; связка с Rust-экосистемой через стабильный C ABI;
- CI: ctest (был только build, тесты не запускались), ASan+UBSan job,
  Rust-bindings job (fmt/clippy/test), smoke-прогон README quickstart;
- CONTRIBUTING.md, PR-шаблон, этот CHANGELOG.

### Changed

- `c_abi.h`: уточнена документация `g_hash.fnv1a64` (словный FNV-1a по u64 LE
  с побайтовым хвостом — не эквивалентен побайтовому FNV-1a) и
  `g_recon_header.fnv1a64` (побайтовый — значения с g_hash не совпадают).
