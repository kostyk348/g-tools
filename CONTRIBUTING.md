# Contributing to g-tools

Инварианты ядра — не пожелания, а контракт. PR, нарушающий их, не проходит.

## Контракт ядра

- **Ноль `std::mutex` в горячем цикле** — только `std::atomic` (relaxed) + fetch_add.
- **Ноль `malloc/new` в горячем цикле** — только `FlatArena` (`aligned_alloc(64)`).
- **Строки не режутся по границам чанков** (инвариант `ChunkAllocator`, тест).
- **C ABI — межъязыковая граница**: не менять сигнатуры/структуры без bump
  минорной версии и синхронного обновления ctypes- и Rust-биндингов.
- Результаты узлов с `offset`-семантикой (entropy, strings, unicode) —
  в возрастающем порядке offset, независимо от числа воркеров.

## Dev-окружение

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
ctest --test-dir build --output-on-failure          # 5 наборов тестов
cargo test --manifest-path bindings/rust/Cargo.toml # Rust-биндинги (нужен cmake)
```

Фаззер запускается дольше одной итерации ctest так:

```bash
./build/fuzz_api 100000 0xDEADBEEF   # итерации, seed
```

## Перед PR

- [ ] `ctest --test-dir build` — все 5 наборов зелёные
- [ ] новые узлы покрыты тестом в `tests/test_analyze.cpp` (герметичная фикстура)
- [ ] для новых узлов с входом «файл + параметры» — инварианты в `fuzz_api`
- [ ] изменения C ABI синхронизированы: `c_abi.h`, `bindings/python/*`, `bindings/rust/*`
- [ ] если контракт ассемблировался по-новому (`-march=`), бенчмарк `g-grep -c`
      не просел

## PR-стиль

Маленькие, одноцелевые PR, заголовок conventional commits (`feat:`, `fix:`,
`perf:`, `docs:`, `ci:`). В описании — цифры до/после для perf-изменений.
