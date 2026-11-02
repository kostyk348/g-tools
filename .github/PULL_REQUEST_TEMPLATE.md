## Что меняется

<!-- Один абзац. Если есть issue: "Closes #12" -->

## Тип

- [ ] Bug fix
- [ ] Feature / новый узел
- [ ] Performance (приложите цифры до/после)
- [ ] Documentation
- [ ] CI / build
- [ ] Refactor (без изменения поведения)

## Инварианты ядра

- [ ] Горячий цикл: без `std::mutex`, без `malloc/new` (только FlatArena/atomic)
- [ ] Порядок результата по offset сохранён (если узел с записями)
- [ ] C ABI не изменён (или изменён синхронно: ctypes + Rust-биндинги, bump версии)

## Чек-лист

- [ ] `ctest --test-dir build` — все 5 наборов зелёные
- [ ] `fuzz_api` инварианты расширены/не нарушены
- [ ] Rust-биндинги пересобраны (`cargo test --manifest-path bindings/rust/Cargo.toml`)
