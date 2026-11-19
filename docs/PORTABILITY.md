# Платформа: Linux и macOS

`g-tools` собирается только на POSIX-системах, и это осознанное ограничение, а не недоделка:

| Что | Почему нельзя на Windows |
|---|---|
| ingest (`core/include/gcore/mmap_ingest.h`) | `mmap(PROT_READ, MAP_SHARED)` + `madvise(MADV_WILLNEED \| MADV_SEQUENTIAL)`; Windows-аналог (`CreateFileMapping` / `MapViewOfFile`) не даёт тех же подсказок ядру |
| raw-syscall путь | на Linux вызовы идут через `syscall(SYS_openat/SYS_mmap/...)` намеренно: иначе `LD_PRELOAD`-shim перехватывает собственный ingest и двойной `mmap/munmap` уничтожает кэш слайсов. На Windows понятия `LD_PRELOAD` нет, и это преимущество не переносится |
| `-Wl,--wrap` / `-rdynamic` | линковка специфична для ELF |

## Что нужно, чтобы появился Windows-порт

1. Реализовать `MmapFile` через `CreateFileMapping` + `MapViewOfFile` (отображение read-only
   разделяемое, закрытие через `UnmapViewOfFile`), сохранив тот же интерфейс `open/size/data/close`.
2. Заменить raw-syscall ветку на обычные CRT-вызовы: на Windows она не нужна, но и
   «zero-copy поверх shim» там не проверяется — это надо честно написать в README.
3. Прогнать `ctest` под MSVC (в коде есть `__attribute__`-места, потребуется `__declspec`-ветка).
4. Пересчитать бенчмарк: числа с Linux нельзя переносить на Windows.

Пока этого нет, `mmap_ingest.h` выдаёт `#error` с этой ссылкой вместо непонятной ошибки
«sys/mman.h: No such file or directory».

## Флаги сборки и ISA

По умолчанию сборка целит в **AVX2 + FMA** (`-mavx2 -mfma`): такой бинарник идёт на любом
x86-64-v3 хосте. `-DGTOOLS_NATIVE=ON` включает `-march=native` — компилятор подхватывает
нативные расширения (на Zen 4 / Sapphire Rapids появляются AVX-512 zmm-пути), но бинарник
становится привязан к CPU сборочной машины. Использовать это стоит только для бенчмарков.

Почему native не включён по умолчанию: с GCC 13 и `-fsanitize=address` на AVX-512 Xeon
сборка с `-march=native` детерминированно роняет `test_analyze` в `SEGV` внутри
`std::vector<g_section_rec>::push_back` (`g_analyze.cpp:407`) сразу после парсинга ELF-заголовка.
Замер на раннере ubuntu-24.04 (Xeon 6975P-C): 8/8 падений с `-march=native` против 0/8 с
закреплённым `-mavx2 -mfma`, одинаковый исходник и те же санитайзер-флаги. Поэтому CI
собирает тесты и санитайзеры в закреплённом режиме, а джоба бенчмарков — с
`-DGTOOLS_NATIVE=ON`.
