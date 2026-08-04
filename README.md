# g-tools — Zero-Copy Dataflow DAG Engine экосистема

Монорепо на базе архитектуры **g-proto / g-core** (см. спеку): замена
POSIX I/O + скалярного парсинга на dataflow DAG над единой mmap-памятью
с SIMD (AVX2 + AVX-512, runtime-диспатч по `cpu_has_avx512()`) и lock-free
синхронизацией.

## Конвейер (каждая утилита — граф нод)

```
[file] --mmap--> [chunk allocator] --> [SIMD scan nodes] --> [flat arena] --> [C-ABI] --> [Python/NumPy]
         node 1        node 2              node 3                 node 4        node 5        node 6
```

Инварианты ядра (главные):
- **Ноль `std::mutex`** в горячем цикле — только `std::atomic` (relaxed) + fetch_add.
- **Ноль `malloc/new`** в горячем цикле — только `FlatArena` (`aligned_alloc(64)`).
- **Строки не режутся** по границам чанков (инвариант `ChunkAllocator`, покрыт тестом).
- **C-ABI** для Python/Rust/Go: результат — плоская арена + владелец.

## Структура

```
core/include/gcore/    ядро (header-only): mmap_ingest, chunk_allocator,
                       flat_arena, simd_scan, c_abi
tools/g-grep/          первый инструмент: CLI + shared lib g-tools
bindings/python/       ctypes-биндинг (g_grep.py)
tests/                 юнит-тесты инвариантов
benchmarks/            генератор CSV + скрипты сравнения
```

## Сборка

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build          # тесты инвариантов
```

## Быстрый старт

```bash
./build/gen_data 20000000 /tmp/g_bench.csv            # 20M строк CSV
./build/g-grep -c NEEDLE /tmp/g_bench.csv             # подсчёт (16 воркеров)
grep -c NEEDLE /tmp/g_bench.csv                       # сравнение с GNU grep
python3 -c "from bindings.python.g_grep import grep; print(len(grep('/tmp/g_bench.csv','NEEDLE')))"
```

## Бенчмарк (данные: 30M строк / 1.8 GB CSV, ~33% строк-хитов)

| Инструмент | Время | Скорость |
|---|---|---|
| `grep -c` (GNU, 1 поток) | 896 ms | ~2.0 GB/s |
| **`g-grep -c`** (16 воркеров) | **116 ms** | **~15.5 GB/s** |
| Ускорение | **7.7x** | |

Примечания:
- Масштабируемость упирается в память/диск (page cache), не в CPU: на этой системе
  RAM занята на 80%+ (fca-проект), поэтому 1→16 воркеров дают лишь ~1.2x.
- `MAP_POPULATE` включается автоматически только когда файл ≤ половины свободной RAM
  (иначе своппинг убивает производительность).
- Результаты воспроизводимы: `./build/gen_data N` + сравнение на одном файле.

## Экосистема (дорожная карта)

| Инструмент | Статус | Описание |
|---|---|---|
| **g-grep** | ✅ готов | mmap + lock-free chunks + SIMD scan |
| **g-strings** | ✅ готов | printable-строки с офсетами + энтропийный фильтр, выход в numpy |
| **g-analyze** | ✅ готов | ноды RE-разведки: entropy_profile, bytes, hash, hist, unicode, sections, diff, xor, recon |
| **g-scan** | ✅ готов | YARA-подобный SIMD-скан сигнатур (Aho-Corasick + SIMD-skip) |
| **g-sort** | ⏳ план | SIMD-сортировка чанков + k-way merge в арену |
| **g-query** | ⏳ план | SQL-ноды над CSV/JSON без импорта (флагман) |
| **g-bus** | ⏳ план | mmap ring-buffer IPC, мост Python ↔ C++ (<2ns) |
| **g-dedup** | ⏳ план | хэш-дедуп через mmap + bloom |
| **g-pcap** | ⏳ план | потоковый анализатор пакетов (поля заголовков как разделители) |

## g-strings (для RE / нейронки)

Извлекает printable-строки `[0x20..0x7E]` из бинарника за один mmap-проход.
**Выход — flat массив `{offset, len}` (16 байт/строка), содержимое НЕ копируется**:
Python читает строки по offset прямо из `np.memmap` файла → ноль копий до нейронки.

```bash
./build/g-strings --min 4 /usr/bin/qemu-system-x86_64      # offset\tlen\ttext
./build/g-strings --count --max-entropy 5.0 file.bin        # отсев мусора из сжатых областей
```

```python
from g_strings import strings
recs, data = strings("fw.bin", min_len=6, max_entropy=5.0)  # numpy view + mmap
for r in recs[:5]: print(hex(r["offset"]), bytes(data[r["offset"]:r["offset"]+r["len"]]))
```

| Метрика (28 MB ELF) | g-strings | GNU strings |
|---|---|---|
| Время | 38 ms | 40 ms |
| Строк (min 4) | 147 555 | 148 144 |
| Расхождение | **0.4%** | — |

Известное отличие от GNU strings (~0.4-1%): краевые случаи на границах чанков
и обработка последней строки файла без разделителя. На файлах > RAM (прошивки,
VFS-образы) отрыв растёт: GNU strings однопоточный + read(), g-strings — 16
воркеров + mmap.

## g-analyze — ноды RE-разведки (C-ABI, все zero-copy)

Расширенные ноды в `tools/g-analyze/g_analyze.cpp`, все через один конвейер
(mmap → чанки → SIMD → арена → C-ABI):

| Нода | Вход | Выход | Назначение |
|---|---|---|---|
| `g_entropy_profile` | path, block | `{offset, entropy}[]` | карта plain/код/сжато по блокам |
| `g_bytes` | path, offset, len | сырые байты | срез для чтения magic/структур |
| `g_hash` | path | `{fnv1a64, crc32c}` | идентификация/дедуп (CRC32C — SSE4.2) |
| `g_hist` | path | `u64[256]` | гистограмма байтов (плотности/нули/таблицы) |
| `g_unicode` | path, min_len, max_entropy | `{offset, len}[]` | UTF-16LE строки (Windows/.NET/PE) |
| `g_sections` | path | `{offset, size, entropy, name, type}[]` | ELF/PE-разведка секций |
| `g_diff` | path_a, path_b, block | `{offset_a, offset_b, len, status}[]` | блочное сравнение версий/патчей |
| `g_xor` | path, offset, len, key | декодированные байты | XOR-обфускация (floss-стиль) |
| `g_recon` | path | карта файла целиком | hash + hist + entropy-регионы + строки-семплы одним проходом |

Ключевые детали:
- `g_strings`/`g_unicode`: воркеры на **64-байтовых блоках** с AVX-512
  (`printable_mask64`/`zero_mask64`, uint64-маски) — при `-march=native` на Zen 4
  включаются zmm-примитивы автоматически, runtime-диспатч для не-AVX512 CPU.
- `g_recon`: полная RE-карта файла за один mmap-проход — FNV-1a 64 + CRC32C
  (SSE4.2), байтовая гистограмма u64[256], энтропийная сегментация по блокам
  ≥4096, до 2000 строк-семплов. Выход — плоский буфер
  `[header][hist][entropy][strings]`.
- `g_unicode`: SIMD-скан по **парам** с двумя сдвигами (чёт/нечёт) — UTF-16 строки
  с нечётным стартом не теряются; 33-й байт для пары (i+31, i+32) берётся из
  `zero_mask(base+i+1) << 1` в uint64 (иначе прогон рвётся на каждом блоке).
- `g_sections`: минимальные парсеры ELF64/ELF32/PE без системных заголовков,
  все чтения через `within()`-проверку границ mmap; энтропия каждой секции.
- `g_diff`: поблочный memcmp, группировка смежных CHANGED; хвосты A/B → DELETED/INSERTED.

Прямой вызов из Python (ctypes):

```bash
python3 tests/test_extra_nodes.py   # тесты всех 8 нод: hash, hist, unicode, sections, diff, xor
```

Все ноды доступны как MCP-инструменты (см. ниже).

## g-scan — мультипаттернный SIMD-скан сигнатур

`tools/g-scan/g_scan.cpp`: YARA-подобный поиск до 1000 паттернов за один проход.

- **Aho-Corasick** над паттернами — линейное время поиска всех паттернов сразу.
- **SIMD-skip**: перед прогоном AC первые байты паттернов сверяются 64-байтовым
  AVX2/AVX-512 маскам (`count_byte`/`find_byte`), тупые области файла
  пропускаются векторно.
- Выход — flat-массив `{offset, pattern_idx}` (16 байт), Python дешифрует в
  numpy без копий.

```bash
python3 tests/test_scan.py  # поиск magic/сигнатур
```

## MCP-сервер g-tools

`/home/lain/.opencode/mcp/g-tools/server.py` — FastMCP поверх libg-tools.so,
зарегистрирован в opencode.json. 12 инструментов:

`g_strings`, `g_unicode`, `g_entropy_profile`, `g_grep_lines`, `g_bytes`,
`g_hash`, `g_hist`, `g_sections`, `g_diff`, `g_xor`, `g_recon`, `g_scan`

RE-разведка за один запрос к нейронке: `g_recon` → полная карта файла
(hash + hist + entropy-регионы + строки) одним вызовом, затем
`g_bytes`/`g_strings` в интересных офсетах → `g_sections` для ELF/PE →
`g_scan` для поиска сигнатур → `g_xor` если строки зашифрованы.
(Принцип «сначала карта за 300ms, потом точечный анализ».)
