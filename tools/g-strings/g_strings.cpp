// g_strings.cpp — второй инструмент экосистемы g-tools.
// Конвейер: mmap → lock-free chunk → SIMD printable-mask → {offset,len} recs
//           → merge + sort по offset → C-ABI (строки НЕ копируются).
//
// Фишка для RE/нейронки: выход — flat массив {offset,len}, содержимое строк
// читается по offset прямо из mmap файла. Ноль копий, дешёвая структурная карта.
#include <gcore/gcore.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using gcore::ChunkAllocator;
using gcore::FlatArena;
using gcore::MmapFile;
using gcore::printable_mask64;
using gcore::shannon_entropy;

extern "C" {
#include <gcore/c_abi.h>
}

namespace {

// ---- воркер: сканирует чанки, собирает recs в локальную арену ----
struct StringsOut {
    FlatArena recs;   // g_strings_rec[] — 16 байт каждая
    size_t count = 0;
};

inline void emit_string(const uint8_t* base, size_t /*total*/, size_t start, size_t epos,
                        int min_len, double max_entropy, StringsOut& out) {
    const size_t len = epos - start;
    if (len < static_cast<size_t>(min_len)) return;
    if (max_entropy >= 0.0 && shannon_entropy(base + start, len) > max_entropy) return;
    g_strings_rec rec{static_cast<uint64_t>(start), static_cast<uint32_t>(len), 0};
    out.recs.append(&rec, sizeof(rec));
    ++out.count;
}

void strings_worker(const uint8_t* base, size_t total, ChunkAllocator& alloc,
                    int min_len, double max_entropy, StringsOut& out) {
// Оценка: в худшем случае каждая 64-байтовая printable-строка даёт rec.
    out.recs.reserve((total / 64 + 1) * 16 + 4096);

    size_t begin = 0, end = 0;
    while (alloc.next(begin, end)) {
        // Сканируем чанк блоками по 64 байта; бит i маски = байт printable.
        // AVX-512: 64 байта за такт (printable_mask64); иначе 2×AVX2/скаляр.
        // Строка = максимальный прогон printable битов длиной >= min_len.
        bool in_string = false;
        size_t run_start = 0;
        size_t i = begin;
        for (; i + 64 <= end; i += 64) {
            const uint64_t m = printable_mask64(base + i);
            uint64_t bits = m;
            int b = 0;
            while (b < 64) {
                if (bits & 0x1ull) {
                    if (!in_string) { in_string = true; run_start = i + b; }
                } else {
                    if (in_string) {
                        emit_string(base, total, run_start, i + b, min_len, max_entropy, out);
                        in_string = false;
                    }
                }
                bits >>= 1ull;
                ++b;
            }
        }
        // Хвост чанка (< 64 байта): скалярно
        for (; i < end; ++i) {
            const uint8_t c = base[i];
            const bool is_p = (c >= 0x20 && c <= 0x7E);
            if (is_p) {
                if (!in_string) { in_string = true; run_start = i; }
            } else {
                if (in_string) {
                    emit_string(base, total, run_start, i, min_len, max_entropy, out);
                    in_string = false;
                }
            }
        }
        // Строка, дотянувшаяся до конца чанка: продолжаем её в следующем чанке.
        // Гарантия ChunkAllocator: границы чанков выровнены по '\n' (0x0A — не
        // printable), поэтому printable-строка НЕ может пересекать границу,
        // кроме обрезанного чанка (нет '\n' в lookahead) — редкий крайний случай,
        // строка теряется (аналогично g-grep).
        if (in_string) {
            // emit только если это реальный конец файла (не обрезанный чанк)
            if (end == total) {
                emit_string(base, total, run_start, end, min_len, max_entropy, out);
            }
            in_string = false;
        }
    }
}

struct StringsResult {
    FlatArena recs;
    size_t count = 0;
    bool ok = false;
};

StringsResult run_strings(const char* path, int min_len, double max_entropy,
                          unsigned nthreads) {
    StringsResult result;
    MmapFile file;
    if (!file.open(path) || min_len < 1) return result;
    const size_t total = file.size();
    if (total == 0) { result.ok = true; return result; }

    const unsigned hw = std::thread::hardware_concurrency();
    const unsigned n = nthreads ? nthreads : (hw ? hw : 4u);

    ChunkAllocator alloc(file.data(), total);
    std::vector<StringsOut> workers(n);
    std::vector<std::thread> threads;
    threads.reserve(n);
    for (unsigned i = 0; i < n; ++i) {
        threads.emplace_back([&, i] {
            strings_worker(file.data(), total, alloc, min_len, max_entropy, workers[i]);
        });
    }
    for (auto& t : threads) t.join();

    size_t total_count = 0;
    size_t total_bytes = 0;
    for (const auto& w : workers) { total_count += w.count; total_bytes += w.recs.size(); }

    if (!result.recs.reserve(total_bytes)) return result;
    for (const auto& w : workers) {
        if (w.recs.size()) result.recs.append(w.recs.data(), w.recs.size());
    }
    // Детерминированный порядок: сортируем recs по offset (без аллокаций —
    // сортируем массив прямо в арене)
    if (result.recs.size()) {
        auto* recs = reinterpret_cast<g_strings_rec*>(result.recs.data());
        const size_t cnt = result.recs.size() / sizeof(g_strings_rec);
        std::sort(recs, recs + cnt,
                  [](const g_strings_rec& a, const g_strings_rec& b) {
                      return a.offset < b.offset;
                  });
    }
    result.count = total_count;
    result.ok = true;
    return result;
}

} // namespace

// ============================ C-ABI ============================

extern "C" {

g_result g_strings(const char* path, int min_len, double max_entropy) {
    StringsResult r = run_strings(path, min_len, max_entropy, 0);
    g_result out{};
    if (!r.ok) return out;
    auto* arena = new gcore::FlatArena(std::move(r.recs));
    out.owner = arena;
    out.data = arena->data();
    out.size = arena->size();
    out.capacity = arena->capacity();
    out.count = r.count;
    return out;
}

int64_t g_strings_count(const char* path, int min_len, double max_entropy) {
    StringsResult r = run_strings(path, min_len, max_entropy, 0);
    return r.ok ? static_cast<int64_t>(r.count) : -1;
}

} // extern "C"
