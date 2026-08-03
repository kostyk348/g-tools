// g_grep.cpp — первый инструмент экосистемы g-tools.
// Конвейер: mmap → lock-free chunk → per-line memmem (glibc, SIMD-оптимизирован)
//           → thread_local FlatArena → merge → C-ABI.
// Горячий цикл: ноль мутексов, ноль malloc (строки копируются в арены),
// строки не режутся по границам чанков (инвариант ChunkAllocator).
#include <gcore/gcore.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using gcore::ChunkAllocator;
using gcore::find_newline;
using gcore::FlatArena;
using gcore::MmapFile;

namespace {

// ---- один воркер: берёт чанки, собирает хиты в свою арену ----
struct WorkerResult {
    FlatArena arena;   // хиты как C-строки (последовательно, \0-терминированы)
    size_t count = 0;
};

void worker(const MmapFile& file, ChunkAllocator& alloc, const char* needle,
            size_t needle_len, int mode, WorkerResult& out) {
    const uint8_t* base = file.data();
    const size_t total = file.size();

    // Предварительная оценка: максимум строк в чанке — резервируем арену один раз.
    if (mode == 0)
        out.arena.reserve(total / 64 + 4096);

    size_t begin = 0, end = 0;
    while (alloc.next(begin, end)) {
        // Сканируем строки в [begin, end): каждая строка = [l, r) где r — '\n'
        size_t l = begin;
        while (l < end) {
            // Граница строки: SIMD-поиск '\n' (32 байта за такт)
            const uint8_t* nl = find_newline(base + l, end - l);
            size_t r = nl ? static_cast<size_t>(nl - base) : end;
            // r указывает на '\n' или конец чанка.
            // Если r == end и end < total — это хвост последней строки файла
            // (файл без завершающего \n) или обрезанный чанк; обрабатываем как строку.
            if (r - l >= needle_len &&
                memmem(base + l, r - l, needle, needle_len) != nullptr) {
                ++out.count;
                if (mode == 0) {
                    // Хит: копируем строку как C-строку (с '\0')
                    out.arena.append(base + l, r - l);
                    out.arena.append("\0", 1);
                }
            }
            if (r >= end) break;  // конец чанка
            l = r + 1;            // следующая строка после '\n'
        }
    }
}

/// Исполняет конвейер g-grep над mmap-буфером.
/// mode: 0 = копировать строки-хиты, 1 = только подсчёт.
struct GrepResult {
    FlatArena arena;   // общая арена (пустая при mode=1)
    size_t count = 0;
    bool ok = false;
};

GrepResult run_grep(const char* path, const char* needle, int mode,
                    unsigned nthreads) {
    GrepResult result;
    MmapFile file;
    if (!file.open(path) || needle == nullptr || needle[0] == '\0') {
        return result;  // ok=false
    }
    const size_t needle_len = std::strlen(needle);
    const size_t total = file.size();
    if (total == 0) { result.ok = true; return result; }

    const unsigned hw = std::thread::hardware_concurrency();
    const unsigned n = nthreads ? nthreads : (hw ? hw : 4u);

    ChunkAllocator alloc(file.data(), total);
    std::vector<WorkerResult> workers(n);
    std::vector<std::thread> threads;
    threads.reserve(n);

    for (unsigned i = 0; i < n; ++i) {
        threads.emplace_back([&, i] {
            worker(file, alloc, needle, needle_len, mode, workers[i]);
        });
    }
    for (auto& t : threads) t.join();

    size_t total_count = 0;
    for (const auto& w : workers) total_count += w.count;

    if (mode == 1) {
        result.count = total_count;
        result.ok = true;
        return result;
    }

    // Merge: конкатенация локальных арен в общую (порядок недетерминирован —
    // для детерминированного порядка нужен офсетный индекс; для grep-вывода ок).
    size_t merged_bytes = 0;
    for (const auto& w : workers) merged_bytes += w.arena.size();
    if (!result.arena.reserve(merged_bytes)) return result;
    for (const auto& w : workers) {
        if (w.arena.size())
            result.arena.append(w.arena.data(), w.arena.size());
    }
    result.count = total_count;
    result.ok = true;
    return result;
}

} // namespace

// ============================ C-ABI ============================

extern "C" {

void g_result_free(g_result* r) {
    if (!r) return;
    if (r->owner) {
        delete static_cast<gcore::FlatArena*>(r->owner);
        r->owner = nullptr;
    }
    r->data = nullptr;
    r->size = r->capacity = r->count = 0;
}

g_result g_grep(const char* path, const char* needle) {
    GrepResult r = run_grep(path, needle, /*mode=*/0, /*nthreads=*/0);
    g_result out{};
    if (!r.ok) return out;
    auto* arena = new gcore::FlatArena(std::move(r.arena));  // одна аллокация на вызов
    out.owner = arena;
    out.data = arena->data();
    out.size = arena->size();
    out.capacity = arena->capacity();
    out.count = r.count;
    return out;
}

int64_t g_grep_count(const char* path, const char* needle) {
    GrepResult r = run_grep(path, needle, /*mode=*/1, /*nthreads=*/0);
    return r.ok ? static_cast<int64_t>(r.count) : -1;
}

} // extern "C"
