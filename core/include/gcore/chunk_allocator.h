// chunk_allocator.h — нода 2 графа: lock-free нарезка mmap-буфера на чанки.
// Один std::atomic<size_t> fetch_add. Никаких мутексов.
//
// Инвариант: каждая строка файла попадает ровно в один чанк:
//   - левый край: частичная строка (начатая до s) пропускается — её дообработал
//     предыдущий воркер (правый край которого был выровнен по '\n');
//   - правый край: выравнивается вперёд до следующего '\n' (+1), чтобы строки
//     не резались посередине.
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "gcore/simd_scan.h"

namespace gcore {

class ChunkAllocator {
public:
    // chunk_size: целевой размер чанка (2-4 MB по спеке).
    // lookahead: запас для поиска '\n' на правой границе (строки длиннее
    // lookahead байт — аномалия; чанк обрежется на границе, строка потеряется
    // в рамках известного ограничения на супер-длинные строки).
    ChunkAllocator(const uint8_t* base, size_t total,
                   size_t chunk_size = 4u << 20,
                   size_t lookahead = 1u << 20) noexcept
        : base_(base), total_(total), chunk_size_(chunk_size > 0 ? chunk_size : 1),
          lookahead_(lookahead) {}

    /// Выдаёт следующий непересекающийся чанк [begin, end).
    /// begin — начало строки (0 для первого чанка), end — после '\n'.
    /// Возвращает false, когда чанки закончились.
    bool next(size_t& begin, size_t& end) noexcept {
        for (;;) {
            const size_t s = next_.fetch_add(chunk_size_, std::memory_order_relaxed);
            if (s >= total_) return false;

            // --- левый край: пропустить хвост строки, начатой в предыдущем чанке ---
            size_t start = s;
            if (s > 0) {
                const size_t avail = (total_ - s < chunk_size_) ? (total_ - s) : chunk_size_;
                const uint8_t* nl = find_newline(base_ + s, avail);
                if (nl) start = static_cast<size_t>(nl - base_) + 1;
                // '\n' не найден → строка длиннее чанка: обработаем [s, e) обрезанно
            }

            // --- правый край: выровнять до '\n' + 1 ---
            size_t e = s + chunk_size_;
            if (e > total_) e = total_;
            if (e < total_) {
                const size_t lim = (total_ - e < lookahead_) ? (total_ - e) : lookahead_;
                const uint8_t* nl = find_newline(base_ + e, lim);
                if (nl) e = static_cast<size_t>(nl - base_) + 1;
                // '\n' не найден в lookahead → чанк обрезается на e (крайний случай)
            }

            if (start < e) {      // валидный непустой чанк
                begin = start;
                end = e;
                return true;
            }
            // Пустой чанк (весь остаток — хвост строки, покрытый предыдущим
            // воркером). Продолжаем: fetch_add сам продвинет нас дальше.
        }
    }

private:
    const uint8_t* base_;
    size_t total_;
    size_t chunk_size_;
    size_t lookahead_;
    std::atomic<size_t> next_{0};
};

} // namespace gcore
