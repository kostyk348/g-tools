// flat_arena.h — нода 4 графа: плоская память под выходной layout.
// Единый 64-byte aligned буфер (попадает в cache lines). Единственная
// аллокация на весь конвейер. Каждый воркер пишет в thread_local арену,
// финальный merge — в общую.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace gcore {

class FlatArena {
public:
    FlatArena() = default;
    ~FlatArena() { reset(); }

    FlatArena(const FlatArena&) = delete;
    FlatArena& operator=(const FlatArena&) = delete;

    FlatArena(FlatArena&& other) noexcept
        : mem_(other.mem_), capacity_(other.capacity_), size_(other.size_) {
        other.mem_ = nullptr;
        other.capacity_ = other.size_ = 0;
    }
    FlatArena& operator=(FlatArena&& other) noexcept {
        if (this != &other) {
            std::free(mem_);
            mem_ = other.mem_; capacity_ = other.capacity_; size_ = other.size_;
            other.mem_ = nullptr;
            other.capacity_ = other.size_ = 0;
        }
        return *this;
    }

    /// Гарантирует capacity байт. Не трогает уже записанные данные.
    bool reserve(size_t capacity) noexcept {
        if (capacity <= capacity_) return true;
        void* m = std::aligned_alloc(64, capacity);
        if (!m) return false;
        if (mem_) std::memcpy(m, mem_, size_);
        std::free(mem_);
        mem_ = static_cast<uint8_t*>(m);
        capacity_ = capacity;
        return true;
    }

    /// Копирует n байт в конец арены. Возвращает offset или (size_t)-1.
    size_t append(const void* src, size_t n) noexcept {
        if (size_ + n > capacity_ && !grow(size_ + n)) return static_cast<size_t>(-1);
        std::memcpy(mem_ + size_, src, n);
        const size_t off = size_;
        size_ += n;
        return off;
    }

    uint8_t* data() noexcept { return mem_; }
    const uint8_t* data() const noexcept { return mem_; }
    size_t size() const noexcept { return size_; }
    size_t capacity() const noexcept { return capacity_; }

    void reset() noexcept {
        std::free(mem_);
        mem_ = nullptr;
        capacity_ = size_ = 0;
    }

private:
    bool grow(size_t need) noexcept {
        size_t nc = capacity_ ? capacity_ : (1u << 20);  // старт: 1 MB
        while (nc < need) nc *= 2;
        return reserve(nc);
    }

    uint8_t* mem_ = nullptr;
    size_t capacity_ = 0;
    size_t size_ = 0;
};

} // namespace gcore
