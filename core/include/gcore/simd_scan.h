// simd_scan.h — SIMD-сканирование байтов (поиск разделителей/подсчёты).
// AVX2: 32 байта за такт через cmpeq + movemask. Скалярный fallback для x86 без AVX2.
#pragma once

#include <cmath>
#include <cstddef>
#include <cstdint>

#ifdef __AVX2__
#include <immintrin.h>
#endif

namespace gcore {

constexpr uint8_t kNL = '\n';  // разделитель строк

namespace detail {

#ifdef __AVX2__
inline size_t count_byte_avx2(const uint8_t* p, size_t n, uint8_t b) {
    const __m256i target = _mm256_set1_epi8(static_cast<char>(b));
    size_t count = 0;
    size_t i = 0;
    for (; i + 32 <= n; i += 32) {
        const __m256i v = _mm256_loadu_si256(
            reinterpret_cast<const __m256i*>(p + i));
        const uint32_t mask = static_cast<uint32_t>(
            _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, target)));
        count += static_cast<size_t>(__builtin_popcount(mask));
    }
    for (; i < n; ++i)
        if (p[i] == b) ++count;
    return count;
}

inline const uint8_t* find_byte_avx2(const uint8_t* p, size_t n, uint8_t b) {
    const __m256i target = _mm256_set1_epi8(static_cast<char>(b));
    size_t i = 0;
    for (; i + 32 <= n; i += 32) {
        const __m256i v = _mm256_loadu_si256(
            reinterpret_cast<const __m256i*>(p + i));
        const uint32_t mask = static_cast<uint32_t>(
            _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, target)));
        if (mask != 0) {
            const int idx = __builtin_ctz(mask);
            return p + i + static_cast<size_t>(idx);
        }
    }
    for (; i < n; ++i)
        if (p[i] == b) return p + i;
    return nullptr;
}

/// Битовый массив 32 байт (bit i = 1) для printable-диапазона [0x20, 0x7E].
inline uint32_t printable_mask_avx2(const uint8_t* p) {
    const __m256i lo = _mm256_set1_epi8(0x20);
    const __m256i hi = _mm256_set1_epi8(0x7E);
    const __m256i v = _mm256_loadu_si256(
        reinterpret_cast<const __m256i*>(p));
    // (v >= lo) && (v <= hi) через min/max без ветвлений
    const __m256i ge = _mm256_cmpeq_epi8(_mm256_max_epu8(v, lo), v);
    const __m256i le = _mm256_cmpeq_epi8(_mm256_min_epu8(v, hi), v);
    return static_cast<uint32_t>(
        _mm256_movemask_epi8(_mm256_and_si256(ge, le)));
}
#endif // __AVX2__

inline size_t count_byte_scalar(const uint8_t* p, size_t n, uint8_t b) {
    size_t count = 0;
    for (size_t i = 0; i < n; ++i)
        if (p[i] == b) ++count;
    return count;
}

inline const uint8_t* find_byte_scalar(const uint8_t* p, size_t n, uint8_t b) {
    for (size_t i = 0; i < n; ++i)
        if (p[i] == b) return p + i;
    return nullptr;
}

} // namespace detail

// ---- Публичный API (диспатч на компиляцию) ----

inline size_t count_byte(const uint8_t* p, size_t n, uint8_t b) {
#ifdef __AVX2__
    return detail::count_byte_avx2(p, n, b);
#else
    return detail::count_byte_scalar(p, n, b);
#endif
}

inline size_t count_newlines(const uint8_t* p, size_t n) {
    return count_byte(p, n, kNL);
}

inline const uint8_t* find_byte(const uint8_t* p, size_t n, uint8_t b) {
#ifdef __AVX2__
    return detail::find_byte_avx2(p, n, b);
#else
    return detail::find_byte_scalar(p, n, b);
#endif
}

inline const uint8_t* find_newline(const uint8_t* p, size_t n) {
    return find_byte(p, n, kNL);
}

// ---- printable-маска (для g-strings) ----

namespace detail {

inline uint32_t printable_mask_scalar(const uint8_t* p) {
    uint32_t m = 0;
    for (int i = 0; i < 32; ++i) {
        const uint8_t b = p[i];
        if (b >= 0x20 && b <= 0x7E) m |= (1u << i);
    }
    return m;
}

} // namespace detail

/// Маска printable [0x20..0x7E] для 32-байтового блока (bit i = байт i printable).
inline uint32_t printable_mask(const uint8_t* p) {
#ifdef __AVX2__
    return detail::printable_mask_avx2(p);
#else
    return detail::printable_mask_scalar(p);
#endif
}

/// Маска нулевых байтов для 32-байтового блока (bit i = байт i == 0).
inline uint32_t zero_mask(const uint8_t* p) {
#ifdef __AVX2__
    const __m256i zero = _mm256_setzero_si256();
    const __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(p));
    return static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_cmpeq_epi8(v, zero)));
#else
    uint32_t m = 0;
    for (int i = 0; i < 32; ++i)
        if (p[i] == 0) m |= (1u << i);
    return m;
#endif
}

/// Энтропия Шеннона блока (биты/байт). Вызывается только на строках-кандидатах.
inline double shannon_entropy(const uint8_t* p, size_t n) {
    if (n == 0) return 0.0;
    uint32_t hist[256] = {0};
    for (size_t i = 0; i < n; ++i) ++hist[p[i]];
    double h = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (!hist[i]) continue;
        const double pi = static_cast<double>(hist[i]) / static_cast<double>(n);
        h -= pi * std::log2(pi);
    }
    return h;
}

} // namespace gcore
