// simd_scan.h — SIMD-сканирование байтов (поиск разделителей/подсчёты).
// AVX-512 (64 Б/такт) с runtime-диспатчем → AVX2 (32 Б) → скалярный fallback.
// На Zen 4 (полный 512-бит датапат) AVX-512 быстрее двух AVX2-проходов.
#pragma once

#include <cmath>
#include <cstddef>
#include <cstdint>

#ifdef __AVX2__
#include <immintrin.h>
#endif
#ifdef __AVX512F__
#include <immintrin.h>
#endif

namespace gcore {

constexpr uint8_t kNL = '\n';  // разделитель строк

/// Есть ли AVX-512 на этой машине (runtime). При компиляции без -mavx512
/// всегда false — код ниже не скомпилирован.
inline bool cpu_has_avx512() noexcept {
#ifdef __AVX512F__
    return __builtin_cpu_supports("avx512f") != 0;
#else
    return false;
#endif
}

namespace detail {

#ifdef __AVX512F__
inline uint64_t count_byte_avx512(const uint8_t* p, size_t n, uint8_t b) {
    const __m512i target = _mm512_set1_epi8(static_cast<char>(b));
    uint64_t count = 0;
    size_t i = 0;
    for (; i + 64 <= n; i += 64) {
        const __m512i v = _mm512_loadu_si512(p + i);
        count += static_cast<size_t>(__builtin_popcountll(
            static_cast<uint64_t>(_mm512_cmpeq_epi8_mask(v, target))));
    }
    for (; i < n; ++i)
        if (p[i] == b) ++count;
    return count;
}

inline const uint8_t* find_byte_avx512(const uint8_t* p, size_t n, uint8_t b) {
    const __m512i target = _mm512_set1_epi8(static_cast<char>(b));
    size_t i = 0;
    for (; i + 64 <= n; i += 64) {
        const __m512i v = _mm512_loadu_si512(p + i);
        const uint64_t mask = static_cast<uint64_t>(_mm512_cmpeq_epi8_mask(v, target));
        if (mask != 0) return p + i + static_cast<size_t>(__builtin_ctzll(mask));
    }
    for (; i < n; ++i)
        if (p[i] == b) return p + i;
    return nullptr;
}

/// 64-байтовая printable-маска [0x20..0x7E] → uint64_t (bit i = байт i printable).
inline uint64_t printable_mask_avx512(const uint8_t* p) {
    const __m512i lo = _mm512_set1_epi8(0x20);
    const __m512i hi = _mm512_set1_epi8(0x7E);
    const __m512i v = _mm512_loadu_si512(p);
    const __mmask64 ge = _mm512_cmpeq_epi8_mask(_mm512_max_epu8(v, lo), v);
    const __mmask64 le = _mm512_cmpeq_epi8_mask(_mm512_min_epu8(v, hi), v);
    return static_cast<uint64_t>(ge & le);
}

inline uint64_t zero_mask_avx512(const uint8_t* p) {
    const __m512i v = _mm512_loadu_si512(p);
    return static_cast<uint64_t>(_mm512_cmpeq_epi8_mask(v, _mm512_setzero_si512()));
}
#endif // __AVX512F__

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

// ---- Публичный API (диспатч на компиляцию + runtime) ----

inline size_t count_byte(const uint8_t* p, size_t n, uint8_t b) {
#ifdef __AVX512F__
    if (cpu_has_avx512()) return detail::count_byte_avx512(p, n, b);
#endif
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
#ifdef __AVX512F__
    if (cpu_has_avx512()) return detail::find_byte_avx512(p, n, b);
#endif
#ifdef __AVX2__
    return detail::find_byte_avx2(p, n, b);
#else
    return detail::find_byte_scalar(p, n, b);
#endif
}

inline const uint8_t* find_newline(const uint8_t* p, size_t n) {
    return find_byte(p, n, kNL);
}

// ---- 32-байтовые маски (AVX2) ----

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

// ---- 64-байтовые маски (AVX-512, runtime-диспатч) ----

namespace detail {

inline uint64_t printable_mask64_scalar(const uint8_t* p) {
    uint64_t m = 0;
    for (int i = 0; i < 64; ++i) {
        const uint8_t b = p[i];
        if (b >= 0x20 && b <= 0x7E) m |= (1ull << i);
    }
    return m;
}

inline uint64_t zero_mask64_scalar(const uint8_t* p) {
    uint64_t m = 0;
    for (int i = 0; i < 64; ++i)
        if (p[i] == 0) m |= (1ull << i);
    return m;
}

} // namespace detail

/// Маска printable [0x20..0x7E] для 64-байтового блока (bit i = байт i printable).
inline uint64_t printable_mask64(const uint8_t* p) {
#ifdef __AVX512F__
    if (cpu_has_avx512()) return detail::printable_mask_avx512(p);
#endif
#ifdef __AVX2__
    const uint32_t lo = detail::printable_mask_avx2(p);
    const uint32_t hi = detail::printable_mask_avx2(p + 32);
    return static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32);
#else
    return detail::printable_mask64_scalar(p);
#endif
}

/// Маска нулевых байтов для 64-байтового блока (bit i = байт i == 0).
inline uint64_t zero_mask64(const uint8_t* p) {
#ifdef __AVX512F__
    if (cpu_has_avx512()) return detail::zero_mask_avx512(p);
#endif
#ifdef __AVX2__
    const uint32_t lo = zero_mask(p);
    const uint32_t hi = zero_mask(p + 32);
    return static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32);
#else
    return detail::zero_mask64_scalar(p);
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
