// g_analyze.cpp — ноды анализа для RE-разведки.
//   g_entropy_profile: энтропия Шеннона по блокам → карта plain/код/сжато.
//   g_bytes:           срез байт [offset, offset+len) → арена.
//   g_hash:            FNV-1a 64 + CRC32C (SSE4.2) для идентификации/дедупа.
//   g_hist:            гистограмма 256 байт (параллельно, lock-free чанки).
//   g_unicode:         UTF-16LE printable-строки (Windows/.NET/PE-ресурсы).
// Конвейер тот же: mmap → блоки → FlatArena → C-ABI.
#include <gcore/gcore.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <new>
#include <thread>
#include <vector>

#include <nmmintrin.h>  // SSE4.2: _mm_crc32_u*

using gcore::ChunkAllocator;
using gcore::FlatArena;
using gcore::MmapFile;
using gcore::printable_mask64;
using gcore::shannon_entropy;
using gcore::zero_mask64;

extern "C" {
#include <gcore/c_abi.h>
}

namespace {

struct AnalyzeResult {
    FlatArena arena;
    size_t count = 0;
    bool ok = false;
};

// ===================== g_entropy_profile =====================

struct EntropyRec {
    uint64_t offset;
    double entropy;
};

void entropy_worker(const uint8_t* base, size_t total, size_t block_size,
                    size_t thread_id, size_t nthreads, FlatArena& out) {
    for (size_t off = thread_id * block_size; off < total; off += nthreads * block_size) {
        const size_t n = (off + block_size <= total) ? block_size : (total - off);
        EntropyRec rec{static_cast<uint64_t>(off), shannon_entropy(base + off, n)};
        out.append(&rec, sizeof(rec));
    }
}

AnalyzeResult run_entropy_profile(const char* path, int block_size, unsigned nthreads) {
    AnalyzeResult r;
    if (block_size < 64) block_size = 64;
    MmapFile file;
    if (!file.open(path)) return r;
    const size_t total = file.size();
    if (total == 0) { r.ok = true; return r; }

    const unsigned hw = std::thread::hardware_concurrency();
    const unsigned n = nthreads ? nthreads : (hw ? hw : 4u);

    std::vector<FlatArena> arenas(n);
    std::vector<std::thread> threads;
    threads.reserve(n);
    for (unsigned i = 0; i < n; ++i) {
        threads.emplace_back([&, i] {
            entropy_worker(file.data(), total, static_cast<size_t>(block_size), i, n, arenas[i]);
        });
    }
    for (auto& t : threads) t.join();

    size_t bytes = 0;
    for (const auto& a : arenas) bytes += a.size();
    if (!r.arena.reserve(bytes)) return r;
    for (const auto& a : arenas) if (a.size()) r.arena.append(a.data(), a.size());
    r.count = bytes / sizeof(EntropyRec);
    r.ok = true;
    return r;
}

// ===================== g_bytes / g_xor =====================

AnalyzeResult run_slice(const char* path, uint64_t offset, uint64_t len, int xor_key) {
    AnalyzeResult r;
    MmapFile file;
    if (!file.open(path)) return r;
    const uint64_t total = file.size();
    if (offset >= total) { r.ok = true; return r; }
    const uint64_t avail = total - offset;
    const uint64_t n = (len == 0 || len > avail) ? avail : len;
    if (!r.arena.reserve(static_cast<size_t>(n))) return r;
    if (xor_key == 0) {
        r.arena.append(file.data() + offset, static_cast<size_t>(n));
    } else {
        const uint8_t* src = file.data() + offset;
        const uint8_t k = static_cast<uint8_t>(xor_key);
        for (uint64_t i = 0; i < n; ++i) {
            const uint8_t b = static_cast<uint8_t>(src[i] ^ k);
            r.arena.append(&b, 1);
        }
    }
    r.count = static_cast<size_t>(n);
    r.ok = true;
    return r;
}

// ===================== g_hash =====================

AnalyzeResult run_hash(const char* path) {
    AnalyzeResult r;
    MmapFile file;
    if (!file.open(path)) return r;
    const uint8_t* p = file.data();
    const size_t n = file.size();

    uint64_t fnv = 1469598103934665603ull;
    uint32_t crc = 0xFFFFFFFFu;
    size_t i = 0;
    for (; i + 8 <= n; i += 8) {
        const uint64_t w = *reinterpret_cast<const uint64_t*>(p + i);
        crc = static_cast<uint32_t>(_mm_crc32_u64(crc, w));
        fnv = (fnv ^ w) * 1099511628211ull;
    }
    for (; i < n; ++i) {
        crc = _mm_crc32_u8(crc, p[i]);
        fnv = (fnv ^ p[i]) * 1099511628211ull;
    }
    crc ^= 0xFFFFFFFFu;

    g_hash_rec rec{fnv, crc};
    if (!r.arena.reserve(sizeof(rec))) return r;
    r.arena.append(&rec, sizeof(rec));
    r.count = 1;
    r.ok = true;
    return r;
}

// ===================== g_hist =====================

void hist_worker(const uint8_t* base, size_t /*total*/, ChunkAllocator& alloc, uint64_t* hist) {
    size_t begin = 0, end = 0;
    while (alloc.next(begin, end)) {
        for (size_t i = begin; i < end; ++i) ++hist[base[i]];
    }
}

AnalyzeResult run_hist(const char* path, unsigned nthreads) {
    AnalyzeResult r;
    MmapFile file;
    if (!file.open(path)) return r;
    const size_t total = file.size();
    if (total == 0) { r.ok = true; return r; }

    const unsigned hw = std::thread::hardware_concurrency();
    const unsigned n = nthreads ? nthreads : (hw ? hw : 4u);
    ChunkAllocator alloc(file.data(), total);
    std::vector<std::array<uint64_t, 256>> hists(n);
    std::vector<std::thread> threads;
    threads.reserve(n);
    for (unsigned i = 0; i < n; ++i) {
        threads.emplace_back([&, i] {
            hist_worker(file.data(), total, alloc, hists[i].data());
        });
    }
    for (auto& t : threads) t.join();

    uint64_t merged[256] = {0};
    for (const auto& h : hists)
        for (int k = 0; k < 256; ++k) merged[k] += h[k];

    if (!r.arena.reserve(sizeof(merged))) return r;
    r.arena.append(merged, sizeof(merged));
    r.count = 256;
    r.ok = true;
    return r;
}

// ===================== g_unicode =====================

struct U16Out {
    FlatArena recs;   // g_strings_rec[]
    size_t count = 0;
};

inline void emit_u16(U16Out& out, const uint8_t* base, size_t start, size_t epos,
                     int min_len, double max_entropy) {
    const size_t len = epos - start;
    if (len < static_cast<size_t>(min_len) * 2) return;
    if (max_entropy >= 0.0 && shannon_entropy(base + start, len) > max_entropy) return;
    g_strings_rec rec{static_cast<uint64_t>(start), static_cast<uint32_t>(len), 0};
    out.recs.append(&rec, sizeof(rec));
    ++out.count;
}

void unicode_worker(const uint8_t* base, size_t /*total*/, ChunkAllocator& alloc,
                    int min_len, double max_entropy, U16Out& out) {
    size_t begin = 0, end = 0;
    while (alloc.next(begin, end)) {
        // UTF-16LE ASCII: символ = пара (low printable, high == 0).
        // Чётность низкого байта фиксирована внутри строки → два независимых
        // сдвига: e0 (чётные пары (2k,2k+1)) и e1 (нечётные (2k+1,2k+2)).
        //   e0: бит 2k = mp[2k] && m0[2k+1]
        //   e1: бит 2k+1 = mp[2k+1] && m0[2k+2]
        // Прогон по парам (шаг 2) — плотный. Блоки по 64 байта (AVX-512).
        bool in0 = false, in1 = false;
        size_t rs0 = 0, rs1 = 0;
        size_t i = begin;
        // SIMD: e1 на k=31 требует байт i+64 → условие i+65 <= end.
        // zero_mask64(base+i) покрывает байты i..i+63; байт i+64 берём из
        // zero_mask64(base+i+1) бит 63 → m0 в uint64 + бит 63 в s1.
        for (; i + 65 <= end; i += 64) {
            const uint64_t mp = printable_mask64(base + i);
            const uint64_t z0 = zero_mask64(base + i);
            const uint64_t z1 = zero_mask64(base + i + 1);
            // m0_lo: бит j = zero(байт i+j), j=0..63 (бит 63 = z1 бит 62)
            const uint64_t m0_lo = z0 | (z1 << 1);
            // s1 бит b = m0_lo бит b+1; бит 63 = zero(байт i+64) = z1 бит 63
            const uint64_t s1 = (m0_lo >> 1) | ((z1 >> 63) << 63);
            const uint64_t e0 = (mp & 0x5555555555555555ull) & (s1 & 0x5555555555555555ull);
            const uint64_t e1 = (mp & 0xAAAAAAAAAAAAAAAAull) & (s1 & 0xAAAAAAAAAAAAAAAAull);
            uint64_t b0 = e0;
            uint64_t b1 = (e1 >> 1);   // нечётные биты → чётные позиции
            for (int k = 0; k < 32; ++k) {
                if (b0 & 1ull) {
                    if (!in0) { in0 = true; rs0 = i + 2 * k; }
                } else if (in0) {
                    emit_u16(out, base, rs0, i + 2 * k, min_len, max_entropy);
                    in0 = false;
                }
                if (b1 & 1ull) {
                    if (!in1) { in1 = true; rs1 = i + 2 * k + 1; }
                } else if (in1) {
                    emit_u16(out, base, rs1, i + 2 * k + 1, min_len, max_entropy);
                    in1 = false;
                }
                b0 >>= 2; b1 >>= 2;
            }
        }
        // хвост (<65 байт): скалярно; чётность позиции выбирает сдвиг
        for (; i + 1 < end; ++i) {
            if (base[i] >= 0x20 && base[i] <= 0x7E && base[i + 1] == 0) {
                if (i & 1u) { if (!in1) { in1 = true; rs1 = i; } }
                else        { if (!in0) { in0 = true; rs0 = i; } }
            } else {
                if (i & 1u) { if (in1) { emit_u16(out, base, rs1, i, min_len, max_entropy); in1 = false; } }
                else        { if (in0) { emit_u16(out, base, rs0, i, min_len, max_entropy); in0 = false; } }
            }
        }
        if (in0) in0 = false;  // строка обрезана границей чанка (редкий случай)
        if (in1) in1 = false;
    }
}

AnalyzeResult run_unicode(const char* path, int min_len, double max_entropy, unsigned nthreads) {
    AnalyzeResult r;
    MmapFile file;
    if (!file.open(path) || min_len < 1) return r;
    const size_t total = file.size();
    if (total == 0) { r.ok = true; return r; }

    const unsigned hw = std::thread::hardware_concurrency();
    const unsigned n = nthreads ? nthreads : (hw ? hw : 4u);
    ChunkAllocator alloc(file.data(), total);
    std::vector<U16Out> workers(n);
    std::vector<std::thread> threads;
    threads.reserve(n);
    for (unsigned i = 0; i < n; ++i) {
        threads.emplace_back([&, i] {
            unicode_worker(file.data(), total, alloc, min_len, max_entropy, workers[i]);
        });
    }
    for (auto& t : threads) t.join();

    size_t bytes = 0, count = 0;
    for (const auto& w : workers) { bytes += w.recs.size(); count += w.count; }
    if (!r.arena.reserve(bytes)) return r;
    for (const auto& w : workers) if (w.recs.size()) r.arena.append(w.recs.data(), w.recs.size());
    // детерминированный порядок по offset
    if (r.arena.size()) {
        auto* recs = reinterpret_cast<g_strings_rec*>(r.arena.data());
        const size_t cnt = r.arena.size() / sizeof(g_strings_rec);
        std::sort(recs, recs + cnt, [](const g_strings_rec& a, const g_strings_rec& b) {
            return a.offset < b.offset;
        });
    }
    r.count = count;
    r.ok = true;
    return r;
}

// ===================== g_sections (ELF/PE) =====================
// Минимальные парсеры без <elf.h>/<winnt.h> — читаем байты напрямую
// с проверкой границ mmap. Офсеты констант:
//   ELF64: e_shoff=0x28, e_shentsize=0x3A, e_shnum=0x3C, e_shstrndx=0x3E
//   ELF32: e_shoff=0x20, e_shentsize=0x2E, e_shnum=0x30, e_shstrndx=0x32
//   shdr64: sh_name@0 u32, sh_type@4 u32, sh_flags@8 u64, sh_offset@0x18 u64, sh_size@0x20 u64
//   shdr32: sh_name@0 u32, sh_type@4 u32, sh_flags@8 u32, sh_offset@0x10 u32, sh_size@0x14 u32
//   PE: e_lfanew@0x3C u32; COFF NumberOfSections@+2 u16, SizeOfOptionalHeader@+20 u16;
//   секция: Name[8]@0, SizeOfRawData@16 u32, PointerToRawData@20 u32, Characteristics@36 u32

inline uint16_t rd16(const uint8_t* p) { uint16_t v; std::memcpy(&v, p, 2); return v; }
inline uint32_t rd32(const uint8_t* p) { uint32_t v; std::memcpy(&v, p, 4); return v; }
inline uint64_t rd64(const uint8_t* p) { uint64_t v; std::memcpy(&v, p, 8); return v; }

bool within(const uint8_t* base, size_t size, const uint8_t* p, size_t n) {
    return p >= base && n <= static_cast<size_t>(base + size - p);
}

// Безопасное копирование имени секции в char[32] (гарантированный NUL).
inline void copy_name(char (&dst)[32], const char* src) {
    const size_t n = std::strlen(src);
    const size_t c = n < sizeof(dst) - 1 ? n : sizeof(dst) - 1;
    std::memcpy(dst, src, c);
    dst[c] = '\0';
}

AnalyzeResult run_sections(const char* path) {
    AnalyzeResult r;
    MmapFile file;
    if (!file.open(path)) return r;
    const uint8_t* base = file.data();
    const size_t size = file.size();
    if (size < 64) { r.ok = true; return r; }

    size_t bytes_needed = 0;
    // пас 1: сколько секций → резервируем арену
    std::vector<g_section_rec> tmp;
    auto section_entropy = [&](uint64_t off, uint64_t sz) -> double {
        if (sz == 0 || off >= size) return 0.0;
        const size_t n = (sz < size - off) ? static_cast<size_t>(sz) : (size - static_cast<size_t>(off));
        return shannon_entropy(base + off, n);
    };

    const bool is_elf = size >= 4 && base[0] == 0x7F && base[1] == 'E' && base[2] == 'L' && base[3] == 'F';
    const bool is_pe = size >= 2 && rd16(base) == 0x5A4D;  // 'MZ'

    if (is_elf) {
        const int cls = base[4];  // 1=32bit, 2=64bit
        if (cls == 1 || cls == 2) {
            const bool is64 = (cls == 2);
            const uint8_t* hdr = base + (is64 ? 0x28 : 0x20);
            if (within(base, size, hdr, is64 ? 8 : 4)) {
                const uint64_t shoff = is64 ? rd64(hdr) : rd32(hdr);
                const uint16_t shentsize = rd16(base + (is64 ? 0x3A : 0x2E));
                const uint16_t shnum = rd16(base + (is64 ? 0x3C : 0x30));
                const uint16_t shstrndx = rd16(base + (is64 ? 0x3E : 0x32));
                const size_t shdr_size = is64 ? 64u : 40u;
                if (shnum > 0 && shentsize >= shdr_size && shoff < size &&
                    static_cast<uint64_t>(shnum) * shentsize <= size - shoff) {
                    const uint8_t* shdr = base + shoff;
                    const uint8_t* strtab = nullptr;
                    size_t strtab_size = 0;
                    if (shstrndx < shnum) {
                        const uint8_t* s = shdr + static_cast<size_t>(shstrndx) * shentsize;
                        const uint64_t soff = is64 ? rd64(s + 0x18) : rd32(s + 0x10);
                        const uint64_t ssz = is64 ? rd64(s + 0x20) : rd32(s + 0x14);
                        if (soff < size && ssz <= size - soff) {
                            strtab = base + soff;
                            strtab_size = static_cast<size_t>(ssz);
                        }
                    }
                    tmp.reserve(shnum);
                    for (uint16_t i = 0; i < shnum; ++i) {
                        const uint8_t* s = shdr + static_cast<size_t>(i) * shentsize;
                        const uint32_t name_off = rd32(s);
                        const uint32_t stype = rd32(s + 4);
                        const uint64_t flags = is64 ? rd64(s + 8) : rd32(s + 8);
                        const uint64_t soff = is64 ? rd64(s + 0x18) : rd32(s + 0x10);
                        const uint64_t ssz = is64 ? rd64(s + 0x20) : rd32(s + 0x14);
                        char name[32] = {0};
                        if (strtab && name_off < strtab_size) {
                            std::strncpy(name, reinterpret_cast<const char*>(strtab + name_off), sizeof(name) - 1);
                        }
                        uint32_t type = 5;  // other
                        if (stype == 8) {          // SHT_NOBITS (bss)
                            type = 5;
                        } else if (stype == 1) {   // SHT_PROGBITS
                            type = (flags & 0x4u) ? 0 : 1;  // SHF_EXECINSTR → code
                        }
                        g_section_rec rec{};
                        rec.offset = soff;
                        rec.size = ssz;
                        rec.entropy = section_entropy(soff, ssz);
                        rec.type = type;
                        copy_name(rec.name, name);
                        tmp.push_back(rec);
                    }
                }
            }
        }
    } else if (is_pe && size >= 0x40) {
        const uint32_t e_lfanew = rd32(base + 0x3C);
        const uint8_t* pe = base + e_lfanew;
        if (within(base, size, pe, 24) && rd32(pe) == 0x00004550u) {  // 'PE\0\0'
            const uint16_t nsects = rd16(pe + 6);
            const uint16_t opt_size = rd16(pe + 20);
            const uint8_t* shdr = pe + 24 + opt_size;
            const size_t shdr_bytes = static_cast<size_t>(nsects) * 40u;
            if (within(base, size, shdr, shdr_bytes)) {
                tmp.reserve(nsects);
                for (uint16_t i = 0; i < nsects; ++i) {
                    const uint8_t* s = shdr + static_cast<size_t>(i) * 40u;
                    char name[9] = {0};
                    std::memcpy(name, s, 8);
                    const uint64_t raw_size = rd32(s + 16);
                    const uint64_t raw_ptr = rd32(s + 20);
                    const uint32_t chars = rd32(s + 36);
                    uint32_t type = 5;
                    if (chars & 0x20000000u) type = 2;          // IMAGE_SCN_MEM_EXECUTE
                    else if (chars & 0x40u) type = 3;           // IMAGE_SCN_CNT_INITIALIZED_DATA
                    if (std::strncmp(name, ".rsrc", 5) == 0) type = 4;
                    g_section_rec rec{};
                    rec.offset = raw_ptr;
                    rec.size = raw_size;
                    rec.entropy = section_entropy(raw_ptr, raw_size);
                    rec.type = type;
                    copy_name(rec.name, name);
                    tmp.push_back(rec);
                }
            }
        }
    }

    bytes_needed = tmp.size() * sizeof(g_section_rec);
    if (!r.arena.reserve(bytes_needed)) return r;
    for (const auto& rec : tmp) r.arena.append(&rec, sizeof(rec));
    r.count = tmp.size();
    r.ok = true;
    return r;
}

// ===================== g_diff =====================

AnalyzeResult run_diff(const char* path_a, const char* path_b, int block_size) {
    AnalyzeResult r;
    if (block_size < 1) block_size = 4096;
    const size_t bs = static_cast<size_t>(block_size);
    MmapFile fa, fb;
    if (!fa.open(path_a) || !fb.open(path_b)) return r;
    const uint8_t* a = fa.data();
    const uint8_t* b = fb.data();
    const size_t sa = fa.size(), sb = fb.size();
    const size_t na = (sa + bs - 1) / bs;
    const size_t nb = (sb + bs - 1) / bs;
    const size_t common = std::min(na, nb);

    // Пары блоков: копируем в std::vector, пакуем SAME/CHANGED (SAME не пишем,
    // только группируем изменённые диапазоны). Вставки/удаления — хвосты.
    struct Run { uint64_t oa, ob; uint32_t len; uint8_t st; };
    std::vector<Run> runs;
    for (size_t i = 0; i < common; ++i) {
        const size_t boff = i * bs;
        const size_t na2 = std::min(bs, sa - boff);
        const size_t nb2 = std::min(bs, sb - boff);
        const bool eq = (na2 == nb2) && std::memcmp(a + boff, b + boff, na2) == 0;
        const uint8_t st = eq ? G_DIFF_SAME : G_DIFF_CHANGED;
        if (!runs.empty() && runs.back().st == st && runs.back().ob + runs.back().len == boff) {
            runs.back().len += static_cast<uint32_t>(bs);
        } else if (st == G_DIFF_CHANGED) {
            runs.push_back(Run{static_cast<uint64_t>(boff), static_cast<uint64_t>(boff), static_cast<uint32_t>(bs), st});
        }
    }
    if (na > nb) {
        const size_t boff = common * bs;
        const uint32_t len = static_cast<uint32_t>(sa - boff);
        runs.push_back(Run{static_cast<uint64_t>(boff), 0, len, G_DIFF_DELETED});
    } else if (nb > na) {
        const size_t boff = common * bs;
        const uint32_t len = static_cast<uint32_t>(sb - boff);
        runs.push_back(Run{0, static_cast<uint64_t>(boff), len, G_DIFF_INSERTED});
    }

    const size_t bytes_needed = runs.size() * sizeof(g_diff_rec);
    if (!r.arena.reserve(bytes_needed)) return r;
    for (const auto& run : runs) {
        g_diff_rec rec{run.oa, run.ob, run.len, run.st};
        r.arena.append(&rec, sizeof(rec));
    }
    r.count = runs.size();
    r.ok = true;
    return r;
}

// ===================== g_recon =====================

AnalyzeResult run_recon(const char* path, int entropy_block) {
    AnalyzeResult r;
    MmapFile file;
    if (!file.open(path)) return r;
    const uint8_t* base = file.data();
    const size_t total = file.size();
    if (total == 0) { r.ok = true; return r; }
    if (entropy_block < 4096) entropy_block = 4096;

    uint64_t fnv = 1469598103934665603ull;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < total; ++i) {
        crc = _mm_crc32_u8(crc, base[i]);
        fnv = (fnv ^ base[i]) * 1099511628211ull;
    }
    crc ^= 0xFFFFFFFFu;

    uint64_t hist[256] = {0};
    for (size_t i = 0; i < total; ++i) ++hist[base[i]];

    size_t n_entropy = (total + static_cast<size_t>(entropy_block) - 1) / static_cast<size_t>(entropy_block);
    if (n_entropy == 0) n_entropy = 1;

    FlatArena str_arena;
    str_arena.reserve(total / 8);
    size_t str_count = 0;
    bool in_str = false;
    size_t run_start = 0;
    for (size_t i = 0; i < total; ++i) {
        const uint8_t c = base[i];
        const bool p = (c >= 0x20 && c <= 0x7E);
        if (p) {
            if (!in_str) { in_str = true; run_start = i; }
        } else {
            if (in_str) {
                const size_t len = i - run_start;
                if (len >= 4 && str_count < 2000) {
                    g_strings_rec rec{static_cast<uint64_t>(run_start), static_cast<uint32_t>(len), 0};
                    str_arena.append(&rec, sizeof(rec));
                    ++str_count;
                }
                in_str = false;
            }
        }
    }
    if (in_str && str_count < 2000) {
        const size_t len = total - run_start;
        if (len >= 4) {
            g_strings_rec rec{static_cast<uint64_t>(run_start), static_cast<uint32_t>(len), 0};
            str_arena.append(&rec, sizeof(rec));
            ++str_count;
        }
    }

    const size_t header_size = sizeof(g_recon_header);
    const size_t hist_size = 256 * sizeof(uint64_t);
    const size_t ent_size = n_entropy * sizeof(g_entropy_rec);
    const size_t str_size = str_arena.size();
    const size_t total_bytes = header_size + hist_size + ent_size + str_size;

    if (!r.arena.reserve(total_bytes)) return r;

    g_recon_header hdr{};
    hdr.fnv1a64 = fnv;
    hdr.crc32c = crc;
    hdr.n_hist = 256;
    hdr.n_entropy = static_cast<uint32_t>(n_entropy);
    hdr.n_strings = static_cast<uint32_t>(str_count);
    r.arena.append(&hdr, sizeof(hdr));
    r.arena.append(hist, hist_size);

    for (size_t b = 0; b < n_entropy; ++b) {
        const size_t off = b * static_cast<size_t>(entropy_block);
        const size_t n = (off + entropy_block <= total) ? static_cast<size_t>(entropy_block) : (total - off);
        g_entropy_rec er{static_cast<uint64_t>(off), shannon_entropy(base + off, n)};
        r.arena.append(&er, sizeof(er));
    }

    if (str_size) r.arena.append(str_arena.data(), str_size);

    r.count = str_count;
    r.ok = true;
    return r;
}

// ===================== C-ABI =====================

} // namespace

extern "C" {

g_result g_entropy_profile(const char* path, int block_size) {
    AnalyzeResult r = run_entropy_profile(path, block_size, 0);
    g_result out{};
    if (!r.ok) return out;
    auto* arena = new gcore::FlatArena(std::move(r.arena));
    out.owner = arena; out.data = arena->data(); out.size = arena->size();
    out.capacity = arena->capacity(); out.count = r.count;
    return out;
}

g_result g_bytes(const char* path, uint64_t offset, uint64_t len) {
    AnalyzeResult r = run_slice(path, offset, len, 0);
    g_result out{};
    if (!r.ok) return out;
    auto* arena = new gcore::FlatArena(std::move(r.arena));
    out.owner = arena; out.data = arena->data(); out.size = arena->size();
    out.capacity = arena->capacity(); out.count = r.count;
    return out;
}

g_result g_xor(const char* path, uint64_t offset, uint64_t len, int key) {
    AnalyzeResult r = run_slice(path, offset, len, key);
    g_result out{};
    if (!r.ok) return out;
    auto* arena = new gcore::FlatArena(std::move(r.arena));
    out.owner = arena; out.data = arena->data(); out.size = arena->size();
    out.capacity = arena->capacity(); out.count = r.count;
    return out;
}

g_result g_hash(const char* path) {
    AnalyzeResult r = run_hash(path);
    g_result out{};
    if (!r.ok) return out;
    auto* arena = new gcore::FlatArena(std::move(r.arena));
    out.owner = arena; out.data = arena->data(); out.size = arena->size();
    out.capacity = arena->capacity(); out.count = r.count;
    return out;
}

g_result g_hist(const char* path) {
    AnalyzeResult r = run_hist(path, 0);
    g_result out{};
    if (!r.ok) return out;
    auto* arena = new gcore::FlatArena(std::move(r.arena));
    out.owner = arena; out.data = arena->data(); out.size = arena->size();
    out.capacity = arena->capacity(); out.count = r.count;
    return out;
}

g_result g_unicode(const char* path, int min_len, double max_entropy) {
    AnalyzeResult r = run_unicode(path, min_len, max_entropy, 0);
    g_result out{};
    if (!r.ok) return out;
    auto* arena = new gcore::FlatArena(std::move(r.arena));
    out.owner = arena; out.data = arena->data(); out.size = arena->size();
    out.capacity = arena->capacity(); out.count = r.count;
    return out;
}

g_result g_sections(const char* path) {
    AnalyzeResult r = run_sections(path);
    g_result out{};
    if (!r.ok) return out;
    auto* arena = new gcore::FlatArena(std::move(r.arena));
    out.owner = arena; out.data = arena->data(); out.size = arena->size();
    out.capacity = arena->capacity(); out.count = r.count;
    return out;
}

g_result g_diff(const char* path_a, const char* path_b, int block_size) {
    AnalyzeResult r = run_diff(path_a, path_b, block_size);
    g_result out{};
    if (!r.ok) return out;
    auto* arena = new gcore::FlatArena(std::move(r.arena));
    out.owner = arena; out.data = arena->data(); out.size = arena->size();
    out.capacity = arena->capacity(); out.count = r.count;
    return out;
}

g_result g_recon(const char* path, int entropy_block) {
    AnalyzeResult r = run_recon(path, entropy_block);
    g_result out{};
    if (!r.ok) return out;
    auto* arena = new gcore::FlatArena(std::move(r.arena));
    out.owner = arena; out.data = arena->data(); out.size = arena->size();
    out.capacity = arena->capacity(); out.count = r.count;
    return out;
}

} // extern "C"
