// g-scan — мультипаттернный SIMD-скан (Aho-Corasick + skip по первым байтам).
// Конвейер: mmap → SIMD-skip (64 Б/такт) → AC-verify кандидатов → арена.
// Для RE-разведки: найти все вхождения набора сигнатур (magic bytes,
// строки, YARA-подобные правила) за один проход.
#include <gcore/gcore.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <queue>
#include <string>
#include <vector>

extern "C" {
#include <gcore/c_abi.h>
}

using gcore::FlatArena;
using gcore::MmapFile;

namespace {

struct AnalyzeResult {
    FlatArena arena;
    size_t count = 0;
    bool ok = false;
};

struct ACNode {
    int   next[256];  // -1 = нет перехода (заменяется на fail-переход)
    int   fail;
    int   output;     // индекс в output_list (-1 = нет)
    ACNode() : fail(0), output(-1) { std::fill(std::begin(next), std::end(next), -1); }
};

struct AC {
    std::vector<ACNode> nodes;
    std::vector<int>    output_pat;  // pattern_idx для каждого output
    std::vector<int>    output_next; // следующий output на fail-chain
    std::vector<int>    pat_len;     // длина каждого паттерна

    AC() { nodes.emplace_back(); }  // root = 0

    int add_pattern(const uint8_t* data, size_t len, int pattern_idx) {
        int cur = 0;
        for (size_t i = 0; i < len; ++i) {
            int c = data[i];
            if (nodes[cur].next[c] == -1) {
                nodes[cur].next[c] = static_cast<int>(nodes.size());
                nodes.emplace_back();
            }
            cur = nodes[cur].next[c];
        }
        pat_len.push_back(static_cast<int>(len));
        output_pat.push_back(pattern_idx);
        int idx = static_cast<int>(output_pat.size()) - 1;
        output_next.push_back(nodes[cur].output);
        nodes[cur].output = idx;
        return idx;
    }

    void build() {
        std::queue<int> q;
        for (int c = 0; c < 256; ++c) {
            if (nodes[0].next[c] != -1) {
                nodes[nodes[0].next[c]].fail = 0;
                q.push(nodes[0].next[c]);
            } else {
                nodes[0].next[c] = 0;
            }
        }
        while (!q.empty()) {
            int u = q.front(); q.pop();
            for (int c = 0; c < 256; ++c) {
                int v = nodes[u].next[c];
                if (v == -1) continue;
                int f = nodes[u].fail;
                while (nodes[f].next[c] == -1 && f != 0)
                    f = nodes[f].fail;
                if (nodes[f].next[c] != -1 && nodes[f].next[c] != v)
                    nodes[v].fail = nodes[f].next[c];
                else
                    nodes[v].fail = 0;
                q.push(v);
            }
        }
    }
};

// ---- Skip-фильтр по первым байтам паттернов ----

struct SkipFilter {
    uint8_t fb[256];  // fb[b] = 1 если b — первый байт какого-то паттерна
    bool    any;
    SkipFilter() : any(false) { std::memset(fb, 0, sizeof(fb)); }
    void add(uint8_t b) { fb[b] = 1; any = true; }
};

// ---- Сканирование ----

AnalyzeResult run_scan(const char* path, const char* const* patterns, int pattern_count) {
    AnalyzeResult r;
    if (pattern_count <= 0) { r.ok = true; return r; }

    MmapFile file;
    if (!file.open(path)) return r;
    const uint8_t* base = file.data();
    const size_t total = file.size();
    if (total == 0) { r.ok = true; return r; }

    AC ac;
    SkipFilter sf;
    for (int i = 0; i < pattern_count; ++i) {
        const size_t plen = std::strlen(patterns[i]);
        if (plen == 0) continue;
        ac.add_pattern(reinterpret_cast<const uint8_t*>(patterns[i]), plen, i);
        sf.add(static_cast<uint8_t>(patterns[i][0]));
    }
    ac.build();

    FlatArena out;
    out.reserve(total / 16);
    size_t count = 0;

    // Уникальные первые байты — один раз
    uint8_t uniq[256];
    int n_uniq = 0;
    if (sf.any) {
        for (int b = 0; b < 256; ++b)
            if (sf.fb[b]) uniq[n_uniq++] = static_cast<uint8_t>(b);
    }

    // Один непрерывный прогон AC по файлу. SIMD-mask — только гейт:
    // блок пропускается целиком, если в нём нет ни одного первого байта
    // паттерна И автомат не в частичном совпадении (state == 0).
    // ВАЖНО: state живёт между блоками — паттерн, начавшийся в блоке N,
    // корректно завершается в блоке N+1 (пересечение границ не теряется).
    int state = 0;
    size_t pos = 0;
    for (; pos + 64 <= total; pos += 64) {
        uint64_t mask = 0;
        if (sf.any) {
#ifdef __AVX2__
            const __m256i block0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(base + pos));
            for (int j = 0; j < std::min(32, n_uniq); ++j) {
                const __m256i t = _mm256_set1_epi8(static_cast<char>(uniq[j]));
                mask |= static_cast<uint32_t>(_mm256_movemask_epi8(_mm256_cmpeq_epi8(block0, t)));
            }
            const __m256i block1 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(base + pos + 32));
            int start = (n_uniq > 32) ? 32 : 0;
            for (int j = start; j < n_uniq; ++j) {
                const __m256i t = _mm256_set1_epi8(static_cast<char>(uniq[j]));
                mask |= static_cast<uint64_t>(static_cast<uint32_t>(
                    _mm256_movemask_epi8(_mm256_cmpeq_epi8(block1, t)))) << 32;
            }
#else
            for (size_t i = 0; i < 64; ++i)
                if (sf.fb[base[pos + i]]) mask |= (1ull << i);
#endif
        }
        if (mask == 0 && state == 0) continue;

        for (size_t k = 0; k < 64; ++k) {
            int c = base[pos + k];
            while (ac.nodes[state].next[c] == -1 && state != 0)
                state = ac.nodes[state].fail;
            if (ac.nodes[state].next[c] != -1)
                state = ac.nodes[state].next[c];
            // Все outputs на fail-цепочке (не обрываемся на первом без output)
            int u = state;
            while (u != 0) {
                int cur = ac.nodes[u].output;
                while (cur != -1) {
                    size_t plen = static_cast<size_t>(ac.pat_len[ac.output_pat[cur]]);
                    uint64_t match_off = pos + k - (plen - 1);
                    g_scan_rec rec{match_off, static_cast<uint32_t>(ac.output_pat[cur]), 0};
                    out.append(&rec, sizeof(rec));
                    ++count;
                    cur = ac.output_next[cur];
                }
                u = ac.nodes[u].fail;
            }
        }
    }

    // Хвост (< 64 байта): продолжаем то же состояние автомата
    for (; pos < total; ++pos) {
        int c = base[pos];
        while (ac.nodes[state].next[c] == -1 && state != 0)
            state = ac.nodes[state].fail;
        if (ac.nodes[state].next[c] != -1) state = ac.nodes[state].next[c];

        int u = state;
        while (u != 0) {
            int cur = ac.nodes[u].output;
            while (cur != -1) {
                size_t plen = static_cast<size_t>(ac.pat_len[ac.output_pat[cur]]);
                uint64_t match_off = pos - (plen - 1);
                g_scan_rec rec{match_off, static_cast<uint32_t>(ac.output_pat[cur]), 0};
                out.append(&rec, sizeof(rec));
                ++count;
                cur = ac.output_next[cur];
            }
            u = ac.nodes[u].fail;
        }
    }

    if (!r.arena.reserve(out.size())) return r;
    if (out.size()) r.arena.append(out.data(), out.size());
    r.count = count;
    r.ok = true;
    return r;
}

} // namespace

extern "C" {

g_result g_scan(const char* path, const char* const* patterns, int pattern_count) {
    AnalyzeResult r = run_scan(path, patterns, pattern_count);
    g_result out{};
    if (!r.ok) return out;
    auto* arena = new gcore::FlatArena(std::move(r.arena));
    out.owner = arena; out.data = arena->data(); out.size = arena->size();
    out.capacity = arena->capacity(); out.count = r.count;
    return out;
}

} // extern "C"
