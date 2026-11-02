// fuzz_api.cpp — детерминированный API-фаззер C-ABI нод g-tools.
//
// Идея: генерировать случайные (валидные) файлы и параметры, вызывать ноды
// и проверять ИНВАРИАНТЫ контракта (не только отсутствие крашей):
//   - g_grep_count == reference-подсчёт по строкам (chunk-границы не режут строки)
//   - g_strings == reference-сканер printable-забегов (максимальность, сортировка)
//   - g_entropy_profile: число блоков, монотонность офсетов, энтропия в [0,8]
//   - g_bytes/g_xor: размер среза == min(len|0->avail, avail), xor-байты точны
//   - g_hash: FNV-1a64/CRC32C совпадают с reference на случайных данных
//   - g_hist: сумма баров == размер файла
//   - g_scan: все совпадения найдены (равенство с наивным поиском), без дублей
//   - g_diff: статусы только из enum, офсеты в границах
//
// Детерминизм: seed фиксирован; одинаковый прогон на любой машине.
// В CI крутится 3000 итераций (~1-2 c в Release). Для локального прогона
// подольше: ./fuzz_api <iterations> [seed].
#include <gcore/gcore.h>

extern "C" {
#include <gcore/c_abi.h>
}

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

struct Rng {
    uint64_t s;
    explicit Rng(uint64_t seed) : s(seed ^ 0x9E3779B97F4A7C15ull) {}
    uint64_t next() {
        s += 0x9E3779B97F4A7C15ull;
        uint64_t z = s;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }
    uint32_t below(uint32_t n) { return n ? static_cast<uint32_t>(next() % n) : 0; }
};

int failures = 0;
std::filesystem::path g_tmp;

void fail(int iter, const char* what, const char* detail) {
    ++failures;
    std::fprintf(stderr, "FAIL iter=%d: %s (%s)\n", iter, what, detail);
}

void write_file(const char* name, const std::string& bytes) {
    std::ifstream probe(g_tmp / name, std::ios::binary);
    std::ofstream f(g_tmp / name, std::ios::binary | std::ios::trunc);
    f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

// --- reference-хэши (см. test_analyze.cpp) ---
// Как в run_hash: FNV-1a по u64-словам (LE) + побайтовый хвост.
uint64_t ref_fnv1a64(const uint8_t* d, size_t n) {
    uint64_t h = 1469598103934665603ull;
    size_t i = 0;
    for (; i + 8 <= n; i += 8) {
        uint64_t w;
        std::memcpy(&w, d + i, 8);
        h = (h ^ w) * 1099511628211ull;
    }
    for (; i < n; ++i) h = (h ^ d[i]) * 1099511628211ull;
    return h;
}

uint32_t ref_crc32c(const uint8_t* d, size_t n) {
    static uint32_t table[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (0x82F63B78u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        init = true;
    }
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; ++i) c = table[(c ^ d[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

double ref_shannon(const uint8_t* d, size_t n) {
    if (n == 0) return 0.0;
    double cnt[256] = {0};
    for (size_t i = 0; i < n; ++i) cnt[d[i]] += 1.0;
    double e = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (cnt[i] > 0) {
            const double p = cnt[i] / static_cast<double>(n);
            e -= p * std::log2(p);
        }
    }
    return e;
}

// --- генераторы входа ---

// Смесь текста и бинарного мусора: строки с случайной длиной, случайные байты.
std::string gen_mixed(Rng& rng) {
    const size_t n_lines = rng.below(64);
    std::string s;
    for (size_t i = 0; i < n_lines; ++i) {
        const uint32_t kind = rng.below(4);
        const uint32_t len = rng.below(70);
        for (uint32_t j = 0; j < len; ++j) {
            if (kind == 0) s += static_cast<char>(' ' + rng.below(95));   // printable
            else if (kind == 1) s += static_cast<char>(rng.below(256));   // бинарь
            else if (kind == 2) s += static_cast<char>('a' + rng.below(26));
            else s += (rng.below(8) ? static_cast<char>('0' + rng.below(10)) : '\t');
        }
        if (rng.below(16) != 0) s += '\n';  // иногда без \n — граница файла
    }
    return s;
}

std::string gen_needle(Rng& rng, const std::string& hay) {
    if (hay.empty()) return "x";
    const uint32_t start = rng.below(static_cast<uint32_t>(hay.size()));
    uint32_t len = 1 + rng.below(6);
    if (start + len > hay.size()) len = static_cast<uint32_t>(hay.size()) - start;
    std::string needle = hay.substr(start, len);
    // \n не допускаем (не строковый поиск); \0 нельзя — C-ABI (const char*)
    // обрезает строку на первом NUL, такой needle невыговариваем через ABI
    needle.erase(std::remove_if(needle.begin(), needle.end(),
                                [](char c) { return c == '\n' || c == '\0'; }),
                 needle.end());
    if (needle.empty()) return "q";
    return needle;
}

size_t ref_grep_count(const std::string& hay, const std::string& needle) {
    size_t count = 0;
    size_t pos = 0;
    while (pos <= hay.size()) {
        size_t eol = hay.find('\n', pos);
        if (eol == std::string::npos) eol = hay.size();
        if (needle.size() > 0 && eol - pos >= 0 &&
            hay.find(needle, pos) != std::string::npos &&
            hay.find(needle, pos) < eol) {
            ++count;
        }
        if (eol == hay.size()) break;
        pos = eol + 1;
    }
    return count;
}

std::vector<std::pair<uint64_t, uint32_t>> ref_strings(const std::string& hay, int min_len) {
    std::vector<std::pair<uint64_t, uint32_t>> out;
    size_t i = 0;
    while (i < hay.size()) {
        if (hay[i] >= 0x20 && hay[i] <= 0x7E) {
            const size_t start = i;
            while (i < hay.size() && hay[i] >= 0x20 && hay[i] <= 0x7E) ++i;
            if (i - start >= static_cast<size_t>(min_len)) {
                out.emplace_back(start, static_cast<uint32_t>(i - start));
            }
        } else {
            ++i;
        }
    }
    return out;
}

void free_ok(g_result r, int iter, const char* what) {
    if (r.owner == nullptr && (r.data != nullptr)) {
        fail(iter, what, "data != NULL без owner");
    }
    g_result_free(&r);
}

}  // namespace

int main(int argc, char** argv) {
    const int iterations = (argc > 1) ? std::atoi(argv[1]) : 3000;
    const uint64_t seed = (argc > 2) ? std::strtoull(argv[2], nullptr, 10) : 0xC0FFEE;
    g_tmp = std::filesystem::temp_directory_path() / "gtools_fuzz";
    std::filesystem::create_directories(g_tmp);

    Rng rng(seed);
    for (int iter = 0; iter < iterations && failures == 0; ++iter) {
        const std::string hay = gen_mixed(rng);
        const auto path = (g_tmp / "fuzz_input.bin").string();
        write_file("fuzz_input.bin", hay);
        const char* p = path.c_str();

        // --- g_grep_count vs reference ---
        const std::string needle = gen_needle(rng, hay);
        const int64_t got = g_grep_count(p, needle.c_str());
        const size_t want = ref_grep_count(hay, needle);
        if (got < 0 || static_cast<size_t>(got) != want) {
            fail(iter, "g_grep_count", needle.c_str());
        }

        // --- g_strings vs reference-сканер ---
        const int min_len = 1 + static_cast<int>(rng.below(8));
        g_result r = g_strings(p, min_len, -1.0);
        {
            const auto want_s = ref_strings(hay, min_len);
            if (r.count != want_s.size()) {
                fail(iter, "g_strings count", "count mismatch");
            } else if (r.data) {
                const auto* recs = reinterpret_cast<const g_strings_rec*>(r.data);
                for (size_t i = 0; i < want_s.size(); ++i) {
                    if (recs[i].offset != want_s[i].first || recs[i].len != want_s[i].second) {
                        fail(iter, "g_strings rec", "offset/len mismatch");
                        break;
                    }
                }
            }
        }
        free_ok(r, iter, "g_strings");

        // --- g_entropy_profile ---
        const int block = 64 << rng.below(7);  // 64..8192
        r = g_entropy_profile(p, block);
        {
            const size_t nblocks = (hay.size() + block - 1) / block;
            if (r.count != nblocks) fail(iter, "g_entropy_profile count", "block mismatch");
            if (r.data) {
                const auto* recs = reinterpret_cast<const g_entropy_rec*>(r.data);
                for (size_t i = 0; i < r.count; ++i) {
                    if (recs[i].offset != i * static_cast<uint64_t>(block)) {
                        fail(iter, "g_entropy_profile offset", "не монотонно");
                        break;
                    }
                    if (recs[i].entropy < 0.0 || recs[i].entropy > 8.0) {
                        fail(iter, "g_entropy_profile entropy", "вне [0,8]");
                        break;
                    }
                }
            }
        }
        free_ok(r, iter, "g_entropy_profile");

        // --- g_bytes / g_xor ---
        const uint64_t off = rng.below(static_cast<uint32_t>(hay.size() + 2));
        const uint64_t len = rng.below(256);
        const int key = static_cast<int>(rng.below(255)) + 1;
        r = g_xor(p, off, len, key);
        {
            const uint64_t avail = off < hay.size() ? hay.size() - off : 0;
            const uint64_t n = (len == 0 || len > avail) ? avail : len;
            if (r.count != n || r.size != n) fail(iter, "g_xor size", "размер среза");
            if (r.data && n > 0) {
                for (uint64_t i = 0; i < n; ++i) {
                    if (r.data[i] != (static_cast<uint8_t>(hay[off + i]) ^ static_cast<uint8_t>(key))) {
                        fail(iter, "g_xor bytes", "xor mismatch");
                        break;
                    }
                }
            }
        }
        free_ok(r, iter, "g_xor");

        // --- g_hash vs reference ---
        r = g_hash(p);
        if (r.count == 1 && r.data) {
            const auto* h = reinterpret_cast<const g_hash_rec*>(r.data);
            if (h->fnv1a64 != ref_fnv1a64(reinterpret_cast<const uint8_t*>(hay.data()), hay.size())) {
                fail(iter, "g_hash fnv1a64", "mismatch");
            }
            if (h->crc32c != ref_crc32c(reinterpret_cast<const uint8_t*>(hay.data()), hay.size())) {
                fail(iter, "g_hash crc32c", "mismatch");
            }
        }
        free_ok(r, iter, "g_hash");

        // --- g_hist: сумма == размер ---
        r = g_hist(p);
        if (r.count == 256 && r.data) {
            const auto* h = reinterpret_cast<const uint64_t*>(r.data);
            uint64_t sum = 0;
            for (int i = 0; i < 256; ++i) sum += h[i];
            if (sum != hay.size()) fail(iter, "g_hist sum", "не равно размеру");
        }
        free_ok(r, iter, "g_hist");

        // --- g_scan: равенство с наивным поиском ---
        {
            const std::string p1 = gen_needle(rng, hay);
            std::string p2 = gen_needle(rng, hay);
            if (p2 == p1) p2 += "!";
            const char* pats[2] = {p1.c_str(), p2.c_str()};
            r = g_scan(p, pats, 2);
            std::vector<std::pair<uint64_t, uint32_t>> want;
            for (const char* pat : pats) {
                if (std::strlen(pat) == 0) continue;
                for (size_t pos = hay.find(pat); pos != std::string::npos;
                     pos = hay.find(pat, pos + 1)) {
                    want.emplace_back(pos, pat == pats[0] ? 0u : 1u);
                }
            }
            std::sort(want.begin(), want.end());
            if (r.count != want.size()) {
                fail(iter, "g_scan count", "не все совпадения найдены");
            } else if (r.data) {
                const auto* s = reinterpret_cast<const g_scan_rec*>(r.data);
                // вывод может идти в порядке AC fail-chain на том же end-position —
                // сравниваем как упорядоченные мультимножества
                std::vector<std::pair<uint64_t, uint32_t>> got;
                for (size_t i = 0; i < r.count; ++i) got.emplace_back(s[i].offset, s[i].pattern_idx);
                std::sort(got.begin(), got.end());
                if (got != want) {
                    for (size_t i = 0; i < got.size() && i < 8; ++i) {
                        std::fprintf(stderr, "  got (%llu,%u) want (%llu,%u)\n",
                                     (unsigned long long)got[i].first, got[i].second,
                                     (unsigned long long)want[i].first, want[i].second);
                    }
                    fail(iter, "g_scan rec", "offset/pattern mismatch");
                }
            }
            free_ok(r, iter, "g_scan");
        }

        // --- g_diff: границы и статусы ---
        {
            const std::string hay2 = gen_mixed(rng);
            const auto path2 = (g_tmp / "fuzz_input_b.bin").string();
            write_file("fuzz_input_b.bin", hay2);
            r = g_diff(p, path2.c_str(), static_cast<int>(64 << rng.below(6)));
            if (r.data) {
                const auto* d = reinterpret_cast<const g_diff_rec*>(r.data);
                for (size_t i = 0; i < r.count; ++i) {
                    if (d[i].status > G_DIFF_DELETED) fail(iter, "g_diff status", "вне enum");
                    if (d[i].offset_a >= hay.size() + 4096 || d[i].offset_b >= hay2.size() + 4096) {
                        fail(iter, "g_diff offset", "вне границ");
                        break;
                    }
                }
            }
            free_ok(r, iter, "g_diff");
        }
    }

    if (failures == 0) {
        std::printf("fuzz_api: %d iterations, all invariants held\n", iterations);
        return 0;
    }
    std::printf("fuzz_api: %d failures (seed %llu)\n", failures,
                static_cast<unsigned long long>(seed));
    return 1;
}
