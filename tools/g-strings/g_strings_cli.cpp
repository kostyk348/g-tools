// g_strings_cli.cpp — CLI: g-strings [--min N] [--max-entropy E] [--count] <file>
#include <gcore/gcore.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" g_result g_strings(const char*, int, double);
extern "C" int64_t g_strings_count(const char*, int, double);

namespace {

void usage(const char* prog) {
    std::fprintf(stderr,
        "g-strings — SIMD-извлечение printable-строк из бинарника (mmap, zero-copy)\n"
        "Usage: %s [--min N] [--max-entropy E] [--count] <file>\n"
        "  --min N          минимальная длина строки (по умолчанию 4, как GNU strings)\n"
        "  --max-entropy E  отсев строк с энтропией Шеннона > E (по умолчанию выкл)\n"
        "  --count          только число строк\n"
        "  --bin            вывод в бинарном формате: g_strings_rec[] (для пайплайнов)\n",
        prog);
}

} // namespace

int main(int argc, char** argv) {
    int min_len = 4;
    double max_entropy = -1.0;
    bool count_only = false;
    bool bin_out = false;
    const char* path = nullptr;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--min") == 0 && i + 1 < argc) {
            min_len = std::atoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--max-entropy") == 0 && i + 1 < argc) {
            max_entropy = std::strtod(argv[++i], nullptr);
        } else if (std::strcmp(argv[i], "--count") == 0) {
            count_only = true;
        } else if (std::strcmp(argv[i], "--bin") == 0) {
            bin_out = true;
        } else if (std::strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            path = argv[i];
        }
    }
    if (!path) { usage(argv[0]); return 2; }

    const auto t0 = std::chrono::steady_clock::now();
    if (count_only) {
        const int64_t c = g_strings_count(path, min_len, max_entropy);
        if (c < 0) { std::fprintf(stderr, "g-strings: не удалось открыть %s\n", path); return 1; }
        std::printf("%lld\n", static_cast<long long>(c));
        const auto t1 = std::chrono::steady_clock::now();
        std::fprintf(stderr, "g-strings: %lld strings in %.2f ms\n",
                     static_cast<long long>(c),
                     std::chrono::duration<double, std::milli>(t1 - t0).count());
        return 0;
    }

    g_result r = g_strings(path, min_len, max_entropy);
    if (!r.data) { std::fprintf(stderr, "g-strings: не удалось открыть %s\n", path); return 1; }

    // Строки печатаем из собственного mmap (нужен доступ к байтам файла)
    gcore::MmapFile file;
    if (!bin_out && !file.open(path)) { g_result_free(&r); return 1; }

    auto* recs = reinterpret_cast<const g_strings_rec*>(r.data);
    const size_t cnt = r.size / sizeof(g_strings_rec);
    for (size_t i = 0; i < cnt; ++i) {
        if (bin_out) {
            std::fwrite(&recs[i], sizeof(g_strings_rec), 1, stdout);
        } else {
            std::printf("0x%08llx\t%u\t%.*s\n",
                        static_cast<unsigned long long>(recs[i].offset),
                        recs[i].len,
                        static_cast<int>(recs[i].len),
                        reinterpret_cast<const char*>(file.data() + recs[i].offset));
        }
    }
    const auto t1 = std::chrono::steady_clock::now();
    std::fprintf(stderr, "g-strings: %zu strings in %.2f ms\n", cnt,
                 std::chrono::duration<double, std::milli>(t1 - t0).count());
    g_result_free(&r);
    return 0;
}
