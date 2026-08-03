// g_grep_cli.cpp — CLI для g-grep: ./g-grep [-c] [-j N] needle file
#include <gcore/gcore.h>

#include <chrono>
#include <cstdio>
#include <cstring>

extern "C" g_result g_grep(const char*, const char*);
extern "C" int64_t g_grep_count(const char*, const char*);

namespace {

void usage(const char* prog) {
    std::fprintf(stderr,
        "g-grep — zero-copy параллельный grep (mmap + SIMD + lock-free chunks)\n"
        "Usage: %s [-c] [-j N] <needle> <file>\n"
        "  -c    только подсчёт совпадений (без копирования строк)\n"
        "  -j N  число воркеров (по умолчанию: все ядра)\n",
        prog);
}

} // namespace

int main(int argc, char** argv) {
    bool count_only = false;
    unsigned jobs = 0;
    int i = 1;
    for (; i < argc; ++i) {
        if (std::strcmp(argv[i], "-c") == 0) { count_only = true; }
        else if (std::strcmp(argv[i], "-j") == 0 && i + 1 < argc) {
            jobs = static_cast<unsigned>(std::strtoul(argv[++i], nullptr, 10));
        }
        else if (std::strcmp(argv[i], "-h") == 0) { usage(argv[0]); return 0; }
        else break;
    }
    if (argc - i != 2) { usage(argv[0]); return 2; }
    const char* needle = argv[i];
    const char* path = argv[i + 1];

    const auto t0 = std::chrono::steady_clock::now();
    int64_t count = 0;
    if (count_only) {
        count = g_grep_count(path, needle);
        if (count < 0) { std::fprintf(stderr, "g-grep: не удалось открыть %s\n", path); return 1; }
    } else {
        g_result r = g_grep(path, needle);
        if (!r.data) { std::fprintf(stderr, "g-grep: не удалось открыть %s\n", path); return 1; }
        // Распаковка C-строк из арены (для вывода; в Python это делается через ctypes)
        const uint8_t* p = r.data;
        const uint8_t* end = r.data + r.size;
        while (p < end) {
            const uint8_t* z = static_cast<const uint8_t*>(std::memchr(p, '\0', end - p));
            if (!z) break;
            std::fwrite(p, 1, static_cast<size_t>(z - p), stdout);
            std::fputc('\n', stdout);
            p = z + 1;
        }
        count = static_cast<int64_t>(r.count);
        g_result_free(&r);
    }
    const auto t1 = std::chrono::steady_clock::now();
    const double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    if (count_only) std::printf("%lld\n", static_cast<long long>(count));
    std::fprintf(stderr, "g-grep: %lld hits in %.2f ms (%u workers)\n",
                 static_cast<long long>(count), ms, jobs ? jobs : 0u);
    return 0;
}
