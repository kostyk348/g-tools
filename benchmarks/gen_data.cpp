// gen_data.cpp — генератор CSV для бенчмарков.
// Создаёт файл с N строками: id,region,value,timestamp,note
// Примерно 30% строк содержат маркер "NEEDLE".
#include <cstdint>
#include <cstdio>
#include <cstdlib>

int main(int argc, char** argv) {
    long nlines = 50'000'000;         // 50M строк по умолчанию (~1.5-2 GB)
    if (argc > 1) nlines = std::atol(argv[1]);
    const char* path = (argc > 2) ? argv[2] : "/tmp/g_bench.csv";

    FILE* f = std::fopen(path, "wb");
    if (!f) { std::perror("fopen"); return 1; }

    const char* regions[] = {"EU", "US", "ASIA", "AF", "OC"};
    uint64_t s = 0x123456789ABCDEFull;
    char line[128];
    for (long i = 0; i < nlines; ++i) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        const int region = static_cast<int>((s >> 32) % 5);
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        const double val = (s % 1000000) / 100.0;
        const int hit = static_cast<int>((s >> 8) % 3) == 0;  // ~1/3 строк
        int len;
        if (hit) {
            len = std::snprintf(line, sizeof(line),
                                "%ld,%s,%.2f,2026-01-01T%02ld:00:00,NEEDLE_RECORD_%ld\n",
                                i, regions[region], val, (s % 24), i);
        } else {
            len = std::snprintf(line, sizeof(line),
                                "%ld,%s,%.2f,2026-01-01T%02ld:00:00,plain_record_%ld\n",
                                i, regions[region], val, (s % 24), i);
        }
        std::fwrite(line, 1, static_cast<size_t>(len), f);
    }
    std::fclose(f);
    std::fprintf(stderr, "generated %ld lines -> %s\n", nlines, path);
    return 0;
}
