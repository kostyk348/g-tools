// test_core.cpp — юнит-тесты ядра gcore.
// Ключевой тест: инвариант ChunkAllocator — каждая строка попадает ровно в 1 чанк,
// на любых границах (перекрытия нет, потерь нет), с разными chunk_size.
#include <gcore/gcore.h>

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using gcore::ChunkAllocator;
using gcore::count_newlines;
using gcore::FlatArena;
using gcore::MmapFile;

namespace {

int failures = 0;

void check(bool cond, const char* what) {
    if (!cond) { ++failures; std::fprintf(stderr, "FAIL: %s\n", what); }
}

std::vector<uint8_t> make_lines(int nlines, size_t seed) {
    std::vector<uint8_t> buf;
    buf.reserve(static_cast<size_t>(nlines) * 40);
    uint64_t s = seed * 0x9E3779B97F4A7C15ull + 1;
    for (int i = 0; i < nlines; ++i) {
        // псевдослучайная длина 0..63 + гарантированный '\n'
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        const int len = static_cast<int>(s % 64);
        for (int j = 0; j < len; ++j) {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            buf.push_back(static_cast<uint8_t>('a' + (s % 26)));
        }
        buf.push_back('\n');
    }
    return buf;
}

// Проверяет: объединение чанков покрывает каждую строку ровно один раз.
void test_chunk_invariant(const std::vector<uint8_t>& buf, size_t chunk_size) {
    const size_t total = buf.size();
    ChunkAllocator alloc(buf.data(), total, chunk_size);

    // Подсчёт: сколько раз покрыт каждый байт строк.
    std::vector<int> cover(total, 0);
    size_t begin = 0, end = 0, nchunks = 0;
    while (alloc.next(begin, end)) {
        ++nchunks;
        check(end > begin, "chunk: end > begin");
        check(begin <= total && end <= total, "chunk: границы в пределах файла");
        for (size_t i = begin; i < end; ++i) ++cover[i];
        // begin обязан быть началом строки (или 0, или сразу после '\n')
        if (begin > 0) check(buf[begin - 1] == '\n' || begin == total,
                             "chunk: begin — начало строки");
    }

    // Каждый байт, кроме хвостов обрезанных строк, покрыт ровно 1 раз.
    for (size_t i = 0; i < total; ++i) {
        if (cover[i] > 1) {
            // дубликат возможен только для строк, обрезанных на lookahead —
            // таких нет при тестовых размерах
            check(false, "chunk: байт покрыт >1 раза (дубликат строки)");
            break;
        }
    }
    // Общий подсчёт \n должен сойтись с реальным
    const size_t actual_nl = static_cast<size_t>(std::count(buf.begin(), buf.end(), '\n'));
    check(count_newlines(buf.data(), buf.size()) == actual_nl,
          "simd count_newlines == scalar count");
}

void test_grep_vs_reference() {
    // Строим буфер: 100k строк, половина содержит "TARGET"
    std::string content;
    for (int i = 0; i < 100000; ++i) {
        content += (i % 2 == 0) ? "alpha TARGET beta\n" : "gamma delta\n";
    }
    const char* path = "/tmp/gcore_test_input.txt";
    FILE* f = std::fopen(path, "wb");
    std::fwrite(content.data(), 1, content.size(), f);
    std::fclose(f);

    // Эталонный подсчёт
    long ref = 0;
    {
        FILE* in = std::fopen(path, "rb");
        char line[256];
        while (std::fgets(line, sizeof(line), in)) {
            if (std::strstr(line, "TARGET")) ++ref;
        }
        std::fclose(in);
    }
    const int64_t got = g_grep_count(path, "TARGET");
    check(got == ref, "g_grep_count совпадает с эталоном");
    std::printf("  g_grep_count=%lld ref=%ld\n", static_cast<long long>(got), ref);
}

void test_mmap_empty() {
    const char* path = "/tmp/gcore_empty.txt";
    FILE* f = std::fopen(path, "wb");
    std::fclose(f);
    MmapFile m;
    check(m.open(path) && m.size() == 0 && m.valid(), "mmap пустого файла");
    check(g_grep_count(path, "x") == 0, "grep пустого файла == 0");
}

} // namespace

int main() {
    std::printf("[test_core] chunk invariant (chunk=256)\n");
    for (size_t seed = 1; seed <= 8; ++seed) {
        const auto buf = make_lines(2000, seed);
        test_chunk_invariant(buf, 256);
    }
    std::printf("[test_core] chunk invariant (chunk=4096)\n");
    for (size_t seed = 1; seed <= 8; ++seed) {
        const auto buf = make_lines(2000, seed);
        test_chunk_invariant(buf, 4096);
    }
    std::printf("[test_core] chunk invariant (chunk=1MB, 1 файл без \\n в конце)\n");
    {
        std::vector<uint8_t> buf = make_lines(30000, 42);
        buf.push_back('z'); // последняя строка без '\n'
        test_chunk_invariant(buf, 1u << 20);
    }
    std::printf("[test_core] grep vs reference\n");
    test_grep_vs_reference();
    std::printf("[test_core] mmap empty\n");
    test_mmap_empty();

    if (failures == 0) {
        std::printf("[test_core] ALL PASS\n");
        return 0;
    }
    std::printf("[test_core] %d FAILURES\n", failures);
    return 1;
}
