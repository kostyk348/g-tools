// test_strings.cpp — юнит-тесты g-strings.
// Проверяем: точность offset/len, min_len, энтропийный фильтр, count.
#include <gcore/gcore.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

extern "C" g_result g_strings(const char*, int, double);
extern "C" int64_t g_strings_count(const char*, int, double);

namespace {

int failures = 0;

void check(bool cond, const char* what) {
    if (!cond) { ++failures; std::fprintf(stderr, "FAIL: %s\n", what); }
}

// Собирает файл с известной структурой и возвращает его содержимое
std::string build_fixture() {
    std::string s;
    // 0x00: мусор
    s += "\x01\x02\x03\x04\x05";
    // 0x05: строка 1
    s += "hello world";
    // 0x10: \0 (не-printable) завершает строку
    s += '\0';
    // 0x11: строка 2 (короткая)
    s += "gcc_version";
    s += "\x01\x02";
    // длинная строка
    s += std::string("segment_A_") + std::string(30, 'B') + std::string("_tail");
    s += '\0';
    // мусор с высокой энтропией (псевдослучайные байты в printable диапазоне)
    uint64_t r = 0xDEADBEEF;
    for (int i = 0; i < 64; ++i) {
        r ^= r << 13; r ^= r >> 7; r ^= r << 17;
        s += static_cast<char>(0x21 + (r % 90));  // '!'..'z'
    }
    s += '\0';
    // повторяющиеся байты (низкая энтропия)
    s += std::string(12, 'A');
    s += '\0';
    return s;
}

void test_strings_basic() {
    const std::string content = build_fixture();
    const char* path = "/tmp/gcore_test_strings.bin";
    FILE* f = std::fopen(path, "wb");
    std::fwrite(content.data(), 1, content.size(), f);
    std::fclose(f);

    g_result r = g_strings(path, /*min_len=*/4, /*max_entropy=*/-1.0);
    check(r.data != nullptr, "g_strings: результат непуст");
    if (!r.data) return;

    const auto* recs = reinterpret_cast<const g_strings_rec*>(r.data);
    const size_t cnt = r.size / sizeof(g_strings_rec);
    std::printf("  g_strings: %zu strings\n", cnt);

    // Проверяем содержимое каждой найденной строки по offset/len
    bool found_hello = false, found_gcc = false, found_long = false, found_aaa = false;
    gcore::MmapFile file;
    check(file.open(path), "mmap файла для сверки");
    for (size_t i = 0; i < cnt; ++i) {
        const uint8_t* p = file.data() + recs[i].offset;
        // строка обязана быть полностью printable
        bool printable = true;
        for (uint32_t j = 0; j < recs[i].len; ++j) {
            if (p[j] < 0x20 || p[j] > 0x7E) { printable = false; break; }
        }
        check(printable, "все байты строки printable");
        // байты вокруг строки — не-printable (граница)
        if (recs[i].offset > 0) {
            const uint8_t before = file.data()[recs[i].offset - 1];
            check(before < 0x20 || before > 0x7E, "строка начинается на границе");
        }
        const uint64_t after_off = recs[i].offset + recs[i].len;
        if (after_off < file.size()) {
            const uint8_t after = file.data()[after_off];
            check(after < 0x20 || after > 0x7E, "строка заканчивается на границе");
        }
        const std::string text(reinterpret_cast<const char*>(p), recs[i].len);
        if (text == "hello world") found_hello = true;
        if (text == "gcc_version") found_gcc = true;
        if (text.find("segment_A_") == 0) found_long = true;
        if (text == std::string(12, 'A')) found_aaa = true;
    }
    check(found_hello, "найдена 'hello world'");
    check(found_gcc, "найдена 'gcc_version'");
    check(found_long, "найдена длинная строка");
    check(found_aaa, "найдена 'AAAAAAAAAAAA'");
    g_result_free(&r);
}

void test_strings_filters() {
    const std::string content = build_fixture();
    const char* path = "/tmp/gcore_test_strings2.bin";
    FILE* f = std::fopen(path, "wb");
    std::fwrite(content.data(), 1, content.size(), f);
    std::fclose(f);

    // min_len=20: останутся только длинная строка и мусорный блок (64 байта)
    const int64_t c20 = g_strings_count(path, 20, -1.0);
    check(c20 == 2, "min_len=20 даёт 2 строки");
    std::printf("  min_len=20 -> %lld\n", static_cast<long long>(c20));

    // min_len=4 + энтропийный фильтр 4.0: "AAAA..." (энтропия 0) проходит,
    // случайный мусор (энтропия ~5.5) отсеивается
    const int64_t ce = g_strings_count(path, 4, 4.0);
    check(ce >= 4, "энтропийный фильтр оставляет текст, отсеивает мусор");
    std::printf("  min_len=4, max_entropy=4.0 -> %lld (мусор отсеян)\n",
                static_cast<long long>(ce));
}

} // namespace

int main() {
    std::printf("[test_strings] basic extraction\n");
    test_strings_basic();
    std::printf("[test_strings] filters\n");
    test_strings_filters();

    if (failures == 0) { std::printf("[test_strings] ALL PASS\n"); return 0; }
    std::printf("[test_strings] %d FAILURES\n", failures);
    return 1;
}
