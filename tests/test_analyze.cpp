// test_analyze.cpp — герметичные C-тесты расширенных C-ABI нод:
// g_strings, g_unicode, g_entropy_profile, g_bytes, g_xor, g_hash, g_hist,
// g_sections (ELF64+PE), g_diff, g_scan, g_recon + ошибки/границы/free(NULL).
// Все фикстуры генерируются во временную директорию — внешних файлов не нужно.
#include <gcore/gcore.h>

extern "C" {
#include <gcore/c_abi.h>
}

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

namespace {

int failures = 0;
std::filesystem::path g_tmp;

void check(bool cond, const char* what) {
    if (!cond) { ++failures; std::fprintf(stderr, "FAIL: %s\n", what); }
}

std::filesystem::path write_file(const char* name, const std::string& bytes) {
    const auto p = g_tmp / name;
    std::ofstream f(p, std::ios::binary);
    f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    return p;
}

std::string slurp(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(f), {});
}

// --- reference-реализации для перекрёстной проверки ---
// Reference для g_hash: FNV-1a по u64-словам (LE) + побайтовый хвост —
// ровно как в run_hash (см. c_abi.h: НЕ побайтовый FNV-1a).
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
    // таблица Reflected poly 0x82F63B78 (Castagnoli)
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

std::string rand_bytes(size_t n, uint64_t seed) {
    std::mt19937_64 rng(seed);
    std::string s(n, '\0');
    for (auto& b : s) b = static_cast<char>(rng() & 0xFF);
    return s;
}

const g_strings_rec* as_strings(const g_result& r) {
    return reinterpret_cast<const g_strings_rec*>(r.data);
}

const g_section_rec* as_sections(const g_result& r) {
    return reinterpret_cast<const g_section_rec*>(r.data);
}

const g_diff_rec* as_diff(const g_result& r) {
    return reinterpret_cast<const g_diff_rec*>(r.data);
}

const g_scan_rec* as_scan(const g_result& r) {
    return reinterpret_cast<const g_scan_rec*>(r.data);
}

// ===================== тесты =====================

void test_result_free_null() {
    g_result_free(nullptr);  // не должно падать
    g_result r{};
    g_result_free(&r);       // и нулевой результат
}

void test_missing_file() {
    const char* ghost = "/nonexistent/g-tools/definitely/not/here.bin";
    g_result r = g_grep(ghost, "x");
    check(r.data == nullptr && r.count == 0, "g_grep: отсутствующий файл -> data==NULL");
    g_result_free(&r);
    check(g_grep_count(ghost, "x") == -1, "g_grep_count: отсутствующий файл -> -1");
    r = g_strings(ghost, 4, -1.0);
    check(r.data == nullptr && r.count == 0, "g_strings: отсутствующий файл -> data==NULL");
    g_result_free(&r);
    r = g_hash(ghost);
    check(r.data == nullptr, "g_hash: отсутствующий файл -> data==NULL");
    g_result_free(&r);
}

void test_strings_extraction() {
    const auto p = write_file("strings.txt", "abc DEF\n\x01\x02gh-01!\n\x7F\n");
    const auto path = p.string();

    g_result r = g_strings(path.c_str(), 4, -1.0);
    check(r.count == 2, "g_strings: найдено 2 строки");
    if (r.count == 2) {
        const auto* recs = as_strings(r);
        check(recs[0].offset == 0 && recs[0].len == 7, "g_strings: 'abc DEF' @0 len7");
        check(recs[1].offset == 10 && recs[1].len == 6, "g_strings: 'gh-01!' @10 len6");
    }
    g_result_free(&r);

    // min_len фильтр: только 'abc DEF' (7 символов)
    r = g_strings(path.c_str(), 7, -1.0);
    check(r.count == 1, "g_strings: min_len=7 -> 1 строка");
    g_result_free(&r);

    // max_entropy: низкоэнтропийные строки проходят, порог 0 отсекает всё
    r = g_strings(path.c_str(), 4, 0.0);
    check(r.count == 0, "g_strings: max_entropy=0 -> всё отфильтровано");
    g_result_free(&r);

    check(g_strings_count(path.c_str(), 4, -1.0) == 2, "g_strings_count == 2");
    check(g_strings_count(path.c_str(), 7, -1.0) == 1, "g_strings_count == 1");
    check(g_strings_count(path.c_str(), 100, -1.0) == 0, "g_strings_count == 0");
}

void test_unicode_utf16le() {
    // u"PACK" + U+0001 + u"MODE" в UTF-16LE: забег по printable u16 рвётся на \x0001
    std::string bytes;
    for (char c : std::string("PACK")) { bytes += c; bytes += '\x00'; }
    bytes += '\x01'; bytes += '\x00';
    for (char c : std::string("MODE")) { bytes += c; bytes += '\x00'; }
    const auto path = write_file("unicode.bin", bytes).string();

    // min_len в СИМВОЛАХ UTF-16 (emit_u16: len_байт < min_len*2 -> skip)
    g_result r = g_unicode(path.c_str(), 4, -1.0);
    check(r.count == 2, "g_unicode: 2 строки (PACK, MODE)");
    if (r.count == 2) {
        const auto* recs = as_strings(r);
        check(recs[0].offset == 0 && recs[0].len == 8, "g_unicode: PACK @0 len8 (в байтах)");
        check(recs[1].offset == 10 && recs[1].len == 8, "g_unicode: MODE @10 len8");
    }
    g_result_free(&r);

    r = g_unicode(path.c_str(), 5, -1.0);
    check(r.count == 0, "g_unicode: min_len=5 символов -> пусто");
    g_result_free(&r);
}

void test_entropy_profile() {
    std::string bytes(4096, '\0');
    bytes += rand_bytes(4096, 42);
    const auto path = write_file("entropy.bin", bytes).string();

    g_result r = g_entropy_profile(path.c_str(), 4096);
    check(r.count == 2, "g_entropy_profile: 2 блока");
    if (r.count == 2) {
        const auto* recs = reinterpret_cast<const g_entropy_rec*>(r.data);
        check(recs[0].offset == 0 && recs[1].offset == 4096, "g_entropy_profile: офсеты 0,4096");
        check(recs[0].entropy < 0.1, "g_entropy_profile: нулевой блок ~0 бит/байт");
        check(recs[1].entropy > 5.0, "g_entropy_profile: случайный блок >5 бит/байт");
    }
    g_result_free(&r);

    r = g_entropy_profile(path.c_str(), 1024);
    check(r.count == 8, "g_entropy_profile: block=1024 -> 8 блоков");
    g_result_free(&r);
}

void test_bytes_slice() {
    const auto path = write_file("hello.bin", "hello world").string();

    g_result r = g_bytes(path.c_str(), 2, 5);
    check(r.count == 5 && r.size == 5, "g_bytes: срез [2,7)");
    if (r.data) check(std::memcmp(r.data, "llo w", 5) == 0, "g_bytes: содержимое 'llo w'");
    g_result_free(&r);

    // len=0 -> до конца файла
    r = g_bytes(path.c_str(), 6, 0);
    check(r.count == 5 && r.data && std::memcmp(r.data, "world", 5) == 0, "g_bytes: len=0 -> хвост");
    g_result_free(&r);

    // срез длиннее остатка обрезается
    r = g_bytes(path.c_str(), 9, 100);
    check(r.count == 2 && r.data && std::memcmp(r.data, "ld", 2) == 0, "g_bytes: обрезание по концу");
    g_result_free(&r);

    // offset >= size -> пустой ok-результат
    r = g_bytes(path.c_str(), 999, 5);
    check(r.count == 0 && r.size == 0, "g_bytes: offset за концом -> пусто");
    g_result_free(&r);
}

void test_xor_key() {
    std::string src;
    for (int i = 0; i < 256; ++i) src += static_cast<char>(i);
    const auto path = write_file("xor.bin", src).string();

    g_result r = g_xor(path.c_str(), 0, 0, 0x5A);
    check(r.count == 256 && r.size == 256, "g_xor: len=0 -> весь файл, 256 байт");
    bool ok = r.data != nullptr;
    for (int i = 0; ok && i < 256; ++i) ok = (r.data[i] == (static_cast<uint8_t>(i) ^ 0x5A));
    check(ok, "g_xor: data[i] == i ^ 0x5A");
    g_result_free(&r);

    // XOR дважды с тем же ключом возвращает исходное
    std::string xored;
    for (int i = 0; i < 256; ++i) xored += static_cast<char>(i ^ 0x5A);
    const auto path2 = write_file("xor2.bin", xored).string();
    r = g_xor(path2.c_str(), 0, 0, 0x5A);
    ok = r.data != nullptr && std::memcmp(r.data, src.data(), 256) == 0;
    check(ok, "g_xor: двукратный XOR возвращает исходник");
    g_result_free(&r);

    // срез
    r = g_xor(path.c_str(), 10, 4, 0x00);  // key=0 -> без XOR, чистый срез
    ok = r.data && std::memcmp(r.data, src.data() + 10, 4) == 0;
    check(ok, "g_xor: key=0 -> сырой срез [10,14)");
    g_result_free(&r);
}

void test_hash() {
    // "123456789" — стандартный check-value CRC-32C = 0xE3069283
    const std::string src = "123456789";
    const auto path = write_file("hash.bin", src).string();

    g_result r = g_hash(path.c_str());
    check(r.count == 1 && r.size == sizeof(g_hash_rec), "g_hash: 1 запись sizeof(g_hash_rec)");
    if (r.data) {
        const auto* h = reinterpret_cast<const g_hash_rec*>(r.data);
        check(h->crc32c == 0xE3069283u, "g_hash: CRC32C('123456789') == 0xE3069283");
        check(h->fnv1a64 == ref_fnv1a64(reinterpret_cast<const uint8_t*>(src.data()), src.size()),
              "g_hash: FNV-1a 64 совпадает с reference");
    }
    g_result_free(&r);
}

void test_hist() {
    std::string src = "AAB";
    src += std::string(200, 'C');
    src += std::string(53, '\xFF');
    const auto path = write_file("hist.bin", src).string();

    g_result r = g_hist(path.c_str());
    check(r.count == 256 && r.size == 256 * sizeof(uint64_t), "g_hist: 256 баров u64");
    if (r.data) {
        const auto* h = reinterpret_cast<const uint64_t*>(r.data);
        check(h['A'] == 2 && h['B'] == 1 && h['C'] == 200 && h[0xFF] == 53,
              "g_hist: счётчики байтов");
        uint64_t sum = 0;
        for (int i = 0; i < 256; ++i) sum += h[i];
        check(sum == src.size(), "g_hist: сумма == размеру файла");
    }
    g_result_free(&r);
}

// Минимальный ELF64: ehdr + 3 shdr (NULL, .shstrtab, .text) + strtab + .text
void test_sections_elf64() {
    std::string f(64, '\0');
    f[0] = '\x7F'; f[1] = 'E'; f[2] = 'L'; f[3] = 'F';
    f[4] = 2;  // ELFCLASS64
    const uint64_t shoff = 64;
    const uint16_t shentsize = 64, shnum = 3, shstrndx = 1;
    std::memcpy(&f[0x28], &shoff, 8);
    std::memcpy(&f[0x3A], &shentsize, 2);
    std::memcpy(&f[0x3C], &shnum, 2);
    std::memcpy(&f[0x3E], &shstrndx, 2);

    // strtab: \0 .text \0 .shstrtab \0  (17 байт, с завершающим NUL)
    std::string strtab(1, '\0');
    strtab += ".text"; strtab += '\0';
    strtab += ".shstrtab"; strtab += '\0';
    const uint64_t strtab_off = shoff + shnum * shentsize;  // 64+192=256
    const uint64_t strtab_size = strtab.size();

    auto put_shdr = [&](int i, uint32_t name, uint32_t type, uint64_t flags,
                        uint64_t off, uint64_t size) {
        std::string s(64, '\0');
        std::memcpy(&s[0], &name, 4);
        std::memcpy(&s[4], &type, 4);
        std::memcpy(&s[8], &flags, 8);
        std::memcpy(&s[0x18], &off, 8);
        std::memcpy(&s[0x20], &size, 8);
        f += s;
    };
    put_shdr(0, 0, 0, 0, 0, 0);                       // NULL
    put_shdr(1, 7, 3, 0, strtab_off, strtab_size);    // .shstrtab (STRTAB)
    // .text: PROGBITS + SHF_EXECINSTR|SHF_ALLOC -> code
    const uint64_t text_off = strtab_off + strtab_size;
    put_shdr(2, 1, 1, 0x6, text_off, 16);
    f += strtab;
    f += rand_bytes(16, 7);  // содержимое .text

    const auto path = write_file("mini.elf", f).string();
    g_result r = g_sections(path.c_str());
    check(r.count == 3, "g_sections: 3 секции ELF64");
    if (r.count == 3) {
        const auto* s = as_sections(r);
        check(s[2].type == 0 && std::strcmp(s[2].name, ".text") == 0, "g_sections: .text -> code");
        check(s[2].offset == text_off && s[2].size == 16, "g_sections: офсет/размер .text");
        check(s[1].type == 5 && std::strcmp(s[1].name, ".shstrtab") == 0,
              "g_sections: .shstrtab -> other");
        check(s[1].offset == strtab_off && s[1].size == strtab_size,
              "g_sections: офсет/размер .shstrtab");
        check(s[0].offset == 0 && s[0].size == 0, "g_sections: NULL-секция пустая");
    }
    g_result_free(&r);
}

// Минимальный PE: 'MZ' + e_lfanew -> 'PE\0\0' + 2 секции (.text exec, .rsrc)
void test_sections_pe() {
    std::string f(0x40, '\0');
    f[0] = 'M'; f[1] = 'Z';
    const uint32_t lfanew = 0x40;
    std::memcpy(&f[0x3C], &lfanew, 4);
    f += std::string("PE\0\0", 4);
    f += std::string(20, '\0');  // остаток COFF-заголовка (pe+4 .. pe+24)
    const uint16_t nsects = 2, opt = 0;
    std::memcpy(&f[lfanew + 6], &nsects, 2);   // NumberOfSections
    std::memcpy(&f[lfanew + 20], &opt, 2);     // SizeOfOptionalHeader
    const uint64_t shdr_off = lfanew + 24;

    auto put = [&](const char name[8], uint32_t raw_size, uint32_t raw_ptr, uint32_t chars) {
        std::string s(40, '\0');
        std::memcpy(&s[0], name, 8);
        std::memcpy(&s[16], &raw_size, 4);
        std::memcpy(&s[20], &raw_ptr, 4);
        std::memcpy(&s[36], &chars, 4);
        f += s;
    };
    put(".text\0\0\0", 8, shdr_off + 80, 0x60000020u);  // exec -> code
    put(".rsrc\0\0\0", 4, shdr_off + 88, 0x40000040u);  // .rsrc -> ресурсная
    f += rand_bytes(12, 9);

    const auto path = write_file("mini.exe", f).string();
    g_result r = g_sections(path.c_str());
    check(r.count == 2, "g_sections: 2 секции PE");
    if (r.count == 2) {
        const auto* s = as_sections(r);
        check(s[0].type == 2 && std::strcmp(s[0].name, ".text") == 0, "g_sections: PE .text -> code");
        check(s[1].type == 4 && std::strcmp(s[1].name, ".rsrc") == 0, "g_sections: PE .rsrc -> rsrc");
        check(s[1].size == 4, "g_sections: PE SizeOfRawData");
    }
    g_result_free(&r);
}

void test_diff() {
    const std::string A = std::string(8, 'A') + std::string(8, 'B') +
                          std::string(8, 'C') + std::string(8, 'D');
    const std::string B = std::string(8, 'A') + std::string("bXbXbXbX") +
                          std::string(8, 'C') + std::string(8, 'D');
    const auto pa = write_file("diff_a.bin", A).string();
    const auto pb = write_file("diff_b.bin", B).string();

    g_result r = g_diff(pa.c_str(), pb.c_str(), 8);
    check(r.count == 1, "g_diff: 1 изменённый блок");
    if (r.count == 1) {
        const auto* d = as_diff(r);
        check(d[0].status == G_DIFF_CHANGED && d[0].offset_a == 8 && d[0].len == 8,
              "g_diff: CHANGED @8 len8");
    }
    g_result_free(&r);

    // B длиннее A -> INSERTED-хвост
    const std::string B2 = B + std::string(8, 'F');
    const auto pb2 = write_file("diff_b2.bin", B2).string();
    r = g_diff(pa.c_str(), pb2.c_str(), 8);
    check(r.count == 2, "g_diff: CHANGED + INSERTED");
    if (r.count == 2) {
        const auto* d = as_diff(r);
        check(d[0].status == G_DIFF_CHANGED, "g_diff: [0] CHANGED");
        check(d[1].status == G_DIFF_INSERTED && d[1].offset_b == 32 && d[1].len == 8,
              "g_diff: [1] INSERTED @B32 len8");
    }
    g_result_free(&r);

    // A длиннее B -> DELETED-хвост
    r = g_diff(pb2.c_str(), pa.c_str(), 8);
    check(r.count == 2, "g_diff: обратный порядок");
    if (r.count == 2) {
        const auto* d = as_diff(r);
        check(d[1].status == G_DIFF_DELETED && d[1].offset_a == 32 && d[1].len == 8,
              "g_diff: [1] DELETED @A32 len8");
    }
    g_result_free(&r);

    // идентичные файлы -> ни одной записи (SAME не пишется)
    const auto pa2 = write_file("diff_a2.bin", A).string();
    r = g_diff(pa.c_str(), pa2.c_str(), 8);
    check(r.count == 0, "g_diff: идентичные файлы -> 0 записей");
    g_result_free(&r);
}

void test_scan_multipattern() {
    const auto path = write_file("scan.txt", "needle need needle").string();
    const char* pats[] = {"needle", "le"};
    g_result r = g_scan(path.c_str(), pats, 2);
    // "needle"(0-5) ' ' "need"(7-10) ' ' "needle"(12-17): needle@0, le@4, needle@12, le@16
    check(r.count == 4, "g_scan: 4 совпадения");
    if (r.count == 4) {
        const auto* s = as_scan(r);
        auto has = [&](uint64_t off, uint32_t idx) {
            for (size_t i = 0; i < r.count; ++i)
                if (s[i].offset == off && s[i].pattern_idx == idx) return true;
            return false;
        };
        check(has(0, 0) && has(4, 1) && has(12, 0) && has(16, 1),
              "g_scan: все (offset, pattern_idx) на месте");
        bool sorted = true;
        for (size_t i = 1; i < r.count; ++i) sorted &= s[i - 1].offset <= s[i].offset;
        check(sorted, "g_scan: порядок по офсету");
    }
    g_result_free(&r);
}

void test_recon_layout() {
    std::string src = "some binary\x00\x01\x02 content with strings inside\x00";
    src += rand_bytes(4096, 11);
    const auto path = write_file("recon.bin", src).string();

    g_result r = g_recon(path.c_str(), 4096);
    check(r.data != nullptr && r.count >= 1, "g_recon: результат не пуст (count = число строк)");
    if (r.data && r.size >= sizeof(g_recon_header)) {
        g_recon_header hdr;
        std::memcpy(&hdr, r.data, sizeof(hdr));
        check(hdr.n_hist == 256, "g_recon: гистограмма 256 баров");
        check(hdr.n_entropy >= 1, "g_recon: есть хотя бы 1 entropy-блок");
        check(hdr.n_strings == r.count, "g_recon: count == n_strings из заголовка");
        const size_t expect_min = sizeof(hdr) + 256 * sizeof(uint64_t) +
                                  static_cast<size_t>(hdr.n_entropy) * sizeof(g_entropy_rec);
        check(r.size >= expect_min, "g_recon: размер буфера согласован с заголовком");
    }
    g_result_free(&r);
}

void test_grep_smoke() {
    std::string src;
    for (int i = 0; i < 1000; ++i) src += (i % 97 == 0) ? "NEEDLE line\n" : "filler line\n";
    const auto path = write_file("grep.txt", src).string();
    check(g_grep_count(path.c_str(), "NEEDLE") == 11, "g_grep_count: 11 хитов");
    g_result r = g_grep(path.c_str(), "NEEDLE");
    check(r.count == 11, "g_grep: 11 строк-хитов");
    if (r.data) {
        const char* first = reinterpret_cast<const char*>(r.data);
        check(std::strcmp(first, "NEEDLE line") == 0, "g_grep: первая строка корректна");
    }
    g_result_free(&r);
}

}  // namespace

int main() {
    g_tmp = std::filesystem::temp_directory_path() / "gtools_test_analyze";
    std::filesystem::create_directories(g_tmp);

    test_result_free_null();
    test_missing_file();
    test_grep_smoke();
    test_strings_extraction();
    test_unicode_utf16le();
    test_entropy_profile();
    test_bytes_slice();
    test_xor_key();
    test_hash();
    test_hist();
    test_sections_elf64();
    test_sections_pe();
    test_diff();
    test_scan_multipattern();
    test_recon_layout();

    if (failures == 0) {
        std::printf("test_analyze: all passed\n");
        return 0;
    }
    std::printf("test_analyze: %d failures\n", failures);
    return 1;
}
