// c_abi.h — нода 5 графа: zero-copy интерфейс для Python/Rust/Go.
// C-ABI (extern "C"): результат — плоская арена + владелец для free.
// Python забирает данные через ctypes без единого копирования.
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Универсальный результат конвейера.
/// data — плоская арена (64-byte aligned), size — занято, capacity — выделено.
/// count — число записей (строк/чисел). owner — opaque для g_result_free.
typedef struct g_result {
    void*    owner;
    uint8_t* data;
    size_t   size;
    size_t   capacity;
    size_t   count;
} g_result;

/// Освобождает память результата. Безопасен для нулевого результата.
void g_result_free(g_result* r);

/// g-grep: ищет needle в файле path.
/// Результат: каждая строка-хит — C-строка (\0-terminated) в плоской арене.
/// count = число хитов. При ошибке: data==NULL, count==0.
g_result g_grep(const char* path, const char* needle);

/// g-grep -c: только подсчёт хитов (без копирования строк). -1 при ошибке.
int64_t g_grep_count(const char* path, const char* needle);

/// Запись строки из g_strings: offset в файле + длина. 16 байт, aligned(8) —
/// совместимо с numpy structured dtype [('offset','u8'),('len','u4'),('pad','u4')].
typedef struct g_strings_rec {
    uint64_t offset;
    uint32_t len;
    uint32_t pad;  ///< зарезервировано (выравнивание)
} g_strings_rec;

/// g-strings: извлекает printable-строки [0x20..0x7E] из бинарника.
/// Результат: data = g_strings_rec[count] (offset/len каждой строки).
/// Содержимое строк НЕ копируется — читается напрямую из mmap файла
/// по (offset, len): ноль копий до Python/нейронки.
/// min_len: минимальная длина строки (>=1). max_entropy < 0 → фильтр выключен;
/// иначе строки с энтропией > max_entropy отсеиваются (мусор из сжатых областей).
/// При ошибке: data==NULL, count==0.
g_result g_strings(const char* path, int min_len, double max_entropy);

/// g-strings --count: только число строк. -1 при ошибке.
int64_t g_strings_count(const char* path, int min_len, double max_entropy);

/// Запись профиля энтропии: offset + энтропия Шеннона блока (биты/байт).
/// 24 байта. Классификация: <4.5 plain, 4.5-7.5 код/текст, >7.5 сжато/шифровано.
typedef struct g_entropy_rec {
    uint64_t offset;
    double entropy;
} g_entropy_rec;

/// g-entropy-profile: карта энтропии файла по блокам block_size (>=64).
/// Результат: data = g_entropy_rec[count], блоки в порядке возрастания offset.
g_result g_entropy_profile(const char* path, int block_size);

/// g-bytes: срез байт [offset, offset+len). len=0 → до конца файла.
/// Результат: data = сырые байты (size = count = длина среза).
g_result g_bytes(const char* path, uint64_t offset, uint64_t len);

// ===================== расширенные ноды анализа =====================

/// g-unicode: UTF-16LE printable-строки (Windows-игры, .NET, PE-ресурсы).
/// Результат: data = g_strings_rec[] (offset — смещение в файле,
/// len — длина в БАЙТАХ исходника, кратно 2). Содержимое не копируется.
g_result g_unicode(const char* path, int min_len, double max_entropy);

/// Хэши файла для идентификации/дедупа. count=1.
typedef struct g_hash_rec {
    uint64_t fnv1a64;   ///< FNV-1a 64 (полный файл)
    uint32_t crc32c;    ///< CRC32C (SSE4.2 hardware)
} g_hash_rec;

g_result g_hash(const char* path);

/// Гистограмма байтов: data = uint64_t[256] (count=256). Для анализа
/// форматов/магии/таблиц: где плотности, где нули (выравнивание/указатели).
g_result g_hist(const char* path);

/// Запись секции ELF/PE. 64 байта, выровнена.
typedef struct g_section_rec {
    uint64_t offset;   ///< файловый офсет секции
    uint64_t size;     ///< размер в файле
    double entropy;    ///< энтропия Шеннона секции (code ~4.5-7, compressed >7.5)
    char name[32];     ///< имя секции (NUL-terminated)
    uint32_t type;     ///< 0=ELF prog, 1=ELF data, 2=PE code, 3=PE data, 4=PE rsrc, 5=other
} g_section_rec;

/// g-sections: ELF/PE-разведка — заголовки, секции с энтропией.
g_result g_sections(const char* path);

/// Статус блока в g_diff.
#define G_DIFF_SAME 0   ///< блок идентичен в обоих файлах
#define G_DIFF_CHANGED 1 ///< блок изменён
#define G_DIFF_INSERTED 2 ///< блок есть только в B
#define G_DIFF_DELETED 3  ///< блок был в A, отсутствует в B

typedef struct g_diff_rec {
    uint64_t offset_a;   ///< офсет в файле A (0 для INSERTED)
    uint64_t offset_b;   ///< офсет в файле B (0 для DELETED)
    uint32_t len;        ///< длина диапазона (блоки сгруппированы)
    uint8_t status;      ///< G_DIFF_*
} g_diff_rec;

/// g-diff: блочное сравнение двух файлов (версии прошивок/патчей).
/// Результат: g_diff_rec[] — изменённые/вставленные/удалённые диапазоны.
g_result g_diff(const char* path_a, const char* path_b, int block_size);

/// g-xor: срез байт [offset, offset+len) XOR с однобайтовым ключом.
/// Для декодирования XOR-обфусцированных строк/данных (floss-стиль).
/// Результат: data = декодированные байты.
g_result g_xor(const char* path, uint64_t offset, uint64_t len, int key);

// ===================== g_recon =====================
// Одна mmap-сессия: hash + hist + entropy(64KB) + strings-семплы.
// Результат — плоский буфер: [header][hist u64[256]][entropy recs][strings recs].
// Python разбирает по заголовку.
typedef struct g_recon_header {
    uint64_t fnv1a64;
    uint32_t crc32c;
    uint32_t n_hist;      // 256
    uint32_t n_entropy;
    uint32_t n_strings;
    uint32_t pad;
} g_recon_header;

g_result g_recon(const char* path, int entropy_block);

// ===================== g_scan =====================
// Мультипаттернный SIMD-скан (Aho-Corasick + skip по первым байтам).
// Результат: g_scan_rec[] — {offset, pattern_idx} для каждого совпадения.
typedef struct g_scan_rec {
    uint64_t offset;
    uint32_t pattern_idx;
    uint32_t pad;
} g_scan_rec;

g_result g_scan(const char* path, const char* const* patterns, int pattern_count);

#ifdef __cplusplus
} // extern "C"
#endif
