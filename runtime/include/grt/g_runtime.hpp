// g_runtime.hpp — ядро g-runtime / Shim-слоя.
// Уровень B (линкуемый): VFS-нормализация + mmap-слайс-кэш + fake-fd таблица.
// Не зависит от LD_PRELOAD — этот же код линкуется в Vita/PS2-проекты.
//
// Философия (из спеки g-proto):
//   - Старый бинарник вызывает open/read/lseek/close (или fopen/fread)
//   - Вместо системного чтения — mmap_ingest из gcore → готовый срез (slice)
//   - Повторные чтения = memcpy из RAM, ноль syscalls, ноль page-cache-промахов
//   - VFS нормализует пути: C:\Games\Data\Maps -> /ux0:data/bf1942/maps (Vita)
//
// Уровень A (LD_PRELOAD, см. g_io_posix.cpp) просто пробрасывает вызовы сюда.
#pragma once

#include <gcore/gcore.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <string_view>

namespace grt {

// ---- VFS: нормализация путей под платформу ----

enum class Platform {
    Linux,   // /home/lain/... (case-sensitive)
    Vita,    // ux0:data/...  (case-insensitive, разделитель /)
    Win32,   // C:\Games\...  (case-insensitive, разделитель \)
};

struct VfsConfig {
    Platform platform = Platform::Linux;
    // корень, куда транслируются "виртуальные" пути игры (для Vita: ux0:data/<game>/)
    std::string root;      // например "/home/lain/bf1942/" или "ux0:data/bf1942/"
    bool case_insensitive = false;
    char path_sep = '/';
};

class Vfs {
public:
    explicit Vfs(VfsConfig cfg = {}) : cfg_(cfg) {
        cfg_.case_insensitive = (cfg_.platform != Platform::Linux);
        cfg_.path_sep = (cfg_.platform == Platform::Win32) ? '\\' : '/';
    }

    Platform platform() const { return cfg_.platform; }
    const std::string& root() const { return cfg_.root; }

    /// Нормализует произвольный путь игры в канонический абсолютный путь хоста.
    /// C:\Games\Data\Maps\map01 -> /home/lain/bf1942/data/maps/map01 (Linux root)
    ///                         -> ux0:data/bf1942/data/maps/map01   (Vita root)
    std::string normalize(std::string_view in) const {
        std::string out;
        out.reserve(cfg_.root.size() + in.size() + 4);
        out += cfg_.root;

        // отрезаем диск/префикс (C:\, ux0:, //host) — но НЕ трогаем ведущий
        // слэш абсолютного пути хоста (иначе /home/x -> home/x ENOENT)
        size_t i = 0;
        if (in.size() >= 2 && in[1] == ':') i = 2;               // "C:" или "u:"
        else if (in.size() >= 2 && (in[0] == '/' || in[0] == '\\') &&
                 (in[1] == '/' || in[1] == '\\')) i = 2;          // "//host/share" (UNC)
        // "C:\..." — остаётся c: префикс в out? нет: cfg_.root пуст для Linux, вставляем корень
        // убираем виртуальный префикс игры, если он совпал с root (idempotent)
        std::string_view rest = in.substr(i);
        if (!cfg_.root.empty() && rest.rfind(cfg_.root, 0) == 0)
            rest = rest.substr(cfg_.root.size());

        for (char c : rest) {
            if (c == '\\') {
                if (cfg_.path_sep == '\\') out += '\\';
                else out += '/';
            } else {
                out += c;
            }
        }
        if (cfg_.case_insensitive) {
            for (auto& c : out) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        return out;
    }

    /// Кэш-ключ: тот же нормализованный путь, но lower-case если case-insensitive.
    std::string cache_key(std::string_view path) const {
        std::string k = normalize(path);
        if (cfg_.case_insensitive) {
            for (auto& c : k) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return k;
    }

private:
    VfsConfig cfg_;
};

// ---- mmap-слайс-кэш ----

// Результат ingest: указатель на готовый срез данных (zero-copy из mmap).
struct Slice {
    const uint8_t* data = nullptr;
    size_t         size = 0;
    uint64_t       id   = 0;      // ключ кэша (для release)
    // реальные stat-данные исходного файла (для консистентных st_dev/st_ino/… в
    // fstat/fstat64). GNU grep/cp сравнивают (st_dev,st_ino) файлов друг с другом —
    // нули ломают их "input == output" и "replaced while copied" проверки.
    dev_t  dev      = 0;
    ino_t  ino      = 0;
    mode_t mode     = 0;
};

// Открытый "файл" — entry в таблице дескрипторов shim-слоя.
struct FileHandle {
    Slice    slice;
    uint64_t pos = 0;             // текущая позиция чтения (lseek/read)
    bool     writable = false;    // открыт на запись (не через mmap — системный)
};

class MmapCache {
public:
    /// Возвращает слайс для пути (mmap через gcore::MmapFile), кэшируя по VFS-ключу.
    /// Повторный open() того же файла = тот же слайс, ноль syscalls.
    Slice ingest(std::string_view path) {
        const std::string key = vfs_.cache_key(path);

        std::lock_guard<std::mutex> lk(mu_);
        auto it = slices_.find(key);
        if (it != slices_.end()) {
            ++it->second.refs;
            return it->second.slice;
        }

        auto* mf = new gcore::MmapFile();
        if (!mf->open(vfs_.normalize(path).c_str())) {
            delete mf;
            return {};
        }
        Entry e;
        e.slice.data = mf->data();
        e.slice.size = mf->size();
        e.slice.id   = next_id_++;
        e.slice.dev  = mf->st_dev();
        e.slice.ino  = mf->st_ino();
        e.slice.mode = mf->st_mode();
        e.mmap       = mf;
        e.refs       = 1;
        slices_[key] = e;
        ++mmaps_;
        bytes_ += e.slice.size;
        return e.slice;
    }

    void release(Slice s) {
        // Шим-слой: файл ОСТАЁТСЯ в RAM после close(). Старые игры открывают
        // одни и те же ресурсы постоянно — повторный open = hit без syscalls.
        // Полное освобождение — только через clear() (вызывается при выходе
        // или когда игра явно требует освободить ресурс).
        std::lock_guard<std::mutex> lk(mu_);
        for (auto it = slices_.begin(); it != slices_.end(); ++it) {
            if (it->second.slice.id == s.id && it->second.slice.data == s.data) {
                if (it->second.refs > 0) --it->second.refs;
                return;
            }
        }
    }

    /// Полная очистка кэша (munmap всех слайсов). Вызывается при завершении.
    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& kv : slices_) delete kv.second.mmap;
        slices_.clear();
        mmaps_ = 0;
    }

    // статистика для отладки shim-слоя
    void stats(size_t& mmaps_out, size_t& bytes_out, size_t& entries_out) const {
        std::lock_guard<std::mutex> lk(mu_);
        mmaps_out = mmaps_;
        bytes_out = bytes_;
        entries_out = slices_.size();
    }

    const Vfs& vfs() const { return vfs_; }

private:
    struct Entry {
        Slice        slice;
        gcore::MmapFile* mmap = nullptr;
        size_t       refs = 0;
    };

    mutable std::mutex mu_;
    std::map<std::string, Entry> slices_;
    Vfs vfs_;
    uint64_t next_id_ = 1;
    size_t mmaps_ = 0;
    size_t bytes_ = 0;   // суммарный размер закешированных mmap (для отладки)
};

// ---- Fake-fd таблица ----
// Старые игры работают с целочисленными fd. Shim выдаёт fake fd >= kFakeFdBase,
// реальные fd (0,1,2 и системные) пробрасываются насквозь.

inline constexpr int kFakeFdBase = 0x6000;   // 24576 — далеко от реальных fd

class FdTable {
public:
    /// Открывает путь на чтение через mmap. Возвращает fake fd или -1.
    int open_read(std::string_view path) {
        Slice s = cache_.ingest(path);
        if (!s.data && s.size == 0) return -1;   // пустой файл тоже валиден

        std::lock_guard<std::mutex> lk(mu_);
        int fd = next_fd_++;
        handles_[fd] = FileHandle{s, 0, false};
        return fd;
    }

    /// Системный fd (не fake): вызывающий должен сам сделать read().
    bool is_fake(int fd) const { return fd >= kFakeFdBase; }

    // read: memcpy из mmap-среза, ноль syscalls
    ssize_t read(int fd, void* buf, size_t n) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = handles_.find(fd);
        if (it == handles_.end()) {
            if (getenv("GIO_DEBUG")) {
                fprintf(stderr, "[g-io] read(%d) не найден в таблице; size=%zu\n",
                        fd, handles_.size());
            }
            return -1;
        }
        FileHandle& h = it->second;
        const size_t avail = h.slice.size - h.pos;
        const size_t want  = n < avail ? n : avail;
        if (want) std::memcpy(buf, h.slice.data + h.pos, want);
        h.pos += want;
        return static_cast<ssize_t>(want);
    }

    // pread: чтение с позиции без изменения текущей позиции (pread(2))
    ssize_t pread(int fd, void* buf, size_t n, uint64_t off) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = handles_.find(fd);
        if (it == handles_.end()) { errno = EBADF; return -1; }
        const FileHandle& h = it->second;
        if (off >= h.slice.size) return 0;          // EOF
        const size_t avail = h.slice.size - static_cast<size_t>(off);
        const size_t want  = n < avail ? n : avail;
        if (want) std::memcpy(buf, h.slice.data + off, want);
        return static_cast<ssize_t>(want);
    }

    // lseek: позиционирование внутри слайса.
    // Отрицательные offset допустимы при SEEK_END/SEEK_CUR (tail -N), т.е. считаем
    // целевую позицию в знаковой арифметике, запрещаем только уход за начало.
    off_t lseek(int fd, off_t off, int whence) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = handles_.find(fd);
        if (it == handles_.end()) { errno = EBADF; return -1; }
        FileHandle& h = it->second;
        off_t target;
        switch (whence) {
            case SEEK_SET: target = off; break;
            case SEEK_CUR: target = static_cast<off_t>(h.pos) + off; break;
            case SEEK_END: target = static_cast<off_t>(h.slice.size) + off; break;
            default: errno = EINVAL; return -1;
        }
        if (target < 0) { errno = EINVAL; return -1; }   // нельзя за начало файла
        h.pos = static_cast<uint64_t>(target);
        return static_cast<off_t>(h.pos);
    }

    bool close(int fd) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = handles_.find(fd);
        if (it == handles_.end()) return false;
        cache_.release(it->second.slice);
        handles_.erase(it);
        return true;
    }

    // mmap поверх fake fd: возвращает прямой указатель на mmap-слайс gcore.
    // zero-copy — GPU/движок читает данные из той же памяти, что и read().
    // Возвращает nullptr, если fd не наш или смещение/размер вне слайса.
    const uint8_t* mmap_slice(int fd, size_t offset, size_t length) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = handles_.find(fd);
        if (it == handles_.end()) return nullptr;
        const Slice& s = it->second.slice;
        if (offset > s.size || length > s.size - offset) return nullptr;
        return s.data + offset;
    }

    // fstat для fake fd: размер = size слайса, тип = обычный файл
    bool fstat(int fd, size_t* size_out) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = handles_.find(fd);
        if (it == handles_.end()) return false;
        if (size_out) *size_out = it->second.slice.size;
        return true;
    }

    // полный stat для fake fd (для fstat/fstat64 hook): возвращает копию Slice
    bool stat(int fd, Slice* out) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = handles_.find(fd);
        if (it == handles_.end()) return false;
        *out = it->second.slice;
        return true;
    }

    // позиция чтения fake fd (для FIONREAD / fdopen cookie)
    uint64_t pos(int fd) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = handles_.find(fd);
        return it == handles_.end() ? 0 : it->second.pos;
    }

    void set_pos(int fd, uint64_t p) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = handles_.find(fd);
        if (it != handles_.end()) it->second.pos = p;
    }

    // проверка: существует ли открытый fake fd (для stat/fstat по пути)
    bool has(int fd) const {
        std::lock_guard<std::mutex> lk(mu_);
        return handles_.count(fd) != 0;
    }

    MmapCache& cache() { return cache_; }
    const Vfs& vfs() const { return cache_.vfs(); }

private:
    mutable std::mutex mu_;
    std::map<int, FileHandle> handles_;
    MmapCache cache_;
    int next_fd_ = kFakeFdBase;
};

// Единственный экземпляр shim-слоя (один на процесс)
inline FdTable& fd_table() {
    static FdTable t;
    return t;
}

} // namespace grt
