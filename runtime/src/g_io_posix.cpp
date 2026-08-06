// g_io_posix.cpp — Уровень A: LD_PRELOAD-перехват системных I/O вызовов.
//
// Подменяет open/open64/read/lseek/close на версии, которые читают файл через
// mmap (gcore::MmapFile) и отдают программе готовый срез из RAM.
//
// Как это работает:
//   LD_PRELOAD=/path/libg_io.so ./старый_бинарь
//   - open(path, O_RDONLY) -> MmapCache::ingest() -> fake fd (>= 0x6000)
//   - read(fake_fd, buf, n) -> memcpy из mmap-среза (ноль syscalls)
//   - lseek/close -> позиционирование/освобождение в таблице fd
//   - fopen/fread glibc-стека тоже попадают сюда: glibc stdio вызывает
//     open()/read() внутри, так что подмена на POSIX-уровне перехватывает
//     и stdio-чтение. (проверено: fopen->open, fread->read)
//
// Статистика: GIO_STATS=1 выводит на stderr число mmap и байт из RAM.
// GIO_VFS_ROOT=<dir> задаёт корень для VFS-нормализации путей.
//
// Для Vita/PS2 этот файл НЕ используется — там g_runtime.hpp линкуется
// напрямую в проект (eboot), вызовы идут через обычный API без dlsym.
#include <grt/g_runtime.hpp>

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <dlfcn.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// ---- RTLD_NEXT-функции реальной libc ----
// Инициализация ленивая (одноразово), иначе рекурсия на старте.

namespace {

using open_fn    = int (*)(const char*, int, ...);
using open64_fn  = int (*)(const char*, int, ...);
using openat_fn  = int (*)(int, const char*, int, ...);
using read_fn    = ssize_t (*)(int, void*, size_t);
using readchk_fn = ssize_t (*)(int, void*, size_t, size_t);   // __read_chk(int, void*, size_t, buflen)
using pread_fn   = ssize_t (*)(int, void*, size_t, off_t);
using pread64_fn = ssize_t (*)(int, void*, size_t, off64_t);
using lseek_fn   = off_t (*)(int, off_t, int);
using lseek64_fn = off64_t (*)(int, off64_t, int);
using close_fn   = int (*)(int);
using fstat_fn   = int (*)(int, struct stat*);
using fstat64_fn = int (*)(int, struct stat64*);
using fcntl_fn   = int (*)(int, int, ...);
using mmap_fn    = void* (*)(void*, size_t, int, int, int, off_t);
using munmap_fn  = int (*)(void*, size_t);
using fadvise_fn = int (*)(int, off_t, off_t, int);
using ioctl_fn   = int (*)(int, unsigned long, ...);
using fdopen_fn  = FILE* (*)(int, const char*);

struct Real {
    open_fn   open   = nullptr;
    open64_fn open64 = nullptr;
    openat_fn openat = nullptr;
read_fn    read   = nullptr;
    readchk_fn readchk = nullptr;
    pread_fn  pread  = nullptr;
    pread64_fn pread64 = nullptr;
    lseek_fn  lseek  = nullptr;
    lseek64_fn lseek64 = nullptr;
    close_fn  close  = nullptr;
    fstat_fn  fstat  = nullptr;
    fstat64_fn fstat64 = nullptr;
    fcntl_fn  fcntl  = nullptr;
    mmap_fn   mmap   = nullptr;
    munmap_fn munmap = nullptr;
    fadvise_fn posix_fadvise = nullptr;
    ioctl_fn  ioctl  = nullptr;
    fdopen_fn fdopen = nullptr;
};

Real& real() {
    static Real r;
    static bool init = false;
    if (!init) {
        r.open    = reinterpret_cast<open_fn>(dlsym(RTLD_NEXT, "open"));
        r.open64  = reinterpret_cast<open64_fn>(dlsym(RTLD_NEXT, "open64"));
        r.openat  = reinterpret_cast<openat_fn>(dlsym(RTLD_NEXT, "openat"));
        r.read    = reinterpret_cast<read_fn>(dlsym(RTLD_NEXT, "read"));
        r.readchk = reinterpret_cast<readchk_fn>(dlsym(RTLD_NEXT, "__read_chk"));
        r.pread   = reinterpret_cast<pread_fn>(dlsym(RTLD_NEXT, "pread"));
        r.pread64 = reinterpret_cast<pread64_fn>(dlsym(RTLD_NEXT, "pread64"));
        r.lseek   = reinterpret_cast<lseek_fn>(dlsym(RTLD_NEXT, "lseek"));
        r.lseek64 = reinterpret_cast<lseek64_fn>(dlsym(RTLD_NEXT, "lseek64"));
        r.close   = reinterpret_cast<close_fn>(dlsym(RTLD_NEXT, "close"));
        r.fstat   = reinterpret_cast<fstat_fn>(dlsym(RTLD_NEXT, "fstat"));
        r.fstat64 = reinterpret_cast<fstat64_fn>(dlsym(RTLD_NEXT, "fstat64"));
        r.fcntl   = reinterpret_cast<fcntl_fn>(dlsym(RTLD_NEXT, "fcntl"));
        r.mmap    = reinterpret_cast<mmap_fn>(dlsym(RTLD_NEXT, "mmap"));
        r.munmap  = reinterpret_cast<munmap_fn>(dlsym(RTLD_NEXT, "munmap"));
        r.posix_fadvise = reinterpret_cast<fadvise_fn>(dlsym(RTLD_NEXT, "posix_fadvise"));
        r.ioctl   = reinterpret_cast<ioctl_fn>(dlsym(RTLD_NEXT, "ioctl"));
        r.fdopen  = reinterpret_cast<fdopen_fn>(dlsym(RTLD_NEXT, "fdopen"));
        init = true;
    }
    return r;
}

bool stats_enabled() {
    static bool v = getenv("GIO_STATS") != nullptr;
    return v;
}

void print_stats() {
    size_t mmaps = 0, bytes = 0, entries = 0;
    grt::fd_table().cache().stats(mmaps, bytes, entries);
    fprintf(stderr, "[g-io] mmaps=%zu cached_entries=%zu bytes_in_ram=%zu\n",
            mmaps, entries, bytes);
}

// открыт ли путь на чтение? (O_WRONLY/O_RDWR/O_APPEND/O_CREAT -> системный путь)
bool read_only(int flags) {
    const int acc = flags & O_ACCMODE;
    return acc == O_RDONLY && !(flags & (O_CREAT | O_TRUNC | O_APPEND));
}

// Reentry-guard: gcore::MmapFile::open внутри вызывает ::open — под LD_PRELOAD
// это снова наш hook. Если мы уже внутри shim-слоя (ингestируем файл), вызываем
// реальную libc напрямую, иначе — бесконечная рекурсия.
thread_local bool g_in_shim = false;

struct ShimGuard {
    bool was_in;
    ShimGuard() : was_in(g_in_shim) { g_in_shim = true; }
    ~ShimGuard() { g_in_shim = was_in; }
};

} // namespace

// ---- перехваченные вызовы ----

extern "C" {

int open(const char* path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
    }
    if (getenv("GIO_DEBUG")) fprintf(stderr, "[g-io] open '%s' flags=%x\n", path, flags);
    if (getenv("GIO_DEBUG")) {
        fprintf(stderr, "[g-io]   in_shim=%d ro=%d plat=%d\n",
                (int)g_in_shim, (int)read_only(flags),
                (int)grt::fd_table().vfs().platform());
    }
    if (!g_in_shim && path && read_only(flags) &&
        grt::fd_table().vfs().platform() == grt::Platform::Linux) {
        ShimGuard guard;
        int fd = grt::fd_table().open_read(path);
        if (getenv("GIO_DEBUG")) fprintf(stderr, "[g-io]   -> open_read=%d\n", fd);
        if (fd >= 0) return fd;   // fake fd — mmap-срез готов
    }
    return real().open ? real().open(path, flags, mode) : -1;
}

int open64(const char* path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
    }
    if (!g_in_shim && path && read_only(flags) &&
        grt::fd_table().vfs().platform() == grt::Platform::Linux) {
        ShimGuard guard;
        int fd = grt::fd_table().open_read(path);
        if (fd >= 0) return fd;
    }
    return real().open64 ? real().open64(path, flags, mode) : -1;
}

int openat(int dirfd, const char* path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
    }
    // перехватываем только абсолютные пути или AT_FDCWD (относительные к cwd)
    if (!g_in_shim && path && read_only(flags) && (dirfd == AT_FDCWD || path[0] == '/') &&
        grt::fd_table().vfs().platform() == grt::Platform::Linux) {
        // относительный путь при AT_FDCWD — нормируем к абсолютному через getcwd
        std::string full;
        if (path[0] != '/') {
            char cwd[4096];
            if (getcwd(cwd, sizeof(cwd))) { full = cwd; full += '/'; }
            full += path;
        } else {
            full = path;
        }
        ShimGuard guard;
        int fd = grt::fd_table().open_read(full);
        if (fd >= 0) return fd;
    }
    return real().openat ? real().openat(dirfd, path, flags, mode) : -1;
}

ssize_t read(int fd, void* buf, size_t count) {
    if (grt::fd_table().is_fake(fd)) {
        if (getenv("GIO_DEBUG")) {
            fprintf(stderr, "[g-io] read hook fake fd=%d count=%zu\n", fd, count);
        }
        return grt::fd_table().read(fd, buf, count);
    }
    return real().read ? real().read(fd, buf, count) : -1;
}

// __read_chk: glibc fortify-вариант read (wc/grep собираются с _FORTIFY_SOURCE).
// Четвёртый аргумент — размер буфера для проверки; для fake fd просто шлём в наш read.
ssize_t __read_chk(int fd, void* buf, size_t count, size_t buflen) {
    if (grt::fd_table().is_fake(fd)) {
        if (getenv("GIO_DEBUG")) {
            fprintf(stderr, "[g-io] __read_chk fake fd=%d count=%zu buflen=%zu\n", fd, count, buflen);
        }
        return grt::fd_table().read(fd, buf, count);
    }
    return real().readchk ? real().readchk(fd, buf, count, buflen) : -1;
}

// pread: позиционное чтение без изменения позиции (grep/md5sum используют)
ssize_t pread(int fd, void* buf, size_t count, off_t offset) {
    if (grt::fd_table().is_fake(fd)) {
        if (offset < 0) { errno = EINVAL; return -1; }
        return grt::fd_table().pread(fd, buf, count, static_cast<uint64_t>(offset));
    }
    return real().pread ? real().pread(fd, buf, count, offset) : -1;
}

ssize_t pread64(int fd, void* buf, size_t count, off64_t offset) {
    if (grt::fd_table().is_fake(fd)) {
        if (offset < 0) { errno = EINVAL; return -1; }
        return grt::fd_table().pread(fd, buf, count, static_cast<uint64_t>(offset));
    }
    return real().pread64 ? real().pread64(fd, buf, count, offset) : -1;
}

off_t lseek(int fd, off_t offset, int whence) {
    if (grt::fd_table().is_fake(fd)) {
        return grt::fd_table().lseek(fd, offset, whence);
    }
    return real().lseek ? real().lseek(fd, offset, whence) : -1;
}

off64_t lseek64(int fd, off64_t offset, int whence) {
    if (grt::fd_table().is_fake(fd)) {
        return static_cast<off64_t>(grt::fd_table().lseek(fd, static_cast<off_t>(offset), whence));
    }
    return real().lseek64 ? real().lseek64(fd, offset, whence) : -1;
}

int close(int fd) {
    if (grt::fd_table().is_fake(fd)) {
        return grt::fd_table().close(fd) ? 0 : -1;
    }
    return real().close ? real().close(fd) : -1;
}

int fstat(int fd, struct stat* st) {
    if (getenv("GIO_DEBUG")) fprintf(stderr, "[g-io] fstat fd=%d fake=%d\n", fd,
                                     (int)grt::fd_table().is_fake(fd));
    if (grt::fd_table().is_fake(fd)) {
        grt::Slice s;
        if (!grt::fd_table().stat(fd, &s)) { errno = EBADF; return -1; }
        std::memset(st, 0, sizeof(*st));
        st->st_dev   = s.dev;                 // реальный исходный файл — консистентно
        st->st_ino   = s.ino;
        st->st_mode  = S_IFREG | 0444;        // read-only
        st->st_nlink = 1;
        st->st_uid   = 0; st->st_gid = 0;
        st->st_size  = static_cast<off_t>(s.size);
        st->st_blksize = 4096;
        st->st_blocks  = static_cast<blkcnt_t>((s.size + 511) / 512);
        st->st_mtime = 0; st->st_ctime = 0; st->st_atime = 0;
        return 0;
    }
    return real().fstat ? real().fstat(fd, st) : -1;
}

// fstat64: coreutils собраны с _FILE_OFFSET_BITS=64 и зовут fstat64 напрямую
int fstat64(int fd, struct stat64* st) {
    if (grt::fd_table().is_fake(fd)) {
        grt::Slice s;
        if (!grt::fd_table().stat(fd, &s)) { errno = EBADF; return -1; }
        std::memset(st, 0, sizeof(*st));
        st->st_dev   = s.dev;
        st->st_ino   = s.ino;
        st->st_mode  = S_IFREG | 0444;
        st->st_nlink = 1;
        st->st_size  = static_cast<off64_t>(s.size);
        st->st_blksize = 4096;
        st->st_blocks  = static_cast<blkcnt64_t>((s.size + 511) / 512);
        return 0;
    }
    return real().fstat64 ? real().fstat64(fd, st) : -1;
}

// fcntl: только F_GETFL для fake fd (cat/ядро проверяют режим доступа)
int fcntl(int fd, int cmd, ...) {
    va_list ap; va_start(ap, cmd);
    if (grt::fd_table().is_fake(fd)) {
        if (getenv("GIO_DEBUG")) {
            fprintf(stderr, "[g-io] fcntl fake fd=%d cmd=%d\n", fd, cmd);
        }
        if (cmd == F_GETFL) {
            va_end(ap);
            return O_RDONLY;               // fake fd всегда read-only
        }
        if (cmd == F_GETFD) {
            va_end(ap);
            return 0;                       // не закрыт по exec
        }
        va_end(ap);
        errno = EINVAL;                    // остальные fcntl на fake fd не поддерживаются
        return -1;
    }
    // реальный fd: пробрасываем как есть (третий аргумент может отсутствовать)
    void* arg = va_arg(ap, void*);
    va_end(ap);
    return real().fcntl ? real().fcntl(fd, cmd, arg) : -1;
}

// mmap/munmap: если приложение само mmap'ит файл (без open/read), пропускаем —
// gcore-слайс уже в памяти, повторный mmap не нужен. Пробрасываем насквозь.
void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
    if (grt::fd_table().is_fake(fd)) {
        // fake fd: файл уже в RAM (gcore::MmapFile). Возвращаем прямой адрес
        // слайса — zero-copy, данные не копируются в отдельный mmap.
        const uint8_t* slice = grt::fd_table().mmap_slice(fd, static_cast<size_t>(offset), length);
        if (slice) return const_cast<uint8_t*>(slice);
        // вне границ слайса — падаем как настоящий mmap (SIGBUS эквивалент)
        errno = ENXIO;
        return MAP_FAILED;
    }
    return real().mmap ? real().mmap(addr, length, prot, flags, fd, offset) : MAP_FAILED;
}

int munmap(void* addr, size_t length) {
    return real().munmap ? real().munmap(addr, length) : -1;
}

// posix_fadvise: fake fd — файл уже в RAM, совет не нужен. GNU sort/cat
// вызывают для чтения; EBADF они не переживают.
int posix_fadvise(int fd, off_t off, off_t len, int advice) {
    if (grt::fd_table().is_fake(fd)) return 0;
    return real().posix_fadvise ? real().posix_fadvise(fd, off, len, advice) : 0;
}

int fadvise64(int fd, off_t off, off_t len, int advice) {
    if (grt::fd_table().is_fake(fd)) return 0;
    return real().posix_fadvise ? real().posix_fadvise(fd, off, len, advice) : 0;
}

// ioctl: только FIONREAD (cat -n спрашивает, сколько байт доступно).
// Остальное пробрасываем — для fake fd это всегда ошибка.
int ioctl(int fd, unsigned long req, ...) {
    va_list ap; va_start(ap, req);
    void* arg = va_arg(ap, void*);
    va_end(ap);
    if (grt::fd_table().is_fake(fd)) {
        if (req == FIONREAD) {
            grt::Slice s;
            if (!grt::fd_table().stat(fd, &s)) { errno = EBADF; return -1; }
            int* p = static_cast<int*>(arg);
            if (p) {
                // FIONREAD: сколько байт ещё можно прочитать (от текущей позиции)
                uint64_t pos = 0;
                *p = static_cast<int>(s.size > pos ? s.size - pos : 0);
            }
            return 0;
        }
        errno = ENOTTY;
        return -1;
    }
    return real().ioctl ? real().ioctl(fd, req, arg) : -1;
}

// ---- fdopen: glibc stdio поверх fake fd ----
// Проблема: stdio (fgets/fread/fdopen) внутри libc вызывает НЕ-интерпозируемый
// внутренний fcntl(fd, F_GETFL) — для fake fd (>=0x6000) это EBADF → sort/grep
// "Bad file descriptor". Решение: fake fd НЕ отдаём stdio, а создаём FILE*
// через fopencookie, который читает прямо из mmap-слайса (ноль копий).

using cookie_read_fn  = ssize_t (*)(void*, char*, size_t);
using cookie_seek_fn  = int (*)(void*, off64_t*, int);
using cookie_close_fn = int (*)(void*);

struct CookieCtx {
    int fd;
};

static ssize_t cookie_read(void* c, char* buf, size_t n) {
    auto* ctx = static_cast<CookieCtx*>(c);
    return grt::fd_table().read(ctx->fd, buf, n);
}

static int cookie_seek(void* c, off64_t* off, int whence) {
    auto* ctx = static_cast<CookieCtx*>(c);
    off_t r = grt::fd_table().lseek(ctx->fd, static_cast<off_t>(*off), whence);
    if (r < 0) return -1;
    *off = r;
    return 0;
}

static int cookie_close(void* c) {
    auto* ctx = static_cast<CookieCtx*>(c);
    grt::fd_table().close(ctx->fd);
    delete ctx;
    return 0;
}

FILE* fdopen(int fd, const char* mode) {
    if (grt::fd_table().is_fake(fd)) {
        auto* ctx = new CookieCtx{fd};
        // glibc fopencookie: cookie-файл поверх callbacks. Режим "r" — только чтение.
        cookie_io_functions_t fns;
        fns.read  = cookie_read;
        fns.write = nullptr;
        fns.seek  = cookie_seek;
        fns.close = cookie_close;
        return fopencookie(ctx, "r", fns);
    }
    return real().fdopen ? real().fdopen(fd, mode) : nullptr;
}

// ---- печать статистики при выгрузке (если GIO_STATS=1) ----
__attribute__((destructor)) static void g_io_stats_dtor() {
    if (stats_enabled()) print_stats();
}

} // extern "C"
