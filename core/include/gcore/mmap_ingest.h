// mmap_ingest.h — нода 1 графа: zero-copy ingest файла в виртуальную память.
// mmap(PROT_READ, MAP_SHARED) + madvise(MADV_WILLNEED | MADV_SEQUENTIAL).
// Ноль копирований из kernel space в user space.
//
// ВАЖНО (g-runtime): все системные вызовы идут через raw syscall(), НЕ через
// libc. Иначе LD_PRELOAD shim (g_io) перехватит собственный ingest gcore —
// двойной mmap + munmap уничтожит кэш слайсов (self-interposition).
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// raw syscalls (Linux x86-64/ARM64): обход libc-перехватчиков
#if defined(__linux__) && defined(SYS_openat) && defined(SYS_mmap)
#include <sys/syscall.h>
#define GCORE_RAW_SYSCALL 1
#endif

namespace gcore {

class MmapFile {
public:
    MmapFile() = default;
    ~MmapFile() { close(); }

    MmapFile(const MmapFile&) = delete;
    MmapFile& operator=(const MmapFile&) = delete;

    /// Открывает файл и отображает его в память. Возвращает false при ошибке.
    bool open(const char* path) {
        close();
#ifdef GCORE_RAW_SYSCALL
        fd_ = static_cast<int>(::syscall(SYS_openat, AT_FDCWD, path, O_RDONLY));
#else
        fd_ = ::open(path, O_RDONLY);
#endif
        if (fd_ < 0) return false;

        struct stat st;
#ifdef GCORE_RAW_SYSCALL
        if (::syscall(SYS_fstat, fd_, &st) != 0 || st.st_size < 0) {
#else
        if (::fstat(fd_, &st) != 0 || st.st_size < 0) {
#endif
            ::close(fd_); fd_ = -1;
            return false;
        }
        size_ = static_cast<size_t>(st.st_size);
        st_dev_  = st.st_dev;
        st_ino_  = st.st_ino;
        st_mode_ = st.st_mode;
        if (size_ == 0) {           // пустой файл — валидный, но mmap не нужен
            ::close(fd_); fd_ = -1;
            data_ = nullptr;
            return true;
        }

        // MAP_POPULATE (prefault): страницы подтягиваются в RAM до начала работы,
        // горячий цикл не платит за page faults. Включаем только если файл заведомо
        // помещается в свободную память (иначе — своппинг и провал производительности).
        const long pages = ::sysconf(_SC_AVPHYS_PAGES);
        const uint64_t avail_bytes =
            pages > 0 ? static_cast<uint64_t>(pages) * static_cast<uint64_t>(::sysconf(_SC_PAGESIZE))
                      : (4ull << 30);
        int flags = MAP_SHARED;
        if (static_cast<uint64_t>(size_) <= avail_bytes / 2) flags |= MAP_POPULATE;

#ifdef GCORE_RAW_SYSCALL
        void* m = reinterpret_cast<void*>(::syscall(SYS_mmap, nullptr, size_, PROT_READ,
                                                    flags, fd_, 0));
#else
        void* m = ::mmap(nullptr, size_, PROT_READ, flags, fd_, 0);
#endif
        if (m == MAP_FAILED) {
            ::close(fd_); fd_ = -1;
            size_ = 0;
            return false;
        }
        data_ = static_cast<uint8_t*>(m);
#ifdef GCORE_RAW_SYSCALL
        ::syscall(SYS_madvise, m, size_, MADV_SEQUENTIAL | MADV_WILLNEED);
        ::syscall(SYS_madvise, m, size_, MADV_HUGEPAGE);
#else
        ::madvise(m, size_, MADV_SEQUENTIAL | MADV_WILLNEED);
        // Huge pages снижают TLB pressure при потоковом доступе к большим файлам
        ::madvise(m, size_, MADV_HUGEPAGE);
#endif
        // fd больше не нужен — отображение живёт независимо
        ::close(fd_); fd_ = -1;
        return true;
    }

    void close() noexcept {
        if (data_) {
#ifdef GCORE_RAW_SYSCALL
            ::syscall(SYS_munmap, data_, size_);
#else
            ::munmap(data_, size_);
#endif
            data_ = nullptr;
            size_ = 0;
        }
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
    }

    const uint8_t* data() const noexcept { return data_; }
    size_t size() const noexcept { return size_; }
    bool valid() const noexcept { return size_ == 0 || data_ != nullptr; }

    // Реальные stat-данные исходного файла (dev/ino/mode) — нужны shim-слою,
    // чтобы fstat на fake fd возвращал консистентные значения (grep/cp
    // сравнивают (st_dev,st_ino) между файлами).
    dev_t  st_dev()  const noexcept { return st_dev_; }
    ino_t  st_ino()  const noexcept { return st_ino_; }
    mode_t st_mode() const noexcept { return st_mode_; }

private:
    int fd_ = -1;
    uint8_t* data_ = nullptr;
    size_t size_ = 0;
    dev_t  st_dev_  = 0;
    ino_t  st_ino_  = 0;
    mode_t st_mode_ = 0;
};

} // namespace gcore
