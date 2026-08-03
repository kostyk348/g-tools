// mmap_ingest.h — нода 1 графа: zero-copy ingest файла в виртуальную память.
// mmap(PROT_READ, MAP_SHARED) + madvise(MADV_WILLNEED | MADV_SEQUENTIAL).
// Ноль копирований из kernel space в user space.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

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
        fd_ = ::open(path, O_RDONLY);
        if (fd_ < 0) return false;

        struct stat st;
        if (::fstat(fd_, &st) != 0 || st.st_size < 0) {
            ::close(fd_); fd_ = -1;
            return false;
        }
        size_ = static_cast<size_t>(st.st_size);
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

        void* m = ::mmap(nullptr, size_, PROT_READ, flags, fd_, 0);
        if (m == MAP_FAILED) {
            ::close(fd_); fd_ = -1;
            size_ = 0;
            return false;
        }
        data_ = static_cast<uint8_t*>(m);
        ::madvise(m, size_, MADV_SEQUENTIAL | MADV_WILLNEED);
        // Huge pages снижают TLB pressure при потоковом доступе к большим файлам
        ::madvise(m, size_, MADV_HUGEPAGE);
        // fd больше не нужен — отображение живёт независимо
        ::close(fd_); fd_ = -1;
        return true;
    }

    void close() noexcept {
        if (data_) {
            ::munmap(data_, size_);
            data_ = nullptr;
            size_ = 0;
        }
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
    }

    const uint8_t* data() const noexcept { return data_; }
    size_t size() const noexcept { return size_; }
    bool valid() const noexcept { return size_ == 0 || data_ != nullptr; }

private:
    int fd_ = -1;
    uint8_t* data_ = nullptr;
    size_t size_ = 0;
};

} // namespace gcore
