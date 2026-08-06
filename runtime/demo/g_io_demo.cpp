// g-io-demo — проверка shim-слоя.
// Читает файл двумя способами:
//   1. stdio (fopen/fread)  — внутри glibc вызывает open/read → перехватывается
//   2. POSIX (open/read/lseek) — напрямую
// Без LD_PRELOAD: системные вызовы. С LD_PRELOAD=libg_io.so: mmap-слайсы.
//
// Проверка: оба способа должны прочитать одинаковое содержимое.
// GIO_STATS=1 покажет статистику mmap-хитов.
#include <cstdio>
#include <cstring>

#include <fcntl.h>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s FILE\n", argv[0]);
        return 2;
    }
    const char* path = argv[1];

    // --- способ 1: stdio ---
    FILE* f = fopen(path, "rb");
    if (!f) { perror("fopen"); return 1; }
    char buf1[4096];
    size_t n1 = fread(buf1, 1, sizeof(buf1), f);
    fclose(f);

    // --- способ 2: POSIX + lseek-подобный доступ ---
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    char buf2[4096];
    ssize_t n2 = read(fd, buf2, sizeof(buf2));
    // прыжок вперёд и обратно — проверить lseek на fake fd
    off_t mid = lseek(fd, n2 > 100 ? 100 : 0, SEEK_SET);
    (void)mid;
    close(fd);

    printf("stdio read  : %zu bytes\n", n1);
    printf("posix read  : %zd bytes\n", n2);
    printf("first bytes : %.16s\n", buf1);
    printf("match       : %s\n",
           (n1 == static_cast<size_t>(n2) && memcmp(buf1, buf2, n1) == 0) ? "OK" : "MISMATCH");
    return 0;
}
