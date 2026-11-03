# g-tools — the Zero-Copy Dataflow DAG Engine ecosystem

[![Release](https://img.shields.io/github/v/release/kostyk348/g-tools?sort=semver&color=blue)](https://github.com/kostyk348/g-tools/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/kostyk348/g-tools/ci.yml?branch=main&label=CI)](https://github.com/kostyk348/g-tools/actions/workflows/ci.yml)
[![tests](https://img.shields.io/badge/ctest-5%20suites%20%2B%20API%20fuzz-22c55e)](#structure)
[![Rust bindings](https://img.shields.io/badge/Rust-gcore%20bindings-orange)](bindings/rust/README.md)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![Last commit](https://img.shields.io/github/last-commit/kostyk348/g-tools?branch=main)](https://github.com/kostyk348/g-tools/commits/main)

English · [Русский](README.ru.md)

A monorepo built on the **g-proto / g-core** architecture: replacing POSIX I/O +
scalar parsing with a dataflow DAG over a single mmap'd memory region, SIMD
(AVX2 + AVX-512 with runtime dispatch via `cpu_has_avx512()`) and lock-free
synchronization.

## Pipeline (every tool is a graph of nodes)

```
[file] --mmap--> [chunk allocator] --> [SIMD scan nodes] --> [flat arena] --> [C-ABI] --> [Python/NumPy]
         node 1        node 2              node 3                 node 4        node 5        node 6
```

Core invariants (the important ones):
- **Zero `std::mutex`** in the hot loop — only `std::atomic` (relaxed) + fetch_add.
- **Zero `malloc/new`** in the hot loop — only `FlatArena` (`aligned_alloc(64)`).
- **Lines are never split** across chunk boundaries (a `ChunkAllocator`
  invariant, covered by a test).
- **C ABI** for Python/Rust/Go: the result is a flat arena + an owner handle.

## Structure

```
core/include/gcore/    the core (header-only): mmap_ingest, chunk_allocator,
                       flat_arena, simd_scan, c_abi
tools/g-grep/          the first tool: CLI + the g-tools shared library
bindings/python/       ctypes binding (g_grep.py)
tests/                 unit tests of the invariants
benchmarks/            CSV generator + comparison scripts
```

## Build and test

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure   # 5 suites: core, strings,
                                             # analyze (13 C-ABI nodes), API fuzz,
                                             # ctypes (hermetic fixtures)
cargo test --manifest-path bindings/rust/Cargo.toml  # Rust bindings
```

The deterministic API fuzzer (`fuzz_api`) checks node contracts against
reference implementations on random inputs; CI runs 3000 iterations plus an
ASan/UBSan pass over every test.

## Quick start

```bash
./build/gen_data 20000000 /tmp/g_bench.csv            # 20M CSV lines
./build/g-grep -c NEEDLE /tmp/g_bench.csv             # count (16 workers)
grep -c NEEDLE /tmp/g_bench.csv                       # compare with GNU grep
python3 -c "from bindings.python.g_grep import grep; print(len(grep('/tmp/g_bench.csv','NEEDLE')))"
```

## Benchmark (30M lines / 1.8 GB CSV, ~33% hit lines)

| Tool | Time | Throughput |
|---|---|---|
| `grep -c` (GNU, 1 thread) | 896 ms | ~2.0 GB/s |
| **`g-grep -c`** (16 workers) | **116 ms** | **~15.5 GB/s** |
| Speedup | **7.7x** | |

Notes:
- Scalability is bounded by memory/disk (page cache), not CPU: on the benchmark
  system RAM was 80%+ busy (the fca project), so 1→16 workers only give ~1.2x.
- `MAP_POPULATE` is enabled automatically only when the file is ≤ half of free
  RAM (otherwise swapping kills performance).
- Results are reproducible: `./build/gen_data N` + comparison on the same file.

## Languages: C++ core + Rust bindings

The core stays **C++** — a deliberate decision, not inertia. g-tools' value is
hand-written AVX-512 intrinsics, mmap tuning (`MAP_POPULATE` sized to free RAM)
and lock-free chunks; a Rust rewrite would be the same `unsafe` + `std::arch`
in different syntax, with no safety win and a risk of losing the benchmark
(7.7x vs GNU grep). The cross-language boundary already exists — the **C ABI**,
in both directions: Python uses ctypes, Rust uses the official bindings:

```bash
cargo test --manifest-path bindings/rust/Cargo.toml   # gcore-sys + gcore
```

```rust
use gcore::{grep_count, scan, strings};
let n = grep_count("/tmp/big.csv", "row1").unwrap_or(0);
let sigs = scan("/tmp/firmware.bin", &["MZ", "PK\x03\x04"]);
let printable = strings("/tmp/firmware.bin", 6, None);
```

Details and ABI contracts: [bindings/rust/README.md](bindings/rust/README.md).

## Ecosystem (roadmap)

| Tool | Status | Description |
|---|---|---|
| **g-grep** | ✅ done | mmap + lock-free chunks + SIMD scan |
| **g-strings** | ✅ done | printable strings with offsets + entropy filter, numpy output |
| **g-analyze** | ✅ done | RE-recon nodes: entropy_profile, bytes, hash, hist, unicode, sections, diff, xor, recon |
| **g-scan** | ✅ done | YARA-like SIMD signature scan (Aho-Corasick + SIMD skip) |
| **g-sort** | ⏳ planned | SIMD chunk sort + k-way merge into the arena |
| **g-query** | ⏳ planned | SQL nodes over CSV/JSON without import (the flagship) |
| **g-bus** | ⏳ planned | mmap ring-buffer IPC, Python ↔ C++ bridge (<2ns) |
| **g-dedup** | ⏳ planned | hash dedup via mmap + bloom |
| **g-pcap** | ⏳ planned | streaming packet analyzer (header fields as delimiters) |
| **gcore (Rust)** | ✅ done | safe bindings to all C-ABI nodes (`bindings/rust`) |

## g-strings (for RE / neural nets)

Extracts printable strings `[0x20..0x7E]` from a binary in one mmap pass.
**The output is a flat `{offset, len}` array (16 bytes/string), the content is
NOT copied**: Python reads strings by offset straight from the file's
`np.memmap` → zero copies down to the neural net.

```bash
./build/g-strings --min 4 /usr/bin/qemu-system-x86_64      # offset\tlen\ttext
./build/g-strings --count --max-entropy 5.0 file.bin        # filters junk from compressed regions
```

```python
from g_strings import strings
recs, data = strings("fw.bin", min_len=6, max_entropy=5.0)  # numpy view + mmap
for r in recs[:5]: print(hex(r["offset"]), bytes(data[r["offset"]:r["offset"]+r["len"]]))
```

| Metric (28 MB ELF) | g-strings | GNU strings |
|---|---|---|
| Time | 38 ms | 40 ms |
| Strings (min 4) | 147 555 | 148 144 |
| Divergence | **0.4%** | — |

Known difference from GNU strings (~0.4-1%): edge cases at chunk boundaries
and handling of the last line without a terminator. On files larger than RAM
(firmware, VFS images) the gap grows: GNU strings is single-threaded + read(),
g-strings is 16 workers + mmap.

## g-analyze — RE-recon nodes (C-ABI, all zero-copy)

The extended nodes live in `tools/g-analyze/g_analyze.cpp`, all through one
pipeline (mmap → chunks → SIMD → arena → C-ABI):

| Node | Input | Output | Purpose |
|---|---|---|---|
| `g_entropy_profile` | path, block | `{offset, entropy}[]` | plain/code/compressed map per block |
| `g_bytes` | path, offset, len | raw bytes | slice for reading magic/structures |
| `g_hash` | path | `{fnv1a64, crc32c}` | identification/dedup (CRC32C — SSE4.2) |
| `g_hist` | path | `u64[256]` | byte histogram (densities/zeros/tables) |
| `g_unicode` | path, min_len, max_entropy | `{offset, len}[]` | UTF-16LE strings (Windows/.NET/PE) |
| `g_sections` | path | `{offset, size, entropy, name, type}[]` | ELF/PE section recon |
| `g_diff` | path_a, path_b, block | `{offset_a, offset_b, len, status}[]` | block diff of versions/patches |
| `g_xor` | path, offset, len, key | decoded bytes | XOR obfuscation (floss-style) |
| `g_recon` | path | a map of the whole file | hash + hist + entropy regions + string samples in one pass |

Key details:
- `g_strings`/`g_unicode`: workers over **64-byte blocks** with AVX-512
  (`printable_mask64`/`zero_mask64`, uint64 masks) — with `-march=native` on
  Zen 4 the zmm primitives switch on automatically, with runtime dispatch for
  non-AVX512 CPUs.
- `g_recon`: a full RE map of the file in one mmap pass — FNV-1a 64 + CRC32C
  (SSE4.2), a u64[256] byte histogram, block entropy segmentation (≥4096), up
  to 2000 string samples. Output is a flat buffer
  `[header][hist][entropy][strings]`.
- `g_unicode`: SIMD scan over **pairs** with two alignments (even/odd) — UTF-16
  strings starting at odd offsets are not lost; the 33rd byte for the pair
  (i+31, i+32) comes from `zero_mask(base+i+1) << 1` packed into uint64
  (otherwise the run breaks on every block).
- `g_sections`: minimal ELF64/ELF32/PE parsers without system headers, every
  read through `within()` mmap bounds checks; per-section entropy.
- `g_diff`: per-block memcmp, adjacent CHANGED runs grouped; A/B tails →
  DELETED/INSERTED.

Direct calls from Python (ctypes):

```bash
python3 tests/test_extra_nodes.py   # tests of all 8 nodes: hash, hist, unicode, sections, diff, xor
```

All nodes are exposed as MCP tools (see below).

## g-scan — multi-pattern SIMD signature scan

`tools/g-scan/g_scan.cpp`: YARA-like search for up to 1000 patterns in one pass.

- **Aho-Corasick** over the patterns — linear time for all patterns at once.
- **SIMD skip**: before the AC run, the pattern first bytes are checked with
  64-byte AVX2/AVX-512 masks (`count_byte`/`find_byte`), dead areas of the
  file are skipped vectorially.
- Output — a flat `{offset, pattern_idx}` array (16 bytes), Python decodes it
  into numpy without copies.

```bash
python3 tests/test_scan.py  # magic/signature search
```

## The g-tools MCP server

`server.py` — FastMCP over libg-tools.so, registered in opencode.json. 12 tools:

`g_strings`, `g_unicode`, `g_entropy_profile`, `g_grep_lines`, `g_bytes`,
`g_hash`, `g_hist`, `g_sections`, `g_diff`, `g_xor`, `g_recon`, `g_scan`

RE recon in a single neural-net request: `g_recon` → the full file map
(hash + hist + entropy regions + strings) in one call, then `g_bytes`/
`g_strings` at interesting offsets → `g_sections` for ELF/PE → `g_scan` for
signature search → `g_xor` if strings are encrypted.
(The "map first in 300ms, then targeted analysis" principle.)

## g-runtime: a shim layer for legacy binaries (LD_PRELOAD)

`runtime/` — a portable layer between a legacy binary (PC/PS2) and a modern
host (Linux/Vita). Two levels:

- **Level A** (`runtime/src/g_io_posix.cpp`): LD_PRELOAD hooks for
  `open/open64/openat/read/pread/read64/lseek/lseek64/close/fstat/fstat64/
  fcntl/mmap/munmap/posix_fadvise/ioctl/fdopen` → the file is read through
  `gcore::MmapFile` (mmap, MAP_POPULATE) and handed to the program as a fake
  fd (>= 0x6000). Repeated reads are memcpy from RAM, zero syscalls.
- **Level B** (`runtime/include/grt/g_runtime.hpp`): VFS path normalization
  (C:\ → /ux0:data/), mmap slice cache, fake-fd table. Links directly into
  Vita/PS2 projects (eboot), no dlsym.

Key decisions beaten out on coreutils:

- **raw syscalls in gcore** (`GCORE_RAW_SYSCALL`): gcore::MmapFile::open goes
  through `syscall(SYS_openat/SYS_mmap/...)`, bypassing the shim's own hooks —
  otherwise infinite recursion and a double mmap.
- **`__read_chk`** (the fortify variant of read): wc/grep are built with
  `_FORTIFY_SOURCE` and call it instead of `read` — without the hook, EBADF.
- **`st_dev/st_ino` in fake fds**: grep/cp compare (dev,ino) of files with each
  other; zeros broke the "input == output" and "replaced while copied" checks.
- **`fopencookie` for fdopen**: glibc stdio internally calls the
  non-interposable `fcntl(fd,F_GETFL)` — a fake fd doesn't fit it, so fdopen
  over a fake fd builds the FILE* via fopencookie, reading straight from the
  mmap slice.
- **`posix_fadvise`/`ioctl(FIONREAD)`** return no-ops for fake fds (the file
  is already in RAM — no advice needed).

```bash
LD_PRELOAD=./build/libg_io.so cat big_file          # read from RAM
GIO_STATS=1 LD_PRELOAD=./build/libg_io.so wc -w f   # mmap statistics
./runtime/test_coreutils.sh      # 21/21 coreutils under the shim
./runtime/test_coreutils_ext.sh  # +11 text/hash/search tools
```

Verified: cat/head/tail/wc/sort/grep/sed/awk/cp/md5sum/sha256sum on files up
to 474MB — output byte-identical to running without the shim.
