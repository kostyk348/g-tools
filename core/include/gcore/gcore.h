// gcore — ядро экосистемы g-tools.
// Zero-copy dataflow DAG engine: mmap → lock-free chunk → SIMD scan → flat arena → C-ABI.
//
// Философия (из спеки g-proto):
//   - НИКАКИХ std::mutex в горячем цикле (только std::atomic, memory_order_relaxed)
//   - НИКАКИХ malloc/new в горячем цикле (только FlatArena, aligned_alloc(64))
//   - НИКАКОГО strtod/sscanf/stdio — SIMD/SWAR парсинг
//   - Единый mmap-буфер, ноды графа читают его напрямую
#pragma once

#include "gcore/mmap_ingest.h"
#include "gcore/chunk_allocator.h"
#include "gcore/flat_arena.h"
#include "gcore/simd_scan.h"
#include "gcore/c_abi.h"
