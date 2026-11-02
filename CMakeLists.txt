cmake_minimum_required(VERSION 3.20)
project(g-tools LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Флаги ядра по спеке g-proto: -O3 -march=native -mavx2 -mfma -ffast-math -pthread
add_compile_options(-O3 -march=native -mavx2 -mfma -ffast-math -pthread
                    -Wall -Wextra)

# ===================== gcore: header-only ядро =====================
add_library(gcore INTERFACE)
target_include_directories(gcore INTERFACE core/include)

# ===================== g-runtime: shim-слой (LD_PRELOAD) =====================
add_library(g_io SHARED runtime/src/g_io_posix.cpp)
target_include_directories(g_io PRIVATE runtime/include)
target_link_libraries(g_io PRIVATE gcore dl pthread)
set_target_properties(g_io PROPERTIES
  OUTPUT_NAME g_io
  POSITION_INDEPENDENT_CODE ON)

add_executable(g-io-demo runtime/demo/g_io_demo.cpp)
target_link_libraries(g-io-demo PRIVATE gcore)

# ===================== g-grep: shared lib (C-ABI) =====================
add_library(g-tools SHARED
  tools/g-grep/g_grep.cpp
  tools/g-strings/g_strings.cpp
  tools/g-analyze/g_analyze.cpp
  tools/g-scan/g_scan.cpp)
target_link_libraries(g-tools PRIVATE gcore pthread)
set_target_properties(g-tools PROPERTIES
  OUTPUT_NAME g-tools
  POSITION_INDEPENDENT_CODE ON)

# ===================== CLI: g-grep, g-strings =====================
add_executable(g-grep tools/g-grep/g_grep_cli.cpp)
target_link_libraries(g-grep PRIVATE g-tools gcore)

add_executable(g-strings tools/g-strings/g_strings_cli.cpp)
target_link_libraries(g-strings PRIVATE g-tools gcore)

# ===================== тесты =====================
enable_testing()
add_executable(test_core tests/test_core.cpp)
target_link_libraries(test_core PRIVATE g-tools gcore pthread)
add_test(NAME test_core COMMAND test_core)

add_executable(test_strings tests/test_strings.cpp)
target_link_libraries(test_strings PRIVATE g-tools gcore pthread)
add_test(NAME test_strings COMMAND test_strings)

# Расширенные C-ABI ноды: hash/hist/entropy/bytes/xor/sections/diff/scan/recon
add_executable(test_analyze tests/test_analyze.cpp)
target_link_libraries(test_analyze PRIVATE g-tools gcore pthread)
add_test(NAME test_analyze COMMAND test_analyze)

# Детерминированный API-фаззер: случайные (валидные) входы + инварианты ABI
add_executable(fuzz_api tests/fuzz_api.cpp)
target_link_libraries(fuzz_api PRIVATE g-tools gcore pthread)
add_test(NAME fuzz_api COMMAND fuzz_api)

# ctypes-тест (герметичный): python3 tests/test_extra_nodes.py <libg-tools.so>
find_program(PYTHON3_EXECUTABLE NAMES python3 python)
if (PYTHON3_EXECUTABLE)
  add_test(NAME test_extra_nodes
           COMMAND ${PYTHON3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/test_extra_nodes.py
                   $<TARGET_FILE:g-tools>)
endif()

# ===================== бенчмарк-генератор =====================
add_executable(gen_data benchmarks/gen_data.cpp)
