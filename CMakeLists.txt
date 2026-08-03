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

# ===================== g-grep: shared lib (C-ABI) =====================
add_library(g-tools SHARED
  tools/g-grep/g_grep.cpp
  tools/g-strings/g_strings.cpp
  tools/g-analyze/g_analyze.cpp)
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

# ===================== бенчмарк-генератор =====================
add_executable(gen_data benchmarks/gen_data.cpp)
