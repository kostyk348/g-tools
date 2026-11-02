//! build.rs — собирает libg-tools (C++) через cmake и линкует её.
//!
//! Требования: cmake >= 3.20, C++20-компилятор (gcc/clang с AVX2; ядро
//! собирается с `-march=native`). Кросс-компиляция не поддерживается
//! (runtime-диспатч SIMD всё равно требует x86-64 хоста для бенчмарков).

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Репозиторий g-tools: bindings/rust/gcore-sys -> вверх 3 уровня.
fn repo_root() -> PathBuf {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    manifest
        .ancestors()
        .nth(3)
        .map(|p| p.to_path_buf())
        .expect("bindings/rust/gcore-sys внутри репозитория")
}

fn main() {
    let repo = repo_root();
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let build_dir = out.join("gtools-build");

    let configure = Command::new("cmake")
        .arg("-B")
        .arg(&build_dir)
        .arg("-S")
        .arg(&repo)
        .arg("-DCMAKE_BUILD_TYPE=Release")
        .status()
        .expect("cmake (configure) не удался — установлен ли cmake >= 3.20?");
    assert!(configure.success(), "cmake configure провалился");

    let build = Command::new("cmake")
        .arg("--build")
        .arg(&build_dir)
        .args(["--config", "Release"])
        .arg("-j")
        .status()
        .expect("cmake --build не удался");
    assert!(build.success(), "сборка libg-tools провалилась");

    // cmake кладёт libg-tools.so в корень build dir (нет CMAKE_LIBRARY_OUTPUT_DIRECTORY)
    let lib_dir = find_lib_dir(&build_dir);
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=dylib=g-tools");
    // rpath, чтобы тесты/бинарники находили .so без LD_LIBRARY_PATH
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_dir.display());

    println!(
        "cargo:rerun-if-changed={}",
        repo.join("core/include").display()
    );
    for tool in ["g-grep", "g-strings", "g-analyze", "g-scan"] {
        println!(
            "cargo:rerun-if-changed={}",
            repo.join("tools").join(tool).display()
        );
    }
    println!(
        "cargo:rerun-if-changed={}",
        repo.join("CMakeLists.txt").display()
    );
}

fn find_lib_dir(build_dir: &Path) -> PathBuf {
    let candidates = [
        build_dir.to_path_buf(),
        build_dir.join("Release"),
        build_dir.join("Debug"),
    ];
    for dir in candidates {
        let found = ["libg-tools.so", "libg-tools.dylib", "g-tools.dll"]
            .iter()
            .any(|l| dir.join(l).exists());
        if found {
            return dir;
        }
    }
    panic!("libg-tools не найдена в {:?} после сборки", build_dir);
}
