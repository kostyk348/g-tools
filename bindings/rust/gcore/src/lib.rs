//! # gcore — безопасная обёртка над C ABI g-tools
//!
//! Zero-copy конвейер: mmap → lock-free chunks → SIMD scan → flat arena → C ABI.
//! Rust-сторона получает плоскую арену как `&[u8]` и освобождает её в Drop.
//!
//! ```no_run
//! use gcore::{grep_count, scan, strings, xor_bytes};
//!
//! let hits = grep_count("/tmp/big.csv", "row1").unwrap_or(0);
//! println!("hits: {hits}");
//! let pats = ["magic", "MZ"];
//! let matches = scan("/tmp/firmware.bin", &pats);
//! println!("scan: {matches:?}");
//! let printable = strings("/tmp/firmware.bin", 6, None);
//! let decoded = xor_bytes("/tmp/firmware.bin", 0, 0, 0xAA);
//! println!("{} strings, {} bytes decoded", printable.len(), decoded.iter().flatten().count());
//! ```
//!
//! Контракты, унаследованные от ABI:
//! - `grep_count` возвращает `None` при ошибке (нет файла и т.п.),
//! - узлы возвращают пустой результат при ошибке (отличить «пусто» от «ошибки»
//!   для count-функций можно по `None`; для арены — по `Result::is_error`),
//! - needle/паттерны не могут содержать `'\0'` (C-строки),
//! - `strings`/`unicode`: `max_entropy: Option<f64>` — `None` = фильтр выключен,
//! - `unicode`-длины в байтах, `min_len` в символах UTF-16 (см. c_abi.h).

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;

use gcore_sys as sys;

/// Плоская арена результата. Освобождает память в Drop (g_result_free).
pub struct RawResult {
    inner: sys::g_result,
}

impl RawResult {
    fn from(r: sys::g_result) -> RawResult {
        RawResult { inner: r }
    }

    /// true, если узел сообщил об ошибке (data == NULL).
    pub fn is_error(&self) -> bool {
        self.inner.data.is_null()
    }

    /// Байты арены. Пусто при ошибке/пустом результате.
    pub fn bytes(&self) -> &[u8] {
        if self.inner.data.is_null() || self.inner.size == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.inner.data, self.inner.size) }
    }

    /// Число записей, заявленное узлом.
    pub fn count(&self) -> usize {
        self.inner.count
    }

    /// Разбор арены как массива записей фиксированного размера.
    fn records<T>(&self) -> &[T] {
        if self.inner.data.is_null() || self.inner.size == 0 {
            return &[];
        }
        assert_eq!(
            self.inner.size % std::mem::size_of::<T>(),
            0,
            "размер арены не кратен размеру записи"
        );
        unsafe {
            std::slice::from_raw_parts(
                self.inner.data as *const T,
                self.inner.size / std::mem::size_of::<T>(),
            )
        }
    }
}

impl Drop for RawResult {
    fn drop(&mut self) {
        unsafe { sys::g_result_free(&mut self.inner) };
    }
}

fn c_path(path: impl AsRef<Path>) -> CString {
    CString::new(path.as_ref().as_os_str().to_string_lossy().as_bytes())
        .expect("путь не должен содержать NUL")
}

fn c_str(s: &str) -> CString {
    CString::new(s.as_bytes()).expect("строка не должна содержать NUL")
}

// ------------------------------------------------------------------ g-grep

/// g_grep_count: число строк-хитов. `None` при ошибке.
pub fn grep_count(path: impl AsRef<Path>, needle: &str) -> Option<u64> {
    let n = unsafe { sys::g_grep_count(c_path(path).as_ptr(), c_str(needle).as_ptr()) };
    if n < 0 {
        None
    } else {
        Some(n as u64)
    }
}

/// g_grep: строки-хиты как Vec<String> (из плоской арены, \0-terminated).
pub fn grep_strings(path: impl AsRef<Path>, needle: &str) -> Vec<String> {
    let r = RawResult::from(unsafe { sys::g_grep(c_path(path).as_ptr(), c_str(needle).as_ptr()) });
    decode_cstring_arena(&r)
}

/// Арена из \0-terminated C-строк -> Vec<String>.
fn decode_cstring_arena(r: &RawResult) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let bytes = r.bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == 0 {
            out.push(String::from_utf8_lossy(&bytes[start..i]).into_owned());
            start = i + 1;
        }
    }
    out
}

// ---------------------------------------------------------------- g-strings

/// g_strings: printable-строки [0x20..0x7E] как (offset, len).
pub fn strings(path: impl AsRef<Path>, min_len: i32, max_entropy: Option<f64>) -> Vec<(u64, u32)> {
    let r = RawResult::from(unsafe {
        sys::g_strings(c_path(path).as_ptr(), min_len, max_entropy.unwrap_or(-1.0))
    });
    r.records::<sys::g_strings_rec>()
        .iter()
        .map(|rec| (rec.offset, rec.len))
        .collect()
}

/// g_strings_count: число строк. `None` при ошибке.
pub fn strings_count(
    path: impl AsRef<Path>,
    min_len: i32,
    max_entropy: Option<f64>,
) -> Option<u64> {
    let n = unsafe {
        sys::g_strings_count(c_path(path).as_ptr(), min_len, max_entropy.unwrap_or(-1.0))
    };
    if n < 0 {
        None
    } else {
        Some(n as u64)
    }
}

/// g_unicode: UTF-16LE printable-строки как (offset, len в байтах).
/// min_len — в символах UTF-16 (см. c_abi.h).
pub fn unicode(path: impl AsRef<Path>, min_len: i32, max_entropy: Option<f64>) -> Vec<(u64, u32)> {
    let r = RawResult::from(unsafe {
        sys::g_unicode(c_path(path).as_ptr(), min_len, max_entropy.unwrap_or(-1.0))
    });
    r.records::<sys::g_strings_rec>()
        .iter()
        .map(|rec| (rec.offset, rec.len))
        .collect()
}

// ------------------------------------------------------------------ анализ

/// g_entropy_profile: (offset блока, энтропия [0..8] бит/байт).
pub fn entropy_profile(path: impl AsRef<Path>, block_size: i32) -> Vec<(u64, f64)> {
    let r = RawResult::from(unsafe { sys::g_entropy_profile(c_path(path).as_ptr(), block_size) });
    r.records::<sys::g_entropy_rec>()
        .iter()
        .map(|rec| (rec.offset, rec.entropy))
        .collect()
}

/// g_bytes: сырой срез файла. `None` при ошибке (нет файла).
pub fn read_bytes(path: impl AsRef<Path>, offset: u64, len: u64) -> Option<Vec<u8>> {
    let r = RawResult::from(unsafe { sys::g_bytes(c_path(path).as_ptr(), offset, len) });
    if r.is_error() {
        None
    } else {
        Some(r.bytes().to_vec())
    }
}

/// g_xor: срез файла XOR с однобайтовым ключом. `None` при ошибке.
pub fn xor_bytes(path: impl AsRef<Path>, offset: u64, len: u64, key: u8) -> Option<Vec<u8>> {
    let r = RawResult::from(unsafe { sys::g_xor(c_path(path).as_ptr(), offset, len, key as i32) });
    if r.is_error() {
        None
    } else {
        Some(r.bytes().to_vec())
    }
}

/// g_hash: (FNV-1a64 словный, CRC32C). `None` при ошибке.
pub fn hash(path: impl AsRef<Path>) -> Option<(u64, u32)> {
    let r = RawResult::from(unsafe { sys::g_hash(c_path(path).as_ptr()) });
    if r.is_error() {
        return None;
    }
    r.records::<sys::g_hash_rec>()
        .first()
        .map(|h| (h.fnv1a64, h.crc32c))
}

/// g_hist: гистограмма байтов [256]. `None` при ошибке.
pub fn hist(path: impl AsRef<Path>) -> Option<[u64; 256]> {
    let r = RawResult::from(unsafe { sys::g_hist(c_path(path).as_ptr()) });
    if r.is_error() {
        return None;
    }
    let mut out = [0u64; 256];
    for (i, v) in r.bytes().chunks_exact(8).enumerate() {
        out[i] = u64::from_le_bytes(v.try_into().unwrap());
    }
    Some(out)
}

/// Секция ELF/PE из g_sections.
#[derive(Debug, Clone, PartialEq)]
pub struct Section {
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
    pub name: String,
    pub type_: u32,
}

/// g_sections: секции ELF/PE (см. type-константы в gcore-sys).
pub fn sections(path: impl AsRef<Path>) -> Vec<Section> {
    let r = RawResult::from(unsafe { sys::g_sections(c_path(path).as_ptr()) });
    r.records::<sys::g_section_rec>()
        .iter()
        .map(|s| Section {
            offset: s.offset,
            size: s.size,
            entropy: s.entropy,
            name: {
                let bytes: Vec<u8> = s
                    .name
                    .iter()
                    .take_while(|c| **c != 0)
                    .map(|c| *c as u8)
                    .collect();
                String::from_utf8_lossy(&bytes).into_owned()
            },
            type_: s.type_,
        })
        .collect()
}

/// Диапазон различий из g_diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiffRec {
    pub offset_a: u64,
    pub offset_b: u64,
    pub len: u32,
    pub status: u8,
}

/// g_diff: блочное сравнение двух файлов.
pub fn diff(a: impl AsRef<Path>, b: impl AsRef<Path>, block_size: i32) -> Vec<DiffRec> {
    let r =
        RawResult::from(unsafe { sys::g_diff(c_path(a).as_ptr(), c_path(b).as_ptr(), block_size) });
    r.records::<sys::g_diff_rec>()
        .iter()
        .map(|d| DiffRec {
            offset_a: d.offset_a,
            offset_b: d.offset_b,
            len: d.len,
            status: d.status,
        })
        .collect()
}

/// g_scan: совпадения мультипаттернного сканера как (offset, pattern_idx).
pub fn scan(path: impl AsRef<Path>, patterns: &[&str]) -> Vec<(u64, u32)> {
    let c_pats: Vec<CString> = patterns.iter().map(|p| c_str(p)).collect();
    let ptrs: Vec<*const c_char> = c_pats.iter().map(|p| p.as_ptr()).collect();
    let r = RawResult::from(unsafe {
        sys::g_scan(c_path(path).as_ptr(), ptrs.as_ptr(), ptrs.len() as i32)
    });
    r.records::<sys::g_scan_rec>()
        .iter()
        .map(|s| (s.offset, s.pattern_idx))
        .collect()
}

/// Рекогносцировка g_recon: хэши + гистограмма + энтропия + строки.
#[derive(Debug, Clone, PartialEq)]
pub struct Recon {
    pub fnv1a64: u64,
    pub crc32c: u32,
    pub hist: Vec<u64>,
    pub entropy: Vec<(u64, f64)>,
    pub strings: Vec<(u64, u32)>,
}

/// g_recon: одна mmap-сессия hash+hist+entropy(64KB)+strings.
pub fn recon(path: impl AsRef<Path>, entropy_block: i32) -> Option<Recon> {
    let r = RawResult::from(unsafe { sys::g_recon(c_path(path).as_ptr(), entropy_block) });
    if r.is_error() {
        return None;
    }
    let bytes = r.bytes();
    if bytes.len() < std::mem::size_of::<sys::g_recon_header>() {
        return None;
    }
    let hdr = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const sys::g_recon_header) };
    let mut pos = std::mem::size_of::<sys::g_recon_header>();
    let mut hist = Vec::with_capacity(hdr.n_hist as usize);
    for _ in 0..hdr.n_hist {
        hist.push(u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?));
        pos += 8;
    }
    let mut entropy = Vec::with_capacity(hdr.n_entropy as usize);
    for _ in 0..hdr.n_entropy {
        let chunk: [u8; 16] = bytes[pos..pos + 16].try_into().ok()?;
        let rec = unsafe { std::ptr::read_unaligned(chunk.as_ptr() as *const sys::g_entropy_rec) };
        entropy.push((rec.offset, rec.entropy));
        pos += 16;
    }
    let mut strings = Vec::with_capacity(hdr.n_strings as usize);
    while pos + 16 <= bytes.len() {
        let chunk: [u8; 16] = bytes[pos..pos + 16].try_into().ok()?;
        let rec = unsafe { std::ptr::read_unaligned(chunk.as_ptr() as *const sys::g_strings_rec) };
        strings.push((rec.offset, rec.len));
        pos += 16;
    }
    Some(Recon {
        fnv1a64: hdr.fnv1a64,
        crc32c: hdr.crc32c,
        hist,
        entropy,
        strings,
    })
}

/// Сырой доступ к арене узла (для своих парсеров поверх ABI).
pub fn raw_grep(path: impl AsRef<Path>, needle: &str) -> RawResult {
    RawResult::from(unsafe { sys::g_grep(c_path(path).as_ptr(), c_str(needle).as_ptr()) })
}

/// C-строка из арены (вспомогательное для сырья).
pub fn cstr_at(bytes: &[u8]) -> Option<&CStr> {
    CStr::from_bytes_until_nul(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fixture(name: &str, content: &[u8]) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("gcore_rs_test_{}_{}", std::process::id(), name));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(content).unwrap();
        p
    }

    #[test]
    fn grep_count_and_strings() {
        let p = fixture("grep.csv", b"row1,a\nrow2,b\nrow1,c\n");
        assert_eq!(grep_count(&p, "row1"), Some(2));
        assert_eq!(grep_count(&p, "absent"), Some(0));
        let hits = grep_strings(&p, "row1");
        assert_eq!(hits, vec!["row1,a", "row1,c"]);
        assert!(grep_count("/nonexistent/path", "x").is_none());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn strings_and_unicode() {
        let p = fixture("str.bin", b"abc DEF\n\x01\x02gh-01!\n");
        let s = strings(&p, 4, None);
        assert_eq!(s, vec![(0, 7), (10, 6)]);
        assert_eq!(strings_count(&p, 4, None), Some(2));
        std::fs::remove_file(&p).ok();

        let mut u16content = Vec::new();
        for c in b"PACK" {
            u16content.push(*c);
            u16content.push(0);
        }
        u16content.extend_from_slice(&[1, 0]);
        for c in b"MODE" {
            u16content.push(*c);
            u16content.push(0);
        }
        let p = fixture("uni.bin", &u16content);
        assert_eq!(unicode(&p, 4, None), vec![(0, 8), (10, 8)]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn hash_hist_entropy_xor_bytes() {
        let p = fixture("hash.bin", b"123456789");
        let (_fnv, crc) = hash(&p).unwrap();
        // CRC32C('123456789') — стандартный check value
        assert_eq!(crc, 0xE3069283);
        let h = hist(&p).unwrap();
        assert_eq!(h.iter().sum::<u64>(), 9);
        assert_eq!(h[b'9' as usize], 1);
        let ent = entropy_profile(&p, 64);
        assert_eq!(ent.len(), 1);
        assert!(ent[0].1.abs() < 4.5); // 9 байт низкой энтропии
        let dec = xor_bytes(&p, 0, 0, 0x20).unwrap();
        assert_eq!(dec[0], b'1' ^ 0x20);
        assert_eq!(read_bytes(&p, 0, 4).unwrap(), b"1234");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn diff_and_scan() {
        let a = fixture("dA.bin", b"AAAABBBBCCCC");
        let b = fixture("dB.bin", b"AAAAXXXXCCCC");
        let d = diff(&a, &b, 4);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].status, sys::G_DIFF_CHANGED);
        assert_eq!(d[0].offset_a, 4);
        let m = scan(&a, &["BBBB", "CCCC"]);
        assert_eq!(m, vec![(4, 0), (8, 1)]);
        std::fs::remove_file(&a).ok();
        std::fs::remove_file(&b).ok();
    }

    #[test]
    fn sections_on_self() {
        // реальный ELF — сама libg-tools.so (в rpath-каталоге сборки)
        let lib = find_libg_tools();
        if let Some(lib) = lib {
            let secs = sections(&lib);
            assert!(!secs.is_empty());
            assert!(secs.iter().any(|s| s.name == ".text" || s.type_ == 0));
        }
    }

    fn find_libg_tools() -> Option<std::path::PathBuf> {
        // build.rs кладёт rpath на каталог с libg-tools.so; ищем по всем
        // потенциальным местам, иначе пропускаем тест
        let candidates = ["../../target/debug/build", "../../target/release/build"];
        for base in candidates {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(base);
            if let Ok(entries) = std::fs::read_dir(&root) {
                for e in entries.flatten() {
                    let out = e.path().join("out/gtools-build/libg-tools.so");
                    if out.exists() {
                        return Some(out);
                    }
                }
            }
        }
        None
    }
}
