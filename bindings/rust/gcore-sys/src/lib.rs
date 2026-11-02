//! # gcore-sys — raw FFI к C ABI g-tools
//!
//! Зеркало `core/include/gcore/c_abi.h`, написано руками (без bindgen —
//! поверхность ABI маленькая и стабильная). Контракт ABI:
//!   - результат — плоская 64-байт выровненная арена + owner для g_result_free;
//!   - пути/needle — NUL-terminated C-строки (байты с '\0' невыговариваемы);
//!   - при ошибке data == NULL и count == 0 (у count-функций -1).
//!
//! Прямо эти функции обычно не зовут — используйте безопасную обёртку `gcore`.

use std::os::raw::{c_char, c_int, c_void};

/// Универсальный результат конвейера: плоская арена + владелец.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct g_result {
    pub owner: *mut c_void,
    pub data: *mut u8,
    pub size: usize,
    pub capacity: usize,
    pub count: usize,
}

impl Default for g_result {
    fn default() -> Self {
        g_result {
            owner: std::ptr::null_mut(),
            data: std::ptr::null_mut(),
            size: 0,
            capacity: 0,
            count: 0,
        }
    }
}

/// g-strings / g-unicode: {offset в файле, len в БАЙТАХ}.
/// Совместимо с numpy dtype [('offset','u8'),('len','u4'),('pad','u4')].
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct g_strings_rec {
    pub offset: u64,
    pub len: u32,
    pub pad: u32,
}

/// g_entropy_profile: {offset блока, энтропия Шеннона в битах/байт}.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct g_entropy_rec {
    pub offset: u64,
    pub entropy: f64,
}

/// g_hash: FNV-1a64 (словный по u64, см. c_abi.h) + CRC32C (SSE4.2).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct g_hash_rec {
    pub fnv1a64: u64,
    pub crc32c: u32,
    pub _pad: u32,
}

/// g_sections: секция ELF/PE.
pub const G_SECTION_OTHER: u32 = 5;
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct g_section_rec {
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
    pub name: [c_char; 32],
    pub type_: u32,
    pub _pad: u32,
}

/// g_diff: статусы диапазонов.
pub const G_DIFF_SAME: u8 = 0;
pub const G_DIFF_CHANGED: u8 = 1;
pub const G_DIFF_INSERTED: u8 = 2;
pub const G_DIFF_DELETED: u8 = 3;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct g_diff_rec {
    pub offset_a: u64,
    pub offset_b: u64,
    pub len: u32,
    pub status: u8,
    pub _pad: [u8; 3],
}

/// g_scan: совпадение мультипаттернного сканера.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct g_scan_rec {
    pub offset: u64,
    pub pattern_idx: u32,
    pub pad: u32,
}

/// g_recon: заголовок плоского буфера hash+hist+entropy+strings.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct g_recon_header {
    /// побайтовый FNV-1a (в g_hash — словный; значения НЕ совпадают)
    pub fnv1a64: u64,
    pub crc32c: u32,
    pub n_hist: u32,
    pub n_entropy: u32,
    pub n_strings: u32,
    pub pad: u32,
}

extern "C" {
    pub fn g_result_free(r: *mut g_result);

    pub fn g_grep(path: *const c_char, needle: *const c_char) -> g_result;
    pub fn g_grep_count(path: *const c_char, needle: *const c_char) -> i64;

    pub fn g_strings(path: *const c_char, min_len: c_int, max_entropy: f64) -> g_result;
    pub fn g_strings_count(path: *const c_char, min_len: c_int, max_entropy: f64) -> i64;

    pub fn g_entropy_profile(path: *const c_char, block_size: c_int) -> g_result;
    pub fn g_bytes(path: *const c_char, offset: u64, len: u64) -> g_result;
    pub fn g_unicode(path: *const c_char, min_len: c_int, max_entropy: f64) -> g_result;
    pub fn g_hash(path: *const c_char) -> g_result;
    pub fn g_hist(path: *const c_char) -> g_result;
    pub fn g_sections(path: *const c_char) -> g_result;
    pub fn g_diff(path_a: *const c_char, path_b: *const c_char, block_size: c_int) -> g_result;
    pub fn g_xor(path: *const c_char, offset: u64, len: u64, key: c_int) -> g_result;
    pub fn g_recon(path: *const c_char, entropy_block: c_int) -> g_result;
    pub fn g_scan(
        path: *const c_char,
        patterns: *const *const c_char,
        pattern_count: c_int,
    ) -> g_result;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_layouts_match_c() {
        // sizeof контрактов — ловим рассинхрон с c_abi.h при изменениях
        assert_eq!(std::mem::size_of::<g_result>(), 40);
        assert_eq!(std::mem::size_of::<g_strings_rec>(), 16);
        assert_eq!(std::mem::size_of::<g_entropy_rec>(), 16);
        assert_eq!(std::mem::size_of::<g_hash_rec>(), 16);
        assert_eq!(std::mem::size_of::<g_section_rec>(), 64);
        assert_eq!(std::mem::size_of::<g_diff_rec>(), 24);
        assert_eq!(std::mem::size_of::<g_scan_rec>(), 16);
        // C: u64 + 5*u32 = 28 -> паддинг до 8
        assert_eq!(std::mem::size_of::<g_recon_header>(), 32);
    }

    #[test]
    fn result_free_null_is_safe() {
        unsafe { g_result_free(std::ptr::null_mut()) };
    }
}
