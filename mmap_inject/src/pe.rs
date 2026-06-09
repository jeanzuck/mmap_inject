//! Minimal PE parsing for x64 DLLs.
//!
//! All pointers are into the caller-owned byte slice; none of the functions
//! allocate or take ownership.  Every function is `unsafe` because it casts
//! raw offsets without bound-checking beyond what the PE spec guarantees.
#![allow(unsafe_op_in_unsafe_fn)]

use core::slice;

// ── PE magic constants ─────────────────────────────────────────────────────

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

// ── Sentinel handles written back by shellcode ─────────────────────────────

// ── Relocation type (x64 only) ─────────────────────────────────────────────
#[inline(always)]
pub fn reloc_is_dir64(rel_info: u16) -> bool {
    (rel_info >> 12) == 10 // IMAGE_REL_BASED_DIR64
}

// ── Repr-C mirrors of the Windows PE structures we need ───────────────────
//
// We re-declare only the fields we actually touch so we don't drag in a
// heavy dependency on a specific `windows-sys` version for struct layouts.

#[repr(C)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub _pad: [u16; 29],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

pub const NUM_DIRECTORY_ENTRIES: usize = 16;

#[repr(C)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; NUM_DIRECTORY_ENTRIES],
}

#[repr(C)]
pub struct ImageNtHeaders64 {
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

#[repr(C)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32, // Misc.VirtualSize
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

// ── Import-related structures ──────────────────────────────────────────────

#[repr(C)]
pub struct ImageImportDescriptor {
    pub original_first_thunk: u32, // OriginalFirstThunk (INT)
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub first_thunk: u32, // FirstThunk (IAT)
}

#[repr(C)]
pub struct ImageImportByName {
    pub hint: u16,
    pub name: [u8; 1], // flexible array member pattern
}

// ── Delayed-import descriptor (IMAGE_DELAYLOAD_DESCRIPTOR) ────────────────
#[repr(C)]
pub struct ImageDelayloadDescriptor {
    pub attributes: u32,
    pub dll_name_rva: u32,
    pub module_handle_rva: u32,
    pub import_address_table_rva: u32,
    pub import_name_table_rva: u32,
    pub bound_import_address_table_rva: u32,
    pub unload_information_table_rva: u32,
    pub time_date_stamp: u32,
}

// ── TLS directory ─────────────────────────────────────────────────────────

#[repr(C)]
pub struct ImageTlsDirectory64 {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64, // pointer to array of PIMAGE_TLS_CALLBACK
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}

// ── Base-relocation block ──────────────────────────────────────────────────

#[allow(dead_code)]
#[repr(C)]
pub struct ImageBaseRelocation {
    pub virtual_address: u32,
    pub size_of_block: u32,
}

// ── Runtime function entry (PDATA / SEH) ──────────────────────────────────

#[repr(C)]
pub struct ImageRuntimeFunctionEntry {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info_address: u32,
}

// ── Data directory indices ─────────────────────────────────────────────────

pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;

// ── Validation & parsing helpers ──────────────────────────────────────────

/// Returns `true` if `bytes` looks like a valid x64 PE/DLL.
pub fn validate(bytes: &[u8]) -> bool {
    if bytes.len() < size_of::<ImageDosHeader>() {
        return false;
    }
    // SAFETY: length checked above
    let dos = unsafe { &*(bytes.as_ptr() as *const ImageDosHeader) };
    if dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 {
        return false;
    }
    let nt_off = dos.e_lfanew as usize;
    if nt_off + size_of::<ImageNtHeaders64>() > bytes.len() {
        return false;
    }
    // SAFETY: offset checked above
    let nt = unsafe { &*(bytes.as_ptr().add(nt_off) as *const ImageNtHeaders64) };
    if nt.signature != IMAGE_NT_SIGNATURE {
        return false;
    }
    if nt.file_header.machine != IMAGE_FILE_MACHINE_AMD64 {
        return false;
    }
    true
}

/// Returns a pointer to the NT headers within `base` (mapped in-process).
///
/// # Safety
/// `base` must point to a fully-mapped PE image in addressable memory.
#[inline]
pub unsafe fn nt_headers(base: *const u8) -> *const ImageNtHeaders64 {
    unsafe {
        let e_lfanew = (*(base as *const ImageDosHeader)).e_lfanew;
        base.add(e_lfanew as usize) as *const ImageNtHeaders64
    }
}

/// Returns a slice of section headers for the PE at `base`.
///
/// # Safety
/// Same as [`nt_headers`].
#[inline]
pub unsafe fn section_headers(nt: *const ImageNtHeaders64) -> &'static [ImageSectionHeader] {
    unsafe {
        let count = (*nt).file_header.number_of_sections as usize;
        // Section headers immediately follow the optional header.
        let opt_size = (*nt).file_header.size_of_optional_header as usize;
        let first = (nt as *const u8)
            .add(size_of::<u32>() + size_of::<ImageFileHeader>() + opt_size)
            as *const ImageSectionHeader;
        slice::from_raw_parts(first, count)
    }
}

use core::mem::size_of;

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn struct_sizes_match_windows_pe() {
        // Verify our repr(C) structs match the Windows PE spec sizes.
        assert_eq!(mem::size_of::<ImageDosHeader>(), 64);
        assert_eq!(mem::size_of::<ImageFileHeader>(), 20);
        assert_eq!(mem::size_of::<ImageDataDirectory>(), 8);
        assert_eq!(mem::size_of::<ImageOptionalHeader64>(), 240);
        // Fixed header (112) + DataDirectory[16] (128) = 240
        assert_eq!(mem::align_of::<ImageOptionalHeader64>(), 8);
        assert_eq!(mem::size_of::<ImageSectionHeader>(), 40);
        assert_eq!(mem::size_of::<ImageImportDescriptor>(), 20);
        assert_eq!(mem::size_of::<ImageBaseRelocation>(), 8);
        assert_eq!(mem::size_of::<ImageRuntimeFunctionEntry>(), 12);
    }

    #[test]
    fn reloc_is_dir64_true() {
        // IMAGE_REL_BASED_DIR64 = 10, so (10 << 12) should match.
        let info = (10u16 << 12) | 0x042;
        assert!(reloc_is_dir64(info));
    }

    #[test]
    fn reloc_is_dir64_false() {
        // IMAGE_REL_BASED_HIGHLOW = 3
        let info = (3u16 << 12) | 0x123;
        assert!(!reloc_is_dir64(info));
    }

    #[test]
    fn validate_rejects_empty() {
        assert!(!validate(&[]));
    }

    #[test]
    fn validate_rejects_junk() {
        assert!(!validate(b"not a PE file at all"));
    }

    #[test]
    fn validate_rejects_tiny_mz() {
        let mut buf = [0u8; 64];
        buf[0] = 0x4D; // 'M'
        buf[1] = 0x5A; // 'Z'
        // e_lfanew points way past the buffer
        buf[0x3C..0x40].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
        assert!(!validate(&buf));
    }

    #[test]
    fn validate_real_dll() {
        // Locate test_dll.dll from the workspace target directory.
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let dll_path = manifest.parent().unwrap().join("target/debug/test_dll.dll");
        let bytes = std::fs::read(&dll_path)
            .unwrap_or_else(|_| panic!("build test_dll first: {}", dll_path.display()));
        assert!(validate(&bytes), "test_dll.dll should be a valid x64 PE");
    }

    #[test]
    fn test_dll_has_expected_sections() {
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let dll_path = manifest.parent().unwrap().join("target/debug/test_dll.dll");
        let bytes = std::fs::read(&dll_path).expect("build test_dll first");
        assert!(validate(&bytes));

        let nt = unsafe { nt_headers(bytes.as_ptr()) };
        let opt = unsafe { &(*nt).optional_header };
        let sections = unsafe { section_headers(nt) };

        // Should have at least .text section
        assert!(!sections.is_empty(), "DLL should have sections");

        // Entry point should be non-zero
        assert_ne!(
            opt.address_of_entry_point, 0,
            "DLL should have an entry point"
        );

        // Image base should be 64-bit aligned for x64
        assert_eq!(
            opt.image_base % 0x10000,
            0,
            "ImageBase should be 64K-aligned"
        );
    }
}
