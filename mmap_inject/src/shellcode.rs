//! Shellcode that executes inside the target process to complete manual mapping.
//!
//! # Design constraints
//! - Only uses `core` APIs (no `std`, no heap allocation).
//! - All external calls go through function pointers in `MappingCtx`; this
//!   makes the code position-independent once copied to the remote process.
//! - The shellcode lives in a dedicated linker section (`.sc`) with boundary
//!   markers so we copy exactly the right bytes.
//! - Release builds only — debug builds emit stack probes and non-inlined
//!   helpers that fall outside the `.sc` section.
#![allow(unsafe_op_in_unsafe_fn)]

use crate::pe::{
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, IMAGE_DIRECTORY_ENTRY_EXCEPTION,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_TLS, ImageDelayloadDescriptor,
    ImageImportByName, ImageImportDescriptor, ImageRuntimeFunctionEntry, ImageTlsDirectory64,
};

// HMODULE / HINSTANCE are just pointer-sized handles.
pub type HMODULE = *mut core::ffi::c_void;

/// Function pointer types that the shellcode calls through `MappingCtx`.
pub type FnLoadLibraryA = unsafe extern "system" fn(*const i8) -> HMODULE;
pub type FnGetProcAddress = unsafe extern "system" fn(HMODULE, *const i8) -> *mut core::ffi::c_void;
pub type FnRtlAddFunctionTable =
    unsafe extern "system" fn(*mut ImageRuntimeFunctionEntry, u32, u64) -> i32;

// ── Error codes written to mod_handle ──────────────────────────────────────

pub const ERR_NO_LOADLIB: usize = 0x40_4041;
pub const ERR_NO_GETPROC: usize = 0x40_4042;
pub const ERR_LOADLIB_FAIL: usize = 0x40_4043;
pub const ERR_GETPROC_FAIL: usize = 0x40_4044;
pub const SEH_FAILED: usize = 0x50_5050;

// ── Diagnostic step markers ────────────────────────────────────────────────

pub const STEP_IMPORT: usize = 0x40_4002;
pub const STEP_DELAY_IMPORT: usize = 0x40_4003;
pub const STEP_TLS: usize = 0x40_4004;
pub const STEP_SEH: usize = 0x40_4005;
pub const STEP_DLLMAIN: usize = 0x40_4006;

/// Human-readable name for a step marker / error code.
pub fn step_name(val: usize) -> &'static str {
    match val {
        ERR_NO_LOADLIB => "fn_load_lib-None",
        ERR_NO_GETPROC => "fn_get_proc-None",
        ERR_LOADLIB_FAIL => "LoadLibrary-failed",
        ERR_GETPROC_FAIL => "GetProcAddress-failed",
        STEP_IMPORT => "imports",
        STEP_DELAY_IMPORT => "delayed-imports",
        STEP_TLS => "TLS callbacks",
        STEP_SEH => "RtlAddFunctionTable",
        STEP_DLLMAIN => "DllMain",
        _ => "???",
    }
}

/// Context block copied into the target process alongside the shellcode.
///
/// Must be `#[repr(C)]` – the shellcode reads it by pointer arithmetic and the
/// same struct is written from injector-side code.
#[repr(C)]
pub struct MappingCtx {
    /// Base address where the DLL image was mapped in the target process.
    pub base_addr: *mut u8,
    /// Pointer to `LoadLibraryA` in the target process.
    pub fn_load_lib: Option<FnLoadLibraryA>,
    /// Pointer to `GetProcAddress` in the target process.
    pub fn_get_proc: Option<FnGetProcAddress>,
    /// Pointer to `RtlAddFunctionTable` in the target process.
    pub fn_add_table: Option<FnRtlAddFunctionTable>,
    /// Written back by shellcode: base address on success, sentinel on failure.
    pub mod_handle: usize,
    /// `DLL_PROCESS_ATTACH` (1) or other reason code.
    pub reason: u32,
    /// Reserved parameter passed through to `DllMain`.
    pub reserved: *mut core::ffi::c_void,
    /// Whether to register SEH unwind data via `RtlAddFunctionTable`.
    pub seh_enabled: bool,
}

// SAFETY: The ctx is sent to a single remote thread; we never share it
// concurrently on the injector side after writing it.
unsafe impl Send for MappingCtx {}

// ── Shellcode section markers ─────────────────────────────────────────────
//
// MSVC linker alphabetically orders subsections `$a` .. `$z` within `.sc`,
// guaranteeing shellcode → shellcode_inner are contiguous and bounded.

#[unsafe(link_section = ".sc$a")]
#[used]
static SC_BEGIN: u8 = 0;

/// Returns `(start_ptr, byte_count)` for the shellcode blob to copy.
pub(crate) fn shellcode_range() -> (*const u8, usize) {
    let start = shellcode as *const u8;
    let end = &raw const SC_END as *const u8;
    let size = unsafe { end.offset_from(start) } as usize;
    (start, size)
}

#[unsafe(link_section = ".sc$b")]
#[unsafe(naked)]
pub unsafe extern "system" fn shellcode(ctx: *mut MappingCtx) -> u32 {
    core::arch::naked_asm!(
        "sub rsp, 0x28",
        "call {inner}",
        "xor eax, eax",
        "add rsp, 0x28",
        "ret",
        inner = sym shellcode_inner,
    );
}

/// Minimal inner function — imports + DllMain only.
/// PE parsing & relocations are done by the injector via WriteProcessMemory.
#[unsafe(link_section = ".sc$c")]
unsafe extern "system" fn shellcode_inner(ctx: *mut MappingCtx) {
    if ctx.is_null() {
        return;
    }
    let ctx = unsafe { &mut *ctx };
    let base = ctx.base_addr;
    let load_lib = match ctx.fn_load_lib {
        Some(f) => f,
        None => {
            ctx.mod_handle = ERR_NO_LOADLIB;
            return;
        }
    };
    let get_proc = match ctx.fn_get_proc {
        Some(f) => f,
        None => {
            ctx.mod_handle = ERR_NO_GETPROC;
            return;
        }
    };

    unsafe {
        // Read minimal PE fields (PE headers still intact in target)
        let e_lfanew = *((base as usize + 0x3C) as *const i32);
        let opt = (base as usize + e_lfanew as usize + 24) as *const u8;
        let entry = *(opt.add(0x10) as *const u32);
        let import_va = *(opt.add(0x70 + IMAGE_DIRECTORY_ENTRY_IMPORT * 8) as *const u32);
        let import_sz = *(opt.add(0x70 + IMAGE_DIRECTORY_ENTRY_IMPORT * 8 + 4) as *const u32);

        // Resolve imports
        if import_sz > 0 {
            let mut desc = base.add(import_va as usize) as *const ImageImportDescriptor;
            while (*desc).name != 0 {
                let dll = load_lib(base.add((*desc).name as usize) as *const i8);
                if dll.is_null() {
                    ctx.mod_handle = ERR_LOADLIB_FAIL;
                    return;
                }
                let int_rva = (*desc).original_first_thunk;
                let iat_rva = (*desc).first_thunk;
                let mut thunk = base.add(if int_rva != 0 {
                    int_rva as usize
                } else {
                    iat_rva as usize
                }) as *const usize;
                let mut iat = base.add(iat_rva as usize) as *mut usize;
                while *thunk != 0 {
                    let func = if *thunk >> 63 != 0 {
                        get_proc(dll, (*thunk & 0xFFFF) as *const i8)
                    } else {
                        let ibn = base.add(*thunk & !(1usize << 63)) as *const ImageImportByName;
                        get_proc(dll, (*ibn).name.as_ptr() as *const i8)
                    };
                    if func.is_null() {
                        ctx.mod_handle = ERR_GETPROC_FAIL;
                        return;
                    }
                    *iat = func as usize;
                    thunk = thunk.add(1);
                    iat = iat.add(1);
                }
                desc = desc.add(1);
            }
        }

        // Delayed imports
        ctx.mod_handle = STEP_DELAY_IMPORT;
        let delay_va = *(opt.add(0x70 + IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT * 8) as *const u32);
        let delay_sz = *(opt.add(0x70 + IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT * 8 + 4) as *const u32);
        if delay_sz > 0 {
            let mut ddesc = base.add(delay_va as usize) as *const ImageDelayloadDescriptor;
            while (*ddesc).dll_name_rva != 0 {
                let dll = load_lib(base.add((*ddesc).dll_name_rva as usize) as *const i8);
                if dll.is_null() {
                    ddesc = ddesc.add(1);
                    continue;
                }
                let mut nt = base.add((*ddesc).import_name_table_rva as usize) as *const usize;
                let mut at = base.add((*ddesc).import_address_table_rva as usize) as *mut usize;
                while *nt != 0 {
                    let func = if *nt >> 63 != 0 {
                        get_proc(dll, (*nt & 0xFFFF) as *const i8)
                    } else {
                        let ibn = base.add(*nt & !(1usize << 63)) as *const ImageImportByName;
                        get_proc(dll, (*ibn).name.as_ptr() as *const i8)
                    };
                    if !func.is_null() {
                        *at = func as usize;
                    }
                    nt = nt.add(1);
                    at = at.add(1);
                }
                ddesc = ddesc.add(1);
            }
        }

        // TLS callbacks
        ctx.mod_handle = STEP_TLS;
        let tls_va = *(opt.add(0x70 + IMAGE_DIRECTORY_ENTRY_TLS * 8) as *const u32);
        let tls_sz = *(opt.add(0x70 + IMAGE_DIRECTORY_ENTRY_TLS * 8 + 4) as *const u32);
        if tls_sz > 0 {
            let tls = base.add(tls_va as usize) as *const ImageTlsDirectory64;
            let mut cb = (*tls).address_of_callbacks as *const *const u8;
            if !cb.is_null() {
                while !(*cb).is_null() {
                    let f: unsafe extern "system" fn(*mut u8, u32, *mut core::ffi::c_void) =
                        core::mem::transmute(*cb);
                    f(base, 1, core::ptr::null_mut());
                    cb = cb.add(1);
                }
            }
        }

        // SEH
        ctx.mod_handle = STEP_SEH;
        let mut seh_failed = false;
        if ctx.seh_enabled {
            let exc_va = *(opt.add(0x70 + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8) as *const u32);
            let exc_sz = *(opt.add(0x70 + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8 + 4) as *const u32);
            if exc_sz > 0 {
                if let Some(add_table) = ctx.fn_add_table {
                    let n = exc_sz as usize / core::mem::size_of::<ImageRuntimeFunctionEntry>();
                    let pdata = base.add(exc_va as usize) as *mut ImageRuntimeFunctionEntry;
                    if add_table(pdata, n as u32, base as u64) == 0 {
                        seh_failed = true;
                    }
                }
            }
        }

        // DllMain
        ctx.mod_handle = STEP_DLLMAIN;
        if entry != 0 {
            let dll_main: unsafe extern "system" fn(*mut u8, u32, *mut core::ffi::c_void) -> i32 =
                core::mem::transmute(base.add(entry as usize));
            dll_main(base, ctx.reason, ctx.reserved);
        }

        ctx.mod_handle = if seh_failed {
            SEH_FAILED
        } else {
            base as usize
        };
    }
}

#[unsafe(link_section = ".sc$z")]
#[used]
static SC_END: u8 = 0;

// ── Unit test: verify contiguous section layout ───────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shellcode_section_is_contiguous() {
        let begin = &raw const SC_BEGIN as usize;
        let sc = shellcode as *const () as usize;
        let inner = shellcode_inner as *const () as usize;
        let end = &raw const SC_END as usize;

        assert!(
            begin < sc && sc < inner && inner < end,
            "shellcode section order: SC_BEGIN({begin:#x}) < shellcode({sc:#x}) < shellcode_inner({inner:#x}) < SC_END({end:#x})"
        );

        let (ptr, size) = shellcode_range();
        assert_eq!(ptr, shellcode as *const u8);
        assert!(size > 0, "shellcode blob must be non-empty");
        assert!(size <= 0x2000, "shellcode blob too large: {size} bytes");
        eprintln!("shellcode blob: {size} bytes at {ptr:p}");
    }
}
