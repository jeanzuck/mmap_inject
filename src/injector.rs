//! Core injection logic: memory allocation, shellcode dispatch, cleanup.

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::Debug::WriteProcessMemory,
        LibraryLoader::{GetProcAddress, LoadLibraryA},
        Memory::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
            VirtualAllocEx, VirtualFreeEx,
        },
        Threading::{CreateRemoteThread, GetExitCodeThread, INFINITE, WaitForSingleObject},
    },
};

use crate::Error;
use crate::pe::{self, ImageSectionHeader, section_headers};
use crate::shellcode::{ERR_NO_LOADLIB, MappingCtx, SEH_FAILED, shellcode_range};

// ── Shellcode ─────────────────────────────────────────────────────────────

/// Maximum PE header bytes to wipe after injection.
const HEADER_WIPE_CAP: usize = 0x1000;

// ── Random base address ────────────────────────────────────────────────────

/// Generates an ASLR-style random 64-bit user-space address aligned to 64 KiB.
fn random_base(image_size: usize) -> *mut u8 {
    // Simple LCG seeded from the tick counter + stack address (no-std friendly).
    // The OS will reject unsuitable addresses and we fall back.
    use windows_sys::Win32::System::SystemInformation::GetTickCount64;
    let seed = unsafe { GetTickCount64() } ^ (random_base as *const () as usize as u64);
    // LCG multiplier / increment (Knuth)
    let r = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);

    // Map into [0x10_0000_0000, 0x7FF_0000_0000) — safe 64-bit user space.
    const LO: u64 = 0x0000_0010_0000_0000;
    const HI: u64 = 0x0000_07FF_0000_0000;
    let range = HI - LO;
    let mut addr = LO + (r % range);

    // Align to 64 KiB (Windows allocation granularity).
    addr &= !0xFFFF;

    // Guard against overflow.
    if addr as usize > usize::MAX - image_size {
        addr = LO;
    }

    addr as *mut u8
}

// ── Helpers ────────────────────────────────────────────────────────────────

unsafe fn free_remote(proc: HANDLE, ptr: *mut u8) {
    if !ptr.is_null() {
        unsafe { VirtualFreeEx(proc, ptr as _, 0, MEM_RELEASE) };
    }
}

unsafe fn write_remote(proc: HANDLE, dst: *mut u8, src: *const u8, len: usize) -> bool {
    unsafe { WriteProcessMemory(proc, dst as _, src as _, len, core::ptr::null_mut()) != 0 }
}

/// Convert PE RVA (relative virtual address) to file offset.
fn rva_to_offset(sections: &[ImageSectionHeader], rva: u32) -> Option<usize> {
    for sec in sections {
        if rva >= sec.virtual_address && rva < sec.virtual_address + sec.size_of_raw_data {
            return Some((sec.pointer_to_raw_data + (rva - sec.virtual_address)) as usize);
        }
    }
    None
}

// ── Public injector function ───────────────────────────────────────────────

/// Manually maps `dll_bytes` into `process`.
///
/// # Safety
/// `process` must be a valid handle opened with `PROCESS_ALL_ACCESS` (or at
/// minimum `PROCESS_VM_*` + `PROCESS_CREATE_THREAD`).
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn inject(process: HANDLE, dll_bytes: &[u8]) -> crate::Result<()> {
    if process == INVALID_HANDLE_VALUE || process == 0 as HANDLE {
        return Err(Error::InvalidArgument);
    }

    // ── Validate PE ───────────────────────────────────────────────────────
    if !pe::validate(dll_bytes) {
        return Err(Error::InvalidPe);
    }

    let base_ptr = dll_bytes.as_ptr();
    let nt = pe::nt_headers(base_ptr);
    let opt = &(*nt).optional_header;
    let _file_hdr = &(*nt).file_header;
    let image_size = opt.size_of_image as usize;
    let headers_size = opt.size_of_headers as usize;

    // ── Allocate image memory in target (3 random attempts + 1 fallback) ──
    let mut target_base: *mut u8 = std::ptr::null_mut();
    for _ in 0..3 {
        let hint = random_base(image_size);
        let p = VirtualAllocEx(
            process,
            hint as _,
            image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if !p.is_null() {
            target_base = p as *mut u8;
            break;
        }
    }
    if target_base.is_null() {
        // OS-chosen address as fallback.
        target_base = VirtualAllocEx(
            process,
            std::ptr::null(),
            image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        ) as *mut u8;
    }
    if target_base.is_null() {
        return Err(Error::last_win32());
    }

    // ── Write PE headers ──────────────────────────────────────────────────
    if !write_remote(process, target_base, base_ptr, headers_size) {
        free_remote(process, target_base);
        return Err(Error::last_win32());
    }

    // ── Write sections ────────────────────────────────────────────────────
    let sections: &[ImageSectionHeader] = section_headers(nt);
    for sec in sections {
        if sec.size_of_raw_data == 0 {
            continue;
        }
        let dst = target_base.add(sec.virtual_address as usize);
        let src = base_ptr.add(sec.pointer_to_raw_data as usize);
        if !write_remote(process, dst, src, sec.size_of_raw_data as usize) {
            free_remote(process, target_base);
            return Err(Error::last_win32());
        }
    }

    // ── Apply base relocations (injector-side) ───────────────────────────
    {
        let delta = target_base as isize - opt.image_base as isize;
        let reloc_dir = &opt.data_directory[pe::IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if delta != 0 && reloc_dir.size > 0 {
            // Convert RVA → file offset
            let reloc_off = match rva_to_offset(sections, reloc_dir.virtual_address) {
                Some(o) => o,
                None => {
                    free_remote(process, target_base);
                    return Err(Error::InvalidPe);
                }
            };
            let reloc_data = &dll_bytes[reloc_off..][..reloc_dir.size as usize];
            let mut off = 0;
            while off + 8 <= reloc_data.len() {
                let page_va = u32::from_le_bytes([
                    reloc_data[off],
                    reloc_data[off + 1],
                    reloc_data[off + 2],
                    reloc_data[off + 3],
                ]);
                let block_sz = u32::from_le_bytes([
                    reloc_data[off + 4],
                    reloc_data[off + 5],
                    reloc_data[off + 6],
                    reloc_data[off + 7],
                ]) as usize;
                if block_sz == 0 {
                    break;
                }
                let count = (block_sz - 8) / 2;
                let entries = &reloc_data[off + 8..][..count * 2];
                for i in 0..count {
                    let r = u16::from_le_bytes([entries[i * 2], entries[i * 2 + 1]]);
                    if pe::reloc_is_dir64(r) {
                        let patch_addr = target_base.add(page_va as usize + (r & 0x0FFF) as usize);
                        // Read current value, add delta, write back
                        let mut val: isize = 0;
                        windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                            process,
                            patch_addr as _,
                            &mut val as *mut isize as _,
                            8,
                            std::ptr::null_mut(),
                        );
                        val += delta;
                        write_remote(process, patch_addr, &val as *const isize as *const u8, 8);
                    }
                }
                off += block_sz;
            }
        }
    }

    // ── Resolve fn ptrs ───────────────────────────────────────────────────
    // These are the same across our process and the target (same DLLs, same
    // ASLR slide for system DLLs on Win10+).
    let kernel32 = {
        let name = b"kernel32.dll\0";
        LoadLibraryA(name.as_ptr() as _)
    };
    if kernel32.is_null() {
        free_remote(process, target_base);
        return Err(Error::last_win32());
    }
    let fn_load = GetProcAddress(kernel32, b"LoadLibraryA\0".as_ptr() as _).ok_or_else(|| {
        unsafe { free_remote(process, target_base) };
        Error::last_win32()
    })?;
    let fn_get = GetProcAddress(kernel32, b"GetProcAddress\0".as_ptr() as _).ok_or_else(|| {
        unsafe { free_remote(process, target_base) };
        Error::last_win32()
    })?;

    let ntdll = {
        let name = b"ntdll.dll\0";
        LoadLibraryA(name.as_ptr() as _)
    };
    let fn_add_table = if !ntdll.is_null() {
        GetProcAddress(ntdll, b"RtlAddFunctionTable\0".as_ptr() as _)
    } else {
        None
    };

    // ── Build MappingCtx ──────────────────────────────────────────────────
    let ctx = MappingCtx {
        base_addr: target_base,
        fn_load_lib: Some(std::mem::transmute(fn_load)),
        fn_get_proc: Some(std::mem::transmute(fn_get)),
        fn_add_table: fn_add_table.map(|f| std::mem::transmute(f)),
        mod_handle: ERR_NO_LOADLIB,
        reason: 1, // DLL_PROCESS_ATTACH
        reserved: std::ptr::null_mut(),
        seh_enabled: fn_add_table.is_some(),
    };

    // ── Write ctx to target ───────────────────────────────────────────────
    let ctx_remote = VirtualAllocEx(
        process,
        std::ptr::null(),
        std::mem::size_of::<MappingCtx>(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) as *mut u8;
    if ctx_remote.is_null() {
        free_remote(process, target_base);
        return Err(Error::last_win32());
    }
    if !write_remote(
        process,
        ctx_remote,
        &ctx as *const MappingCtx as *const u8,
        std::mem::size_of::<MappingCtx>(),
    ) {
        free_remote(process, ctx_remote);
        free_remote(process, target_base);
        return Err(Error::last_win32());
    }

    // ── Write shellcode to target ─────────────────────────────────────────
    let (sc_src, sc_size) = shellcode_range();
    let sc_remote = VirtualAllocEx(
        process,
        std::ptr::null(),
        sc_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    ) as *mut u8;
    if sc_remote.is_null() {
        free_remote(process, ctx_remote);
        free_remote(process, target_base);
        return Err(Error::last_win32());
    }
    // Copy the exact shellcode bytes (section `.sc$a` through `.sc$z`).
    if !write_remote(process, sc_remote, sc_src, sc_size) {
        free_remote(process, sc_remote);
        free_remote(process, ctx_remote);
        free_remote(process, target_base);
        return Err(Error::last_win32());
    }

    // ── CreateRemoteThread ────────────────────────────────────────────────
    let thread = CreateRemoteThread(
        process,
        std::ptr::null(),
        0,
        Some(std::mem::transmute(sc_remote)),
        ctx_remote as _,
        0,
        std::ptr::null_mut(),
    );
    if thread.is_null() {
        free_remote(process, sc_remote);
        free_remote(process, ctx_remote);
        free_remote(process, target_base);
        return Err(Error::last_win32());
    }

    WaitForSingleObject(thread, INFINITE);

    // Check if the remote thread crashed.
    let mut exit_code: u32 = 0;
    let ok = GetExitCodeThread(thread, &mut exit_code);
    if ok != 0 && exit_code != 0 {
        // Non-zero exit code means the shellcode crashed or failed internally.
        // Still read back mod_handle for diagnostics.
        let mut result_ctx = std::mem::zeroed::<MappingCtx>();
        windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            process,
            ctx_remote as _,
            &mut result_ctx as *mut MappingCtx as _,
            std::mem::size_of::<MappingCtx>(),
            std::ptr::null_mut(),
        );
        CloseHandle(thread);
        free_remote(process, sc_remote);
        free_remote(process, ctx_remote);
        free_remote(process, target_base);
        return Err(Error::ShellcodeCrashed(exit_code, result_ctx.mod_handle));
    }

    CloseHandle(thread);

    // ── Read back result ──────────────────────────────────────────────────
    let mut result_ctx = std::mem::zeroed::<MappingCtx>();
    let ok = windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
        process,
        ctx_remote as _,
        &mut result_ctx as *mut MappingCtx as _,
        std::mem::size_of::<MappingCtx>(),
        std::ptr::null_mut(),
    );

    // ── Wipe and free shellcode + ctx ─────────────────────────────────────
    let zeros = vec![0u8; sc_size];
    write_remote(process, sc_remote, zeros.as_ptr(), sc_size);
    free_remote(process, sc_remote);
    free_remote(process, ctx_remote);

    if ok == 0 {
        free_remote(process, target_base);
        return Err(Error::last_win32());
    }

    match result_ctx.mod_handle {
        ERR_NO_LOADLIB
        | crate::shellcode::ERR_NO_GETPROC
        | crate::shellcode::ERR_LOADLIB_FAIL
        | crate::shellcode::ERR_GETPROC_FAIL => {
            free_remote(process, target_base);
            return Err(Error::ShellcodeFailed(result_ctx.mod_handle));
        }
        SEH_FAILED => {
            // DLL loaded but SEH registration failed — partial error.
        }
        _ => {}
    }

    // ── Wipe PE headers in target ─────────────────────────────────────────
    let wipe_hdr_size = headers_size.min(HEADER_WIPE_CAP);
    let hdr_zeros = vec![0u8; wipe_hdr_size];
    write_remote(process, target_base, hdr_zeros.as_ptr(), wipe_hdr_size);

    if result_ctx.mod_handle == SEH_FAILED {
        return Err(Error::SehRegistrationFailed);
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::ImageSectionHeader;

    #[test]
    fn rva_to_offset_inside_section() {
        let sections = [ImageSectionHeader {
            name: [b'.', b't', b'e', b'x', b't', 0, 0, 0],
            virtual_address: 0x1000,
            virtual_size: 0x500,
            size_of_raw_data: 0x400,
            pointer_to_raw_data: 0x400,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0,
        }];
        assert_eq!(rva_to_offset(&sections, 0x1100), Some(0x500));
    }

    #[test]
    fn rva_to_offset_outside_section() {
        let sections = [ImageSectionHeader {
            name: [0; 8],
            virtual_address: 0x1000,
            virtual_size: 0x100,
            size_of_raw_data: 0x100,
            pointer_to_raw_data: 0x200,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0,
        }];
        assert_eq!(rva_to_offset(&sections, 0x2000), None);
    }
}
