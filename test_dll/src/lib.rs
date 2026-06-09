//! Minimal test DLL — shows "Hello from test_dll" MessageBox on a separate
//! thread so `DllMain` returns immediately.

use core::ffi::c_void;
use windows_sys::Win32::{System::Threading::CreateThread, UI::WindowsAndMessaging::MessageBoxA};

unsafe extern "system" fn show_msg(_param: *mut c_void) -> u32 {
    unsafe {
        MessageBoxA(
            core::ptr::null_mut(),
            b"Hello from test_dll\0".as_ptr() as _,
            b"mmap_inject\0".as_ptr() as _,
            0x40,
        );
    }
    0
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    _hinst: *mut c_void,
    reason: u32,
    _reserved: *mut c_void,
) -> i32 {
    if reason == 1 {
        // DLL_PROCESS_ATTACH
        #[cfg(not(feature = "no_gui"))]
        unsafe {
            CreateThread(
                core::ptr::null(),
                0,
                Some(show_msg),
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
            );
        }
    }
    1 // return immediately — thread handles the rest
}
