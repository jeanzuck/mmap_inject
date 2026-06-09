//! Test DLL — shows a MessageBox with the host process PID when attached.
//! MessageBox runs on a separate thread so `DllMain` returns immediately.

use core::ffi::c_void;
use windows_sys::Win32::{
    System::Threading::{CreateThread, GetCurrentProcessId},
    UI::WindowsAndMessaging::MessageBoxA,
};

unsafe extern "system" fn show_msg(msg_ptr: *mut c_void) -> u32 {
    let msg = unsafe { Box::from_raw(msg_ptr as *mut String) };
    unsafe {
        MessageBoxA(
            core::ptr::null_mut(),
            msg.as_ptr() as _,
            b"mmap_inject\0".as_ptr() as _,
            0x40,
        );
    }
    // Box dropped → String freed
    0
}

// SAFETY: called by the shellcode with DLL_PROCESS_ATTACH.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    _hinst: *mut c_void,
    reason: u32,
    _reserved: *mut c_void,
) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;

    if reason == DLL_PROCESS_ATTACH {
        #[cfg(not(feature = "no_gui"))]
        {
            let pid = unsafe { GetCurrentProcessId() };
            let msg = Box::new(format!("Hello from PID: {pid}\0"));

            unsafe {
                CreateThread(
                    core::ptr::null(),
                    0,
                    Some(show_msg),
                    Box::into_raw(msg) as _,
                    0,
                    core::ptr::null_mut(),
                );
            }
        }
    }

    1 // TRUE — successful attach
}
