//! Test EXE — prints PID and waits, providing a target for injection testing.

use windows_sys::Win32::{
    System::Console::SetConsoleTitleA,
    System::Threading::{GetCurrentProcessId, Sleep},
};

fn main() {
    unsafe {
        let pid = GetCurrentProcessId();
        let _ = SetConsoleTitleA(
            format!("test_exe  |  PID: {pid}  |  Press Ctrl+C to exit\0").as_ptr() as *const u8,
        );
    }

    println!("=========================================");
    println!("  test_exe — Manual Map Injection Target ");
    println!("=========================================");
    println!();
    println!("  PID  : {}", unsafe { GetCurrentProcessId() });
    println!();
    println!("  Use mmap_inject to inject test_dll.dll");
    println!("  into this process.                        ");
    println!();
    println!("  Waiting... Press Ctrl+C to exit.          ");
    println!("=========================================");

    // Idle loop — keeps the process alive as an injection target.
    loop {
        unsafe { Sleep(1000) };
    }
}
