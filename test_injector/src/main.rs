//! Self-injector — injects `test_dll.dll` into a process.
//!
//! Usage:
//!   test_injector          → inject into self
//!   test_injector <PID>    → inject into target PID

use std::{env, fs, path::PathBuf, time::Duration};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_ALL_ACCESS},
};

fn find_dll() -> PathBuf {
    let mut exe = env::current_exe().expect("cannot get exe path");
    exe.pop();
    exe.push("test_dll.dll");
    exe
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let pid: u32 = if args.len() >= 2 {
        args[1].parse().unwrap_or_else(|_| {
            eprintln!("error: invalid PID: {}", args[1]);
            std::process::exit(1);
        })
    } else {
        unsafe { GetCurrentProcessId() }
    };

    let dll_bytes = fs::read(find_dll()).unwrap_or_else(|e| {
        eprintln!("error: cannot read test_dll.dll: {e}");
        std::process::exit(1);
    });

    let h_proc = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if h_proc.is_null() || h_proc == -1isize as HANDLE {
        eprintln!("error: cannot open PID {pid}");
        std::process::exit(1);
    }

    println!("mmap_inject — manual map injection test");
    println!("  pid     : {pid}");
    println!("  dll     : test_dll.dll  ({} bytes)", dll_bytes.len());
    print!("  inject  : ");

    match unsafe { mmap_inject::inject_dll(h_proc, &dll_bytes) } {
        Ok(()) => {
            println!("OK");
            println!();
            println!("  A MessageBox should appear in the target process.");
            println!("  Press Ctrl+C to exit.");
        }
        Err(e) => {
            println!("FAILED");
            eprintln!("  {e}");
            std::process::exit(1);
        }
    }

    unsafe { CloseHandle(h_proc) };

    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}
