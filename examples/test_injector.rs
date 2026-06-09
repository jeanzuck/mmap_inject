//! Self-injector — injects `test_dll.dll` into a process.
//!
//! Usage:
//!   cargo build --examples
//!   cargo run --example test_injector          → inject into self
//!   cargo run --example test_injector -- <PID> → inject into target PID

use std::{env, fs, path::PathBuf, time::Duration};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_ALL_ACCESS},
};

fn find_dll() -> PathBuf {
    // 1) Next to the running executable (e.g. after `cargo build --examples`)
    let mut exe = env::current_exe().expect("cannot get exe path");
    exe.pop();
    exe.push("test_dll.dll");
    if exe.exists() {
        return exe;
    }

    // 2) Fallback: CARGO_MANIFEST_DIR / target / <profile> / examples /
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let from_manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(profile)
        .join("examples")
        .join("test_dll.dll");
    if from_manifest.exists() {
        return from_manifest;
    }

    // 3) Return the first path as default (error message will be clear).
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

    let dll_path = find_dll();
    let dll_bytes = fs::read(&dll_path).unwrap_or_else(|e| {
        eprintln!(
            "error: cannot read {}: {e}\n\
             hint: run `cargo build --example test_dll` first",
            dll_path.display()
        );
        std::process::exit(1);
    });

    let h_proc = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if h_proc.is_null() || h_proc == -1isize as HANDLE {
        eprintln!("error: cannot open PID {pid}");
        std::process::exit(1);
    }

    println!("mmap_inject — manual map injection test");
    println!("  pid     : {pid}");
    println!(
        "  dll     : {}  ({} bytes)",
        dll_path.display(),
        dll_bytes.len()
    );
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
