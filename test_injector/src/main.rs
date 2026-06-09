//! Auto-injector — finds `test_exe.exe`, injects `test_dll.dll` from current dir.

use std::{env, fs, path::PathBuf};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        },
        Threading::{OpenProcess, PROCESS_ALL_ACCESS},
    },
};

fn find_process(target: &str) -> Option<u32> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == -1isize as HANDLE {
            return None;
        }
        let mut pe = std::mem::zeroed::<PROCESSENTRY32W>();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut pe) == 0 {
            CloseHandle(snap);
            return None;
        }
        loop {
            let exe = widestr(&pe.szExeFile);
            if exe.eq_ignore_ascii_case(target) {
                CloseHandle(snap);
                return Some(pe.th32ProcessID);
            }
            if Process32NextW(snap, &mut pe) == 0 {
                break;
            }
        }
        CloseHandle(snap);
    }
    None
}

unsafe fn widestr(ptr: &[u16; 260]) -> String {
    let len = ptr.iter().position(|&c| c == 0).unwrap_or(ptr.len());
    String::from_utf16_lossy(&ptr[..len])
}

fn find_dll() -> PathBuf {
    let mut exe = env::current_exe().expect("cannot get exe path");
    exe.pop();
    exe.push("test_dll.dll");
    exe
}

fn main() {
    let dll_path = find_dll();
    let dll_bytes = fs::read(&dll_path).unwrap_or_else(|e| {
        eprintln!("ERROR: cannot read {}: {e}", dll_path.display());
        std::process::exit(1);
    });

    let pid = find_process("test_exe.exe").unwrap_or_else(|| {
        eprintln!("ERROR: test_exe.exe is not running. Start it first.");
        std::process::exit(1);
    });

    let h_proc = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if h_proc.is_null() || h_proc == -1isize as HANDLE {
        eprintln!("ERROR: cannot open PID {pid}. Run as admin?");
        std::process::exit(1);
    }

    print!("Injecting test_dll.dll into PID {pid}... ");
    match unsafe { mmap_inject::inject_dll(h_proc, &dll_bytes) } {
        Ok(()) => println!("Success"),
        Err(e) => eprintln!("Failed: {e}"),
    }

    unsafe { CloseHandle(h_proc) };
}
