mod injector;
mod pe;
mod shellcode;

use windows_sys::Win32::Foundation::HANDLE;

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum Error {
    /// The provided byte slice is not a valid x64 PE file.
    InvalidPe,
    /// A Win32 API call failed; contains the `GetLastError()` code.
    Win32(u32),
    /// An invalid argument was supplied (null handle, empty slice, etc.).
    InvalidArgument,
    /// The shellcode reported failure (containing mod_handle error code).
    ShellcodeFailed(usize),
    /// DLL was injected but SEH unwind table registration failed.
    SehRegistrationFailed,
    /// The remote thread crashed (exit_code, last_step_marker).
    ShellcodeCrashed(u32, usize),
}

impl Error {
    fn last_win32() -> Self {
        use windows_sys::Win32::Foundation::GetLastError;
        Error::Win32(unsafe { GetLastError() })
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidPe => write!(f, "not a valid x64 PE/DLL"),
            Error::Win32(code) => write!(f, "Win32 error 0x{code:08X}"),
            Error::InvalidArgument => write!(f, "invalid argument"),
            Error::ShellcodeFailed(code) => {
                let name = crate::shellcode::step_name(*code);
                write!(f, "shellcode failed: {name} (0x{code:08X})")
            }
            Error::SehRegistrationFailed => write!(f, "DLL injected but SEH registration failed"),
            Error::ShellcodeCrashed(code, step) => {
                let name = crate::shellcode::step_name(*step);
                write!(f, "shellcode crashed at step '{name}' (exit 0x{code:08X})")
            }
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

// ── Public API ─────────────────────────────────────────────────────────────

/// Manually maps `dll_bytes` into the process identified by `process`.
///
/// `process` must be opened with at minimum:
/// - `PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION`
/// - `PROCESS_CREATE_THREAD`
///
/// Returns `Ok(())` on success.  PE headers are wiped, shellcode and context
///
/// # Safety
/// The caller is responsible for providing a valid process handle.
pub unsafe fn inject_dll(process: HANDLE, dll_bytes: &[u8]) -> Result<()> {
    unsafe { injector::inject(process, dll_bytes) }
}
