# mmap_inject

[![Rust](https://img.shields.io/badge/rust-nightly--2024-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A minimal, robust manual-map DLL injection library for Windows x64, written in Rust.

Ported from [ManualMapInjection](https://github.com/thetobysiu/ManualMapInjection) (C++) and refactored with a cleaner split: heavy PE processing runs in the injector process; a small, reliable shellcode handles only import resolution, TLS, SEH, and the DllMain call.

## Features

- **Manual Mapping** — injects DLLs without `LoadLibrary`, evading basic user-mode hooks
- **Randomized Base Address** — ASLR-style allocation in 64-bit user space (3 retries + OS fallback)
- **SEH Support** — calls `RtlAddFunctionTable` for x64 structured exception handling
- **Automatic Cleanup** — RAII guard zero-fills and frees injection on drop
- **PE Header Wiping** — overwrites PE headers immediately after injection
- **Import Resolution** — resolves normal import tables (IAT) and delayed imports
- **TLS Callbacks** — executes `DLL_PROCESS_ATTACH` TLS callbacks
- **Base Relocations** — applies `IMAGE_REL_BASED_DIR64` relocations when the DLL isn't loaded at its preferred base
- **Detailed error diagnostics** — unique error codes identify exactly which step failed
- **Zero-cost FFI** — single dependency on `windows-sys`, no heavy runtime

## Quick Start

```toml
# Cargo.toml
[dependencies]
mmap_inject = "0.1.0"
```

```rust
use mmap_inject::inject_dll;
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

// Inject a DLL into a target process
let dll_bytes = std::fs::read("my_dll.dll")?;
let h_proc = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, target_pid) };

unsafe {
    inject_dll(h_proc, &dll_bytes)?;
    println!("Injected!");
}
```

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   Injector Process                    │
│                                                      │
│  injector.rs                                         │
│  ├─ validate PE                                      │
│  ├─ VirtualAllocEx (random base)                     │
│  ├─ write headers + sections                         │
│  ├─ apply base relocations (injector-side)           │
│  ├─ write MappingCtx + shellcode                     │
│  └─ CreateRemoteThread → WaitForSingleObject         │
│                                                      │
│                ▼                                     │
│  ┌──────────────────────────────────────┐            │
│  │         Target Process               │            │
│  │                                      │            │
│  │  shellcode.rs (minimal, ~2 KB)       │            │
│  │  ├─ resolve imports (IAT)            │            │
│  │  ├─ resolve delayed imports          │            │
│  │  ├─ execute TLS callbacks            │            │
│  │  ├─ RtlAddFunctionTable (SEH)        │            │
│  │  └─ DllMain(DLL_PROCESS_ATTACH)      │            │
│  └──────────────────────────────────────┘            │
└──────────────────────────────────────────────────────┘
```

### Why the shellcode is this small

The original C++ reference ran relocations inside the shellcode.  We moved
relocations to the injector side (`ReadProcessMemory` → patch → `WriteProcessMemory`).
This makes the shellcode much simpler and eliminates the need for inline
assembly tricks — all PE parsing lives in safe Rust.

## API

### `inject_dll`

```rust
pub unsafe fn inject_dll(process: HANDLE, dll_bytes: &[u8]) -> Result<()>
```

Manually maps the raw DLL bytes into the target process.
PE headers are wiped immediately; shellcode and context memory are freed.
The DLL itself stays loaded in the target until the process exits.

The process handle needs at minimum:
- `PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION`
- `PROCESS_CREATE_THREAD`

### `Error`

| Variant | Meaning |
|---|---|
| `InvalidPe` | Not a valid x64 PE file |
| `Win32(u32)` | A Win32 API returned an error (`GetLastError`) |
| `InvalidArgument` | Null handle, empty payload, etc. |
| `ShellcodeFailed(usize)` | Import resolution failed; code indicates which step |
| `SehRegistrationFailed` | DLL loaded but `RtlAddFunctionTable` failed |
| `ShellcodeCrashed(u32, usize)` | Remote thread crashed; code = NTSTATUS, step = last marker |

## Building

Requires **Rust nightly** (edition 2024).

```powershell
cargo +nightly build --release
```

### Static CRT

The workspace `.cargo/config.toml` enables `+crt-static` (equivalent to MSVC `/MT`)
so injected DLLs don't depend on `VCRUNTIME140.dll`.  It also enables
`/DYNAMICBASE` for full `.reloc` section generation.

### Notes for injected DLLs

- Rust heap allocation (`format!`, `Box`, `String`, `Vec`) **works fine** in
  manually-mapped DLLs — the default Windows allocator wraps `HeapAlloc` and
  needs no CRT initialization.
- Statically link the CRT (`+crt-static`) so your DLL has no external CRT
  dependency.
- Enable `/DYNAMICBASE` so the DLL has a `.reloc` section (the injector
  applies relocations when loading at a different base).

## Testing

```powershell
# Unit tests (PE structs, RVA conversion, shellcode layout) — fast, no GUI
cargo +nightly test -p mmap_inject

# Full end-to-end test (requires terminal interaction)
cargo run -p test_exe          # terminal 1 — injection target
cargo run -p test_injector     # terminal 2 — auto-injects test_dll.dll
```

## Workspace

| Crate | Description |
|---|---|
| `mmap_inject` | The injection library |
| `test_dll` | Example DLL — shows `MessageBox("Hello from PID: xxx")` |
| `test_exe` | Console target that prints its PID and waits |
| `test_injector` | Auto-injector — finds `test_exe.exe`, injects `test_dll.dll` |

## License

MIT — see [LICENSE](LICENSE).

---

Ported from [thetobysiu/ManualMapInjection](https://github.com/thetobysiu/ManualMapInjection).
