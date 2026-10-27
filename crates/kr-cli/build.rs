//! Gives `kr` the main-thread stack on Windows that Linux and macOS give it.
//!
//! `kr` runs the whole command as one future that the main thread blocks on, so the future lives
//! on that thread's stack. The main thread's stack is the one stack that this program's own code
//! does not size. Linux and macOS give it 8 MiB. Windows takes the size from the executable's
//! header, where the linker's default is 1 MiB (2 MiB for the GNU linker), so a future deep
//! enough can overflow only there. The header is set at link time instead of moving the runtime
//! to a thread of its own: the runtime still starts on the main thread, and nothing that has to
//! run there moves. The size is address space reserved, and pages are committed as the stack
//! grows. Threads that Windows starts without a size of their own, such as those of its thread
//! pool, reserve the same amount; that is address space, not memory.

/// The main thread's stack on Linux and macOS.
const MAIN_THREAD_STACK_BYTES: u32 = 8 * 1024 * 1024;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let size = MAIN_THREAD_STACK_BYTES;
    let environment = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let argument = match environment.as_str() {
        "msvc" => format!("/STACK:{size}"),
        "gnu" => format!("-Wl,--stack,{size}"),
        other => {
            panic!("the main thread's stack cannot be sized for the Windows environment {other:?}")
        }
    };
    println!("cargo:rustc-link-arg-bin=kr={argument}");
}
