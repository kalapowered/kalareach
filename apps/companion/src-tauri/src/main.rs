//! The desktop application's entry point.
//!
//! Everything the application does is in the library beside this file, so the same code runs
//! under the crate's own tests without a window.

// The window owns the user interface; nothing here writes to a console. On Windows a console
// subsystem binary opens one behind the window, so the release build declares the windows
// subsystem instead.
#![cfg_attr(
    not(debug_assertions),
    cfg_attr(windows, windows_subsystem = "windows")
)]

fn main() {
    companion_tauri::run();
}
