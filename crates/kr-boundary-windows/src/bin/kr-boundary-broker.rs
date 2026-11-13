//! The resident service that starts Git as the two boundary accounts. Windows runs it as SYSTEM;
//! the installation registers it.

#![deny(clippy::disallowed_methods)]

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    kr_boundary_windows::win::broker::main()
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    // text: broker-3
    eprintln!(
        "kr-boundary-broker is the Windows execution boundary's service and runs on Windows only"
    );
    std::process::ExitCode::from(2)
}
