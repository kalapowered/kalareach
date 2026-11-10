//! The program that installs, repairs and removes the Windows execution boundary. It runs
//! elevated, started by `kr host boundary`, and takes the person's typed yes before it changes
//! anything.

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    kr_boundary_windows::win::setup::main()
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("kr-boundary-setup installs the Windows execution boundary and runs on Windows only");
    std::process::ExitCode::from(2)
}
