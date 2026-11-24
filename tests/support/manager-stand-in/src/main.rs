//! The stand-in service manager's program: see the library for what it answers.

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let status = kr_manager_stand_in::run(&arguments);
    std::process::ExitCode::from(u8::try_from(status).unwrap_or(REFUSED_EXIT))
}

/// The status a status that does not fit a byte is reported as.
#[cfg(unix)]
const REFUSED_EXIT: u8 = 64;

#[cfg(not(unix))]
fn main() {}
