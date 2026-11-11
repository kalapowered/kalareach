//! The program the launch cases start as a child, as a grandchild and as the helper of Git. It
//! reports what it inherited and crashes on request. It is built only for the guest's cases.

#[cfg(windows)]
#[allow(unsafe_code)]
fn main() -> std::process::ExitCode {
    use std::os::windows::process::CommandExt as _;
    use std::process::{Command, ExitCode};
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT};
    use windows_sys::Win32::Storage::FileSystem::GetFileType;
    use windows_sys::Win32::System::Diagnostics::Debug::{GetErrorMode, RaiseFailFastException};
    use windows_sys::Win32::System::JobObjects::IsProcessInJob;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;

    fn in_any_job() -> bool {
        let mut inside = 0;
        // SAFETY: the current process pseudo-handle is valid; no job handle asks about any job.
        unsafe {
            IsProcessInJob(GetCurrentProcess(), null_mut(), &raw mut inside);
        }
        inside != 0
    }

    fn report(label: &str) {
        // SAFETY: reads the process's own error mode.
        let mode = unsafe { GetErrorMode() };
        println!(
            "{label} pid={} error-mode={mode:#x} in-job={}",
            std::process::id(),
            in_any_job()
        );
    }

    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let mode = arguments.first().map_or("report", String::as_str);
    match mode {
        "report" => report("report"),
        // The external diff program of Git: Git passes it seven arguments.
        "diff" => report("diff"),
        "handles" => {
            // Every handle value that is open here, whether it is inheritable and what it is.
            let mut value = 4_usize;
            while value < 0x4000 {
                let mut flags = 0_u32;
                let handle = value as *mut core::ffi::c_void;
                // SAFETY: asking about a handle value that may not be open is how it is found out.
                if unsafe { GetHandleInformation(handle, &raw mut flags) } != 0 {
                    // SAFETY: the handle is open.
                    let kind = unsafe { GetFileType(handle) };
                    println!(
                        "handle {value:#x} inherit={} type={kind}",
                        u32::from(flags & HANDLE_FLAG_INHERIT != 0)
                    );
                }
                value += 4;
            }
        }
        "spawn" => {
            // A grandchild that reports what it inherited, and reports the way it was started.
            report("child");
            let output = Command::new(std::env::current_exe().unwrap())
                .arg("report")
                .output();
            match output {
                Ok(output) => print!("{}", String::from_utf8_lossy(&output.stdout)),
                Err(error) => println!("spawn-failed {error}"),
            }
        }
        "breakaway" => {
            // Asks to leave the job.
            report("child");
            let started = Command::new(std::env::current_exe().unwrap())
                .arg("report")
                .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
                .output();
            match started {
                Ok(output) => {
                    println!("breakaway-started");
                    print!("{}", String::from_utf8_lossy(&output.stdout));
                }
                Err(error) => println!("breakaway-refused {:?}", error.raw_os_error()),
            }
        }
        "crash-access-violation" => {
            report("crash");
            // SAFETY: a deliberate access violation, to see what the system does with it.
            unsafe { std::ptr::write_volatile(null_mut::<u8>(), 1) };
        }
        "crash-fail-fast" => {
            report("crash");
            // SAFETY: a deliberate fail-fast, for the same reason.
            unsafe {
                RaiseFailFastException(null(), null(), 0);
            }
        }
        "marker" => {
            // Leaves a file that says it ran, for the cases that look for a program that started
            // where it should not have.
            if let Some(path) = arguments.get(1) {
                let _ = std::fs::write(path, std::process::id().to_string());
            }
        }
        "sleep" => {
            let milliseconds = arguments
                .get(1)
                .and_then(|text| text.parse::<u64>().ok())
                .unwrap_or(60_000);
            std::thread::sleep(std::time::Duration::from_millis(milliseconds));
        }
        "write-stderr" => eprintln!("on the error stream"),
        "arguments" => {
            for argument in std::env::args().skip(2) {
                println!("argument {argument:?}");
            }
        }
        "environment" => {
            for (name, value) in std::env::vars() {
                println!("variable {name}={value}");
            }
        }
        other => {
            eprintln!("unknown mode {other}");
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("kr-launch-stand-in runs on Windows only");
    std::process::ExitCode::from(2)
}
