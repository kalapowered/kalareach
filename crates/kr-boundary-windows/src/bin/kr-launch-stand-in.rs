//! The program the launch cases start as a child, as a grandchild and as the helper of Git. It
//! reports what it inherited and crashes on request. It is built only for the guest's cases.

#[cfg(windows)]
#[allow(unsafe_code)]
fn main() -> std::process::ExitCode {
    use std::os::windows::process::CommandExt as _;
    use std::process::{Command, ExitCode, Stdio};
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT};
    use windows_sys::Win32::Storage::FileSystem::GetFileType;
    use windows_sys::Win32::System::Diagnostics::Debug::{
        GetErrorMode, RaiseFailFastException, SetErrorMode,
    };
    use windows_sys::Win32::System::JobObjects::IsProcessInJob;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;

    /// Where this program was started from, as its command line names it.
    fn own_path() -> std::path::PathBuf {
        std::path::PathBuf::from(std::env::args_os().next().unwrap_or_default())
    }

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

    fn crash(kind: &str) {
        report("crash");
        match kind {
            "access-violation" => {
                // SAFETY: a deliberate access violation, to see what the system does with it.
                unsafe { std::ptr::write_volatile(null_mut::<u8>(), 1) };
            }
            _ => {
                // SAFETY: a deliberate fail-fast, for the same reason.
                unsafe {
                    RaiseFailFastException(null(), null(), 0);
                }
            }
        }
    }

    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let mut mode = arguments.first().map_or("report", String::as_str);
    // Git runs an external diff program with seven arguments and no mode: the mode is then in a
    // file beside this program, or the program only reports.
    let from_file;
    let known = [
        "report",
        "diff",
        "handles",
        "spawn",
        "breakaway",
        "crash-access-violation",
        "crash-fail-fast",
        "crash-default-mode",
        "spawn-crash",
        "spawn-hold",
        "marker",
        "sleep",
        "write-stderr",
        "shell",
        "arguments",
        "environment",
    ];
    if arguments.len() >= 7 && !known.contains(&mode) {
        let beside = own_path().with_file_name("diff-mode.txt");
        from_file = std::fs::read_to_string(beside).unwrap_or_else(|_| "diff".to_owned());
        mode = from_file.trim();
    }
    match mode {
        "report" => report("report"),
        // The external diff program of Git, when no file beside it asks for a crash.
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
            let output = Command::new(own_path()).arg("report").output();
            match output {
                Ok(output) => print!("{}", String::from_utf8_lossy(&output.stdout)),
                Err(error) => println!("spawn-failed {error}"),
            }
        }
        "breakaway" => {
            // Asks to leave the job.
            report("child");
            let started = Command::new(own_path())
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
        "crash-access-violation" => crash("access-violation"),
        "crash-fail-fast" => crash("fail-fast"),
        // The same crash after asking for the default error mode again: outside what the broker's
        // mode promises, and the control that shows the system would have reported it.
        "crash-default-mode" => {
            // SAFETY: sets the process's error mode, which has no memory safety condition.
            unsafe {
                SetErrorMode(0);
            }
            crash(arguments.get(1).map_or("fail-fast", String::as_str));
        }
        // A grandchild that crashes.
        "spawn-crash" => {
            report("child");
            let kind = arguments.get(1).map_or("fail-fast", String::as_str);
            let output = Command::new(own_path())
                .arg(format!("crash-{kind}"))
                .output();
            match output {
                Ok(output) => print!("{}", String::from_utf8_lossy(&output.stdout)),
                Err(error) => println!("spawn-failed {error}"),
            }
        }
        // A grandchild that stays, so that the job holds a tree.
        "spawn-hold" => {
            let grandchild = Command::new(own_path())
                .args(["sleep", "120000"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
            match grandchild {
                Ok(grandchild) => println!("grandchild pid={}", grandchild.id()),
                Err(error) => println!("spawn-failed {error}"),
            }
            std::thread::sleep(std::time::Duration::from_secs(120));
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
        // Starts PowerShell with a hidden console of its own, which a detached program has to ask
        // for because PowerShell needs one, and passes on what it wrote.
        "shell" => {
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            let root = std::env::var("SystemRoot").unwrap_or_default();
            let shell = std::path::Path::new(&root)
                .join("System32")
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe");
            let output = Command::new(shell)
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-EncodedCommand",
                    arguments.get(1).map_or("", String::as_str),
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .output();
            match output {
                Ok(output) => {
                    println!("shell exit {:?}", output.status.code());
                    print!("{}", String::from_utf8_lossy(&output.stdout));
                    eprint!("{}", String::from_utf8_lossy(&output.stderr));
                }
                Err(error) => println!("shell-failed {error}"),
            }
        }
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
