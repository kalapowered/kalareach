//! The launcher on Windows, where a process cannot be replaced in place.
//!
//! The launcher creates the program itself, suspended, in its own job and console and with its
//! three standard handles, and says so to the backend: `going`, naming the program and the directory
//! the program inherits. Only when the backend says the launch is committed does it start the
//! program, say so, and wait for it; the launcher then ends with the program's whole 32-bit exit
//! code. A backend that refuses, does not answer within its deadline or does not commit leaves a
//! program that never ran: the launcher ends it and runs the typed command as typed.
//!
//! The program is the launcher's own child, so it is in whatever job the launcher is in and shares
//! its console. The launcher handles console control events by returning that it handled them, so
//! an interrupt reaches the program, which decides what it means, and not the launcher, which waits
//! for it.

#![expect(
    unsafe_code,
    reason = "creating a process, starting it and waiting for it are calls with no safe form"
)]

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::Path;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetConsoleCtrlHandler,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION,
    ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

use super::{
    ADMISSION_DEADLINE, COMMIT_DEADLINE, EXIT_NOT_A_LAUNCH, Record, Route, Variable, exec_after,
    read_credential, read_record, typed_vector,
};
use crate::registration::REGISTRATION_VARIABLE;

/// The longest answer the backend writes.
const MAX_ANSWER_BYTES: usize = 4096;

/// The longest command line `CreateProcessW` takes, in UTF-16 units, its terminator included.
const MAX_COMMAND_LINE: usize = 32_767;

/// Builds the command line a program is started with: each word quoted so that the program's own
/// parser reads it back whole.
///
/// An argument is quoted when it is empty or holds a space, a tab or a quotation mark. Inside the
/// quotes a run of `n` backslashes before a quotation mark is written as `2n + 1` of them, a run
/// before the closing quote as `2n`, and a run anywhere else exactly as it is. This is the rule
/// the worker writes every command line with.
pub(super) fn command_line(argv: &[OsString]) -> String {
    let mut line = String::new();
    for argument in argv {
        if !line.is_empty() {
            line.push(' ');
        }
        let argument = argument.to_string_lossy();
        if !argument.is_empty() && !argument.contains([' ', '\t', '"']) {
            line.push_str(&argument);
            continue;
        }
        line.push('"');
        let mut backslashes = 0_usize;
        for character in argument.chars() {
            match character {
                '\\' => backslashes += 1,
                '"' => {
                    for _ in 0..=backslashes.saturating_mul(2) {
                        line.push('\\');
                    }
                    backslashes = 0;
                    line.push('"');
                }
                _ => {
                    for _ in 0..backslashes {
                        line.push('\\');
                    }
                    backslashes = 0;
                    line.push(character);
                }
            }
        }
        for _ in 0..backslashes.saturating_mul(2) {
            line.push('\\');
        }
        line.push('"');
    }
    line
}

/// Builds an environment block: this process's own variables with `variables` set over them, sorted
/// by name without regard to case as the system wants them, ending with an empty one.
pub(super) fn environment_block(
    own: impl IntoIterator<Item = (OsString, OsString)>,
    variables: &[Variable],
) -> Vec<u16> {
    let mut by_name: std::collections::BTreeMap<String, (Vec<u16>, Vec<u16>)> =
        std::collections::BTreeMap::new();
    let key = |name: &OsStr| name.to_string_lossy().to_uppercase();
    for (name, value) in own {
        by_name.insert(
            key(&name),
            (name.encode_wide().collect(), value.encode_wide().collect()),
        );
    }
    for variable in variables {
        let name = OsStr::new(&variable.name);
        by_name.insert(
            key(name),
            (
                name.encode_wide().collect(),
                OsStr::new(&variable.value).encode_wide().collect(),
            ),
        );
    }
    let mut block = Vec::new();
    for (name, value) in by_name.into_values() {
        block.extend(name);
        block.push(u16::from(b'='));
        block.extend(value);
        block.push(0);
    }
    block.push(0);
    block
}

/// The program the launcher created, suspended.
pub(super) struct Program {
    process: OwnedHandle,
    thread: OwnedHandle,
    id: u32,
}

impl Program {
    /// Creates the program suspended, in the launcher's own job and console, with the launcher's
    /// standard handles and no other, and the environment the integration declares.
    fn create(
        executable: &Path,
        vector: &[OsString],
        variables: &[Variable],
    ) -> Result<Self, String> {
        let mut line: Vec<u16> = command_line(vector)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        if line.len() > MAX_COMMAND_LINE {
            return Err(format!(
                "the command line is {} characters, and the most the system takes is {}",
                line.len() - 1,
                MAX_COMMAND_LINE - 1
            ));
        }
        let program: Vec<u16> = executable
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let environment = environment_block(std::env::vars_os(), variables);
        let mut handles: Vec<HANDLE> = Vec::new();
        let mut standard = [std::ptr::null_mut::<std::ffi::c_void>(); 3];
        for (slot, which) in
            standard
                .iter_mut()
                .zip([STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE])
        {
            // SAFETY: the argument is a value; the call returns a handle value or an invalid one.
            let handle = unsafe { GetStdHandle(which) };
            if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
                *slot = handle;
                if !handles.contains(&handle) {
                    handles.push(handle);
                }
            }
        }
        let mut bytes = 0_usize;
        // SAFETY: the count is a local this thread owns, and a null list is what asks for the size;
        // the call reports failure for it, which is the answer.
        unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &raw mut bytes) };
        let mut list = vec![0_usize; bytes.div_ceil(std::mem::size_of::<usize>())];
        let attributes: LPPROC_THREAD_ATTRIBUTE_LIST = list.as_mut_ptr().cast();
        // SAFETY: the buffer is at least the size the call above asked for and outlives every use.
        if unsafe { InitializeProcThreadAttributeList(attributes, 1, 0, &raw mut bytes) } == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if !handles.is_empty() {
            // SAFETY: the list is initialised, the array outlives the creation, and the size is
            // that array's own.
            let updated = unsafe {
                UpdateProcThreadAttribute(
                    attributes,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    handles.as_ptr().cast(),
                    std::mem::size_of_val(handles.as_slice()),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                )
            };
            if updated == 0 {
                let failure = std::io::Error::last_os_error();
                // SAFETY: the list was initialised above and nothing else holds it.
                unsafe { DeleteProcThreadAttributeList(attributes) };
                return Err(failure.to_string());
            }
        }
        // SAFETY: all zeroes is the documented starting state of a structure of integers, pointers
        // and handles.
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = u32::try_from(std::mem::size_of::<STARTUPINFOEXW>()).unwrap_or(0);
        startup.lpAttributeList = attributes;
        startup.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = standard[0];
        startup.StartupInfo.hStdOutput = standard[1];
        startup.StartupInfo.hStdError = standard[2];
        // SAFETY: all zeroes is a structure of integers that the call fills in.
        let mut started: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: every pointer is to a local that outlives the call. The command line is mutable
        // because the call may write into it. The handles inherited are the ones the list names;
        // with none to name, none are inherited.
        let created = unsafe {
            CreateProcessW(
                program.as_ptr(),
                line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                i32::from(!handles.is_empty()),
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
                environment.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                std::ptr::null(),
                std::ptr::from_mut(&mut startup).cast(),
                &raw mut started,
            )
        };
        let failure = (created == 0).then(std::io::Error::last_os_error);
        // SAFETY: the list was initialised above, the creation no longer needs it, and nothing else
        // holds it.
        unsafe { DeleteProcThreadAttributeList(attributes) };
        if let Some(failure) = failure {
            return Err(format!(
                "{} could not be created: {failure}",
                executable.display()
            ));
        }
        // SAFETY: the call reported both handles, and each is this process's own with nothing else
        // holding it.
        let (process, thread) = unsafe {
            (
                OwnedHandle::from_raw_handle(started.hProcess.cast()),
                OwnedHandle::from_raw_handle(started.hThread.cast()),
            )
        };
        Ok(Self {
            process,
            thread,
            id: started.dwProcessId,
        })
    }

    /// Ends the program, which has not run: nothing it could have started exists.
    fn end(&self) {
        // SAFETY: the handle is this value's own and open for the call.
        unsafe { TerminateProcess(self.process.as_raw_handle().cast(), 1) };
    }

    /// Starts the program.
    fn resume(&self) -> Result<(), String> {
        // SAFETY: the thread is the one the creation made, suspended, and this handle is the only
        // one for it.
        if unsafe { ResumeThread(self.thread.as_raw_handle().cast()) } == u32::MAX {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }

    /// Waits for the program and returns its whole exit code.
    fn wait(&self) -> u32 {
        // SAFETY: the handle is this value's own and open for the call.
        let waited = unsafe { WaitForSingleObject(self.process.as_raw_handle().cast(), INFINITE) };
        let mut code = 1_u32;
        if waited == WAIT_OBJECT_0 {
            // SAFETY: the handle is open for the call and the code is a local this thread owns.
            unsafe { GetExitCodeProcess(self.process.as_raw_handle().cast(), &raw mut code) };
        }
        code
    }
}

/// Answers every console control event as handled.
///
/// An interrupt is delivered to every process attached to the console, the program's and this
/// launcher's. The program decides what it means; the launcher, which only waits for it, must not
/// end on it.
unsafe extern "system" fn handled(_event: u32) -> i32 {
    1
}

/// One admitted connection to the backend, read and written under deadlines.
struct Admitted {
    runtime: tokio::runtime::Runtime,
    reader: BufReader<tokio::io::ReadHalf<kr_ipc::endpoint::Connection>>,
    writer: tokio::io::WriteHalf<kr_ipc::endpoint::Connection>,
}

impl Admitted {
    /// Writes one line by `deadline`.
    fn write_line(&mut self, line: &[u8], deadline: Instant) -> Result<(), String> {
        let left = deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| "the deadline passed".to_owned())?;
        let writer = &mut self.writer;
        self.runtime
            .block_on(async {
                tokio::time::timeout(left, async {
                    writer.write_all(line).await?;
                    writer.write_all(b"\n").await?;
                    writer.flush().await
                })
                .await
            })
            .map_err(|_| "the deadline passed".to_owned())?
            .map_err(|error| format!("the endpoint cannot be written: {error}"))
    }

    /// Reads one line by `deadline`.
    fn read_line(&mut self, deadline: Instant) -> Result<String, String> {
        let left = deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| "the backend did not answer in time".to_owned())?;
        let reader = &mut self.reader;
        let line = self
            .runtime
            .block_on(async {
                tokio::time::timeout(left, async {
                    let mut line = Vec::new();
                    let read = (&mut *reader)
                        .take(u64::try_from(MAX_ANSWER_BYTES + 1).unwrap_or(u64::MAX))
                        .read_until(b'\n', &mut line)
                        .await?;
                    Ok::<_, std::io::Error>((read, line))
                })
                .await
            })
            .map_err(|_| "the backend did not answer in time".to_owned())?
            .map_err(|error| format!("the endpoint cannot be read: {error}"))?;
        let (read, mut line) = line;
        if read == 0 {
            return Err("the backend refused it".to_owned());
        }
        if line.last() != Some(&b'\n') {
            return Err(if line.len() > MAX_ANSWER_BYTES {
                "the backend's answer is too long".to_owned()
            } else {
                "the endpoint closed in the middle of an answer".to_owned()
            });
        }
        line.pop();
        String::from_utf8(line).map_err(|_| "the backend's answer is not text".to_owned())
    }

    /// Says the launcher cannot start the program, and why.
    fn decline(&mut self, why: &str) {
        let frame = serde_json::json!({ "kr_launch": { "going": false, "declined": why } });
        let _ = self.write_line(
            frame.to_string().as_bytes(),
            Instant::now() + COMMIT_DEADLINE,
        );
    }
}

/// Presents this process to the backend and waits for its admission, all within
/// [`ADMISSION_DEADLINE`] of the launcher's start.
fn present(
    executable: &Path,
    vector: &[OsString],
    registration: &Path,
    record: &Record,
    started: Instant,
) -> Result<Admitted, String> {
    let deadline = started + ADMISSION_DEADLINE;
    let credential = read_credential(registration, record)?;
    let identity = kr_ipc::identity::process_start_identity(std::process::id())
        .map_err(|error| format!("this process cannot be identified: {error}"))?;
    let executable_text = executable
        .to_str()
        .ok_or_else(|| "the executable's path is not text".to_owned())?;
    let arguments: Vec<&str> = vector
        .iter()
        .map(|argument| argument.to_str())
        .collect::<Option<_>>()
        .ok_or_else(|| "an argument is not text".to_owned())?;
    let endpoint = match crate::registration::Endpoint::parse(&record.endpoint)
        .map_err(|error| error.to_string())?
    {
        crate::registration::Endpoint::NamedPipe(name) => name,
        crate::registration::Endpoint::PrivateSocket(_) => {
            return Err("the launch record names no private endpoint".to_owned());
        }
    };
    let address = kr_ipc::paths::Endpoint::from_name(endpoint)
        .map_err(|error| format!("the endpoint cannot be named: {error}"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("no runtime could be made: {error}"))?;
    let left = deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| "the deadline passed".to_owned())?;
    // The client opens the pipe for identification only and refuses a pipe whose own list is not
    // this account's, so a pipe another account created first is never written to.
    let connection = runtime
        .block_on(async {
            tokio::time::timeout(left, kr_ipc::endpoint::Connection::connect(&address)).await
        })
        .map_err(|_| "the endpoint did not accept in time".to_owned())?
        .map_err(|error| format!("the endpoint cannot be reached: {error}"))?;
    let (reader, writer) = tokio::io::split(connection);
    let mut admitted = Admitted {
        runtime,
        reader: BufReader::new(reader),
        writer,
    };
    let rest = serde_json::json!({
        "pid": identity.pid.get(),
        "start": identity.start_value.get(),
        "executable": executable_text,
        "arguments": arguments,
    })
    .to_string();
    // `{"kr_launch":{"credential":"<hex>",` then the rest of the object without its opening brace.
    // The credential is hexadecimal, so it needs no escaping, and it is assembled in the host's own
    // zeroising buffer.
    let tail = rest.as_bytes().get(1..).unwrap_or_default();
    let opening: &[u8] = br#"{"kr_launch":{"credential":""#;
    let mut line = Vec::with_capacity(opening.len() + credential.len() + tail.len() + 4);
    line.extend_from_slice(opening);
    line.extend_from_slice(credential.expose());
    line.extend_from_slice(br#"","#);
    line.extend_from_slice(tail);
    line.extend_from_slice(b"}");
    let line = kr_crypto::secret::SecretVec::new(line);
    admitted.write_line(line.expose(), deadline)?;
    drop(line);
    let answer = admitted.read_line(deadline)?;
    if super::answers(&answer, "admitted") {
        Ok(admitted)
    } else {
        Err("the backend answered something other than an admission".to_owned())
    }
}

/// Runs one invocation on Windows: presented, admitted and committed, or as typed.
pub(super) fn run(
    executable: &Path,
    vector: &[OsString],
    registration: &Path,
    started: Instant,
    hold_after_admission: Option<Duration>,
    hold_before_exec: Option<&Path>,
) -> std::process::ExitCode {
    let typed = match typed_vector(registration, vector) {
        Ok(typed) => typed,
        Err(why) => {
            crate::report(&format!(
                "{REGISTRATION_VARIABLE} names no launch this program could have been given \
                 ({why}), so nothing is run"
            ));
            return std::process::ExitCode::from(EXIT_NOT_A_LAUNCH);
        }
    };
    let record = &match read_record(registration) {
        Ok(record) => record,
        Err(why) => {
            crate::report(&format!(
                "the backend's launch record cannot be read ({why}), so the program runs as typed"
            ));
            return exec_after(hold_before_exec, executable, &typed, Route::AsTyped);
        }
    };
    let mut admitted = match present(executable, vector, registration, record, started) {
        Ok(admitted) => admitted,
        Err(why) => {
            crate::report(&format!(
                "the backend did not admit this launch ({why}), so the program runs as typed"
            ));
            return exec_after(hold_before_exec, executable, &typed, Route::AsTyped);
        }
    };
    if let Some(hold) = hold_after_admission {
        std::thread::sleep(hold);
    }
    // The program is created before the backend is told, so that the backend can name it; it does
    // not run until the backend says the launch is committed.
    let program = match Program::create(executable, vector, &record.variables) {
        Ok(program) => program,
        Err(why) => {
            admitted.decline(&why);
            drop(admitted);
            crate::report(&format!(
                "the program could not be created ({why}), so it runs as typed"
            ));
            return exec_after(hold_before_exec, executable, &typed, Route::AsTyped);
        }
    };
    // From here the launcher waits for the program, and an interrupt is the program's.
    // SAFETY: the handler is a function with the signature the call takes and no state.
    unsafe { SetConsoleCtrlHandler(Some(handled), 1) };
    let deadline = Instant::now() + COMMIT_DEADLINE;
    let directory = std::env::current_dir()
        .ok()
        .and_then(|directory| directory.to_str().map(str::to_owned));
    let going = serde_json::json!({
        "kr_launch": { "going": true, "program": program.id, "directory": directory }
    });
    let committed = admitted
        .write_line(going.to_string().as_bytes(), deadline)
        .and_then(|()| admitted.read_line(deadline))
        .and_then(|answer| {
            if super::answers(&answer, "committed") {
                Ok(())
            } else {
                Err("the backend answered something other than a commit".to_owned())
            }
        });
    if let Err(why) = committed {
        program.end();
        drop(admitted);
        crate::report(&format!(
            "the backend did not commit this launch ({why}), so the program runs as typed"
        ));
        return exec_after(hold_before_exec, executable, &typed, Route::AsTyped);
    }
    if let Some(barrier) = hold_before_exec {
        let waited = Instant::now();
        while !barrier.exists() && waited.elapsed() < super::BARRIER_LIMIT {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    if let Err(why) = program.resume() {
        program.end();
        drop(admitted);
        crate::report(&format!(
            "the committed program could not be started ({why}), so it runs as typed"
        ));
        return exec_after(hold_before_exec, executable, &typed, Route::AsTyped);
    }
    // Started: whatever happens now, the typed command is never run again.
    let resumed = serde_json::json!({ "kr_launch": { "resumed": true } });
    let _ = admitted.write_line(
        resumed.to_string().as_bytes(),
        Instant::now() + COMMIT_DEADLINE,
    );
    drop(admitted);
    let code = program.wait();
    // The whole 32-bit code: an exit code is not a byte on this platform.
    std::process::exit(i32::from_ne_bytes(code.to_ne_bytes()))
}
