//! What the `backup_setup` cases need on Windows and Unix does not have: the program that stands in
//! a console beside `kr`, a model of the screen the console drew, and a second program of the same
//! account that opens `kr`'s process, its threads and its token.
//!
//! The observer is a mode of the `backup_setup` test binary itself: the binary is started in a
//! pseudo-console with a marker in its environment, which makes the helper case named
//! [`THE_TEST`] run [`observe`] and every other case return at once. The observer ignores Ctrl-C
//! and Ctrl-Break with a handler function, runs `kr`, and then says what it found, so that a case
//! can tell what `kr` left in the console.

#![expect(
    unsafe_code,
    reason = "the console half of these cases calls the console, process, thread and token \
              interfaces of the system, which have no safe form"
)]

use std::fs::File;
use std::io::{BufRead as _, Read, Write};
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_NO_MORE_FILES, FILETIME, GetLastError, INVALID_HANDLE_VALUE, LUID,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    TOKEN_PRIVILEGES,
};
use windows_sys::Win32::System::Console::{
    ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, GenerateConsoleCtrlEvent,
    GetConsoleMode, GetNumberOfConsoleInputEvents, INPUT_RECORD, KEY_EVENT, KEY_EVENT_RECORD,
    KEY_EVENT_RECORD_0, PeekConsoleInputW, SetConsoleCtrlHandler, SetConsoleMode,
    WriteConsoleInputW,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetThreadTimes, OpenProcess, OpenProcessToken, OpenThread,
};

/// The variable that makes this test binary run the observer instead of its cases. Its value is
/// the mode: [`SETUP`], [`BREAK_PROBE`] or [`IDLE`].
pub const MARKER: &str = "KR_SETUP_OBSERVER";
/// The observer's mode that runs `kr` and reports what it left in the console.
pub const SETUP: &str = "setup";
/// The mode that only reports a Ctrl-C or a Ctrl-Break that reached it.
pub const BREAK_PROBE: &str = "break-probe";
/// The mode that does nothing for as long as it is let live: a plain program of the account.
pub const IDLE: &str = "idle";
/// The name of the case of `backup_setup.rs` that runs the observer when [`MARKER`] is set.
pub const THE_TEST: &str = "the_console_half_of_a_setup_window";
/// The path of the `kr` the observer runs.
pub const KR: &str = "KR_SETUP_OBSERVER_KR";
/// The arguments of that `kr`, one to a line.
pub const ARGUMENTS: &str = "KR_SETUP_OBSERVER_ARGUMENTS";
/// When set, the observer clears the console's line, echo and processed input before `kr` runs.
pub const RAW: &str = "KR_SETUP_OBSERVER_RAW";
/// When set, the observer sets the console's `DISABLE_NEWLINE_AUTO_RETURN` before `kr` runs.
pub const NO_AUTO_RETURN: &str = "KR_SETUP_OBSERVER_NO_AUTO_RETURN";
/// When set, the observer starts `kr` as the program it debugs.
pub const DEBUGGED: &str = "KR_SETUP_OBSERVER_DEBUGGED";
/// The text the observer puts into the console's input, as key records, before it starts `kr`.
pub const TYPE_AHEAD: &str = "KR_SETUP_OBSERVER_TYPE_AHEAD";
/// The path of a file whose appearance makes the observer send Ctrl-Break to its console.
pub const BREAK_FILE: &str = "KR_SETUP_OBSERVER_BREAK_FILE";

/// The rows and columns of the console. More rows than the dialogue prints, so nothing scrolls and
/// the screen shows each line once.
pub const ROWS: u16 = 300;
/// See [`ROWS`].
pub const COLUMNS: u16 = 200;

static CTRL_C: AtomicU32 = AtomicU32::new(0);
static CTRL_BREAK: AtomicU32 = AtomicU32::new(0);

/// Answers Ctrl-C and Ctrl-Break by taking them, so that the observer outlives the command it runs.
/// A function, not `SetConsoleCtrlHandler(NULL, TRUE)`: a program started from the observer
/// inherits that setting, and the command must find its own handler working.
unsafe extern "system" fn take_the_event(event: u32) -> i32 {
    match event {
        0 => {
            CTRL_C.fetch_add(1, Ordering::SeqCst);
            1
        }
        1 => {
            CTRL_BREAK.fetch_add(1, Ordering::SeqCst);
            1
        }
        _ => 0,
    }
}

fn console(name: &str) -> File {
    File::options()
        .read(true)
        .write(true)
        .open(name)
        .unwrap_or_else(|error| panic!("the observer opens {name}: {error}"))
}

fn mode_of(console: &File) -> u32 {
    let mut mode = 0_u32;
    // SAFETY: the handle is an open console handle and the pointer is a live `u32`.
    let read = unsafe { GetConsoleMode(console.as_raw_handle().cast(), &raw mut mode) };
    assert!(read != 0, "the observer reads a console mode");
    mode
}

fn set_mode(console: &File, mode: u32) {
    // SAFETY: the handle is an open console handle.
    let set = unsafe { SetConsoleMode(console.as_raw_handle().cast(), mode) };
    assert!(set != 0, "the observer sets a console mode");
}

/// What the helper case runs: the observer of the mode `mode`.
pub fn observe(mode: &str) {
    // The test program has printed the name of this case without a line end. Every line the observer
    // says begins a row of its own, so a case reads it from the start of the row.
    println!();
    // SAFETY: the handler is a function that lives for the whole process and touches only atomics.
    let installed = unsafe { SetConsoleCtrlHandler(Some(take_the_event), 1) };
    assert!(installed != 0, "the observer installs its handler");
    match mode {
        SETUP => run_kr(),
        BREAK_PROBE => break_probe(),
        IDLE => {
            std::thread::spawn(|| std::thread::sleep(Duration::from_secs(120)));
            std::thread::sleep(Duration::from_secs(120));
        }
        other => panic!("the observer has no mode {other:?}"),
    }
}

/// Sends Ctrl-Break to every program on this console when the file named by [`BREAK_FILE`] shows
/// up, as a person's Ctrl-Break reaches every program on a console.
fn send_break_when_asked() {
    let Some(file) = std::env::var_os(BREAK_FILE).map(PathBuf::from) else {
        return;
    };
    std::thread::spawn(move || {
        loop {
            if file.exists() {
                // SAFETY: the call takes two integers.
                unsafe { GenerateConsoleCtrlEvent(1, 0) };
                let _ = std::fs::remove_file(&file);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    });
}

fn break_probe() {
    send_break_when_asked();
    println!("kr-observer: ready");
    let started = Instant::now();
    let (mut seen_c, mut seen_break) = (0, 0);
    while started.elapsed() < Duration::from_secs(60) {
        let (c, b) = (
            CTRL_C.load(Ordering::SeqCst),
            CTRL_BREAK.load(Ordering::SeqCst),
        );
        if c != seen_c {
            seen_c = c;
            println!("kr-observer: ctrl-c arrived");
        }
        if b != seen_break {
            seen_break = b;
            println!("kr-observer: break arrived");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The key records of `text` as a person's keys make them: a key down and a key up for each unit,
/// and Enter for a line end.
fn key_records(text: &str) -> Vec<INPUT_RECORD> {
    const VK_RETURN: u16 = 0x0D;

    let mut records = Vec::new();
    for unit in text.encode_utf16() {
        let unit = if unit == u16::from(b'\n') {
            u16::from(b'\r')
        } else {
            unit
        };
        let key = match u8::try_from(unit) {
            Ok(b'\r') => VK_RETURN,
            Ok(byte) if byte.is_ascii_alphanumeric() => u16::from(byte.to_ascii_uppercase()),
            _ => 0,
        };
        for down in [1, 0] {
            // SAFETY: the structure is plain data for which all zeroes is a valid start.
            let mut record: INPUT_RECORD = unsafe { std::mem::zeroed() };
            record.EventType = u16::try_from(KEY_EVENT).expect("a small event type");
            record.Event.KeyEvent = KEY_EVENT_RECORD {
                bKeyDown: down,
                wRepeatCount: 1,
                wVirtualKeyCode: key,
                wVirtualScanCode: 0,
                uChar: KEY_EVENT_RECORD_0 { UnicodeChar: unit },
                dwControlKeyState: 0,
            };
            records.push(record);
        }
    }
    records
}

/// Puts `text` into the console's input as key records, and reads the input back to see that they
/// are there: the line a person typed before the command had said anything, which no program has
/// read yet. The case that asks for this fails here, in words, when the console did not take them.
fn type_ahead(input: &File, text: &str) {
    let records = key_records(text);
    let count = u32::try_from(records.len()).expect("a short line");
    let mut written = 0_u32;
    // SAFETY: the handle is an open console input, the buffer holds `count` records and the count
    // written is a local.
    let put = unsafe {
        WriteConsoleInputW(
            input.as_raw_handle().cast(),
            records.as_ptr(),
            count,
            &raw mut written,
        )
    };
    assert!(
        put != 0 && written == count,
        "the observer queues the typed-ahead line: {written} of {count} records written"
    );
    // SAFETY: the structures are plain data for which all zeroes is a valid start.
    let mut peeked: Vec<INPUT_RECORD> = vec![unsafe { std::mem::zeroed() }; records.len() + 64];
    let mut seen = 0_u32;
    // SAFETY: the buffer holds the number of records the call is told, and the count is a local.
    let peek = unsafe {
        PeekConsoleInputW(
            input.as_raw_handle().cast(),
            peeked.as_mut_ptr(),
            u32::try_from(peeked.len()).expect("a short line"),
            &raw mut seen,
        )
    };
    assert!(
        peek != 0 && seen >= count,
        "the observer sees the typed-ahead line in the input: {seen} of {count} records queued"
    );
    println!("kr-observer: typed ahead {count} records, {seen} queued");
}

/// How many input records wait in the console, as the console says.
fn queued(input: &File) -> u32 {
    let mut waiting = 0_u32;
    // SAFETY: the handle is an open console input and the count is a local.
    let asked =
        unsafe { GetNumberOfConsoleInputEvents(input.as_raw_handle().cast(), &raw mut waiting) };
    if asked == 0 { 0 } else { waiting }
}

fn run_kr() {
    let input = console("CONIN$");
    let output = console("CONOUT$");
    if std::env::var_os(RAW).is_some() {
        set_mode(
            &input,
            mode_of(&input) & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT),
        );
    }
    if std::env::var_os(NO_AUTO_RETURN).is_some() {
        set_mode(
            &output,
            mode_of(&output) | windows_sys::Win32::System::Console::DISABLE_NEWLINE_AUTO_RETURN,
        );
    }
    let before = (mode_of(&input), mode_of(&output));
    if let Ok(text) = std::env::var(TYPE_AHEAD) {
        type_ahead(&input, &text);
    }
    send_break_when_asked();
    // The most records that waited in the console's input at any time while `kr` ran: a case that
    // asks whether `kr` throws input away reads it, so that a case whose input never waited cannot
    // pass for want of anything to throw away.
    let most_queued = Arc::new(AtomicU32::new(0));
    let watching = Arc::clone(&most_queued);
    let watched = input.try_clone().expect("the observer watches the input");
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let finished = Arc::clone(&done);
    let watcher = std::thread::spawn(move || {
        while !finished.load(Ordering::SeqCst) {
            watching.fetch_max(queued(&watched), Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let kr = std::env::var(KR).expect("the observer is told which kr to run");
    let arguments = std::env::var(ARGUMENTS).unwrap_or_default();
    let arguments: Vec<&str> = arguments.lines().filter(|line| !line.is_empty()).collect();
    let code = if std::env::var_os(DEBUGGED).is_some() {
        run_under_debugger(&kr, &arguments)
    } else {
        let mut child = std::process::Command::new(&kr)
            .args(&arguments)
            .spawn()
            .expect("the observer starts kr");
        println!("{}{}", crate::KR_PID_SAID, child.id());
        child
            .wait()
            .expect("the observer waits for kr")
            .code()
            .unwrap_or(-1)
    };
    let after = (mode_of(&input), mode_of(&output));
    done.store(true, Ordering::SeqCst);
    let _ = watcher.join();
    // The modes come first: a case that waits for the end of `kr` has them by then.
    println!(
        "kr-observer: modes before {:x}:{:x} after {:x}:{:x}",
        before.0, before.1, after.0, after.1
    );
    println!(
        "kr-observer: most queued {}",
        most_queued.load(Ordering::SeqCst)
    );
    println!("kr ended {code}");
    // A line of its own, read as a shell reads the next thing a person types.
    set_mode(
        &input,
        mode_of(&input) | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT,
    );
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    println!("first:{}", line.trim_end_matches(['\r', '\n']));
}

/// Runs `kr` as the program this process debugs, and returns its exit code. A program under a
/// debugger answers `IsDebuggerPresent` with true.
fn run_under_debugger(kr: &str, arguments: &[&str]) -> i32 {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        ContinueDebugEvent, DEBUG_EVENT, WaitForDebugEvent,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DEBUG_ONLY_THIS_PROCESS, INFINITE, PROCESS_INFORMATION, STARTUPINFOW,
    };

    const EXCEPTION_DEBUG_EVENT: u32 = 1;
    const EXIT_PROCESS_DEBUG_EVENT: u32 = 5;
    const DBG_CONTINUE: i32 = 0x0001_0002;
    const DBG_EXCEPTION_NOT_HANDLED: i32 = 0x8001_0001_u32 as i32;
    const EXCEPTION_BREAKPOINT: i32 = 0x8000_0003_u32 as i32;

    let mut line = format!("\"{kr}\"");
    for argument in arguments {
        line.push_str(&format!(" \"{argument}\""));
    }
    let mut line: Vec<u16> = line.encode_utf16().chain(Some(0)).collect();
    // SAFETY: both structures are plain data for which all zeroes is a valid start.
    let (mut startup, mut process): (STARTUPINFOW, PROCESS_INFORMATION) =
        unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
    startup.cb = u32::try_from(std::mem::size_of::<STARTUPINFOW>()).expect("a small size");
    // SAFETY: `line` is a writable, NUL-ended buffer, and the structures outlive the call.
    let started = unsafe {
        CreateProcessW(
            std::ptr::null(),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            DEBUG_ONLY_THIS_PROCESS,
            std::ptr::null(),
            std::ptr::null(),
            &raw const startup,
            &raw mut process,
        )
    };
    assert!(started != 0, "the observer starts kr as its debuggee");
    println!("{}{}", crate::KR_PID_SAID, process.dwProcessId);
    loop {
        // SAFETY: the structure is plain data that the call fills.
        let mut event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
        // SAFETY: the pointer is a live structure.
        if unsafe { WaitForDebugEvent(&raw mut event, INFINITE) } == 0 {
            return -1;
        }
        let code = event.dwDebugEventCode;
        let exit = if code == EXIT_PROCESS_DEBUG_EVENT {
            // SAFETY: the event says the exit record is the one that holds the value.
            Some(unsafe { event.u.ExitProcess.dwExitCode } as i32)
        } else {
            None
        };
        let status = if code == EXCEPTION_DEBUG_EVENT {
            // SAFETY: the event says the exception record is the one that holds the value.
            let exception = unsafe { event.u.Exception.ExceptionRecord.ExceptionCode };
            if exception == EXCEPTION_BREAKPOINT {
                DBG_CONTINUE
            } else {
                DBG_EXCEPTION_NOT_HANDLED
            }
        } else {
            DBG_CONTINUE
        };
        // SAFETY: the identifiers are those of the event just waited for.
        unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status) };
        if let Some(exit) = exit {
            return exit;
        }
    }
}

/* -------------------------------------------------------------------------- */
/* The console's window                                                        */
/* -------------------------------------------------------------------------- */

/// A pseudo-console with `command` attached to it, and the person's side of it.
pub struct Opened {
    pub terminal: portable_pty::PtyPair,
    pub shell: Box<dyn portable_pty::Child + Send + Sync>,
    pub typing: Arc<Mutex<Box<dyn Write + Send>>>,
    pub seen: Arc<Mutex<Vec<u8>>>,
}

/// Starts this test binary in a pseudo-console as the observer of `mode`, with `environment` and
/// nothing else of the person's environment, in `directory`.
pub fn open(mode: &str, environment: &[(String, String)], directory: &Path) -> Opened {
    let terminal = portable_pty::native_pty_system()
        .openpty(portable_pty::PtySize {
            rows: ROWS,
            cols: COLUMNS,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("opens a console");
    let mut command = portable_pty::CommandBuilder::new(
        std::env::current_exe().expect("this test binary has a path"),
    );
    command.args(["--exact", THE_TEST, "--nocapture", "--test-threads=1"]);
    command.env_clear();
    for (name, value) in environment {
        command.env(name, value);
    }
    command.env(MARKER, mode);
    command.cwd(directory);
    let typing: Arc<Mutex<Box<dyn Write + Send>>> =
        Arc::new(Mutex::new(terminal.master.take_writer().expect("a writer")));
    let shell = terminal
        .slave
        .spawn_command(command)
        .expect("starts the observer");
    let mut reader = terminal.master.try_clone_reader().expect("a reader");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let collected = Arc::clone(&seen);
    let answers = Arc::clone(&typing);
    std::thread::spawn(move || {
        // The pseudo-console asks where its cursor is when it starts, and serves nothing to the
        // program on it until it is told. A real terminal answers at once; this one gives the
        // fixed position that the console host needs.
        const QUERY: &[u8] = b"\x1b[6n";
        const REPLY: &[u8] = b"\x1b[1;1R";
        let mut answered = 0_usize;
        let mut buffer = [0_u8; 4096];
        while let Ok(read) = reader.read(&mut buffer) {
            if read == 0 {
                break;
            }
            let asked = {
                let mut seen = collected.lock().unwrap_or_else(PoisonError::into_inner);
                seen.extend_from_slice(&buffer[..read]);
                seen.windows(QUERY.len())
                    .filter(|window| *window == QUERY)
                    .count()
            };
            while answered < asked {
                let mut typing = answers.lock().unwrap_or_else(PoisonError::into_inner);
                let _ = typing.write_all(REPLY);
                let _ = typing.flush();
                answered += 1;
            }
        }
    });
    Opened {
        terminal,
        shell,
        typing,
        seen,
    }
}

/// A model of the screen that the bytes a pseudo-console sent draw: the characters at their places,
/// with the cursor moves, erasures and line ends applied, and every other sequence skipped. What
/// the console drew is then read as a person reads it, and a line that the console drew again is
/// not counted twice.
pub struct Screen {
    rows: Vec<Vec<char>>,
}

impl Screen {
    /// Draws `bytes` on a screen of [`COLUMNS`] columns.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let text = String::from_utf8_lossy(bytes);
        let mut screen = Self { rows: Vec::new() };
        let (mut row, mut column) = (0_usize, 0_usize);
        let mut chars = text.chars().peekable();
        while let Some(next) = chars.next() {
            match next {
                '\r' => column = 0,
                '\n' => row += 1,
                '\u{8}' => column = column.saturating_sub(1),
                '\u{1b}' => match chars.next() {
                    Some('[') => {
                        let mut parameters = String::new();
                        let mut last = ' ';
                        for byte in chars.by_ref() {
                            if ('\u{40}'..='\u{7e}').contains(&byte) {
                                last = byte;
                                break;
                            }
                            parameters.push(byte);
                        }
                        let numbers: Vec<usize> = parameters
                            .trim_start_matches('?')
                            .split(';')
                            .map(|part| part.parse().unwrap_or(0))
                            .collect();
                        let first = numbers.first().copied().unwrap_or(0);
                        let count = first.max(1);
                        match last {
                            'H' | 'f' => {
                                row = first.max(1) - 1;
                                column = numbers.get(1).copied().unwrap_or(0).max(1) - 1;
                            }
                            'A' => row = row.saturating_sub(count),
                            'B' => row += count,
                            'C' => column += count,
                            'D' => column = column.saturating_sub(count),
                            'G' => column = count - 1,
                            'd' => row = count - 1,
                            'K' => screen.erase_line(row, column, first),
                            'J' if first == 2 || first == 3 => screen.rows.clear(),
                            'J' => {
                                screen.erase_line(row, column, 0);
                                screen.rows.truncate(row + 1);
                            }
                            'X' => {
                                for offset in 0..count {
                                    screen.put(row, column + offset, ' ');
                                }
                            }
                            _ => {}
                        }
                    }
                    Some(']') => {
                        // A title or another operating-system command, ended by BEL or ESC \.
                        while let Some(byte) = chars.next() {
                            if byte == '\u{7}' {
                                break;
                            }
                            if byte == '\u{1b}' {
                                chars.next();
                                break;
                            }
                        }
                    }
                    Some('(' | ')') => {
                        chars.next();
                    }
                    _ => {}
                },
                printable if !printable.is_control() => {
                    screen.put(row, column, printable);
                    column += 1;
                    if column >= usize::from(COLUMNS) {
                        column = 0;
                        row += 1;
                    }
                }
                _ => {}
            }
        }
        screen
    }

    fn put(&mut self, row: usize, column: usize, character: char) {
        while self.rows.len() <= row {
            self.rows.push(Vec::new());
        }
        let line = &mut self.rows[row];
        while line.len() <= column {
            line.push(' ');
        }
        line[column] = character;
    }

    fn erase_line(&mut self, row: usize, column: usize, how: usize) {
        if let Some(line) = self.rows.get_mut(row) {
            match how {
                0 => line.truncate(column),
                1 => {
                    for cell in line.iter_mut().take(column + 1) {
                        *cell = ' ';
                    }
                }
                _ => line.clear(),
            }
        }
    }

    /// The lines of the screen as drawn: nothing is trimmed on the left, so a line that the
    /// console drew from the middle of a row shows as indented, and the ends are trimmed.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let mut lines: Vec<String> = self
            .rows
            .iter()
            .map(|line| line.iter().collect::<String>().trim_end().to_owned())
            .collect();
        while lines.last().is_some_and(String::is_empty) {
            lines.pop();
        }
        lines
    }

    /// The screen as text.
    #[must_use]
    pub fn text(&self) -> String {
        self.lines().join("\n")
    }
}

/* -------------------------------------------------------------------------- */
/* A second program of the same account                                        */
/* -------------------------------------------------------------------------- */

/// The system's answer to an open that the list refuses.
pub const ACCESS_DENIED: u32 = 5;

/// The rights an open asks for, as the system names them.
pub mod rights {
    /// `PROCESS_VM_READ`.
    pub const PROCESS_VM_READ: u32 = 0x0010;
    /// `PROCESS_DUP_HANDLE`.
    pub const PROCESS_DUP_HANDLE: u32 = 0x0040;
    /// `PROCESS_QUERY_LIMITED_INFORMATION`.
    pub const PROCESS_QUERY_LIMITED: u32 = 0x1000;
    /// `WRITE_DAC`.
    pub const WRITE_DAC: u32 = 0x0004_0000;
    /// `THREAD_TERMINATE`.
    pub const THREAD_TERMINATE: u32 = 0x0001;
    /// `THREAD_SUSPEND_RESUME`.
    pub const THREAD_SUSPEND_RESUME: u32 = 0x0002;
    /// `THREAD_GET_CONTEXT`.
    pub const THREAD_GET_CONTEXT: u32 = 0x0008;
    /// `THREAD_SET_CONTEXT`.
    pub const THREAD_SET_CONTEXT: u32 = 0x0010;
    /// `THREAD_QUERY_LIMITED_INFORMATION`.
    pub const THREAD_QUERY_LIMITED: u32 = 0x0800;
    /// `TOKEN_DUPLICATE`.
    pub const TOKEN_DUPLICATE: u32 = 0x0002;
    /// `TOKEN_QUERY`.
    pub const TOKEN_QUERY: u32 = 0x0008;
    /// `TOKEN_ADJUST_DEFAULT`.
    pub const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
}

fn owned(handle: windows_sys::Win32::Foundation::HANDLE) -> Result<OwnedHandle, u32> {
    if handle.is_null() {
        // SAFETY: the call reads the calling thread's last error.
        Err(unsafe { GetLastError() })
    } else {
        // SAFETY: the handle was just opened and nothing else owns it.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle.cast()) })
    }
}

/// Opens the process `pid` for `rights`, or says the system's error.
///
/// # Errors
///
/// The system's error code when the open is refused.
pub fn open_process(pid: u32, rights: u32) -> Result<OwnedHandle, u32> {
    // SAFETY: the call takes integers and returns a handle or null.
    owned(unsafe { OpenProcess(rights, 0, pid) })
}

/// Opens the thread `thread` for `rights`, or says the system's error.
///
/// # Errors
///
/// The system's error code when the open is refused.
pub fn open_thread(thread: u32, rights: u32) -> Result<OwnedHandle, u32> {
    // SAFETY: the call takes integers and returns a handle or null.
    owned(unsafe { OpenThread(rights, 0, thread) })
}

/// Opens the token of the process `process` for `rights`, or says the system's error.
///
/// # Errors
///
/// The system's error code when the open is refused.
pub fn open_token(process: &OwnedHandle, rights: u32) -> Result<OwnedHandle, u32> {
    let mut token = std::ptr::null_mut();
    // SAFETY: the process handle is open and the pointer is a live handle slot.
    let opened =
        unsafe { OpenProcessToken(process.as_raw_handle().cast(), rights, &raw mut token) };
    if opened == 0 {
        // SAFETY: the call reads the calling thread's last error.
        Err(unsafe { GetLastError() })
    } else {
        owned(token)
    }
}

/// A thread of a process, with when it was made.
#[derive(Clone, Copy, Debug)]
pub struct Thread {
    /// The thread's identifier.
    pub id: u32,
    /// When the thread was made, as a file time, or zero when the open that reads it was refused.
    pub created: u64,
}

/// The threads of the process `pid` now, each with its creation time. The case fails when the
/// snapshot cannot be taken or the enumeration ends for any reason but the system's end of the
/// entries: a snapshot that was cut short would let a case read a thread as gone that is live.
///
/// # Panics
///
/// When the system refuses the snapshot, or an enumeration call fails with an error other than
/// `ERROR_NO_MORE_FILES`.
#[must_use]
pub fn threads_of(pid: u32) -> Vec<Thread> {
    // SAFETY: the call takes integers and returns a handle.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    // The call says `INVALID_HANDLE_VALUE`, not null, when it fails.
    if snapshot.is_null() || snapshot == INVALID_HANDLE_VALUE {
        // SAFETY: the call reads the calling thread's last error.
        let code = unsafe { GetLastError() };
        panic!("the thread snapshot is taken, and the system said {code}");
    }
    // SAFETY: the snapshot was just opened and nothing else owns it.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot.cast()) };
    // SAFETY: the structure is plain data that the calls fill.
    let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = u32::try_from(std::mem::size_of::<THREADENTRY32>()).expect("a small size");
    let mut threads = Vec::new();
    // SAFETY: the snapshot is open and the pointer is a live structure.
    let mut found = unsafe { Thread32First(snapshot.as_raw_handle().cast(), &raw mut entry) } != 0;
    loop {
        if !found {
            // SAFETY: the call reads the calling thread's last error, which the failed call set.
            let code = unsafe { GetLastError() };
            assert_eq!(
                code, ERROR_NO_MORE_FILES,
                "the enumeration of the threads ends only at the system's end of the entries, and \
                 the system said {code}"
            );
            return threads;
        }
        if entry.th32OwnerProcessID == pid {
            let created = open_thread(entry.th32ThreadID, rights::THREAD_QUERY_LIMITED)
                .map_or(0, |thread| creation_time(&thread));
            threads.push(Thread {
                id: entry.th32ThreadID,
                created,
            });
        }
        // SAFETY: as above.
        found = unsafe { Thread32Next(snapshot.as_raw_handle().cast(), &raw mut entry) } != 0;
    }
}

fn creation_time(thread: &OwnedHandle) -> u64 {
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: the thread handle is open and the pointers are live structures.
    let read = unsafe {
        GetThreadTimes(
            thread.as_raw_handle().cast(),
            &raw mut created,
            &raw mut exited,
            &raw mut kernel,
            &raw mut user,
        )
    };
    if read == 0 {
        0
    } else {
        (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime)
    }
}

/// The time now as a file time, which counts hundred-nanosecond steps from 1601.
#[must_use]
pub fn now() -> u64 {
    const FROM_1601_TO_1970: u64 = 116_444_736_000_000_000;
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970");
    FROM_1601_TO_1970 + u64::try_from(since.as_nanos() / 100).expect("a time that fits")
}

/// Removes the debug privilege from this program's own token and says what it found: an elevated
/// program that holds it passes every list, so the opens of the cases would prove nothing.
#[must_use]
pub fn drop_the_debug_privilege() -> String {
    const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
    const SE_PRIVILEGE_REMOVED: u32 = 0x0000_0004;
    const TOKEN_ELEVATION_CLASS: i32 = 20;

    let mut token = std::ptr::null_mut();
    // SAFETY: the pseudo-handle for this process needs no close and the pointer is a live slot.
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | rights::TOKEN_QUERY,
            &raw mut token,
        )
    };
    assert!(opened != 0, "the case opens its own token");
    let token = owned(token).expect("the token handle");
    let mut elevation = 0_u32;
    let mut returned = 0_u32;
    // SAFETY: the buffer is a live `u32` of the size the call is told.
    let read = unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            TOKEN_ELEVATION_CLASS,
            (&raw mut elevation).cast(),
            4,
            &raw mut returned,
        )
    };
    assert!(read != 0, "the case reads its token's elevation");
    let name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    // SAFETY: the name is NUL-ended and the pointer is a live structure.
    let found = unsafe { LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &raw mut luid) };
    assert!(found != 0, "the system knows the debug privilege");
    let removal = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_REMOVED,
        }],
    };
    // SAFETY: the token is open for the change and the structure is live.
    let changed = unsafe {
        AdjustTokenPrivileges(
            token.as_raw_handle().cast(),
            0,
            &raw const removal,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert!(
        changed != 0,
        "this case could not make its condition: the call that removes the debug privilege failed"
    );
    // The call also succeeds for a token that never held the privilege, and for one whose removal
    // did not take: the privileges the token holds now are read, and the debug privilege must not
    // be among them. A token that never held it passes.
    let held = privileges_of(&token);
    assert!(
        !held.contains(&(luid.LowPart, luid.HighPart)),
        "this case could not make its condition: the token still holds the debug privilege, so \
         every open of a case would be granted whatever the lists say"
    );
    format!(
        "the case's token is {}elevated; it holds no debug privilege",
        if elevation == 0 { "not " } else { "" },
    )
}

/// The privileges a token holds, each as the low and high part of its identifier.
fn privileges_of(token: &OwnedHandle) -> Vec<(u32, i32)> {
    const TOKEN_PRIVILEGES_CLASS: i32 = 3;
    let mut length = 0_u32;
    // SAFETY: the call is asked only how much room it needs; the handle is open.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            TOKEN_PRIVILEGES_CLASS,
            std::ptr::null_mut(),
            0,
            &raw mut length,
        )
    };
    let mut buffer = vec![
        0_u32;
        usize::try_from(length)
            .expect("a small size")
            .div_ceil(4)
            .max(1)
    ];
    // SAFETY: the buffer has at least the room the system asked for.
    let read = unsafe {
        GetTokenInformation(
            token.as_raw_handle().cast(),
            TOKEN_PRIVILEGES_CLASS,
            buffer.as_mut_ptr().cast(),
            length,
            &raw mut length,
        )
    };
    assert!(read != 0, "the case reads the privileges of its token");
    // The count, then for each privilege its low part, its high part and its attributes.
    let count = usize::try_from(buffer[0]).expect("a small count");
    (0..count)
        .map(|at| {
            let entry = &buffer[1 + at * 3..4 + at * 3];
            (entry[0], i32::from_ne_bytes(entry[1].to_ne_bytes()))
        })
        .collect()
}
