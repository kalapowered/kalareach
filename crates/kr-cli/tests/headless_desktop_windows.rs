//! Where a session's worker and its programs draw on Windows, against a real daemon and a real
//! worker.
//!
//! KR-REQ-03.24: a `headless_user` session has no inherited GUI access. Its worker is started on a
//! window station and desktop of its own, so neither it nor a program it starts inherits the
//! interactive desktop of the person signed in, while a `desktop_bound` session is on that desktop.
//! The same probe runs in each session's shell, which is a console program in a pseudo-console, so
//! that the shell answering at all shows that such a program still runs on a desktop of its own.
//!
//! This is not a boundary against a process of the same account, which can still open the
//! interactive desktop by name; nothing here claims that it is.
//!
//! This needs a signed-in interactive session. A session the Task Scheduler starts for a task with
//! no signed-in user has no interactive desktop, so the control below fails there rather than
//! passing without having shown anything.

#![cfg(windows)]

mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;
mod windows_session;

use windows_session::{WorkerHost, WorkerTerminal};

/// How long a session's shell keeps its window up, which is long enough for this test to look for
/// it and for the session to be closed afterwards.
const WINDOW_MILLISECONDS: u32 = 60_000;

/// The probe's C# source: which station and desktop the process is on, what it can open, and a
/// window it can make and look for.
///
/// `Run` reports the process's own station and desktop, whether the interactive window station
/// and its `Default` desktop open, and whether the input desktop opens from where the process is.
/// It switches nothing, so what it reports is where the process was started. `Show` makes a
/// visible window with the title it is given, says so, and keeps it for a while; `Seen` says
/// whether a window with that title is on the desktop of the process that asks. The strings it
/// prints hold the pieces of the marker apart, so what a terminal waits for is the output and not
/// the echo of what was typed.
const CLASS: &str = r#"using System; using System.Runtime.InteropServices; using System.Text; public static class KrProbe { [DllImport("user32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern IntPtr OpenWindowStationW(string n,bool i,uint a); [DllImport("user32.dll")] static extern IntPtr GetProcessWindowStation(); [DllImport("user32.dll")] static extern IntPtr GetThreadDesktop(int t); [DllImport("kernel32.dll")] static extern int GetCurrentThreadId(); [DllImport("user32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool GetUserObjectInformationW(IntPtr h,int i,StringBuilder b,int l,out int n); [DllImport("user32.dll",SetLastError=true)] static extern IntPtr OpenInputDesktop(uint f,bool i,uint a); [DllImport("user32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern IntPtr OpenDesktopW(string n,uint f,bool i,uint a); [DllImport("user32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern IntPtr CreateWindowExW(uint e,string c,string t,uint s,int x,int y,int w,int h,IntPtr p,IntPtr m,IntPtr i,IntPtr a); [DllImport("user32.dll")] static extern bool DestroyWindow(IntPtr h); [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern IntPtr FindWindowW(string c,string n); static string Name(IntPtr h){ var b=new StringBuilder(256); int n; GetUserObjectInformationW(h,2,b,512,out n); return b.ToString(); } static string R(IntPtr h){ return h==IntPtr.Zero ? "refused-"+Marshal.GetLastWin32Error() : "opened"; } public static string Run(){ var s=Name(GetProcessWindowStation()); var d=Name(GetThreadDesktop(GetCurrentThreadId())); var wr=R(OpenWindowStationW("WinSta0",false,0x02000000)); var dr=R(OpenDesktopW("Default",0,false,0x02000000)); var ir=R(OpenInputDesktop(0,false,0x02000000)); return "station="+s+" desktop="+d+" winsta0="+wr+" default="+dr+" input="+ir; } public static void Show(string t,int ms){ var h=CreateWindowExW(0,"STATIC",t,0x90000000,0,0,100,100,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero); Console.WriteLine("kr-"+"shown "+(h==IntPtr.Zero ? "failed-"+Marshal.GetLastWin32Error() : "ok")+" kr-"+"end."); System.Threading.Thread.Sleep(ms); if(h!=IntPtr.Zero) DestroyWindow(h); } public static bool Seen(string t){ return FindWindowW(null,t)!=IntPtr.Zero; } }"#;

/// PowerShell source that defines the probe's class.
fn load() -> String {
    format!("Add-Type -TypeDefinition '{CLASS}'")
}

/// What a probe found.
#[derive(Debug)]
struct Found {
    station: String,
    desktop: String,
    winsta0: String,
    default: String,
    input: String,
}

impl Found {
    /// Reads the probe's line out of what a terminal showed.
    fn of(text: &str) -> Self {
        let start = text
            .rfind("kr-probe ")
            .unwrap_or_else(|| panic!("the probe printed nothing: {text}"));
        let line = &text[start + "kr-probe ".len()..];
        let line = &line[..line
            .find(" kr-end.")
            .unwrap_or_else(|| panic!("the probe's line has no end: {line}"))];
        let field = |name: &str| {
            let key = format!("{name}=");
            let from = line
                .find(&key)
                .unwrap_or_else(|| panic!("the probe's line has no {name}: {line}"))
                + key.len();
            line[from..]
                .split(' ')
                .next()
                .unwrap_or_default()
                .to_owned()
        };
        Self {
            station: field("station"),
            desktop: field("desktop"),
            winsta0: field("winsta0"),
            default: field("default"),
            input: field("input"),
        }
    }

    /// Whether this process is on the interactive window station and desktop.
    fn on_the_interactive_desktop(&self) -> bool {
        self.station.eq_ignore_ascii_case("WinSta0") && self.desktop.eq_ignore_ascii_case("Default")
    }
}

/// A title no other window has.
fn title(kind: &str) -> String {
    format!("kr-window-{kind}-{}", kr_ipc::new_uuid())
}

/// Runs the probe in the shell of the session `created` made, makes a window there titled `title`,
/// and returns what the probe found with the terminal that is still holding the window up.
///
/// The window is made only after the probe has reported, and the shell says when it has, so a
/// caller that looks for the window afterwards looks for one that exists.
async fn probe_in_session(
    host: &WorkerHost,
    created: &windows_session::Created,
    title: &str,
) -> (Found, WorkerTerminal) {
    assert!(
        created.succeeded(),
        "the session was not created: {}",
        created.said()
    );
    let (session_id, dimensions) = created.session();
    let environment = host.tree.environment();
    let mut typist = WorkerTerminal::attach(&environment, session_id, dimensions).await;
    typist
        .type_line(&format!(
            "{}; Write-Host ('kr-'+'probe '+[KrProbe]::Run()+' kr-'+'end.'); \
             [KrProbe]::Show('{title}',{WINDOW_MILLISECONDS})",
            load()
        ))
        .await;
    let text = typist
        .shown("kr-shown ok kr-end.", "the session's shell made its window")
        .await;
    (Found::of(&text), typist)
}

/// Runs `command` in a PowerShell of this test's own, in the desktop this test has, and returns
/// what it printed.
fn here(command: &str) -> String {
    let shell = kr_worker::default_shell::platform_default();
    let output = std::process::Command::new(&shell)
        .args(["-NoProfile", "-NonInteractive", "-Command", command])
        .output()
        .unwrap_or_else(|error| panic!("{shell} could not be run: {error}"));
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "{command} failed in {shell}: {text} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    text
}

/// The probe run directly by this test, in the desktop this test has.
fn probe_here() -> Found {
    Found::of(&here(&format!(
        "{}; Write-Host ('kr-'+'probe '+[KrProbe]::Run()+' kr-'+'end.')",
        load()
    )))
}

/// Whether a window titled `title` is on the desktop this test has.
fn window_here(title: &str) -> bool {
    here(&format!(
        "{}; Write-Host ('kr-'+'seen '+[KrProbe]::Seen('{title}'))",
        load()
    ))
    .contains("kr-seen True")
}

/// KR-REQ-03.24: a headless session's shell is on a station and desktop of its own, away from the
/// interactive ones, draws nothing on them, and still runs; a desktop-bound session's shell is on
/// the interactive desktop and its window is there.
///
/// The control is this test's own probe: if it is not on the interactive desktop, the machine this
/// runs on has no signed-in session and nothing here would show anything. The desktop-bound
/// session's window is the control for the headless session's: the same call, on the interactive
/// desktop, is seen from here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_headless_session_is_not_on_the_interactive_desktop_and_a_desktop_bound_one_is() {
    let control = probe_here();
    assert!(
        control.on_the_interactive_desktop(),
        "this case needs a signed-in interactive session, and this test runs on {control:?}"
    );
    assert_eq!(
        (control.winsta0.as_str(), control.default.as_str()),
        ("opened", "opened"),
        "the control opens the interactive station and desktop: {control:?}"
    );

    let host = WorkerHost::start().await;

    let headless_title = title("headless");
    let created = host.kr_new(&["--shell-mode", "native_compat"]).await;
    let (headless, _holding) = probe_in_session(&host, &created, &headless_title).await;
    assert!(
        !headless.station.eq_ignore_ascii_case("WinSta0"),
        "a headless session's shell is on the interactive window station: {headless:?}"
    );
    assert!(
        headless.desktop.starts_with("kr-worker-"),
        "a headless session's shell is on the desktop made for its worker: {headless:?}"
    );
    assert!(
        headless.input.starts_with("refused-"),
        "the input desktop is not open to a headless session's shell: {headless:?}"
    );
    assert!(
        !window_here(&headless_title),
        "a window a headless session's shell made is on the interactive desktop"
    );

    let cwd = host.tree.root().display().to_string();
    let output = host
        .kr(
            &[
                "--json",
                "new",
                "--invisible",
                "--desktop",
                "--cwd",
                &cwd,
                "--shell-mode",
                "native_compat",
            ],
            &[],
        )
        .await;
    let created = windows_session::Created {
        document: serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Null),
        output,
    };
    let bound_title = title("bound");
    let (bound, _holding_too) = probe_in_session(&host, &created, &bound_title).await;
    assert!(
        bound.on_the_interactive_desktop(),
        "a desktop-bound session's shell is not on the interactive desktop: {bound:?}"
    );
    assert_eq!(
        (bound.winsta0.as_str(), bound.default.as_str()),
        ("opened", "opened"),
        "a desktop-bound session's shell reaches the interactive desktop: {bound:?}"
    );
    assert!(
        window_here(&bound_title),
        "a window a desktop-bound session's shell made is not on the interactive desktop, so the \
         look for the headless session's window could not have found one"
    );
}
