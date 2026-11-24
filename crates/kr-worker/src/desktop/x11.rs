//! The screen image on X11: the tools that take one, what each is asked, and what proves what it
//! wrote.
//!
//! An X11 client that holds the display and its authority needs no further permission, so what a
//! check can establish here is whether the display opens, whether a tool writes a whole image of it
//! and what the display said when it did not. Every tool takes the whole X screen, every monitor on
//! it, and writes one file into the check's own directory under a name whose suffix names the
//! format: `maim` and `scrot` refuse a suffix they do not know, and `import` writes PostScript for
//! one. Nothing the tool prints decides success. Only a file that holds a whole image does.
//!
//! A tool fails the same way whether the display refused its authority or could not be reached, so
//! two independent facts tell them apart: whether this worker can connect to the display's socket
//! itself, and whether the tool's error output holds the line the client library prints when the
//! server refuses the connection.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kr_protocol::desktop::{DesktopContext, DisplayServer};
use kr_protocol::hostinfo::export::Sentence;

use super::capability::installed_in;
use super::payload::{self, Fault};
use super::probe::{
    Check, Deadline, Exit, Outcome, Plan, Ran, Setting, bounded_with, on_a_thread,
};
use super::routes::{Asking, Operation, Program, Route, Variables};

/// The programs a screen image is taken with on X11, in the order they are looked for.
const PROGRAM_NAMES: [&str; 4] = ["maim", "import", "scrot", "xwd"];

/// [`PROGRAM_NAMES`], as the list the platform's own record looks for a tool in, so that the record
/// and the check can never name different programs.
pub(super) const PROGRAMS: &[&str] = &PROGRAM_NAMES;

/// The folder the X server's own sockets are in.
const SOCKETS: &str = "/tmp/.X11-unix";

/// How long the worker waits for a display's socket to accept a connection: it is a local socket,
/// so a second is far more than an answer takes.
const CONNECT_BOUND: Duration = Duration::from_secs(1);

/// What a tool writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Image {
    /// A PNG file.
    Png,
    /// An X window dump.
    Xwd,
}

/// The image [`xwd`] accepts, as the phrase [`Fault::left_no_usable_image`] puts into its endings.
const XWD_IMAGE: &str = "an XWD image";

impl Image {
    /// The image the format is, as a phrase that reads after "a file that is not ".
    const fn phrase(self) -> &'static str {
        match self {
            Self::Png => payload::PNG_IMAGE,
            Self::Xwd => XWD_IMAGE,
        }
    }
}

/// One row: a tool, how it is asked and what it writes.
struct Tool {
    route: Route,
    program: &'static str,
    /// What comes before the output file in the argument vector, which ends with the file.
    before: &'static [&'static str],
    /// The output file's name in the check's own directory. Its suffix names the format.
    file: &'static str,
    image: Image,
}

impl Tool {
    /// The argument vector that makes this tool write its image to `output`.
    fn vector(&self, output: &Path) -> Vec<String> {
        self.before
            .iter()
            .map(|argument| (*argument).to_owned())
            .chain([output.to_string_lossy().into_owned()])
            .collect()
    }
}

/// The X11 rows. The quiet argument is the one that keeps the display's bell from ringing.
const TOOLS: [Tool; 4] = [
    Tool {
        route: Route {
            name: "x11-maim",
            asking: Asking::Never,
        },
        program: PROGRAM_NAMES[0],
        before: &[],
        file: "capture.png",
        image: Image::Png,
    },
    Tool {
        route: Route {
            name: "x11-import",
            asking: Asking::Never,
        },
        program: PROGRAM_NAMES[1],
        before: &["-silent", "-window", "root"],
        file: "capture.png",
        image: Image::Png,
    },
    Tool {
        route: Route {
            name: "x11-scrot",
            asking: Asking::Never,
        },
        program: PROGRAM_NAMES[2],
        before: &[],
        file: "capture.png",
        image: Image::Png,
    },
    Tool {
        route: Route {
            name: "x11-xwd",
            asking: Asking::Never,
        },
        program: PROGRAM_NAMES[3],
        before: &["-root", "-silent", "-out"],
        file: "capture.xwd",
        image: Image::Xwd,
    },
];

/// The route of a screen image on X11 when no row's tool is installed.
const NO_TOOL: Route = Route {
    name: "x11-screen-image",
    asking: Asking::Never,
};

/// Resolves the screen image on an X11 desktop to the first tool of the table that is installed.
///
/// Rows are chosen by the display server the context names and never by a `DISPLAY` being set: an
/// X11 tool in a Wayland session reaches XWayland, which shows only X11 windows.
pub(super) fn resolve(
    check: Check,
    desktop: &DesktopContext,
    search: Option<&OsStr>,
) -> Option<Operation> {
    if check != Check::ScreenImage || desktop.display_server != DisplayServer::X11 {
        return None;
    }
    let found = TOOLS.iter().find_map(|tool| {
        installed_in(tool.program, search).map(|path| (tool.route, Program::Tool(path)))
    });
    let (route, program) = found.unwrap_or((NO_TOOL, Program::Absent(None)));
    Some(Operation {
        check,
        route,
        program,
        target: None,
    })
}

/// Whether the operation is one of this table's.
pub(super) fn performs(operation: &Operation) -> bool {
    operation.route == NO_TOOL || TOOLS.iter().any(|tool| tool.route == operation.route)
}

/// Performs the screen image on the display the worker holds.
pub(super) fn perform(plan: &Plan, setting: &Setting<'_>, operation: &Operation) -> Ran {
    perform_in(plan, setting, operation, Path::new(SOCKETS))
}

/// [`perform`], with the folder the display's sockets are looked for in given.
fn perform_in(plan: &Plan, setting: &Setting<'_>, operation: &Operation, sockets: &Path) -> Ran {
    let check = Check::ScreenImage;
    let (Some(tool), Program::Tool(program)) = (
        TOOLS.iter().find(|tool| tool.route == operation.route),
        &operation.program,
    ) else {
        // No row's tool is installed: the record names none, and the platform's own words stand.
        return Ran {
            check,
            facility: operation.program.named_path().map(str::to_owned),
            outcome: Outcome::FacilityMissing,
            left: None,
        };
    };
    let Some(display) = setting
        .variables
        .display
        .as_deref()
        .filter(|display| !display.trim().is_empty())
    else {
        return not_started(
            program,
            "this worker holds no X11 display, so no tool was started",
        );
    };
    let number = match named(display) {
        Named::Here(number) => number,
        Named::Network => return not_started(program, NETWORK_DISPLAY),
        Named::Nowhere => return not_started(program, NO_SUCH_DISPLAY),
    };
    let image = plan.scratch.join(tool.file);
    // A file from before is not this run's image.
    let _ = payload::remove_image(&image);
    let vector = tool.vector(&image);
    let arguments: Vec<&str> = vector.iter().map(String::as_str).collect();
    let ran = bounded_with(
        check,
        program,
        &arguments,
        &environment_of(setting.variables, display),
        plan,
        setting.deadline,
    );
    // What the tool and the file it left came to. A whole image waits for the removal, because
    // "kept none of it" is true only once the file is gone.
    let measured: Result<usize, Outcome> = match ran.exit {
        Exit::Succeeded(_) => match payload::read_image(&image, setting.deadline) {
            // The image could not be read before the check's time ran out.
            None => Err(Outcome::TimedOut),
            Some(read) => read
                .and_then(|bytes| validate(tool.image, &bytes).map(|()| bytes.len()))
                .map_err(|fault| Outcome::NotAttempted {
                    detail: fault.left_no_usable_image(tool.image.phrase()),
                }),
        },
        // A check with no time left to try the socket in does not guess at why the tool failed.
        Exit::Failed(_) => Err(
            reach(number, sockets, setting.deadline).map_or(Outcome::TimedOut, |reach| {
                outcome_of(told_by(
                    ran.error_output.as_deref().unwrap_or_default(),
                    reach,
                ))
            }),
        ),
        Exit::Unfinished(outcome) => Err(outcome),
    };
    // Removed whatever happened: an image outliving the check is the one thing this must not leave
    // behind, and a removal that failed is said with the answer rather than passed over.
    let left = payload::remove_image(&image);
    let outcome = measured.map_or_else(
        |other| other,
        |length| Outcome::Performed {
            detail: Sentence::new()
                .stated("it read a ")
                .number(u64::try_from(length).unwrap_or(u64::MAX))
                .stated("-byte image of the whole X screen, every monitor on it, into memory")
                .stated(if left.is_none() {
                    " and kept none of it"
                } else {
                    ""
                }),
        },
    );
    Ran {
        check,
        facility: ran.facility,
        outcome,
        left,
    }
}

/// The words of a display that this check does not try, as it answers before any tool starts.
const NETWORK_DISPLAY: &str =
    "the display is reached over the network, which this check does not test, so no tool was started";

/// The words of a display name that names no display on this machine.
const NO_SUCH_DISPLAY: &str = "the X11 display name this worker holds names no display on this \
                               machine, so no tool was started";

/// An answer that no tool was started, in these words.
fn not_started(program: &str, words: &'static str) -> Ran {
    Ran {
        check: Check::ScreenImage,
        facility: Some(program.to_owned()),
        outcome: Outcome::NotAttempted {
            detail: Sentence::new().stated(words),
        },
        left: None,
    }
}

/// What a display name names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Named {
    /// A display on this machine, by its number: `:0`, `:0.0` and `unix:0` name display 0.
    Here(u32),
    /// A display on another machine: a host comes before the colon.
    Network,
    /// Nothing on this machine: there is no display number in it, or no display name at all.
    Nowhere,
}

/// What the display name names. The worker's own socket is tried only for a display on this
/// machine, and no tool is started for any other.
fn named(display: &str) -> Named {
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    if let Some(rest) = display
        .strip_prefix(':')
        .or_else(|| display.strip_prefix("unix:"))
    {
        let (number, screen) = rest
            .split_once('.')
            .map_or((rest, None), |(number, screen)| (number, Some(screen)));
        if digits(number) && screen.is_none_or(digits) {
            if let Ok(number) = number.parse() {
                return Named::Here(number);
            }
        }
        return Named::Nowhere;
    }
    match display.split_once(':') {
        Some((host, _)) if !host.trim().is_empty() => Named::Network,
        _ => Named::Nowhere,
    }
}

/// The child's environment: the display and the authority this worker holds, and no Wayland socket.
///
/// The rest is the worker's own, so that a tool finds its home folder and its search path. A
/// worker that holds no authority gives the child none, so that the child does not read the one of
/// whichever process started this one. A variable with no value is removed from what the child
/// inherits.
fn environment_of<'a>(
    variables: &'a Variables,
    display: &'a str,
) -> [(&'static str, Option<&'a str>); 3] {
    [
        ("DISPLAY", Some(display)),
        ("WAYLAND_DISPLAY", None),
        ("XAUTHORITY", variables.authority.as_deref()),
    ]
}

/// What the worker could tell of the display itself, apart from what the tool said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reach {
    /// The display's socket accepted a connection from this worker.
    Connects,
    /// The display's socket did not.
    Silent,
}

/// What a failed tool and the display's socket say together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Told {
    /// The display accepted the connection and refused the authority this worker holds.
    AuthorityRefused,
    /// The display accepted a connection and the tool failed without the refusal line.
    Accepted,
    /// The display cannot be reached.
    Unreachable,
}

/// The lines the client library prints when the server refuses a connection, as recorded from four
/// tools with an empty authority file and a wrong key. A tool's own sentence is never matched: the
/// ImageMagick one carries its program name.
const REFUSALS: [&str; 2] = ["Authorization required", "Invalid MIT-MAGIC-COOKIE-1 key"];

/// Whether the error output holds a line that says the server refused the connection.
fn refusal_line(error_output: &str) -> bool {
    error_output.lines().any(|line| {
        REFUSALS
            .iter()
            .any(|phrase| line.trim_start().starts_with(phrase))
    })
}

/// What the two facts tell: a refusal needs the display to accept the connection and the refusal
/// line to be there.
fn told_by(error_output: &str, reach: Reach) -> Told {
    match reach {
        Reach::Connects if refusal_line(error_output) => Told::AuthorityRefused,
        Reach::Connects => Told::Accepted,
        Reach::Silent => Told::Unreachable,
    }
}

/// The outcome a failed tool comes to. None of them is a permission a person grants.
fn outcome_of(told: Told) -> Outcome {
    let detail = match told {
        Told::AuthorityRefused => Sentence::new().stated(
            "the display refused the authority this worker holds. A worker holds the authority \
             its login had when it started; a new session may hold the current one",
        ),
        Told::Accepted => Sentence::new()
            .stated("the display accepted a connection and the tool could not open it"),
        Told::Unreachable => Sentence::new().stated("the display cannot be reached"),
    };
    Outcome::NotAttempted { detail }
}

/// Whether this worker can connect to the display's socket, as `number` names it.
///
/// `None` is the deadline having no time left to try in, which says nothing about the display.
fn reach(number: u32, sockets: &Path, deadline: &Deadline) -> Option<Reach> {
    if deadline.expired() {
        return None;
    }
    Some(if connects(&sockets.join(format!("X{number}")), deadline) {
        Reach::Connects
    } else {
        Reach::Silent
    })
}

/// Whether a connection to the socket is accepted: the file system name first, then the abstract
/// name an X server on Linux listens on as well.
fn connects(path: &Path, deadline: &Deadline) -> bool {
    let bound = |deadline: &Deadline| deadline.left().min(CONNECT_BOUND);
    on_a_thread(path, bound(deadline), connect_to_file).is_some_and(|result| result.is_ok())
        || on_a_thread(path, bound(deadline), connect_to_abstract)
            .is_some_and(|result| result.is_ok())
}

#[cfg(unix)]
fn connect_to_file(path: PathBuf) -> std::io::Result<()> {
    std::os::unix::net::UnixStream::connect(path).map(drop)
}

#[cfg(not(unix))]
fn connect_to_file(_path: PathBuf) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

/// The abstract name is the file system name with no file behind it.
#[cfg(target_os = "linux")]
fn connect_to_abstract(path: PathBuf) -> std::io::Result<()> {
    use std::os::linux::net::SocketAddrExt as _;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::net::{SocketAddr, UnixStream};

    let address = SocketAddr::from_abstract_name(path.as_os_str().as_bytes())?;
    UnixStream::connect_addr(&address).map(drop)
}

#[cfg(not(target_os = "linux"))]
fn connect_to_abstract(_path: PathBuf) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

/// Whether the bytes are a whole image of the format.
///
/// A header alone, or a payload cut short, establishes nothing. Any bit depth and colour type is
/// accepted, and there is no size floor: a blank screen gives a file of a few hundred bytes.
pub(super) fn validate(image: Image, bytes: &[u8]) -> Result<(), Fault> {
    match image {
        Image::Png => payload::png(bytes).map(drop),
        Image::Xwd => xwd(bytes),
    }
}

/// An XWD: a header of at least 100 bytes at version 7 with a width and a height, and a file that
/// holds the header, the colour map it names and every row of pixels. Every field is big-endian.
fn xwd(bytes: &[u8]) -> Result<(), Fault> {
    const FIXED: usize = 100;
    let field = |offset: usize| -> Option<u64> {
        let word = bytes.get(offset..offset + 4)?;
        Some(u64::from(u32::from_be_bytes([
            word[0], word[1], word[2], word[3],
        ])))
    };
    if bytes.is_empty() {
        return Err(Fault::Empty);
    }
    if bytes.len() < FIXED {
        return Err(Fault::CutShort);
    }
    let (Some(header), Some(version)) = (field(0), field(4)) else {
        return Err(Fault::CutShort);
    };
    if header < FIXED as u64 || version != 7 {
        return Err(Fault::NotThisFormat);
    }
    let (Some(width), Some(height), Some(row), Some(colours)) =
        (field(16), field(20), field(48), field(76))
    else {
        return Err(Fault::CutShort);
    };
    if width == 0 || height == 0 {
        return Err(Fault::NoPixels);
    }
    // A colour map entry is 12 bytes. The sums cannot overflow: every term is below 2^32.
    let needed = header + colours * 12 + row * height;
    if (bytes.len() as u64) < needed {
        return Err(Fault::CutShort);
    }
    Ok(())
}

// The cases run stand-in programs and sockets of a unix system, which is every system that has an
// X server.
#[cfg(all(test, unix))]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    use kr_protocol::desktop::{
        CapabilityEvidenceSource, CapabilityState, ContainerEnvironment, DesktopAvailability,
        DesktopGenerationSource, DesktopSessionKind,
    };
    use kr_protocol::identity::{BootIdentity, BootIdentitySource, WorkerProfile};
    use kr_protocol::ids::DesktopSessionId;
    use kr_protocol::scalars::{Bytes, Nullable, U64};

    use super::super::probe::{self, HostOs, judge};
    use super::*;

    /// A context on a display server, in a login that is available and has graphic access.
    fn context(display_server: DisplayServer, graphic_access: bool) -> DesktopContext {
        DesktopContext {
            desktop_session_id: Nullable::some(
                DesktopSessionId::new(
                    "linux_logind:user=someone:uid=1000:session=1952:generation=2:boot=abcd",
                )
                .expect("a desktop name"),
            ),
            kind: DesktopSessionKind::LinuxLogind,
            platform_session: Nullable::some("1952".to_owned()),
            login_generation: Nullable::some(U64::new(2)),
            generation_source: DesktopGenerationSource::LinuxSessionLeader,
            os_user: "someone".to_owned(),
            uid: Nullable::some(U64::new(1000)),
            boot_identity: BootIdentity {
                source: BootIdentitySource::LinuxBootId,
                value: Bytes::new(vec![0xab, 0xcd]),
            },
            graphic_access,
            remote: false,
            availability: DesktopAvailability::Available,
            container: ContainerEnvironment::Host,
            display_server,
            compositor: Nullable::null(),
            worker_profile: WorkerProfile::DesktopBound,
        }
    }

    /// A folder of this test's own that is removed with it.
    fn folder() -> tempfile::TempDir {
        tempfile::tempdir().expect("a folder of this test's own")
    }

    /// An executable file of this test's own.
    fn program(folder: &Path, name: &str, script: &str) -> PathBuf {
        let path = folder.join(name);
        let mut file = std::fs::File::create(&path).expect("a program");
        file.write_all(script.as_bytes()).expect("its text");
        file.sync_all().expect("its text on disk");
        drop(file);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("its mode");
        path
    }

    /// The bytes of a PNG whose chunks are as given, each with a check value this reader ignores.
    fn chunks(parts: &[(&[u8; 4], Vec<u8>)]) -> Vec<u8> {
        let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        for (kind, data) in parts {
            bytes.extend(u32::try_from(data.len()).expect("a length").to_be_bytes());
            bytes.extend(kind.iter());
            bytes.extend(data);
            bytes.extend([0, 0, 0, 0]);
        }
        bytes
    }

    fn header(width: u32, height: u32, depth: u8, colour: u8) -> Vec<u8> {
        let mut data = width.to_be_bytes().to_vec();
        data.extend(height.to_be_bytes());
        data.extend([depth, colour, 0, 0, 0]);
        data
    }

    /// A PNG of the shape a tool wrote: the header, one chunk of data of the given length, the end.
    fn png_of(width: u32, height: u32, depth: u8, colour: u8, data: usize) -> Vec<u8> {
        chunks(&[
            (b"IHDR", header(width, height, depth, colour)),
            (b"IDAT", vec![7; data]),
            (b"IEND", Vec::new()),
        ])
    }

    /// An XWD as `xwd -root` wrote it on a 24-bit screen: a header of 107 bytes that names the
    /// window, a colour map of 256 entries and rows of 5120 bytes, with `missing` bytes of the
    /// pixels cut off the end.
    fn xwd_of(width: u32, height: u32, missing: usize) -> Vec<u8> {
        let mut words = [0_u32; 25];
        words[0] = 107;
        words[1] = 7;
        words[2] = 2;
        words[3] = 24;
        words[4] = width;
        words[5] = height;
        words[11] = 32;
        words[12] = 5120;
        words[18] = 256;
        words[19] = 256;
        words[20] = width;
        words[21] = height;
        let mut bytes: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
        bytes.extend(b"xwdump\0");
        bytes.extend(vec![0; 256 * 12]);
        bytes.extend(vec![0; 5120 * height as usize - missing]);
        bytes
    }

    /// KR-REQ-03.29, LX-1: an image is accepted only when it is whole. The three shapes the tools
    /// wrote on a blank screen and an XWD that fills its file exactly are accepted, with no size
    /// floor; an empty file, a header with no payload, a payload cut short, text under the name of
    /// an image and PostScript are not.
    #[test]
    fn kr_req_03_29_an_x11_image_is_accepted_only_when_it_is_whole() {
        // The three PNG shapes the tools wrote, by bit depth, colour type and size of data.
        assert_eq!(validate(Image::Png, &png_of(1280, 800, 1, 0, 148)), Ok(()));
        assert_eq!(validate(Image::Png, &png_of(1280, 800, 8, 2, 3000)), Ok(()));
        assert_eq!(validate(Image::Png, &png_of(1280, 800, 8, 6, 5969)), Ok(()));
        // The XWD the one sample gave: 4,099,179 bytes, which is its header, its colour map and
        // its pixels exactly.
        let whole = xwd_of(1280, 800, 0);
        assert_eq!(whole.len(), 4_099_179);
        assert_eq!(validate(Image::Xwd, &whole), Ok(()));

        for (name, image, bytes, expected) in [
            ("empty png", Image::Png, Vec::new(), Fault::Empty),
            ("empty xwd", Image::Xwd, Vec::new(), Fault::Empty),
            (
                "text named png",
                Image::Png,
                b"this is not an image, whatever its name".to_vec(),
                Fault::NotThisFormat,
            ),
            (
                "postscript",
                Image::Png,
                [b"%!PS-Adobe-3.0\n".as_slice(), &[b'x'; 265_030]].concat(),
                Fault::NotThisFormat,
            ),
            (
                "png cut in its header",
                Image::Png,
                png_of(1280, 800, 8, 6, 5969)[..20].to_vec(),
                Fault::CutShort,
            ),
            (
                "png header only",
                Image::Png,
                chunks(&[(b"IHDR", header(1280, 800, 8, 6))]),
                Fault::CutShort,
            ),
            (
                "png cut in its data",
                Image::Png,
                png_of(1280, 800, 8, 6, 5969)[..3000].to_vec(),
                Fault::CutShort,
            ),
            (
                "png without its end",
                Image::Png,
                {
                    let mut bytes = png_of(1280, 800, 8, 6, 5969);
                    bytes.truncate(bytes.len() - 12);
                    bytes
                },
                Fault::CutShort,
            ),
            (
                "png with no size",
                Image::Png,
                png_of(0, 800, 8, 6, 100),
                Fault::NoPixels,
            ),
            (
                "png with no data",
                Image::Png,
                png_of(1280, 800, 8, 6, 0),
                Fault::NoPixels,
            ),
            (
                "xwd cut in its header",
                Image::Xwd,
                xwd_of(1280, 800, 0)[..60].to_vec(),
                Fault::CutShort,
            ),
            (
                "xwd cut in its pixels",
                Image::Xwd,
                xwd_of(1280, 800, 1),
                Fault::CutShort,
            ),
            (
                "xwd with no size",
                Image::Xwd,
                xwd_of(0, 800, 0),
                Fault::NoPixels,
            ),
        ] {
            assert_eq!(validate(image, &bytes), Err(expected), "{name}");
        }
        // A file of the wrong version is not this format, whatever else it holds.
        let mut old = xwd_of(1280, 800, 0);
        old[7] = 6;
        assert_eq!(validate(Image::Xwd, &old), Err(Fault::NotThisFormat));
    }

    /// KR-REQ-03.29, LX-2: each tool is asked in the vector discovery fixed, with its quiet
    /// argument, one output file inside the run directory whose suffix names its format, and no
    /// shell.
    #[test]
    fn kr_req_03_29_each_x11_tool_is_asked_in_the_vector_discovery_fixed() {
        let run = Path::new("/run/dir");
        let vectors: Vec<(&str, Vec<String>)> = TOOLS
            .iter()
            .map(|tool| (tool.program, tool.vector(&run.join(tool.file))))
            .collect();
        let expected: [(&str, &[&str]); 4] = [
            ("maim", &["/run/dir/capture.png"]),
            (
                "import",
                &["-silent", "-window", "root", "/run/dir/capture.png"],
            ),
            ("scrot", &["/run/dir/capture.png"]),
            ("xwd", &["-root", "-silent", "-out", "/run/dir/capture.xwd"]),
        ];
        assert_eq!(vectors.len(), expected.len());
        for ((program, vector), (named, wanted)) in vectors.iter().zip(expected) {
            assert_eq!(*program, named);
            assert_eq!(
                vector.iter().map(String::as_str).collect::<Vec<_>>(),
                wanted
            );
            assert!(
                !program.contains('/'),
                "a program is a bare name, not a shell line"
            );
        }
        // The platform's own record looks for the same programs, in the same order.
        assert_eq!(
            PROGRAMS,
            TOOLS.iter().map(|tool| tool.program).collect::<Vec<_>>()
        );
    }

    /// Records the environment of a tool and writes a whole PNG where it is asked to.
    fn recording_tool(folder: &Path) -> PathBuf {
        let image = png_of(1280, 800, 8, 6, 5969);
        std::fs::write(folder.join("whole.png"), image).expect("an image");
        program(
            folder,
            "maim",
            "#!/bin/sh\n\
             here=$(dirname \"$0\")\n\
             { echo \"DISPLAY=${DISPLAY-unset}\"; echo \"XAUTHORITY=${XAUTHORITY-unset}\"; \
             echo \"WAYLAND_DISPLAY=${WAYLAND_DISPLAY-unset}\"; } > \"$here/seen\"\n\
             for last do :; done\n\
             cp \"$here/whole.png\" \"$last\"\n",
        )
    }

    /// Performs the screen image on an X11 desktop with these variables, the tools being the ones
    /// in `tools`.
    fn perform_with(plan: &Plan, tools: &Path, variables: &Variables, sockets: &Path) -> Ran {
        let desktop = context(DisplayServer::X11, true);
        let operation =
            resolve(Check::ScreenImage, &desktop, Some(tools.as_os_str())).expect("an X11 row");
        let deadline = Deadline::after(Duration::from_secs(20));
        perform_in(
            plan,
            &Setting {
                desktop: &desktop,
                variables,
                operation: Some(&operation),
                deadline: &deadline,
            },
            &operation,
            sockets,
        )
    }

    /// The marker that makes the inner case of LX-3 run.
    const INNER: &str = "KR_X11_ENVIRONMENT_CASE_FOLDER";

    /// KR-REQ-03.29, LX-3: the tool is given the display and the authority the worker holds and no
    /// Wayland socket, whatever the process that runs the check holds. The case starts its own
    /// test binary with `DISPLAY=:8` and a `WAYLAND_DISPLAY` in its environment, which no test of
    /// this crate may set for itself.
    #[test]
    fn kr_req_03_29_the_tool_is_given_the_display_and_authority_the_worker_holds() {
        let folder = folder();
        let exe = std::env::current_exe().expect("this test binary");
        let name = format!(
            "{}::the_x11_environment_inner_case",
            module_path!().split_once("::").expect("a crate path").1
        );
        let output = std::process::Command::new(exe)
            .args(["--exact", &name, "--nocapture", "--test-threads=1"])
            .env("DISPLAY", ":8")
            .env("WAYLAND_DISPLAY", "wayland-9")
            .env(INNER, folder.path())
            .output()
            .expect("the test binary starts");
        let said = String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{said}");
        assert!(
            said.contains("the environment was as the worker holds it"),
            "{said}"
        );
    }

    /// The inner case: it does nothing unless the case above started it.
    #[test]
    fn the_x11_environment_inner_case() {
        let Some(folder) = std::env::var_os(INNER).map(PathBuf::from) else {
            return;
        };
        assert_eq!(std::env::var("DISPLAY").as_deref(), Ok(":8"));
        assert_eq!(std::env::var("WAYLAND_DISPLAY").as_deref(), Ok("wayland-9"));
        recording_tool(&folder);
        let scratch = folder.join("run");
        let plan = Plan::in_directory(&scratch);
        let variables = Variables {
            display: Some(":6".to_owned()),
            wayland_display: Some("wayland-0".to_owned()),
            authority: Some("/home/someone/.Xauthority-of-the-login".to_owned()),
            ..Variables::default()
        };
        let ran = perform_with(&plan, &folder, &variables, &folder);
        assert!(matches!(ran.outcome, Outcome::Performed { .. }), "{ran:?}");
        let seen = std::fs::read_to_string(folder.join("seen")).expect("what the tool saw");
        assert_eq!(
            seen,
            "DISPLAY=:6\nXAUTHORITY=/home/someone/.Xauthority-of-the-login\n\
             WAYLAND_DISPLAY=unset\n"
        );
        // A worker that holds no authority gives the tool none.
        let variables = Variables {
            authority: None,
            ..variables
        };
        let _ = perform_with(&plan, &folder, &variables, &folder);
        let seen = std::fs::read_to_string(folder.join("seen")).expect("what the tool saw");
        assert!(seen.contains("XAUTHORITY=unset"), "{seen}");
        // And with no display, no tool starts.
        std::fs::remove_file(folder.join("seen")).expect("the earlier reading");
        let variables = Variables {
            display: None,
            ..variables
        };
        let ran = perform_with(&plan, &folder, &variables, &folder);
        assert!(
            matches!(ran.outcome, Outcome::NotAttempted { .. }),
            "{ran:?}"
        );
        assert!(
            !folder.join("seen").exists(),
            "a tool started with no display"
        );
        println!("the environment was as the worker holds it");
    }

    /// A stand-in tool that prints what it is given to print and writes the image it is given to,
    /// where it is asked, then exits as it is told.
    fn stand_in(
        folder: &Path,
        name: &str,
        image: Option<&[u8]>,
        on_output: &str,
        on_error: &str,
        exit: u8,
    ) {
        for (suffix, bytes) in [
            ("payload", image.unwrap_or_default()),
            ("output", on_output.as_bytes()),
            ("error", on_error.as_bytes()),
        ] {
            std::fs::write(folder.join(format!("{name}.{suffix}")), bytes).expect("a file");
        }
        let has_image = if image.is_some() { "yes" } else { "no" };
        program(
            folder,
            name,
            &format!(
                "#!/bin/sh\n\
                 here=$(dirname \"$0\")\n\
                 for last do :; done\n\
                 [ {has_image} = yes ] && cp \"$here/{name}.payload\" \"$last\"\n\
                 cat \"$here/{name}.output\"\n\
                 cat \"$here/{name}.error\" >&2\n\
                 exit {exit}\n"
            ),
        );
    }

    /// What the check said, as the reason its record would carry.
    fn said(ran: &Ran) -> String {
        judge(ran.check, &ran.outcome, Asking::Never)
            .2
            .map(|reason| reason.as_str().to_owned())
            .unwrap_or_default()
    }

    fn variables(display: &str) -> Variables {
        Variables {
            display: Some(display.to_owned()),
            authority: Some("/nowhere/authority".to_owned()),
            ..Variables::default()
        }
    }

    /// KR-REQ-03.29, LX-1 at the facility: only a file that holds a whole image is performed, and
    /// the file is gone afterwards whichever way it went.
    #[test]
    fn kr_req_03_29_a_tool_that_exits_without_a_whole_image_establishes_nothing() {
        let tools = folder();
        let whole = png_of(1280, 800, 1, 0, 148);
        let cut = whole[..whole.len() - 20].to_vec();
        for (name, image, wanted) in [
            ("whole", Some(whole.clone()), "it read a "),
            (
                "no file",
                None,
                "left no usable image: no file, or an empty one",
            ),
            (
                "postscript",
                Some(b"%!PS-Adobe-3.0\n%%Pages: 1\n".to_vec()),
                "left no usable image: a file that is not a PNG image",
            ),
            (
                "no pixels",
                Some(png_of(1280, 800, 8, 6, 0)),
                "left no usable image: a PNG image with no pixels",
            ),
            (
                "cut",
                Some(cut),
                "left no usable image: a PNG image that is cut short",
            ),
        ] {
            stand_in(tools.path(), "maim", image.as_deref(), "", "", 0);
            let scratch = folder();
            let plan = Plan::in_directory(scratch.path());
            let ran = perform_with(&plan, tools.path(), &variables(":7"), tools.path());
            assert!(said(&ran).contains(wanted), "{name}: {}", said(&ran));
            assert_eq!(
                matches!(ran.outcome, Outcome::Performed { .. }),
                name == "whole",
                "{name}"
            );
            assert!(
                !scratch.path().join("capture.png").exists(),
                "{name}: the image was left in the check's own directory"
            );
        }
        // The same words for the one tool that writes an XWD, which is asked for a file of its own.
        let tools = folder();
        let whole = xwd_of(64, 4, 0);
        for (name, image, wanted) in [
            ("whole", Some(whole.clone()), "it read a "),
            (
                "not an xwd",
                Some([b"%!PS-Adobe-3.0\n".as_slice(), &[b'x'; 300]].concat()),
                "left no usable image: a file that is not an XWD image",
            ),
            (
                "cut",
                Some(xwd_of(64, 4, 1)),
                "left no usable image: an XWD image that is cut short",
            ),
        ] {
            stand_in(tools.path(), "xwd", image.as_deref(), "", "", 0);
            let scratch = folder();
            let plan = Plan::in_directory(scratch.path());
            let ran = perform_with(&plan, tools.path(), &variables(":7"), tools.path());
            assert!(said(&ran).contains(wanted), "xwd {name}: {}", said(&ran));
            assert!(
                !scratch.path().join("capture.xwd").exists(),
                "xwd {name}: the image was left in the check's own directory"
            );
        }
    }

    /// KR-REQ-03.29, LX-4: a refusal of the display's authority is told from a display that cannot
    /// be reached by two independent facts, the worker's own connection to the socket and the line
    /// the client library prints. The four fixtures are the error output the four tools gave on an
    /// X server with an empty authority file, with a wrong key and with no such display.
    #[test]
    fn kr_req_03_29_a_refused_authority_is_told_from_an_unreachable_display_by_two_facts() {
        let sentences = [
            "Maim encountered an error:\nError: Failed to open X display: :90\n",
            "import-im6.q16: unable to open X server `:90' @ error/import.c/ImportImageCommand/346.\n",
            "scrot: Can't open X display. It *is* running, yeah? [:90]\n",
            "xwd:  unable to open display ':90'\n",
        ];
        for sentence in sentences {
            let refused = format!(
                "Authorization required, but no authorization protocol specified\n\n{sentence}"
            );
            let wrong_key = format!("Invalid MIT-MAGIC-COOKIE-1 key\n{sentence}");
            for said in [&refused, &wrong_key] {
                assert_eq!(
                    told_by(said, Reach::Connects),
                    Told::AuthorityRefused,
                    "{said}"
                );
            }
            // The tool's own sentence alone, with a display that accepted the connection.
            assert_eq!(
                told_by(sentence, Reach::Connects),
                Told::Accepted,
                "{sentence}"
            );
            // No socket: unreachable, with the sentence alone and with the refusal line too.
            assert_eq!(
                told_by(sentence, Reach::Silent),
                Told::Unreachable,
                "{sentence}"
            );
            assert_eq!(
                told_by(&refused, Reach::Silent),
                Told::Unreachable,
                "{refused}"
            );
        }
        // What each answer comes to: none is a permission a person grants.
        let (state, evidence, reason) = judge(
            Check::ScreenImage,
            &outcome_of(Told::AuthorityRefused),
            Asking::Never,
        );
        assert_eq!(state, CapabilityState::TemporarilyUnavailable);
        assert_eq!(evidence, CapabilityEvidenceSource::DisclosedProbe);
        let reason = reason.expect("a reason").as_str().to_owned();
        assert!(
            reason.contains("the display refused the authority this worker holds"),
            "{reason}"
        );
        assert!(
            reason.contains("a new session may hold the current one"),
            "{reason}"
        );
        assert!(!reason.contains("xhost"), "{reason}");
        for told in [Told::Accepted, Told::Unreachable] {
            let (state, _, _) = judge(Check::ScreenImage, &outcome_of(told), Asking::Never);
            assert_eq!(state, CapabilityState::TemporarilyUnavailable, "{told:?}");
        }
    }

    /// KR-REQ-03.29, LX-4 at the facility: the error output alone is read, the socket is tried by
    /// the worker, and a display reached over the network is not guessed at.
    #[test]
    fn kr_req_03_29_the_worker_tries_the_display_socket_and_reads_the_error_output_alone() {
        let sockets = folder();
        let _listening = std::os::unix::net::UnixListener::bind(sockets.path().join("X7"))
            .expect("a socket of this test's own");
        let tools = folder();
        let refusal = "Authorization required, but no authorization protocol specified\n\n";
        let deadline = Deadline::after(Duration::from_secs(5));
        for (number, expected) in [(7, Reach::Connects), (8, Reach::Silent)] {
            assert_eq!(
                reach(number, sockets.path(), &deadline),
                Some(expected),
                "{number}"
            );
        }
        // With no time left nothing is tried, and nothing is said of the display.
        assert_eq!(
            reach(7, sockets.path(), &Deadline::after(Duration::ZERO)),
            None
        );
        // The refusal line on the error output of a tool that failed, and the display accepts.
        stand_in(tools.path(), "maim", None, "", refusal, 1);
        let scratch = folder();
        let plan = Plan::in_directory(scratch.path());
        let ran = perform_with(&plan, tools.path(), &variables(":7"), sockets.path());
        assert!(
            said(&ran).contains("refused the authority this worker holds"),
            "{}",
            said(&ran)
        );
        // The same line on the output of a tool that printed nothing on its error output is not a
        // refusal: the two streams are kept apart.
        stand_in(tools.path(), "maim", None, refusal, "", 1);
        let ran = perform_with(&plan, tools.path(), &variables(":7"), sockets.path());
        assert!(
            said(&ran).contains("accepted a connection and the tool could not open it"),
            "{}",
            said(&ran)
        );
        // No socket behind the display the tool was asked for.
        let ran = perform_with(&plan, tools.path(), &variables(":8"), sockets.path());
        assert!(
            said(&ran).contains("the display cannot be reached"),
            "{}",
            said(&ran)
        );
    }

    /// KR-REQ-03.29, LX-4: the abstract name an X server on Linux also listens on connects too.
    #[cfg(target_os = "linux")]
    #[test]
    fn kr_req_03_29_the_abstract_display_socket_is_tried_as_well() {
        use std::os::linux::net::SocketAddrExt as _;
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::net::{SocketAddr, UnixListener};

        let sockets = folder();
        let name = sockets.path().join("X9");
        let address = SocketAddr::from_abstract_name(name.as_os_str().as_bytes()).expect("a name");
        let _listening = UnixListener::bind_addr(&address).expect("an abstract socket");
        let deadline = Deadline::after(Duration::from_secs(5));
        assert_eq!(
            reach(9, sockets.path(), &deadline),
            Some(Reach::Connects)
        );
        assert_eq!(reach(10, sockets.path(), &deadline), Some(Reach::Silent));
    }

    /// KR-REQ-03.29, LX-12: a display that is not on this machine starts no tool. A host part
    /// names a display reached over the network, and a name with no local display number names
    /// none on this machine: each is answered before any tool starts, in its own words. A display
    /// on this machine, with or without a screen number, starts the tool.
    #[test]
    fn kr_req_03_29_a_display_that_is_not_on_this_machine_starts_no_tool() {
        for (display, expected) in [
            (":0", Named::Here(0)),
            (":7.1", Named::Here(7)),
            ("unix:7", Named::Here(7)),
            ("unix:7.0", Named::Here(7)),
            ("host:0", Named::Network),
            ("host:0.0", Named::Network),
            ("tcp/host:0", Named::Network),
            ("10.0.0.1:0", Named::Network),
            (":abc", Named::Nowhere),
            (":", Named::Nowhere),
            (" :0", Named::Nowhere),
            (":0.x", Named::Nowhere),
            (":0.", Named::Nowhere),
            (":+7", Named::Nowhere),
            ("unix:", Named::Nowhere),
            ("host", Named::Nowhere),
        ] {
            assert_eq!(named(display), expected, "{display:?}");
        }
        let tools = folder();
        recording_tool(tools.path());
        let seen = tools.path().join("seen");
        let scratch = folder();
        let plan = Plan::in_directory(scratch.path());
        let ran = perform_with(
            &plan,
            tools.path(),
            &variables(":7"),
            tools.path(),
        );
        assert!(
            matches!(ran.outcome, Outcome::Performed { .. }),
            "a display on this machine: {ran:?}"
        );
        assert!(seen.exists(), "a display on this machine starts the tool");
        for (display, words) in [
            ("host:0", "reached over the network"),
            ("tcp/host:0", "reached over the network"),
            (":abc", "names no display on this machine"),
            (":", "names no display on this machine"),
            (" :0", "names no display on this machine"),
        ] {
            let _ = std::fs::remove_file(&seen);
            let ran = perform_with(
                &plan,
                tools.path(),
                &variables(display),
                tools.path(),
            );
            assert!(
                matches!(ran.outcome, Outcome::NotAttempted { .. }),
                "{display:?}: {ran:?}"
            );
            assert!(
                said(&ran).contains(words) && said(&ran).contains("so no tool was started"),
                "{display:?}: {}",
                said(&ran)
            );
            assert!(!seen.exists(), "{display:?}: a tool was started");
        }
    }

    /// KR-REQ-03.29, LX-6: the rows are chosen by the display server of the context. A Wayland
    /// session resolves no X11 row, however many tools are installed, and an X11 session whose
    /// tool is not installed resolves the route that names none.
    #[test]
    fn kr_req_03_29_no_x11_row_is_chosen_in_a_wayland_session() {
        let tools = folder();
        for name in ["maim", "import", "scrot", "xwd", "spectacle"] {
            program(tools.path(), name, "#!/bin/sh\nexit 0\n");
        }
        let search = Some(tools.path().as_os_str());
        for display_server in [
            DisplayServer::Wayland,
            DisplayServer::WindowsDesktop,
            DisplayServer::Unknown,
            DisplayServer::None,
        ] {
            assert_eq!(
                super::super::routes::resolve(
                    Check::ScreenImage,
                    &context(display_server, true),
                    search
                ),
                None,
                "{display_server:?}"
            );
        }
        let x11 = context(DisplayServer::X11, true);
        let operation =
            super::super::routes::resolve(Check::ScreenImage, &x11, search).expect("an X11 row");
        assert_eq!(operation.route.name, "x11-maim");
        assert_eq!(
            operation.program,
            Program::Tool(tools.path().join("maim").to_string_lossy().into_owned())
        );
        // Only the screen image has an X11 row in this table.
        assert_eq!(
            super::super::routes::resolve(Check::AccessibleElement, &x11, search),
            None
        );
        // The first tool of the table that is installed, and none for a tool the table lacks.
        let only = folder();
        program(only.path(), "xwd", "#!/bin/sh\nexit 0\n");
        program(only.path(), "spectacle", "#!/bin/sh\nexit 0\n");
        let operation =
            resolve(Check::ScreenImage, &x11, Some(only.path().as_os_str())).expect("an X11 row");
        assert_eq!(operation.route.name, "x11-xwd");
        let none = folder();
        program(none.path(), "spectacle", "#!/bin/sh\nexit 0\n");
        let operation = resolve(Check::ScreenImage, &x11, Some(none.path().as_os_str()))
            .expect("the route that names no tool");
        assert_eq!(operation.program, Program::Absent(None));
        assert!(performs(&operation));
        let ran = perform_with(
            &Plan::in_directory(none.path()),
            none.path(),
            &variables(":7"),
            none.path(),
        );
        assert_eq!(ran.outcome, Outcome::FacilityMissing);
    }

    /// KR-REQ-03.29, LX-7: an X11 screen image that did not answer says that the deadline expired
    /// and that nothing is established, and not that anything on this desktop asks the person.
    #[test]
    fn kr_req_03_29_an_x11_check_that_did_not_answer_does_not_say_the_person_is_asked() {
        let tools = folder();
        program(tools.path(), "scrot", "#!/bin/sh\nexit 0\n");
        let operation = resolve(
            Check::ScreenImage,
            &context(DisplayServer::X11, true),
            Some(tools.path().as_os_str()),
        )
        .expect("an X11 row");
        let (state, _, reason) = judge(
            Check::ScreenImage,
            &Outcome::NotAnswered {
                waited: Duration::from_secs(15),
                stopped: true,
            },
            operation.route.asking,
        );
        assert_eq!(state, CapabilityState::TemporarilyUnavailable);
        let reason = reason.expect("a reason").as_str().to_owned();
        assert!(
            reason.contains("nothing is established either way"),
            "{reason}"
        );
        assert!(
            reason.contains(
                "Nothing on this desktop is known to ask the person about this operation"
            ),
            "{reason}"
        );
        assert!(!reason.contains("looks exactly like this"), "{reason}");
    }

    /// KR-REQ-03.29, LX-8c: a context that passes every other gate and holds no graphic access is
    /// not asked for the screen image, and one that holds it is.
    #[test]
    fn kr_req_03_29_an_x11_context_without_graphic_access_is_asked_for_the_file_read_alone() {
        let without = probe::performable_on(HostOs::Linux, &context(DisplayServer::X11, false));
        assert_eq!(without, vec![Check::AuthorisedFileRead]);
        let with = probe::performable_on(HostOs::Linux, &context(DisplayServer::X11, true));
        assert!(with.contains(&Check::ScreenImage), "{with:?}");
    }

    /// KR-REQ-03.29: through the report, the X11 row runs the first tool that is installed with the
    /// display the worker holds, and the record it produces names the route and the program it
    /// ran, with the digest of that file.
    #[test]
    fn kr_req_03_29_the_report_runs_the_x11_row_and_its_record_names_the_tool() {
        use kr_protocol::desktop::CapabilitySubject;
        use kr_protocol::ids::{CapabilityRevision, EnvironmentId, SessionId};
        use kr_protocol::scalars::Uuid;

        use super::super::routes::Surroundings;

        let tools = folder();
        recording_tool(tools.path());
        let scratch = folder();
        let first = Surroundings {
            desktop: context(DisplayServer::X11, true),
            variables: Variables {
                display: Some(":7".to_owned()),
                search: Some(tools.path().as_os_str().to_owned()),
                ..Variables::default()
            },
        };
        let source = {
            let reading = first.clone();
            move |_: &Deadline| reading.clone()
        };
        let subject = CapabilitySubject {
            environment_id: EnvironmentId::new(Uuid::from_bytes([7; 16])),
            desktop_session_id: Nullable::null(),
            session_id: Nullable::<SessionId>::null(),
            application: Nullable::null(),
            terminal: Nullable::null(),
        };
        let records = probe::report(
            &first,
            &[Check::ScreenImage],
            &subject,
            &source,
            CapabilityRevision::new(3),
            &Plan::in_directory(scratch.path()),
            &probe::Platform,
        );
        assert_eq!(records.len(), 1, "{records:?}");
        let record = &records[0];
        assert_eq!(
            record.state,
            CapabilityState::QualifiedAvailable,
            "{record:?}"
        );
        assert_eq!(
            record.evidence_source,
            CapabilityEvidenceSource::DisclosedProbe
        );
        assert_eq!(
            record.identity.schema.as_ref().map(String::as_str),
            Some("x11-maim")
        );
        assert_eq!(
            record.identity.binary.as_ref().map(String::as_str),
            Some(tools.path().join("maim").to_string_lossy().as_ref())
        );
        assert!(record.identity.version.is_present(), "{record:?}");
    }

    /// An X server of this test's own, with an authority that names its cookie.
    #[cfg(target_os = "linux")]
    struct Server {
        child: std::process::Child,
        display: String,
        authority: PathBuf,
    }

    #[cfg(target_os = "linux")]
    impl Drop for Server {
        fn drop(&mut self) {
            // Asked to stop first, so that it takes its socket and its lock file with it.
            if let Some(pid) = rustix::process::Pid::from_raw(
                i32::try_from(self.child.id()).expect("a process number"),
            ) {
                let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
            }
            let asked = std::time::Instant::now();
            while asked.elapsed() < Duration::from_secs(5) {
                if matches!(self.child.try_wait(), Ok(Some(_))) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// An authority file that holds this cookie for this display.
    #[cfg(target_os = "linux")]
    fn authority_for(folder: &Path, file: &str, display: &str, cookie: &str) -> PathBuf {
        let path = folder.join(file);
        let status = std::process::Command::new("xauth")
            .args(["-f", &path.to_string_lossy(), "add", display, ".", cookie])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("xauth starts");
        assert!(status.success(), "xauth could not write {}", path.display());
        path
    }

    /// Starts an `Xvfb` that holds one cookie, on a display number nobody on this machine holds.
    #[cfg(target_os = "linux")]
    fn start_server(folder: &Path) -> Server {
        for attempt in 0..8 {
            let number = 300 + std::process::id() % 500 + attempt;
            let display = format!(":{number}");
            if Path::new(&format!("/tmp/.X11-unix/X{number}")).exists()
                || Path::new(&format!("/tmp/.X{number}-lock")).exists()
            {
                continue;
            }
            let cookie = kr_ipc::new_uuid().to_string().replace('-', "");
            let authority = authority_for(folder, &format!("right-{number}"), &display, &cookie);
            let child = std::process::Command::new("Xvfb")
                .args([&display, "-auth", &authority.to_string_lossy()])
                .args(["-nolisten", "tcp", "-screen", "0", "1280x800x24"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("Xvfb starts");
            let mut server = Server {
                child,
                display,
                authority,
            };
            let started = std::time::Instant::now();
            while started.elapsed() < Duration::from_secs(10) {
                if Path::new(&format!("/tmp/.X11-unix/X{number}")).exists()
                    && connects(
                        &Path::new("/tmp/.X11-unix").join(format!("X{number}")),
                        &Deadline::after(Duration::from_secs(2)),
                    )
                {
                    return server;
                }
                if matches!(server.child.try_wait(), Ok(Some(_))) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        panic!("no X server came up on a display number of this test's own");
    }

    /// The programs a real X server case needs that are installed, or none when it stands down.
    ///
    /// A machine that has none of them stands down with a printed reason, unless the run says it
    /// is meant to have a virtual display, as the native backend's step does: there a missing one
    /// fails the case.
    #[cfg(target_os = "linux")]
    fn real_x_tools() -> Option<Vec<(&'static str, String)>> {
        let search = std::env::var_os("PATH");
        let found = |name: &str| installed_in(name, search.as_deref());
        let missing: Vec<&str> = ["Xvfb", "xauth"]
            .into_iter()
            .chain(PROGRAMS.iter().copied())
            .filter(|name| found(name).is_none())
            .collect();
        let required = std::env::var_os("KR_REQUIRE_VIRTUAL_DISPLAY").is_some();
        if required {
            assert!(
                missing.is_empty(),
                "this run needs {missing:?} and does not have them"
            );
        } else if !missing.is_empty() {
            println!("this case stands down: {missing:?} are not installed");
            if missing.contains(&"Xvfb")
                || missing.contains(&"xauth")
                || missing.len() == PROGRAMS.len()
            {
                return None;
            }
        }
        Some(
            PROGRAMS
                .iter()
                .filter_map(|name| found(name).map(|path| (*name, path)))
                .collect(),
        )
    }

    /// KR-REQ-03.29, LX-8a: a real X server and each real tool installed. With the cookie the
    /// server holds, the tool writes a whole image, the check is performed and the file is gone
    /// from the check's own directory before any directory is removed. With a wrong key and with an
    /// empty authority file the display refuses and says so, and with a display number nobody
    /// holds the display cannot be reached.
    #[cfg(target_os = "linux")]
    #[test]
    fn kr_req_03_29_a_real_x_server_gives_an_image_and_a_refusal_its_words() {
        let Some(tools) = real_x_tools() else {
            return;
        };
        let folder = folder();
        let server = start_server(folder.path());
        let number = server
            .display
            .trim_start_matches(':')
            .parse::<u32>()
            .expect("a number");
        let wrong = authority_for(
            folder.path(),
            "wrong",
            &server.display,
            "00000000000000000000000000000001",
        );
        let empty = folder.path().join("empty");
        std::fs::write(&empty, b"").expect("an empty authority file");
        let sockets = Path::new(SOCKETS);
        for (name, path) in tools {
            let only = folder.path().join(format!("only-{name}"));
            std::fs::create_dir(&only).expect("a folder");
            std::os::unix::fs::symlink(&path, only.join(name)).expect("a link to the tool");
            let file = TOOLS
                .iter()
                .find(|tool| tool.program == name)
                .expect("a row")
                .file;
            let with = |display: &str, authority: &Path| Variables {
                display: Some(display.to_owned()),
                authority: Some(authority.to_string_lossy().into_owned()),
                ..Variables::default()
            };
            let run = |variables: &Variables| {
                let scratch = folder.path().join(format!("run-{name}"));
                let _ = std::fs::remove_dir_all(&scratch);
                let plan = Plan::in_directory(&scratch);
                let ran = perform_with(&plan, &only, variables, sockets);
                // Looked at before any directory removal, in the directory the tool was asked to
                // write into.
                assert!(
                    !scratch.join(file).exists(),
                    "{name}: the image was left behind"
                );
                ran
            };
            let ran = run(&with(&server.display, &server.authority));
            assert!(
                matches!(ran.outcome, Outcome::Performed { .. }),
                "{name}: {ran:?}"
            );
            assert!(
                said(&ran).contains("of the whole X screen, every monitor on it"),
                "{name}: {}",
                said(&ran)
            );
            assert_eq!(
                ran.facility.as_deref(),
                Some(only.join(name).to_string_lossy().as_ref()),
                "{name} at {path}"
            );
            for (case, authority) in [("wrong key", &wrong), ("empty file", &empty)] {
                let ran = run(&with(&server.display, authority));
                assert!(
                    said(&ran).contains("the display refused the authority this worker holds"),
                    "{name}, {case}: {}",
                    said(&ran)
                );
            }
            let ran = run(&with(&format!(":{}", number + 1), &server.authority));
            assert!(
                said(&ran).contains("the display cannot be reached"),
                "{name}: {}",
                said(&ran)
            );
        }
    }
}
