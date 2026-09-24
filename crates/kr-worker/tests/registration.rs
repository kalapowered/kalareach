//! The forwarder a launched agent runs acts only on a whole registration.
//!
//! The worker publishes a launch's registration by a rename, so a forwarder finds all of it or
//! nothing. These cases hold the forwarder to its half: whatever it finds before then, an empty
//! file or one cut short, it reads again rather than acts on, until its deadline. Each starts the
//! forwarder this host ships with the two paths in its environment, and a real listener stands at
//! the endpoint the registration names.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.43 | every case: the forwarder presents the launch's exchange only where a whole registration says |
//! | KR-REQ-12.14 | every case: the endpoint is the one the whole registration names |

#![cfg(unix)]

use std::io::BufRead as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The private exchange, as the worker writes it for a launch.
const CREDENTIAL: &str = "0909090909090909090909090909090909090909090909090909090909090909";

/// How long a forwarder that has the whole registration has to reach its endpoint.
const REACHES_WITHIN: Duration = Duration::from_secs(30);

/// How long the forwarder waits for its registration.
const FORWARDER_DEADLINE: Duration = Duration::from_secs(10);

/// A launch's runtime directory, with the forwarder copied into it.
///
/// The directory is short, because a socket path has a small bound on every Unix, and on the
/// machine's own disk, so the forwarder starts at once.
struct Launch {
    directory: PathBuf,
    forwarder: PathBuf,
}

impl Launch {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let name: String = kr_ipc::new_uuid()
            .to_string()
            .chars()
            .filter(char::is_ascii_hexdigit)
            .take(8)
            .collect();
        let directory = std::env::temp_dir().join(format!("kr-r-{name}"));
        std::fs::create_dir_all(&directory).expect("the directory is created");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("the directory is made private");
        let forwarder = directory.join("kr-hook");
        kr_ipc::testing::place_program(Path::new(env!("CARGO_BIN_EXE_kr-hook")), &forwarder);
        // One run first, so the first start of a new executable is not what a case times.
        let warmed = std::process::Command::new(&forwarder)
            .env_remove("KR_REGISTRATION")
            .env_remove("KR_CREDENTIAL")
            .output()
            .expect("the forwarder runs");
        assert!(
            !warmed.status.success(),
            "without a launch it has nothing to do"
        );
        kr_ipc::paths::create_new_owner_only_file(
            &directory.join("credential"),
            CREDENTIAL.as_bytes(),
        )
        .expect("the credential is published");
        Self {
            directory,
            forwarder,
        }
    }

    fn registration(&self) -> PathBuf {
        self.directory.join("registration")
    }

    fn listen(&self, name: &str) -> (PathBuf, UnixListener) {
        let path = self.directory.join(name);
        let listener = UnixListener::bind(&path).expect("the listener binds");
        listener
            .set_nonblocking(true)
            .expect("the listener is polled");
        (path, listener)
    }

    /// Writes the registration in place, the way a writer that is not whole-or-nothing does.
    fn write_in_place(&self, text: &str) {
        std::fs::write(self.registration(), text).expect("written");
    }

    /// Publishes the registration whole, the way the worker does.
    fn publish(&self, text: &str) {
        kr_ipc::paths::write_owner_only_file(&self.registration(), text.as_bytes())
            .expect("published");
    }

    fn start(&self) -> std::process::Child {
        std::process::Command::new(&self.forwarder)
            .env("KR_REGISTRATION", self.registration())
            .env("KR_CREDENTIAL", self.directory.join("credential"))
            .env_remove("KR_SESSION")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("the forwarder starts")
    }
}

impl Drop for Launch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// A whole registration, as the worker writes it, naming `endpoint`.
fn whole(endpoint: &Path) -> String {
    format!(
        "endpoint={}\nprofile=lp-1\ninstance=02020202-0202-0202-0202-020202020202\npid=1\nstart=1\n\
         framing=json_lines\n",
        endpoint.display()
    )
}

/// The one connection that reaches `listener` within `within`, if one does.
fn accepted(listener: &UnixListener, within: Duration) -> Option<UnixStream> {
    let deadline = Instant::now() + within;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Some(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("the listener failed: {error}"),
        }
    }
}

/// The hello the forwarder writes before anything else.
fn hello(stream: UnixStream) -> serde_json::Value {
    stream.set_nonblocking(false).expect("blocking");
    stream
        .set_read_timeout(Some(REACHES_WITHIN))
        .expect("bounded");
    let mut line = String::new();
    std::io::BufReader::new(stream)
        .read_line(&mut line)
        .expect("the hello is read");
    serde_json::from_str(&line).expect("the hello is JSON")
}

fn stop(mut forwarder: std::process::Child) {
    let _ = forwarder.kill();
    let _ = forwarder.wait();
}

/// KR-REQ-12.14: a registration the forwarder finds empty is read again, and once it is whole the
/// forwarder reaches the endpoint it names and presents the launch's exchange.
#[test]
fn kr_req_12_14_an_empty_registration_is_read_again_until_it_is_whole() {
    let launch = Launch::new();
    let (endpoint, listener) = launch.listen("e.sock");
    launch.write_in_place("");
    let mut forwarder = launch.start();

    std::thread::sleep(Duration::from_secs(1));
    assert!(
        forwarder.try_wait().expect("readable").is_none(),
        "an empty registration is not the end of the wait"
    );
    assert!(accepted(&listener, Duration::ZERO).is_none());

    launch.publish(&whole(&endpoint));
    let reached = accepted(&listener, REACHES_WITHIN).expect("the forwarder reaches the endpoint");
    let said = hello(reached);
    assert_eq!(said["kr_hello"]["credential"], CREDENTIAL);
    assert_eq!(said["kr_hello"]["pid"], forwarder.id());
    stop(forwarder);
}

/// KR-REQ-11.43, KR-REQ-12.14: a registration cut short is not acted on, even where what it
/// already says names an endpoint. Cut inside a line, whole lines short of the record, or with
/// every field but not the line break after the last, the forwarder waits; the endpoint it reaches
/// is the one the whole registration names, and the one the partial record named hears nothing.
#[test]
fn kr_req_11_43_a_registration_cut_short_is_not_acted_on() {
    let launch = Launch::new();
    let (decoy, decoy_listener) = launch.listen("d.sock");
    let (endpoint, listener) = launch.listen("e.sock");
    launch.write_in_place(&format!("endpoint={}\nprofile=lp", decoy.display()));
    let mut forwarder = launch.start();

    std::thread::sleep(Duration::from_secs(1));
    assert!(forwarder.try_wait().expect("readable").is_none());
    let short_of_the_record = whole(&decoy);
    let short_of_the_record = short_of_the_record
        .strip_suffix("framing=json_lines\n")
        .expect("the last line");
    launch.write_in_place(short_of_the_record);
    std::thread::sleep(Duration::from_secs(1));
    assert!(forwarder.try_wait().expect("readable").is_none());
    let every_field = whole(&decoy);
    launch.write_in_place(every_field.strip_suffix('\n').expect("the last line break"));
    std::thread::sleep(Duration::from_secs(1));
    assert!(forwarder.try_wait().expect("readable").is_none());
    assert!(accepted(&decoy_listener, Duration::ZERO).is_none());

    launch.publish(&whole(&endpoint));
    let reached = accepted(&listener, REACHES_WITHIN).expect("the forwarder reaches the endpoint");
    assert_eq!(hello(reached)["kr_hello"]["credential"], CREDENTIAL);
    assert!(
        accepted(&decoy_listener, Duration::ZERO).is_none(),
        "the endpoint a partial record named is never reached"
    );
    stop(forwarder);
}

/// KR-REQ-12.14: a registration that never becomes whole ends the forwarder at its deadline, with
/// a failure and a diagnostic, having reached nothing.
#[test]
fn kr_req_12_14_a_registration_that_never_becomes_whole_ends_the_forwarder_at_its_deadline() {
    let launch = Launch::new();
    let (endpoint, listener) = launch.listen("e.sock");
    launch.write_in_place(&format!("endpoint={}\n", endpoint.display()));
    let started = Instant::now();
    let mut forwarder = launch.start();
    // Bounded, so a forwarder that acts on the partial record, and then waits on the endpoint it
    // reached, fails this case rather than hanging it.
    let status = loop {
        if let Some(status) = forwarder.try_wait().expect("readable") {
            break status;
        }
        if started.elapsed() > FORWARDER_DEADLINE + REACHES_WITHIN {
            stop(forwarder);
            panic!("the forwarder outlived its deadline");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let took = started.elapsed();
    assert!(!status.success());
    assert!(
        took >= FORWARDER_DEADLINE - Duration::from_secs(1),
        "it waited out its deadline: {took:?}"
    );
    let mut said = String::new();
    std::io::Read::read_to_string(
        forwarder.stderr.as_mut().expect("its diagnostics"),
        &mut said,
    )
    .expect("the diagnostics are read");
    assert!(
        said.contains("was not a whole registration within 10 seconds"),
        "{said}"
    );
    assert!(accepted(&listener, Duration::ZERO).is_none());
}
