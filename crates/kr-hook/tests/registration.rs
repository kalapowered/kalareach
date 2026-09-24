//! The forwarder acts only on a whole registration.
//!
//! The worker publishes a launch's registration by a rename, so a forwarder finds all of it or
//! nothing. These cases hold the forwarder to its half: whatever it finds before then, an empty
//! file or one cut short, it reads again rather than acts on, until its deadline. Each starts the
//! relay a launched agent runs, with the registration's path in its environment and nothing else,
//! and a real listener stands at the endpoint the registration names.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.43 | every case: the forwarder presents the launch's exchange only where a whole registration says |
//! | KR-REQ-12.14 | every case: the endpoint is the one the whole registration names |
//! | KR-REQ-05.09 | the credential is the file the registration names beside it, whatever else the environment says |

#![cfg(unix)]

mod common;

use std::io::BufRead as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::{LIVENESS, Placed};

/// The private exchange, as the worker writes it for a launch.
const CREDENTIAL: &str = "0909090909090909090909090909090909090909090909090909090909090909";

/// How long the relay waits for its registration.
const RELAY_DEADLINE: Duration = kr_hook::relay::REGISTRATION_APPEARS_WITHIN;

/// A launch's runtime directory beside a placed forwarder.
struct Launch {
    placed: Placed,
    directory: PathBuf,
}

impl Launch {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let placed = Placed::new();
        // Short, because a socket path has a small bound on every Unix.
        let directory = placed.host.root().join("l");
        std::fs::create_dir_all(&directory).expect("a directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("made private");
        kr_ipc::paths::create_new_owner_only_file(
            &directory.join("credential"),
            CREDENTIAL.as_bytes(),
        )
        .expect("the credential is published");
        Self { placed, directory }
    }

    fn registration(&self) -> PathBuf {
        self.directory.join("registration")
    }

    fn credential(&self) -> PathBuf {
        self.directory.join("credential")
    }

    /// A whole registration, as the worker writes it, naming `endpoint` and this launch's
    /// credential file.
    fn whole(&self, endpoint: &Path) -> String {
        whole(endpoint, &self.credential())
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
        let mut relay = self.placed.command(&["relay"]);
        relay
            .env("KR_REGISTRATION", self.registration())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        relay.spawn().expect("the relay starts")
    }
}

/// A whole registration, as the worker writes it, naming `endpoint` and `credential`.
fn whole(endpoint: &Path, credential: &Path) -> String {
    format!(
        "endpoint={}\nprofile=lp-1\ninstance=02020202-0202-0202-0202-020202020202\npid=1\nstart=1\n\
         credential={}\nframing=json_lines\n",
        endpoint.display(),
        credential.display()
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
    stream.set_read_timeout(Some(LIVENESS)).expect("bounded");
    let mut line = String::new();
    std::io::BufReader::new(stream)
        .read_line(&mut line)
        .expect("the hello is read");
    serde_json::from_str(&line).expect("the hello is JSON")
}

fn stop(mut relay: std::process::Child) {
    let _ = relay.kill();
    let _ = relay.wait();
}

/// KR-REQ-12.14: a registration the forwarder finds empty is read again, and once it is whole the
/// forwarder reaches the endpoint it names and presents the launch's exchange.
#[test]
fn kr_req_12_14_an_empty_registration_is_read_again_until_it_is_whole() {
    let launch = Launch::new();
    let (endpoint, listener) = launch.listen("e.sock");
    launch.write_in_place("");
    let mut relay = launch.start();

    std::thread::sleep(Duration::from_secs(1));
    assert!(
        relay.try_wait().expect("readable").is_none(),
        "an empty registration is not the end of the wait"
    );
    assert!(accepted(&listener, Duration::ZERO).is_none());

    launch.publish(&launch.whole(&endpoint));
    let reached = accepted(&listener, LIVENESS).expect("the relay reaches the endpoint");
    let said = hello(reached);
    assert_eq!(said["kr_hello"]["credential"], CREDENTIAL);
    assert_eq!(said["kr_hello"]["pid"], relay.id());
    stop(relay);
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
    let mut relay = launch.start();

    std::thread::sleep(Duration::from_secs(1));
    assert!(relay.try_wait().expect("readable").is_none());
    let short_of_the_record = launch.whole(&decoy);
    let short_of_the_record = short_of_the_record
        .strip_suffix("framing=json_lines\n")
        .expect("the last line");
    launch.write_in_place(short_of_the_record);
    std::thread::sleep(Duration::from_secs(1));
    assert!(relay.try_wait().expect("readable").is_none());
    let every_field = launch.whole(&decoy);
    launch.write_in_place(every_field.strip_suffix('\n').expect("the last line break"));
    std::thread::sleep(Duration::from_secs(1));
    assert!(relay.try_wait().expect("readable").is_none());
    assert!(accepted(&decoy_listener, Duration::ZERO).is_none());

    launch.publish(&launch.whole(&endpoint));
    let reached = accepted(&listener, LIVENESS).expect("the relay reaches the endpoint");
    assert_eq!(hello(reached)["kr_hello"]["credential"], CREDENTIAL);
    assert!(
        accepted(&decoy_listener, Duration::ZERO).is_none(),
        "the endpoint a partial record named is never reached"
    );
    stop(relay);
}

/// KR-REQ-12.14: a registration that never becomes whole ends the forwarder at its deadline, with
/// a failure and a diagnostic, having reached nothing.
#[test]
fn kr_req_12_14_a_registration_that_never_becomes_whole_ends_the_forwarder_at_its_deadline() {
    let launch = Launch::new();
    let (endpoint, listener) = launch.listen("e.sock");
    launch.write_in_place(&format!("endpoint={}\n", endpoint.display()));
    let started = Instant::now();
    let mut relay = launch.start();
    // Bounded, so a forwarder that acts on the partial record, and then waits on the endpoint it
    // reached, fails this case rather than hanging it.
    let status = loop {
        if let Some(status) = relay.try_wait().expect("readable") {
            break status;
        }
        if started.elapsed() > RELAY_DEADLINE + LIVENESS {
            stop(relay);
            panic!("the relay outlived its deadline");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let took = started.elapsed();
    assert!(!status.success());
    assert!(
        took >= RELAY_DEADLINE - Duration::from_secs(1),
        "it waited out its deadline: {took:?}"
    );
    let mut said = String::new();
    std::io::Read::read_to_string(relay.stderr.as_mut().expect("its diagnostics"), &mut said)
        .expect("the diagnostics are read");
    assert!(
        said.contains("was not a whole registration within"),
        "{said}"
    );
    assert!(accepted(&listener, Duration::ZERO).is_none());
}

/// KR-REQ-05.09: the forwarder needs one variable. The credential it presents is the one in the
/// file its registration names, and a credential variable in the environment, which an application
/// may scrub or another process may set, is not read.
#[test]
fn kr_req_05_09_the_credential_is_the_one_the_registration_names() {
    let launch = Launch::new();
    let (endpoint, listener) = launch.listen("e.sock");
    let decoy = launch.directory.join("decoy");
    kr_ipc::paths::create_new_owner_only_file(
        &decoy,
        b"0505050505050505050505050505050505050505050505050505050505050505",
    )
    .expect("a decoy credential");
    launch.publish(&launch.whole(&endpoint));
    let mut relay = launch.placed.command(&["relay"]);
    relay
        .env("KR_REGISTRATION", launch.registration())
        .env("KR_CREDENTIAL", &decoy)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let relay = relay.spawn().expect("the relay starts");
    let reached = accepted(&listener, LIVENESS).expect("the relay reaches the endpoint");
    assert_eq!(
        hello(reached)["kr_hello"]["credential"],
        CREDENTIAL,
        "the exchange is the registration's own"
    );
    stop(relay);
}

/// KR-REQ-05.09: a registration that names a credential file anywhere but its own directory, or
/// names none, is not one the worker wrote. The forwarder presents nothing from it, reaches
/// nothing, and says why.
#[test]
fn kr_req_05_09_a_credential_outside_the_registration_s_directory_is_refused() {
    let launch = Launch::new();
    let (endpoint, listener) = launch.listen("e.sock");
    let elsewhere = launch.placed.host.root().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("a directory");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o700))
            .expect("made private");
    }
    let foreign = elsewhere.join("credential");
    kr_ipc::paths::create_new_owner_only_file(&foreign, CREDENTIAL.as_bytes())
        .expect("a credential elsewhere");
    let unnamed = launch.whole(&endpoint).replace(
        &format!("credential={}\n", launch.credential().display()),
        "",
    );
    for (registration, why) in [
        (
            whole(&endpoint, &foreign),
            "a credential outside the registration's directory",
        ),
        (
            whole(&endpoint, Path::new("credential")),
            "a relative credential path",
        ),
    ] {
        launch.publish(&registration);
        let mut relay = launch.start();
        let status = wait(&mut relay);
        assert!(!status.success(), "{why}: the relay fails");
        let mut said = String::new();
        std::io::Read::read_to_string(relay.stderr.as_mut().expect("its diagnostics"), &mut said)
            .expect("the diagnostics are read");
        assert!(
            said.contains("not in the registration's own directory"),
            "{why}: {said}"
        );
        assert!(
            accepted(&listener, Duration::ZERO).is_none(),
            "{why}: nothing is reached"
        );
        std::fs::remove_file(launch.registration()).expect("the registration is removed");
    }
    // A registration that names no credential file at all is not whole, and is waited on until
    // the deadline like any other that is not.
    assert!(!kr_hook::registration::whole(&unnamed));
}

/// KR-REQ-05.09: a credential beside the registration that is a link is not the worker's file,
/// wherever it points and however closed its target is: out of the registration's directory, or to
/// another file in it. The forwarder reads it through the registration's directory without
/// following it, presents nothing and reaches nothing.
#[test]
fn kr_req_05_09_a_credential_that_is_a_link_is_refused() {
    for leaves_the_directory in [true, false] {
        let launch = Launch::new();
        let (endpoint, listener) = launch.listen("e.sock");
        let target = if leaves_the_directory {
            let elsewhere = launch.placed.host.root().join("target");
            std::fs::create_dir_all(&elsewhere).expect("a directory");
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o700))
                    .expect("made private");
            }
            elsewhere.join("credential")
        } else {
            launch.directory.join("credential.real")
        };
        kr_ipc::paths::create_new_owner_only_file(&target, CREDENTIAL.as_bytes())
            .expect("a closed credential the link points at");
        std::fs::remove_file(launch.credential()).expect("the launch's own credential is removed");
        // A link inside the directory is relative, the kind a directory handle would follow.
        let pointing_at = if leaves_the_directory {
            target.clone()
        } else {
            PathBuf::from("credential.real")
        };
        std::os::unix::fs::symlink(&pointing_at, launch.credential()).expect("a link in its place");
        launch.publish(&launch.whole(&endpoint));

        let mut relay = launch.start();
        let status = wait(&mut relay);
        let what = if leaves_the_directory {
            "a link out of the directory"
        } else {
            "a link inside the directory"
        };
        assert!(!status.success(), "{what}: the relay fails");
        let mut said = String::new();
        std::io::Read::read_to_string(relay.stderr.as_mut().expect("its diagnostics"), &mut said)
            .expect("the diagnostics are read");
        assert!(said.contains("could not be read"), "{what}: {said}");
        assert!(
            accepted(&listener, Duration::ZERO).is_none(),
            "{what}: nothing is reached through a linked credential"
        );
    }
}

/// Waits for a relay that is expected to end on its own, within its deadline.
fn wait(relay: &mut std::process::Child) -> std::process::ExitStatus {
    let started = Instant::now();
    loop {
        if let Some(status) = relay.try_wait().expect("readable") {
            return status;
        }
        assert!(
            started.elapsed() <= RELAY_DEADLINE + LIVENESS,
            "the relay outlived its deadline"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
