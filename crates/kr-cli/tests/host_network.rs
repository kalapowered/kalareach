//! `kr host network`: a host joins the service it uses, or leaves it, as one validated edit of its
//! configuration document.
//!
//! KR-REQ-26.16, KR-REQ-10.02, KR-REQ-17.12: edits are validated, the effective value and its
//! source are shown, discovery and relays are selected separately, and a service names its own
//! selection. The command is the real `kr` on a real host tree. The service is the stand-in held
//! to the Worker's source, over loopback, signing with a key the test makes and giving the command
//! its public half, as a person who runs a service does. Nothing here reaches a real service:
//! every case names `--service`, and the managed origin the command starts from is read in the
//! deployed run.
//!
//! The first case is the whole of it. A host that joined starts its real control daemon over the
//! document the command wrote, and the diagnostics report the endpoint built with the relay and
//! the discovery servers the service described, from the document, as it would for a document
//! written by hand. The cases after it hold what the command refuses and what it never changes: a
//! service that cannot be had or is not accepted writes nothing and repeats nothing, a person's own
//! values are not replaced without `--replace`, a document this build must not rewrite ends the
//! command before any request is made, and a request never goes round the proxy the document names.

#![cfg(unix)]

use std::net::TcpListener as StdListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use kr_crypto::keys::AuthorisationKeyPair;
use kr_ipc::client::LocalClient;
use kr_protocol::ids::BuildId;
use kr_protocol::local::LocalClientKind;
use kr_service_stand_in::{Served, serve, signed_service_description};
use serde_json::{Value, json};

mod support;

use support::kr;

/// How long a wait for something to happen is given. It fails when the thing never happens.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// Text a hostile service plants in what it says, which no refusal repeats.
const PLANTED: &str = "planted-by-the-service-3f9a1c";

/// A host tree and the `kr` that works on it, with no daemon.
struct Tree {
    temp: kr_ipc::testing::TempHost,
}

impl Tree {
    fn create() -> Self {
        Self {
            temp: kr_ipc::testing::TempHost::create(),
        }
    }

    fn document_path(&self) -> PathBuf {
        kr_cli::doctor::configuration::document_path(&self.temp.environment())
    }

    /// The document's bytes, or none while there is no document.
    fn document_bytes(&self) -> Option<Vec<u8>> {
        std::fs::read(self.document_path()).ok()
    }

    /// The document as JSON.
    fn document(&self) -> Value {
        serde_json::from_slice(&self.document_bytes().expect("the document was written"))
            .expect("the document is JSON")
    }

    /// Writes a document as a person or an earlier release left it.
    fn write_document(&self, document: &Value) {
        let path = self.document_path();
        std::fs::create_dir_all(path.parent().expect("a directory")).expect("the state directory");
        kr_ipc::paths::write_owner_only_file(&path, document.to_string().as_bytes())
            .expect("the document");
    }

    fn environment(&self) -> Vec<(String, String)> {
        vec![
            ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
            (
                "KR_RUNTIME_DIR".to_owned(),
                self.temp.paths().runtime_root().display().to_string(),
            ),
            (
                "KR_STATE_DIR".to_owned(),
                self.temp.paths().state_root().display().to_string(),
            ),
        ]
    }

    /// Runs `kr` on plain pipes.
    fn kr(&self, arguments: &[&str]) -> std::process::Output {
        std::process::Command::new(kr())
            .args(arguments)
            .env_clear()
            .envs(self.environment())
            .current_dir("/")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("runs kr")
    }

    /// Runs `kr --json` and reads what it printed, whether or not it succeeded.
    fn kr_json(&self, arguments: &[&str]) -> (std::process::Output, Value) {
        let mut all = vec!["--json"];
        all.extend_from_slice(arguments);
        let output = self.kr(&all);
        let printed = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "kr {} printed JSON ({error}): {}{}",
                arguments.join(" "),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output, printed)
    }
}

/// A service on loopback that signs with a key of the test's own.
struct Service {
    served: Served,
    key: AuthorisationKeyPair,
}

impl Service {
    async fn start() -> Self {
        Self {
            served: serve().await,
            key: AuthorisationKeyPair::generate().expect("a key pair"),
        }
    }

    fn origin(&self) -> String {
        self.served.origin().to_owned()
    }

    /// The public key a person who runs this service gives `--key`.
    fn public_key(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.key.public().as_bytes())
    }

    /// What this service says of itself: a relay and a discovery server on this machine, and the
    /// three services at its own origin.
    fn description(&self) -> Value {
        json!({
            "schema_version": 1,
            "network": {
                "relay_urls": ["http://127.0.0.1:3340"],
                "pkarr_publisher_url": "http://127.0.0.1:3341/pkarr",
                "pkarr_resolver_url": "http://127.0.0.1:3341/pkarr",
            },
            "authority": { "origin": self.origin() },
            "mailbox": { "origin": self.origin() },
            "relay": { "origin": self.origin() },
        })
    }

    fn publish(&self) {
        self.publish_description(&self.description());
    }

    fn publish_description(&self, description: &Value) {
        let reply = signed_service_description(description, &self.key);
        self.served
            .web()
            .publish_service_description(&serde_json::to_vec(&reply).expect("a reply"));
    }

    /// Publishes exactly these bytes, as a service that is wrong or hostile would.
    fn publish_bytes(&self, reply: &[u8]) {
        self.served.web().publish_service_description(reply);
    }
}

/// A listener that counts the connections made to it and closes each at once, standing where a
/// service or a proxy would be.
struct Counting {
    port: u16,
    accepted: Arc<AtomicUsize>,
}

impl Counting {
    fn start() -> Self {
        let listener = StdListener::bind("127.0.0.1:0").expect("a loopback listener");
        let port = listener.local_addr().expect("an address").port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&accepted);
        std::thread::spawn(move || {
            while let Ok((socket, _)) = listener.accept() {
                counted.fetch_add(1, Ordering::SeqCst);
                drop(socket);
            }
        });
        Self { port, accepted }
    }

    /// An `http` address of this listener.
    fn http(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// An `https` address of this listener, which nothing here speaks TLS for.
    fn https(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

/// A port nothing listens on.
fn closed_port() -> u16 {
    let listener = StdListener::bind("127.0.0.1:0").expect("a loopback listener");
    listener.local_addr().expect("an address").port()
}

fn said(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The arguments of a join of `service`, verified under its key.
fn join<'a>(service: &'a str, key: &'a str) -> Vec<&'a str> {
    vec![
        "host",
        "network",
        "--join",
        "--service",
        service,
        "--key",
        key,
    ]
}

/* -------------------------------------------------------------------------- */
/* The whole of it                                                              */
/* -------------------------------------------------------------------------- */

fn beside_this_test(name: &str) -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let profile = executable.parent()?.parent()?;
    let candidate = profile.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    candidate.is_file().then_some(candidate)
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// KR-REQ-26.16: a host that joined a service starts its real daemon over the document the command
/// wrote, and the diagnostics report each setting with the source `host_configuration` and the
/// endpoint built with the relay and the discovery servers the service described; the same daemon
/// over a document that never joined is on no network.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_joined_runs_on_what_the_command_wrote() {
    let controller = beside_this_test("kr-controller").unwrap_or_else(|| {
        panic!(
            "the kr-controller executable is not built beside this test, so this check cannot \
             run; a workspace test run builds it, and so does `cargo build -p kr-controller`"
        )
    });
    let service = Service::start().await;
    service.publish();

    let joined = Tree::create();
    // Where the endpoint binds is the machine's own choice, and the command leaves it alone.
    joined.write_document(&json!({
        "version": 3, "revision": 1, "network": { "bind_address": "127.0.0.1:0" }
    }));
    let origin = service.origin();
    let (output, shown) = joined.kr_json(&join(&origin, &service.public_key()));
    assert!(output.status.success(), "{}", said(&output));
    assert_eq!(shown["changed"], true, "{shown}");

    let alone = Tree::create();
    alone.write_document(&json!({
        "version": 3, "revision": 1, "network": { "enabled": true, "bind_address": "127.0.0.1:0" }
    }));

    for (tree, relays, discovery) in [(&joined, 1, 2), (&alone, 0, 0)] {
        let daemon = Daemon::start(&controller, tree).await;
        let (_, report) = tree.kr_json(&["doctor"]);
        let values = report["configuration"]["values"]
            .as_array()
            .unwrap_or_else(|| panic!("the report holds the values: {report}"));
        let row = |key: &str| {
            values
                .iter()
                .find(|value| value["key"] == key)
                .unwrap_or_else(|| panic!("the report shows {key}: {report}"))
        };
        let network = report["doctor"]["checks"]
            .as_array()
            .and_then(|checks| {
                checks
                    .iter()
                    .find(|check| check["id"] == "configuration-network")
            })
            .unwrap_or_else(|| panic!("the report holds the network check: {report}"));
        assert!(
            network["detail"]
                .as_str()
                .unwrap_or_default()
                .contains(&format!(
                    "with {relays} relays and {discovery} discovery services selected"
                )),
            "{network}"
        );
        if relays > 0 {
            for key in [
                "network.relay_urls",
                "network.pkarr_publisher_url",
                "network.pkarr_resolver_url",
                "authority.origin",
                "mailbox.origin",
                "relay.origin",
            ] {
                assert_eq!(row(key)["source"], "host_configuration", "{key}: {report}");
                assert_eq!(row(key)["effect"], "next_start", "{key}: {report}");
            }
            assert!(
                row("network.relay_urls")["value"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("127.0.0.1:3340"),
                "{report}"
            );
            assert_eq!(row("network.dns_origin")["source"], "default", "{report}");
        }
        drop(daemon);
    }
}

/// A real control daemon on a host tree, on loopback alone.
struct Daemon {
    child: Option<std::process::Child>,
}

impl Daemon {
    async fn start(controller: &Path, tree: &Tree) -> Self {
        let bin = tree.temp.root().join("bin");
        std::fs::create_dir_all(&bin).expect("a directory for the executable");
        let destination = bin.join(controller.file_name().expect("the executable has a name"));
        kr_ipc::testing::place_program(controller, &destination);
        let log = std::fs::File::create(tree.temp.root().join("daemon.log")).expect("a log");
        let child = std::process::Command::new(&destination)
            .current_dir(tree.temp.root())
            .arg("--runtime-dir")
            .arg(tree.temp.root().join("r"))
            .arg("--state-dir")
            .arg(tree.temp.root().join("s"))
            .arg("--secret-store")
            .arg("file")
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().expect("duplicates the log"))
            .stderr(log)
            .spawn()
            .expect("the daemon starts");
        let daemon = Self { child: Some(child) };
        let endpoint = tree
            .temp
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let started = Instant::now();
        while LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .is_err()
        {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "the daemon did not answer; its log says: {}",
                std::fs::read_to_string(tree.temp.root().join("daemon.log")).unwrap_or_default()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        daemon
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/* -------------------------------------------------------------------------- */
/* What it writes                                                               */
/* -------------------------------------------------------------------------- */

/// A join on a fresh host writes the settings the service described, at the level its sections
/// give, and nothing else; the same join again changes nothing, the revision included; and an
/// explicit choice of no network is a value of the person's and is not turned on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_join_writes_what_the_service_described_and_a_second_changes_nothing() {
    let service = Service::start().await;
    service.publish();
    let tree = Tree::create();
    let origin = service.origin();
    let key = service.public_key();
    let arguments = join(&origin, &key);

    let (output, shown) = tree.kr_json(&arguments);
    assert!(output.status.success(), "{}", said(&output));
    assert_eq!(shown["changed"], true, "{shown}");
    assert_eq!(shown["signed"], true, "{shown}");
    let written = tree.document();
    assert_eq!(written["version"], 3, "{written}");
    assert_eq!(written["revision"], 1, "{written}");
    assert_eq!(
        written["level"], 4,
        "the relay section arrived with level 4: {written}"
    );
    assert_eq!(written["network"]["enabled"], true, "{written}");
    assert_eq!(
        written["network"]["relay_urls"],
        json!(["http://127.0.0.1:3340"]),
        "{written}"
    );
    assert_eq!(
        written["network"]["pkarr_resolver_url"], "http://127.0.0.1:3341/pkarr",
        "{written}"
    );
    assert_eq!(written["authority"]["origin"], origin, "{written}");
    assert_eq!(written["mailbox"]["origin"], origin, "{written}");
    assert_eq!(written["relay"]["origin"], origin, "{written}");
    assert!(
        written["startup"]["controller"].is_null()
            && written["preferences"]["sleep_inhibition"].is_null()
            && written["network"]["bind_address"].is_null()
            && written["network"]["proxy_url"].is_null()
            && written["shell"]["mode"].is_null(),
        "nothing else is chosen: {written}"
    );
    assert_eq!(shown["network"]["network.enabled"], true, "{shown}");

    let bytes = tree.document_bytes();
    let (output, again) = tree.kr_json(&arguments);
    assert!(output.status.success(), "{}", said(&output));
    assert_eq!(again["changed"], false, "{again}");
    assert_eq!(tree.document_bytes(), bytes, "the document is as it was");

    let chosen = Tree::create();
    chosen.write_document(&json!({
        "version": 3, "revision": 1, "network": { "enabled": false }
    }));
    let before = chosen.document_bytes();
    let output = chosen.kr(&arguments);
    assert_eq!(output.status.code(), Some(2), "{}", said(&output));
    assert!(
        said(&output).contains("network.enabled"),
        "{}",
        said(&output)
    );
    assert_eq!(chosen.document_bytes(), before, "and nothing was written");
}

/// What a person is shown without joining: each setting a join owns, and nothing is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_flag_it_shows_what_the_document_selects() {
    let tree = Tree::create();
    let (output, shown) = tree.kr_json(&["host", "network"]);
    assert!(output.status.success(), "{}", said(&output));
    assert_eq!(shown["changed"], false, "{shown}");
    for key in [
        "network.enabled",
        "network.relay_urls",
        "network.pkarr_publisher_url",
        "network.pkarr_resolver_url",
        "network.dns_origin",
        "authority.origin",
        "mailbox.origin",
        "relay.origin",
    ] {
        assert!(shown["network"].get(key).is_some(), "{key}: {shown}");
    }
    assert!(tree.document_bytes().is_none(), "nothing was written");
}

/* -------------------------------------------------------------------------- */
/* What it refuses                                                              */
/* -------------------------------------------------------------------------- */

/// A service that cannot be had, or whose description is not accepted, ends the command with
/// nothing written, and nothing the service said is repeated: not its words, and not a value it
/// planted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_service_that_cannot_be_had_or_is_not_accepted_writes_nothing_and_repeats_nothing() {
    let service = Service::start().await;
    let tree = Tree::create();
    let origin = service.origin();
    let unsigned = |origin: &str| {
        vec![
            "host".to_owned(),
            "network".to_owned(),
            "--join".to_owned(),
            "--service".to_owned(),
            origin.to_owned(),
            "--unsigned".to_owned(),
        ]
    };
    let attempt = |arguments: &[String]| {
        let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
        tree.kr(&arguments)
    };
    let nothing_written = |why: &str, output: &std::process::Output, code: i32| {
        assert_eq!(output.status.code(), Some(code), "{why}: {}", said(output));
        assert!(
            tree.document_bytes().is_none(),
            "{why}: nothing was written"
        );
        assert!(!said(output).contains(PLANTED), "{why}: {}", said(output));
    };

    // The service publishes no description, and one is not listening at all.
    nothing_written("no description", &attempt(&unsigned(&origin)), 1);
    let gone = format!("http://127.0.0.1:{}", closed_port());
    nothing_written("nothing listening", &attempt(&unsigned(&gone)), 1);

    // A description past the bound the command reads under.
    let large = json!({ "description": { "schema_version": 1, "padding": "x".repeat(20_000) } });
    service.publish_bytes(&serde_json::to_vec(&large).expect("text"));
    nothing_written("too large", &attempt(&unsigned(&origin)), 1);

    // What a service can say wrong, each with a value it planted.
    let wrong = |description: Value| {
        serde_json::to_vec(&json!({ "description": description })).expect("text")
    };
    let relay = json!(["http://127.0.0.1:3340"]);
    for (why, body) in [
        ("not JSON", format!("<html>{PLANTED}</html>").into_bytes()),
        (
            "a later schema",
            wrong(json!({ "schema_version": 2, "note": PLANTED })),
        ),
        (
            "a member of the wrong type",
            wrong(json!({ "schema_version": 1, "network": { "relay_urls": PLANTED } })),
        ),
        (
            "nothing to join",
            wrong(json!({ "schema_version": 1, "authority": { "origin": PLANTED } })),
        ),
        (
            "a misspelt member",
            wrong(json!({
                "schema_version": 1, "network": { "relay_urls": relay, "pkarr_publisher_ur": PLANTED }
            })),
        ),
        (
            "a plain http relay on another machine",
            wrong(json!({
                "schema_version": 1, "network": { "relay_urls": ["http://relay.example.test"] },
                "authority": { "origin": PLANTED }
            })),
        ),
        (
            "an address the document refuses",
            wrong(json!({
                "schema_version": 1, "network": { "relay_urls": ["http://127.0.0.1:3340/a b"] },
                "authority": { "origin": PLANTED }
            })),
        ),
    ] {
        service.publish_bytes(&body);
        let code = 2;
        nothing_written(why, &attempt(&unsigned(&origin)), code);
    }

    // And the control: the same service, saying it right, is joined.
    service.publish();
    let output = tree.kr(&join(&origin, &service.public_key()));
    assert!(output.status.success(), "{}", said(&output));
    assert!(tree.document_bytes().is_some());
}

/// A service you run is joined under its key or on the connection alone, and said so; the managed
/// service is verified under the key this build pins, which a flag does not replace; and a
/// description that is unsigned or signed by another key is refused where a key is required.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_description_is_read_under_the_key_named_and_a_flag_does_not_replace_the_managed_key() {
    let service = Service::start().await;
    service.publish();
    let tree = Tree::create();
    let origin = service.origin();
    let other = AuthorisationKeyPair::generate().expect("a key pair");
    let other_key =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(other.public().as_bytes());

    let output = tree.kr(&["host", "network", "--join", "--service", &origin]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a service you run names its key or says so"
    );
    assert!(said(&output).contains("--key") && said(&output).contains("--unsigned"));

    let output = tree.kr(&join(&origin, &other_key));
    assert_eq!(output.status.code(), Some(2), "{}", said(&output));
    assert!(
        tree.document_bytes().is_none(),
        "signed by another key, so nothing was written"
    );

    let output = tree.kr(&join(&origin, "not a key"));
    assert_eq!(output.status.code(), Some(2), "{}", said(&output));

    let output = tree.kr(&["host", "network", "--join", "--key", &service.public_key()]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a key is for a service that is named"
    );
    for managed_flag in ["--unsigned", "--key"] {
        let key = service.public_key();
        let mut arguments = vec![
            "host",
            "network",
            "--join",
            "--service",
            "https://reach.kala.to",
            managed_flag,
        ];
        if managed_flag == "--key" {
            arguments.push(&key);
        }
        let output = tree.kr(&arguments);
        assert_eq!(output.status.code(), Some(2), "{}", said(&output));
        assert!(tree.document_bytes().is_none());
    }

    // A description a service published without a signature is read only on the connection alone,
    // and the output says so.
    let unsigned =
        serde_json::to_vec(&json!({ "description": service.description() })).expect("text");
    service.publish_bytes(&unsigned);
    let output = tree.kr(&join(&origin, &service.public_key()));
    assert_eq!(output.status.code(), Some(2), "{}", said(&output));
    assert!(tree.document_bytes().is_none());
    let output = tree.kr(&[
        "host",
        "network",
        "--join",
        "--service",
        &origin,
        "--unsigned",
    ]);
    assert!(output.status.success(), "{}", said(&output));
    assert!(
        said(&output).contains("connection alone"),
        "{}",
        said(&output)
    );
    assert!(tree.document_bytes().is_some());
}

/// A join never replaces a value the document already holds: it names the settings that differ and
/// shows both values, and `--replace` takes the service's, a setting the service leaves out
/// included.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_value_the_person_wrote_is_replaced_only_when_they_say_so() {
    let service = Service::start().await;
    service.publish_description(&{
        let mut description = service.description();
        description
            .as_object_mut()
            .expect("description")
            .remove("mailbox");
        description
    });
    let tree = Tree::create();
    let origin = service.origin();
    tree.write_document(&json!({
        "version": 3,
        "level": 3,
        "revision": 4,
        "network": { "enabled": true, "relay_urls": ["https://relay.example.test"] },
        "mailbox": { "origin": "https://mail.example.test" },
    }));
    let before = tree.document_bytes();

    let output = tree.kr(&join(&origin, &service.public_key()));
    assert_eq!(output.status.code(), Some(2), "{}", said(&output));
    let said = said(&output);
    for key in ["network.relay_urls", "mailbox.origin"] {
        assert!(said.contains(key), "the refusal names {key}: {said}");
    }
    assert!(
        said.contains("https://relay.example.test") && said.contains("127.0.0.1:3340"),
        "and shows both values: {said}"
    );
    assert!(
        !said.contains("network.enabled"),
        "a setting that is the same is not named: {said}"
    );
    assert_eq!(tree.document_bytes(), before, "nothing was written");

    let key = service.public_key();
    let mut arguments = join(&origin, &key);
    arguments.push("--replace");
    let output = tree.kr(&arguments);
    assert!(output.status.success(), "{}", self::said(&output));
    let written = tree.document();
    assert_eq!(written["revision"], 5, "{written}");
    assert_eq!(
        written["network"]["relay_urls"],
        json!(["http://127.0.0.1:3340"]),
        "{written}"
    );
    assert!(
        written["mailbox"].is_null() || written.get("mailbox").is_none(),
        "the service leaves the mailbox out, so the join does: {written}"
    );
}

/// The machine's own choices and every other section survive a join, a replace and a clear, and the
/// level follows what the document holds. A clear that would leave `relay_only` with no relay, and a
/// replace with no relay over it, are refused as the document refuses them, with the setting named.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_machines_own_choices_and_other_sections_survive_a_join_a_replace_and_a_clear() {
    let service = Service::start().await;
    service.publish();
    let tree = Tree::create();
    let origin = service.origin();
    tree.write_document(&json!({
        "version": 3,
        "level": 6,
        "revision": 7,
        "preferences": { "sleep_inhibition": "mains_only" },
        "startup": { "controller": "standalone" },
        "shell": { "mode": "native_compat" },
        "network": {
            "bind_address": "127.0.0.1:0",
            "relay_urls": ["http://127.0.0.1:3340"],
            "relay_only": true,
            "local_discovery": true,
            "mainline_dht": false,
        },
    }));
    let own = |document: &Value| {
        json!({
            "sleep": document["preferences"]["sleep_inhibition"],
            "startup": document["startup"]["controller"],
            "shell": document["shell"]["mode"],
            "bind_address": document["network"]["bind_address"],
            "relay_only": document["network"]["relay_only"],
            "local_discovery": document["network"]["local_discovery"],
            "mainline_dht": document["network"]["mainline_dht"],
        })
    };
    let kept = own(&tree.document());

    let output = tree.kr(&join(&origin, &service.public_key()));
    assert!(output.status.success(), "{}", said(&output));
    let joined = tree.document();
    assert_eq!(own(&joined), kept, "{joined}");
    assert_eq!(
        joined["level"], 6,
        "the shell section holds the level: {joined}"
    );
    assert_eq!(joined["network"]["enabled"], true, "{joined}");

    // A clear that would leave relay_only with no relay is refused, naming it, with nothing written.
    let bytes = tree.document_bytes();
    let output = tree.kr(&["host", "network", "--clear"]);
    assert_eq!(output.status.code(), Some(2), "{}", said(&output));
    assert!(
        said(&output).contains("network.relay_only"),
        "{}",
        said(&output)
    );
    assert_eq!(tree.document_bytes(), bytes);

    // Nor does a replace with a description that names no relay.
    service.publish_description(&json!({
        "schema_version": 1,
        "network": { "pkarr_publisher_url": "http://127.0.0.1:3341/pkarr" },
    }));
    let output = tree.kr(&[
        "host",
        "network",
        "--join",
        "--service",
        &origin,
        "--key",
        &service.public_key(),
        "--replace",
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", said(&output));
    assert!(
        said(&output).contains("network.relay_only"),
        "{}",
        said(&output)
    );
    assert_eq!(tree.document_bytes(), bytes);

    // Once the person has put relay_only right, the clear takes out the eight and only the eight.
    let mut put_right = tree.document();
    put_right["network"]["relay_only"] = json!(false);
    tree.write_document(&put_right);
    let output = tree.kr(&["host", "network", "--clear"]);
    assert!(output.status.success(), "{}", said(&output));
    let cleared = tree.document();
    for held in [
        &cleared["network"]["enabled"],
        &cleared["network"]["relay_urls"],
        &cleared["authority"]["origin"],
        &cleared["mailbox"]["origin"],
        &cleared["relay"]["origin"],
    ] {
        assert!(held.is_null(), "{cleared}");
    }
    assert_eq!(
        cleared["network"]["bind_address"], "127.0.0.1:0",
        "{cleared}"
    );
    assert_eq!(own(&cleared)["startup"], kept["startup"], "{cleared}");
    assert_eq!(cleared["level"], 6, "{cleared}");

    // And a clear of nothing writes nothing.
    let bytes = tree.document_bytes();
    let output = tree.kr(&["host", "network", "--clear"]);
    assert!(output.status.success(), "{}", said(&output));
    assert_eq!(tree.document_bytes(), bytes);
}

/// A document this build must not rewrite, or cannot read, ends the command before any request is
/// made, even when it names a proxy: it names none the command can use, and a request that went
/// direct would go round it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_document_that_cannot_be_edited_ends_the_command_before_any_request() {
    let service = Counting::start();
    let proxy = Counting::start();
    let origin = service.http();
    let usable = json!({
        "version": 3, "revision": 1, "network": { "proxy_url": proxy.http() }
    });
    let unusable = [
        (
            "an unknown version",
            json!({ "version": 99, "revision": 1, "network": { "proxy_url": proxy.http() } }),
        ),
        (
            "a level above this build's",
            json!({
                "version": 3, "level": 99, "revision": 1, "network": { "proxy_url": proxy.http() },
                "a_section_of_a_later_release": { "origin": "https://later.example.test" },
            }),
        ),
        (
            "a document that is not valid",
            json!({
                "version": 3, "revision": 1, "network": { "proxy_url": proxy.http() },
                "bogus": 1
            }),
        ),
    ];
    for (why, document) in unusable {
        let tree = Tree::create();
        tree.write_document(&document);
        let before = tree.document_bytes();
        let output = tree.kr(&[
            "host",
            "network",
            "--join",
            "--service",
            &origin,
            "--unsigned",
        ]);
        assert_eq!(output.status.code(), Some(2), "{why}: {}", said(&output));
        assert_eq!(tree.document_bytes(), before, "{why}: nothing was written");
    }
    assert_eq!(service.accepted(), 0, "no request went to the service");
    assert_eq!(proxy.accepted(), 0, "and none to the proxy");

    // The control: a document that can be used does reach a service, so the count above means
    // something; and a plain http service is not asked for through a proxy at all.
    let tree = Tree::create();
    tree.write_document(&json!({ "version": 3, "revision": 1 }));
    let output = tree.kr(&[
        "host",
        "network",
        "--join",
        "--service",
        &origin,
        "--unsigned",
    ]);
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert!(
        service.accepted() >= 1,
        "a usable document reaches the service"
    );
    let reached = service.accepted();
    let tree = Tree::create();
    tree.write_document(&usable);
    let output = tree.kr(&[
        "host",
        "network",
        "--join",
        "--service",
        &origin,
        "--unsigned",
    ]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a plain http service is not asked for through a proxy: {}",
        said(&output)
    );
    assert_eq!(
        service.accepted(),
        reached,
        "so the service was not reached"
    );
    assert_eq!(proxy.accepted(), 0, "nor the proxy");
}

/// The request goes through the proxy the document names and never round it: a proxy that refuses
/// connections ends the command, and the service itself is not reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_request_goes_through_the_proxy_the_document_names_and_never_round_it() {
    let service = Counting::start();
    let origin = service.https();
    let through = |proxy: Option<String>| {
        let tree = Tree::create();
        let mut document = json!({ "version": 3, "revision": 1 });
        if let Some(proxy) = proxy {
            document["network"] = json!({ "proxy_url": proxy });
        }
        tree.write_document(&document);
        let output = tree.kr(&[
            "host",
            "network",
            "--join",
            "--service",
            &origin,
            "--unsigned",
        ]);
        assert_eq!(output.status.code(), Some(1), "{}", said(&output));
        output
    };

    // The control: with no proxy the command goes to the service itself.
    through(None);
    let direct = service.accepted();
    assert!(direct >= 1, "with no proxy the service is reached");

    // With a proxy that refuses connections the service is not reached.
    through(Some(format!("http://127.0.0.1:{}", closed_port())));
    assert_eq!(
        service.accepted(),
        direct,
        "the request did not go round the proxy"
    );
}
