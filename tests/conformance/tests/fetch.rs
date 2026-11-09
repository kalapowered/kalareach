//! The fetch of the pinned applications: what the script says when a release cannot be fetched,
//! what it builds then, and what it takes from an archive the cache already holds.
//!
//! Each case runs `scripts/run-conformance.sh --group applications` as it is committed, from a copy
//! of the tree that holds the script and a lock of its own. `curl` is replaced by a program that
//! serves the files of one directory and refuses every other address as a host that answers 504
//! does, and `cargo` and the report's own program by programs that do nothing, so that the run ends
//! when the fetch has.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use tempfile::TempDir;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// Serves the file of `$STUB_SERVE` that the address names, and refuses any other.
const CURL: &str = "#!/bin/sh
out=
url=
while [ $# -gt 0 ]; do
    case \"$1\" in
        -o) out=$2; shift ;;
        --retry|--retry-delay|--retry-max-time|--connect-timeout|--max-time) shift ;;
        -*) ;;
        *) url=$1 ;;
    esac
    shift
done
echo \"$url\" >> \"$STUB_LOG\"
file=\"$STUB_SERVE/${url##*/}\"
if [ -f \"$file\" ]; then
    cp \"$file\" \"$out\"
    exit 0
fi
echo 'curl: (22) The requested URL returned error: 504' >&2
exit 22
";

/// A program that does nothing and succeeds.
const NOTHING: &str = "#!/bin/sh\nexit 0\n";

/// A copy of the tree the script reads, with the programs it runs replaced.
struct Stage {
    root: TempDir,
}

impl Stage {
    fn new() -> Self {
        let stage = Self {
            root: TempDir::new().expect("a directory for the case"),
        };
        for directory in [
            "tree/scripts",
            "tree/tests/conformance",
            "served",
            "stubs",
            "work",
            "cache",
            "tmp",
            "evidence",
            "target/debug",
        ] {
            fs::create_dir_all(stage.path(directory)).expect("a directory");
        }
        fs::copy(
            repository().join("scripts/run-conformance.sh"),
            stage.path("tree/scripts/run-conformance.sh"),
        )
        .expect("the script is copied");
        stage.program("stubs/curl", CURL);
        stage.program("stubs/cargo", NOTHING);
        stage.program("target/debug/kr-conformance", NOTHING);
        stage
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.path().join(relative)
    }

    fn program(&self, relative: &str, text: &str) {
        let path = self.path(relative);
        fs::write(&path, text).expect("a program");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("executable");
    }

    /// Packs `files` (a path, its text and its mode) into `served/<name>.tar.gz` under one top
    /// directory, and returns the archive's SHA-256.
    fn archive(&self, name: &str, files: &[(&str, String, u32)]) -> String {
        for (relative, text, mode) in files {
            let path = self.path(&format!("work/{name}/{relative}"));
            fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
            fs::write(&path, text).expect("a file");
            fs::set_permissions(&path, fs::Permissions::from_mode(*mode)).expect("a mode");
        }
        let archive = self.path(&format!("served/{name}.tar.gz"));
        let packed = Command::new("tar")
            .env("COPYFILE_DISABLE", "1")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(self.path("work"))
            .arg(name)
            .status()
            .expect("tar runs");
        assert!(packed.success(), "{name} is packed");
        digest(&archive)
    }

    /// A release that is taken as it is: one program.
    fn release(&self, name: &str) -> String {
        self.archive(
            name,
            &[(
                &format!("bin/{name}"),
                "#!/bin/sh\nexit 0\n".to_owned(),
                0o755,
            )],
        )
    }

    /// A release built from its source: a `configure` that leaves its mark and writes a makefile
    /// that installs `file` under `directory` of the prefix.
    fn source(&self, name: &str, directory: &str, file: &str) -> String {
        let mark = self.path(&format!("marks/{name}"));
        fs::create_dir_all(self.path("marks")).expect("a directory");
        let configure = format!(
            "#!/bin/sh
prefix=
for argument in \"$@\"; do
    case \"$argument\" in
        --prefix=*) prefix=\"${{argument#--prefix=}}\" ;;
    esac
done
echo built > '{mark}'
{{
    echo 'all:'
    printf '\\t@true\\n'
    echo 'install:'
    printf '\\tmkdir -p \"%s/{directory}\"\\n' \"$prefix\"
    printf '\\tcp built \"%s/{directory}/{file}\"\\n' \"$prefix\"
}} > Makefile
",
            mark = mark.display(),
        );
        self.archive(
            name,
            &[
                ("configure", configure, 0o755),
                ("built", "#!/bin/sh\nexit 0\n".to_owned(), 0o755),
            ],
        )
    }

    /// Whether the build of `name` was started.
    fn built(&self, name: &str) -> bool {
        self.path(&format!("marks/{name}")).exists()
    }

    fn write_lock(&self, applications: &[Value]) {
        let lock = json!({ "lock_version": 1, "description": "a lock of the case's own", "applications": applications });
        fs::write(
            self.path("tree/tests/conformance/applications.lock"),
            serde_json::to_string_pretty(&lock).expect("JSON"),
        )
        .expect("the lock");
    }

    fn run(&self) -> Output {
        let path = format!(
            "{}:{}",
            self.path("stubs").display(),
            std::env::var("PATH").expect("a path")
        );
        Command::new("bash")
            .arg(self.path("tree/scripts/run-conformance.sh"))
            .args(["--group", "applications"])
            .env("PATH", path)
            .env("TMPDIR", self.path("tmp"))
            .env("KR_CONFORMANCE_APPLICATIONS", self.path("cache"))
            .env("KR_TEST_ARTIFACTS_DIR", self.path("evidence"))
            .env("CARGO_TARGET_DIR", self.path("target"))
            .env("STUB_SERVE", self.path("served"))
            .env("STUB_LOG", self.path("asked.log"))
            .output()
            .expect("the script runs")
    }

    /// The addresses the stand-in `curl` was asked for.
    fn asked(&self) -> String {
        fs::read_to_string(self.path("asked.log")).unwrap_or_default()
    }

    /// What the cache's index says of a program.
    fn index_of(&self, id: &str) -> Value {
        let index: Value = serde_json::from_str(
            &fs::read_to_string(self.path("cache/index.json")).expect("the index"),
        )
        .expect("JSON");
        index["applications"]
            .as_array()
            .expect("applications")
            .iter()
            .find(|entry| entry["id"] == id)
            .unwrap_or_else(|| panic!("the index names {id}"))
            .clone()
    }
}

fn digest(path: &Path) -> String {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .or_else(|_| {
            Command::new("shasum")
                .args(["-a", "256"])
                .arg(path)
                .output()
        })
        .expect("a digest tool");
    String::from_utf8(output.stdout)
        .expect("text")
        .split_whitespace()
        .next()
        .expect("a digest")
        .to_owned()
}

fn address(name: &str) -> String {
    format!("https://example.invalid/{name}.tar.gz")
}

fn source_of(name: &str, sha256: &str, extra: &Value) -> Value {
    let mut source = json!({
        "platform": "unix",
        "url": address(name),
        "sha256": sha256,
        "strip_components": 1,
    });
    for (key, value) in extra.as_object().expect("an object") {
        source[key] = value.clone();
    }
    source
}

fn application(id: &str, role: &str, source: &Value) -> Value {
    json!({ "id": id, "name": id, "version": "1.0", "role": role, "sources": [source] })
}

/// The library a program is built against, a program that needs it, and a program taken as it is.
fn lock_of(stage: &Stage) -> Vec<Value> {
    let library = stage.source("libone", "lib", "libone.a");
    let needing = stage.source("needs-one", "bin", "needs-one");
    let plain = stage.release("plain");
    vec![
        application(
            "libone",
            "library",
            &source_of("libone", &library, &json!({ "build": { "configure": [] } })),
        ),
        application(
            "needs-one",
            "program",
            &source_of(
                "needs-one",
                &needing,
                &json!({
                    "executable": "bin/needs-one",
                    "build": { "configure": [], "libraries": ["libone"] },
                }),
            ),
        ),
        application(
            "plain",
            "program",
            &source_of("plain", &plain, &json!({ "executable": "bin/plain" })),
        ),
    ]
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// A release its host does not serve is named by its address, with what it cost, and a program
/// that is built against a library that could not be fetched is not built: its own build would
/// stop at a configure step with a log that says nothing of why the library is missing.
#[test]
fn a_release_that_cannot_be_fetched_is_named_and_what_needs_it_is_not_built() {
    let stage = Stage::new();
    let mut lock = lock_of(&stage);
    // The host answers 504 for the library and for a program of its own.
    fs::remove_file(stage.path("served/libone.tar.gz")).expect("the library is not served");
    lock.push(application(
        "unserved",
        "program",
        &source_of(
            "unserved",
            &"0".repeat(64),
            &json!({ "executable": "bin/unserved" }),
        ),
    ));
    stage.write_lock(&lock);

    let output = stage.run();
    let text = said(&output);
    assert!(output.status.success(), "the run goes on: {text}");

    assert!(
        text.lines()
            .any(|line| line.contains(&address("libone")) && line.contains("could not be fetched")),
        "the library is named by its address: {text}"
    );
    let unserved = stage.index_of("unserved");
    assert_eq!(unserved["status"], "unavailable");
    assert!(
        unserved["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains(&address("unserved"))),
        "the reason names the address: {unserved}"
    );

    let needing = stage.index_of("needs-one");
    assert_eq!(needing["status"], "unavailable", "{text}");
    assert!(
        needing["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("libone")),
        "the reason names the library: {needing}"
    );
    assert!(
        !stage.built("needs-one"),
        "its build was not started: {text}"
    );

    // What does not depend on it is not lost with it.
    assert_eq!(stage.index_of("plain")["status"], "installed", "{text}");
}

/// A program is built against the library it needs when that was fetched, and an archive the cache
/// holds is used only when it is the pinned bytes: one under the pin's name that is not them is
/// fetched again, and bytes the host serves that are not them are never installed.
#[test]
fn an_archive_the_cache_holds_is_used_only_when_it_is_the_pinned_bytes() {
    let stage = Stage::new();
    let mut lock = lock_of(&stage);
    // A program whose host serves bytes that are not the pin's.
    let pinned = stage.release("tampered");
    fs::write(
        stage.path("served/tampered.tar.gz"),
        b"not the pinned bytes",
    )
    .expect("served");
    lock.push(application(
        "tampered",
        "program",
        &source_of(
            "tampered",
            &pinned,
            &json!({ "executable": "bin/tampered" }),
        ),
    ));
    stage.write_lock(&lock);

    // The cache holds the library's archive as pinned, and a program's under its pin's name with
    // other bytes.
    fs::create_dir_all(stage.path("cache/archives")).expect("the archives");
    let library = digest(&stage.path("served/libone.tar.gz"));
    fs::copy(
        stage.path("served/libone.tar.gz"),
        stage.path(&format!("cache/archives/{library}.tar.gz")),
    )
    .expect("held");
    let plain = digest(&stage.path("served/plain.tar.gz"));
    fs::write(
        stage.path(&format!("cache/archives/{plain}.tar.gz")),
        b"bytes that are not the pin's",
    )
    .expect("held");

    let output = stage.run();
    let text = said(&output);
    assert!(output.status.success(), "{text}");

    let asked = stage.asked();
    assert!(
        !asked.contains(&address("libone")),
        "the pinned archive the cache holds is not fetched again: {asked}"
    );
    assert!(
        asked.contains(&address("plain")),
        "the archive that is not the pin's is fetched again: {asked}"
    );
    assert!(
        stage.built("needs-one"),
        "the library reached what needs it: {text}"
    );
    for installed in ["needs-one", "plain"] {
        assert_eq!(stage.index_of(installed)["status"], "installed", "{text}");
    }
    let tampered = stage.index_of("tampered");
    assert_eq!(tampered["status"], "unavailable", "{text}");
    assert!(
        !stage.path("cache/tampered/1.0").exists(),
        "bytes that are not the pin's are not installed: {text}"
    );
}
