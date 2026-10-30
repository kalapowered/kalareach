//! The push gateway a build registers with, shown by building.
//!
//! Each case builds a small package of its own around the code the companion's build runs: the
//! package's build script is the companion's `build_push_gateway.rs` over `push_origin.rs`, and its
//! library reads the origin from the record the build step wrote, as the companion's library does.
//! So what a case sees is what the companion's build step does with the build's inputs, and what
//! the program built by it reads back. A case sets the inputs the way a builder would: in the
//! environment, or in the `[env]` table of a Cargo configuration file, which a case writes into its
//! own scratch directory and never anywhere a person's own Cargo reads.

use std::path::{Path, PathBuf};
use std::process::Command;

const PUSH_GATEWAY_INPUT: &str = "KR_PUSH_GATEWAY_ORIGIN";
const OFFICIAL_BUILD_MARK: &str = "KR_OFFICIAL_BUILD";
const OWN_GATEWAY: &str = "https://push.builder.example";

/// What one build of the scratch package gave.
struct Built {
    succeeded: bool,
    /// What the build said: Cargo's own report, with the build step's warnings and its refusal.
    said: String,
    /// What the program built by it printed: the origin its library read from the record.
    recorded: String,
}

/// A build of the scratch package, set up by the inputs a builder gives.
struct Case {
    name: &'static str,
    /// The build inputs in the environment of the build.
    environment: Vec<(&'static str, &'static str)>,
    /// The text of a Cargo configuration file beside the package, or none.
    configuration: Option<String>,
}

impl Case {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            environment: Vec::new(),
            configuration: None,
        }
    }

    fn with(mut self, input: &'static str, value: &'static str) -> Self {
        self.environment.push((input, value));
        self
    }

    fn configured(mut self, text: String) -> Self {
        self.configuration = Some(text);
        self
    }

    /// Builds and runs the scratch package.
    fn build(&self) -> Built {
        let companion = Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = companion.ancestors().nth(3).expect("the workspace's root");
        let scratch = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join("push-gateway-build")
            .join(self.name);
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(scratch.join("src")).expect("a scratch package");
        let write = |name: &str, text: String| {
            let path = scratch.join(name);
            std::fs::create_dir_all(path.parent().expect("a directory")).expect("a directory");
            std::fs::write(path, text).expect("a scratch file");
        };

        let package = format!("push-gateway-{}", self.name.replace('_', "-"));
        let protocol = slashed(&root.join("crates").join("kr-protocol"));
        write(
            "Cargo.toml",
            format!(
                "[package]\nname = '{package}'\nversion = '0.0.0'\nedition = '2024'\npublish = false\n\n\
                 [workspace]\n\n\
                 [dependencies]\nkr-protocol = {{ path = '{protocol}' }}\n\n\
                 [build-dependencies]\nkr-protocol = {{ path = '{protocol}' }}\n"
            ),
        );
        let shared = format!(
            "#[allow(dead_code, unused_imports, unused_macros)]\n\
             #[path = \"{}\"]\nmod push_origin;\n",
            slashed(&companion.join("src").join("push_origin.rs"))
        );
        write(
            "build.rs",
            format!(
                "{shared}#[path = \"{}\"]\nmod build_push_gateway;\n\n\
                 fn main() {{\n    build_push_gateway::run();\n}}\n",
                slashed(&companion.join("build_push_gateway.rs"))
            ),
        );
        write(
            "src/lib.rs",
            format!(
                "{shared}\n/// The origin the build recorded, as the companion's library reads it.\n\
                 pub fn recorded() -> &'static str {{\n    \
                 push_origin::given_by(push_origin::the_builds_record!()).expect(\"a record\")\n}}\n"
            ),
        );
        let library = package.replace('-', "_");
        write(
            "src/main.rs",
            format!("fn main() {{\n    print!(\"{{}}\", {library}::recorded());\n}}\n"),
        );
        std::fs::copy(root.join("Cargo.lock"), scratch.join("Cargo.lock")).expect("the lock file");
        if let Some(text) = &self.configuration {
            write(".cargo/config.toml", text.clone());
        }

        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let mut command = Command::new(cargo);
        command
            .arg("run")
            .arg("--offline")
            .arg("--color=never")
            .arg("--manifest-path")
            .arg(scratch.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(target_directory())
            .current_dir(&scratch);
        // What the outer build and test run set for themselves, and the inputs under test, are not
        // this build's: the case gives the inputs it means.
        for (name, _) in std::env::vars_os() {
            if name.to_str().is_some_and(is_set_by_the_outer_run) {
                command.env_remove(name);
            }
        }
        for (input, value) in &self.environment {
            command.env(input, value);
        }
        let output = command.output().expect("cargo runs");
        Built {
            succeeded: output.status.success(),
            said: String::from_utf8_lossy(&output.stderr).into_owned(),
            recorded: String::from_utf8_lossy(&output.stdout).into_owned(),
        }
    }
}

/// The target directory every case builds into, so the protocol crate is compiled once.
fn target_directory() -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join("push-gateway-build-target")
}

/// Whether the environment variable `name` belongs to the run of this test and not to a build of
/// the scratch package.
fn is_set_by_the_outer_run(name: &str) -> bool {
    const OWN_PREFIXES: [&str; 5] = [
        "CARGO_PKG_",
        "CARGO_BIN_",
        "CARGO_CRATE_",
        "CARGO_MANIFEST_",
        "CARGO_PRIMARY_",
    ];
    const OWN_NAMES: [&str; 4] = [
        "CARGO_TARGET_TMPDIR",
        "CARGO_ENCODED_RUSTFLAGS",
        PUSH_GATEWAY_INPUT,
        OFFICIAL_BUILD_MARK,
    ];
    OWN_PREFIXES.iter().any(|prefix| name.starts_with(prefix)) || OWN_NAMES.contains(&name)
}

/// `path` as the forward-slashed text Cargo and Rust accept on every platform.
fn slashed(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// A Cargo configuration file whose `[env]` table gives the push gateway input.
fn configuration_giving(input: &str, value: &str) -> String {
    format!("[env]\n{input} = '{value}'\n")
}

fn announces(said: &str, origin: &str) -> bool {
    said.contains(&format!(
        "this build registers with the push gateway at {origin}"
    ))
}

/// A build given no gateway records none and says nothing: it talks to the managed service's
/// gateway, as it did before the input existed.
#[test]
fn a_build_given_no_gateway_records_none_and_says_nothing() {
    let built = Case::new("given_none").build();
    assert!(built.succeeded, "{}", built.said);
    assert_eq!(built.recorded, "");
    assert!(!built.said.contains("registers with the push gateway"));
}

/// KR-REQ-16.04: a build given a gateway registers with that gateway: the build says so, and the
/// program it built reads the same origin back from the record, since the record is where the
/// library gets it.
#[test]
fn a_build_given_a_gateway_says_so_and_the_program_it_builds_reads_the_same_origin() {
    let built = Case::new("given_own")
        .with(PUSH_GATEWAY_INPUT, OWN_GATEWAY)
        .build();
    assert!(built.succeeded, "{}", built.said);
    assert!(announces(&built.said, OWN_GATEWAY), "{}", built.said);
    assert_eq!(built.recorded, OWN_GATEWAY);
}

/// A Cargo configuration file's `[env]` table reaches the build the way the environment does, so
/// the input can arrive by a file the builder's shell never shows.
#[test]
fn a_gateway_a_cargo_configuration_adds_reaches_the_build_like_one_in_the_environment() {
    let built = Case::new("configured_own")
        .configured(configuration_giving(PUSH_GATEWAY_INPUT, OWN_GATEWAY))
        .build();
    assert!(built.succeeded, "{}", built.said);
    assert!(announces(&built.said, OWN_GATEWAY), "{}", built.said);
    assert_eq!(built.recorded, OWN_GATEWAY);
}

/// KR-REQ-16.04: an official build registers with the official gateway whatever its Cargo
/// configuration adds. A script that unsets the input in its shell does not stop a configuration
/// file from setting it again, so the build is marked, and the mark refuses the input however it
/// arrived.
#[test]
fn an_official_build_refuses_a_gateway_a_cargo_configuration_adds() {
    let built = Case::new("official_configured")
        .with(OFFICIAL_BUILD_MARK, "1")
        .configured(configuration_giving(PUSH_GATEWAY_INPUT, OWN_GATEWAY))
        .build();
    assert!(!built.succeeded, "{}", built.said);
    assert!(built.said.contains(OFFICIAL_BUILD_MARK), "{}", built.said);
    assert_eq!(built.recorded, "");
}

/// KR-REQ-16.04: an official build refuses a gateway in its environment too, and one given the
/// official gateway's own text, since it is given none.
#[test]
fn an_official_build_refuses_a_gateway_in_its_environment() {
    for (name, value) in [
        ("official_environment", OWN_GATEWAY),
        ("official_own_text", "https://reach.kala.to"),
    ] {
        let built = Case::new(name)
            .with(OFFICIAL_BUILD_MARK, "1")
            .with(PUSH_GATEWAY_INPUT, value)
            .build();
        assert!(!built.succeeded, "{value}: {}", built.said);
        assert!(built.said.contains(OFFICIAL_BUILD_MARK), "{}", built.said);
    }
}

/// An official build given no gateway builds, and records none: it registers with the official one.
#[test]
fn an_official_build_given_no_gateway_builds_and_records_none() {
    let built = Case::new("official_none")
        .with(OFFICIAL_BUILD_MARK, "1")
        .build();
    assert!(built.succeeded, "{}", built.said);
    assert_eq!(built.recorded, "");
}

/// A value that is not an `https` origin stops the build rather than giving an application that
/// cannot register.
#[test]
fn a_gateway_that_is_not_an_https_origin_stops_the_build() {
    let built = Case::new("malformed")
        .with(PUSH_GATEWAY_INPUT, "http://push.builder.example")
        .build();
    assert!(!built.succeeded, "{}", built.said);
    assert!(built.said.contains(PUSH_GATEWAY_INPUT), "{}", built.said);
}
