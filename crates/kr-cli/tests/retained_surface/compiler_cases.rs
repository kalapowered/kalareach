//! The cases of the compiler's reading: the stamp, the report of each way Rust binds a name (one
//! crate of a fixture workspace for each, built by the pinned compiler), the closed check and each
//! refusal with its text. The reading of this checkout and of the release tags are ignored cases that
//! the box steps run.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::OnceLock;

use super::compiler::{
    self, Candidate, Meta, OUTSIDE_PROC_MACROS, PLAN, Platform, Report, SightKind, Sighting,
    Stamped, refusal,
};

fn write(root: &Path, path: &str, text: &str) {
    let file = root.join(path);
    std::fs::create_dir_all(file.parent().expect("a folder")).expect("the folder");
    std::fs::write(file, text).expect("the file");
}

fn manifest(name: &str, dependencies: &str) -> String {
    format!(
        "[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\n{dependencies}"
    )
}

const METHOD: &str = r#"macro_rules! methods {
    ($($variant:ident = $name:literal;)+) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Method {
            $(
                $variant,
            )+
        }

        impl Method {
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            pub fn from_wire(value: &str) -> Option<Self> {
                match value {
                    $($name => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

methods! {
    AgentPromptSubmit = "agent.prompt.submit";
    AgentPromptQueue = "agent.prompt.queue";
    AgentTurnSteer = "agent.turn.steer";
    AgentTurnCancel = "agent.turn.cancel";
    AgentApprovalRespond = "agent.approval.respond";
    PluginActionInvoke = "plugin.action.invoke";
    SessionOpen = "session.open";
}
"#;

const ENVELOPE: &str = r#"pub type EnvironmentId = u32;

pub struct ActionTarget {
    pub environment_id: EnvironmentId,
    pub session_id: Option<u32>,
}

impl ActionTarget {
    pub const fn environment(environment_id: EnvironmentId) -> Self {
        Self {
            environment_id,
            session_id: None,
        }
    }
}

pub struct MutationRequest {
    pub request_id: u32,
    pub method: crate::method::Method,
    pub target: ActionTarget,
}
"#;

const RIGHTS: &str = "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub enum ActionRight {\n    AgentTurnCancel,\n    SessionOpen,\n}\n";

/// The protocol crate of a fixture: the stamped places in the shape the real one has them.
fn protocol(root: &Path) {
    write(
        root,
        "crates/kr-protocol/Cargo.toml",
        &manifest("kr-protocol", ""),
    );
    write(
        root,
        "crates/kr-protocol/src/lib.rs",
        "pub mod envelope;\npub mod method;\npub mod rights;\n",
    );
    write(root, "crates/kr-protocol/src/method.rs", METHOD);
    write(root, "crates/kr-protocol/src/envelope.rs", ENVELOPE);
    write(root, "crates/kr-protocol/src/rights.rs", RIGHTS);
    for receiver in ["kr-controller", "kr-worker"] {
        write(
            root,
            &format!("crates/{receiver}/Cargo.toml"),
            &manifest(receiver, ""),
        );
        write(root, &format!("crates/{receiver}/src/lib.rs"), "");
    }
}

const FORMS: &str = r#"use kr_protocol::envelope::{ActionTarget, MutationRequest};
use kr_protocol::method::Method;
use kr_protocol::method::Method as Renamed;
use kr_protocol::method::Method::PluginActionInvoke;
use kr_protocol::rights::ActionRight;

include!("included.rs");

#[path = "elsewhere/other.rs"]
pub mod elsewhere;

pub fn direct() -> Method {
    Method::AgentTurnCancel
}

pub fn pattern(method: Method) -> u8 {
    match method {
        Method::AgentTurnSteer => 1,
        _ => 0,
    }
}

type Alias = Method;

pub fn through_alias() -> Alias {
    Alias::AgentPromptQueue
}

pub fn through_rename() -> Renamed {
    Renamed::AgentPromptSubmit
}

pub fn qualified() -> Method {
    <Method>::AgentApprovalRespond
}

pub fn raw() -> Method {
    Method::r#AgentTurnCancel
}

#[allow(deprecated)]
pub fn allowed() -> Method {
    Method::AgentTurnCancel
}

macro_rules! cancel {
    () => {
        Method::AgentTurnCancel
    };
}

pub fn from_macro() -> Method {
    cancel!()
}

macro_rules! named {
    ($variant:ident) => {
        Method::$variant
    };
}

pub fn from_argument() -> Method {
    named!(AgentTurnSteer)
}

pub fn request() -> MutationRequest {
    MutationRequest {
        request_id: 1,
        method: Method::SessionOpen,
        target: ActionTarget::environment(7),
    }
}

pub struct Wrapper(pub u32);

impl From<Wrapper> for ActionTarget {
    fn from(wrapper: Wrapper) -> Self {
        Self {
            environment_id: wrapper.0,
            session_id: None,
        }
    }
}

pub fn from_data() -> Option<Method> {
    Method::from_wire("agent.prompt.queue")
}

pub fn literal() -> &'static str {
    "agent.turn.cancel"
}

#[cfg(target_os = "ios")]
pub fn mobile_only() -> Method {
    Method::AgentTurnCancel
}

#[cfg(windows)]
pub fn windows_only() -> Method {
    Method::AgentPromptSubmit
}

pub enum Local {
    AgentTurnCancel,
}

pub fn right() -> ActionRight {
    ActionRight::AgentTurnCancel
}

pub fn imported() -> Method {
    PluginActionInvoke
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_test_builds_it() {
        let _ = Method::AgentTurnCancel;
    }
}
"#;

/// A workspace with the protocol crate and the one client crate that holds a function for each way a
/// client names what the compiler reports.
fn forms(root: &Path) {
    write(
        root,
        "Cargo.toml",
        "[workspace]\nresolver = \"2\"\nmembers = [\"crates/*\"]\n",
    );
    protocol(root);
    write(
        root,
        "crates/kr-forms/Cargo.toml",
        &manifest("kr-forms", "kr-protocol = { path = \"../kr-protocol\" }\n"),
    );
    write(root, "crates/kr-forms/src/lib.rs", FORMS);
    write(
        root,
        "crates/kr-forms/src/included.rs",
        "pub fn included() -> Method {\n    Method::AgentPromptSubmit\n}\n",
    );
    write(
        root,
        "crates/kr-forms/src/elsewhere/other.rs",
        "use kr_protocol::method::Method;\n\npub fn elsewhere() -> Method {\n    Method::AgentTurnSteer\n}\n",
    );
    write(
        root,
        "crates/kr-forms/src/orphan.rs",
        "use kr_protocol::method::Method;\n\npub fn orphan() -> Method {\n    Method::AgentTurnCancel\n}\n",
    );
}

/// The fixture workspace, stamped and built once for every case, with its report.
fn built() -> &'static (tempfile::TempDir, Stamped, Platform) {
    static BUILT: OnceLock<(tempfile::TempDir, Stamped, Platform)> = OnceLock::new();
    BUILT.get_or_init(|| {
        let root = tempfile::tempdir().expect("a folder");
        forms(root.path());
        let lock = compiler::cargo_command()
            .args(["generate-lockfile", "--offline"])
            .current_dir(root.path())
            .output()
            .expect("cargo runs");
        assert!(
            lock.status.success(),
            "{}",
            String::from_utf8_lossy(&lock.stderr)
        );
        // The unstamped tree is the one that is read for its items and its tokens; the stamped copy is
        // the one that is built.
        let scratch = tempfile::tempdir().expect("a folder");
        compiler::copy_tree(root.path(), scratch.path());
        let target = tempfile::tempdir().expect("a folder");
        let platform = compiler::read_platform(
            scratch.path(),
            target.path(),
            compiler::host_name(),
            "forms",
            "forms",
        );
        let stamped = platform.stamped.clone();
        (root, stamped, platform)
    })
}

fn shown(sightings: &[Sighting]) -> Vec<String> {
    let mut all: Vec<String> = sightings
        .iter()
        .map(|sighting| {
            let kinds: Vec<String> = sighting
                .kinds
                .iter()
                .map(|kind| format!("{kind:?}"))
                .collect();
            format!("{} {} {}", sighting.krate, sighting.name, kinds.join("+"))
        })
        .collect();
    all.sort();
    all
}

fn read_forms() -> compiler::Reading {
    let (root, _, platform) = built();
    let meta = compiler::metadata(root.path()).expect("the metadata");
    compiler::merge(
        root.path(),
        &meta,
        &[platform.clone()],
        &[compiler::host_name()],
        &[],
    )
}

#[test]
fn the_stamp_marks_the_variants_the_fields_and_the_accessors_a_tree_has() {
    let root = tempfile::tempdir().expect("a folder");
    protocol(root.path());
    let stamped = compiler::stamp(root.path()).expect("the stamp");
    assert_eq!(
        stamped,
        Stamped {
            variants: true,
            fields: 5,
            accessors: vec![
                "Method::ALL",
                "Method::from_wire",
                "ActionTarget::environment"
            ],
        }
    );
    let method = std::fs::read_to_string(root.path().join("crates/kr-protocol/src/method.rs"))
        .expect("the file");
    assert!(
        method.contains("#[deprecated(note = $name)]\n                $variant,"),
        "{method}"
    );
    let envelope = std::fs::read_to_string(root.path().join("crates/kr-protocol/src/envelope.rs"))
        .expect("the file");
    assert!(
        envelope
            .contains("#[deprecated(note = \"MutationRequest.target\")] pub target: ActionTarget,"),
        "{envelope}"
    );
    assert!(
        envelope
            .contains("#[deprecated(note = \"ActionTarget.environment_id\")] pub environment_id")
    );
    // The notes are what a report is read by.
    for (note, kind) in [
        ("agent.turn.cancel", Some(SightKind::Names)),
        ("session.open", None),
        ("Method::from_wire", Some(SightKind::Names)),
        ("ActionTarget.session_id", Some(SightKind::Target)),
        ("ActionTarget::environment", Some(SightKind::Target)),
        ("MutationRequest.method", Some(SightKind::Request)),
        ("Actions.target", None),
    ] {
        assert_eq!(compiler::kind_of(note), kind, "{note}");
    }
}

#[test]
fn a_tree_the_stamp_cannot_mark_in_each_place_is_refused_with_the_text() {
    let doubled = tempfile::tempdir().expect("a folder");
    protocol(doubled.path());
    let method = doubled.path().join("crates/kr-protocol/src/method.rs");
    let text = std::fs::read_to_string(&method).expect("the file");
    std::fs::write(
        &method,
        text.replace("methods! {", "                $variant,\nmethods! {"),
    )
    .expect("the file");
    let error = compiler::stamp(doubled.path()).expect_err("two lines");
    assert!(
        error.contains("the stamp needs one line `$variant,`"),
        "{error}"
    );
    assert!(error.contains("and finds 2"), "{error}");

    let without = tempfile::tempdir().expect("a folder");
    protocol(without.path());
    write(
        without.path(),
        "crates/kr-protocol/src/envelope.rs",
        &ENVELOPE.replace("pub struct MutationRequest {", "pub struct Other {"),
    );
    let error = compiler::stamp(without.path()).expect_err("no struct");
    assert!(
        error.contains("the stamp needs one file under")
            && error.contains("pub struct MutationRequest {"),
        "{error}"
    );
}

#[test]
fn each_way_a_client_names_a_stamped_item_is_read_by_the_compiler_and_the_rest_is_unread() {
    let sightings = read_forms().expect("the forms are read");
    assert_eq!(
        shown(&sightings),
        [
            "kr_forms ActionTarget::from Target",
            "kr_forms Local Unread",
            "kr_forms direct Names",
            "kr_forms elsewhere Names",
            "kr_forms from_argument Names",
            "kr_forms from_data Names+Unread",
            "kr_forms from_macro Names",
            "kr_forms imported Names",
            "kr_forms literal Unread",
            "kr_forms macro:cancel Expands",
            "kr_forms mobile_only Unread",
            "kr_forms orphan Unread",
            "kr_forms pattern Names",
            "kr_forms qualified Names",
            "kr_forms raw Names",
            "kr_forms request Request+Target",
            "kr_forms through_alias Names",
            "kr_forms through_rename Names",
            "kr_forms use:crates/kr-forms/src/lib.rs Names",
            "kr_forms windows_only Names",
            "kr_forms allowed Names",
            "kr_forms included Names",
        ]
        .iter()
        .map(|line| (*line).to_owned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
    );
}

#[test]
fn a_function_a_test_alone_builds_gives_no_sighting_and_no_unread_token() {
    let sightings = read_forms().expect("the forms are read");
    assert!(
        !sightings
            .iter()
            .any(|sighting| sighting.name.contains("only_a_test_builds_it")),
        "{sightings:?}"
    );
    let (_, _, platform) = built();
    assert!(
        platform
            .reports
            .iter()
            .any(|report| report.test_only && report.krate == "kr_forms"),
        "no report is marked as test-only"
    );
}

#[test]
fn the_canary_and_the_count_of_stamped_items_show_that_the_stamp_took() {
    let (_, stamped, platform) = built();
    assert_eq!(
        stamped,
        &Stamped {
            variants: true,
            fields: 5,
            accessors: vec![
                "Method::ALL",
                "Method::from_wire",
                "ActionTarget::environment"
            ],
        }
    );
    assert_eq!(
        platform.canary,
        Ok(7),
        "every variant of the transcriber is reported"
    );
    assert_eq!(
        platform
            .builds
            .iter()
            .map(|(name, exit, finished)| (name.as_str(), *exit, *finished))
            .collect::<Vec<_>>(),
        PLAN.iter()
            .map(|config| (config.name, 0, true))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_reader_that_drops_the_reports_of_a_name_is_refused_by_the_closed_check_with_unread_tokens() {
    let (root, _, platform) = built();
    let meta = compiler::metadata(root.path()).expect("the metadata");
    let mut weakened = platform.clone();
    weakened
        .reports
        .retain(|report| compiler::kind_of(&report.note) != Some(SightKind::Names));
    let sightings = compiler::merge(
        root.path(),
        &meta,
        &[weakened],
        &[compiler::host_name()],
        &[],
    )
    .expect("the reading is complete");
    let unread: BTreeSet<&str> = sightings
        .iter()
        .filter(|sighting| sighting.kinds.contains(&SightKind::Unread))
        .map(|sighting| sighting.name.as_str())
        .collect();
    for name in [
        "direct",
        "pattern",
        "through_alias",
        "macro:cancel",
        "from_argument",
        "windows_only",
        "included",
    ] {
        assert!(
            unread.contains(name),
            "{name} is read by nothing and is not unread: {unread:?}"
        );
    }
    let mut empty = platform.clone();
    empty.reports.clear();
    let sightings = compiler::merge(root.path(), &meta, &[empty], &[compiler::host_name()], &[])
        .expect("the reading is complete");
    assert!(
        sightings
            .iter()
            .all(|sighting| sighting.kinds == BTreeSet::from([SightKind::Unread])),
        "{sightings:?}"
    );
}

fn tokens(text: &str) -> Vec<(String, usize)> {
    compiler::candidates(text, "a.rs")
        .expect("the tokens")
        .into_iter()
        .map(|Candidate { what, line, .. }| (what, line))
        .collect()
}

#[test]
fn a_token_that_names_a_stamped_item_is_found_in_a_group_a_raw_name_and_a_literal_of_any_form() {
    let found = tokens(
        "fn a() { f(Method::AgentTurnCancel); }\n\
         fn b() { g!(Method::r#AgentPromptQueue); }\n\
         fn c() { let _ = ActionRight::AgentTurnCancel; let _ = ActionRight::AgentTurnSteer; }\n\
         fn d() -> (&'static str, &'static [u8]) { (r#\"x agent.turn.steer y\"#, b\"agent.turn.cancel\") }\n\
         fn e() -> &'static str { \"agent\\x2eturn.steer\" }\n\
         fn f() { let _ = MutationRequest { a: 1 }; let _ = ActionTarget { a: 1 }; }\n\
         impl Trait for ActionTarget { }\n\
         impl ActionTarget { }\n\
         fn g() -> &'static str { \"agent_turn_steer\" }\n",
    );
    assert_eq!(
        found,
        [
            ("AgentTurnCancel".to_owned(), 1),
            ("AgentPromptQueue".to_owned(), 2),
            ("\"agent.turn.steer\"".to_owned(), 4),
            ("\"agent.turn.cancel\"".to_owned(), 4),
            ("\"agent.turn.steer\"".to_owned(), 5),
            ("MutationRequest {".to_owned(), 6),
            ("ActionTarget {".to_owned(), 6),
        ]
    );
}

fn reports_for_refusals() -> (tempfile::TempDir, Meta, Platform) {
    let root = tempfile::tempdir().expect("a folder");
    forms(root.path());
    let platform = Platform {
        name: compiler::host_name().to_owned(),
        builds: PLAN
            .iter()
            .map(|config| (config.name.to_owned(), 0, true))
            .collect(),
        canary: Ok(7),
        ..Platform::default()
    };
    let mut meta = Meta::default();
    meta.members
        .insert(root.path().join("crates/kr-forms"), "kr_forms".to_owned());
    meta.folders.insert(
        "kr_forms".to_owned(),
        std::fs::canonicalize(root.path())
            .expect("the root")
            .join("crates/kr-forms"),
    );
    (root, meta, platform)
}

fn refused(
    root: &Path,
    meta: &Meta,
    platforms: &[Platform],
    required: &[&str],
    allowed: &[&str],
) -> Vec<String> {
    compiler::merge(root, meta, platforms, required, allowed).expect_err("the reading is refused")
}

#[test]
fn each_refusal_of_the_reading_has_the_text_the_lead_approved() {
    let (root, meta, platform) = reports_for_refusals();
    let host = compiler::host_name();
    // A platform that was not read.
    assert_eq!(
        refused(
            root.path(),
            &meta,
            std::slice::from_ref(&platform),
            &[host, "elsewhere"],
            &[]
        ),
        [format!(
            "the platform elsewhere was not read, so the reading is not complete"
        )]
    );
    // A tree the stamp could not mark.
    let mut stamp = platform.clone();
    stamp.refused = Some("no file".to_owned());
    assert_eq!(
        refused(root.path(), &meta, &[stamp], &[host], &[]),
        [format!("{host}: the tree cannot be stamped (no file)")]
    );
    // A configuration that was not built, and a build that failed.
    let mut builds = platform.clone();
    builds.builds.retain(|(name, _, _)| name != "windows");
    builds
        .builds
        .iter_mut()
        .find(|(name, _, _)| name == "host-tests")
        .expect("a build")
        .1 = 101;
    let mut problems = refused(root.path(), &meta, &[builds], &[host], &[]);
    problems.sort();
    assert_eq!(
        problems,
        [
            format!(
                "{host}: the build of host-tests failed (exit 101), so the compiler read nothing for it"
            ),
            format!(
                "{host}: the configuration windows was not built, so the reading is not complete"
            ),
        ]
    );
    // A canary that failed.
    let mut canary = platform.clone();
    canary.canary = Err(
        "kr_protocol reports no use of agent.turn.cancel; its transcriber uses every variant"
            .to_owned(),
    );
    assert_eq!(
        refused(root.path(), &meta, &[canary], &[host], &[]),
        [format!(
            "{host}: the compiler's report does not hold (kr_protocol reports no use of agent.turn.cancel; its transcriber uses every variant)"
        )]
    );
    // A procedural-macro crate of the workspace, and an outside one that is not on the list.
    let mut proc_macros = meta_with(&meta);
    proc_macros.proc_macros.insert(
        "kr_forms".to_owned(),
        BTreeSet::from([
            ("kr-derive".to_owned(), true),
            ("odd-macros".to_owned(), false),
            ("serde_derive".to_owned(), false),
        ]),
    );
    let mut problems = refused(
        root.path(),
        &proc_macros,
        std::slice::from_ref(&platform),
        &[host],
        &["serde_derive"],
    );
    problems.sort();
    assert_eq!(
        problems,
        [
            "kr_forms: depends on kr-derive, a procedural-macro crate of this workspace, which can write code the compiler reports only at its call".to_owned(),
            "kr_forms: depends on odd-macros, a procedural-macro crate that is not on the list of the ones that are read".to_owned(),
        ]
    );
    assert!(OUTSIDE_PROC_MACROS.contains(&"serde_derive"));
}

fn meta_with(meta: &Meta) -> Meta {
    Meta {
        members: meta.members.clone(),
        folders: meta.folders.clone(),
        proc_macros: meta.proc_macros.clone(),
    }
}

fn report_at(file: &str, line: usize, column: usize, end_column: usize, note: &str) -> Report {
    let place = compiler::Place {
        file: file.to_owned(),
        line,
        column,
        end_line: line,
        end_column,
    };
    Report {
        config: "host".to_owned(),
        krate: "kr_forms".to_owned(),
        note: note.to_owned(),
        here: place.clone(),
        at: place,
        macros: Vec::new(),
        test_only: false,
    }
}

#[test]
fn a_report_inside_a_use_that_renames_or_a_type_alias_is_refused_where_it_stands() {
    let (root, meta, platform) = reports_for_refusals();
    write(
        root.path(),
        "crates/kr-forms/src/lib.rs",
        "use kr_protocol::method::Method::AgentTurnCancel as Cancel;\ntype Number = [u8; { let _ = 0; 1 }];\n",
    );
    let file = "crates/kr-forms/src/lib.rs";
    let mut read = platform.clone();
    read.reports = vec![
        report_at(file, 1, 36, 52, "agent.turn.cancel"),
        report_at(file, 2, 28, 29, "agent.turn.steer"),
    ];
    let problems = refused(root.path(), &meta, &[read], &[compiler::host_name()], &[]);
    assert_eq!(
        problems,
        [
            "crates/kr-forms/src/lib.rs:1: the compiler reports agent.turn.cancel in a use that renames, which gives the name another name that the reading does not follow".to_owned(),
            "crates/kr-forms/src/lib.rs:2: the compiler reports agent.turn.steer in a type alias, which gives the name another name that the reading does not follow".to_owned(),
        ]
    );
}

#[test]
fn a_report_at_a_place_outside_the_tree_is_refused() {
    let (root, meta, platform) = reports_for_refusals();
    let mut read = platform.clone();
    read.reports = vec![report_at("../outside/lib.rs", 3, 1, 5, "agent.turn.cancel")];
    let problems = refused(root.path(), &meta, &[read], &[compiler::host_name()], &[]);
    assert_eq!(
        problems,
        ["../outside/lib.rs:3: the compiler reports a use at a place that is no file of this tree".to_owned()]
    );
}

#[test]
fn the_data_of_a_platform_reads_back_as_it_was_written() {
    let (_, _, platform) = built();
    let text = platform.text();
    let again = Platform::parse(&text).expect("the text reads");
    assert_eq!(again.len(), 1);
    assert_eq!(&again[0], platform);
    assert!(Platform::parse("report\ta\tb").is_err());
    let two = format!("{text}{text}");
    assert_eq!(Platform::parse(&two).expect("two platforms").len(), 2);
}

#[test]
fn a_record_is_a_line_for_each_kind_of_each_sighting_in_the_order_of_crate_and_item() {
    let sightings = vec![
        Sighting {
            krate: "kr_cli".to_owned(),
            name: "send".to_owned(),
            kinds: BTreeSet::from([SightKind::Target, SightKind::Names]),
        },
        Sighting {
            krate: "kr_cli".to_owned(),
            name: "a".to_owned(),
            kinds: BTreeSet::from([SightKind::Unread]),
        },
    ];
    assert_eq!(
        compiler::record_lines("packages/v1", &sightings),
        [
            "packages/v1\t\t\tRead",
            "packages/v1\tkr_cli\ta\tUnread",
            "packages/v1\tkr_cli\tsend\tNames",
            "packages/v1\tkr_cli\tsend\tTarget",
        ]
    );
}

#[test]
fn a_dep_info_file_lists_its_files_with_escaped_spaces() {
    let text = "target/debug/libkr_a.rlib: crates/kr-a/src/lib.rs crates/kr-a/src/my\\ mod.rs /home/x/dep.rs crates/kr-a/data.txt\n\ncrates/kr-a/src/lib.rs:\n";
    assert_eq!(
        compiler::files_of(text),
        [
            std::path::PathBuf::from("crates/kr-a/src/lib.rs"),
            std::path::PathBuf::from("crates/kr-a/src/my mod.rs"),
            std::path::PathBuf::from("/home/x/dep.rs"),
            std::path::PathBuf::from("crates/kr-a/data.txt"),
        ]
    );
}

#[test]
fn cargo_names_the_procedural_macro_crates_each_client_depends_on() {
    let root = tempfile::tempdir().expect("a folder");
    write(
        root.path(),
        "Cargo.toml",
        "[workspace]\nresolver = \"2\"\nmembers = [\"crates/*\", \"tests/*\"]\n",
    );
    protocol(root.path());
    write(
        root.path(),
        "crates/kr-derive/Cargo.toml",
        &format!("{}\n[lib]\nproc-macro = true\n", manifest("kr-derive", "")),
    );
    write(root.path(), "crates/kr-derive/src/lib.rs", "");
    write(
        root.path(),
        "crates/kr-user/Cargo.toml",
        &manifest("kr-user", "kr-derive = { path = \"../kr-derive\" }\n"),
    );
    write(root.path(), "crates/kr-user/src/lib.rs", "");
    write(
        root.path(),
        "tests/kr-harness/Cargo.toml",
        &manifest(
            "kr-harness",
            "kr-derive = { path = \"../../crates/kr-derive\" }\n",
        ),
    );
    write(root.path(), "tests/kr-harness/src/lib.rs", "");
    let lock = compiler::cargo_command()
        .args(["generate-lockfile", "--offline"])
        .current_dir(root.path())
        .output()
        .expect("cargo runs");
    assert!(
        lock.status.success(),
        "{}",
        String::from_utf8_lossy(&lock.stderr)
    );
    let meta = compiler::metadata(root.path()).expect("the metadata");
    assert_eq!(
        meta.proc_macros.get("kr_user"),
        Some(&BTreeSet::from([("kr-derive".to_owned(), true)]))
    );
    assert!(
        !meta.folders.contains_key("kr_harness"),
        "a crate under tests/ is no client"
    );
    assert!(
        meta.proc_macros.get("kr_protocol").is_none(),
        "a receiver is not checked"
    );
    let platform = Platform {
        name: compiler::host_name().to_owned(),
        builds: PLAN
            .iter()
            .map(|config| (config.name.to_owned(), 0, true))
            .collect(),
        canary: Ok(7),
        ..Platform::default()
    };
    assert_eq!(
        refused(
            root.path(),
            &meta,
            &[platform],
            &[compiler::host_name()],
            &[]
        ),
        [refusal::proc_macro_member("kr_user", "kr-derive")]
    );
}

/// The sightings of this checkout by this machine's platform, in the file that
/// `KR_COMPILER_SIGHTINGS` names, and printed. Run by hand with `--show-output`: it stamps a copy of
/// this checkout and builds it, which takes minutes.
#[test]
#[ignore = "stamps and builds a copy of this checkout"]
fn the_compiler_reads_this_checkout() {
    let repository = super::repository();
    let sightings = compiler::read_checkout(&repository)
        .unwrap_or_else(|problems| panic!("the reading is refused:\n{}", problems.join("\n")));
    let lines = compiler::record_lines("checkout", &sightings);
    println!(
        "this checkout: {} sightings, {} record lines",
        sightings.len(),
        lines.len()
    );
    for line in &lines {
        println!("  {line}");
    }
    if let Some(path) = std::env::var_os("KR_COMPILER_SIGHTINGS") {
        std::fs::write(path, lines.join("\n") + "\n").expect("the sightings file");
    }
}

/// The release tags to read: all the repository lists, or the tags `KR_COMPILER_TAGS` names, and then
/// the shard `KR_COMPILER_SHARD=<k>/<n>` (the tags whose place in the order is `k` modulo `n`), in the
/// order of versions.
fn selected_releases(repository: &Path) -> Vec<(String, String)> {
    let mut all = super::releases::inventory(repository).expect("the releases");
    all.sort_by(|left, right| {
        left.version
            .cmp(&right.version)
            .then(left.tag.cmp(&right.tag))
    });
    let named: Option<Vec<String>> = std::env::var("KR_COMPILER_TAGS")
        .ok()
        .map(|list| list.split(',').map(str::to_owned).collect());
    let shard: Option<(usize, usize)> = std::env::var("KR_COMPILER_SHARD").ok().map(|text| {
        let (k, n) = text.split_once('/').expect("KR_COMPILER_SHARD is <k>/<n>");
        (k.parse().expect("k"), n.parse().expect("n"))
    });
    all.into_iter()
        .enumerate()
        .filter(|(at, release)| {
            named
                .as_ref()
                .is_none_or(|names| names.contains(&release.tag))
                && shard.is_none_or(|(k, n)| at % n == k)
        })
        .map(|(_, release)| (release.tag, release.commit))
        .collect()
}

/// This machine's reading of each release tag, appended to the file `KR_COMPILER_REPORT` names as each
/// tag ends. The tags, one after another: each is unpacked, stamped and built in the plan's
/// configurations in the folder `compiler-reader` of the target folder, so that the dependencies are
/// built once. A tag that cannot be stamped or built is a line of its own in the report, and the
/// record case refuses it. Run by hand with `--show-output`: hours of machine time for all the tags
/// (`KR_COMPILER_SHARD` and `KR_COMPILER_TAGS` choose some).
#[test]
#[ignore = "stamps and builds each release tag"]
fn a_platform_reads_each_release_tag_and_writes_its_report() {
    use std::io::Write as _;
    let repository = super::repository();
    let report =
        std::env::var_os("KR_COMPILER_REPORT").expect("KR_COMPILER_REPORT names the report");
    let platform =
        std::env::var("KR_PLATFORM").unwrap_or_else(|_| compiler::host_name().to_owned());
    let releases = selected_releases(&repository);
    let (builds, _keep) = compiler::builds_folder().expect("the builds folder");
    println!("platform {platform} reads {} tags", releases.len());
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&report)
        .expect("the report file");
    let mut bad = 0;
    for (tag, commit) in &releases {
        let started = std::time::Instant::now();
        let folder = tempfile::tempdir().expect("a folder");
        let read = match compiler::unpack_commit(&repository, commit, folder.path()) {
            Ok(()) => compiler::read_platform(folder.path(), &builds, &platform, tag, commit),
            Err(error) => {
                let mut read = Platform::default();
                read.name.clone_from(&platform);
                read.tag.clone_from(tag);
                read.commit.clone_from(commit);
                read.refused = Some(error);
                read
            }
        };
        let finished = read
            .builds
            .iter()
            .all(|(_, exit, done)| *exit == 0 && *done);
        let good = read.refused.is_none() && finished && read.canary.is_ok();
        bad += usize::from(!good);
        file.write_all(read.text().as_bytes()).expect("the report");
        file.flush().expect("the report");
        println!(
            "read {tag} by {platform} in {:?}: {} ({} builds, {} reports, {} files, stamp {}, canary {:?})",
            started.elapsed(),
            if good { "ok" } else { "NOT COMPLETE" },
            read.builds.len(),
            read.reports.len(),
            read.files.len(),
            read.stamped.line().replace('\t', " "),
            read.canary,
        );
    }
    println!(
        "platform {platform} read {} tags, {bad} not complete",
        releases.len()
    );
}

/// The record of each release tag from the reports of the platforms in the files `KR_COMPILER_REPORTS`
/// names (separated by `:`), each tag's own tree read again for its items and its tokens. A tag
/// that a refusal stops is named with its texts and fails the case. The lines go to the file
/// `KR_COMPILER_RECORD` names, and the difference from the committed record is printed, by item and
/// kind, with the number of tags it holds for.
#[test]
#[ignore = "reads the reports of the platforms and every release tag's tree"]
fn the_reports_of_the_platforms_give_the_record_of_each_release_tag() {
    use std::collections::BTreeMap;
    let repository = super::repository();
    let files =
        std::env::var("KR_COMPILER_REPORTS").expect("KR_COMPILER_REPORTS names the reports");
    let required: Vec<String> = std::env::var("KR_COMPILER_REQUIRED")
        .unwrap_or_else(|_| "macos,linux".to_owned())
        .split(',')
        .map(str::to_owned)
        .collect();
    let mut by_tag: BTreeMap<String, Vec<Platform>> = BTreeMap::new();
    for file in files.split(':') {
        let text = std::fs::read_to_string(file).unwrap_or_else(|error| panic!("{file}: {error}"));
        for platform in Platform::parse(&text).unwrap_or_else(|error| panic!("{file}: {error}")) {
            by_tag
                .entry(platform.tag.clone())
                .or_default()
                .push(platform);
        }
    }
    let releases = super::releases::inventory(&repository).expect("the releases");
    let mut tags: Vec<(String, String)> = releases
        .iter()
        .filter(|release| by_tag.contains_key(&release.tag))
        .map(|release| (release.tag.clone(), release.commit.clone()))
        .collect();
    tags.sort();
    let required: Vec<&str> = required.iter().map(String::as_str).collect();
    let results = super::history::in_threads_of_their_own(tags.clone(), 4, |(tag, commit)| {
        let folder = tempfile::tempdir().map_err(|error| vec![error.to_string()])?;
        compiler::unpack_commit(&repository, &commit, folder.path())
            .map_err(|error| vec![error])?;
        let meta = compiler::metadata(folder.path()).map_err(|error| vec![error])?;
        let read = compiler::merge(
            folder.path(),
            &meta,
            &by_tag[&tag],
            &required,
            OUTSIDE_PROC_MACROS,
        )?;
        Ok::<_, Vec<String>>(compiler::record_lines(&tag, &read))
    });
    let mut record: Vec<String> = Vec::new();
    let mut refused = 0;
    let mut now: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for ((tag, _), result) in tags.iter().zip(results) {
        match result {
            Ok(lines) => {
                println!("{tag}: {} lines", lines.len());
                for line in &lines {
                    let fields: Vec<&str> = line.splitn(2, '\t').collect();
                    if fields[1] != "\t\tRead" {
                        now.entry(fields[0].to_owned())
                            .or_default()
                            .insert(fields[1].to_owned());
                    }
                }
                record.extend(lines);
            }
            Err(problems) => {
                refused += 1;
                println!("{tag}: REFUSED\n    {}", problems.join("\n    "));
            }
        }
    }
    if let Some(path) = std::env::var_os("KR_COMPILER_RECORD") {
        std::fs::write(path, record.join("\n") + "\n").expect("the record file");
    }
    let mut before: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in include_str!("../retained_history_record.txt").lines() {
        let (tag, rest) = line.split_once('\t').expect("a record line");
        if rest != "\t\tRead" {
            before
                .entry(tag.to_owned())
                .or_default()
                .insert(rest.to_owned());
        }
    }
    let mut differences: BTreeMap<(char, String), usize> = BTreeMap::new();
    let mut differing = 0;
    for (tag, _) in &tags {
        let (old, new) = (
            before.get(tag).cloned().unwrap_or_default(),
            now.get(tag).cloned().unwrap_or_default(),
        );
        differing += usize::from(old != new);
        for line in old.difference(&new) {
            *differences.entry(('-', line.clone())).or_default() += 1;
        }
        for line in new.difference(&old) {
            *differences.entry(('+', line.clone())).or_default() += 1;
        }
    }
    for ((sign, line), tags) in &differences {
        println!("{sign} {line}\t{tags} tags");
    }
    println!(
        "the compiler's record: {} tags, {} lines, {refused} refused; the committed record: {} lines; {differing} tags differ in {} lines",
        tags.len(),
        record.len(),
        include_str!("../retained_history_record.txt")
            .lines()
            .count(),
        differences.len()
    );
    assert_eq!(refused, 0, "a tag is refused");
}
