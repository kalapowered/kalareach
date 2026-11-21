//! The compiler as the reader of what builds a mutation for a worker.
//!
//! A scratch copy of a tree gets `#[deprecated(note = ..)]` on what a sender of one of the six
//! methods has to name: the variants of `Method` (the note is the wire name), the fields of
//! `MutationRequest` and `ActionTarget`, the accessors that turn data into a method and
//! `ActionTarget`'s constructor. Cargo then checks the copy with `--force-warn deprecated`, and
//! rustc's own name resolution reports each use of a stamped item with its span and the chain of
//! macro calls that led to it. No form of Rust that binds a name is read here by hand.
//!
//! Three parts:
//! * **The stamp and the builds** ([`stamp`], [`read_platform`]): one platform's reading of one tree,
//!   as data (a [`Platform`]).
//! * **The sightings** ([`merge`]): the reports of every platform, each at the innermost item of its
//!   outermost call site (`syn` with span locations), and the closed check. A token that names a
//!   stamped item and lies on no report of any build is an `Unread` sighting, which is loud: the
//!   derive output, code that no built configuration reaches and a wire name in a literal all end
//!   there. A result that cannot be complete is refused with a text and never turned into a pass.
//! * **The record** ([`record_lines`]): the sightings of a release tag, one line for each kind.

use std::collections::{BTreeMap, BTreeSet};
use std::io::BufRead as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use proc_macro2::{Delimiter, Group, TokenStream, TokenTree};
use serde_json::Value;
use syn::ext::IdentExt as _;
use syn::visit::Visit;

/// What a sighting names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SightKind {
    /// One of the six variant names, or a way to turn data into a method (`Method::from_wire`,
    /// `Method::ALL`, `REGISTRY`, `MethodName::new`, `MethodName::method`).
    Names,
    /// A field of `MutationRequest`.
    Request,
    /// A field of `ActionTarget`, or its constructor.
    Target,
    /// A `macro_rules!` whose transcriber holds a use that the compiler reports.
    Expands,
    /// A token that names a stamped item and lies on no report of any build.
    Unread,
}

/// An item that builds, names or sets what a mutation for a worker carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sighting {
    pub krate: String,
    pub name: String,
    pub kinds: BTreeSet<SightKind>,
}

/// The six methods a worker's input rule may refuse more for: their variants and wire names.
pub const VARIANTS: [&str; 6] = [
    "AgentPromptSubmit",
    "AgentPromptQueue",
    "AgentTurnSteer",
    "AgentTurnCancel",
    "AgentApprovalRespond",
    "PluginActionInvoke",
];
pub const WIRE_NAMES: [&str; 6] = [
    "agent.prompt.submit",
    "agent.prompt.queue",
    "agent.turn.steer",
    "agent.turn.cancel",
    "agent.approval.respond",
    "plugin.action.invoke",
];

/// The structs whose fields are stamped, with the kind a use of a field gives.
const STAMPED_STRUCTS: [(&str, SightKind); 2] = [
    ("ActionTarget", SightKind::Target),
    ("MutationRequest", SightKind::Request),
];

/// The accessors the stamp marks in the file that holds `macro_rules! methods`: the trimmed line each
/// is declared on, and its note.
const METHOD_ACCESSORS: [(&str, &str); 5] = [
    (
        "pub const ALL: &'static [Self] = &[$(Self::$variant,)+];",
        "Method::ALL",
    ),
    (
        "pub fn from_wire(value: &str) -> Option<Self> {",
        "Method::from_wire",
    ),
    ("pub static REGISTRY: &[MethodEntry] = &[", "REGISTRY"),
    (
        "pub fn new(value: impl Into<String>) -> Result<Self, MethodNameError> {",
        "MethodName::new",
    ),
    (
        "pub fn method(&self) -> Option<Method> {",
        "MethodName::method",
    ),
];

/// The constructor of `ActionTarget`, in the file that holds the struct.
const TARGET_ACCESSORS: [(&str, &str); 1] = [(
    "pub const fn environment(environment_id: EnvironmentId) -> Self {",
    "ActionTarget::environment",
)];

/// Whether a note is a variant's wire name: not an accessor's and not a field's.
fn is_variant_note(note: &str) -> bool {
    !METHOD_ACCESSORS
        .iter()
        .chain(&TARGET_ACCESSORS)
        .any(|(_, found)| *found == note)
        && !STAMPED_STRUCTS.iter().any(|(name, _)| {
            note.strip_prefix(name)
                .is_some_and(|rest| rest.starts_with('.') || rest.starts_with("::"))
        })
}

/// The kind a use of an item with this note is a sighting of; none for a variant of another method.
pub fn kind_of(note: &str) -> Option<SightKind> {
    if WIRE_NAMES.contains(&note) || METHOD_ACCESSORS.iter().any(|(_, found)| *found == note) {
        return Some(SightKind::Names);
    }
    STAMPED_STRUCTS.iter().find_map(|(name, kind)| {
        note.strip_prefix(name)
            .filter(|rest| rest.starts_with('.') || rest.starts_with("::"))
            .map(|_| *kind)
    })
}

// ---------------------------------------------------------------------------------------------
// The stamp
// ---------------------------------------------------------------------------------------------

/// What the stamp marked: whether the variants were, the fields of each struct and the notes of the
/// accessors found (an accessor a release does not have is not stamped and is not named).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stamped {
    pub variants: bool,
    pub fields: usize,
    pub accessors: Vec<&'static str>,
}

impl Stamped {
    pub fn line(&self) -> String {
        format!(
            "{}\t{}\t{}",
            u8::from(self.variants),
            self.fields,
            self.accessors.join(",")
        )
    }
}

fn rust_files(folder: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(folder)
        .map_err(|error| format!("{}: {error}", folder.display()))?
        .flatten()
        .map(|entry| entry.path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rust_files(&path, out)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// The one file under `folder` whose text holds `needle`.
fn file_holding(folder: &Path, needle: &str) -> Result<PathBuf, String> {
    let mut files = Vec::new();
    rust_files(folder, &mut files)?;
    let mut found = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file)
            .map_err(|error| format!("{}: {error}", file.display()))?;
        if text.contains(needle) {
            found.push(file);
        }
    }
    match found.as_slice() {
        [one] => Ok(one.clone()),
        other => Err(format!(
            "the stamp needs one file under {} that holds `{needle}` and finds {}",
            folder.display(),
            other.len()
        )),
    }
}

/// `text` with `attribute` on a line of its own above each line whose trimmed text is `line`, and the
/// number of lines so marked.
fn mark_lines(text: &str, line: &str, attribute: &str) -> (String, usize) {
    let mut out = String::with_capacity(text.len() + 64);
    let mut marked = 0;
    for each in text.split_inclusive('\n') {
        if each.trim() == line {
            let indent = &each[..each.len() - each.trim_start().len()];
            out.push_str(&format!("{indent}{attribute}\n"));
            marked += 1;
        }
        out.push_str(each);
    }
    (out, marked)
}

/// The byte offset of a position of `syn` (the line from 1, the column in characters from 0).
fn offset_of(text: &str, line: usize, column: usize) -> Option<usize> {
    let mut start = 0;
    for _ in 1..line {
        start += text[start..].find('\n')? + 1;
    }
    let rest = &text[start..];
    let within = rest
        .char_indices()
        .nth(column)
        .map_or(rest.len(), |(at, _)| at);
    Some(start + within)
}

/// The text with `#[deprecated(note = "<struct>.<field>")]` before each field of the struct
/// `name`.
fn mark_fields(text: &str, name: &str) -> Result<(String, usize), String> {
    let file = syn::parse_file(text).map_err(|error| format!("{name}: {error}"))?;
    let found = file.items.iter().find_map(|item| match item {
        syn::Item::Struct(item) if item.ident == name => Some(item),
        _ => None,
    });
    let Some(item) = found else {
        return Err(format!("the stamp finds no struct {name} in its file"));
    };
    let syn::Fields::Named(fields) = &item.fields else {
        return Err(format!("the stamp needs {name} to have named fields"));
    };
    let mut at: Vec<(usize, String)> = Vec::new();
    for field in &fields.named {
        let ident = field
            .ident
            .as_ref()
            .ok_or_else(|| format!("a field of {name} has no name"))?;
        let start = match &field.vis {
            syn::Visibility::Inherited => ident.span().start(),
            vis => syn::spanned::Spanned::span(vis).start(),
        };
        let offset = offset_of(text, start.line, start.column)
            .ok_or_else(|| format!("a field of {name} is at no place of its file"))?;
        at.push((
            offset,
            format!("#[deprecated(note = \"{name}.{}\")] ", ident.unraw()),
        ));
    }
    at.sort_by_key(|(offset, _)| std::cmp::Reverse(*offset));
    let count = at.len();
    let mut out = text.to_owned();
    for (offset, attribute) in at {
        out.insert_str(offset, &attribute);
    }
    Ok((out, count))
}

/// Marks the tree at `root` in place, which is a scratch extraction and never a checkout: the
/// variants of `Method`, the fields of `MutationRequest` and `ActionTarget`, and the accessors. A
/// tree the stamp cannot mark in each place it needs is refused with the text.
pub fn stamp(root: &Path) -> Result<Stamped, String> {
    let source = root.join("crates/kr-protocol/src");
    let mut stamped = Stamped::default();
    let method = file_holding(&source, "macro_rules! methods")?;
    let mut text = std::fs::read_to_string(&method)
        .map_err(|error| format!("{}: {error}", method.display()))?;
    let (marked, count) = mark_lines(&text, "$variant,", "#[deprecated(note = $name)]");
    if count != 1 {
        return Err(format!(
            "the stamp needs one line `$variant,` in {} and finds {count}",
            method.display()
        ));
    }
    text = marked;
    stamped.variants = true;
    for (line, note) in METHOD_ACCESSORS {
        let (marked, count) = mark_lines(&text, line, &format!("#[deprecated(note = \"{note}\")]"));
        match count {
            0 => {}
            1 => {
                text = marked;
                stamped.accessors.push(note);
            }
            more => {
                return Err(format!(
                    "the stamp needs at most one line `{line}` in {} and finds {more}",
                    method.display()
                ));
            }
        }
    }
    std::fs::write(&method, text).map_err(|error| format!("{}: {error}", method.display()))?;
    for (name, _) in STAMPED_STRUCTS {
        let file = file_holding(&source, &format!("pub struct {name} {{"))?;
        let mut text = std::fs::read_to_string(&file)
            .map_err(|error| format!("{}: {error}", file.display()))?;
        let (marked, count) = mark_fields(&text, name)?;
        text = marked;
        stamped.fields += count;
        if name == "ActionTarget" {
            for (line, note) in TARGET_ACCESSORS {
                let (marked, count) =
                    mark_lines(&text, line, &format!("#[deprecated(note = \"{note}\")]"));
                match count {
                    0 => {}
                    1 => {
                        text = marked;
                        stamped.accessors.push(note);
                    }
                    more => {
                        return Err(format!(
                            "the stamp needs at most one line `{line}` in {} and finds {more}",
                            file.display()
                        ));
                    }
                }
            }
        }
        std::fs::write(&file, text).map_err(|error| format!("{}: {error}", file.display()))?;
    }
    Ok(stamped)
}

// ---------------------------------------------------------------------------------------------
// Cargo's data about the tree
// ---------------------------------------------------------------------------------------------

/// The crates that receive a mutation: no client of the six methods is read there.
pub const RECEIVERS: [&str; 3] = ["kr_protocol", "kr_worker", "kr_controller"];

/// The procedural-macro crates outside the workspace that the client crates may depend on: each one
/// derives or rewrites an item and none of them makes a path the compiler does not resolve for the
/// site of the call. A procedural-macro crate of the workspace, and any outside one that is not
/// here, is refused.
pub const OUTSIDE_PROC_MACROS: &[&str] = &[
    "arg_enum_proc_macro",
    "asn1-rs-derive",
    "asn1-rs-impl",
    "async-recursion",
    "async-trait",
    "bytecheck_derive",
    "clap_derive",
    "cssparser-macros",
    "ctor-proc-macro",
    "curve25519-dalek-derive",
    "darling_macro",
    "data-encoding-macro-internal",
    "defmt-macros",
    "derive_more-impl",
    "displaydoc",
    "dlopen2_derive",
    "doctest-file",
    "dtor-proc-macro",
    "enum-as-inner",
    "enum-assoc",
    "enumflags2_derive",
    "equator-macro",
    "foreign-types-macros",
    "futures-macro",
    "g2gen",
    "glib-macros",
    "gtk3-macros",
    "interpolate_name",
    "iroh-metrics-derive",
    "jiff-static",
    "jni-macros",
    "jni-sys-macros",
    "multiversion-macros",
    "multiversion_no_op",
    "munge_macro",
    "n0-error-macros",
    "noop_proc_macro",
    "num-derive",
    "num_enum_derive",
    "paste",
    "pastey",
    "pest_derive",
    "phf_macros",
    "pin-project-internal",
    "postcard-derive",
    "proc-macro-error-attr",
    "profiling-procmacros",
    "ptr_meta_derive",
    "pulley-macros",
    "ref-cast-impl",
    "rkyv_derive",
    "rmcp-macros",
    "rustversion",
    "schemars_derive",
    "serde_derive",
    "serde_repr",
    "serde_with_macros",
    "serialize-to-javascript-impl",
    "simd_helpers",
    "snafu-derive",
    "spez",
    "strum_macros",
    "tao-macros",
    "tauri-macros",
    "thiserror-impl",
    "time-macros",
    "tokio-macros",
    "tracing-attributes",
    "wasm-bindgen-macro",
    "wasmtime-internal-component-macro",
    "wasmtime-internal-versioned-export-macros",
    "wayland-scanner",
    "webview2-com-macros",
    "wezterm-dynamic-derive",
    "windows-implement",
    "windows-interface",
    "yoke-derive",
    "zbus_macros",
    "zerocopy-derive",
    "zerofrom-derive",
    "zeroize_derive",
    "zerovec-derive",
    "zvariant_derive",
];

/// What `cargo metadata` says of a tree, for the crates that are clients.
#[derive(Debug, Default)]
pub struct Meta {
    /// Each member by the folder of its manifest, with its crate name.
    pub members: BTreeMap<PathBuf, String>,
    /// The folder of each member, by crate name.
    pub folders: BTreeMap<String, PathBuf>,
    /// The procedural-macro crates each client crate depends on, by any kind of dependency: the
    /// package, and whether it is a member of the workspace.
    pub proc_macros: BTreeMap<String, BTreeSet<(String, bool)>>,
    /// The members (by package name) that depend directly on `llama-cpp-2`, the model runtime.
    pub model_runtime: BTreeSet<String>,
}

pub fn is_client(krate: &str) -> bool {
    !RECEIVERS.contains(&krate)
}

fn cargo() -> PathBuf {
    std::env::var_os("CARGO").map_or_else(|| PathBuf::from(env!("CARGO")), PathBuf::from)
}

/// Cargo, run by its own path, with the `rustc` of the same toolchain.
pub fn cargo_command() -> Command {
    let cargo = cargo();
    let mut command = Command::new(&cargo);
    // A build script runs the tools of the machine (`cmake`, `rustfmt`): the program that is started
    // with a bare `PATH` names the one its builds need in `KR_BUILD_PATH`.
    let path = std::env::var_os("KR_BUILD_PATH")
        .or_else(|| std::env::var_os("PATH"))
        .unwrap_or_default();
    if let Some(folder) = cargo.parent() {
        let mut parts = vec![folder.to_path_buf()];
        parts.extend(std::env::split_paths(&path));
        if let Ok(joined) = std::env::join_paths(parts) {
            command.env("PATH", joined);
        }
        let rustc = folder.join("rustc");
        if rustc.is_file() {
            command.env("RUSTC", rustc);
        }
    }
    command
}

/// Cargo's description of the tree at `root`, with its dependency graph.
pub fn metadata(root: &Path) -> Result<Meta, String> {
    let root =
        &std::fs::canonicalize(root).map_err(|error| format!("{}: {error}", root.display()))?;
    let output = cargo_command()
        .args(["metadata", "--format-version", "1", "--locked", "--offline"])
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("{}: cargo metadata: {error}", root.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{}: cargo metadata failed: {}",
            root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("{}: cargo metadata: {error}", root.display()))?;
    let packages: BTreeMap<&str, &Value> = value["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|package| Some((package["id"].as_str()?, package)))
        .collect();
    let members: BTreeSet<&str> = value["workspace_members"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let mut meta = Meta::default();
    let mut crate_of: BTreeMap<&str, String> = BTreeMap::new();
    for id in &members {
        let package = packages.get(id).ok_or_else(|| {
            format!("cargo metadata names the member {id} and does not describe it")
        })?;
        let name = package["name"]
            .as_str()
            .unwrap_or_default()
            .replace('-', "_");
        let folder = Path::new(package["manifest_path"].as_str().unwrap_or_default())
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| format!("the manifest of {name} has no folder"))?;
        // The crates under `tests/` are programs that exercise the product, not clients of it.
        if folder.starts_with(root.join("tests")) {
            continue;
        }
        meta.members.insert(folder.clone(), name.clone());
        meta.folders.insert(name.clone(), folder);
        if package["dependencies"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|dependency| dependency["name"] == "llama-cpp-2")
        {
            meta.model_runtime
                .insert(package["name"].as_str().unwrap_or_default().to_owned());
        }
        crate_of.insert(id, name);
    }
    let nodes: BTreeMap<&str, &Value> = value["resolve"]["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|node| Some((node["id"].as_str()?, node)))
        .collect();
    let proc_macro = |id: &str| {
        packages.get(id).is_some_and(|package| {
            package["targets"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|target| {
                    target["kind"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .any(|kind| kind == "proc-macro")
                })
        })
    };
    for (id, krate) in &crate_of {
        if !is_client(krate) {
            continue;
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut pending = vec![*id];
        let mut found = BTreeSet::new();
        while let Some(at) = pending.pop() {
            if !seen.insert(at) {
                continue;
            }
            if at != *id && proc_macro(at) {
                let name = packages[at]["name"].as_str().unwrap_or_default().to_owned();
                found.insert((name, members.contains(at)));
            }
            for dependency in nodes
                .get(at)
                .map(|node| node["deps"].as_array().into_iter().flatten())
                .into_iter()
                .flatten()
            {
                if let Some(next) = dependency["pkg"].as_str() {
                    pending.push(next);
                }
            }
        }
        meta.proc_macros.insert(krate.clone(), found);
    }
    Ok(meta)
}

// ---------------------------------------------------------------------------------------------
// The builds
// ---------------------------------------------------------------------------------------------

/// One configuration the compiler builds: the host or the Windows target, with the product's
/// libraries and binaries, or with the test targets as well.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub name: &'static str,
    pub target: Option<&'static str>,
    pub tests: bool,
    /// Whether this configuration leaves out the members that depend directly on `llama-cpp-2` (the
    /// model runtime, found from `cargo metadata`): the build script of `llama-cpp-sys-2` builds
    /// `llama.cpp`, which needs a C++ toolchain for the target, so the configurations of the host
    /// read such a member and the Windows one does not. The rule holds because no client names a
    /// stamped item in the model runtime; a token of a stamped name in its Windows-only code is an
    /// `Unread` sighting, and a member that a client depends on still builds with it, and a build
    /// that fails is refused.
    pub without_model_runtime: bool,
}

/// The members a configuration does not build: the receivers, and the model runtime where the
/// configuration leaves it out.
pub fn excluded(config: Config, meta: &Meta) -> Vec<String> {
    let mut members: Vec<String> = ["kr-controller", "kr-worker"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    if config.without_model_runtime {
        members.extend(meta.model_runtime.iter().cloned());
    }
    members
}

/// The one target besides the host that every platform checks.
pub const WINDOWS_GNU: &str = "x86_64-pc-windows-gnu";

/// The three configurations of a platform: its own product and test targets, and the product for
/// Windows. The test build is what marks a report that only test code holds; test code that only
/// Windows builds is not built, and a token in it is an `Unread` sighting.
pub const PLAN: [Config; 3] = [
    Config {
        name: "host",
        target: None,
        tests: false,
        without_model_runtime: false,
    },
    Config {
        name: "host-tests",
        target: None,
        tests: true,
        without_model_runtime: false,
    },
    Config {
        name: "windows",
        target: Some(WINDOWS_GNU),
        tests: false,
        without_model_runtime: true,
    },
];

/// A place in a file: the first position and the end of a span (lines from 1, columns from 1).
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Place {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

impl Place {
    fn of(span: &Value) -> Option<Self> {
        let number = |key: &str| usize::try_from(span[key].as_u64()?).ok();
        Some(Self {
            file: span["file_name"].as_str()?.to_owned(),
            line: number("line_start")?,
            column: number("column_start")?,
            end_line: number("line_end")?,
            end_column: number("column_end")?,
        })
    }

    fn fields(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}",
            self.file, self.line, self.column, self.end_line, self.end_column
        )
    }
}

/// One use of a stamped item that the compiler reports.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Report {
    /// The configuration that was built.
    pub config: String,
    /// The crate whose build made the report.
    pub krate: String,
    /// The note of the stamped item: a wire name, or the name of an accessor or of a field.
    pub note: String,
    /// The span the compiler points at.
    pub here: Place,
    /// The outermost call site of the macros that expanded to `here`, or `here` itself.
    pub at: Place,
    /// The macros between the two, innermost first.
    pub macros: Vec<String>,
    /// Whether no build of the product reports it and a test build does.
    pub test_only: bool,
}

/// What one platform read of one tree, as data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Platform {
    pub name: String,
    pub tag: String,
    pub commit: String,
    /// The text of a failed stamp, in place of the rest.
    pub refused: Option<String>,
    pub stamped: Stamped,
    /// Each configuration, with the exit of its build and whether Cargo said it finished well.
    pub builds: Vec<(String, i32, bool)>,
    /// The files of the tree that the compilers read (their dep-info), by crate.
    pub files: BTreeSet<(String, String)>,
    pub reports: Vec<Report>,
    /// The canary: the number of wire names `kr_protocol` reports, or what is missing.
    pub canary: Result<usize, String>,
}

impl Default for Platform {
    fn default() -> Self {
        Self {
            name: String::new(),
            tag: String::new(),
            commit: String::new(),
            refused: None,
            stamped: Stamped::default(),
            builds: Vec::new(),
            files: BTreeSet::new(),
            reports: Vec::new(),
            canary: Err("not read".to_owned()),
        }
    }
}

/// What one build gave: its reports, its dep-info files and its end.
struct Built {
    exit: i32,
    finished: bool,
    reports: Vec<Report>,
    files: BTreeSet<(String, String)>,
}

/// The reports are made by `rustc` for the crates of this workspace only: a use in a dependency from
/// the registry is no sighting of ours.
fn build(root: &Path, target_dir: &Path, config: Config, meta: &Meta) -> Result<Built, String> {
    let mut errors = tempfile::tempfile().map_err(|error| error.to_string())?;
    let mut command = cargo_command();
    command.args([
        "check",
        "--locked",
        "--offline",
        "--workspace",
        "--lib",
        "--bins",
    ]);
    for member in excluded(config, meta) {
        command.args(["--exclude", &member]);
    }
    if config.tests {
        command.arg("--tests");
    }
    if let Some(target) = config.target {
        command.args(["--target", target]);
    }
    command
        .arg("--message-format=json")
        .current_dir(root)
        .env("CARGO_TARGET_DIR", target_dir)
        .env("RUSTFLAGS", "--force-warn deprecated")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(
            errors.try_clone().map_err(|error| error.to_string())?,
        ));
    let mut child = command
        .spawn()
        .map_err(|error| format!("{}: cargo check: {error}", config.name))?;
    let stdout = child.stdout.take().ok_or("cargo check has no output")?;
    let canonical_root = std::fs::canonicalize(root).map_err(|error| error.to_string())?;
    let mut built = Built {
        exit: -1,
        finished: false,
        reports: Vec::new(),
        files: BTreeSet::new(),
    };
    let mut errors_said: Vec<String> = Vec::new();
    for line in std::io::BufReader::new(stdout).lines() {
        let line = line.map_err(|error| error.to_string())?;
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        match message["reason"].as_str() {
            Some("build-finished") => built.finished = message["success"] == true,
            Some("compiler-message") => {
                if message["message"]["level"] == "error"
                    && errors_said.len() < 6
                    && let Some(text) = message["message"]["rendered"].as_str()
                {
                    errors_said.push(text.lines().take(14).collect::<Vec<_>>().join("\n"));
                }
                if let Some(report) = report_of(&message, config, meta) {
                    built.reports.push(report);
                }
            }
            Some("compiler-artifact") => {
                // The files of the product build; a test build reads the test targets' as well.
                let Some(krate) = member_of(&message, meta).filter(|_| !config.tests) else {
                    continue;
                };
                for artifact in message["filenames"].as_array().into_iter().flatten() {
                    let Some(info) = artifact.as_str().and_then(own_dep_info) else {
                        continue;
                    };
                    let Ok(text) = std::fs::read_to_string(&info) else {
                        continue;
                    };
                    for file in files_of(&text) {
                        let path = if file.is_absolute() {
                            file
                        } else {
                            canonical_root.join(file)
                        };
                        let Ok(path) = std::fs::canonicalize(&path) else {
                            continue;
                        };
                        if let Ok(relative) = path.strip_prefix(&canonical_root) {
                            if relative.starts_with("target") {
                                continue;
                            }
                            built
                                .files
                                .insert((krate.clone(), relative.display().to_string()));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    built.exit = child
        .wait()
        .map_err(|error| error.to_string())?
        .code()
        .unwrap_or(-1);
    if built.exit != 0 || !built.finished {
        // What Cargo and the compiler said, for the person who reads the log: the last of Cargo's lines and
        // the compiler's first errors.
        use std::io::{Read as _, Seek as _};
        let mut said = String::new();
        errors.rewind().map_err(|error| error.to_string())?;
        errors
            .read_to_string(&mut said)
            .map_err(|error| error.to_string())?;
        let tail: Vec<&str> = said.lines().rev().take(40).collect();
        println!(
            "{}: cargo check failed (exit {}); its last lines:\n{}",
            config.name,
            built.exit,
            tail.into_iter().rev().collect::<Vec<_>>().join("\n")
        );
        if !errors_said.is_empty() {
            println!(
                "{}: the compiler's errors:\n{}",
                config.name,
                errors_said.join("\n--\n")
            );
        }
    }
    Ok(built)
}

fn member_of(message: &Value, meta: &Meta) -> Option<String> {
    let manifest = Path::new(message["manifest_path"].as_str()?).parent()?;
    meta.members.get(manifest).cloned()
}

/// The report a `deprecated` warning makes, if it is one of a member of the workspace.
fn report_of(message: &Value, config: Config, meta: &Meta) -> Option<Report> {
    let diagnostic = &message["message"];
    if diagnostic["code"]["code"] != "deprecated" {
        return None;
    }
    let krate = member_of(message, meta)?;
    let text = diagnostic["message"].as_str()?;
    let (_, note) = text.rsplit_once("`: ")?;
    let primary = diagnostic["spans"]
        .as_array()?
        .iter()
        .find(|span| span["is_primary"] == true)?;
    let here = Place::of(primary)?;
    let mut at = here.clone();
    let mut macros = Vec::new();
    let mut span = primary;
    while !span["expansion"].is_null() {
        let expansion = &span["expansion"];
        macros.push(expansion["macro_decl_name"].as_str()?.to_owned());
        span = &expansion["span"];
        at = Place::of(span)?;
    }
    Some(Report {
        config: config.name.to_owned(),
        krate,
        note: note.to_owned(),
        here,
        at,
        macros,
        test_only: false,
    })
}

/// rustc's own dep-info of the artifact `artifact`: the `<crate>-<hash>.d` in `deps/` beside the file
/// (without the `lib` of a library's name). An artifact that Cargo links or copies above `deps/` is
/// found by the file in `deps/` that is the same file (a hard link) or a copy of it (the same size and
/// time), which names the hash.
pub fn own_dep_info(artifact: &str) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt as _;
    let artifact = Path::new(artifact);
    let folder = artifact.parent()?;
    let twin = if folder.file_name()? == "deps" {
        artifact.to_path_buf()
    } else {
        let above = std::fs::metadata(artifact).ok()?;
        std::fs::read_dir(folder.join("deps"))
            .ok()?
            .flatten()
            .map(|entry| entry.path())
            .find(|path| {
                std::fs::metadata(path).is_ok_and(|found| {
                    (found.ino() == above.ino() && found.dev() == above.dev())
                        || (found.len() == above.len()
                            && found.modified().ok() == above.modified().ok()
                            && path.extension().is_none())
                })
            })?
    };
    let stem = twin.file_stem()?.to_str()?;
    [stem.strip_prefix("lib").unwrap_or(stem), stem]
        .into_iter()
        .map(|name| twin.with_file_name(format!("{name}.d")))
        .find(|info| info.is_file())
}

/// The files a dep-info file lists after the target's colon (a space in a name is escaped by a
/// backslash).
pub fn files_of(text: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for line in text.lines() {
        let Some((_, deps)) = line.split_once(": ") else {
            continue;
        };
        let mut current = String::new();
        let mut chars = deps.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\\' if chars.peek() == Some(&' ') => {
                    current.push(' ');
                    chars.next();
                }
                ' ' => {
                    if !current.is_empty() {
                        files.push(PathBuf::from(std::mem::take(&mut current)));
                    }
                }
                other => current.push(other),
            }
        }
        if !current.is_empty() {
            files.push(PathBuf::from(current));
        }
    }
    files
}

/// Stamps the scratch tree at `root` and builds each configuration of the plan, in the target folder
/// `target_dir`. A stamp that cannot mark the tree is the refusal in the result, and a build that
/// fails is its exit: the platform is data, and whether it is enough is [`merge`]'s to say.
pub fn read_platform(
    root: &Path,
    target_dir: &Path,
    platform: &str,
    tag: &str,
    commit: &str,
) -> Platform {
    let mut read = Platform {
        name: platform.to_owned(),
        tag: tag.to_owned(),
        commit: commit.to_owned(),
        canary: Err("not read".to_owned()),
        ..Platform::default()
    };
    let root = &match std::fs::canonicalize(root) {
        Ok(root) => root,
        Err(error) => {
            read.refused = Some(format!("{}: {error}", root.display()));
            return read;
        }
    };
    match stamp(root) {
        Ok(stamped) => read.stamped = stamped,
        Err(error) => {
            read.refused = Some(error);
            return read;
        }
    }
    let meta = match metadata(root) {
        Ok(meta) => meta,
        Err(error) => {
            read.refused = Some(error);
            return read;
        }
    };
    for config in PLAN {
        match build(root, target_dir, config, &meta) {
            Ok(built) => {
                read.builds
                    .push((config.name.to_owned(), built.exit, built.finished));
                read.files.extend(built.files);
                read.reports.extend(built.reports);
            }
            Err(error) => {
                read.refused = Some(error);
                return read;
            }
        }
    }
    mark_test_only(&mut read.reports);
    read.canary = canary(root, &read.reports);
    read
}

/// The reports that only a test build makes are marked, and the copies of a report that several
/// builds make are one.
fn mark_test_only(reports: &mut Vec<Report>) {
    let key = |report: &Report| {
        (
            report.krate.clone(),
            report.note.clone(),
            report.here.clone(),
            report.at.clone(),
        )
    };
    let product: BTreeSet<_> = reports
        .iter()
        .filter(|report| !report.config.ends_with("tests"))
        .map(key)
        .collect();
    for report in reports.iter_mut() {
        report.test_only = !product.contains(&key(report));
    }
    // One copy of each report: the product build's where there is one.
    reports.sort_by(|left, right| {
        key(left).cmp(&key(right)).then(
            left.config
                .ends_with("tests")
                .cmp(&right.config.ends_with("tests")),
        )
    });
    reports.dedup_by(|later, earlier| key(later) == key(earlier));
}

/// The wire names that the file holding `macro_rules! methods` quotes and `kr_protocol` must report:
/// its own transcriber uses each variant, and the compiler must say so. The whole file is read, so a
/// name quoted anywhere in it counts. A name it does not report is a stamp that did not take, and
/// nothing a client reports is then to be trusted.
fn canary(root: &Path, reports: &[Report]) -> Result<usize, String> {
    let source = root.join("crates/kr-protocol/src");
    let method = file_holding(&source, "macro_rules! methods")?;
    let text = std::fs::read_to_string(&method)
        .map_err(|error| format!("{}: {error}", method.display()))?;
    let reported: BTreeSet<&str> = reports
        .iter()
        .filter(|report| report.krate == "kr_protocol" && report.config == "host")
        .map(|report| report.note.as_str())
        .collect();
    let missing: Vec<&str> = WIRE_NAMES
        .iter()
        .filter(|name| text.contains(&format!("\"{name}\"")) && !reported.contains(*name))
        .copied()
        .collect();
    if missing.is_empty() {
        Ok(reported.iter().filter(|note| is_variant_note(note)).count())
    } else {
        Err(format!(
            "kr_protocol reports no use of {}; its transcriber uses every variant",
            missing.join(", ")
        ))
    }
}

// ---------------------------------------------------------------------------------------------
// The platform's text
// ---------------------------------------------------------------------------------------------

impl Platform {
    /// The data of the platform, a line each: `tag`, `refused`, `stamp`, `build`, `canary`, `file`
    /// and `report`.
    pub fn text(&self) -> String {
        let mut out = format!("tag\t{}\t{}\t{}\n", self.name, self.tag, self.commit);
        if let Some(refused) = &self.refused {
            out.push_str(&format!("refused\t{}\n", refused.replace('\n', " ")));
        }
        out.push_str(&format!("stamp\t{}\n", self.stamped.line()));
        for (config, exit, finished) in &self.builds {
            out.push_str(&format!(
                "build\t{config}\t{exit}\t{}\n",
                u8::from(*finished)
            ));
        }
        match &self.canary {
            Ok(count) => out.push_str(&format!("canary\tok\t{count}\n")),
            Err(error) => out.push_str(&format!("canary\tfailed\t{}\n", error.replace('\n', " "))),
        }
        for (krate, file) in &self.files {
            out.push_str(&format!("file\t{krate}\t{file}\n"));
        }
        for report in &self.reports {
            out.push_str(&format!(
                "report\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                report.config,
                report.krate,
                u8::from(report.test_only),
                report.note,
                report.macros.join(","),
                report.here.fields(),
                report.at.fields()
            ));
        }
        out
    }

    /// The platforms a text holds: each starts at a `tag` line.
    pub fn parse(text: &str) -> Result<Vec<Self>, String> {
        let mut all: Vec<Self> = Vec::new();
        for (number, line) in text.lines().enumerate() {
            let fields: Vec<&str> = line.split('\t').collect();
            let bad = || format!("line {}: the platform text has `{line}`", number + 1);
            if fields[0] == "tag" {
                let [_, name, tag, commit] = fields[..] else {
                    return Err(bad());
                };
                all.push(Self {
                    name: name.to_owned(),
                    tag: tag.to_owned(),
                    commit: commit.to_owned(),
                    canary: Err("no canary line".to_owned()),
                    ..Self::default()
                });
                continue;
            }
            let Some(current) = all.last_mut() else {
                return Err(bad());
            };
            match fields[..] {
                ["refused", why] => current.refused = Some(why.to_owned()),
                ["stamp", variants, count, accessors] => {
                    current.stamped = Stamped {
                        variants: variants == "1",
                        fields: count.parse().map_err(|_| bad())?,
                        accessors: accessors
                            .split(',')
                            .filter(|note| !note.is_empty())
                            .map(|note| {
                                METHOD_ACCESSORS
                                    .iter()
                                    .chain(&TARGET_ACCESSORS)
                                    .map(|(_, found)| *found)
                                    .find(|found| *found == note)
                                    .ok_or_else(bad)
                            })
                            .collect::<Result<_, _>>()?,
                    };
                }
                ["build", config, exit, finished] => current.builds.push((
                    config.to_owned(),
                    exit.parse().map_err(|_| bad())?,
                    finished == "1",
                )),
                ["canary", "ok", count] => current.canary = Ok(count.parse().map_err(|_| bad())?),
                ["canary", "failed", why] => current.canary = Err(why.to_owned()),
                ["file", krate, file] => {
                    current.files.insert((krate.to_owned(), file.to_owned()));
                }
                [
                    "report",
                    config,
                    krate,
                    test_only,
                    note,
                    macros,
                    hf,
                    hl,
                    hc,
                    hel,
                    hec,
                    af,
                    al,
                    ac,
                    ael,
                    aec,
                ] => {
                    let number = |text: &str| text.parse::<usize>().map_err(|_| bad());
                    current.reports.push(Report {
                        config: config.to_owned(),
                        krate: krate.to_owned(),
                        note: note.to_owned(),
                        here: Place {
                            file: hf.to_owned(),
                            line: number(hl)?,
                            column: number(hc)?,
                            end_line: number(hel)?,
                            end_column: number(hec)?,
                        },
                        at: Place {
                            file: af.to_owned(),
                            line: number(al)?,
                            column: number(ac)?,
                            end_line: number(ael)?,
                            end_column: number(aec)?,
                        },
                        macros: macros
                            .split(',')
                            .filter(|name| !name.is_empty())
                            .map(str::to_owned)
                            .collect(),
                        test_only: test_only == "1",
                    });
                }
                _ => return Err(bad()),
            }
        }
        Ok(all)
    }
}

// ---------------------------------------------------------------------------------------------
// Items of a file
// ---------------------------------------------------------------------------------------------

type Position = (usize, usize);

#[derive(Clone, Debug)]
struct Range {
    start: Position,
    end: Position,
    name: String,
    /// What the range is when no sighting is to be made in it as it is: `use … as` or `type … =`.
    alias: Option<&'static str>,
    macro_rules: bool,
}

/// The items of one file, by their extent: a function (also in an impl or a trait), a constant, a
/// `macro_rules!`, a type, a `use` and an impl, and nothing inside a function body.
struct FileItems {
    ranges: Vec<Range>,
}

fn extent(tokens: &TokenStream) -> Option<(Position, Position)> {
    let mut all = tokens.clone().into_iter();
    let first = all.next()?;
    let last = all.last().unwrap_or_else(|| first.clone());
    let start = first.span().start();
    let end = last.span().end();
    Some(((start.line, start.column + 1), (end.line, end.column + 1)))
}

struct Collector<'a> {
    file: &'a str,
    ranges: Vec<Range>,
    owner: Vec<String>,
}

impl Collector<'_> {
    fn push(
        &mut self,
        node: &impl quote::ToTokens,
        name: String,
        alias: Option<&'static str>,
        macro_rules: bool,
    ) {
        if let Some((start, end)) = extent(&node.to_token_stream()) {
            self.ranges.push(Range {
                start,
                end,
                name,
                alias,
                macro_rules,
            });
        }
    }

    fn owned(&self, name: &syn::Ident) -> String {
        match self.owner.last() {
            Some(owner) => format!("{owner}::{}", name.unraw()),
            None => name.unraw().to_string(),
        }
    }
}

fn type_name(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(path) => path.path.segments.last().map_or_else(
            || "?".to_owned(),
            |segment| segment.ident.unraw().to_string(),
        ),
        syn::Type::Reference(reference) => type_name(&reference.elem),
        _ => "?".to_owned(),
    }
}

fn renames(tree: &syn::UseTree) -> bool {
    match tree {
        syn::UseTree::Rename(_) => true,
        syn::UseTree::Path(path) => renames(&path.tree),
        syn::UseTree::Group(group) => group.items.iter().any(renames),
        _ => false,
    }
}

impl<'ast> Visit<'ast> for Collector<'_> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let name = self.owned(&node.sig.ident);
        self.push(node, name, None, false);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let owner = type_name(&node.self_ty);
        self.push(node, format!("impl {owner}"), None, false);
        self.owner.push(owner);
        for item in &node.items {
            match item {
                syn::ImplItem::Fn(method) => {
                    let name = self.owned(&method.sig.ident);
                    self.push(method, name, None, false);
                }
                syn::ImplItem::Const(constant) => {
                    let name = self.owned(&constant.ident);
                    self.push(constant, name, None, false);
                }
                syn::ImplItem::Type(alias) => {
                    let name = self.owned(&alias.ident);
                    self.push(alias, name, Some("a type alias"), false);
                }
                _ => {}
            }
        }
        self.owner.pop();
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        let owner = node.ident.unraw().to_string();
        self.push(node, owner.clone(), None, false);
        self.owner.push(owner);
        for item in &node.items {
            match item {
                syn::TraitItem::Fn(method) => {
                    let name = self.owned(&method.sig.ident);
                    self.push(method, name, None, false);
                }
                syn::TraitItem::Const(constant) => {
                    let name = self.owned(&constant.ident);
                    self.push(constant, name, None, false);
                }
                syn::TraitItem::Type(alias) => {
                    let name = self.owned(&alias.ident);
                    self.push(alias, name, Some("a type alias"), false);
                }
                _ => {}
            }
        }
        self.owner.pop();
    }

    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        self.push(node, node.ident.unraw().to_string(), None, false);
    }

    fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
        self.push(node, node.ident.unraw().to_string(), None, false);
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        self.push(node, node.ident.unraw().to_string(), None, false);
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        self.push(node, node.ident.unraw().to_string(), None, false);
    }

    fn visit_item_union(&mut self, node: &'ast syn::ItemUnion) {
        self.push(node, node.ident.unraw().to_string(), None, false);
    }

    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        self.push(
            node,
            node.ident.unraw().to_string(),
            Some("a type alias"),
            false,
        );
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        let alias = renames(&node.tree).then_some("a use that renames");
        self.push(node, format!("use:{}", self.file), alias, false);
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if let Some((_, items)) = &node.content {
            for item in items {
                self.visit_item(item);
            }
        }
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        match &node.ident {
            Some(name) if node.mac.path.is_ident("macro_rules") => {
                self.push(node, format!("macro:{}", name.unraw()), None, true);
            }
            _ => {
                let path = node
                    .mac
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.unraw().to_string())
                    .collect::<Vec<_>>()
                    .join("::");
                self.push(
                    node,
                    format!("{path}! invocation @{}", self.file),
                    None,
                    false,
                );
            }
        }
    }
}

impl FileItems {
    fn of(text: &str, file: &str) -> Result<Self, String> {
        let parsed = syn::parse_file(text).map_err(|error| {
            format!("{file}: the file does not parse, so no item is known in it ({error})")
        })?;
        let mut collector = Collector {
            file,
            ranges: Vec::new(),
            owner: Vec::new(),
        };
        collector.visit_file(&parsed);
        Ok(Self {
            ranges: collector.ranges,
        })
    }

    /// The innermost range that holds the position.
    fn at(&self, line: usize, column: usize) -> Option<&Range> {
        self.ranges
            .iter()
            .filter(|range| range.start <= (line, column) && (line, column) < range.end)
            .max_by(|left, right| left.start.cmp(&right.start).then(right.end.cmp(&left.end)))
    }

    /// The alias form the position stands in, if any (looked for outward from the innermost range).
    fn alias_at(&self, line: usize, column: usize) -> Option<&'static str> {
        self.ranges
            .iter()
            .filter(|range| range.start <= (line, column) && (line, column) < range.end)
            .find_map(|range| range.alias)
    }
}

// ---------------------------------------------------------------------------------------------
// The closed check's tokens
// ---------------------------------------------------------------------------------------------

/// A token that names a stamped item: its position (the line from 1, the column from 1).
#[derive(Debug, PartialEq, Eq)]
pub struct Candidate {
    pub line: usize,
    pub column: usize,
    /// Where the token, or the brace group after a stamped type's name, ends.
    pub end_line: usize,
    pub end_column: usize,
    pub what: String,
}

/// The keywords that may stand before a stamped type's name and a brace group without the group
/// being a value of the type. They count outside the tokens of a macro only: a macro may read any of
/// them as it likes.
const BEFORE_A_BODY: [&str; 6] = ["impl", "for", "struct", "enum", "union", "trait"];

fn decoded(literal: &proc_macro2::Literal) -> Option<String> {
    let text = literal.to_string();
    let string_like = [
        "\"", "r\"", "r#", "b\"", "br\"", "br#", "c\"", "cr\"", "cr#",
    ]
    .iter()
    .any(|prefix| text.starts_with(prefix));
    if !string_like {
        return None;
    }
    match syn::parse_str::<syn::Lit>(&text).ok()? {
        syn::Lit::Str(value) => Some(value.value()),
        syn::Lit::ByteStr(value) => Some(String::from_utf8_lossy(&value.value()).into_owned()),
        syn::Lit::CStr(value) => Some(value.value().to_string_lossy().into_owned()),
        _ => None,
    }
}

/// Whether the group at `group` holds the parameters of a function (`fn name(..)`, `fn name<..>(..)`),
/// of a function pointer (`fn(..)`) or of an `Fn` bound (`Fn(..)`): the word or the generics before it
/// say so.
fn is_parameter_group(trees: &[TokenTree], group: usize) -> bool {
    let punct = |index: usize, wanted: char| matches!(trees.get(index), Some(TokenTree::Punct(found)) if found.as_char() == wanted);
    let arrow = |index: usize| punct(index, '>') && index > 0 && punct(index - 1, '-');
    let word = |index: usize| match trees.get(index) {
        Some(TokenTree::Ident(word)) => word.to_string(),
        _ => String::new(),
    };
    let Some(mut before) = group.checked_sub(1) else {
        return false;
    };
    if punct(before, '>') && !arrow(before) {
        // The generics of `fn name<..>(..)`: back to the `<` that opens them.
        let mut depth = 0_usize;
        loop {
            if punct(before, '>') && !arrow(before) {
                depth += 1;
            } else if punct(before, '<') {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            let Some(earlier) = before.checked_sub(1) else {
                return false;
            };
            before = earlier;
        }
        let Some(name) = before.checked_sub(1) else {
            return false;
        };
        before = name;
    }
    matches!(word(before).as_str(), "fn" | "Fn" | "FnMut" | "FnOnce")
        || (!word(before).is_empty() && before > 0 && word(before - 1) == "fn")
}

/// Whether the name at `at` ends the return type of a function or a closure (`-> Name`, `-> &'a mut
/// p::Name`): the brace group after it is the body, not a value of the type. The arrow has to follow
/// the parameters of a signature or the bars of a closure's parameters; in the arguments of a macro it
/// is any token, and the group is then a value.
fn is_return_type(trees: &[TokenTree], at: usize) -> bool {
    let punct = |index: usize, wanted: char| matches!(trees.get(index), Some(TokenTree::Punct(found)) if found.as_char() == wanted);
    let mut back = at;
    while back > 0 {
        match &trees[back - 1] {
            TokenTree::Punct(found) if found.as_char() == '&' => back -= 1,
            TokenTree::Ident(word) if word == "mut" => back -= 1,
            TokenTree::Ident(_) if back >= 2 && punct(back - 2, '\'') => back -= 2,
            TokenTree::Punct(found)
                if found.as_char() == ':' && back >= 2 && punct(back - 2, ':') =>
            {
                // A `::` and the segment before it (a path that starts with `::` has none).
                back -= 2;
                if matches!(
                    back.checked_sub(1).map(|index| &trees[index]),
                    Some(TokenTree::Ident(_))
                ) {
                    back -= 1;
                }
            }
            _ => break,
        }
    }
    let Some(before) = back.checked_sub(3) else {
        return false;
    };
    if !(punct(back - 2, '-') && punct(back - 1, '>')) {
        return false;
    }
    match &trees[before] {
        TokenTree::Group(parameters) if parameters.delimiter() == Delimiter::Parenthesis => {
            is_parameter_group(trees, before)
        }
        TokenTree::Punct(bar) if bar.as_char() == '|' => (0..before).any(|index| punct(index, '|')),
        _ => false,
    }
}

/// Whether the group at `at` holds the brackets of an attribute (`#[..]`, `#![..]`).
fn is_attribute(trees: &[TokenTree], at: usize, group: &Group) -> bool {
    let punct = |index: Option<usize>, wanted: char| {
        index.is_some_and(
            |index| matches!(trees.get(index), Some(TokenTree::Punct(found)) if found.as_char() == wanted),
        )
    };
    group.delimiter() == Delimiter::Bracket
        && (punct(at.checked_sub(1), '#')
            || (punct(at.checked_sub(1), '!') && punct(at.checked_sub(2), '#')))
}

/// The keywords that may stand before a `!` that is the operator and no macro call (`return !{..}`,
/// `if !(..)`, `while !(..)`).
const BEFORE_A_NOT: [&str; 8] = [
    "if", "while", "match", "return", "in", "else", "break", "yield",
];

/// Whether the group at `at` holds the tokens of a macro: the arguments of a call (`name!(..)`,
/// `name![..]`, `name! {..}`) or the rules of a definition (`macro_rules! name {..}`). A macro may do
/// anything with its tokens, so what stands in them is not an attribute or a function.
fn is_macro_group(trees: &[TokenTree], at: usize) -> bool {
    let punct = |index: Option<usize>, wanted: char| {
        index.is_some_and(
            |index| matches!(trees.get(index), Some(TokenTree::Punct(found)) if found.as_char() == wanted),
        )
    };
    let word = |index: Option<usize>| match index.and_then(|index| trees.get(index)) {
        Some(TokenTree::Ident(word)) => word.to_string(),
        _ => String::new(),
    };
    (punct(at.checked_sub(1), '!')
        && !word(at.checked_sub(2)).is_empty()
        && !BEFORE_A_NOT.contains(&word(at.checked_sub(2)).as_str()))
        || (!word(at.checked_sub(1)).is_empty()
            && punct(at.checked_sub(2), '!')
            && word(at.checked_sub(3)) == "macro_rules")
}

/// The tokens of an attribute's brackets at an item or a statement. What a `doc` attribute holds is
/// documentation and no use: `doc = ".."` (what `///` and `//!` are read as), `doc(alias = "..")` and
/// `doc = concat!(..)`, alone or as an attribute of `cfg_attr(<condition>, ..)`. Any other attribute,
/// and the condition of a `cfg_attr`, is read as it stands.
fn walk_attribute(stream: TokenStream, found: &mut Vec<Candidate>) {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    match trees.as_slice() {
        [TokenTree::Ident(name), ..] if name == "doc" => {}
        [TokenTree::Ident(name), TokenTree::Group(arguments)]
            if name == "cfg_attr" && arguments.delimiter() == Delimiter::Parenthesis =>
        {
            let arguments: Vec<TokenTree> = arguments.stream().into_iter().collect();
            for (index, part) in arguments
                .split(|tree| matches!(tree, TokenTree::Punct(comma) if comma.as_char() == ','))
                .enumerate()
            {
                let part: TokenStream = part.iter().cloned().collect();
                if index == 0 {
                    walk_tokens(part, found, false);
                } else {
                    walk_attribute(part, found);
                }
            }
        }
        _ => walk_tokens(trees.into_iter().collect(), found, false),
    }
}

/// The tokens of `stream` that name a stamped item; `in_macro` is set inside the tokens of a macro.
fn walk_tokens(stream: TokenStream, found: &mut Vec<Candidate>, in_macro: bool) {
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    let punct = |at: usize| match trees.get(at) {
        Some(TokenTree::Punct(punct)) => Some(punct.as_char()),
        _ => None,
    };
    for (at, tree) in trees.iter().enumerate() {
        let start = tree.span().start();
        let end = tree.span().end();
        let position = |what: String| Candidate {
            line: start.line,
            column: start.column + 1,
            end_line: end.line,
            end_column: end.column + 1,
            what,
        };
        match tree {
            TokenTree::Group(group) => {
                if in_macro {
                    walk_tokens(group.stream(), found, true);
                } else if is_attribute(&trees, at, group) {
                    walk_attribute(group.stream(), found);
                } else {
                    walk_tokens(group.stream(), found, is_macro_group(&trees, at));
                }
            }
            TokenTree::Ident(ident) => {
                let name = ident.unraw().to_string();
                if VARIANTS.contains(&name.as_str()) {
                    let after_right = at >= 3
                        && punct(at - 1) == Some(':')
                        && punct(at - 2) == Some(':')
                        && matches!(&trees[at - 3], TokenTree::Ident(before) if before.unraw() == "ActionRight");
                    if !after_right {
                        found.push(position(name));
                    }
                } else if STAMPED_STRUCTS.iter().any(|(stamped, _)| *stamped == name)
                    && matches!(trees.get(at + 1), Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Brace)
                    && (in_macro
                        || !matches!(at.checked_sub(1).map(|before| &trees[before]), Some(TokenTree::Ident(before)) if BEFORE_A_BODY.contains(&before.to_string().as_str())))
                    && (in_macro || !is_return_type(&trees, at))
                {
                    let mut candidate = position(format!("{name} {{"));
                    let after = trees[at + 1].span().end();
                    candidate.end_line = after.line;
                    candidate.end_column = after.column + 1;
                    found.push(candidate);
                }
            }
            TokenTree::Literal(literal) => {
                if let Some(text) = decoded(literal)
                    && let Some(wire) = WIRE_NAMES.iter().find(|wire| text.contains(**wire))
                {
                    found.push(position(format!("\"{wire}\"")));
                }
            }
            TokenTree::Punct(_) => {}
        }
    }
}

/// The tokens of a file's text that name a stamped item.
pub fn candidates(text: &str, file: &str) -> Result<Vec<Candidate>, String> {
    let stream: TokenStream = text
        .parse()
        .map_err(|error| format!("{file}: the file cannot be tokenised ({error})"))?;
    let mut found = Vec::new();
    walk_tokens(stream, &mut found, false);
    Ok(found)
}

// ---------------------------------------------------------------------------------------------
// The sightings
// ---------------------------------------------------------------------------------------------

/// What the reports of the platforms say of a tree: the sightings of its client crates, or the texts
/// that refuse the reading.
pub type Reading = Result<Vec<Sighting>, Vec<String>>;

/// The text of each refusal, as the lead approved it.
pub mod refusal {
    pub fn platform_missing(platform: &str) -> String {
        format!("the platform {platform} was not read, so the reading is not complete")
    }
    pub fn stamp_refused(platform: &str, why: &str) -> String {
        format!("{platform}: the tree cannot be stamped ({why})")
    }
    pub fn build_missing(platform: &str, config: &str) -> String {
        format!(
            "{platform}: the configuration {config} was not built, so the reading is not complete"
        )
    }
    pub fn build_failed(platform: &str, config: &str, exit: i32) -> String {
        format!(
            "{platform}: the build of {config} failed (exit {exit}), so the compiler read nothing for it"
        )
    }
    pub fn canary_failed(platform: &str, why: &str) -> String {
        format!("{platform}: the compiler's report does not hold ({why})")
    }
    pub fn alias(file: &str, line: usize, note: &str, form: &str) -> String {
        format!(
            "{file}:{line}: the compiler reports {note} in {form}, which gives the name another name that the reading does not follow"
        )
    }
    pub fn proc_macro_member(krate: &str, package: &str) -> String {
        format!(
            "{krate}: depends on {package}, a procedural-macro crate of this workspace, which can write code the compiler reports only at its call"
        )
    }
    pub fn proc_macro_outside(krate: &str, package: &str) -> String {
        format!(
            "{krate}: depends on {package}, a procedural-macro crate that is not on the list of the ones that are read"
        )
    }
    pub fn no_site(file: &str, line: usize) -> String {
        format!("{file}:{line}: the compiler reports a use at a place that is no file of this tree")
    }
    pub fn no_tag_selected() -> String {
        "the reading selected no release tag, so it is not complete".to_owned()
    }
    pub fn tags_short(written: usize, selected: usize) -> String {
        format!(
            "the reading wrote {written} of the {selected} release tags it selected, so it is not complete"
        )
    }
}

struct Parsed {
    items: BTreeMap<String, FileItems>,
}

impl Parsed {
    fn get(&mut self, root: &Path, file: &str) -> Result<&FileItems, String> {
        if !self.items.contains_key(file) {
            let path = root.join(file);
            let text = std::fs::read_to_string(&path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            self.items
                .insert(file.to_owned(), FileItems::of(&text, file)?);
        }
        Ok(&self.items[file])
    }
}

/// The path of a file the way the tree names it: the file that the written path names once the system
/// has resolved it, each link followed before the `..` that comes after it (rustc writes a file that
/// `#[path = "../extra/more.rs"]` loads as `crates/c/src/../extra/more.rs`), relative to `root`. A file
/// outside the tree, and one that cannot be resolved, is none.
fn in_tree(root: &Path, file: &str) -> Option<String> {
    let resolved = std::fs::canonicalize(root.join(file)).ok()?;
    Some(resolved.strip_prefix(root).ok()?.display().to_string())
}

/// The sightings of the tree at `root` from the reports of the platforms that read it, and the closed
/// check over its files. `required` names the platforms that must be among them. Any text in the
/// answer means the reading is refused: a sighting list is given only when nothing refuses it.
pub fn merge(
    root: &Path,
    meta: &Meta,
    platforms: &[Platform],
    required: &[&str],
    allowed_proc_macros: &[&str],
) -> Reading {
    let root = &std::fs::canonicalize(root).map_err(|error| vec![error.to_string()])?;
    let mut problems: Vec<String> = Vec::new();
    for need in required {
        if !platforms.iter().any(|platform| platform.name == *need) {
            problems.push(refusal::platform_missing(need));
        }
    }
    for platform in platforms {
        if let Some(why) = &platform.refused {
            problems.push(refusal::stamp_refused(&platform.name, why));
            continue;
        }
        for config in PLAN {
            match platform
                .builds
                .iter()
                .find(|(name, _, _)| name == config.name)
            {
                None => problems.push(refusal::build_missing(&platform.name, config.name)),
                Some((_, exit, finished)) if *exit != 0 || !finished => {
                    problems.push(refusal::build_failed(&platform.name, config.name, *exit));
                }
                Some(_) => {}
            }
        }
        if let Err(why) = &platform.canary {
            problems.push(refusal::canary_failed(&platform.name, why));
        }
    }
    for (krate, found) in &meta.proc_macros {
        for (package, member) in found {
            if *member {
                problems.push(refusal::proc_macro_member(krate, package));
            } else if !allowed_proc_macros.contains(&package.as_str()) {
                problems.push(refusal::proc_macro_outside(krate, package));
            }
        }
    }
    if !problems.is_empty() {
        return Err(problems);
    }
    let mut parsed = Parsed {
        items: BTreeMap::new(),
    };
    let mut sightings: BTreeMap<(String, String), BTreeSet<SightKind>> = BTreeMap::new();
    let mut covered: BTreeMap<String, Vec<Place>> = BTreeMap::new();
    let mut seen: BTreeSet<&Report> = BTreeSet::new();
    for platform in platforms {
        for report in &platform.reports {
            for place in [&report.here, &report.at] {
                if let Some(file) = in_tree(root, &place.file) {
                    covered.entry(file).or_default().push(place.clone());
                }
            }
            if report.test_only || !is_client(&report.krate) || !seen.insert(report) {
                continue;
            }
            let Some(kind) = kind_of(&report.note) else {
                continue;
            };
            let Some(file) = in_tree(root, &report.at.file) else {
                problems.push(refusal::no_site(&report.at.file, report.at.line));
                continue;
            };
            let items = match parsed.get(root, &file) {
                Ok(items) => items,
                Err(error) => {
                    problems.push(error);
                    continue;
                }
            };
            for (place, shown) in [(&report.at, &file), (&report.here, &file)] {
                if let Some(form) = items.alias_at(place.line, place.column) {
                    problems.push(refusal::alias(shown, place.line, &report.note, form));
                }
            }
            let name = items
                .at(report.at.line, report.at.column)
                .map_or_else(|| format!("file:{file}"), |range| range.name.clone());
            sightings
                .entry((report.krate.clone(), name))
                .or_default()
                .insert(kind);
            // A use in the transcriber of a macro of a client crate marks the macro.
            if !report.macros.is_empty()
                && let Some(defined) = in_tree(root, &report.here.file)
                && meta.members.iter().any(|(folder, krate)| {
                    is_client(krate) && root.join(&defined).starts_with(folder)
                })
                && let Ok(items) = parsed.get(root, &defined)
                && let Some(range) = items.at(report.here.line, report.here.column)
                && range.macro_rules
            {
                let krate = meta
                    .members
                    .iter()
                    .find(|(folder, _)| root.join(&defined).starts_with(folder))
                    .map(|(_, krate)| krate.clone())
                    .unwrap_or_default();
                let name = range.name.clone();
                sightings
                    .entry((krate, name))
                    .or_default()
                    .insert(SightKind::Expands);
            }
        }
    }
    // The closed check: each token that names a stamped item, in each file a client crate holds or a
    // compiler read for it, lies on a report of some build or is an `Unread` sighting.
    let mut files: BTreeSet<(String, String)> = BTreeSet::new();
    for (krate, folder) in &meta.folders {
        if !is_client(krate) {
            continue;
        }
        // The product files of a crate: its `src` and its build script; the test targets are read
        // through the test build's reports and are not part of this check.
        let mut found = Vec::new();
        if folder.join("src").is_dir()
            && let Err(error) = rust_files(&folder.join("src"), &mut found)
        {
            problems.push(error);
            continue;
        }
        if folder.join("build.rs").is_file() {
            found.push(folder.join("build.rs"));
        }
        for path in found {
            if let Ok(relative) = path.strip_prefix(root)
                && !relative.starts_with("target")
                && !relative
                    .components()
                    .any(|part| part.as_os_str() == "node_modules")
            {
                files.insert((krate.clone(), relative.display().to_string()));
            }
        }
    }
    for platform in platforms {
        files.extend(
            platform
                .files
                .iter()
                .filter(|(krate, _)| is_client(krate))
                .cloned(),
        );
    }
    for (krate, file) in &files {
        let path = root.join(file);
        let text = match std::fs::read(&path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(error) => {
                problems.push(format!("{}: {error}", path.display()));
                continue;
            }
        };
        let places = covered.get(file);
        let candidates = if file.ends_with(".rs") {
            match candidates(&text, file) {
                Ok(found) => found,
                Err(error) => {
                    problems.push(error);
                    continue;
                }
            }
        } else {
            // A file that the compiler read and that is no Rust (`include_str!`): a wire name in it
            // stands for the file, as a literal would.
            WIRE_NAMES
                .iter()
                .filter(|wire| text.contains(**wire))
                .map(|wire| Candidate {
                    line: 0,
                    column: 0,
                    end_line: 0,
                    end_column: 0,
                    what: (*wire).to_owned(),
                })
                .collect()
        };
        for candidate in candidates {
            // The token and a report overlap: the report's span holds the token, or the token's
            // group holds the report (the fields of a struct value are reports inside its braces).
            let on_a_report = candidate.line > 0
                && places.is_some_and(|places| {
                    places.iter().any(|place| {
                        (place.line, place.column) < (candidate.end_line, candidate.end_column)
                            && (candidate.line, candidate.column)
                                < (place.end_line, place.end_column)
                    })
                });
            if on_a_report {
                continue;
            }
            let name = if file.ends_with(".rs") {
                match parsed.get(root, file) {
                    Ok(items) => items
                        .at(candidate.line, candidate.column)
                        .map_or_else(|| format!("file:{file}"), |range| range.name.clone()),
                    Err(error) => {
                        problems.push(error);
                        continue;
                    }
                }
            } else {
                format!("file:{file}")
            };
            sightings
                .entry((krate.clone(), name))
                .or_default()
                .insert(SightKind::Unread);
        }
    }
    if !problems.is_empty() {
        problems.sort();
        problems.dedup();
        return Err(problems);
    }
    Ok(sightings
        .into_iter()
        .map(|((krate, name), kinds)| Sighting { krate, name, kinds })
        .collect())
}

// ---------------------------------------------------------------------------------------------
// The record
// ---------------------------------------------------------------------------------------------

/// The lines of a record for one tag: a line that says the tag was read, then the crate, the item
/// and the kind of each sighting, one line for each kind, in the order of crate, item and kind. A tag
/// with no sighting is only the first line, so that a tag missing from a record is told from one that
/// was read and sends nothing.
pub fn record_lines(tag: &str, sightings: &[Sighting]) -> Vec<String> {
    let mut sorted: Vec<&Sighting> = sightings.iter().collect();
    sorted.sort_by(|left, right| (&left.krate, &left.name).cmp(&(&right.krate, &right.name)));
    let mut lines = vec![format!("{tag}\t\t\tRead")];
    lines.extend(sorted.iter().flat_map(|sighting| {
        sighting
            .kinds
            .iter()
            .map(move |kind| format!("{tag}\t{}\t{}\t{kind:?}", sighting.krate, sighting.name))
    }));
    lines
}

/// What a record holds: the sightings of each tag it says it read.
#[derive(Debug, Default)]
pub struct Record {
    tags: BTreeMap<String, Vec<Sighting>>,
    /// The releases that stayed unread, with the cause: a line of their own, never no sightings.
    not_read: BTreeMap<String, String>,
}

/// The line of a release that stayed unread, with its cause.
pub fn not_read_line(tag: &str, cause: &str) -> String {
    format!("{tag}\t\t{}\tNotRead", cause.replace(['\t', '\n'], " "))
}

impl Record {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut record = Self::default();
        let mut open: BTreeMap<(String, String, String), BTreeSet<SightKind>> = BTreeMap::new();
        for (number, line) in text.lines().enumerate() {
            let bad = || format!("record line {}: `{line}`", number + 1);
            let [tag, krate, name, kind] = line.split('\t').collect::<Vec<_>>()[..] else {
                return Err(bad());
            };
            if kind == "NotRead" && krate.is_empty() {
                if record.tags.contains_key(tag)
                    || record
                        .not_read
                        .insert(tag.to_owned(), name.to_owned())
                        .is_some()
                {
                    return Err(bad());
                }
                continue;
            }
            if kind == "Read" && krate.is_empty() && name.is_empty() {
                if record.not_read.contains_key(tag) {
                    return Err(bad());
                }
                record.tags.entry(tag.to_owned()).or_default();
                continue;
            }
            let kind = match kind {
                "Names" => SightKind::Names,
                "Request" => SightKind::Request,
                "Target" => SightKind::Target,
                "Expands" => SightKind::Expands,
                "Unread" => SightKind::Unread,
                _ => return Err(bad()),
            };
            if !record.tags.contains_key(tag) {
                return Err(format!(
                    "record line {}: `{tag}` has a sighting before its Read line",
                    number + 1
                ));
            }
            open.entry((tag.to_owned(), krate.to_owned(), name.to_owned()))
                .or_default()
                .insert(kind);
        }
        for ((tag, krate, name), kinds) in open {
            if let Some(list) = record.tags.get_mut(&tag) {
                list.push(Sighting { krate, name, kinds });
            }
        }
        Ok(record)
    }

    /// The sightings of a release, or the text that says the record never read it.
    pub fn sightings(&self, tag: &str) -> Result<Vec<Sighting>, String> {
        if let Some(cause) = self.not_read.get(tag) {
            return Err(format!("the release was not read: {cause}"));
        }
        self.tags
            .get(tag)
            .cloned()
            .ok_or_else(|| format!("the record of the compiler's readings has no line for {tag}"))
    }
}

// ---------------------------------------------------------------------------------------------
// Trees to read
// ---------------------------------------------------------------------------------------------

/// The name this machine gives its platform in a report.
pub fn host_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "other"
    }
}

/// The release tags a reading selects out of `all` (tag and commit, in the order of versions): the tags
/// `named` lists, separated by commas, and then the ones whose place in `all` is `k` modulo `n` when
/// `shard` is `<k>/<n>`. An empty list names every tag, and an empty shard is no shard. A selection of
/// no tag is refused: a reading of nothing is never a pass.
pub fn select_tags(
    all: &[(String, String)],
    named: Option<&str>,
    shard: Option<&str>,
) -> Result<Vec<(String, String)>, String> {
    let named: Option<Vec<&str>> = named
        .filter(|list| !list.is_empty())
        .map(|list| list.split(',').collect());
    let shard: Option<(usize, usize)> = match shard.filter(|text| !text.is_empty()) {
        None => None,
        Some(text) => {
            let bad = || "KR_COMPILER_SHARD is <k>/<n>".to_owned();
            let (k, n) = text.split_once('/').ok_or_else(bad)?;
            let (k, n): (usize, usize) =
                (k.parse().map_err(|_| bad())?, n.parse().map_err(|_| bad())?);
            if n == 0 {
                return Err(bad());
            }
            Some((k, n))
        }
    };
    let selected: Vec<(String, String)> = all
        .iter()
        .enumerate()
        .filter(|(at, (tag, _))| {
            named
                .as_ref()
                .is_none_or(|names| names.contains(&tag.as_str()))
                && shard.is_none_or(|(k, n)| at % n == k)
        })
        .map(|(_, release)| release.clone())
        .collect();
    if selected.is_empty() {
        return Err(refusal::no_tag_selected());
    }
    Ok(selected)
}

/// Whether the text of a platform's report, as this run wrote it, holds every tag of the selection
/// for `platform`: a report with fewer tags than were selected is refused.
pub fn check_written(
    platform: &str,
    selected: &[(String, String)],
    written: &str,
) -> Result<(), String> {
    if selected.is_empty() {
        return Err(refusal::no_tag_selected());
    }
    let wrote = Platform::parse(written)?;
    let count = selected
        .iter()
        .filter(|(tag, _)| {
            wrote
                .iter()
                .any(|read| read.name == platform && read.tag == *tag)
        })
        .count();
    if count < selected.len() {
        return Err(refusal::tags_short(count, selected.len()));
    }
    Ok(())
}

/// Whether the reports of the platforms hold, for each platform that must be among them, every tag that
/// the record is made for: the texts that refuse them, none when they do. Reports with no tag, or
/// without a tag of one platform, are refused: a record of nothing is never a pass.
pub fn inputs_short(
    expected: &[(String, String)],
    by_tag: &BTreeMap<String, Vec<Platform>>,
    required: &[&str],
) -> Vec<String> {
    if expected.is_empty() {
        return vec![refusal::no_tag_selected()];
    }
    let mut problems = Vec::new();
    for need in required {
        let count = expected
            .iter()
            .filter(|(tag, _)| {
                by_tag
                    .get(tag)
                    .is_some_and(|read| read.iter().any(|platform| platform.name == *need))
            })
            .count();
        if count < expected.len() {
            problems.push(format!(
                "{need}: {}",
                refusal::tags_short(count, expected.len())
            ));
        }
    }
    problems
}

/// Fetches the crates that the lock file of the tree at `root` names, with the network, before the
/// reading that is offline: Cargo's metadata needs the manifest of every package of the lock, those
/// of other platforms too, and a machine's cache holds only the ones it has needed. The exit is
/// printed. A fetch that fails is the cause that the tree is refused with.
pub fn fetch(root: &Path) -> Result<(), String> {
    let output = cargo_command()
        .args(["fetch", "--locked"])
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("{}: cargo fetch: {error}", root.display()))?;
    let exit = output.status.code().unwrap_or(-1);
    println!("cargo fetch --locked in {}: exit {exit}", root.display());
    if output.status.success() {
        return Ok(());
    }
    let said = String::from_utf8_lossy(&output.stderr);
    let tail: Vec<&str> = said.lines().rev().take(3).collect();
    Err(format!(
        "cargo fetch --locked failed (exit {exit}): {}",
        tail.into_iter().rev().collect::<Vec<_>>().join(" ")
    ))
}

/// Copies the files that Git tracks in the checkout `repository`, as they are now, into `dest`.
pub fn copy_checkout(repository: &Path, dest: &Path) -> Result<(), String> {
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(repository)
        .output()
        .map_err(|error| format!("git ls-files: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git ls-files: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    for name in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        let name = String::from_utf8_lossy(name).into_owned();
        let from = repository.join(&name);
        let to = dest.join(&name);
        if let Some(folder) = to.parent() {
            std::fs::create_dir_all(folder).map_err(|error| error.to_string())?;
        }
        if from.is_file() {
            std::fs::copy(&from, &to).map_err(|error| format!("{name}: {error}"))?;
        }
    }
    Ok(())
}

/// Copies every file under `from` into `to`.
pub fn copy_tree(from: &Path, to: &Path) {
    for entry in std::fs::read_dir(from).expect("a folder").flatten() {
        let path = entry.path();
        let target = to.join(entry.file_name());
        if path.is_dir() {
            std::fs::create_dir_all(&target).expect("a folder");
            copy_tree(&path, &target);
        } else {
            std::fs::copy(&path, &target).expect("a file");
        }
    }
}

/// Unpacks the tree of `commit` into `dest`.
pub fn unpack_commit(repository: &Path, commit: &str, dest: &Path) -> Result<(), String> {
    let output = Command::new("git")
        .args(["archive", "--format=tar", commit])
        .current_dir(repository)
        .output()
        .map_err(|error| format!("git archive {commit}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git archive {commit}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    // The files get the time of the unpacking and not the commit's time. Cargo takes the outputs of
    // an earlier tree in the same target folder as fresh when every source of a crate is older than
    // them, and the files of an old release are: a crate that differs between two releases would be
    // read as the release before has it.
    let mut archive = tar::Archive::new(output.stdout.as_slice());
    archive.set_preserve_mtime(false);
    archive
        .unpack(dest)
        .map_err(|error| format!("unpacking {commit}: {error}"))
}

/// The folder the builds of the compiler's reading share: `compiler-reader` in the target folder
/// that Cargo was given, so that the dependencies are built once for every tree; a scratch folder when
/// there is none.
pub fn builds_folder() -> Result<(PathBuf, Option<tempfile::TempDir>), String> {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(folder) => Ok((PathBuf::from(folder).join("compiler-reader"), None)),
        None => {
            let scratch = tempfile::tempdir().map_err(|error| error.to_string())?;
            Ok((scratch.path().to_path_buf(), Some(scratch)))
        }
    }
}

/// The sightings of the checkout at `repository` by this machine's platform alone (the check that a
/// train makes of the head): the stamped copy is built here, and the closed check is made over it.
pub fn read_checkout(repository: &Path) -> Reading {
    let scratch = tempfile::tempdir().map_err(|error| vec![error.to_string()])?;
    copy_checkout(repository, scratch.path()).map_err(|error| vec![error])?;
    let (builds, _keep) = builds_folder().map_err(|error| vec![error])?;
    // The tree is read unstamped for the items and the closed check: the stamp changes only
    // `kr-protocol`, which is no client.
    let unstamped = tempfile::tempdir().map_err(|error| vec![error.to_string()])?;
    copy_checkout(repository, unstamped.path()).map_err(|error| vec![error])?;
    let platform = read_platform(scratch.path(), &builds, host_name(), "checkout", "checkout");
    let meta = metadata(unstamped.path()).map_err(|error| vec![error])?;
    merge(
        unstamped.path(),
        &meta,
        &[platform],
        &[host_name()],
        OUTSIDE_PROC_MACROS,
    )
}
