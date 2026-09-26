//! Every `Debug` in the two crates, held to what may be shown.
//!
//! A `Debug` reaches places its reader did not choose as surely as a failure does: an assertion's
//! message, a log a dependency writes, a panic further up, somebody's own `{:?}`. So a type of this
//! library or of the command line that has one says only what may be shown: this program's words,
//! numbers, values claimed `Plain`, a `Shown`, and values whose own `Debug` does the same.
//!
//! What a derived `Debug` prints is decided by the types of its fields, and those come from every
//! crate, so this reads every crate in the workspace for what it declares. A type *carries* text
//! when its `Debug` can print text that arrived: text, a character, bytes, a JSON or CBOR value, a
//! path, a file, a URL, an I/O failure, a trait object; or a type of any crate whose own `Debug`
//! prints one, found to a fixpoint. A type or a `Debug` that a `macro_rules!` writes is read from
//! the macro's own text where the file that writes the macro invokes it; a type a macro declares
//! anywhere else is one this reading cannot place, and a type whose `Debug` it cannot find
//! carries. The test fails with the file, the line and the item wherever a type of the two crates
//! has
//!
//! * a derived `Debug` over a field whose type names a carrier anywhere in it, its generic
//!   arguments included, or
//! * a `Debug` written by hand that formats a carrier, or a value this reading cannot place.
//!
//! A `Debug` written by hand is read the same way in every crate: the formatter is used only to
//! write this program's words and to format values, and each value is checked for the trait that
//! formats it. Whatever this reading cannot follow counts as a carrier: a type from outside the
//! workspace that it does not list, a name it cannot place, a generic parameter formatted by hand,
//! an expression it does not read. `shown!("{}", value)` is always read: the compiler holds its
//! parts to `Plain`.
//!
//! Each name is placed where the compiler places it, through scopes, imports, globs, namespaces
//! and every set of `cfg` conditions, within the limits below, and a name this reading cannot
//! place counts against the code: in the two crates a trait, a macro, an attribute or a derive it
//! cannot place is a finding where it is written, and a type it cannot place carries. The name
//! `Debug` itself is the standard library's alone in the two crates, its trait and its derive: an
//! item named `Debug`, an import renamed to it, and an import or a glob that can give the name
//! anything else, or that this reading cannot follow, are findings. So no item, import or glob
//! this reading sees there gives the name to anything else.
//!
//! This reads the code the workspace writes, not every program Rust accepts, and it does not try
//! to hold code written to get past it. What it does not read:
//!
//! * the traits, imports and modules that a macro writes at item level in another crate: no scope
//!   gives their names here (the types and the `Debug`s it writes are read as above). So a glob
//!   of that crate can give a name this reading does not know of, which it then places where the
//!   scopes around the glob place it. In the two crates, outside the files that define what may
//!   be shown, a macro used is one this reading reads or lists, or a finding;
//! * the namespaces an item it does not read is in, and the conditions an item has in each
//!   namespace behind an import: an item of the standard library, one from outside the workspace
//!   and a value of the workspace count as a type, a trait and a macro at once, and an import
//!   counts as there in every namespace its item is in whenever the import itself is. So a glob
//!   can give a name as a macro, or as a trait a `cfg` can leave out, which this reading then takes
//!   for the trait where the compiler goes on to a trait of that name further out. The naming rule
//!   leaves no such import or glob of the name `Debug` in the two crates; for any other name, the
//!   standard library's `Debug` imported under another name among them, this is a limit;
//! * values: a function, a constant or a static is not read, so a glob that gives the name `Debug`
//!   only to one of them is not found. The compiler never takes a value for a type, a trait or a
//!   macro.

use super::*;

/* -------------------------------------------------------------------------------------------- */
/* What types from outside the workspace print                                                   */
/* -------------------------------------------------------------------------------------------- */

/// What a type from outside the workspace prints in its `Debug`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outside {
    /// Text that arrived, or bytes.
    Text,
    /// Nothing it holds: a time, a counter, a handle.
    Nothing,
    /// What its type arguments hold, and nothing else.
    Holds,
}

/// Types from outside the workspace by full path, the standard library's spelled `std::`, each
/// read in its source for what its `Debug` prints. A channel prints what it holds (a `watch`
/// channel prints its value), so channels are listed with the containers.
const OUTSIDE: &[(&str, Outside)] = &[
    ("std::string::String", Outside::Text),
    ("std::ffi::OsString", Outside::Text),
    ("std::ffi::OsStr", Outside::Text),
    ("std::ffi::CString", Outside::Text),
    ("std::ffi::CStr", Outside::Text),
    ("std::path::PathBuf", Outside::Text),
    ("std::path::Path", Outside::Text),
    ("std::fs::File", Outside::Text),
    ("std::io::Error", Outside::Text),
    ("std::fmt::Arguments", Outside::Text),
    ("std::process::Command", Outside::Text),
    ("std::process::Output", Outside::Text),
    ("serde_json::Value", Outside::Text),
    ("serde_json::value::Value", Outside::Text),
    ("serde_json::Map", Outside::Text),
    ("serde_json::map::Map", Outside::Text),
    ("serde_json::value::RawValue", Outside::Text),
    ("bytes::Bytes", Outside::Text),
    ("bytes::BytesMut", Outside::Text),
    ("url::Url", Outside::Text),
    ("ciborium::value::Value", Outside::Text),
    ("ciborium::Value", Outside::Text),
    // A relay's address, a peer's request identifier (a number or whatever text the peer sent),
    // and a TLS configuration or a connection, which print protocol bytes and connection state.
    ("iroh::RelayUrl", Outside::Text),
    ("rmcp::model::RequestId", Outside::Text),
    ("rustls::ClientConfig", Outside::Text),
    ("rustls::client::ClientConfig", Outside::Text),
    ("tokio_rustls::rustls::ClientConfig", Outside::Text),
    ("iroh::endpoint::Connection", Outside::Text),
    ("iroh::endpoint::SendStream", Outside::Text),
    ("iroh::endpoint::RecvStream", Outside::Text),
    ("std::time::Duration", Outside::Nothing),
    ("std::time::Instant", Outside::Nothing),
    ("std::time::SystemTime", Outside::Nothing),
    ("std::marker::PhantomData", Outside::Nothing),
    ("std::fmt::Error", Outside::Nothing),
    ("std::sync::atomic::AtomicBool", Outside::Nothing),
    ("std::sync::atomic::AtomicU8", Outside::Nothing),
    ("std::sync::atomic::AtomicU16", Outside::Nothing),
    ("std::sync::atomic::AtomicU32", Outside::Nothing),
    ("std::sync::atomic::AtomicU64", Outside::Nothing),
    ("std::sync::atomic::AtomicUsize", Outside::Nothing),
    ("std::sync::atomic::AtomicI32", Outside::Nothing),
    ("std::sync::atomic::AtomicI64", Outside::Nothing),
    ("tokio::time::Instant", Outside::Nothing),
    // A child process prints its three pipes, and a pipe its handle, each by the handle alone.
    ("std::process::Child", Outside::Nothing),
    ("std::io::PipeWriter", Outside::Nothing),
    ("std::io::PipeReader", Outside::Nothing),
    // An address is numbers: a host's address and a port.
    ("std::net::SocketAddr", Outside::Nothing),
    ("std::net::IpAddr", Outside::Nothing),
    ("std::net::Ipv4Addr", Outside::Nothing),
    ("std::net::Ipv6Addr", Outside::Nothing),
    ("std::option::Option", Outside::Holds),
    ("std::result::Result", Outside::Holds),
    ("std::vec::Vec", Outside::Holds),
    ("std::boxed::Box", Outside::Holds),
    ("std::rc::Rc", Outside::Holds),
    ("std::sync::Arc", Outside::Holds),
    ("std::borrow::Cow", Outside::Holds),
    ("std::collections::HashMap", Outside::Holds),
    ("std::collections::BTreeMap", Outside::Holds),
    ("std::collections::HashSet", Outside::Holds),
    ("std::collections::BTreeSet", Outside::Holds),
    ("std::collections::VecDeque", Outside::Holds),
    ("std::collections::hash_map::HashMap", Outside::Holds),
    ("std::collections::btree_map::BTreeMap", Outside::Holds),
    ("std::sync::Mutex", Outside::Holds),
    ("std::sync::RwLock", Outside::Holds),
    ("std::sync::OnceLock", Outside::Holds),
    ("std::cell::Cell", Outside::Holds),
    ("std::cell::RefCell", Outside::Holds),
    ("std::cell::OnceCell", Outside::Holds),
    ("std::cmp::Reverse", Outside::Holds),
    ("tokio::sync::Mutex", Outside::Holds),
    ("tokio::sync::RwLock", Outside::Holds),
    ("tokio::sync::watch::Sender", Outside::Holds),
    ("tokio::sync::watch::Receiver", Outside::Holds),
    ("tokio::sync::mpsc::Sender", Outside::Holds),
    ("tokio::sync::mpsc::Receiver", Outside::Holds),
    ("tokio::sync::mpsc::UnboundedSender", Outside::Holds),
    ("tokio::sync::mpsc::UnboundedReceiver", Outside::Holds),
    ("tokio::sync::oneshot::Sender", Outside::Holds),
    ("tokio::sync::oneshot::Receiver", Outside::Holds),
    ("tokio::sync::broadcast::Sender", Outside::Holds),
    ("tokio::sync::broadcast::Receiver", Outside::Holds),
    ("zeroize::Zeroizing", Outside::Holds),
];

/// The prelude's types, which every file names without importing them.
const PRELUDE: &[(&str, &str)] = &[
    ("Option", "std::option::Option"),
    ("Result", "std::result::Result"),
    ("Vec", "std::vec::Vec"),
    ("String", "std::string::String"),
    ("Box", "std::boxed::Box"),
];

/// The prelude's traits, which every file names without importing them.
const PRELUDE_TRAITS: [&str; 31] = [
    "AsMut",
    "AsRef",
    "Clone",
    "Copy",
    "Default",
    "DoubleEndedIterator",
    "Drop",
    "Eq",
    "ExactSizeIterator",
    "Extend",
    "Fn",
    "FnMut",
    "FnOnce",
    "From",
    "FromIterator",
    "Future",
    "Into",
    "IntoFuture",
    "IntoIterator",
    "Iterator",
    "Ord",
    "PartialEq",
    "PartialOrd",
    "Send",
    "Sized",
    "Sync",
    "ToOwned",
    "ToString",
    "TryFrom",
    "TryInto",
    "Unpin",
];

/// The standard library's macros, which every file names without importing them.
const STD_MACROS: [&str; 35] = [
    "assert",
    "assert_eq",
    "assert_ne",
    "cfg",
    "column",
    "compile_error",
    "concat",
    "dbg",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
    "env",
    "eprint",
    "eprintln",
    "file",
    "format",
    "format_args",
    "include",
    "include_bytes",
    "include_str",
    "line",
    "matches",
    "module_path",
    "option_env",
    "panic",
    "print",
    "println",
    "stringify",
    "thread_local",
    "todo",
    "unimplemented",
    "unreachable",
    "vec",
    "write",
    "writeln",
];

/// The `Debug` trait, and the library's macros that this reading acts on, by full path.
const DEBUG_TRAIT: &str = "std::fmt::Debug";
const DEBUG_AS_NAME: &str = "kr_client::debug_as_name";
const DEBUG_FIELDS: &str = "kr_client::debug_fields";
const DEBUG_AS_DISPLAY: &str = "kr_client::debug_as_display";
const SHOWN_MACRO: &str = "kr_client::shown";

/// The rule that keeps the name `Debug` from leading anywhere but the standard library's trait and
/// derive in the two crates, which each place it finds says.
const ONLY_STD_DEBUG: &str = "only the standard library's Debug may carry the name Debug";

/// The library's macros, which the files that define what may be shown write: what each writes is
/// read where it is used, or is theirs to decide.
const LIBRARY_MACROS: [&str; 6] = [
    SHOWN_MACRO,
    DEBUG_AS_NAME,
    DEBUG_FIELDS,
    DEBUG_AS_DISPLAY,
    "kr_client::display_as_said",
    "kr_client::plain",
];

/// Macros from outside the workspace that the two crates may use, each read in its source for
/// writing no type and no `impl` a caller can reach where it is used.
const QUIET_MACROS: [&str; 4] = [
    "serde_json::json",
    "tokio::join",
    "tokio::pin",
    "tokio::select",
];

/// The standard library's macros that a file names through a module: `std::pin::pin!`.
const STD_MODULE_MACROS: [&str; 5] = ["addr_of", "addr_of_mut", "offset_of", "pin", "ready"];

/// Traits from outside the workspace that the two crates implement, each read in its source for
/// being its crate's own trait and not the `Debug` trait under another name.
const QUIET_TRAITS: [&str; 7] = [
    "rmcp::ServerHandler",
    "rmcp::transport::Transport",
    "serde::Deserialize",
    "serde::de::DeserializeSeed",
    "serde::de::Visitor",
    "tokio::io::AsyncRead",
    "tokio::io::AsyncWrite",
];

/// The derives the prelude gives every file.
const PRELUDE_DERIVES: [&str; 9] = [
    "Clone",
    "Copy",
    "Debug",
    "Default",
    "Eq",
    "Hash",
    "Ord",
    "PartialEq",
    "PartialOrd",
];

/// Derives from outside the workspace that the two crates may use, each read in its source for
/// writing no `Debug`.
const QUIET_DERIVES: [&str; 8] = [
    "clap::Args",
    "clap::Parser",
    "clap::Subcommand",
    "clap::ValueEnum",
    "schemars::JsonSchema",
    "serde::Deserialize",
    "serde::Serialize",
    "thiserror::Error",
];

/// Attribute macros from outside the workspace that the two crates may use, each read in its
/// source for writing no `Debug`.
const QUIET_ATTRIBUTES: [&str; 3] = ["rmcp::tool", "rmcp::tool_handler", "rmcp::tool_router"];

/// Where a name the compiler reads as an attribute of its own, or as a helper of a derive, is
/// placed: such an attribute writes nothing, and a macro of the same name in scope makes the name
/// ambiguous to the compiler.
const INERT: &str = "{inert}";

/// The attributes the compiler reads itself, and the helper attributes of the derives the two
/// crates may use.
const INERT_ATTRIBUTES: [&str; 50] = [
    "allow",
    "arg",
    "automatically_derived",
    "backtrace",
    "cfg",
    "cfg_attr",
    "clap",
    "cold",
    "collapse_debuginfo",
    "command",
    "crate_name",
    "crate_type",
    "debugger_visualizer",
    "default",
    "deny",
    "deprecated",
    "derive",
    "doc",
    "error",
    "expect",
    "export_name",
    "forbid",
    "from",
    "global_allocator",
    "group",
    "ignore",
    "inline",
    "link",
    "link_name",
    "link_section",
    "macro_export",
    "macro_use",
    "must_use",
    "no_mangle",
    "non_exhaustive",
    "panic_handler",
    "path",
    "recursion_limit",
    "repr",
    "schemars",
    "serde",
    "should_panic",
    "source",
    "target_feature",
    "test",
    "track_caller",
    "unsafe",
    "used",
    "value",
    "warn",
];

/// The tools whose attributes the compiler leaves to them, which write nothing.
const TOOL_ATTRIBUTES: [&str; 3] = ["clippy", "diagnostic", "rustfmt"];

/// The words that can stand before a `!` without naming a macro: `if !done`, `return !done`.
const KEYWORDS: [&str; 31] = [
    "as", "async", "await", "box", "break", "const", "continue", "crate", "dyn", "else", "enum",
    "extern", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub",
    "ref", "return", "static", "unsafe", "where", "while", "yield",
];

/// What an alias's expansion writes for a parameter of the type the alias was used in, which no
/// path can spell.
const PARAMETER: &str = "{a parameter}";

/// The primitive types whose `Debug` is a number or a switch.
const NUMBERS: [&str; 15] = [
    "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "bool",
    "f32", "f64",
];

/// The standard library's types whose `len`, `is_empty`, `is_some` and `is_none` return a number
/// or a switch, whatever they hold.
const MEASURED: [&str; 11] = [
    "std::string::String",
    "prim::str",
    "std::vec::Vec",
    "std::option::Option",
    "std::result::Result",
    "std::collections::HashMap",
    "std::collections::BTreeMap",
    "std::collections::HashSet",
    "std::collections::BTreeSet",
    "std::collections::VecDeque",
    "bytes::Bytes",
];

/// The standard library's sequences, which hold bytes when their element is a byte.
const SEQUENCES: [&str; 5] = [
    "std::vec::Vec",
    "std::collections::VecDeque",
    "std::collections::BinaryHeap",
    "std::collections::HashSet",
    "std::collections::BTreeSet",
];

/// The methods that measure one of [`MEASURED`].
const MEASURES: [&str; 6] = ["len", "is_empty", "is_some", "is_none", "is_ok", "is_err"];

/* -------------------------------------------------------------------------------------------- */
/* What every crate declares                                                                     */
/* -------------------------------------------------------------------------------------------- */

/// A type as written somewhere, so its names resolve as the compiler resolves them there.
#[derive(Clone)]
struct Written {
    /// The file, as an index into the sources.
    source: usize,
    /// The scope it is written in.
    scope: usize,
    /// The generic parameters in force there.
    generics: Vec<String>,
    /// The type.
    tokens: Vec<Located>,
}

/// One field of a declared type.
struct Member {
    name: String,
    written: Written,
    /// Whether a `cfg` this reading cannot decide can leave it out.
    conditional: bool,
}

impl Shape {
    /// The members whose name or position no `cfg` can change: every named field, and the tuple's
    /// fields before the first one a `cfg` can leave out, which moves every position after it.
    fn stable(&self) -> impl Iterator<Item = &Member> {
        let moving = self
            .members
            .iter()
            .position(|member| member.conditional && member.name.parse::<usize>().is_ok())
            .unwrap_or(usize::MAX);
        self.members
            .iter()
            .enumerate()
            .filter(move |(at, member)| member.name.parse::<usize>().is_err() || *at < moving)
            .map(|(_, member)| member)
    }
}

/// A struct's one shape, or one variant of an enum.
struct Shape {
    name: String,
    members: Vec<Member>,
    /// Whether a `cfg` this reading cannot decide can leave the variant out.
    conditional: bool,
}

/// One struct, enum or union some crate declares. A path can have several, one for each set of
/// `cfg` conditions; each is read.
struct Declared {
    /// The file, as an index into the sources.
    source: usize,
    /// The index of its `struct`, `enum` or `union` in the source's tokens; none for one a macro
    /// declares.
    keyword: Option<usize>,
    /// The name it is declared with.
    name: String,
    /// The line of its `derive` that names `Debug`, when it derives one.
    derived: Option<usize>,
    shapes: Vec<Shape>,
}

/// A `Debug` written by hand.
struct ByHand {
    /// The type it is for, by full path.
    target: String,
    /// The type as the `impl` writes it, which is what `self` is.
    written: Written,
    /// The line of the `impl`.
    line: usize,
    /// The `impl` block, from its opening brace to its closing one.
    tokens: Vec<Located>,
    /// Where `tokens` start among the source's own tokens, so that a name in the body is placed in
    /// the scope it is written in; none for a body a macro writes, whose names are placed where
    /// the macro is used.
    origin: Option<usize>,
}

/// Why a type carries text, or why a `Debug` written by hand is refused.
type Why = String;

/// Where each path this reading places leads: by the source and scope it is written in, the path,
/// and what it is read as.
type Placements = BTreeMap<(usize, usize, Vec<String>, Kind), Result<String, Why>>;

/// What every crate in a workspace declares, and what the rule holds of the two crates' `Debug`s.
struct Debugs {
    sources: Vec<Source>,
    /// How many of `sources`, from the first, are the two crates' own.
    guarded: usize,
    /// The workspace's crates, as code names them.
    crates: BTreeSet<String>,
    /// Every module of the workspace by its full path, with each source and scope that gives its
    /// names: one for each set of `cfg` conditions that declares it.
    modules: BTreeMap<String, Vec<(usize, usize)>>,
    /// Every macro a crate of the workspace writes, by full path, and whether it exports it at its
    /// crate's root.
    macros: BTreeMap<String, bool>,
    /// The exported macros one of whose definitions no `cfg` this reading cannot decide can leave
    /// out.
    always_macros: BTreeSet<String>,
    /// The crates that take macros from another crate with `#[macro_use]`, where a macro's single
    /// name can be one this reading does not list.
    macro_use: BTreeSet<String>,
    /// Each type by full path, with every definition it has.
    declared: BTreeMap<String, Vec<Declared>>,
    /// Each type alias by full path, with every definition it has.
    type_aliases: BTreeMap<String, Vec<Written>>,
    /// Every trait some crate defines, by full path.
    traits: BTreeSet<String>,
    by_hand: Vec<ByHand>,
    known: Known,
    plain: BTreeSet<String>,
    /// The types the two files that define what may be shown declare, which write their own
    /// renderings.
    shown_types: BTreeSet<String>,
    /// The functions of those two files that are declared to return a `Shown`.
    shown_functions: BTreeSet<String>,
    /// The types whose `Debug` is their `Display`: those the library's `debug_as_display!` names.
    as_display: BTreeSet<String>,
    /// The places in the two crates where a trait or a macro cannot be placed, a macro is one this
    /// reading does not read, or an extern crate changes what a path names.
    unplaced: Vec<Finding>,
    /// Where each path this reading has placed leads, by where it is written and what it names.
    placed: std::cell::RefCell<Placements>,
    /// How many aliases are being expanded, one inside another.
    expanding: std::cell::Cell<usize>,
}

/// Every crate under the workspace's `crates/`, by the name code gives it, and its library's root.
fn workspace_crates(workspace: &Path) -> Vec<(String, PathBuf)> {
    let mut crates = Vec::new();
    let Ok(entries) = std::fs::read_dir(workspace.join("crates")) else {
        return crates;
    };
    for entry in entries.flatten() {
        let root = entry.path().join("src").join("lib.rs");
        let Ok(manifest) = std::fs::read_to_string(entry.path().join("Cargo.toml")) else {
            continue;
        };
        let name = manifest.lines().find_map(|line| {
            let value = line
                .trim()
                .strip_prefix("name")?
                .trim_start()
                .strip_prefix('=')?;
            Some(value.trim().trim_matches('"').replace('-', "_"))
        });
        if let Some(name) = name
            && root.exists()
        {
            crates.push((name, root));
        }
    }
    crates.sort();
    crates
}

impl Debugs {
    /// Reads `guarded`, the two crates' own files, and every crate of `workspace`: first every
    /// type and type alias each declares, then, with every type known, every `Debug` and every
    /// macro the two crates use, each name placed where it is written.
    fn read(workspace: &Path, guarded: Vec<Source>) -> Self {
        let guarded_names: BTreeSet<String> = guarded
            .iter()
            .map(|source| source.crate_name.clone())
            .collect();
        let mut sources = guarded;
        let count = sources.len();
        let mut crates: BTreeSet<String> = guarded_names.clone();
        for (name, root) in workspace_crates(workspace) {
            crates.insert(name.clone());
            if guarded_names.contains(&name) {
                continue;
            }
            if let Ok(found) = read_crate(workspace, &root, &name, false) {
                sources.extend(found);
            }
        }
        let mut modules = BTreeMap::new();
        let mut macros = BTreeMap::new();
        let mut macro_use = BTreeSet::new();
        for (index, source) in sources.iter().enumerate() {
            for (scope, entry) in source.scopes.iter().enumerate() {
                if !entry.block {
                    modules
                        .entry(source.module_of(scope).join("::"))
                        .or_insert_with(Vec::new)
                        .push((index, scope));
                }
            }
            let tokens = &source.tokens;
            let attributed = |at: usize, attribute: &str| {
                tokens[before_item(tokens, at)..at]
                    .iter()
                    .any(|located| ident(Some(located)) == Some(attribute))
            };
            for (name, open, _) in macro_bodies(tokens) {
                // `macro_rules`, `!` and the name come before the body.
                let exported = attributed(open - 3, "macro_export");
                *macros
                    .entry(format!("{}::{name}", source.crate_name))
                    .or_insert(false) |= exported;
            }
            for at in 0..tokens.len() {
                if ident(tokens.get(at)) == Some("extern")
                    && ident(tokens.get(at + 1)) == Some("crate")
                    && attributed(at, "macro_use")
                {
                    macro_use.insert(source.crate_name.clone());
                }
            }
        }
        let known = collect_known(&sources[..count], &aliases(&sources[..count]));
        let mut debugs = Self {
            sources,
            guarded: count,
            crates,
            modules,
            macros,
            always_macros: BTreeSet::new(),
            macro_use,
            declared: BTreeMap::new(),
            type_aliases: BTreeMap::new(),
            traits: BTreeSet::new(),
            by_hand: Vec::new(),
            known,
            plain: BTreeSet::new(),
            shown_types: BTreeSet::new(),
            shown_functions: BTreeSet::new(),
            as_display: BTreeSet::new(),
            unplaced: Vec::new(),
            placed: std::cell::RefCell::new(BTreeMap::new()),
            expanding: std::cell::Cell::new(0),
        };
        debugs.always_macros = debugs.exported_always();
        for index in 0..debugs.sources.len() {
            debugs.declare_types(index);
        }
        for index in 0..debugs.sources.len() {
            debugs.declare_debugs(index);
        }
        debugs.plain = debugs
            .known
            .plain
            .iter()
            .map(|path| debugs.canonical(path))
            .collect();
        debugs
    }

    /// The source a finding names, when it is one of the two crates' own.
    fn guarded_file(&self, index: usize) -> Option<&str> {
        let name = self.sources[index].name.as_str();
        (index < self.guarded && !SHOWN_FILES.contains(&name)).then_some(name)
    }

    /// The full path of the type the path `segments` names where `written` is written, placed as
    /// the compiler places it, or why this reading cannot place it.
    fn resolve(&self, written: &Written, segments: &[String]) -> Result<String, Why> {
        self.place(written.source, written.scope, segments, Kind::Type)
    }

    /// Reads the types and type aliases one source declares, and the types the macros it writes
    /// declare where it uses them.
    fn declare_types(&mut self, index: usize) {
        let tokens = self.sources[index].tokens.clone();
        let macros = macro_bodies(&tokens);
        for at in 0..tokens.len() {
            if in_macro_body(&macros, at) {
                continue;
            }
            let scope = self.sources[index].scope_at(at);
            match ident(tokens.get(at)) {
                Some("struct" | "enum" | "union")
                    if ident(tokens.get(at + 1)).is_some()
                        && !(at > 0
                            && (punct(tokens.get(at - 1), '.')
                                || ident(tokens.get(at - 1)) == Some("fn"))) =>
                {
                    self.declare_type(index, &tokens, at, scope, None);
                }
                Some("type")
                    if ident(tokens.get(at + 1)).is_some()
                        && !self.sources[index].scopes[scope].block =>
                {
                    self.declare_alias(index, &tokens, at, scope);
                }
                Some("trait") => {
                    if let Some(name) = ident(tokens.get(at + 1)) {
                        let path = self.sources[index].defined_path(scope, name);
                        self.traits.insert(path);
                    }
                }
                _ => {}
            }
        }
        for (invoked, scope, expanded) in self.expansions(index, &tokens, &macros) {
            for item in 0..expanded.len() {
                match ident(expanded.get(item)) {
                    Some("struct" | "enum" | "union")
                        if ident(expanded.get(item + 1)).is_some() =>
                    {
                        self.declare_type(index, &expanded, item, scope, Some(invoked));
                    }
                    Some("trait") => {
                        if let Some(name) = ident(expanded.get(item + 1)) {
                            let path = self.sources[index].defined_path(scope, name);
                            self.traits.insert(path);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Each place a source uses a macro it writes itself: the name's index, its scope, and the
    /// macro's body with the item's name the use gives it. A name is such a macro only where the
    /// compiler can take it so: after the macro is written, in its scope or one inside it; each
    /// macro of that name there is read, since `cfg` decides which of them is the latest.
    /// Anywhere else the name is another macro, whose types this reading does not know.
    fn expansions(
        &self,
        index: usize,
        tokens: &[Located],
        macros: &[(String, usize, usize)],
    ) -> Vec<(usize, usize, Vec<Located>)> {
        let source = &self.sources[index];
        let mut found = Vec::new();
        for at in 0..tokens.len() {
            let Some(word) = ident(tokens.get(at)) else {
                continue;
            };
            if !punct(tokens.get(at + 1), '!')
                || in_macro_body(macros, at)
                || (at > 0
                    && (ident(tokens.get(at - 1)) == Some("macro_rules")
                        || punct(tokens.get(at - 1), ':')))
            {
                continue;
            }
            let scope = source.scope_at(at);
            let Some(group_close) = closing(tokens, at + 2) else {
                continue;
            };
            let invoked = first_word(&tokens[at + 3..group_close]);
            // `macro_rules`, `!` and the name come before the body.
            for (_, open, close) in macros.iter().filter(|(name, open, close)| {
                name == word && *close < at && encloses(source, source.scope_at(open - 3), scope)
            }) {
                found.push((
                    at,
                    scope,
                    substitute(&tokens[*open + 1..*close], invoked.as_deref()),
                ));
            }
        }
        found
    }

    /// Reads what one source writes a `Debug` with, once every type is known: each `impl` of the
    /// `Debug` trait, its own or one a macro it writes writes, the trait placed where the `impl`
    /// is written; and in the two crates, each macro used. In a file the rule holds, a trait this
    /// reading cannot place is recorded where it is.
    fn declare_debugs(&mut self, index: usize) {
        let tokens = self.sources[index].tokens.clone();
        let macros = macro_bodies(&tokens);
        let file = self.guarded_file(index).map(ToOwned::to_owned);
        for (at, start, at_for) in trait_impls(&tokens) {
            if in_macro_body(&macros, at) {
                continue;
            }
            let scope = self.sources[index].scope_at(at);
            let item = format!("impl {}", spelled(&tokens[start..at_for]));
            match self.trait_named(index, scope, &tokens[start..at_for]) {
                Ok(path) if self.is_debug_trait(&path) => {
                    self.declare_by_hand(index, &tokens, at, at_for, scope, None);
                }
                // A trait from outside is known only from the list: under another name, it can be
                // the `Debug` trait.
                Ok(path) if self.outside(&path) && !QUIET_TRAITS.contains(&path.as_str()) => {
                    self.record(
                        file.as_deref(),
                        tokens[at].line,
                        item,
                        format!(
                            "a trait from outside the workspace this reading does not list: {path}"
                        ),
                    );
                }
                Ok(_) => {}
                Err(why) => self.record(
                    file.as_deref(),
                    tokens[at].line,
                    item,
                    format!("a trait this reading cannot place: {why}"),
                ),
            }
        }
        for (invoked, scope, expanded) in self.expansions(index, &tokens, &macros) {
            for (at, start, at_for) in trait_impls(&expanded) {
                if matches!(
                    self.trait_named(index, scope, &expanded[start..at_for]),
                    Ok(path) if self.is_debug_trait(&path)
                ) {
                    self.declare_by_hand(index, &expanded, at, at_for, scope, Some(invoked));
                }
            }
        }
        if index < self.guarded {
            self.declare_used_macros(index, &tokens, &macros, file.as_deref());
            self.hold_the_name_debug(index);
        }
    }

    /// Holds one file of the two crates to the rule that the name `Debug` is the standard
    /// library's there, its trait and its derive, so that the name leads nowhere else through any
    /// scope, glob, namespace or `cfg`. Recorded, under every set of conditions and in the files
    /// that define what may be shown too: an item named `Debug`, written or in a macro's body; an
    /// import renamed to `Debug`; and an import or a glob that gives the name anything else, or
    /// that this reading cannot follow. This reading does not read values, so a glob that gives
    /// the name only to a function, a constant or a static of another crate is not found; the
    /// compiler never takes a value for a trait or a derive.
    fn hold_the_name_debug(&mut self, index: usize) {
        let source = &self.sources[index];
        let tokens = &source.tokens;
        let mut found = Vec::new();
        for at in 1..tokens.len() {
            if ident(tokens.get(at)) != Some("Debug") {
                continue;
            }
            let item = match ident(tokens.get(at - 1)) {
                Some(
                    keyword @ ("struct" | "enum" | "union" | "trait" | "type" | "fn" | "const"
                    | "static" | "mod"),
                ) => format!("{keyword} Debug"),
                Some("mut") if ident(tokens.get(at.wrapping_sub(2))) == Some("static") => {
                    "static mut Debug".to_owned()
                }
                _ if punct(tokens.get(at - 1), '!')
                    && ident(tokens.get(at.wrapping_sub(2))) == Some("macro_rules") =>
                {
                    "macro_rules! Debug".to_owned()
                }
                _ => continue,
            };
            found.push((tokens[at].line, item, "an item named Debug".to_owned()));
        }
        for (position, import) in source.imports.iter().enumerate() {
            if import.local != "Debug" {
                continue;
            }
            let spelled = format!(
                "{}{}",
                if import.global { "::" } else { "" },
                import.written.join("::")
            );
            if import.written.last().map(String::as_str) != Some("Debug") {
                found.push((
                    import.line,
                    format!("use {spelled} as Debug"),
                    "an import renamed to Debug".to_owned(),
                ));
                continue;
            }
            // An import's own path is read without it, as the compiler reads it.
            let mut visiting = vec![format!("import {index} {position}")];
            let what = match self.target(
                index,
                import.scope,
                &import.written,
                import.global,
                &mut visiting,
            ) {
                Ok(path) if std_item(&path) == Some("Debug") => continue,
                Ok(path) => format!("an import that gives Debug to {path}"),
                Err(why) => format!("an import of Debug this reading cannot place: {why}"),
            };
            found.push((import.line, format!("use {spelled}"), what));
        }
        for (position, glob) in source.globs.iter().enumerate() {
            let module = source.module_of(glob.scope).join("::");
            let item = format!(
                "use {}{}::*",
                if glob.global { "::" } else { "" },
                glob.written.join("::")
            );
            match self.through_glob(index, position, "Debug", Space::Any, &mut Vec::new()) {
                Ok(given) => {
                    for named in given {
                        if named.reach.seen_from(&module) == Some(false)
                            || std_item(&named.path) == Some("Debug")
                        {
                            continue;
                        }
                        found.push((
                            glob.line,
                            item.clone(),
                            format!("a glob that can give Debug to {}", named.path),
                        ));
                    }
                }
                Err(why) => found.push((
                    glob.line,
                    item,
                    format!("a glob whose Debug this reading cannot place: {why}"),
                )),
            }
        }
        let file = source.name.clone();
        self.unplaced
            .extend(found.into_iter().map(|(line, item, what)| Finding {
                file: file.clone(),
                line,
                item,
                what: format!("{what}; {ONLY_STD_DEBUG}"),
            }));
    }

    /// Reads each macro a source of the two crates uses, placed where it is used: the library's
    /// two macros that write a `Debug`, as the `Debug` each writes, and `debug_as_display!`, whose
    /// types' `Debug` is their `Display`; and each attribute and derive. In a file the rule holds,
    /// a macro, an attribute or a derive this reading cannot place or does not read, and an
    /// extern crate, are recorded where they are.
    fn declare_used_macros(
        &mut self,
        index: usize,
        tokens: &[Located],
        macros: &[(String, usize, usize)],
        file: Option<&str>,
    ) {
        for at in 0..tokens.len() {
            if in_macro_body(macros, at) {
                continue;
            }
            let line = tokens[at].line;
            let scope = self.sources[index].scope_at(at);
            if ident(tokens.get(at)) == Some("extern") && ident(tokens.get(at + 1)) == Some("crate")
            {
                self.record(
                    file,
                    line,
                    "extern crate".to_owned(),
                    "an extern crate, which can change what a path names".to_owned(),
                );
                continue;
            }
            if punct(tokens.get(at), '#') {
                let open = at + 1 + usize::from(punct(tokens.get(at + 1), '!'));
                if punct(tokens.get(open), '[')
                    && let Some(close) = closing(tokens, open)
                {
                    self.declare_attribute(
                        index,
                        tokens,
                        at,
                        scope,
                        &tokens[open + 1..close],
                        file,
                    );
                }
                continue;
            }
            let Some(word) = ident(tokens.get(at)) else {
                continue;
            };
            if !punct(tokens.get(at + 1), '!')
                || !matches!(
                    tokens.get(at + 2).map(|located| &located.token),
                    Some(Token::Punct('(' | '[' | '{'))
                )
                || KEYWORDS.contains(&word)
            {
                continue;
            }
            let segments = path_ending_at(tokens, at);
            let item = format!("{}!", segments.join("::"));
            match self.place(index, scope, &segments, Kind::Macro).as_deref() {
                Ok(DEBUG_AS_NAME) => self.declare_written(index, tokens, at, scope, false),
                Ok(DEBUG_FIELDS) => self.declare_written(index, tokens, at, scope, true),
                Ok(DEBUG_AS_DISPLAY) => {
                    for argument in arguments(tokens, at + 2).unwrap_or_default() {
                        let (named, after) = spelled_path(&argument);
                        if after == argument.len()
                            && let Ok(path) = self.place(index, scope, &named, Kind::Type)
                        {
                            self.as_display.insert(path);
                        }
                    }
                }
                Ok(path) if macro_read(path) => {}
                Ok(path) => self.record(
                    file,
                    line,
                    item,
                    format!(
                        "a macro this reading does not read, which can write a type or a Debug: \
                         {path}"
                    ),
                ),
                Err(why) => self.record(
                    file,
                    line,
                    item,
                    format!("a macro this reading cannot place: {why}"),
                ),
            }
        }
    }

    /// Records a place in a file the rule holds where a trait, a macro, an attribute or a derive
    /// cannot be placed, or is one this reading does not read.
    fn record(&mut self, file: Option<&str>, line: usize, item: String, what: String) {
        if let Some(file) = file {
            self.unplaced.push(Finding {
                file: file.to_owned(),
                line,
                item,
                what,
            });
        }
    }

    /// Reads one attribute of the two crates, the tokens inside its brackets, placed where it is
    /// written: one the compiler reads itself or a derive's helper writes nothing, as do the
    /// attribute macros listed and a tool's attributes; each attribute under `cfg_attr` and each
    /// derive is read in turn.
    fn declare_attribute(
        &mut self,
        index: usize,
        tokens: &[Located],
        at: usize,
        scope: usize,
        attribute: &[Located],
        file: Option<&str>,
    ) {
        let line = tokens[at].line;
        let (segments, after) = spelled_path(attribute);
        let item = format!("#[{}]", segments.join("::"));
        let placed = match self.place(index, scope, &segments, Kind::Attribute) {
            Ok(placed) => placed,
            Err(why) => {
                return self.record(
                    file,
                    line,
                    item,
                    format!("an attribute this reading cannot place: {why}"),
                );
            }
        };
        // A tool's attribute, `#[rustfmt::skip]`, where no scope gives the tool's name another
        // meaning: then the path is placed as it is written.
        if segments.len() > 1
            && TOOL_ATTRIBUTES.contains(&segments[0].as_str())
            && placed == segments.join("::")
        {
            return;
        }
        // An attribute the compiler reads itself, by the name it has under the standard library
        // too: `#[std::prelude::v1::derive(…)]` is `derive`.
        let builtin = placed
            .strip_prefix(INERT)
            .and_then(|rest| rest.strip_prefix("::"))
            .or_else(|| std_item(&placed).filter(|name| INERT_ATTRIBUTES.contains(name)));
        match builtin {
            // `cfg_attr(predicate, attribute, …)`: each attribute after the predicate.
            Some("cfg_attr") => {
                for part in arguments(attribute, after)
                    .unwrap_or_default()
                    .iter()
                    .skip(1)
                {
                    self.declare_attribute(index, tokens, at, scope, part, file);
                }
            }
            Some("derive") => {
                for derive in arguments(attribute, after).unwrap_or_default() {
                    self.declare_derive(index, tokens, at, scope, &derive, file);
                }
            }
            Some(_) => {}
            None if QUIET_ATTRIBUTES.contains(&placed.as_str()) => {}
            None => self.record(
                file,
                line,
                item,
                format!(
                    "an attribute this reading does not read, which can write a type or a Debug: \
                     {placed}"
                ),
            ),
        }
    }

    /// Reads one derive of the two crates, placed where it is written: the standard library's
    /// `Debug`, under whatever name, is the item's derived `Debug`; the standard library's other
    /// derives and those listed write no `Debug`.
    fn declare_derive(
        &mut self,
        index: usize,
        tokens: &[Located],
        at: usize,
        scope: usize,
        derive: &[Located],
        file: Option<&str>,
    ) {
        let line = tokens[at].line;
        let (segments, after) = spelled_path(derive);
        let item = format!("derive({})", spelled(derive));
        if segments.is_empty() || after != derive.len() {
            return self.record(
                file,
                line,
                item,
                "a derive this reading cannot read".to_owned(),
            );
        }
        let placed = match self.place(index, scope, &segments, Kind::Derive) {
            Ok(placed) => placed,
            Err(why) => {
                return self.record(
                    file,
                    line,
                    item,
                    format!("a derive this reading cannot place: {why}"),
                );
            }
        };
        match std_item(&placed) {
            Some("Debug") => {
                if let Some(keyword) = item_keyword_after(tokens, at)
                    && let Some(name) = ident(tokens.get(keyword + 1))
                {
                    let path = self.sources[index].defined_path(scope, name);
                    let definition = self.declared.get_mut(&path).and_then(|definitions| {
                        definitions.iter_mut().find(|declared| {
                            declared.source == index && declared.keyword == Some(keyword)
                        })
                    });
                    if let Some(declared) = definition
                        && declared.derived.is_none()
                    {
                        declared.derived = Some(line);
                    }
                }
            }
            Some(name) if PRELUDE_DERIVES.contains(&name) => {}
            None if QUIET_DERIVES.contains(&placed.as_str()) => {}
            _ => self.record(
                file,
                line,
                item,
                format!("a derive this reading does not read, which can write a Debug: {placed}"),
            ),
        }
    }

    /// Reads a use at `at` of one of the library's two macros that write a `Debug`, as the `Debug`
    /// it writes: the type's name alone, or with `fields`, the type's name and the fields named.
    fn declare_written(
        &mut self,
        index: usize,
        tokens: &[Located],
        at: usize,
        scope: usize,
        fields: bool,
    ) {
        let line = tokens[at].line;
        let parts = arguments(tokens, at + 2).unwrap_or_default();
        let written: Vec<(String, String)> = if fields {
            let Some(name) = ident(tokens.get(at + 3)).map(ToOwned::to_owned) else {
                return;
            };
            let fields = arguments(tokens, at + 4)
                .unwrap_or_default()
                .iter()
                .filter_map(|field| match field.first().map(|located| &located.token) {
                    Some(Token::Ident(word) | Token::Number(word)) => {
                        Some(format!(".field(\"{word}\", &self.{word})"))
                    }
                    _ => None,
                })
                .collect::<String>();
            vec![(name, fields)]
        } else {
            parts
                .iter()
                .filter_map(|part| ident(part.first()).map(|name| (name.to_owned(), String::new())))
                .collect()
        };
        for (name, fields) in written {
            let text = format!(
                "{{ fn fmt(&self, formatter: &mut Formatter<'_>) -> Result {{ \
                 formatter.debug_struct(\"{name}\"){fields}.finish_non_exhaustive() }} }}"
            );
            let Ok(mut body) = lex(&text) else {
                continue;
            };
            for located in &mut body {
                located.line = line;
            }
            let target = Written {
                source: index,
                scope,
                generics: Vec::new(),
                tokens: vec![Located {
                    token: Token::Ident(name.clone()),
                    line,
                }],
            };
            let path = self
                .resolve(&target, std::slice::from_ref(&name))
                .unwrap_or_else(|_| format!("?{name}"));
            self.by_hand.push(ByHand {
                target: path,
                written: target,
                line,
                tokens: body,
                origin: None,
            });
        }
    }

    /// The trait an `impl` names in `tokens`, a path with any generic arguments after it, placed
    /// where the `impl` is written.
    fn trait_named(&self, index: usize, scope: usize, tokens: &[Located]) -> Result<String, Why> {
        let (segments, after) = spelled_path(tokens);
        let end = if punct(tokens.get(after), '<') {
            angle_close(tokens, after).map_or(usize::MAX, |close| close + 1)
        } else {
            after
        };
        if segments.is_empty() || end != tokens.len() {
            return Err(format!(
                "{}, a trait this reading cannot read",
                spelled(tokens)
            ));
        }
        self.place(index, scope, &segments, Kind::Trait)
    }

    /// Whether the trait at `path` is the `Debug` trait: a path into the standard library whose
    /// item is `Debug`, or a path outside the workspace and the standard library whose name is
    /// `Debug`, since such a crate can give the trait a path of its own.
    fn is_debug_trait(&self, path: &str) -> bool {
        match std_item(path) {
            Some(name) => name == "Debug",
            None => self.outside(path) && path.rsplit("::").next() == Some("Debug"),
        }
    }

    /// Whether `path` leads outside the workspace and the standard library, where this reading
    /// knows an item only from a list.
    fn outside(&self, path: &str) -> bool {
        let root = path.split("::").next().unwrap_or_default();
        !self.crates.contains(root) && !matches!(root, "std" | "prim")
    }

    /// Reads the struct, enum or union whose keyword is at `at`.
    fn declare_type(
        &mut self,
        index: usize,
        tokens: &[Located],
        at: usize,
        scope: usize,
        invoked: Option<usize>,
    ) {
        let Some(name) = ident(tokens.get(at + 1)).map(ToOwned::to_owned) else {
            return;
        };
        let path = self.sources[index].defined_path(scope, &name);
        let (generics, mut cursor) = generic_parameters(tokens, at + 2);
        while cursor < tokens.len()
            && !punct(tokens.get(cursor), '{')
            && !punct(tokens.get(cursor), '(')
            && !punct(tokens.get(cursor), ';')
        {
            cursor += 1;
        }
        let line = invoked.map_or(tokens[at].line, |invoked| {
            self.sources[index].tokens[invoked].line
        });
        let start = before_item(tokens, at);
        let mut derived = None;
        for place in start..at {
            if ident(tokens.get(place)) == Some("derive") && punct(tokens.get(place + 1), '(') {
                let names = derive_names(tokens, place + 1);
                if names
                    .iter()
                    .any(|name| name == "Debug" || name.ends_with("::Debug"))
                {
                    derived = Some(invoked.map_or(tokens[place].line, |_| line));
                }
            }
        }
        let written = |field_tokens: Vec<Located>| Written {
            source: index,
            scope,
            generics: generics.clone(),
            tokens: field_tokens,
        };
        let mut shapes = Vec::new();
        let enumeration = ident(tokens.get(at)) == Some("enum");
        if !punct(tokens.get(cursor), ';') {
            if enumeration {
                let close = closing(tokens, cursor).unwrap_or(tokens.len());
                let mut variant = cursor + 1;
                while variant < close {
                    let mut conditional = false;
                    while punct(tokens.get(variant), '#') {
                        conditional |= cfg_is_conditional(tokens, variant + 1);
                        variant = attribute_end(tokens, variant).unwrap_or(close);
                    }
                    let Some(variant_name) = ident(tokens.get(variant)).map(ToOwned::to_owned)
                    else {
                        variant += 1;
                        continue;
                    };
                    variant += 1;
                    let mut members = Vec::new();
                    if punct(tokens.get(variant), '{') || punct(tokens.get(variant), '(') {
                        members = fields(tokens, variant)
                            .into_iter()
                            .map(|field| Member {
                                name: field.name,
                                written: written(field.type_tokens),
                                conditional: field.conditional,
                            })
                            .collect();
                        variant = closing(tokens, variant).map_or(close, |end| end + 1);
                    }
                    shapes.push(Shape {
                        name: variant_name,
                        members,
                        conditional,
                    });
                    while variant < close && !punct(tokens.get(variant), ',') {
                        variant += 1;
                    }
                    variant += 1;
                }
            } else {
                let members = fields(tokens, cursor)
                    .into_iter()
                    .map(|field| Member {
                        name: field.name,
                        written: written(field.type_tokens),
                        conditional: field.conditional,
                    })
                    .collect();
                shapes.push(Shape {
                    name: name.clone(),
                    members,
                    conditional: false,
                });
            }
        }
        self.declared.entry(path).or_default().push(Declared {
            source: index,
            keyword: invoked.is_none().then_some(at),
            name,
            derived,
            shapes,
        });
    }

    /// Reads the type alias whose keyword is at `at`.
    fn declare_alias(&mut self, index: usize, tokens: &[Located], at: usize, scope: usize) {
        let Some(name) = ident(tokens.get(at + 1)).map(ToOwned::to_owned) else {
            return;
        };
        let (generics, cursor) = generic_parameters(tokens, at + 2);
        if !punct(tokens.get(cursor), '=') {
            return;
        }
        // The `;` that ends the item, not one inside an array's type.
        let end = (cursor..tokens.len())
            .find(|&end| punct(tokens.get(end), ';') && depth_between(tokens, cursor, end) == 0)
            .unwrap_or(tokens.len());
        let path = self.sources[index].defined_path(scope, &name);
        self.type_aliases.entry(path).or_default().push(Written {
            source: index,
            scope,
            generics,
            tokens: tokens[cursor + 1..end].to_vec(),
        });
    }

    /// Reads the `impl Debug for` whose `impl` is at `at` and whose `for` is at `at_for`. `invoked`
    /// is where a macro that writes it is used, when one does.
    fn declare_by_hand(
        &mut self,
        index: usize,
        tokens: &[Located],
        at: usize,
        at_for: usize,
        scope: usize,
        invoked: Option<usize>,
    ) {
        let mut open = at_for + 1;
        while open < tokens.len()
            && !punct(tokens.get(open), '{')
            && ident(tokens.get(open)) != Some("where")
        {
            open += 1;
        }
        let target_tokens = tokens[at_for + 1..open].to_vec();
        while open < tokens.len() && !punct(tokens.get(open), '{') {
            open += 1;
        }
        let Some(close) = closing(tokens, open) else {
            return;
        };
        // The `impl`'s own generic parameters, which the target names.
        let (generics, _) = generic_parameters(tokens, at + 1);
        let written = Written {
            source: index,
            scope,
            generics,
            tokens: target_tokens,
        };
        let (segments, _) = spelled_path(&strip_references(&written.tokens));
        let target = self
            .resolve(&written, &segments)
            .unwrap_or_else(|_| format!("?{}", segments.join("::")));
        let line = invoked.map_or(tokens[at].line, |invoked| {
            self.sources[index].tokens[invoked].line
        });
        self.by_hand.push(ByHand {
            target,
            written,
            line,
            tokens: tokens[open..=close].to_vec(),
            origin: invoked.is_none().then_some(open),
        });
    }
}

/// The index of the `struct`, `enum` or `union` that the attributes around `at` belong to.
fn item_keyword_after(tokens: &[Located], at: usize) -> Option<usize> {
    (at..tokens.len())
        .find(|&index| {
            matches!(
                ident(tokens.get(index)),
                Some(
                    "struct"
                        | "enum"
                        | "union"
                        | "fn"
                        | "impl"
                        | "mod"
                        | "trait"
                        | "type"
                        | "use"
                        | "const"
                        | "static"
                )
            )
        })
        .filter(|&index| matches!(ident(tokens.get(index)), Some("struct" | "enum" | "union")))
}

/// Whether the scope `inner` of `source` is the scope `outer` or one inside it.
fn encloses(source: &Source, outer: usize, inner: usize) -> bool {
    let mut current = Some(inner);
    while let Some(scope) = current {
        if scope == outer {
            return true;
        }
        current = source.scopes[scope].parent;
    }
    false
}

/// Whether the token at `at` is inside the body of one of `macros`.
fn in_macro_body(macros: &[(String, usize, usize)], at: usize) -> bool {
    macros
        .iter()
        .any(|(_, open, close)| at > *open && at < *close)
}

/// The path written at the start of `tokens`, and the index after it. A path written from the
/// crates' root, `::name`, starts with an empty name.
fn spelled_path(tokens: &[Located]) -> (Vec<String>, usize) {
    let (mut segments, after) = written_path(tokens);
    if punct(tokens.first(), ':') && punct(tokens.get(1), ':') && !segments.is_empty() {
        segments.insert(0, String::new());
    }
    (segments, after)
}

/// The path whose last segment is the word at `at`, as [`spelled_path`] reads it:
/// `std::fmt::Debug` from its `Debug`.
fn path_ending_at(tokens: &[Located], at: usize) -> Vec<String> {
    let mut segments = Vec::new();
    let Some(last) = ident(tokens.get(at)) else {
        return segments;
    };
    segments.push(last.to_owned());
    let mut index = at;
    while index >= 3
        && punct(tokens.get(index - 1), ':')
        && punct(tokens.get(index - 2), ':')
        && let Some(word) = ident(tokens.get(index - 3))
    {
        segments.insert(0, word.to_owned());
        index -= 3;
    }
    if index >= 2 && punct(tokens.get(index - 1), ':') && punct(tokens.get(index - 2), ':') {
        segments.insert(0, String::new());
    }
    segments
}

/// `tokens` as they are written, for a finding.
fn spelled(tokens: &[Located]) -> String {
    let mut text = String::new();
    let mut word_before = false;
    for located in tokens {
        let (piece, word) = match &located.token {
            Token::Ident(word) | Token::Number(word) | Token::Lifetime(word) => {
                (word.clone(), true)
            }
            Token::Punct(c) => (c.to_string(), false),
            Token::Str(contents) => (format!("{contents:?}"), true),
            Token::Char => ("'?'".to_owned(), true),
        };
        if word && word_before {
            text.push(' ');
        }
        text.push_str(&piece);
        word_before = word;
    }
    text
}

/// Each `impl` of a trait in `tokens`: the index of its `impl`, where the trait's path starts, and
/// the index of its `for`. An `impl` in a type's place, `-> impl Trait`, is not an item.
fn trait_impls(tokens: &[Located]) -> Vec<(usize, usize, usize)> {
    let mut found = Vec::new();
    for at in 0..tokens.len() {
        if ident(tokens.get(at)) != Some("impl") {
            continue;
        }
        let item = at == 0
            || matches!(
                tokens.get(at - 1).map(|located| &located.token),
                Some(Token::Punct(';' | '}' | '{' | ']'))
            )
            || matches!(ident(tokens.get(at - 1)), Some("unsafe" | "default"));
        if !item {
            continue;
        }
        let start = if punct(tokens.get(at + 1), '<') {
            angle_close(tokens, at + 1).map_or(tokens.len(), |close| close + 1)
        } else {
            at + 1
        };
        // The `for` outside every bracket, before the body or a `where`.
        let mut depth = 0_i64;
        for cursor in start..tokens.len() {
            match &tokens[cursor].token {
                Token::Punct('<' | '(' | '[') => depth += 1,
                Token::Punct('>') if !punct(tokens.get(cursor.wrapping_sub(1)), '-') => depth -= 1,
                Token::Punct(')' | ']') => depth -= 1,
                Token::Punct('{' | ';') if depth == 0 => break,
                Token::Ident(word) if depth == 0 && word == "where" => break,
                Token::Ident(word) if depth == 0 && word == "for" => {
                    found.push((at, start, cursor));
                    break;
                }
                _ => {}
            }
        }
    }
    found
}

/// Whether this reading knows what the macro at `path` writes where it is used: the library's,
/// which it reads or which the files that define what may be shown decide, the standard library's
/// it names but `include!`, and those from outside the workspace it lists.
fn macro_read(path: &str) -> bool {
    match std_item(path) {
        Some(name) => {
            name != "include" && (STD_MACROS.contains(&name) || STD_MODULE_MACROS.contains(&name))
        }
        None => LIBRARY_MACROS.contains(&path) || QUIET_MACROS.contains(&path),
    }
}

/// Each `macro_rules!` in `tokens`: its name and its body's braces.
fn macro_bodies(tokens: &[Located]) -> Vec<(String, usize, usize)> {
    let mut found = Vec::new();
    for at in 0..tokens.len() {
        if ident(tokens.get(at)) == Some("macro_rules")
            && punct(tokens.get(at + 1), '!')
            && let Some(name) = ident(tokens.get(at + 2))
            && let Some(close) = closing(tokens, at + 3)
        {
            found.push((name.to_owned(), at + 3, close));
        }
    }
    found
}

/// The first word an invocation gives, past any attributes in front of it.
fn first_word(tokens: &[Located]) -> Option<String> {
    let mut at = 0;
    while at < tokens.len() {
        if punct(tokens.get(at), '#') {
            at = attribute_end(tokens, at)?;
            continue;
        }
        return ident(tokens.get(at)).map(ToOwned::to_owned);
    }
    None
}

/// A macro's body with the fragment each item names itself by replaced by `name`: the one after
/// `struct`, `enum`, `union` or `for`. Every other fragment is left as it is, and a type that holds
/// one is one this reading cannot place.
fn substitute(body: &[Located], name: Option<&str>) -> Vec<Located> {
    let mut named: BTreeSet<String> = BTreeSet::new();
    for at in 0..body.len() {
        if matches!(
            ident(body.get(at)),
            Some("struct" | "enum" | "union" | "for")
        ) && punct(body.get(at + 1), '$')
            && let Some(fragment) = ident(body.get(at + 2))
        {
            named.insert(fragment.to_owned());
        }
    }
    let mut out = Vec::with_capacity(body.len());
    let mut at = 0;
    while at < body.len() {
        if punct(body.get(at), '$')
            && let Some(fragment) = ident(body.get(at + 1))
            && named.contains(fragment)
            && let Some(name) = name
        {
            out.push(Located {
                token: Token::Ident(name.to_owned()),
                line: body[at].line,
            });
            at += 2;
            continue;
        }
        out.push(body[at].clone());
        at += 1;
    }
    out
}

/// The generic parameters of an item whose `<` would be at `at`, and the index past them.
fn generic_parameters(tokens: &[Located], at: usize) -> (Vec<String>, usize) {
    if !punct(tokens.get(at), '<') {
        return (Vec::new(), at);
    }
    let close = angle_close(tokens, at).unwrap_or(tokens.len() - 1);
    let names = split_commas(&tokens[at + 1..close])
        .iter()
        .filter_map(
            |parameter| match parameter.first().map(|located| &located.token) {
                Some(Token::Ident(word)) if word == "const" => {
                    ident(parameter.get(1)).map(ToOwned::to_owned)
                }
                Some(Token::Ident(word)) => Some(word.clone()),
                _ => None,
            },
        )
        .collect();
    (names, close + 1)
}

/// The `>` that closes the `<` at `open`, where an arrow's `>` closes nothing.
fn angle_close(tokens: &[Located], open: usize) -> Option<usize> {
    let mut depth = 0_i64;
    for at in open..tokens.len() {
        match tokens[at].token {
            Token::Punct('<') => depth += 1,
            Token::Punct('>') if !(at > 0 && punct(tokens.get(at - 1), '-')) => {
                depth -= 1;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
    }
    None
}

/// A type with any references, lifetimes and `mut` in front of it taken off.
fn strip_references(tokens: &[Located]) -> Vec<Located> {
    let mut at = 0;
    while punct(tokens.get(at), '&')
        || matches!(
            tokens.get(at).map(|located| &located.token),
            Some(Token::Lifetime(_))
        )
        || ident(tokens.get(at)) == Some("mut")
        || ident(tokens.get(at)) == Some("dyn")
    {
        at += 1;
    }
    tokens[at.min(tokens.len())..].to_vec()
}

/* -------------------------------------------------------------------------------------------- */
/* Where a name leads                                                                            */
/* -------------------------------------------------------------------------------------------- */

/// What a path is read as, which decides where a single name that no scope gives leads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    /// A type: a primitive, or one of the prelude's.
    Type,
    /// A trait: one of the prelude's.
    Trait,
    /// A macro: one its crate writes, or one of the standard library's.
    Macro,
    /// An attribute: one the compiler reads itself, or a derive's helper.
    Attribute,
    /// A derive: one of the prelude's.
    Derive,
    /// The path of an import: a crate.
    Import,
}

/// Where an item a name leads to may be seen from.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Reach {
    Everywhere,
    /// The module this full path names, and each module inside it.
    Within(String),
    Nowhere,
    /// Somewhere this reading does not follow.
    Unsure,
}

impl Reach {
    /// What both `self` and `other` reach.
    fn and(&self, other: &Reach) -> Reach {
        match (self, other) {
            (Reach::Nowhere, _) | (_, Reach::Nowhere) => Reach::Nowhere,
            (Reach::Everywhere, reach) | (reach, Reach::Everywhere) => reach.clone(),
            (Reach::Unsure, _) | (_, Reach::Unsure) => Reach::Unsure,
            (Reach::Within(first), Reach::Within(second)) => {
                if within(first, second) {
                    Reach::Within(first.clone())
                } else if within(second, first) {
                    Reach::Within(second.clone())
                } else {
                    Reach::Nowhere
                }
            }
        }
    }

    /// Whether code in the module `module` sees the item, or `None` when this reading cannot tell.
    fn seen_from(&self, module: &str) -> Option<bool> {
        match self {
            Reach::Everywhere => Some(true),
            Reach::Within(of) => Some(within(module, of)),
            Reach::Nowhere => Some(false),
            Reach::Unsure => None,
        }
    }
}

/// Whether the module `module` is the module `of` or one inside it.
fn within(module: &str, of: &str) -> bool {
    module == of
        || module
            .strip_prefix(of)
            .is_some_and(|rest| rest.starts_with("::"))
}

/// Where an item declared with `visibility` in the module `module` may be seen from.
fn reach(visibility: Visibility, module: &str) -> Reach {
    match visibility {
        Visibility::Public => Reach::Everywhere,
        Visibility::Crate => {
            Reach::Within(module.split("::").next().unwrap_or_default().to_owned())
        }
        Visibility::Super => module
            .rsplit_once("::")
            .map_or(Reach::Unsure, |(parent, _)| {
                Reach::Within(parent.to_owned())
            }),
        Visibility::Private => Reach::Within(module.to_owned()),
        Visibility::Other => Reach::Unsure,
    }
}

/// An item a name leads to, by full path, and where it may be seen from.
struct Named {
    path: String,
    reach: Reach,
    /// Whether it is there under every set of conditions: a `cfg` this reading cannot decide can
    /// leave an item out, and then the name leads further.
    present: bool,
}

/// The one item `given` leads to, or why `name`, which leads to none or to more than one, cannot
/// be placed.
fn one_of(given: &[Named], name: &str) -> Result<String, Why> {
    let paths: BTreeSet<&String> = given.iter().map(|named| &named.path).collect();
    match (paths.first(), paths.len()) {
        (Some(path), 1) => Ok((*path).clone()),
        (None, _) => Err(format!("`{name}`, which this reading cannot find")),
        _ => Err(format!("`{name}`, which names more than one item")),
    }
}

/// The name of the item a full path into the standard library names, which is that item's
/// identity: the standard library gives an item it re-exports its own name wherever it does, so
/// `std::prelude::v1::Debug` is `Debug`. `None` for a path outside the standard library.
fn std_item(path: &str) -> Option<&str> {
    path.strip_prefix("std::")
        .map(|rest| rest.rsplit("::").next().unwrap_or(rest))
}

/// A full path with the standard library spelled `std::`, as `core::` and `alloc::` are re-exported
/// there.
fn std_spelled(path: &str) -> String {
    ["core::", "alloc::"]
        .iter()
        .find_map(|from| path.strip_prefix(from))
        .map_or_else(|| path.to_owned(), |rest| format!("std::{rest}"))
}

/// The namespace a name is looked up in: the compiler keeps types, traits and modules apart from
/// macros, so a name can be one of each at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Space {
    /// Types, traits, modules and crates: every name of a path but its last, and the last of a
    /// type's or a trait's.
    Types,
    /// Macros, attributes and derives.
    Macros,
    /// Either: the last name of an import, which brings whatever it names.
    Any,
}

impl Kind {
    /// The namespace the last name of a path read as this is looked up in.
    fn space(self) -> Space {
        match self {
            Kind::Type | Kind::Trait => Space::Types,
            Kind::Macro | Kind::Attribute | Kind::Derive => Space::Macros,
            Kind::Import => Space::Any,
        }
    }
}

impl Debugs {
    /// The full path of the item the path `segments`, written at `scope` of source `index`, names,
    /// placed as the compiler places it, or why this reading cannot place it. A path written from
    /// the crates' root starts with an empty name.
    ///
    /// The first name is the innermost scope's that gives it: by an item or an import of its own,
    /// or else through its globs, then the scopes around it, then a crate or the prelude. Each
    /// name after it is the one the module reached gives, by an item or an import of its own, or
    /// else through its globs. Every name but the last is looked up among types, traits and
    /// modules, and the last in the namespace `kind` names. An import's path is read where the
    /// import is written. A glob gives what its module sees: another crate's item only when it and
    /// each glob on the way are public. Where a glob may or may not give a name, every way the
    /// compiler could place it has to agree; a name given twice, a module this reading cannot
    /// find, and a glob of a module outside the workspace whose names it cannot list leave the path
    /// unplaced.
    fn place(
        &self,
        index: usize,
        scope: usize,
        segments: &[String],
        kind: Kind,
    ) -> Result<String, Why> {
        let key = (index, scope, segments.to_vec(), kind);
        if let Some(placed) = self.placed.borrow().get(&key) {
            return placed.clone();
        }
        let placed = self.place_from(index, scope, segments, kind, &mut Vec::new());
        self.placed.borrow_mut().insert(key, placed.clone());
        placed
    }

    /// [`Debugs::place`], with the imports, globs and modules being followed in `visiting`.
    fn place_from(
        &self,
        index: usize,
        scope: usize,
        segments: &[String],
        kind: Kind,
        visiting: &mut Vec<String>,
    ) -> Result<String, Why> {
        let source = &self.sources[index];
        let spelled = segments.join("::");
        let Some((first, rest)) = segments.split_first() else {
            return Err("a path this reading cannot read".to_owned());
        };
        let (start, rest) = match first.as_str() {
            // `::name`: a crate.
            "" => match rest.split_first() {
                Some((krate, rest)) => (krate.clone(), rest),
                None => return Err(format!("{spelled}, a path this reading cannot read")),
            },
            "crate" => (source.crate_name.clone(), rest),
            "self" => (source.module_of(scope).join("::"), rest),
            "super" => {
                let supers = segments
                    .iter()
                    .take_while(|segment| *segment == "super")
                    .count();
                let module = source.module_of(scope);
                let Some(keep) = module.len().checked_sub(supers).filter(|keep| *keep > 0) else {
                    return Err(format!("{spelled}, which goes past its crate"));
                };
                (module[..keep].join("::"), &segments[supers..])
            }
            "Self" => return Err(format!("{spelled}, which names Self")),
            _ => {
                let scopes = source.visible(scope);
                match self.first_name(index, &scopes, first, rest.is_empty(), kind, visiting)? {
                    Some(start) => (start, rest),
                    None => {
                        return Err(format!("{spelled}, which no scope, crate or prelude gives"));
                    }
                }
            }
        };
        self.walk(start, rest, kind.space(), visiting)
    }

    /// The item the names `rest` lead to, one after another, from the module or item `start`: every
    /// name but the last among types, traits and modules, and the last in `space`.
    fn walk(
        &self,
        start: String,
        rest: &[String],
        space: Space,
        visiting: &mut Vec<String>,
    ) -> Result<String, Why> {
        let mut path = start;
        for (position, name) in rest.iter().enumerate() {
            let space = if position + 1 == rest.len() {
                space
            } else {
                Space::Types
            };
            path = self.one(&path, name, space, visiting)?;
        }
        Ok(std_spelled(&path))
    }

    /// What the first name of a path leads to where it is written: the first of `scopes`, the
    /// innermost first, that gives the name in the namespace it is looked up in, by its own items
    /// and imports before any glob; past them, a crate or the prelude.
    fn first_name(
        &self,
        index: usize,
        scopes: &[usize],
        name: &str,
        single: bool,
        kind: Kind,
        visiting: &mut Vec<String>,
    ) -> Result<Option<String>, Why> {
        let Some((&scope, outer)) = scopes.split_first() else {
            return self.beyond(index, name, single, kind);
        };
        let space = if single { kind.space() } else { Space::Types };
        let given = self.explicit(index, scope, name, space, visiting)?;
        if given.iter().any(|named| named.present) {
            return one_of(&given, name).map(Some);
        }
        // An item or an import a `cfg` can leave out is one candidate; past it, the name is placed
        // as if it were left out, and every candidate has to agree.
        let mut candidates: Vec<(String, bool)> =
            given.into_iter().map(|named| (named.path, false)).collect();
        let source = &self.sources[index];
        let module = source.module_of(scope).join("::");
        for (position, glob) in source.globs.iter().enumerate() {
            if glob.scope != scope {
                continue;
            }
            for named in self.through_glob(index, position, name, space, visiting)? {
                match named.reach.seen_from(&module) {
                    Some(true) if !glob.conditional => candidates.push((named.path, true)),
                    Some(false) => {}
                    _ => candidates.push((named.path, false)),
                }
            }
        }
        let paths: BTreeSet<&String> = candidates.iter().map(|(path, _)| path).collect();
        let Some(path) = paths.first().map(|path| (*path).clone()) else {
            return self.first_name(index, outer, name, single, kind, visiting);
        };
        if paths.len() > 1 {
            return Err(format!("`{name}`, which more than one glob can give"));
        }
        if candidates.iter().any(|(_, sure)| *sure) {
            return Ok(Some(path));
        }
        // The glob may not give it, and then the scopes around place it: the two have to agree.
        match self.first_name(index, outer, name, single, kind, visiting)? {
            Some(further) if further != path => {
                Err(format!("`{name}`, which a glob may or may not give"))
            }
            _ => Ok(Some(path)),
        }
    }

    /// What a first name that no scope gives leads to: a crate, when a path goes on past it or an
    /// import names it alone; else a primitive or a type of the prelude, a trait of the prelude,
    /// a macro its crate writes or the standard library gives every file, an attribute the
    /// compiler reads or a derive's helper, or a derive of the prelude.
    fn beyond(
        &self,
        index: usize,
        name: &str,
        single: bool,
        kind: Kind,
    ) -> Result<Option<String>, Why> {
        if !single || kind == Kind::Import {
            return Ok(Some(name.to_owned()));
        }
        let krate = &self.sources[index].crate_name;
        let own = format!("{krate}::{name}");
        Ok(match kind {
            Kind::Type => PRIMITIVES
                .contains(&name)
                .then(|| format!("prim::{name}"))
                .or_else(|| {
                    PRELUDE
                        .iter()
                        .find(|(short, _)| *short == name)
                        .map(|(_, path)| (*path).to_owned())
                }),
            Kind::Trait => PRELUDE_TRAITS
                .contains(&name)
                .then(|| format!("std::prelude::{name}")),
            Kind::Macro if self.macros.contains_key(&own) => Some(own),
            Kind::Macro if self.macro_use.contains(krate) => {
                return Err(format!(
                    "`{name}`, which a crate's macros taken with macro_use can give"
                ));
            }
            Kind::Macro | Kind::Import => {
                STD_MACROS.contains(&name).then(|| format!("std::{name}"))
            }
            Kind::Attribute => INERT_ATTRIBUTES
                .contains(&name)
                .then(|| format!("{INERT}::{name}")),
            Kind::Derive => PRELUDE_DERIVES
                .contains(&name)
                .then(|| format!("std::prelude::{name}")),
        })
    }

    /// The namespaces the item at the full path `path` is in: types, traits and modules, macros,
    /// or, for an item this reading does not read, either.
    fn namespaces(&self, path: &str) -> (bool, bool) {
        let types = self.declared.contains_key(path)
            || self.type_aliases.contains_key(path)
            || self.modules.contains_key(path)
            || self.traits.contains(path);
        let macros = self.macros.contains_key(path);
        if types || macros {
            (types, macros)
        } else {
            (true, true)
        }
    }

    /// What `scope` of source `index` gives under `name` in `space` by its own items and imports,
    /// each with where it may be seen from.
    fn explicit(
        &self,
        index: usize,
        scope: usize,
        name: &str,
        space: Space,
        visiting: &mut Vec<String>,
    ) -> Result<Vec<Named>, Why> {
        let wants_types = space != Space::Macros;
        let wants_macros = space != Space::Types;
        let source = &self.sources[index];
        let module = source.module_of(scope).join("::");
        let mut given = Vec::new();
        for (position, import) in source.imports.iter().enumerate() {
            if import.scope != scope || import.local != name {
                continue;
            }
            // An import's own path is read without it: `use log::log;` names the crate.
            let key = format!("import {index} {position}");
            if visiting.contains(&key) {
                continue;
            }
            visiting.push(key);
            let target = self.target(index, scope, &import.written, import.global, visiting);
            visiting.pop();
            let path = target?;
            // An import brings its item in the item's own namespaces.
            let (types, macros) = self.namespaces(&path);
            if !(types && wants_types || macros && wants_macros) {
                continue;
            }
            given.push(Named {
                path,
                reach: if import.conditional {
                    Reach::Unsure
                } else {
                    reach(import.visibility, &module)
                },
                present: !import.conditional,
            });
        }
        let key = (scope, name.to_owned());
        let visibility = source
            .visibilities
            .get(&key)
            .copied()
            .unwrap_or(Visibility::Private);
        let defined = source.defined_path(scope, name);
        let always = source.always.contains(&key);
        let item_reach = if always {
            reach(visibility, &module)
        } else {
            Reach::Unsure
        };
        if wants_types && source.definitions.contains(&key) {
            given.push(Named {
                path: defined,
                reach: item_reach.clone(),
                present: always,
            });
        } else if wants_types
            && (self.declared.contains_key(&defined) || self.type_aliases.contains_key(&defined))
        {
            // A type a macro declares here, whose visibility and conditions this reading does not
            // read.
            given.push(Named {
                path: defined,
                reach: Reach::Unsure,
                present: false,
            });
        }
        let declares_module = (scope == 0
            && source
                .children
                .iter()
                .any(|(child, test)| child == name && !test))
            || source.scopes.iter().any(|other| {
                other.parent == Some(scope)
                    && !other.block
                    && other.module.last().is_some_and(|last| last == name)
            });
        if wants_types && declares_module {
            let path = format!("{module}::{name}");
            // A module file whose own `cfg` this reading cannot decide can be left out as well.
            let file_conditional = self.modules.get(&path).is_some_and(|scopes| {
                scopes.iter().any(|&(child, child_scope)| {
                    child_scope == 0 && self.sources[child].conditional
                })
            });
            let present = always && !file_conditional;
            given.push(Named {
                path,
                reach: if present { item_reach } else { Reach::Unsure },
                present,
            });
        }
        let exported = format!("{module}::{name}");
        if wants_macros
            && scope == 0
            && source.module.len() == 1
            && self.macros.get(&exported) == Some(&true)
        {
            let present = self.always_macros.contains(&exported);
            given.push(Named {
                path: exported,
                reach: if present {
                    Reach::Everywhere
                } else {
                    Reach::Unsure
                },
                present,
            });
        }
        Ok(given)
    }

    /// What the glob at `position` of source `index` gives under `name` in `space`, before the
    /// scope the glob is written in decides what it sees.
    fn through_glob(
        &self,
        index: usize,
        position: usize,
        name: &str,
        space: Space,
        visiting: &mut Vec<String>,
    ) -> Result<Vec<Named>, Why> {
        // A glob's own path is read without it.
        let key = format!("glob {index} {position}");
        if visiting.contains(&key) {
            return Ok(Vec::new());
        }
        visiting.push(key);
        let glob = &self.sources[index].globs[position];
        let given = self
            .target(index, glob.scope, &glob.written, glob.global, visiting)
            .and_then(|module| self.member(&module, name, space, visiting));
        visiting.pop();
        given
    }

    /// What the module at the full path `module` gives under `name` in `space`: its own items and
    /// imports, or else what its globs give it, each with where it may be seen from. A module
    /// outside the workspace gives the item its path names, which this reading cannot say is there
    /// unless it is one this reading acts on.
    fn member(
        &self,
        module: &str,
        name: &str,
        space: Space,
        visiting: &mut Vec<String>,
    ) -> Result<Vec<Named>, Why> {
        let full = std_spelled(&format!("{module}::{name}"));
        if name.starts_with("{block") || module.contains("{block") {
            // A path this reading wrote for a type a block declares.
            return Ok(vec![Named {
                path: full,
                reach: Reach::Unsure,
                present: true,
            }]);
        }
        let Some(scopes) = self.modules.get(module) else {
            let root = module.split("::").next().unwrap_or_default();
            if !self.crates.contains(root) {
                let reach = if full == DEBUG_TRAIT || LIBRARY_MACROS.contains(&full.as_str()) {
                    Reach::Everywhere
                } else {
                    Reach::Unsure
                };
                return Ok(vec![Named {
                    path: full,
                    reach,
                    present: true,
                }]);
            }
            // A type of the workspace, whose variants an import can name: they are types, not
            // macros.
            return match self.declared.get(module) {
                Some(_) if space == Space::Macros => Ok(Vec::new()),
                Some(definitions) => {
                    let variant = |declared: &Declared, always: bool| {
                        declared.shapes.iter().any(|shape| {
                            shape.name == name
                                && shape.name != declared.name
                                && !(always && shape.conditional)
                        })
                    };
                    // A variant a `cfg` can leave out, or one another definition of the enum
                    // lacks, is there under some conditions only.
                    let present = definitions.iter().all(|declared| variant(declared, true));
                    Ok(definitions
                        .iter()
                        .any(|declared| variant(declared, false))
                        .then(|| Named {
                            path: full.clone(),
                            reach: if present {
                                Reach::Everywhere
                            } else {
                                Reach::Unsure
                            },
                            present,
                        })
                        .into_iter()
                        .collect())
                }
                None => Err(format!("{module}, a module this reading cannot find")),
            };
        };
        let key = format!("member {full} {space:?}");
        if visiting.contains(&key) {
            // A cycle of globs gives nothing more.
            return Ok(Vec::new());
        }
        visiting.push(key);
        // A module declared once for each set of `cfg` conditions gives what any of them gives;
        // where the declarations give the name differently, or one does not give it, what it
        // leads to is there only under some conditions.
        let mut each = Vec::new();
        for &(index, scope) in scopes {
            match self.module_member(index, scope, module, name, space, visiting) {
                Ok(named) => each.push(named),
                Err(why) => {
                    visiting.pop();
                    return Err(why);
                }
            }
        }
        visiting.pop();
        let signature = |named: &[Named]| {
            let mut signature: Vec<String> = named
                .iter()
                .map(|named| format!("{} {:?} {}", named.path, named.reach, named.present))
                .collect();
            signature.sort();
            signature
        };
        let alike = each
            .windows(2)
            .all(|pair| signature(&pair[0]) == signature(&pair[1]));
        // A crate whose root a `cfg` can empty is there with nothing in it, so what its root gives
        // is there only under some conditions.
        let certain = alike && !(!module.contains("::") && self.emptied(module));
        Ok(each
            .into_iter()
            .flatten()
            .map(|named| {
                if certain {
                    named
                } else {
                    Named {
                        reach: Reach::Unsure,
                        present: false,
                        ..named
                    }
                }
            })
            .collect())
    }

    /// [`Debugs::member`] for one declaration of a module of the workspace, whose names `scope` of
    /// source `index` gives.
    fn module_member(
        &self,
        index: usize,
        scope: usize,
        module: &str,
        name: &str,
        space: Space,
        visiting: &mut Vec<String>,
    ) -> Result<Vec<Named>, Why> {
        let given = self.explicit(index, scope, name, space, visiting)?;
        if given.iter().any(|named| named.present) {
            return Ok(given);
        }
        // An item or an import a `cfg` can leave out gives the name under some conditions only;
        // past it, the module's globs can give it.
        let mut found = given;
        for (position, glob) in self.sources[index].globs.iter().enumerate() {
            if glob.scope != scope {
                continue;
            }
            let passed_on = if glob.conditional {
                Reach::Unsure
            } else {
                reach(glob.visibility, module)
            };
            for named in self.through_glob(index, position, name, space, visiting)? {
                // A glob takes what its module sees, and gives it on no further than itself.
                if named.reach.seen_from(module) != Some(false) {
                    found.push(Named {
                        reach: named.reach.and(&passed_on),
                        present: named.present && !glob.conditional,
                        path: named.path,
                    });
                }
            }
        }
        Ok(found)
    }

    /// The one item the module `module` gives under `name` in `space`, where a path names it there.
    fn one(
        &self,
        module: &str,
        name: &str,
        space: Space,
        visiting: &mut Vec<String>,
    ) -> Result<String, Why> {
        let given = self.member(module, name, space, visiting)?;
        one_of(&given, &format!("{module}::{name}"))
    }

    /// The item an import's or a glob's path, exactly as written, leads to: from the crate it
    /// names when it is written from the crates' root, and otherwise read where it is written.
    fn target(
        &self,
        index: usize,
        scope: usize,
        path: &[String],
        global: bool,
        visiting: &mut Vec<String>,
    ) -> Result<String, Why> {
        if global {
            let Some((krate, rest)) = path.split_first() else {
                return Err("an import this reading cannot read".to_owned());
            };
            return self.walk(krate.clone(), rest, Space::Any, visiting);
        }
        self.place_from(index, scope, path, Kind::Import, visiting)
    }

    /// Where the full path `path` of a type leads through every re-export, or `path` itself when
    /// this reading cannot follow it.
    fn canonical(&self, path: &str) -> String {
        let segments: Vec<String> = path.split("::").map(ToOwned::to_owned).collect();
        let Some((first, rest)) = segments.split_first() else {
            return path.to_owned();
        };
        self.walk(first.clone(), rest, Space::Types, &mut Vec::new())
            .unwrap_or_else(|_| path.to_owned())
    }

    /// Whether the module at the full path `module` is there with what it declares under every set
    /// of conditions: a crate's root that no `cfg` at its top can empty, or a module one
    /// declaration of which no `cfg` this reading cannot decide can leave out, in a module that is
    /// there too.
    fn present_module(&self, module: &str) -> bool {
        let Some((parent, name)) = module.rsplit_once("::") else {
            return !self.emptied(module);
        };
        let Some(scopes) = self.modules.get(module) else {
            return false;
        };
        let declared_in = |index: usize, scope: usize| {
            self.sources[index]
                .always
                .contains(&(scope, name.to_owned()))
        };
        self.present_module(parent)
            && scopes.iter().any(|&(index, scope)| {
                match self.sources[index].scopes[scope].parent {
                    // An inline module, declared in the scope around it.
                    Some(around) => declared_in(index, around),
                    // A module file, not left out by its own `#![cfg(…)]`, declared in its parent.
                    None => {
                        !self.sources[index].conditional
                            && self.modules.get(parent).is_some_and(|declaring| {
                                declaring
                                    .iter()
                                    .any(|&(at, at_scope)| declared_in(at, at_scope))
                            })
                    }
                }
            })
    }

    /// Whether a `#![cfg(…)]` at the top of the root of the workspace's crate `krate` that this
    /// reading cannot decide can leave out everything the crate declares: the crate is then there
    /// with nothing in it, and a glob of it gives nothing.
    fn emptied(&self, krate: &str) -> bool {
        self.modules.get(krate).is_some_and(|scopes| {
            scopes
                .iter()
                .any(|&(index, scope)| scope == 0 && self.sources[index].conditional)
        })
    }

    /// The exported macros that are at their crate's root under every set of conditions: each
    /// exported by a `#[macro_export]` of its own, not one `cfg_attr` gives, and written where no
    /// `cfg` this reading cannot decide can leave it out, through every module around it.
    fn exported_always(&self) -> BTreeSet<String> {
        let mut always = BTreeSet::new();
        for source in &self.sources {
            let tokens = &source.tokens;
            for (name, open, _) in macro_bodies(tokens) {
                // `macro_rules`, `!` and the name come before the body.
                let at = open - 3;
                let exported = (before_item(tokens, at)..at).any(|index| {
                    punct(tokens.get(index), '#')
                        && punct(tokens.get(index + 1), '[')
                        && ident(tokens.get(index + 2)) == Some("macro_export")
                });
                if !exported || item_conditional(tokens, at) {
                    continue;
                }
                let mut scope = source.scope_at(at);
                let mut present = true;
                while let Some(around) = source.scopes[scope].parent {
                    let entry = &source.scopes[scope];
                    // A macro written in a block is there only when the item around it is.
                    let declared = !entry.block
                        && entry.module.last().is_some_and(|module| {
                            source.always.contains(&(around, module.clone()))
                        });
                    if !declared {
                        present = false;
                        break;
                    }
                    scope = around;
                }
                if present && self.present_module(&source.module.join("::")) {
                    always.insert(format!("{}::{name}", source.crate_name));
                }
            }
        }
        always
    }
}

/* -------------------------------------------------------------------------------------------- */
/* Which types carry text                                                                        */
/* -------------------------------------------------------------------------------------------- */

/// The types found to carry text so far, each with why.
type Carrying = BTreeMap<String, Why>;

impl Debugs {
    /// Whether the rule decides what `path`'s `Debug` prints without reading it: a claim, a type
    /// the files that define what may be shown write, or a `Debug` that the library's
    /// `debug_as_display!` makes its `Display`, which is how each of the two crates' failures has
    /// its `Debug`.
    fn decided(&self, path: &str) -> bool {
        self.plain.contains(path)
            || path == SHOWN
            || path == IO_FAULT
            || self.shown_types.contains(path)
            || self.as_display.contains(path)
    }

    /// Why the type written in `written` carries text, or `None` when its `Debug` prints none.
    fn carries(&self, written: &Written, carrying: &Carrying) -> Option<Why> {
        self.carries_in(written, &written.tokens, carrying)
    }

    fn carries_in(
        &self,
        written: &Written,
        tokens: &[Located],
        carrying: &Carrying,
    ) -> Option<Why> {
        let Some(first) = tokens.first() else {
            return Some("a type this reading cannot read".to_owned());
        };
        match &first.token {
            Token::Punct('&') => {
                let mut at = 1;
                let lifetime = match tokens.get(at).map(|located| &located.token) {
                    Some(Token::Lifetime(lifetime)) => {
                        at += 1;
                        lifetime.clone()
                    }
                    _ => String::new(),
                };
                if ident(tokens.get(at)) == Some("mut") {
                    at += 1;
                }
                let rest = &tokens[at..];
                let (text, after) = spelled_path(rest);
                if lifetime == "'static"
                    && after == rest.len()
                    && self.resolve(written, &text).ok().as_deref() == Some("prim::str")
                {
                    return None;
                }
                self.carries_in(written, rest, carrying)
            }
            Token::Punct('*') => self.carries_in(written, tokens.get(2..).unwrap_or(&[]), carrying),
            Token::Punct('[') => {
                let close = closing(tokens, 0).unwrap_or(tokens.len());
                let inner = &tokens[1..close.min(tokens.len())];
                let element_end = inner
                    .iter()
                    .position(|located| located.token == Token::Punct(';'))
                    .unwrap_or(inner.len());
                let element = &inner[..element_end];
                if self.is_byte(written, element) {
                    return Some("bytes".to_owned());
                }
                self.carries_in(written, element, carrying)
            }
            Token::Punct('(') => {
                let close = closing(tokens, 0).unwrap_or(tokens.len());
                split_commas(&tokens[1..close.min(tokens.len())])
                    .iter()
                    .find_map(|part| self.carries_in(written, part, carrying))
            }
            Token::Punct('!') => None,
            Token::Ident(word) if word == "_" => None,
            Token::Ident(word) if word == "fn" || word == "unsafe" || word == "extern" => None,
            Token::Ident(word) if word == "dyn" || word == "impl" => {
                Some("a trait object, which prints whatever implements it".to_owned())
            }
            Token::Ident(_) | Token::Punct(':') => self.path_carries(written, tokens, carrying),
            _ => Some("a type this reading cannot read".to_owned()),
        }
    }

    /// Why a type written as a path carries text.
    fn path_carries(
        &self,
        written: &Written,
        tokens: &[Located],
        carrying: &Carrying,
    ) -> Option<Why> {
        let (segments, after) = spelled_path(tokens);
        if segments.is_empty() {
            return Some("a type this reading cannot read".to_owned());
        }
        // Every argument but a lifetime, in its place, for an alias's parameters; and those that
        // are types, for what a container holds.
        let positional: Vec<Vec<Located>> = if punct(tokens.get(after), '<') {
            let close = angle_close(tokens, after).unwrap_or(tokens.len());
            split_commas(&tokens[after + 1..close.min(tokens.len())])
                .into_iter()
                .filter(|argument| {
                    !matches!(
                        argument.first().map(|located| &located.token),
                        Some(Token::Lifetime(_))
                    )
                })
                .collect()
        } else {
            Vec::new()
        };
        let arguments: Vec<Vec<Located>> = if punct(tokens.get(after), '<') {
            positional
                .iter()
                .filter(|argument| {
                    !matches!(
                        argument.first().map(|located| &located.token),
                        Some(Token::Number(_) | Token::Punct('{'))
                    )
                })
                .cloned()
                .collect()
        } else {
            if after < tokens.len() {
                return Some(format!(
                    "a type this reading cannot read: {}",
                    segments.join("::")
                ));
            }
            Vec::new()
        };
        let arguments_carry = || {
            arguments
                .iter()
                .find_map(|argument| self.carries_in(written, argument, carrying))
        };
        if segments.len() == 1 && segments[0] == "Self" {
            return arguments_carry();
        }
        if segments.len() == 1 && segments[0] == PARAMETER {
            // A parameter of the type an alias was used in: where that type is used, its
            // argument is read there.
            return None;
        }
        if written.generics.contains(&segments[0]) {
            // A parameter: where the type is used, its argument is read there.
            return if segments.len() == 1 {
                None
            } else {
                Some(format!(
                    "an associated type this reading cannot follow: {}",
                    segments.join("::")
                ))
            };
        }
        let path = match self.resolve(written, &segments) {
            Ok(path) => path,
            Err(why) => return Some(format!("a type this reading cannot place: {why}")),
        };
        if let Some(primitive) = path.strip_prefix("prim::") {
            return if NUMBERS.contains(&primitive) {
                None
            } else {
                Some(primitive.to_owned())
            };
        }
        if self.decided(&path) {
            return None;
        }
        // A path defined once for each set of `cfg` conditions, as aliases, types or both, carries
        // when any definition does.
        if let Some(aliases) = self.type_aliases.get(&path) {
            for alias in aliases {
                let Some(expanded) = self.expand_alias(alias, written, &positional) else {
                    return Some(format!("{path}, an alias this reading cannot expand"));
                };
                let why = self.carries(&expanded, carrying);
                self.expanding.set(self.expanding.get().saturating_sub(1));
                if why.is_some() {
                    return why;
                }
            }
            if !self.declared.contains_key(&path) {
                return None;
            }
        }
        if let Some(definitions) = self.declared.get(&path) {
            if let Some(why) = carrying.get(&path) {
                return Some(format!("{path}, which carries {why}"));
            }
            if positional.is_empty() {
                return arguments_carry();
            }
            for declared in definitions {
                if declared.derived.is_none() {
                    if let Some(why) = arguments_carry() {
                        return Some(why);
                    }
                    continue;
                }
                // A generic type with a derived `Debug` is read with its arguments in place of its
                // parameters, since an argument that is safe alone can be bytes in a sequence.
                for member in declared.shapes.iter().flat_map(|shape| &shape.members) {
                    let Some(expanded) = self.expand_alias(&member.written, written, &positional)
                    else {
                        return Some(format!("{path}, a generic type this reading cannot expand"));
                    };
                    let why = self.carries(&expanded, carrying);
                    self.expanding.set(self.expanding.get().saturating_sub(1));
                    if let Some(why) = why {
                        return Some(format!("{path}, which with its arguments carries {why}"));
                    }
                }
            }
            return None;
        }
        let root = path.split("::").next().unwrap_or_default();
        if self.crates.contains(root) {
            return Some(format!("{path}, a type this reading cannot place"));
        }
        match OUTSIDE.iter().find(|(listed, _)| *listed == path) {
            Some((_, Outside::Text)) => Some(path),
            Some((_, Outside::Nothing)) => None,
            // A sequence of bytes holds bytes, whatever its own `Debug` does with them. One byte in
            // an option, a cell or a lock is a number.
            Some((_, Outside::Holds))
                if SEQUENCES.contains(&path.as_str())
                    && arguments
                        .iter()
                        .any(|argument| self.is_byte(written, argument)) =>
            {
                Some("bytes".to_owned())
            }
            Some((_, Outside::Holds)) => arguments_carry(),
            None => Some(format!(
                "{path}, a type from outside the workspace this reading does not list"
            )),
        }
    }

    /// A type alias as its use at `use_site` spells it: its parameters replaced by the arguments
    /// given there, each written as the full path it names at the use site, so the whole reads the
    /// same in the alias's own scope.
    ///
    /// `None` when an argument names a type this reading cannot place where it is written, when
    /// the arguments do not fill the parameters, or past a depth no alias chain reaches: each is
    /// a type this reading cannot follow, and so a carrier. While the expansion is read, the depth
    /// it adds is held; the caller gives it back.
    fn expand_alias(
        &self,
        alias: &Written,
        use_site: &Written,
        arguments: &[Vec<Located>],
    ) -> Option<Written> {
        if self.expanding.get() >= 32 || arguments.len() != alias.generics.len() {
            return None;
        }
        let qualified: Vec<Vec<Located>> = arguments
            .iter()
            .map(|argument| self.qualified(use_site, argument))
            .collect::<Option<_>>()?;
        self.expanding.set(self.expanding.get() + 1);
        let mut tokens = Vec::with_capacity(alias.tokens.len());
        for (at, located) in alias.tokens.iter().enumerate() {
            let standalone = !(at > 0 && punct(alias.tokens.get(at - 1), ':'))
                && !punct(alias.tokens.get(at + 1), ':');
            match &located.token {
                Token::Ident(word) if standalone => {
                    match alias
                        .generics
                        .iter()
                        .position(|parameter| parameter == word)
                    {
                        Some(position) if position < qualified.len() => {
                            tokens.extend(qualified[position].iter().cloned());
                        }
                        _ => tokens.push(located.clone()),
                    }
                }
                _ => tokens.push(located.clone()),
            }
        }
        Some(Written {
            source: alias.source,
            scope: alias.scope,
            generics: Vec::new(),
            tokens,
        })
    }

    /// `tokens` with each path in them written from the crates' root as the full path it names at
    /// `written`'s place, and a parameter of the type written there as [`PARAMETER`]; `None` when a
    /// path cannot be placed there, since read anywhere else it could name another type.
    fn qualified(&self, written: &Written, tokens: &[Located]) -> Option<Vec<Located>> {
        let mut out = Vec::with_capacity(tokens.len());
        let mut at = 0;
        while at < tokens.len() {
            let starts = matches!(tokens[at].token, Token::Ident(_))
                && !(at > 0 && punct(tokens.get(at - 1), ':'));
            if !starts {
                out.push(tokens[at].clone());
                at += 1;
                continue;
            }
            let (segments, after) = spelled_path(&tokens[at..]);
            let line = tokens[at].line;
            if segments.len() == 1 && written.generics.contains(&segments[0]) {
                out.push(Located {
                    token: Token::Ident(PARAMETER.to_owned()),
                    line,
                });
                at += after.max(1);
                continue;
            }
            let path = self.resolve(written, &segments).ok()?;
            for segment in path.split("::") {
                out.push(Located {
                    token: Token::Punct(':'),
                    line,
                });
                out.push(Located {
                    token: Token::Punct(':'),
                    line,
                });
                out.push(Located {
                    token: Token::Ident(segment.to_owned()),
                    line,
                });
            }
            at += after.max(1);
        }
        Some(out)
    }

    /// Whether a type written at `written`'s place is one byte, through any aliases.
    fn is_byte(&self, written: &Written, tokens: &[Located]) -> bool {
        let (segments, after) = spelled_path(tokens);
        if segments.is_empty() {
            return false;
        }
        let arguments: Vec<Vec<Located>> = if punct(tokens.get(after), '<') {
            let close = angle_close(tokens, after).unwrap_or(tokens.len());
            split_commas(&tokens[after + 1..close.min(tokens.len())])
                .into_iter()
                .filter(|argument| {
                    !matches!(
                        argument.first().map(|located| &located.token),
                        Some(Token::Lifetime(_))
                    )
                })
                .collect()
        } else if after == tokens.len() {
            Vec::new()
        } else {
            return false;
        };
        match self.resolve(written, &segments).ok().as_deref() {
            Some("prim::u8") => true,
            Some(path) => self.type_aliases.get(path).is_some_and(|aliases| {
                aliases.iter().any(|alias| {
                    self.expand_alias(alias, written, &arguments)
                        .is_some_and(|expanded| {
                            let byte = self.is_byte(&expanded, &expanded.tokens);
                            self.expanding.set(self.expanding.get().saturating_sub(1));
                            byte
                        })
                })
            }),
            None => false,
        }
    }

    /// Why a derived `Debug` over `declared`'s fields prints text.
    fn derived_carries(&self, declared: &Declared, carrying: &Carrying) -> Option<Why> {
        declared.shapes.iter().find_map(|shape| {
            shape.members.iter().find_map(|member| {
                self.carries(&member.written, carrying).map(|why| {
                    if shape.name == declared.name {
                        format!("the field `{}`: {why}", member.name)
                    } else {
                        format!("the field `{}` of `{}`: {why}", member.name, shape.name)
                    }
                })
            })
        })
    }

    /// Every type whose `Debug` carries text, to a fixpoint.
    fn fixpoint(&self) -> Carrying {
        let mut carrying = Carrying::new();
        loop {
            let mut changed = false;
            for (path, definitions) in &self.declared {
                if carrying.contains_key(path) || self.decided(path) {
                    continue;
                }
                let hands: Vec<&ByHand> = self
                    .by_hand
                    .iter()
                    .filter(|hand| hand.target == *path)
                    .collect();
                // A type defined once for each set of `cfg` conditions carries when any definition
                // does, and each `Debug` written by hand for it is read beside a derived one, since
                // `cfg` can put either in force.
                let why = definitions
                    .iter()
                    .find_map(|declared| match declared.derived {
                        Some(_) => self.derived_carries(declared, &carrying),
                        // A type formatted somewhere has a `Debug`: one this reading cannot find is
                        // one it cannot hold.
                        None if hands.is_empty() => {
                            Some("a type whose Debug this reading cannot find".to_owned())
                        }
                        None => None,
                    })
                    .or_else(|| {
                        hands
                            .iter()
                            .find_map(|hand| self.read_by_hand(hand, &carrying).err())
                            .map(|(_, why)| why)
                    });
                if let Some(why) = why {
                    carrying.insert(path.clone(), why);
                    changed = true;
                }
            }
            if !changed {
                return carrying;
            }
        }
    }

    /// Every place in the two crates where a `Debug` can print text that arrived.
    fn findings(&self) -> Vec<Finding> {
        let carrying = self.fixpoint();
        let mut findings = BTreeSet::new();
        for declared in self.declared.values().flatten() {
            let (Some(file), Some(line)) = (self.guarded_file(declared.source), declared.derived)
            else {
                continue;
            };
            if let Some(why) = self.derived_carries(declared, &carrying) {
                findings.insert(Finding {
                    file: file.to_owned(),
                    line,
                    item: declared.name.clone(),
                    what: format!("a derived Debug over text that arrived: {why}"),
                });
            }
        }
        for hand in &self.by_hand {
            let Some(file) = self.guarded_file(hand.written.source) else {
                continue;
            };
            if let Err((line, why)) = self.read_by_hand(hand, &carrying) {
                let item = hand.target.rsplit("::").next().unwrap_or("?").to_owned();
                findings.insert(Finding {
                    file: file.to_owned(),
                    line,
                    item,
                    what: format!("a Debug written by hand that formats {why}"),
                });
            }
        }
        findings.extend(self.unplaced.iter().cloned());
        findings.into_iter().collect()
    }
}

/* -------------------------------------------------------------------------------------------- */
/* Reading a Debug written by hand                                                               */
/* -------------------------------------------------------------------------------------------- */

/// The trait a value is formatted with.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Trait {
    Debug,
    Display,
    /// `LowerHex` and the other number formats.
    Number,
    /// `write_str`, which writes text as it is: held as a `Display` is.
    Text,
}

/// A name a pattern or a `let` binds in part of a body: its type, when this reading knows it.
struct Binding {
    name: String,
    from: usize,
    to: usize,
    written: Option<Written>,
    /// Whether a `cfg` this reading cannot decide can leave the `let` out, and an earlier binding
    /// of the name stay in force.
    removable: bool,
}

/// One `Debug` written by hand, being read.
struct Reading<'a> {
    debugs: &'a Debugs,
    hand: &'a ByHand,
    carrying: &'a Carrying,
    /// The body of `fmt`, from its opening brace to its closing one.
    body: &'a [Located],
    /// Where `body` starts in the `impl` block's tokens.
    offset: usize,
    formatter: String,
    bindings: Vec<Binding>,
}

type Refused = (usize, Why);

impl Debugs {
    /// Reads one `Debug` written by hand, and says the first thing it formats that may carry text:
    /// every `fn fmt` of the `impl`, since `cfg` can put any of them in force.
    fn read_by_hand(&self, hand: &ByHand, carrying: &Carrying) -> Result<(), Refused> {
        let tokens = &hand.tokens;
        let bodies: Vec<usize> = (0..tokens.len())
            .filter(|&at| {
                ident(tokens.get(at)) == Some("fn") && ident(tokens.get(at + 1)) == Some("fmt")
            })
            .collect();
        if bodies.is_empty() {
            return Err((hand.line, "a body this reading cannot find".to_owned()));
        }
        for at in bodies {
            self.read_fmt(hand, carrying, at)?;
        }
        Ok(())
    }

    /// Reads the `fn fmt` at `at` of a `Debug` written by hand.
    fn read_fmt(&self, hand: &ByHand, carrying: &Carrying, at: usize) -> Result<(), Refused> {
        let tokens = &hand.tokens;
        let refuse = |why: &str| (hand.line, why.to_owned());
        let open = at + 2;
        let close =
            closing(tokens, open).ok_or_else(|| refuse("a body this reading cannot find"))?;
        let parameters = split_commas(&tokens[open + 1..close]);
        let formatter = parameters
            .get(1)
            .and_then(|parameter| ident(parameter.first()))
            .ok_or_else(|| refuse("a formatter this reading cannot find"))?
            .to_owned();
        let body_open = (close..tokens.len())
            .find(|&at| punct(tokens.get(at), '{'))
            .ok_or_else(|| refuse("a body this reading cannot find"))?;
        let body_close =
            closing(tokens, body_open).ok_or_else(|| refuse("a body this reading cannot find"))?;
        let mut reading = Reading {
            debugs: self,
            hand,
            carrying,
            body: &tokens[body_open..=body_close],
            offset: body_open,
            formatter,
            bindings: Vec::new(),
        };
        reading.bind();
        reading.read()
    }
}

impl Reading<'_> {
    fn refuse(&self, at: usize, why: impl Into<String>) -> Refused {
        (
            self.body
                .get(at)
                .map_or(self.hand.line, |located| located.line),
            why.into(),
        )
    }

    /// The type of `self`.
    fn self_type(&self) -> Written {
        self.hand.written.clone()
    }

    /// The scope the body's token at `at` is written in: its own, for a body in a source, and
    /// where the macro is used, for one a macro writes.
    fn scope_at(&self, at: usize) -> usize {
        self.hand.origin.map_or(self.hand.written.scope, |origin| {
            self.debugs.sources[self.hand.written.source].scope_at(origin + self.offset + at)
        })
    }

    /// The type the path `tokens` names, written at the body's token `at`.
    fn written_at(&self, at: usize, tokens: &[Located]) -> Written {
        Written {
            source: self.hand.written.source,
            scope: self.scope_at(at),
            generics: self.hand.written.generics.clone(),
            tokens: tokens.to_vec(),
        }
    }

    /// Where the path `segments`, written at the body's token `at`, leads, read as `kind`.
    fn placed_at(&self, at: usize, segments: &[String], kind: Kind) -> Result<String, Why> {
        self.debugs
            .place(self.hand.written.source, self.scope_at(at), segments, kind)
    }

    /// The binding of `name` in force at `at`, the innermost first.
    fn binding(&self, name: &str, at: usize) -> Option<&Binding> {
        let latest = self
            .bindings
            .iter()
            .filter(|binding| binding.name == name && binding.from <= at && at <= binding.to)
            .max_by_key(|binding| binding.from)?;
        // A binding a `cfg` can leave out may not be the one in force: the name has no one type.
        (!latest.removable).then_some(latest)
    }

    /// Records every name a `match`, a `let` or an `if let` binds, with where it is in force.
    fn bind(&mut self) {
        let body = self.body;
        for at in 0..body.len() {
            match ident(body.get(at)) {
                Some("match") => {
                    let Some(open) = (at + 1..body.len()).find(|&open| punct(body.get(open), '{'))
                    else {
                        continue;
                    };
                    let scrutinee = self.place_type(&body[at + 1..open], at).ok();
                    let close = closing(body, open).unwrap_or(body.len() - 1);
                    let mut cursor = open + 1;
                    while cursor < close {
                        let Some(arrow) = (cursor..close).find(|&arrow| {
                            punct(body.get(arrow), '=')
                                && punct(body.get(arrow + 1), '>')
                                && depth_between(body, cursor, arrow) == 0
                        }) else {
                            break;
                        };
                        let pattern = &body[cursor..arrow];
                        let arm_start = arrow + 2;
                        let arm_end = if punct(body.get(arm_start), '{') {
                            closing(body, arm_start).unwrap_or(close)
                        } else {
                            (arm_start..close)
                                .find(|&end| {
                                    punct(body.get(end), ',')
                                        && depth_between(body, arm_start, end) == 0
                                })
                                .unwrap_or(close)
                        };
                        self.bind_pattern(pattern, scrutinee.as_ref(), arm_start, arm_end);
                        cursor = arm_end + 1;
                        if punct(body.get(cursor), ',') {
                            cursor += 1;
                        }
                    }
                }
                Some("let") => {
                    let bound = self.bindings.len();
                    let removable = (before_item(body, at)..at).any(|index| {
                        punct(body.get(index), '#') && cfg_is_conditional(body, index + 1)
                    });
                    self.bind_let(at);
                    for binding in &mut self.bindings[bound..] {
                        binding.removable = removable;
                    }
                }
                _ => {}
            }
        }
    }

    /// Records the names the `let` at `at` binds.
    fn bind_let(&mut self, at: usize) {
        let body = self.body;
        let Some(equals) = (at + 1..body.len()).find(|&equals| {
            (punct(body.get(equals), '=') && !punct(body.get(equals + 1), '='))
                || punct(body.get(equals), ';')
        }) else {
            return;
        };
        let conditional = at > 0 && matches!(ident(body.get(at - 1)), Some("if" | "while"));
        let end = (equals..body.len())
            .find(|&end| {
                (punct(body.get(end), ';') || (conditional && punct(body.get(end), '{')))
                    && depth_between(body, equals, end) == 0
            })
            .unwrap_or(body.len() - 1);
        let value = &body[equals + 1..end];
        let scrutinee = self.place_type(value, at).ok();
        let (from, to) = if conditional {
            (end, closing(body, end).unwrap_or(body.len() - 1))
        } else {
            (end, enclosing_close(body, at))
        };
        let mut pattern = &body[at + 1..equals];
        // A type written on the binding is its type.
        if let Some(colon) = pattern
            .iter()
            .position(|located| located.token == Token::Punct(':'))
        {
            let written = self.written_at(at, &pattern[colon + 1..]);
            pattern = &pattern[..colon];
            if let Some(name) = single_binding(pattern) {
                self.bindings.push(Binding {
                    name,
                    from,
                    to,
                    written: Some(written),
                    removable: false,
                });
                return;
            }
        }
        if conditional {
            self.bind_pattern(pattern, scrutinee.as_ref(), from, to);
        } else if let Some(name) = single_binding(pattern) {
            self.bindings.push(Binding {
                name,
                from,
                to,
                written: scrutinee,
                removable: false,
            });
        } else {
            self.bind_unknown(pattern, from, to);
        }
    }

    /// Binds what `pattern` names, matched against a value of type `scrutinee`, from `from` to
    /// `to`.
    fn bind_pattern(
        &mut self,
        pattern: &[Located],
        scrutinee: Option<&Written>,
        from: usize,
        to: usize,
    ) {
        if let Some(name) = single_binding(pattern) {
            self.bindings.push(Binding {
                name,
                from,
                to,
                written: scrutinee.cloned(),
                removable: false,
            });
            return;
        }
        let (segments, after) = spelled_path(pattern);
        let group = pattern.get(after);
        let whole = after == pattern.len() || closing(pattern, after) == Some(pattern.len() - 1);
        let shape = match (scrutinee, segments.last()) {
            (Some(scrutinee), Some(variant)) if whole => self.shape_of(scrutinee, variant),
            _ => None,
        };
        let Some(members) = shape else {
            self.bind_unknown(pattern, from, to);
            return;
        };
        let named = punct(group, '{');
        let parts = if punct(group, '(') || named {
            arguments(pattern, after).unwrap_or_default()
        } else {
            Vec::new()
        };
        for (position, part) in parts.iter().enumerate() {
            let (member, sub) = if named {
                match part
                    .iter()
                    .position(|located| located.token == Token::Punct(':'))
                {
                    Some(colon) => (
                        ident(part.first()).map(ToOwned::to_owned),
                        &part[colon + 1..],
                    ),
                    None => (single_binding(part), &part[..]),
                }
            } else {
                (Some(position.to_string()), &part[..])
            };
            if matches!(sub, [one] if ident(Some(one)) == Some("_"))
                || sub.iter().all(|located| located.token == Token::Punct('.'))
            {
                continue;
            }
            let Some(name) = single_binding(sub) else {
                self.bind_unknown(sub, from, to);
                continue;
            };
            // A field defined more than once, once for each set of `cfg` conditions, has no one type.
            let written = member.and_then(|member| {
                match members
                    .iter()
                    .filter(|(candidate, _)| *candidate == member)
                    .collect::<Vec<_>>()
                    .as_slice()
                {
                    [(_, written)] => Some(written.clone()),
                    _ => None,
                }
            });
            self.bindings.push(Binding {
                name,
                from,
                to,
                written,
                removable: false,
            });
        }
    }

    /// Binds every name in `pattern` with no type this reading knows.
    fn bind_unknown(&mut self, pattern: &[Located], from: usize, to: usize) {
        for (at, located) in pattern.iter().enumerate() {
            if let Token::Ident(word) = &located.token
                && word
                    .chars()
                    .next()
                    .is_some_and(|first| first.is_lowercase() || first == '_')
                && !matches!(word.as_str(), "ref" | "mut" | "_" | "self")
                && !punct(pattern.get(at + 1), ':')
                && !punct(pattern.get(at + 1), '(')
                && !punct(pattern.get(at + 1), '{')
            {
                self.bindings.push(Binding {
                    name: word.clone(),
                    from,
                    to,
                    written: None,
                    removable: false,
                });
            }
        }
    }

    /// The members of the variant or struct `name` of the type `scrutinee`, each by name with its
    /// type.
    fn shape_of(&self, scrutinee: &Written, name: &str) -> Option<Vec<(String, Written)>> {
        let declared = self.declaration(scrutinee)?;
        // A variant defined more than once, once for each set of `cfg` conditions, has no one shape.
        let named: Vec<&Shape> = declared
            .shapes
            .iter()
            .filter(|shape| shape.name == name)
            .collect();
        let shape = match named.as_slice() {
            [shape] => *shape,
            [] if declared.shapes.len() == 1 => &declared.shapes[0],
            _ => return None,
        };
        Some(
            shape
                .stable()
                .map(|member| (member.name.clone(), member.written.clone()))
                .collect(),
        )
    }

    /// The declaration of the type `written` names, through references, `Box`, `Arc` and `Rc`.
    fn declaration(&self, written: &Written) -> Option<&Declared> {
        let inner = self.dereferenced(written)?;
        let (segments, _) = spelled_path(&inner.tokens);
        let path = self.debugs.resolve(&inner, &segments).ok()?;
        // A type with more than one definition, one for each set of `cfg` conditions, as aliases,
        // types or both, is one whose fields this reading cannot tell apart.
        let aliases = self
            .debugs
            .type_aliases
            .get(&path)
            .map_or(&[][..], Vec::as_slice);
        let definitions = self
            .debugs
            .declared
            .get(&path)
            .map_or(&[][..], Vec::as_slice);
        match (aliases, definitions) {
            ([alias], []) => self.declaration(alias),
            ([], [declared]) => Some(declared),
            _ => None,
        }
    }

    /// The type `written` names once references, `Box`, `Arc` and `Rc` are looked through.
    fn dereferenced(&self, written: &Written) -> Option<Written> {
        let tokens = strip_references(&written.tokens);
        let (segments, after) = spelled_path(&tokens);
        let path = self.debugs.resolve(written, &segments).ok();
        if matches!(
            path.as_deref(),
            Some("std::boxed::Box" | "std::sync::Arc" | "std::rc::Rc")
        ) && punct(tokens.get(after), '<')
        {
            let close = angle_close(&tokens, after)?;
            let inner = Written {
                tokens: tokens[after + 1..close].to_vec(),
                ..written.clone()
            };
            return self.dereferenced(&inner);
        }
        Some(Written {
            tokens,
            ..written.clone()
        })
    }

    /// The full path of the type `written` names once references are looked through.
    fn head(&self, written: &Written) -> Option<String> {
        let tokens = strip_references(&written.tokens);
        if punct(tokens.first(), '[') {
            return Some("prim::slice".to_owned());
        }
        let (segments, _) = spelled_path(&tokens);
        self.debugs.resolve(written, &segments).ok()
    }

    /// The type of a place, `self` or a binding followed by fields: `self.a.0.b`.
    fn place_type(&self, tokens: &[Located], at: usize) -> Result<Written, Why> {
        let mut tokens = tokens;
        while punct(tokens.first(), '&')
            || punct(tokens.first(), '*')
            || ident(tokens.first()) == Some("mut")
        {
            tokens = &tokens[1..];
        }
        let mut current = match ident(tokens.first()) {
            Some("self") => self.self_type(),
            Some(name) => self
                .binding(name, at)
                .and_then(|binding| binding.written.clone())
                .ok_or_else(|| format!("`{name}`, a value this reading cannot place"))?,
            None => return Err("a value this reading cannot place".to_owned()),
        };
        let mut index = 1;
        while index < tokens.len() {
            if !punct(tokens.get(index), '.') {
                return Err("an expression this reading does not read".to_owned());
            }
            let field = match tokens.get(index + 1).map(|located| &located.token) {
                Some(Token::Ident(word)) => vec![word.clone()],
                Some(Token::Number(number)) => number.split('.').map(ToOwned::to_owned).collect(),
                _ => return Err("an expression this reading does not read".to_owned()),
            };
            if punct(tokens.get(index + 2), '(') {
                return Err("a method call".to_owned());
            }
            for name in field {
                current = self.field_type(&current, &name)?;
            }
            index += 2;
        }
        Ok(current)
    }

    /// The type of the field `name` of a value of type `of`.
    fn field_type(&self, of: &Written, name: &str) -> Result<Written, Why> {
        let declared = self
            .declaration(of)
            .ok_or_else(|| "a field of a type this reading cannot place".to_owned())?;
        let shapes: Vec<&Shape> = declared
            .shapes
            .iter()
            .filter(|shape| shape.name == declared.name)
            .collect();
        let members: Vec<&Member> = shapes
            .iter()
            .flat_map(|shape| &shape.members)
            .filter(|member| member.name == name)
            .collect();
        let stable = shapes
            .iter()
            .flat_map(|shape| shape.stable())
            .any(|member| member.name == name);
        let member = match members.as_slice() {
            [member] if stable => *member,
            [_] => {
                return Err(format!(
                    "the field `{name}`, a position cfg can move by leaving a field out"
                ));
            }
            [] => {
                return Err(format!(
                    "the field `{name}`, which this reading cannot find"
                ));
            }
            _ => {
                return Err(format!(
                    "the field `{name}`, which has more than one definition, one for each set of \
                     cfg conditions"
                ));
            }
        };
        let (segments, after) = spelled_path(&strip_references(&member.written.tokens));
        if segments.len() == 1
            && member.written.generics.contains(&segments[0])
            && after == strip_references(&member.written.tokens).len()
        {
            return Err(format!(
                "the field `{name}`, whose type is a generic parameter"
            ));
        }
        Ok(member.written.clone())
    }

    /// Reads every use of the formatter, and every value each formats.
    fn read(&self) -> Result<(), Refused> {
        let body = self.body;
        let mut used: BTreeSet<usize> = BTreeSet::new();
        let mut at = 0;
        while at < body.len() {
            let word = ident(body.get(at));
            // A macro this reading does not know can give a name the body uses a binding of its
            // own, `let $name = …`: the body is read only with the macros this reading knows.
            if let Some(name) = word
                && punct(body.get(at + 1), '!')
                && matches!(
                    body.get(at + 2).map(|located| &located.token),
                    Some(Token::Punct('(' | '[' | '{'))
                )
                && !KEYWORDS.contains(&name)
                && !self
                    .placed_at(at, &path_ending_at(body, at), Kind::Macro)
                    .is_ok_and(|path| macro_read(&path))
            {
                return Err(self.refuse(
                    at,
                    format!("the macro {name}!, which this reading does not read"),
                ));
            }
            if word == Some(self.formatter.as_str()) && punct(body.get(at + 1), '.') {
                let end = self.read_chain(at)?;
                used.insert(at);
                at = end;
                continue;
            }
            // `write!` and `writeln!` are read when they are the standard library's; a macro of
            // either name placed elsewhere is not, and the formatter it is given is refused below.
            if matches!(word, Some("write" | "writeln"))
                && punct(body.get(at + 1), '!')
                && self
                    .placed_at(at, &path_ending_at(body, at), Kind::Macro)
                    .is_ok_and(|path| matches!(std_item(&path), Some("write" | "writeln")))
            {
                let parts = arguments(body, at + 2).unwrap_or_default();
                if matches!(parts.first().map(Vec::as_slice), Some([one]) if ident(Some(one)) == Some(self.formatter.as_str()))
                {
                    self.read_format(at, &parts)?;
                    if let Some(position) = (at..body.len()).find(|&position| {
                        ident(body.get(position)) == Some(self.formatter.as_str())
                    }) {
                        used.insert(position);
                    }
                }
            }
            if word == Some("fmt")
                && punct(body.get(at + 1), '(')
                && at >= 2
                && punct(body.get(at - 1), ':')
            {
                let parts = arguments(body, at + 1).unwrap_or_default();
                if matches!(parts.get(1).map(Vec::as_slice), Some([one]) if ident(Some(one)) == Some(self.formatter.as_str()))
                {
                    // The trait whose `fmt` this is, placed where it is written: only the standard
                    // library's formatting traits are read, by what they are, not by their name.
                    let path = path_ending_at(body, at);
                    let owner = &path[..path.len() - 1];
                    let placed = self.placed_at(at, owner, Kind::Trait).ok();
                    let named = match placed.as_deref().and_then(std_item) {
                        Some("Debug") => Trait::Debug,
                        Some("Display") => Trait::Display,
                        Some(
                            "Binary" | "LowerExp" | "LowerHex" | "Octal" | "UpperExp" | "UpperHex",
                        ) => Trait::Number,
                        _ => {
                            return Err(self.refuse(
                                at,
                                format!(
                                    "the fmt of {}, a trait this reading does not read",
                                    owner.join("::")
                                ),
                            ));
                        }
                    };
                    self.value(&parts[0], at, named)?;
                    if let Some(position) = (at..body.len()).find(|&position| {
                        ident(body.get(position)) == Some(self.formatter.as_str())
                    }) {
                        used.insert(position);
                    }
                }
            }
            at += 1;
        }
        for (position, located) in body.iter().enumerate() {
            if ident(Some(located)) == Some(self.formatter.as_str()) && !used.contains(&position) {
                return Err(self.refuse(position, "text through a formatter it passes on"));
            }
        }
        Ok(())
    }

    /// Reads a chain of the formatter's methods starting at the formatter at `at`, and returns the
    /// index past it.
    fn read_chain(&self, at: usize) -> Result<usize, Refused> {
        let body = self.body;
        let mut cursor = at + 1;
        let mut kind = "";
        while punct(body.get(cursor), '.') {
            let Some(method) = ident(body.get(cursor + 1)) else {
                break;
            };
            if !punct(body.get(cursor + 2), '(') {
                return Err(self.refuse(cursor, format!("the formatter's `{method}`")));
            }
            let close = closing(body, cursor + 2).unwrap_or(body.len() - 1);
            let parts = arguments(body, cursor + 2).unwrap_or_default();
            match (kind, method) {
                ("", "write_str") => {
                    let [text] = parts.as_slice() else {
                        return Err(self.refuse(cursor, "text it does not read"));
                    };
                    self.value(text, cursor, Trait::Text)?;
                }
                ("", "debug_struct" | "debug_tuple") => {
                    if !matches!(parts.as_slice(), [one] if matches!(one.as_slice(), [Located { token: Token::Str(_), .. }]))
                    {
                        return Err(self.refuse(cursor, "a name that is not this program's words"));
                    }
                    kind = if method == "debug_struct" {
                        "struct"
                    } else {
                        "tuple"
                    };
                }
                ("", "debug_list" | "debug_set") => kind = "list",
                ("", "debug_map") => kind = "map",
                ("", "alternate") => {}
                ("struct", "field") => {
                    let [name, value] = parts.as_slice() else {
                        return Err(self.refuse(cursor, "a field it does not read"));
                    };
                    if !matches!(
                        name.as_slice(),
                        [Located {
                            token: Token::Str(_),
                            ..
                        }]
                    ) {
                        return Err(
                            self.refuse(cursor, "a field name that is not this program's words")
                        );
                    }
                    self.value(value, cursor, Trait::Debug)?;
                }
                ("tuple", "field") | ("list", "entry") | ("map", "key" | "value") => {
                    let [value] = parts.as_slice() else {
                        return Err(self.refuse(cursor, "a field it does not read"));
                    };
                    self.value(value, cursor, Trait::Debug)?;
                }
                ("map", "entry") => {
                    for value in &parts {
                        self.value(value, cursor, Trait::Debug)?;
                    }
                }
                (_, "finish" | "finish_non_exhaustive") => {}
                (_, other) => {
                    return Err(self.refuse(cursor, format!("the formatter's `{other}`")));
                }
            }
            cursor = close + 1;
        }
        Ok(cursor)
    }

    /// Reads `write!(formatter, "…", …)`: each hole's value, for the trait the hole uses.
    fn read_format(&self, at: usize, parts: &[Vec<Located>]) -> Result<(), Refused> {
        let Some(
            [
                Located {
                    token: Token::Str(template),
                    ..
                },
            ],
        ) = parts.get(1).map(Vec::as_slice)
        else {
            return Err(self.refuse(at, "a format that is not this program's words"));
        };
        let rest = &parts[2..];
        let mut positional = rest.iter().filter(|part| {
            !(ident(part.first()).is_some() && punct(part.get(1), '=') && !punct(part.get(2), '='))
        });
        let named = |name: &str| {
            rest.iter()
                .find(|part| {
                    ident(part.first()) == Some(name)
                        && punct(part.get(1), '=')
                        && !punct(part.get(2), '=')
                })
                .map(|part| part[2..].to_vec())
        };
        for hole in holes(template) {
            let (argument, spec) = hole.split_once(':').unwrap_or((hole.as_str(), ""));
            let argument = argument.trim();
            let used = if spec.contains('?') {
                Trait::Debug
            } else if spec.ends_with(|last: char| "xXobeEp".contains(last)) {
                Trait::Number
            } else {
                Trait::Display
            };
            if spec.contains('$') || spec.contains('*') {
                return Err(self.refuse(at, "a format whose width or precision is a value"));
            }
            let value: Vec<Located> = if argument.is_empty() {
                positional
                    .next()
                    .cloned()
                    .ok_or_else(|| self.refuse(at, "a format with more holes than values"))?
            } else if let Ok(position) = argument.parse::<usize>() {
                rest.get(position)
                    .cloned()
                    .ok_or_else(|| self.refuse(at, "a format naming a value it does not have"))?
            } else if let Some(value) = named(argument) {
                value
            } else {
                vec![Located {
                    token: Token::Ident(argument.to_owned()),
                    line: self.body[at].line,
                }]
            };
            self.value(&value, at, used)?;
        }
        Ok(())
    }

    /// Whether a value formatted with `used` says only what may be shown.
    fn value(&self, tokens: &[Located], at: usize, used: Trait) -> Result<(), Refused> {
        let mut tokens = tokens;
        while punct(tokens.first(), '&')
            || punct(tokens.first(), '*')
            || ident(tokens.first()) == Some("mut")
        {
            tokens = &tokens[1..];
        }
        // A literal is this program's words.
        if let [one] = tokens {
            match &one.token {
                Token::Str(_) | Token::Char | Token::Number(_) => return Ok(()),
                Token::Ident(word) if word == "true" || word == "false" => return Ok(()),
                _ => {}
            }
        }
        // A `Shown` by construction, or its text.
        if let Some(end) = self.shown(tokens, at) {
            let rest = &tokens[end..];
            if rest.is_empty()
                || matches!(rest, [dot, method, open, close] if punct(Some(dot), '.') && matches!(ident(Some(method)), Some("as_str" | "into_string")) && punct(Some(open), '(') && punct(Some(close), ')'))
            {
                return Ok(());
            }
            return Err(self.refuse(at, "a value this reading does not read"));
        }
        // A place, measured or mapped by what this reading knows.
        let place_end = place_end(tokens);
        let place = self
            .place_type(&tokens[..place_end], at)
            .map_err(|why| self.refuse(at, why))?;
        let tail = &tokens[place_end..];
        if tail.is_empty() {
            return self
                .formats(&place, used)
                .map_err(|why| self.refuse(at, why));
        }
        let Some(method) = ident(tail.get(1)) else {
            return Err(self.refuse(at, "an expression this reading does not read"));
        };
        let head = self.head(&place).unwrap_or_default();
        let after = closing(tail, 2).map_or(tail.len(), |close| close + 1);
        if MEASURES.contains(&method)
            && after == tail.len()
            && (MEASURED.contains(&head.as_str()) || head == "prim::slice")
        {
            return Ok(());
        }
        let mut remainder = tail;
        if matches!(method, "as_ref" | "as_deref") && head == "std::option::Option" {
            remainder = &tail[after..];
        }
        let optional = head == "std::option::Option";
        match (optional, ident(remainder.get(1))) {
            (true, Some(mapping @ ("map" | "map_or"))) => {
                let parts = arguments(remainder, 2).unwrap_or_default();
                let end = closing(remainder, 2).map_or(remainder.len(), |close| close + 1);
                if end != remainder.len() {
                    return Err(self.refuse(at, "an expression this reading does not read"));
                }
                let (fallback, function) = match (mapping, parts.as_slice()) {
                    ("map", [function]) => (None, function),
                    ("map_or", [fallback, function]) => (Some(fallback), function),
                    _ => return Err(self.refuse(at, "a mapping this reading does not read")),
                };
                if let Some(fallback) = fallback
                    && !matches!(
                        fallback.as_slice(),
                        [Located {
                            token: Token::Str(_) | Token::Number(_),
                            ..
                        }]
                    )
                {
                    return Err(self.refuse(at, "a fallback that is not this program's words"));
                }
                if self.mapping_says_nothing(function, at) {
                    return Ok(());
                }
                Err(self.refuse(at, "a mapping this reading does not read"))
            }
            (true, Some("unwrap_or")) => {
                let parts = arguments(remainder, 2).unwrap_or_default();
                let end = closing(remainder, 2).map_or(remainder.len(), |close| close + 1);
                if end != remainder.len()
                    || !matches!(parts.as_slice(), [one] if matches!(one.as_slice(), [Located { token: Token::Str(_) | Token::Number(_), .. }]))
                {
                    return Err(self.refuse(at, "a fallback this reading does not read"));
                }
                let inner = self
                    .option_argument(&place)
                    .ok_or_else(|| self.refuse(at, "an option this reading cannot place"))?;
                self.formats(&inner, used)
                    .map_err(|why| self.refuse(at, why))
            }
            _ => Err(self.refuse(
                at,
                format!("the method `{method}`, which this reading does not read"),
            )),
        }
    }

    /// Whether a function mapped over an option returns only what may be shown: a length, a
    /// `Shown`, or a literal whatever it is given.
    fn mapping_says_nothing(&self, function: &[Located], at: usize) -> bool {
        if let [bar, underscore, bar_again, literal] = function
            && punct(Some(bar), '|')
            && ident(Some(underscore)) == Some("_")
            && punct(Some(bar_again), '|')
            && matches!(literal.token, Token::Str(_) | Token::Number(_))
        {
            return true;
        }
        let (segments, after) = spelled_path(function);
        let after = past_turbofish(function, after);
        if after != function.len() || segments.len() < 2 {
            return false;
        }
        let (name, owner) = segments.split_last().unwrap_or((&segments[0], &[]));
        if name == "len" {
            let owner = self.placed_at(at, owner, Kind::Type).unwrap_or_default();
            return MEASURED.contains(&owner.as_str());
        }
        self.returns_shown(&segments, at)
    }

    /// Whether the function `segments` names is one this reading knows returns a `Shown`.
    fn returns_shown(&self, segments: &[String], at: usize) -> bool {
        let Some((name, owner)) = segments.split_last() else {
            return false;
        };
        if owner.is_empty() {
            return false;
        }
        let owner = self.placed_at(at, owner, Kind::Type).unwrap_or_default();
        owner == SHOWN
            || self
                .debugs
                .shown_functions
                .contains(&format!("{owner}::{name}"))
    }

    /// Where a `Shown` built by construction ends in `tokens`, when they start with one.
    fn shown(&self, tokens: &[Located], at: usize) -> Option<usize> {
        let (segments, after) = spelled_path(tokens);
        let after = past_turbofish(tokens, after);
        if punct(tokens.get(after), '!')
            && self.placed_at(at, &segments, Kind::Macro).ok().as_deref() == Some(SHOWN_MACRO)
        {
            return closing(tokens, after + 1).map(|close| close + 1);
        }
        if punct(tokens.get(after), '(') && self.returns_shown(&segments, at) {
            return closing(tokens, after).map(|close| close + 1);
        }
        None
    }

    /// The type an option of type `written` holds.
    fn option_argument(&self, written: &Written) -> Option<Written> {
        let tokens = strip_references(&written.tokens);
        let (_, after) = spelled_path(&tokens);
        let close = angle_close(&tokens, after)?;
        Some(Written {
            tokens: tokens[after + 1..close].to_vec(),
            ..written.clone()
        })
    }

    /// Whether a value of type `written`, formatted with `used`, says only what may be shown.
    fn formats(&self, written: &Written, used: Trait) -> Result<(), Why> {
        match used {
            Trait::Debug => match self.debugs.carries(written, self.carrying) {
                None => Ok(()),
                Some(why) => Err(why),
            },
            // `write_str` writes the text as it is, through no `Display`: only this program's
            // words may be written so, and a value's type says so only as a `&'static str`.
            Trait::Text => {
                if matches!(written.tokens.as_slice(), [and, lifetime, word] if punct(Some(and), '&') && matches!(&lifetime.token, Token::Lifetime(name) if name == "'static") && ident(Some(word)) == Some("str"))
                {
                    Ok(())
                } else {
                    Err("text written as it is, which only this program's words may be".to_owned())
                }
            }
            Trait::Display => {
                if matches!(written.tokens.as_slice(), [and, lifetime, word] if punct(Some(and), '&') && matches!(&lifetime.token, Token::Lifetime(name) if name == "'static") && ident(Some(word)) == Some("str"))
                {
                    return Ok(());
                }
                let head = self.head(written).unwrap_or_default();
                let number = head
                    .strip_prefix("prim::")
                    .is_some_and(|primitive| NUMBERS.contains(&primitive));
                let ours = head.starts_with("kr_client::") || head.starts_with("kr_cli::");
                if number
                    || head == SHOWN
                    || self.debugs.plain.contains(&head)
                    || (ours && self.debugs.declared.contains_key(&head))
                {
                    Ok(())
                } else {
                    Err(format!(
                        "the Display of {}",
                        if head.is_empty() {
                            "a type this reading cannot place"
                        } else {
                            &head
                        }
                    ))
                }
            }
            Trait::Number => {
                let head = self.head(written).unwrap_or_default();
                if head
                    .strip_prefix("prim::")
                    .is_some_and(|primitive| NUMBERS.contains(&primitive))
                {
                    Ok(())
                } else {
                    Err(format!("{head} formatted as a number"))
                }
            }
        }
    }
}

/// The index past a path's generic arguments, when a turbofish gives them: `f::<T>`, where the
/// path's reading may already have taken the `::`.
fn past_turbofish(tokens: &[Located], after: usize) -> usize {
    let open = if punct(tokens.get(after), '<') {
        after
    } else if punct(tokens.get(after), ':') && punct(tokens.get(after + 2), '<') {
        after + 2
    } else {
        return after;
    };
    angle_close(tokens, open).map_or(tokens.len(), |close| close + 1)
}

/// The index past the place at the start of `tokens`: a name and the fields after it, up to a
/// method call.
fn place_end(tokens: &[Located]) -> usize {
    let mut at = 1;
    while punct(tokens.get(at), '.')
        && matches!(
            tokens.get(at + 1).map(|located| &located.token),
            Some(Token::Ident(_) | Token::Number(_))
        )
        && !punct(tokens.get(at + 2), '(')
    {
        at += 2;
    }
    at.min(tokens.len())
}

/// The one name a pattern binds when it is only a name, with any `ref` or `mut`.
fn single_binding(pattern: &[Located]) -> Option<String> {
    let words: Vec<&Located> = pattern
        .iter()
        .filter(|located| !matches!(ident(Some(located)), Some("ref" | "mut")))
        .collect();
    match words.as_slice() {
        [one] => match &one.token {
            Token::Ident(word)
                if word
                    .chars()
                    .next()
                    .is_some_and(|first| first.is_lowercase() || first == '_')
                    && word != "_"
                    && word != "self" =>
            {
                Some(word.clone())
            }
            _ => None,
        },
        _ => None,
    }
}

/// How deep in groups `to` is, counted from `from`.
fn depth_between(tokens: &[Located], from: usize, to: usize) -> i64 {
    let mut depth = 0;
    for located in &tokens[from..to.min(tokens.len())] {
        match located.token {
            Token::Punct('{' | '(' | '[') => depth += 1,
            Token::Punct('}' | ')' | ']') => depth -= 1,
            _ => {}
        }
    }
    depth
}

/// The closing brace of the block that `at` is in.
fn enclosing_close(tokens: &[Located], at: usize) -> usize {
    let mut depth = 0_i64;
    for (index, located) in tokens.iter().enumerate().skip(at) {
        match located.token {
            Token::Punct('{' | '(' | '[') => depth += 1,
            Token::Punct('}' | ')' | ']') => {
                depth -= 1;
                if depth < 0 {
                    return index;
                }
            }
            _ => {}
        }
    }
    tokens.len().saturating_sub(1)
}

/* -------------------------------------------------------------------------------------------- */
/* The rule over the two crates, and its controls                                                */
/* -------------------------------------------------------------------------------------------- */

impl Debugs {
    /// Records what the two files that define what may be shown declare, and which of their
    /// functions are declared to return a `Shown`.
    fn read_shown_files(&mut self) {
        let mut types = Vec::new();
        let mut functions = Vec::new();
        for index in 0..self.guarded {
            let source = &self.sources[index];
            if !SHOWN_FILES.contains(&source.name.as_str()) {
                continue;
            }
            let tokens = &source.tokens;
            for at in 0..tokens.len() {
                let scope = source.scope_at(at);
                match ident(tokens.get(at)) {
                    Some("struct" | "enum" | "union") => {
                        if let Some(name) = ident(tokens.get(at + 1)) {
                            types.push(source.defined_path(scope, name));
                        }
                    }
                    Some("fn") if scope == 0 => {
                        let Some(name) = ident(tokens.get(at + 1)) else {
                            continue;
                        };
                        let Some(open) =
                            (at..tokens.len()).find(|&open| punct(tokens.get(open), '('))
                        else {
                            continue;
                        };
                        let Some(close) = closing(tokens, open) else {
                            continue;
                        };
                        if punct(tokens.get(close + 1), '-') && punct(tokens.get(close + 2), '>') {
                            let end = (close + 3..tokens.len())
                                .find(|&end| {
                                    punct(tokens.get(end), '{')
                                        || ident(tokens.get(end)) == Some("where")
                                })
                                .unwrap_or(tokens.len());
                            let written = Written {
                                source: index,
                                scope,
                                generics: Vec::new(),
                                tokens: tokens[close + 3..end].to_vec(),
                            };
                            let (segments, after) = spelled_path(&written.tokens);
                            if after == written.tokens.len()
                                && self.resolve(&written, &segments).ok().as_deref() == Some(SHOWN)
                            {
                                let module = source.module_of(scope).join("::");
                                functions.push(format!("{module}::{name}"));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        self.shown_types.extend(types);
        self.shown_functions.extend(functions);
    }
}

/// Every place in the two crates where a `Debug` can print text that arrived.
fn debug_findings(workspace: &Path, guarded: Vec<Source>) -> Vec<Finding> {
    let mut debugs = Debugs::read(workspace, guarded);
    debugs.read_shown_files();
    debugs.findings()
}

/// Every `Debug` in the two crates says only what may be shown.
#[test]
fn no_debug_in_either_crate_prints_text_that_arrived() {
    let findings = debug_findings(&workspace(), both_crates());
    let listed = findings
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        findings.is_empty(),
        "{} places have a Debug that can print text that arrived:\n{listed}",
        findings.len()
    );
}

/// What the `Debug` rule finds in one control file of a command-line crate, beside the claims and
/// the failures every control can use, with `other` as a crate of the workspace it does not hold.
fn debug_findings_in(label: &str, text: &str, other: &str) -> Vec<Finding> {
    debug_findings_among(label, text, other, &[])
}

/// [`debug_findings_in`], with `more` files beside the other crate's root.
fn debug_findings_among(
    label: &str,
    text: &str,
    other: &str,
    more: &[(&str, &str)],
) -> Vec<Finding> {
    let mut files = vec![
        ("crates/kr-cli/Cargo.toml", "[package]\nname = \"kr-cli\"\n"),
        (
            "crates/kr-cli/src/lib.rs",
            "mod control;\nmod error;\nmod shown;\n",
        ),
        ("crates/kr-cli/src/shown.rs", SHOWN_CONTROL),
        ("crates/kr-cli/src/error.rs", ERRORS_CONTROL),
        ("crates/kr-cli/src/control.rs", text),
        (
            "crates/kr-other/Cargo.toml",
            "[package]\nname = \"kr-other\"\n",
        ),
        ("crates/kr-other/src/lib.rs", other),
    ];
    files.extend_from_slice(more);
    let scratch = Scratch::files(label, &files);
    let guarded = crate_sources(
        &scratch.workspace,
        &scratch.workspace.join("crates/kr-cli/src/lib.rs"),
        "kr_cli",
    )
    .expect("the control is readable");
    debug_findings(&scratch.workspace, guarded)
        .into_iter()
        .filter(|finding| finding.file.ends_with("control.rs"))
        .collect()
}

/// The crate every control can name beside its own: a type that holds text, one that does not,
/// and the types a macro declares.
const OTHER_CONTROL: &str = "pub struct Held(pub String);\n\
                             #[derive(Debug)]\npub struct Counted(pub u64);\n\
                             #[derive(Debug)]\npub struct Wrapping(pub Held);\n\
                             macro_rules! opaque {\n    ($name:ident) => {\n        #[derive(Debug)]\n        pub struct $name(String);\n    };\n}\n\
                             opaque!(Opaque);\n\
                             macro_rules! counter {\n    ($name:ident) => {\n        #[derive(Debug)]\n        pub struct $name(u64);\n    };\n}\n\
                             counter!(Revision);\n\
                             impl std::fmt::Debug for Held {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Held\").field(&self.0).finish()\n    }\n}\n";

/// Each way a `Debug` can print text that arrived is found, at its line, in a source that has
/// nothing else.
#[test]
fn each_debug_that_can_print_text_is_named_with_its_place() {
    let cases: &[(&str, &str, usize, &str)] = &[
        (
            "a derived Debug over text",
            "#[derive(Debug)]\npub struct Planted {\n    pub id: u64,\n    pub text: String,\n}\n",
            1,
            "a derived Debug over text that arrived: the field `text`: std::string::String",
        ),
        (
            "a Debug written by hand that formats text",
            "pub struct Planted {\n    pub text: String,\n}\nimpl std::fmt::Debug for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_struct(\"Planted\").field(\"text\", &self.text).finish()\n    }\n}\n",
            6,
            "a Debug written by hand that formats std::string::String",
        ),
        (
            "text through another type",
            "pub struct Inner {\n    pub text: String,\n}\n#[derive(Debug)]\npub struct Planted {\n    pub inner: Inner,\n}\nimpl std::fmt::Debug for Inner {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        write!(formatter, \"Inner({:?})\", self.text)\n    }\n}\n",
            4,
            "which carries",
        ),
        (
            "bytes",
            "#[derive(Debug)]\npub struct Planted(pub [u8; 32]);\n",
            1,
            "bytes",
        ),
        (
            "text in a generic argument",
            "#[derive(Debug)]\npub struct Planted {\n    pub names: std::collections::BTreeMap<u64, Vec<String>>,\n}\n",
            1,
            "std::string::String",
        ),
        (
            "a channel that prints its value",
            "#[derive(Debug)]\npub struct Planted {\n    pub latest: tokio::sync::watch::Sender<String>,\n}\n",
            1,
            "std::string::String",
        ),
        (
            "a type from outside the workspace this reading does not list",
            "#[derive(Debug)]\npub struct Planted {\n    pub unknown: somewhere::Unlisted,\n}\n",
            1,
            "does not list",
        ),
        (
            "another crate's type whose Debug is written by hand over text",
            "#[derive(Debug)]\npub struct Planted {\n    pub held: kr_other::Held,\n}\n",
            1,
            "kr_other::Held, which carries",
        ),
        (
            "another crate's type that holds one",
            "#[derive(Debug)]\npub struct Planted {\n    pub held: kr_other::Wrapping,\n}\n",
            1,
            "kr_other::Wrapping, which carries",
        ),
        (
            "a type another crate's macro declares over text",
            "#[derive(Debug)]\npub struct Planted {\n    pub id: kr_other::Opaque,\n}\n",
            1,
            "kr_other::Opaque, which carries",
        ),
        (
            "a character",
            "#[derive(Debug)]\npub enum Planted {\n    Typed(char),\n}\n",
            1,
            "the field `0` of `Typed`: char",
        ),
        (
            "a method this reading does not read",
            "pub struct Planted {\n    pub text: String,\n}\nimpl std::fmt::Debug for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.write_str(&self.text.clone())\n    }\n}\n",
            6,
            "the method `clone`",
        ),
        (
            "a fallback over text",
            "pub struct Planted {\n    pub text: Option<String>,\n}\nimpl std::fmt::Debug for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Planted\").field(&self.text.as_deref().unwrap_or(\"none\")).finish()\n    }\n}\n",
            6,
            "formats std::string::String",
        ),
        (
            "a length that is not the standard library's",
            "pub struct Name(String);\nimpl Name {\n    pub fn len(&self) -> &str { &self.0 }\n}\npub struct Planted {\n    pub name: Name,\n}\nimpl std::fmt::Debug for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_struct(\"Planted\").field(\"name\", &self.name.len()).finish()\n    }\n}\n",
            10,
            "the method `len`",
        ),
        (
            "a Display of a value that is not Plain",
            "pub struct Planted {\n    pub text: String,\n}\nimpl std::fmt::Debug for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        write!(formatter, \"Planted({})\", self.text)\n    }\n}\n",
            6,
            "the Display of std::string::String",
        ),
        (
            "a binding a match gives from text",
            "pub enum Planted {\n    Said(String),\n    Counted(u64),\n}\nimpl std::fmt::Debug for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        match self {\n            Self::Said(text) => formatter.debug_tuple(\"Said\").field(text).finish(),\n            Self::Counted(count) => formatter.debug_tuple(\"Counted\").field(count).finish(),\n        }\n    }\n}\n",
            8,
            "std::string::String",
        ),
        (
            "a formatter passed on",
            "pub struct Planted {\n    pub text: String,\n}\nimpl std::fmt::Debug for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        std::fmt::Display::fmt(&self.text, formatter)\n    }\n}\n",
            6,
            "the Display of std::string::String",
        ),
        (
            "a field named to the Debug that says only the fields named",
            "pub struct Planted {\n    pub id: u64,\n    pub text: String,\n}\nkr_client::debug_fields!(Planted { id, text });\n",
            5,
            "formats std::string::String",
        ),
        (
            "bytes in a vector",
            "#[derive(Debug)]\npub struct Planted(pub Vec<u8>);\n",
            1,
            "bytes",
        ),
        (
            "bytes a Debug written by hand formats",
            "pub struct Planted {\n    pub bytes: Vec<u8>,\n}\nimpl std::fmt::Debug for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Planted\").field(&self.bytes).finish()\n    }\n}\n",
            6,
            "formats bytes",
        ),
        (
            "the Debug trait under another name",
            "use std::fmt::Debug as Shows;\npub struct Planted {\n    pub text: String,\n}\nimpl Shows for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Planted\").field(&self.text).finish()\n    }\n}\n",
            7,
            "formats std::string::String",
        ),
        (
            "a Debug macro under another name",
            "use kr_client::debug_fields as fields;\npub struct Planted {\n    pub text: String,\n}\nfields!(Planted { text });\n",
            5,
            "formats std::string::String",
        ),
        (
            "text written as it is from a type of this crate",
            "pub struct Wrapped(String);\nimpl std::ops::Deref for Wrapped {\n    type Target = str;\n    fn deref(&self) -> &str { &self.0 }\n}\npub struct Planted {\n    pub secret: Wrapped,\n}\nimpl std::fmt::Debug for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.write_str(&self.secret)\n    }\n}\n",
            11,
            "text written as it is",
        ),
        (
            "bytes under an alias",
            "type Byte = u8;\n#[derive(Debug)]\npub struct Planted(pub Vec<Byte>);\n",
            2,
            "bytes",
        ),
        (
            "bytes under a generic alias",
            "type Bytes<T> = Vec<T>;\n#[derive(Debug)]\npub struct Planted(pub Bytes<u8>);\n",
            2,
            "bytes",
        ),
        (
            "bytes under an alias that a Debug written by hand formats",
            "type Byte = u8;\npub struct Planted {\n    pub bytes: Vec<Byte>,\n}\nimpl std::fmt::Debug for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Planted\").field(&self.bytes).finish()\n    }\n}\n",
            7,
            "formats bytes",
        ),
        (
            "the Debug trait under a name a re-export gives it",
            "mod names {\n    pub use std::fmt::Debug as Shows;\n}\nuse names::Shows as D;\npub struct Planted {\n    pub text: String,\n}\nimpl D for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Planted\").field(&self.text).finish()\n    }\n}\n",
            10,
            "formats std::string::String",
        ),
        (
            "a Debug macro where another is imported under its name elsewhere in the file",
            "mod inner {\n    use kr_client::debug_as_name as debug_fields;\n}\npub struct Planted {\n    pub text: String,\n}\nkr_client::debug_fields!(Planted { text });\n",
            7,
            "formats std::string::String",
        ),
        (
            "the Debug trait through a glob",
            "use std::fmt::*;\npub struct Planted(String);\nimpl Debug for Planted {\n    fn fmt(&self, formatter: &mut Formatter<'_>) -> Result {\n        formatter.debug_tuple(\"Planted\").field(&self.0).finish()\n    }\n}\n",
            5,
            "a Debug written by hand that formats",
        ),
        (
            "a Debug macro through a glob",
            "use kr_client::*;\npub struct Planted {\n    pub text: String,\n}\ndebug_fields!(Planted { text });\n",
            5,
            "a Debug written by hand that formats",
        ),
        (
            "an alias's argument read where it is written, not in the alias's scope",
            "mod aliases {\n    type Item = u64;\n    pub type Identity<T> = T;\n}\nmod values {\n    pub type Item = String;\n}\nuse values::*;\n#[derive(Debug)]\npub struct Planted(aliases::Identity<Item>);\n",
            9,
            "the field `0`: std::string::String",
        ),
        (
            "an alias whose type argument follows a const one",
            "type T = u64;\ntype Pair<const N: usize, T> = ([u16; N], T);\n#[derive(Debug)]\npub struct Planted(Pair<1, String>);\n",
            3,
            "std::string::String",
        ),
        (
            "a generic type whose parameter is the element of a byte sequence",
            "#[derive(Debug)]\npub struct Wrapper<T> {\n    pub items: Vec<T>,\n}\n#[derive(Debug)]\npub struct Planted {\n    pub wrapped: Wrapper<u8>,\n}\n",
            5,
            "which with its arguments carries bytes",
        ),
        (
            "a byte array given to a generic type",
            "#[derive(Debug)]\npub struct Wrapper<T>(pub T);\n#[derive(Debug)]\npub struct Planted(pub Wrapper<[u8; 32]>);\n",
            3,
            "bytes",
        ),
        (
            "an array of bytes under an alias",
            "type Byte = u8;\n#[derive(Debug)]\npub struct Planted(pub [Byte; 4]);\n",
            2,
            "bytes",
        ),
        (
            "the Debug trait through a glob a module re-exports",
            "mod names {\n    pub use std::fmt::*;\n}\nuse names::Debug;\npub struct Planted(String);\nimpl Debug for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Planted\").field(&self.0).finish()\n    }\n}\n",
            8,
            "a Debug written by hand that formats",
        ),
        (
            "the Debug trait renamed behind a chain of globs",
            "mod first {\n    pub use std::fmt::Debug as Shows;\n}\nmod second {\n    pub use super::first::*;\n}\nuse second::*;\npub struct Planted(pub u64, pub std::string::String);\nimpl Shows for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Planted\").field(&self.1).finish()\n    }\n}\n",
            11,
            "a Debug written by hand that formats",
        ),
        (
            "a name that is not the program's words",
            "pub struct Planted {\n    pub name: &'static str,\n}\nimpl std::fmt::Debug for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_struct(self.name).finish()\n    }\n}\n",
            6,
            "a name that is not this program's words",
        ),
    ];
    for (position, (class, text, line, what)) in cases.iter().enumerate() {
        let findings = debug_findings_in(&format!("debug-case-{position}"), text, OTHER_CONTROL);
        assert!(
            findings
                .iter()
                .any(|finding| finding.line == *line && finding.what.contains(what)),
            "{class}: expected a finding at line {line} saying {what:?}, found {findings:?}"
        );
    }
}

/// What the `Debug` rule allows is not found: the same shapes, written the way the rule asks.
#[test]
fn what_the_debug_rule_allows_is_not_named() {
    let text = "use kr_client::shown::Shown;\n\
                #[derive(Debug)]\n\
                pub struct Counts {\n    pub id: u64,\n    pub label: &'static str,\n    pub ids: Vec<kr_protocol::scalars::Uuid>,\n    pub when: std::time::Duration,\n    pub other: kr_other::Counted,\n    pub revision: kr_other::Revision,\n    pub shown: Shown,\n}\n\
                pub enum Said {\n    Text(String),\n    Count(u64),\n}\n\
                pub struct Held {\n    pub text: String,\n    pub maybe: Option<String>,\n    pub count: Option<u64>,\n    pub counts: Counts,\n    pub said: Said,\n}\n\
                impl std::fmt::Debug for Held {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter\n            .debug_struct(\"Held\")\n            .field(\"text_bytes\", &self.text.len())\n            .field(\"maybe_bytes\", &self.maybe.as_ref().map(String::len))\n            .field(\"present\", &self.maybe.as_ref().map(|_| \"<present>\"))\n            .field(\"count\", &self.count.unwrap_or(0))\n            .field(\"counts\", &self.counts)\n            .field(\"said\", &self.said)\n            .field(\"words\", &Shown::said(\"words\"))\n            .field(\"composed\", &kr_client::shown!(\"{}\", 3_u64))\n            .finish_non_exhaustive()\n    }\n}\n\
                pub struct Store {\n    pub file: std::fs::File,\n    pub name: String,\n}\n\
                kr_client::debug_as_name!(Store);\n\
                pub struct Named {\n    pub id: u64,\n    pub text: String,\n}\n\
                kr_client::debug_fields!(Named { id });\n\
                #[derive(Debug)]\npub struct Holding {\n    pub store: Store,\n    pub named: Named,\n    pub mode: Option<u8>,\n    pub pairs: Pairs,\n    pub words: Wrapped<&'static str>,\n}\n#[derive(Debug)]\npub struct Wrapped<T>(pub T);\ntype Pair<const N: usize, T> = ([u16; N], T);\ntype Pairs = Pair<1, u64>;\n\
                impl std::fmt::Debug for Said {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        match self {\n            Self::Text(text) => write!(formatter, \"Text({} bytes)\", text.len()),\n            Self::Count(count) => write!(formatter, \"Count({count})\"),\n        }\n    }\n}\n";
    let findings = debug_findings_in("debug-allowed", text, OTHER_CONTROL);
    assert!(findings.is_empty(), "{findings:?}");
}

/// Each way a name can reach the `Debug` trait or a macro that writes a `Debug` is followed as the
/// compiler follows it, and a name this reading cannot follow, or a macro it does not read, is named
/// where it is written. Each case has its own neighbouring crate.
#[test]
fn each_name_is_placed_where_the_compiler_places_it() {
    let cases: &[(&str, &str, &str, usize, &str)] = &[
        (
            "the Debug trait under an import named like its own crate",
            "pub trait Debug {}\npub mod exports {\n    use std::fmt as kr_other;\n    pub use kr_other::Debug;\n}\n",
            "pub struct Leak(pub String);\nimpl kr_other::exports::Debug for Leak {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n    }\n}\n",
            4,
            "formats std::string::String",
        ),
        (
            "the standard library's Debug derive under the name of another derive of its prelude",
            "pub use std::prelude::v1::Debug as Clone;\n",
            "use kr_other::Clone;\n#[derive(Clone)]\npub struct Leak(pub String);\n",
            2,
            "a derived Debug over text that arrived",
        ),
        (
            "the standard library's include! under another name",
            "pub use std::prelude::v1::include as load;\n",
            "kr_other::load!(\"leak.rs\");\n",
            1,
            "a macro this reading does not read",
        ),
        (
            "a trait from outside the workspace this reading does not list",
            "",
            "pub struct Leak(pub String);\nimpl somewhere::names::Shows for Leak {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n    }\n}\n",
            2,
            "a trait from outside the workspace this reading does not list",
        ),
        (
            "a Debug macro imported by name beside a glob that gives the name another item",
            "pub use std::fmt::Debug as debug_fields;\npub const TAG: u64 = 0;\n",
            "use kr_client::debug_fields;\nuse kr_other::*;\npub const USED_TAG: u64 = TAG;\npub struct Leak {\n    pub text: String,\n}\ndebug_fields!(Leak { text });\n",
            7,
            "formats std::string::String",
        ),
        (
            "the Debug trait under a path whose first name a glob gives",
            "pub mod names {\n    pub use std::fmt::Debug as Shows;\n}\npub mod exports {\n    pub use super::names;\n}\n",
            "use kr_other::exports::*;\npub struct Leak(pub String);\nimpl names::Shows for Leak {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n    }\n}\n",
            5,
            "formats std::string::String",
        ),
        (
            "the Debug trait under an import whose path starts at another import",
            "pub mod names {\n    pub use std::fmt::Debug as Shows;\n}\n",
            "use kr_other::names;\nuse names::Shows;\npub struct Leak(pub String);\nimpl Shows for Leak {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n    }\n}\n",
            6,
            "formats std::string::String",
        ),
        (
            "the Debug trait a glob in a block gives over a trait of the module's own",
            "pub mod names {\n    pub use std::fmt::Debug as Shows;\n}\n",
            "pub trait Shows {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;\n}\npub struct Leak(pub String);\nconst _: () = {\n    use kr_other::names::*;\n    impl Shows for Leak {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n            formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n        }\n    }\n};\n",
            9,
            "formats std::string::String",
        ),
        (
            "the Debug trait with empty generic arguments",
            "",
            "pub struct Leak(pub String);\nimpl std::fmt::Debug<> for Leak {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n    }\n}\n",
            4,
            "formats std::string::String",
        ),
        (
            "text under a type of the module's own named like a number",
            "",
            "#[allow(non_camel_case_types)]\ntype u8 = String;\n#[derive(Debug)]\npub struct Leak(pub u8);\n",
            3,
            "std::string::String",
        ),
        (
            "the Debug trait by a global path past a module named std",
            "",
            "mod std {\n    pub mod fmt {\n        pub trait Debug {}\n    }\n}\npub struct Leak(pub String);\nimpl ::std::fmt::Debug for Leak {\n    fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {\n        formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n    }\n}\n",
            9,
            "formats std::string::String",
        ),
        (
            "the Debug trait under a module a glob gives with the name of a crate",
            "pub mod shadow {\n    pub mod kr_client {\n        pub use std::fmt::Debug as debug_fields;\n    }\n}\n",
            "use kr_other::shadow::*;\npub struct Leak(pub String);\nimpl kr_client::debug_fields for Leak {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n    }\n}\n",
            5,
            "formats std::string::String",
        ),
        (
            "the Debug trait from around a glob that cannot give another crate's private trait",
            "pub mod hidden {\n    #[allow(dead_code)]\n    trait Debug {}\n    pub fn open() {}\n}\n",
            "use std::fmt::Debug;\npub struct Leak(pub String);\nconst _: () = {\n    use kr_other::hidden::*;\n    impl Debug for Leak {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n            formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n        }\n    }\n};\n",
            7,
            "formats std::string::String",
        ),
        (
            "the Debug trait from around a glob that cannot give a sibling module's private trait",
            "",
            "use std::fmt::Debug;\nmod hidden {\n    #[allow(dead_code)]\n    trait Debug {}\n    pub fn open() {}\n}\npub struct Leak(pub String);\nconst _: () = {\n    use hidden::*;\n    impl Debug for Leak {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n            formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n        }\n    }\n};\n",
            12,
            "formats std::string::String",
        ),
        (
            "a trait a glob in the same crate may or may not give",
            "",
            "use std::fmt::Debug;\nmod outer {\n    pub mod hidden {\n        #[allow(dead_code)]\n        pub(in super) trait Debug {}\n        pub fn open() {}\n    }\n}\npub struct Leak(pub String);\nconst _: () = {\n    use outer::hidden::*;\n    impl Debug for Leak {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n            formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n        }\n    }\n};\n",
            12,
            "a trait this reading cannot place",
        ),
        (
            "a trait whose first name only a glob from outside the workspace can give",
            "",
            "use somewhere::*;\npub struct Leak(pub String);\nimpl names::Shows for Leak {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n    }\n}\n",
            3,
            "a trait this reading cannot place",
        ),
        (
            "a macro only a glob from outside the workspace can give",
            "",
            "use somewhere::*;\npub struct Leak {\n    pub text: String,\n}\nfields!(Leak { text });\n",
            5,
            "a macro this reading does not read",
        ),
        (
            "a macro a glob from outside the workspace may give in place of the standard library's",
            "",
            "use somewhere::*;\npub fn said() -> String {\n    format!(\"{}\", 1)\n}\n",
            3,
            "a macro this reading cannot place",
        ),
        (
            "an alias's argument a glob from outside the workspace may give",
            "",
            "mod aliases {\n    pub type Identity<T> = T;\n}\nuse somewhere::*;\n#[derive(Debug)]\npub struct Leak(aliases::Identity<String>);\n",
            5,
            "an alias this reading cannot expand",
        ),
        (
            "a name that is a trait and a macro at once",
            "pub mod both {\n    pub trait Shows {\n        fn said(&self) -> u64 {\n            0\n        }\n    }\n    pub use kr_client::debug_fields as Shows;\n}\n",
            "use kr_other::both::Shows;\npub struct Leak {\n    pub text: String,\n}\nShows!(Leak { text });\n",
            5,
            "a macro this reading cannot place",
        ),
        (
            "a shown! of another crate in a Debug written by hand",
            "#[macro_export]\nmacro_rules! shown {\n    ($($any:tt)*) => {\n        ::std::format!($($any)*)\n    };\n}\n",
            "use kr_other::shown;\npub struct Leak(pub String);\nimpl std::fmt::Debug for Leak {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.write_str(shown!(\"{}\", self.0).as_str())\n    }\n}\n",
            5,
            "`shown`, a value this reading cannot place",
        ),
        (
            "a Debug from a debug_as_display! of another crate",
            "#[macro_export]\nmacro_rules! debug_as_display {\n    ($name:ident) => {\n        impl ::core::fmt::Debug for $name {\n            fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {\n                formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n            }\n        }\n    };\n}\n",
            "use kr_other::debug_as_display;\npub struct Leak(pub String);\ndebug_as_display!(Leak);\n#[derive(Debug)]\npub struct Holder(pub Leak);\n",
            4,
            "which carries a type whose Debug this reading cannot find",
        ),
        (
            "a macro of another crate of the workspace",
            "#[macro_export]\nmacro_rules! opaque_text {\n    ($name:ident) => {\n        #[derive(Debug)]\n        pub struct $name(pub String);\n    };\n}\n",
            "kr_other::opaque_text!(Leak);\n",
            1,
            "a macro this reading does not read",
        ),
        (
            "a macro from outside the workspace this reading does not list",
            "",
            "somewhere::declare!(Leak);\n",
            1,
            "a macro this reading does not read",
        ),
        (
            "an attribute macro from outside the workspace this reading does not list",
            "",
            "#[attr_debug::add_debug]\npub struct Leak(pub String);\n",
            1,
            "an attribute this reading does not read",
        ),
        (
            "an attribute macro under cfg_attr",
            "",
            "#[cfg_attr(all(), attr_debug::add_debug)]\npub struct Leak(pub String);\n",
            1,
            "an attribute this reading does not read",
        ),
        (
            "a derive of another crate under the name of one of the prelude's",
            "",
            "use attr_debug::Clone;\n#[derive(Clone)]\npub struct Leak(pub String);\n",
            2,
            "a derive this reading does not read",
        ),
        (
            "the standard library's Debug derive under a name a re-export gives it",
            "pub use std::fmt::Debug as Show;\n",
            "use kr_other::Show;\n#[derive(Show)]\npub struct Leak(pub String);\n",
            2,
            "a derived Debug over text that arrived",
        ),
        (
            "the Display trait under the name Debug, whose fmt a Debug written by hand calls",
            "pub struct Secret(pub String);\nimpl std::fmt::Debug for Secret {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.write_str(\"Secret\")\n    }\n}\nimpl std::fmt::Display for Secret {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.write_str(&self.0)\n    }\n}\npub use std::fmt::Display as Debug;\n",
            "use kr_other::Debug;\npub struct Leak(pub kr_other::Secret);\nimpl std::fmt::Debug for Leak {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        Debug::fmt(&self.0, formatter)\n    }\n}\n",
            5,
            "the Display of kr_other::Secret",
        ),
        (
            "an attribute macro under a module named like a tool",
            "",
            "mod rustfmt {\n    pub use attr_debug::add_debug as skip;\n}\n#[rustfmt::skip]\npub struct Leak(pub String);\n",
            4,
            "an attribute this reading does not read",
        ),
        (
            "a type another crate declares with a macro its module's own macro does not stand for",
            "mod quiet {\n    #[allow(unused_macros)]\n    macro_rules! declare {\n        ($name:ident) => {\n            #[derive(Debug)]\n            pub struct $name(pub u64);\n        };\n    }\n}\nuse somewhere::declare;\ndeclare!(Opaque);\n",
            "#[derive(Debug)]\npub struct Leak(pub kr_other::Opaque);\n",
            1,
            "a derived Debug over text that arrived",
        ),
        (
            "a type another crate declares with a macro before its own macro of that name is written",
            "use somewhere::declare;\ndeclare!(Opaque);\n#[allow(unused_macros)]\nmacro_rules! declare {\n    ($name:ident) => {\n        #[derive(Debug)]\n        pub struct $name(pub u64);\n    };\n}\n",
            "#[derive(Debug)]\npub struct Leak(pub kr_other::Opaque);\n",
            1,
            "a derived Debug over text that arrived",
        ),
        (
            "a type defined once for each platform, the second of which holds text",
            "",
            "#[cfg(not(unix))]\n#[derive(Debug)]\npub struct Leak(pub u64);\n#[cfg(unix)]\n#[derive(Debug)]\npub struct Leak(pub String);\n",
            5,
            "std::string::String",
        ),
        (
            "an alias defined once for each platform, the first of which is text",
            "",
            "#[cfg(unix)]\ntype Raw = String;\n#[cfg(not(unix))]\ntype Raw = u64;\n#[derive(Debug)]\npub struct Leak(pub Raw);\n",
            5,
            "std::string::String",
        ),
        (
            "a type another crate declares with a macro written once for each platform",
            "#[cfg(unix)]\nmacro_rules! declare {\n    ($name:ident) => {\n        #[derive(Debug)]\n        pub struct $name(pub String);\n    };\n}\n#[cfg(not(unix))]\nmacro_rules! declare {\n    ($name:ident) => {\n        #[derive(Debug)]\n        pub struct $name(pub u64);\n    };\n}\ndeclare!(Opaque);\n",
            "#[derive(Debug)]\npub struct Leak(pub kr_other::Opaque);\n",
            1,
            "a derived Debug over text that arrived",
        ),
        (
            "a type another crate defines as a struct on one platform and an alias on another",
            "#[cfg(unix)]\n#[derive(Debug)]\npub struct Platform(pub String);\n#[cfg(not(unix))]\npub type Platform = u64;\n",
            "#[derive(Debug)]\npub struct Leak(pub kr_other::Platform);\n",
            1,
            "a derived Debug over text that arrived",
        ),
        (
            "a name one module path gives once for each platform",
            "#[cfg(not(unix))]\npub mod platform {\n    pub use std::time::Duration as Handle;\n}\n#[cfg(unix)]\npub mod platform {\n    pub use std::string::String as Handle;\n}\n",
            "#[derive(Debug)]\npub struct Leak(pub kr_other::platform::Handle);\n",
            1,
            "a derived Debug over text that arrived",
        ),
        (
            "a field defined once for each platform, read by a Debug written by hand",
            "",
            "pub struct Leak {\n    #[cfg(not(unix))]\n    pub text: u64,\n    #[cfg(unix)]\n    pub text: String,\n}\nimpl std::fmt::Debug for Leak {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_struct(\"Leak\").field(\"text\", &self.text).finish()\n    }\n}\n",
            9,
            "more than one definition",
        ),
        (
            "a variant defined once for each platform, matched by a Debug written by hand",
            "",
            "pub enum Leak {\n    #[cfg(not(unix))]\n    Said(u64),\n    #[cfg(unix)]\n    Said(String),\n}\nimpl std::fmt::Debug for Leak {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        match self {\n            Self::Said(said) => formatter.debug_tuple(\"Said\").field(said).finish(),\n        }\n    }\n}\n",
            10,
            "a value this reading cannot place",
        ),
        (
            "a trait a glob gives on one platform only, past which the outer name is the Debug trait",
            "pub mod names {\n    #[cfg(unix)]\n    #[allow(dead_code)]\n    trait Debug {}\n    #[cfg(not(unix))]\n    pub trait Debug {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;\n    }\n    pub fn open() {}\n}\n",
            "use std::fmt::Debug;\npub struct Leak(pub String);\nconst _: () = {\n    use kr_other::names::*;\n    impl Debug for Leak {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n            formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n        }\n    }\n};\n",
            5,
            "a trait this reading cannot place",
        ),
        (
            "a type another crate derives Debug for on one platform and writes it by hand for on another",
            "#[cfg_attr(not(unix), derive(Debug))]\npub struct Code(pub u64);\n#[cfg(unix)]\nimpl std::fmt::Debug for Code {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.write_str(&::std::format!(\"{}\", \"SECRET\"))\n    }\n}\n",
            "#[derive(Debug)]\npub struct Leak(pub kr_other::Code);\n",
            1,
            "a derived Debug over text that arrived",
        ),
        (
            "a trait one module path makes private on one platform and public on another",
            "#[cfg(unix)]\npub mod names {\n    #[allow(dead_code)]\n    trait Debug {}\n    pub fn open() {}\n}\n#[cfg(not(unix))]\npub mod names {\n    pub trait Debug {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;\n    }\n    pub fn open() {}\n}\n",
            "use std::fmt::Debug;\npub struct Leak(pub String);\nconst _: () = {\n    use kr_other::names::*;\n    impl Debug for Leak {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n            formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n        }\n    }\n};\n",
            5,
            "a trait this reading cannot place",
        ),
        (
            "a tuple position a field under cfg moves",
            "",
            "pub struct Leak(#[cfg(not(unix))] pub u64, #[cfg(unix)] pub String);\nimpl std::fmt::Debug for Leak {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n    }\n}\n",
            4,
            "a position cfg can move",
        ),
        (
            "a variant's position a field under cfg moves",
            "",
            "pub enum Leak {\n    Said(#[cfg(not(unix))] u64, #[cfg(unix)] String),\n}\nimpl std::fmt::Debug for Leak {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        match self {\n            Self::Said(said) => formatter.debug_tuple(\"Said\").field(said).finish(),\n        }\n    }\n}\n",
            7,
            "a value this reading cannot place",
        ),
        (
            "a trait a glob gives only under some conditions, past which the outer name is the Debug trait",
            "pub mod names {\n    #[cfg(not(unix))]\n    pub trait Debug {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;\n    }\n    pub fn open() {}\n}\n",
            "use std::fmt::Debug;\npub struct Leak(pub String);\nconst _: () = {\n    use kr_other::names::*;\n    impl Debug for Leak {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n            formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n        }\n    }\n};\n",
            5,
            "a trait this reading cannot place",
        ),
        (
            "an import in force only under some conditions, past which the outer name is the Debug trait",
            "pub mod names {\n    pub trait Debug {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;\n    }\n}\n",
            "use std::fmt::Debug;\npub struct Leak(pub String);\nconst _: () = {\n    #[cfg(not(unix))]\n    use kr_other::names::Debug;\n    impl Debug for Leak {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n            formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n        }\n    }\n};\n",
            6,
            "a trait this reading cannot place",
        ),
        (
            "a type defined only under some conditions over one a glob gives",
            "pub type Handle = String;\n",
            "use kr_other::*;\n#[cfg(not(unix))]\n#[derive(Debug)]\npub struct Handle(pub u64);\n#[derive(Debug)]\npub struct Leak(pub Handle);\n",
            5,
            "a derived Debug over text that arrived",
        ),
        (
            "a variant a glob gives under some conditions only, past which the outer name is the Debug trait",
            "",
            "use std::fmt::Debug;\npub enum Names {\n    #[cfg(not(unix))]\n    Debug,\n}\npub struct Leak(pub String);\nconst _: () = {\n    use self::Names::*;\n    #[cfg(unix)]\n    impl Debug for Leak {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n            formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n        }\n    }\n};\n",
            10,
            "a trait this reading cannot place",
        ),
        (
            "an alias a cfg under cfg_attr can leave out, past which a glob gives text",
            "pub mod values {\n    pub type Handle = String;\n}\npub mod names {\n    pub use super::values::*;\n    #[cfg_attr(unix, cfg(not(unix)))]\n    pub type Handle = u64;\n}\n",
            "#[derive(Debug)]\npub struct Leak(pub kr_other::names::Handle);\n",
            1,
            "a derived Debug over text that arrived",
        ),
        (
            "a binding in a Debug written by hand a cfg can leave out",
            "",
            "pub struct Leak(pub String);\nimpl std::fmt::Debug for Leak {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        let value = &self.0;\n        #[cfg(not(unix))]\n        let value: u64 = 0;\n        formatter.debug_tuple(\"Leak\").field(&value).finish()\n    }\n}\n",
            7,
            "a value this reading cannot place",
        ),
        (
            "a binding a macro in another crate's Debug written by hand gives the name again",
            "macro_rules! shadow {\n    ($name:ident, $value:expr) => {\n        let $name = $value;\n    };\n}\npub struct Secret(pub u64, pub String);\nimpl std::fmt::Debug for Secret {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        let value = &self.0;\n        shadow!(value, &self.1);\n        formatter.debug_tuple(\"Secret\").field(value).finish()\n    }\n}\n",
            "#[derive(Debug)]\npub struct Leak(pub kr_other::Secret);\n",
            1,
            "a derived Debug over text that arrived",
        ),
        (
            "an alias a cfg(test) under cfg_attr leaves out on one platform, past which a glob gives text",
            "pub mod values {\n    pub type Handle = String;\n}\npub mod names {\n    pub use super::values::*;\n    #[cfg_attr(unix, cfg(test))]\n    pub type Handle = u64;\n}\n",
            "#[derive(Debug)]\npub struct Leak(pub kr_other::names::Handle);\n",
            1,
            "a derived Debug over text that arrived",
        ),
        (
            "a module a cfg inside it leaves out, past which the outer name is the Debug trait",
            "pub mod names {\n    #![cfg(not(unix))]\n    pub trait Shows {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;\n    }\n}\n",
            "mod names {\n    pub use std::fmt::Debug as Shows;\n}\npub struct Leak(pub String);\nconst _: () = {\n    use kr_other::*;\n    impl names::Shows for Leak {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n            formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n        }\n    }\n};\n",
            7,
            "a trait this reading cannot place",
        ),
        (
            "a macro a glob gives under the Debug trait's name, where the compiler looks for a trait",
            "#[macro_export]\nmacro_rules! Debug {\n    () => {};\n}\n",
            "use std::fmt::Debug;\npub struct Leak(pub String);\nconst _: () = {\n    use kr_other::*;\n    impl Debug for Leak {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n            formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n        }\n    }\n};\n",
            7,
            "formats std::string::String",
        ),
        (
            "a macro exported under some conditions only, which a glob gives under the Debug trait's name",
            "#[cfg_attr(not(unix), macro_export)]\nmacro_rules! Debug {\n    () => {};\n}\n",
            "use std::fmt::Debug;\npub struct Leak(pub String);\nconst _: () = {\n    use kr_other::*;\n    #[cfg(unix)]\n    impl Debug for Leak {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n            formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n        }\n    }\n};\n",
            8,
            "formats std::string::String",
        ),
        (
            "a module a cfg(test) inside it leaves out, past which the outer name is the Debug trait",
            "pub mod names {\n    #![cfg(test)]\n    pub trait Shows {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;\n    }\n}\n",
            "mod names {\n    pub use std::fmt::Debug as Shows;\n}\npub struct Leak(pub String);\nconst _: () = {\n    use kr_other::*;\n    impl names::Shows for Leak {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n            formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n        }\n    }\n};\n",
            7,
            "a trait this reading cannot place",
        ),
        (
            "a Debug written by hand with one fmt for each platform, the second of which formats text",
            "",
            "pub struct Leak(pub String);\nimpl std::fmt::Debug for Leak {\n    #[cfg(not(unix))]\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.write_str(\"safe\")\n    }\n    #[cfg(unix)]\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n    }\n}\n",
            9,
            "formats std::string::String",
        ),
        (
            "an extern crate",
            "",
            "extern crate kr_other;\n",
            1,
            "an extern crate",
        ),
        (
            "a glob that gives Debug to a macro of the standard library, past which the outer name is the Debug trait",
            "pub use std::line as Debug;\n",
            "use std::fmt::Debug;\npub struct Leak(pub String);\nconst _: () = {\n    use kr_other::*;\n    impl Debug for Leak {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n            formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n        }\n    }\n};\n",
            4,
            "only the standard library's Debug may carry the name Debug",
        ),
        (
            "a glob that gives Debug to a function of the standard library, past which the outer name is the Debug trait",
            "pub use std::mem::drop as Debug;\n",
            "use std::fmt::Debug;\npub struct Leak(pub String);\nconst _: () = {\n    use kr_other::*;\n    impl Debug for Leak {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n            formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n        }\n    }\n};\n",
            4,
            "only the standard library's Debug may carry the name Debug",
        ),
        (
            "an import of another crate's Debug, whose trait a cfg can leave out, past which the outer name is the Debug trait",
            "#[cfg(not(unix))]\npub trait Debug {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;\n}\n#[macro_export]\nmacro_rules! Debug {\n    () => {};\n}\n",
            "use std::fmt::Debug;\npub struct Leak(pub String);\nconst _: () = {\n    use kr_other::Debug;\n    #[cfg(unix)]\n    impl Debug for Leak {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n            formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n        }\n    }\n};\n",
            4,
            "only the standard library's Debug may carry the name Debug",
        ),
        (
            "an import renamed to Debug",
            "pub trait Shows {}\n",
            "#[allow(unused_imports)]\nuse kr_other::Shows as Debug;\n",
            2,
            "only the standard library's Debug may carry the name Debug",
        ),
        (
            "a glob of an enum's variants, one of which is named Debug",
            "",
            "pub enum Level {\n    Debug,\n    Info,\n}\n#[allow(unused_imports)]\nuse Level::*;\n",
            6,
            "only the standard library's Debug may carry the name Debug",
        ),
        (
            "a trait of the crate's own named Debug",
            "",
            "pub trait Debug {}\n",
            1,
            "only the standard library's Debug may carry the name Debug",
        ),
        (
            "a trait named Debug under a module of the crate's own named std",
            "",
            "mod std {\n    pub mod fmt {\n        pub trait Debug {\n            fn fmt(&self) -> u64;\n        }\n    }\n}\npub struct Leak(pub String);\nimpl std::fmt::Debug for Leak {\n    fn fmt(&self) -> u64 {\n        0\n    }\n}\n",
            3,
            "only the standard library's Debug may carry the name Debug",
        ),
        (
            "a macro of the crate's own named Debug",
            "",
            "#[allow(unused_macros)]\nmacro_rules! Debug {\n    () => {};\n}\n",
            2,
            "only the standard library's Debug may carry the name Debug",
        ),
        (
            "a function of the crate's own named Debug",
            "",
            "#[allow(non_snake_case)]\npub fn Debug() {}\n",
            2,
            "only the standard library's Debug may carry the name Debug",
        ),
        (
            "a mutable static of the crate's own named Debug",
            "",
            "#[allow(non_upper_case_globals)]\npub static mut Debug: u64 = 0;\n",
            2,
            "only the standard library's Debug may carry the name Debug",
        ),
    ];
    let missed: Vec<String> = cases
        .iter()
        .enumerate()
        .filter_map(|(position, (class, other, text, line, what))| {
            let findings = debug_findings_in(&format!("debug-name-{position}"), text, other);
            (!findings
                .iter()
                .any(|finding| finding.line == *line && finding.what.contains(what)))
            .then(|| {
                format!(
                    "{class}: expected a finding at line {line} saying {what:?}, found {findings:?}"
                )
            })
        })
        .collect();
    assert!(missed.is_empty(), "{}", missed.join("\n"));
}

/// A name the compiler places on another item is not named: the same shapes, where the name is a
/// trait that is not `Debug`, and the macros from outside the library the two crates use.
#[test]
fn names_the_compiler_places_elsewhere_are_not_named() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "a trait imported by name beside a glob that gives the Debug trait under its name",
            "pub trait Shows {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;\n}\npub mod names {\n    pub use std::fmt::Debug as Shows;\n}\n",
            "use kr_other::Shows;\nuse kr_other::names::*;\npub struct Leak(pub String);\nimpl Shows for Leak {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n    }\n}\n",
        ),
        (
            "a trait under a path whose first name a glob gives, which is not the Debug trait",
            "pub mod names {\n    pub trait Shows {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;\n    }\n}\npub mod exports {\n    pub use super::names;\n}\n",
            "use kr_other::exports::*;\npub struct Leak(pub String);\nimpl names::Shows for Leak {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n    }\n}\n",
        ),
        (
            "a trait around a glob that cannot give another crate's private import of the Debug trait",
            "pub trait Shows {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;\n}\npub mod hidden {\n    #[allow(unused_imports)]\n    use std::fmt::Debug as Shows;\n    pub fn open() {}\n}\n",
            "use kr_other::Shows;\npub struct Leak(pub String);\nconst _: () = {\n    use kr_other::hidden::*;\n    impl Shows for Leak {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n            formatter.debug_tuple(\"Leak\").field(&self.0).finish()\n        }\n    }\n};\n",
        ),
        (
            "the attributes and derives the two crates use",
            "",
            "#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]\n#[must_use]\n#[non_exhaustive]\npub struct Counted {\n    #[doc = \"a count\"]\n    pub count: u64,\n}\n#[derive(serde::Serialize, serde::Deserialize)]\n#[serde(rename_all = \"snake_case\")]\npub struct Wire {\n    #[serde(default)]\n    pub count: u64,\n}\n#[cfg_attr(unix, must_use)]\n#[rustfmt::skip]\npub struct Kept(pub u64);\n",
        ),
        (
            "a trait from outside the workspace this reading lists",
            "",
            "pub struct Service;\nimpl rmcp::ServerHandler for Service {}\n",
        ),
        (
            "the macros the two crates use from outside the library",
            "",
            "pub fn used() -> usize {\n    let value = serde_json::json!(null);\n    let pinned = std::pin::pin!(async {});\n    let _ = pinned;\n    let _ = format!(\"{}\", 1);\n    vec![value].len()\n}\n",
        ),
        (
            "the standard library's Debug under its own name, by an import, a derive and a Debug written by hand",
            "",
            "use std::fmt::{self, Debug};\n#[derive(Debug)]\npub struct Counted(pub u64);\npub struct Named(pub u64);\nimpl Debug for Named {\n    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {\n        formatter.debug_tuple(\"Named\").field(&self.0).finish()\n    }\n}\n",
        ),
        (
            "a glob and an import that give the standard library's Debug under its own name",
            "pub mod names {\n    pub use std::fmt::Debug;\n}\npub use core::fmt::Debug;\n",
            "use kr_other::Debug;\npub struct Counted(pub u64);\nconst _: () = {\n    use kr_other::names::*;\n    impl Debug for Counted {\n        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n            formatter.debug_tuple(\"Counted\").field(&self.0).finish()\n        }\n    }\n};\n",
        ),
        (
            "a glob of the standard library's formatting module, which gives its own Debug",
            "",
            "pub struct Counted(pub u64);\nconst _: () = {\n    use std::fmt::*;\n};\n",
        ),
    ];
    let named: Vec<String> = cases
        .iter()
        .enumerate()
        .filter_map(|(position, (class, other, text))| {
            let findings = debug_findings_in(&format!("debug-elsewhere-{position}"), text, other);
            (!findings.is_empty()).then(|| format!("{class}: {findings:?}"))
        })
        .collect();
    assert!(named.is_empty(), "{}", named.join("\n"));
}

/// A module whose file a `#[path]` names is not read at its default place, where another file can
/// stand: what the module holds is unknown to this reading, so a type it gives carries.
#[test]
fn a_module_a_path_moves_is_not_read_at_its_default_place() {
    let findings = debug_findings_among(
        "debug-path",
        "#[derive(Debug)]\npub struct Leak(pub kr_other::net::Handle);\n",
        "#[path = \"real.rs\"]\npub mod net;\n",
        &[
            ("crates/kr-other/src/real.rs", "pub type Handle = String;\n"),
            ("crates/kr-other/src/net.rs", "pub type Handle = u64;\n"),
        ],
    );
    assert!(
        findings.iter().any(|finding| finding.line == 1
            && finding
                .what
                .contains("a derived Debug over text that arrived")),
        "{findings:?}"
    );
}

/// A crate whose root a `cfg` this reading cannot decide can leave empty is there with nothing in
/// it, so a glob of it gives no name for certain: where the scopes around the glob give the name
/// another item, the name is not placed. A crate no such `cfg` can empty gives its names as ever.
#[test]
fn a_glob_of_a_crate_a_cfg_can_empty_decides_no_name() {
    fn library(root: &str) -> [(&'static str, &str); 2] {
        [
            (
                "crates/kr-client/Cargo.toml",
                "[package]\nname = \"kr-client\"\n",
            ),
            ("crates/kr-client/src/lib.rs", root),
        ]
    }
    let shown =
        "#[macro_export]\nmacro_rules! shown {\n    ($($any:tt)*) => {\n        ()\n    };\n}\n";
    let emptied = format!("#![cfg(not(unix))]\n{shown}");
    let findings = debug_findings_among(
        "debug-emptied",
        "use kr_other::shown;\npub struct Leak(pub String);\nconst _: () = {\n    use kr_client::*;\n    shown!(\"leak.rs\")\n};\n",
        "pub use std::include as shown;\n",
        &library(&emptied),
    );
    assert!(
        findings.iter().any(|finding| finding.line == 5
            && finding.what.contains("a macro this reading cannot place")),
        "{findings:?}"
    );
    let findings = debug_findings_among(
        "debug-certain",
        "pub struct Held(pub u64);\nconst _: () = {\n    use kr_client::*;\n    shown!(\"leak.rs\")\n};\n",
        "",
        &library(shown),
    );
    assert!(findings.is_empty(), "{findings:?}");
}
