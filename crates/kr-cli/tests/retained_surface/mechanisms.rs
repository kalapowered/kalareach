//! The mechanism table: one fixture for each way Rust can give a name to another name, to a macro
//! or to a place, with the exact sightings the scan gives it or the exact text it refuses it with.
//! The scan never decides what a name stands for, so a mechanism is read by its names wherever
//! they stand, refused, or a stated limit that the fixture shows (a name the scan cannot join from
//! pieces); the table shows which, and a new variant of [`Mechanism`] is a compile error until the
//! table holds a fixture for it.

use super::walker_cases::{small_tree, tree_at, write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mechanism {
    Direct,
    Rename,
    Glob,
    Reexport,
    TypeAlias,
    RequestAlias,
    SelfBrace,
    QualifiedPath,
    ImportedVariant,
    ExternCrateRename,
    CargoRename,
    TextualMacro,
    ExportedMacro,
    MacroUseModule,
    MacroUseExternCrate,
    FunctionBodyMacro,
    TranscriberMacro,
    MetavariableCallee,
    MetavariableVariant,
    MetavariableType,
    ExternalMacroListed,
    ExternalMacroUnlisted,
    Escape,
    LongerLiteral,
    Concat,
    Include,
    CfgOnItem,
    CfgOnStatement,
    CfgOnImplItem,
    CfgOnModule,
    CfgInner,
    CfgAttrPath,
    CfgAttrOther,
    PathAttribute,
    ParentPath,
    Link,
    ActionRightDefinition,
}

/// The mechanism after `mechanism`, with an arm for each one: the table is walked by this, so a
/// variant that is not here does not compile.
fn next(mechanism: Mechanism) -> Option<Mechanism> {
    use Mechanism::*;
    match mechanism {
        Direct => Some(Rename),
        Rename => Some(Glob),
        Glob => Some(Reexport),
        Reexport => Some(TypeAlias),
        TypeAlias => Some(RequestAlias),
        RequestAlias => Some(SelfBrace),
        SelfBrace => Some(QualifiedPath),
        QualifiedPath => Some(ImportedVariant),
        ImportedVariant => Some(ExternCrateRename),
        ExternCrateRename => Some(CargoRename),
        CargoRename => Some(TextualMacro),
        TextualMacro => Some(ExportedMacro),
        ExportedMacro => Some(MacroUseModule),
        MacroUseModule => Some(MacroUseExternCrate),
        MacroUseExternCrate => Some(FunctionBodyMacro),
        FunctionBodyMacro => Some(TranscriberMacro),
        TranscriberMacro => Some(MetavariableCallee),
        MetavariableCallee => Some(MetavariableVariant),
        MetavariableVariant => Some(MetavariableType),
        MetavariableType => Some(ExternalMacroListed),
        ExternalMacroListed => Some(ExternalMacroUnlisted),
        ExternalMacroUnlisted => Some(Escape),
        Escape => Some(LongerLiteral),
        LongerLiteral => Some(Concat),
        Concat => Some(Include),
        Include => Some(CfgOnItem),
        CfgOnItem => Some(CfgOnStatement),
        CfgOnStatement => Some(CfgOnImplItem),
        CfgOnImplItem => Some(CfgOnModule),
        CfgOnModule => Some(CfgInner),
        CfgInner => Some(CfgAttrPath),
        CfgAttrPath => Some(CfgAttrOther),
        CfgAttrOther => Some(PathAttribute),
        PathAttribute => Some(ParentPath),
        ParentPath => Some(Link),
        Link => Some(ActionRightDefinition),
        ActionRightDefinition => None,
    }
}

/// What the scan of the crate gives: the sightings as `name:kinds` in order, or the refusal.
enum Expect {
    Sightings(&'static [&'static str]),
    Refused(&'static str),
}

struct Fixture {
    /// The library of the crate the scan reads.
    lib: &'static str,
    /// Other files of the crate, by their path below `crates/kr-sender/`.
    files: &'static [(&'static str, &'static str)],
    expect: Expect,
}

const PROTOCOL_DEPENDENCY: &str = "[package]\nname = \"kr-sender\"\nversion = \"0.0.0\"\n\n[dependencies]\nproto = { package = \"kr-protocol\", path = \"../kr-protocol\" }\n";

fn fixture(mechanism: Mechanism) -> Fixture {
    use Expect::{Refused, Sightings};
    use Mechanism::*;
    let one = |lib, expect| Fixture {
        lib,
        files: &[],
        expect,
    };
    match mechanism {
        Direct => one(
            "pub fn f() { let _ = Method::AgentTurnCancel; }\n",
            Sightings(&["f:Names"]),
        ),
        Rename => one(
            "use kr_protocol::Method as M;\npub fn f() { let _ = M::AgentTurnCancel; }\n",
            Refused(
                "crates/kr-sender/src/lib.rs: the scan does not read Method under another name (as M)",
            ),
        ),
        Glob => one(
            "use kr_protocol::Method::*;\npub fn f() { let _ = AgentTurnCancel; }\n",
            Sightings(&["f:Names"]),
        ),
        Reexport => one(
            "pub use kr_protocol::Method;\npub fn f() { let _ = crate::Method::AgentTurnCancel; }\n",
            Sightings(&["f:Names"]),
        ),
        TypeAlias => one(
            "type M = Method;\npub fn f() { let _ = M::AgentTurnCancel; }\n",
            Sightings(&["f:Names"]),
        ),
        RequestAlias => one(
            "type R = MutationRequest;\n",
            Refused(
                "crates/kr-sender/src/lib.rs: the scan does not read a type alias of MutationRequest (R)",
            ),
        ),
        SelfBrace => one(
            "impl MutationRequest { pub fn make() -> Self { Self { x: 1 } } }\n",
            Sightings(&["MutationRequest::make:Request"]),
        ),
        QualifiedPath => one(
            "pub fn f() { let _ = <Method>::AgentTurnCancel; }\n",
            Sightings(&["f:Names"]),
        ),
        // An over-read: the `use` that names a variant is a sighting of its own.
        ImportedVariant => one(
            "use kr_protocol::Method::AgentTurnCancel;\npub fn f() { let _ = AgentTurnCancel; }\n",
            Sightings(&["f:Names", "use:lib.rs:Names"]),
        ),
        ExternCrateRename => one(
            "extern crate core as Method;\n",
            Refused(
                "crates/kr-sender/src/lib.rs: the scan does not read core under another name (as Method)",
            ),
        ),
        CargoRename => Fixture {
            lib: "pub fn f() { let _ = proto::Method::AgentTurnCancel; }\n",
            files: &[("Cargo.toml", PROTOCOL_DEPENDENCY)],
            expect: Sightings(&["f:Names"]),
        },
        TextualMacro => one(
            "macro_rules! m { () => { Method::AgentTurnCancel }; }\npub fn f() { m!(); }\n",
            Sightings(&["macro:m:Names"]),
        ),
        ExportedMacro => one(
            "#[macro_export]\nmacro_rules! m { () => { Method::AgentTurnCancel }; }\npub fn f() { crate::m!(); }\n",
            Sightings(&["macro:m:Names"]),
        ),
        MacroUseModule => Fixture {
            lib: "#[macro_use]\nmod inner;\npub fn f() { m!(); }\n",
            files: &[(
                "src/inner.rs",
                "macro_rules! m { () => { Method::AgentTurnCancel }; }\n",
            )],
            expect: Sightings(&["macro:m:Names"]),
        },
        MacroUseExternCrate => one(
            "#[macro_use]\nextern crate core;\n",
            Refused(
                "crates/kr-sender/src/lib.rs: the scan does not read #[macro_use] on extern crate",
            ),
        ),
        FunctionBodyMacro => one(
            "pub fn f() { macro_rules! n { () => { Method::AgentTurnCancel }; }\n n!(); }\n",
            Sightings(&["f:Names"]),
        ),
        TranscriberMacro => one(
            "macro_rules! outer { () => { macro_rules! inner { () => {}; } }; }\npub fn f() { outer!(); }\n",
            Refused(
                "crates/kr-sender/src/lib.rs: the scan does not read a macro_rules! written in the tokens of another macro (macro_rules! inner in the tokens of macro_rules!)",
            ),
        ),
        MetavariableCallee => one(
            "macro_rules! meta { ($m:ident) => { $m!(Method::AgentTurnCancel) }; }\nfn uses() { meta!(Method::AgentTurnCancel); }\n",
            Refused(
                "kr_sender: the macro meta calls a macro through a metavariable, which the scan cannot follow",
            ),
        ),
        MetavariableVariant => one(
            "macro_rules! pick { ($v:ident) => { Method::$v }; }\npub fn f() { let _ = pick!(AgentTurnCancel); }\n",
            Sightings(&["f:Names", "macro:pick:Expands"]),
        ),
        // A type name in a macro's arguments is a sighting where it is written (S3), and marks the
        // macro, whose transcriber may write the brace group.
        MetavariableType => one(
            "macro_rules! make { ($t:ident) => { $t { x: 1 } }; }\npub fn f() { let _ = make!(MutationRequest); }\n",
            Sightings(&["f:Request", "macro:make:Expands"]),
        ),
        ExternalMacroListed => one("tokio::task_local! { static X: u8; }\n", Sightings(&[])),
        ExternalMacroUnlisted => one(
            "other::thing! { }\n",
            Refused(
                "crates/kr-sender/src/lib.rs: other::thing! is called at item position and is not written as one of the macros the scan accepts",
            ),
        ),
        Escape => one(
            "pub fn f() { let _ = \"agent\\x2eturn.cancel\"; }\n",
            Sightings(&["f:Names"]),
        ),
        LongerLiteral => one(
            "pub fn f() { let _ = \"the agent.turn.cancel method\"; }\n",
            Sightings(&["f:Names"]),
        ),
        // A limit the request states: each literal is read alone, so a wire name that `concat!` joins
        // from pieces is not seen (no site at the head or at a tag, and the gate's oracle reads alike).
        Concat => one(
            "pub fn f() { let _ = concat!(\"agent.turn.\", \"cancel\"); }\n",
            Sightings(&[]),
        ),
        Include => Fixture {
            lib: "include!(\"more.rs\");\n",
            files: &[(
                "src/more.rs",
                "pub fn g() { let _ = Method::AgentTurnCancel; }\n",
            )],
            expect: Refused("crates/kr-sender/src/lib.rs: the scan does not read include!"),
        },
        CfgOnItem => one(
            "#[cfg(test)]\nfn t() { let _ = Method::AgentTurnCancel; }\npub fn f() {}\n",
            Sightings(&[]),
        ),
        // An over-read: only a place that is an item is left out, so a statement under a false
        // `cfg` stays part of its function.
        CfgOnStatement => one(
            "pub fn f() { #[cfg(test)] let _ = Method::AgentTurnCancel; }\n",
            Sightings(&["f:Names"]),
        ),
        CfgOnImplItem => one(
            "pub struct S;\nimpl S { #[cfg(test)] fn t() { let _ = Method::AgentTurnCancel; } pub fn g() {} }\n",
            Sightings(&[]),
        ),
        CfgOnModule => one(
            "#[cfg(test)]\nmod tests { fn t() { let _ = Method::AgentTurnCancel; } }\n",
            Sightings(&[]),
        ),
        CfgInner => Fixture {
            lib: "mod inner;\n",
            files: &[(
                "src/inner.rs",
                "#![cfg(test)]\nfn t() { let _ = Method::AgentTurnCancel; }\n",
            )],
            expect: Sightings(&[]),
        },
        CfgAttrPath => one(
            "#[cfg_attr(unix, path = \"x.rs\")]\nmod m;\n",
            Refused(
                "crates/kr-sender/src/lib.rs: the scan does not read a cfg_attr that sets a path (# [cfg_attr (unix , path = \"x.rs\")])",
            ),
        ),
        CfgAttrOther => one(
            "#[cfg_attr(unix, derive(Debug))]\npub struct S;\npub fn f() { let _ = Method::AgentTurnCancel; }\n",
            Sightings(&["f:Names"]),
        ),
        PathAttribute => Fixture {
            lib: "#[path = \"other.rs\"]\nmod m;\n",
            files: &[(
                "src/other.rs",
                "pub fn g() { let _ = Method::AgentTurnCancel; }\n",
            )],
            expect: Sightings(&["g:Names"]),
        },
        ParentPath => one(
            "#[path = \"../outside.rs\"]\nmod m;\n",
            Refused(
                "crates/kr-sender/src/lib.rs: the scan does not read a path through a link, with .. or from the root of the file system (it is ../outside.rs)",
            ),
        ),
        // A link needs the file system to make one: the case makes it, on a system that has them.
        Link => Fixture {
            lib: "#[path = \"linked.rs\"]\nmod m;\n",
            files: &[(
                "src/real.rs",
                "pub fn g() { let _ = Method::AgentTurnCancel; }\n",
            )],
            expect: Refused(
                "crates/kr-sender/src/lib.rs: the scan does not read a path through a link, with .. or from the root of the file system (<root>/crates/kr-sender/src/linked.rs is a link)",
            ),
        },
        // A crate that defines the name `ActionRight` hides which type `ActionRight::<Variant>` is.
        ActionRightDefinition => one(
            "type ActionRight = kr_protocol::method::Method;\npub fn f() { let _ = ActionRight::AgentTurnCancel; }\n",
            Refused(
                "crates/kr-sender/src/lib.rs: the scan does not read a type alias named ActionRight",
            ),
        ),
    }
}

/// The sightings of the crate as `name:kinds`, or the refusal.
fn scan(mechanism: Mechanism, fixture: &Fixture) -> Result<Vec<String>, String> {
    let folder = small_tree(fixture.lib);
    for (path, text) in fixture.files {
        write(folder.path(), &format!("crates/kr-sender/{path}"), text);
    }
    #[cfg(unix)]
    if mechanism == Mechanism::Link {
        std::os::unix::fs::symlink(
            folder.path().join("crates/kr-sender/src/real.rs"),
            folder.path().join("crates/kr-sender/src/linked.rs"),
        )
        .expect("a link");
    }
    let root = std::fs::canonicalize(folder.path())
        .expect("a folder")
        .to_string_lossy()
        .into_owned();
    let hide = |text: String| text.replace(&root, "<root>");
    let tree = tree_at(folder.path()).map_err(hide)?;
    tree.sightings(&|krate| krate == "kr_sender")
        .map_err(hide)
        .map(|found| {
            found
                .into_iter()
                .map(|sighting| {
                    let kinds: Vec<String> =
                        sighting.kinds.iter().map(|k| format!("{k:?}")).collect();
                    format!("{}:{}", sighting.name, kinds.join(","))
                })
                .collect()
        })
}

#[test]
fn each_way_rust_can_bind_a_name_is_read_by_its_names_or_refused_with_a_text_of_its_own() {
    let mut mismatches = Vec::new();
    let mut at = Some(Mechanism::Direct);
    let mut count = 0;
    while let Some(mechanism) = at {
        count += 1;
        let fixture = fixture(mechanism);
        // A link cannot be made where the system has none.
        if mechanism == Mechanism::Link && !cfg!(unix) {
            at = next(mechanism);
            continue;
        }
        let found = scan(mechanism, &fixture);
        let expected: Result<Vec<String>, String> = match fixture.expect {
            Expect::Sightings(list) => Ok(list.iter().map(|text| (*text).to_owned()).collect()),
            Expect::Refused(text) => Err(text.to_owned()),
        };
        if found != expected {
            mismatches.push(format!("{mechanism:?} => {found:?}"));
        }
        at = next(mechanism);
    }
    assert_eq!(count, 37, "the table holds {count} mechanisms");
    assert!(mismatches.is_empty(), "\n{}", mismatches.join("\n"));
}
