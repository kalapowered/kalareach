//! The package the stand-in route installs for an agent other than Codex.
//!
//! The stand-in route has no signed generation that an operator names, so the run publishes one of
//! its own. For Codex the package is the one this crate keeps. For another agent it is written
//! here from the release the run was given: the release's manifest and the files that manifest
//! lists, as the release has them, with one change. A build list entry has no match rules, so the
//! release's own are replaced by one rule that recognises the entry's command, which is the name
//! the stand-in program is placed under. The actions, the capabilities, the command integration
//! and the platforms stay the release's, so the host registers the actions the release declares
//! and the installation's grant is what the release asks for.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use kr_e2e_agents::build::Build;
use kr_e2e_agents::detect::check_detected;
use kr_e2e_agents::subject::Subject;
use kr_ipc::paths::{EnvironmentPaths, HostPaths};
use kr_plugin_catalogue::CatalogueError;
use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::ids::PluginName;
use kr_plugin_sdk::matching::{ExecutableMatch, MatchConfidence, MatchRule};
use kr_plugin_sdk::package::MANIFEST_FILE;
use kr_plugin_sdk::plugin::PluginManifest;
use kr_plugin_sdk::validate::validate_package_directory;
use kr_protocol::ids::{EnvironmentId, PluginId};
use kr_protocol::scalars::Nullable;

use super::staged_a::{BY_HAND, HandAgent, detects, launched};
use super::{
    Chosen, Context, ISOLATION_UNPROVEN, Session, Setup, generations, run_case_with, shells,
};

/// The one match rule of a written package: the executable named `command`, in any directory,
/// whatever distribution it came from. A command is a name, never a path: the stand-in is placed
/// at `t/<command>`.
fn rule_of(manifest: &PluginManifest, command: &str) -> Result<MatchRule, String> {
    let id = format!("{}-executable", manifest.plugin_name.as_str());
    Ok(MatchRule {
        id: PluginName::new(&id).map_err(|error| format!("{id} is not a rule name: {error}"))?,
        executable: ExecutableMatch {
            file_stem: command.to_owned(),
            path_suffix: Vec::new(),
            version_range: Nullable(None),
        },
        distribution: Nullable(None),
        confidence: MatchConfidence::Inferred,
    })
}

/// Writes the package that `subject` stands for, made from the release in `release`, into `into`,
/// and returns its manifest.
///
/// # Errors
///
/// Returns why no package is written: the release has no readable manifest, is another package's
/// than the subject's, lists a file that is missing or is not the digest the manifest names, or
/// the written package is not one the host reads.
pub fn write(subject: &Subject, release: &Path, into: &Path) -> Result<PluginManifest, String> {
    let manifest_path = release.join(MANIFEST_FILE);
    let bytes = std::fs::read(&manifest_path).map_err(|error| {
        format!(
            "the release's manifest {}: {error}",
            manifest_path.display()
        )
    })?;
    let mut manifest: PluginManifest = serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "the release's manifest {}: {error}",
            manifest_path.display()
        )
    })?;
    let named = format!("{}/{}", manifest.publisher_id, manifest.plugin_name);
    if named != subject.plugin().to_string() {
        return Err(format!(
            "the release is of the package {named}, not of the subject's package {}",
            subject.plugin()
        ));
    }
    manifest.match_rules = vec![rule_of(&manifest, subject.command())?];
    std::fs::create_dir_all(into)
        .map_err(|error| format!("a directory for the package {}: {error}", into.display()))?;
    for payload in &manifest.payloads {
        let from = release.join(payload.path.as_str());
        let content = std::fs::read(&from)
            .map_err(|error| format!("the release's file {}: {error}", from.display()))?;
        if PayloadDigest::of(&content) != payload.digest {
            return Err(format!(
                "the release's file {} does not have the digest the manifest names",
                payload.path.as_str()
            ));
        }
        let to = into.join(payload.path.as_str());
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("a directory {}: {error}", parent.display()))?;
        }
        std::fs::write(&to, content)
            .map_err(|error| format!("the file {}: {error}", to.display()))?;
    }
    let mut text = serde_json::to_string_pretty(&manifest)
        .map_err(|error| format!("the package's manifest: {error}"))?;
    text.push('\n');
    std::fs::write(into.join(MANIFEST_FILE), text)
        .map_err(|error| format!("the package's manifest: {error}"))?;
    let validated = validate_package_directory(into);
    if validated.report.is_valid() {
        Ok(manifest)
    } else {
        Err(format!(
            "the written package is not one the host reads: {}",
            validated
                .report
                .findings
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        ))
    }
}

/// The capabilities an installation of a written package is granted: those its own manifest asks
/// for that the repository's ceiling does not already allow.
pub fn grant_of(manifest: &PluginManifest) -> Vec<PluginCapability> {
    super::beyond_the_ceiling(
        manifest
            .capabilities
            .iter()
            .map(|request| request.capability),
    )
}

/// The directory the stand-in route writes the package of a subject made from a release into, below
/// the state of the environment that installs it.
pub fn written_place(environment: &EnvironmentPaths) -> PathBuf {
    super::generation_source(environment).join("package")
}

/// The directory of the package the host installed for `subject`: the one written from its release,
/// or else the package this crate keeps.
///
/// # Panics
///
/// Panics where the subject has no package.
pub fn installed(subject: &Subject, environment: &EnvironmentPaths) -> PathBuf {
    if subject.selected_release().is_some() {
        written_place(environment)
    } else {
        subject
            .package()
            .expect("the subject's package")
            .to_path_buf()
    }
}

/// What a synthetic release declares, for the cases that write a package from one.
#[derive(Clone, Copy, Debug)]
pub enum Shape {
    /// Codex's package under another name, with its command integration and backend.
    Backend,
    /// Codex's package under another name, with no command integration and terminal input
    /// requested besides, which no grant of Codex's covers.
    TerminalInput,
    /// The SDK's example package under another name: one presentation action, and nothing that the
    /// repository's ceiling does not already allow.
    Observed,
}

/// The synthetic entries the cases write a package for: the plugin, the command and what the
/// release declares.
pub const SYNTHETIC: [(&str, &str, Shape); 3] = [
    ("kalareach/claude-code", "claude", Shape::Backend),
    ("kalareach/opencode", "opencode", Shape::Observed),
    ("kalareach/kimi-code-cli", "kimi", Shape::TerminalInput),
];

/// Writes a release of the package `plugin` for an agent typed as `command` into `into`.
///
/// # Panics
///
/// Panics where the release cannot be written.
pub fn release(into: &Path, plugin: &str, command: &str, shape: Shape) {
    let name = plugin.split_once('/').expect("a plugin identifier").1;
    if let Shape::Observed = shape {
        let presentation = kr_plugin_sdk::example::example_presentation_json();
        let mut manifest = kr_plugin_sdk::example::example_manifest_for(presentation.as_bytes());
        manifest.plugin_name = PluginName::new(name).expect("a plugin name");
        std::fs::create_dir_all(into).expect("a directory for the release");
        let mut text = serde_json::to_string_pretty(&manifest).expect("a manifest");
        text.push('\n');
        std::fs::write(into.join(MANIFEST_FILE), text).expect("the release's manifest");
        std::fs::write(
            into.join(kr_plugin_sdk::package::PRESENTATION_FILE),
            presentation,
        )
        .expect("the release's presentation");
        return;
    }
    super::generations::copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("codex-package"),
        into,
    );
    let path = into.join(MANIFEST_FILE);
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("the copied manifest"))
            .expect("a manifest");
    json["plugin_name"] = serde_json::json!(name);
    match shape {
        Shape::Backend => {
            json["command_integration"]["command"] = serde_json::json!(command);
        }
        Shape::TerminalInput => {
            json.as_object_mut()
                .expect("a manifest")
                .remove("command_integration");
            let capabilities = json["capabilities"].as_array_mut().expect("capabilities");
            capabilities.retain(|request| request["capability"] != "command_integration.launch");
            capabilities.push(serde_json::json!({
                "capability": "terminal.input",
                "reason": "Type a path at the terminal's prompt when a device attaches a file"
            }));
        }
        Shape::Observed => unreachable!("written above"),
    }
    // The connector table names the package it belongs to, and the manifest names its digest.
    let connector_path = into.join("connector.json");
    let mut connector: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&connector_path).expect("the copied table"))
            .expect("a connector table");
    connector["plugin_id"] = serde_json::json!(plugin);
    let table = serde_json::to_vec_pretty(&connector).expect("a connector table");
    std::fs::write(&connector_path, &table).expect("the release's connector table");
    let payload = json["payloads"]
        .as_array_mut()
        .expect("payloads")
        .iter_mut()
        .find(|payload| payload["path"] == "connector.json")
        .expect("the connector table is a payload");
    payload["digest"] = serde_json::json!(PayloadDigest::of(&table).to_string());
    payload["size_bytes"] = serde_json::json!(table.len().to_string());
    let mut text = serde_json::to_string_pretty(&json).expect("a manifest");
    text.push('\n');
    std::fs::write(&path, text).expect("the release's manifest");
}

/// A build list entry for `plugin`, typed as `command`.
pub fn entry(plugin: &str, command: &str) -> kr_e2e_agents::build::Build {
    serde_json::from_value(serde_json::json!({
        "package": plugin, "application": "a", "version": "1", "prefix": "/p",
        "pinned": format!("bin/{command}"), "sha256": "00", "command": command,
        "launch": "native", "ready": "r", "harmless": { "input": "h", "shows": "h" },
        "transcript": "t", "missing": {}
    }))
    .expect("an entry")
}

/// A directory of this case's own below the system's temporary one, empty.
fn scratch(case: &str) -> std::path::PathBuf {
    let directory = std::env::temp_dir().join(format!("kr-package-{case}-{}", super::mark()));
    std::fs::create_dir_all(&directory).expect("a directory for the case");
    directory
}

/// The subject of `plugin` typed as `command`, whose release of `shape` is written into `release`.
fn subject_of(release_directory: &Path, plugin: &str, command: &str, shape: Shape) -> Subject {
    release(release_directory, plugin, command, shape);
    let manifest: PluginManifest = serde_json::from_slice(
        &std::fs::read(release_directory.join(MANIFEST_FILE)).expect("the release's manifest"),
    )
    .expect("a manifest");
    Subject::from_build(&entry(plugin, command), &manifest).expect("a subject")
}

/// The package written for each synthetic entry is a package the host reads, and carries the
/// version, the actions, the capabilities, the command integration and the platforms of the release
/// it was written from.
#[test]
fn a_written_package_is_valid_and_keeps_what_its_release_declares() {
    for (plugin, command, shape) in SYNTHETIC {
        let base = scratch("valid");
        let subject = subject_of(&base.join("release"), plugin, command, shape);
        let released: PluginManifest = serde_json::from_slice(
            &std::fs::read(base.join("release").join(MANIFEST_FILE)).expect("the release"),
        )
        .expect("a manifest");
        let written = write(&subject, &base.join("release"), &base.join("package"))
            .unwrap_or_else(|why| panic!("{plugin}: {why}"));
        let on_disk: PluginManifest = serde_json::from_slice(
            &std::fs::read(base.join("package").join(MANIFEST_FILE)).expect("the package"),
        )
        .expect("a manifest");
        assert_eq!(on_disk, written, "{plugin}: the manifest on disk");
        assert_eq!(written.version, released.version, "{plugin}");
        assert_eq!(written.actions, released.actions, "{plugin}");
        assert_eq!(written.capabilities, released.capabilities, "{plugin}");
        assert_eq!(
            written.command_integration, released.command_integration,
            "{plugin}"
        );
        assert_eq!(written.platforms, released.platforms, "{plugin}");
        assert_eq!(written.payloads, released.payloads, "{plugin}");
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// The written package recognises a program by the entry's command and by no other name, and keeps
/// none of the release's own rules, which name a distribution or a location the stand-in has not.
#[test]
fn a_written_package_recognises_the_entrys_command_and_no_other_name() {
    for (plugin, command, shape) in SYNTHETIC {
        let base = scratch("rules");
        let subject = subject_of(&base.join("release"), plugin, command, shape);
        let written = write(&subject, &base.join("release"), &base.join("package"))
            .unwrap_or_else(|why| panic!("{plugin}: {why}"));
        assert_eq!(written.match_rules.len(), 1, "{plugin}");
        let rule = &written.match_rules[0];
        assert_eq!(rule.executable.file_stem, command, "{plugin}");
        assert!(rule.executable.path_suffix.is_empty(), "{plugin}");
        assert!(rule.distribution.0.is_none(), "{plugin}");
        assert!(
            rule.executable.matches_path(&format!("/run/t/{command}")),
            "{plugin}: the command's own place"
        );
        for other in ["codex", "other", &format!("{command}-other")] {
            assert!(
                !rule.executable.matches_path(&format!("/run/t/{other}")),
                "{plugin}: {other}"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// The subject of `plugin` typed as `command`, made from the release of `shape` that is written
/// into `release_directory`, for a run on the stand-in route.
fn selected_subject(
    release_directory: &Path,
    plugin: &str,
    command: &str,
    shape: Shape,
) -> Subject {
    release(release_directory, plugin, command, shape);
    Subject::from_release(&entry(plugin, command), release_directory)
        .expect("a subject of the release")
}

/// Runs `body` on a host that has the package written for `subject` installed, with the agent
/// started by hand and no login, on the stand-in route.
fn by_hand_on(
    subject: Subject,
    test: &str,
    body: impl FnOnce(&Context, &Session<'_>) -> serde_json::Value,
) {
    if kr_ipc::testing::account_launchd::stands_down("the host start") {
        return;
    }
    let shell = match shells::managed_zsh() {
        Ok(shell) => shell,
        Err(why) if shells::required() => panic!("the package leg's managed shell: {why}"),
        Err(why) => {
            eprintln!("skipping: the package leg: {why}");
            return;
        }
    };
    run_case_with(
        Setup {
            manual: true,
            no_login: true,
            ..Setup::default()
        },
        "package",
        "package",
        test,
        "by-hand",
        (
            shell,
            Chosen {
                subject,
                generation: None,
            },
            false,
        ),
        body,
    );
}

/// A release of another package than the subject's is refused, naming both.
#[test]
fn a_release_of_another_package_than_the_subjects_is_not_written() {
    let base = scratch("other");
    let subject = subject_of(
        &base.join("release"),
        "kalareach/claude-code",
        "claude",
        Shape::Backend,
    );
    release(
        &base.join("other"),
        "kalareach/gemini-cli",
        "gemini",
        Shape::Backend,
    );
    let refused = write(&subject, &base.join("other"), &base.join("package"))
        .expect_err("a release of another package");
    assert!(
        refused.contains("kalareach/gemini-cli") && refused.contains("kalareach/claude-code"),
        "{refused}"
    );
    assert!(!base.join("package").join(MANIFEST_FILE).exists());
    let _ = std::fs::remove_dir_all(&base);
}

/// A file of the release whose digest is not the one its manifest names is not written.
#[test]
fn a_release_file_without_the_digest_its_manifest_names_is_not_written() {
    let base = scratch("digest");
    let subject = subject_of(
        &base.join("release"),
        "kalareach/claude-code",
        "claude",
        Shape::Backend,
    );
    std::fs::write(base.join("release").join("README.md"), "changed").expect("a changed file");
    let refused = write(&subject, &base.join("release"), &base.join("package"))
        .expect_err("a file of another digest");
    assert!(
        refused
            .contains("the release's file README.md does not have the digest the manifest names"),
        "{refused}"
    );
    let _ = std::fs::remove_dir_all(&base);
}

/// The host that installed the package written for each synthetic entry detects a program that is
/// typed under the entry's command, as one live instance of that package.
#[test]
fn the_host_detects_a_program_typed_as_the_command_of_the_package_it_installed() {
    const TEST: &str =
        "the_host_detects_a_program_typed_as_the_command_of_the_package_it_installed";
    for (plugin, command, shape) in SYNTHETIC {
        let base = scratch("detects");
        let subject = selected_subject(&base.join("release"), plugin, command, shape);
        by_hand_on(subject, TEST, |ctx, session| {
            let agent = HandAgent::starts(ctx, session);
            let shown = detects(ctx, &session.remote, session.session_id());
            check_detected(&launched(ctx, &agent), &shown).unwrap_or_else(|why| {
                panic!("{plugin}: the host did not detect a program typed as {command}: {why}")
            });
            agent.ends();
            serde_json::json!({ "plugin": plugin, "detection": shown.detection.evidence() })
        });
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// The name a program is placed and typed under that no match rule of a written package names.
const OTHER_NAME: &str = "kr-other-name";

/// The host that installed a written package does not detect a program that runs under another name
/// than the entry's command, though the program is the same file as the one it detects.
#[test]
fn the_host_does_not_detect_a_program_run_under_another_name_than_the_entrys_command() {
    const TEST: &str =
        "the_host_does_not_detect_a_program_run_under_another_name_than_the_entrys_command";
    let (plugin, command, shape) = SYNTHETIC[1];
    let base = scratch("not-detected");
    let subject = selected_subject(&base.join("release"), plugin, command, shape);
    by_hand_on(subject, TEST, |ctx, session| {
        let other = ctx.bin.join(OTHER_NAME);
        ctx.run
            .place_built("codex-stand-in", &other, &["--version"]);
        let place = format!("t/{OTHER_NAME}");
        ctx.run
            .note_placed(Path::new(&place))
            .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
        // The program is started as `starts_the_agent_showing` starts the entry's own command.
        if !session.environment_read.replace(true) {
            session
                .person
                .reads_the_environment(&session.person.expected)
                .unwrap_or_else(|why| panic!("{why}"));
        }
        if session.stand_in_leaves_the_tree {
            session.host.agent_is_a_stand_in();
        }
        session.host.agent_starts();
        let _ = session.person.types_until_it_shows(
            OTHER_NAME,
            BY_HAND,
            "the program placed under another name starts",
            &|| {
                ctx.checks_the_placed_files();
                ctx.run
                    .placed_as_it_was(Path::new(&place))
                    .unwrap_or_else(|why| panic!("{ISOLATION_UNPROVEN} {why}"));
            },
        );
        let agent = HandAgent::running(ctx, session, &other);
        let shown = detects(ctx, &session.remote, session.session_id());
        assert!(
            shown.detection.instances.is_empty(),
            "{plugin}: the host announced live instances ({}) for a program named {OTHER_NAME}, \
             though no rule of the package recognises that name",
            shown.detection.instances.len()
        );
        agent
            .runs()
            .unwrap_or_else(|why| panic!("the program ran while the host looked: {why}"));
        agent.ends();
        serde_json::json!({ "plugin": plugin, "detection": shown.detection.evidence() })
    });
    let _ = std::fs::remove_dir_all(&base);
}

/// Installs the package written into `directory`, whose manifest is `manifest`, with `grant`, from
/// a generation and a catalogue of their own below `base`, named `attempt`.
fn installs(
    base: &Path,
    directory: &Path,
    manifest: &PluginManifest,
    grant: &[PluginCapability],
    attempt: &str,
) -> Result<PayloadDigest, CatalogueError> {
    let runtime = super::runtime();
    let home = base.join(format!("generation-{attempt}"));
    std::fs::create_dir_all(&home).expect("a directory for the generation");
    let generation = runtime.block_on(generations::Generation::build(
        &home,
        generations::GenerationSpec {
            package: Some(directory.to_path_buf()),
            ..generations::GenerationSpec::default()
        },
    ));
    let state = base.join(format!("state-{attempt}"));
    std::fs::create_dir_all(&state).expect("a directory for the catalogue");
    let plugin = PluginId::new(format!(
        "{}/{}",
        manifest.publisher_id, manifest.plugin_name
    ))
    .expect("a plugin identifier");
    runtime.block_on(super::install_published(
        &state,
        EnvironmentId::new(kr_ipc::new_uuid()),
        (
            generations::directory_url(&generation.metadata_dir()),
            generations::directory_url(&generation.targets_dir()),
            generation.root_bytes(),
        ),
        &plugin,
        &manifest.version.to_string(),
        grant.to_vec(),
    ))
}

/// The grant of the package written for each synthetic entry is the capabilities its own manifest
/// asks for that the repository's ceiling does not allow: none for a package that asks for no more,
/// and not the four that Codex's package is granted.
#[test]
fn the_grant_of_a_written_package_is_what_its_own_manifest_asks_for_beyond_the_ceiling() {
    use PluginCapability::{
        ApprovalDecode, ApprovalRespond, CommandIntegrationLaunch, TerminalInput, UpstreamAction,
    };
    let expected = [
        vec![
            CommandIntegrationLaunch,
            ApprovalDecode,
            ApprovalRespond,
            UpstreamAction,
        ],
        Vec::new(),
        vec![
            ApprovalDecode,
            ApprovalRespond,
            UpstreamAction,
            TerminalInput,
        ],
    ];
    for ((plugin, command, shape), mut expected) in SYNTHETIC.into_iter().zip(expected) {
        expected.sort();
        let base = scratch("grant-of");
        let subject = subject_of(&base.join("release"), plugin, command, shape);
        let written = write(&subject, &base.join("release"), &base.join("package"))
            .unwrap_or_else(|why| panic!("{plugin}: {why}"));
        assert_eq!(grant_of(&written), expected, "{plugin}");
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// The package written for each synthetic entry is installed with its own grant, and an install
/// whose grant lacks a capability that an action of the package needs is refused, naming it.
#[test]
fn a_written_package_is_not_installed_without_the_grant_of_a_capability_one_of_its_actions_needs() {
    for (plugin, command, shape) in SYNTHETIC {
        let base = scratch("without-grant");
        let subject = subject_of(&base.join("release"), plugin, command, shape);
        let written = write(&subject, &base.join("release"), &base.join("package"))
            .unwrap_or_else(|why| panic!("{plugin}: {why}"));
        let grant = grant_of(&written);
        let needed = super::beyond_the_ceiling(
            written
                .actions
                .iter()
                .map(|action| action.effect.required_capability()),
        );
        for (index, capability) in needed.iter().enumerate() {
            let without: Vec<PluginCapability> = grant
                .iter()
                .copied()
                .filter(|held| held != capability)
                .collect();
            let refused = installs(
                &base,
                &base.join("package"),
                &written,
                &without,
                &format!("without-{index}"),
            )
            .expect_err("an install without the grant of an action's capability");
            assert!(
                matches!(&refused, CatalogueError::GrantRequired { capability: named, .. } if named == capability),
                "{plugin}: the install without the grant of {capability} was refused for another \
                 reason: {refused}"
            );
        }
        installs(&base, &base.join("package"), &written, &grant, "with")
            .unwrap_or_else(|why| panic!("{plugin}: the install with its own grant: {why}"));
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// A grant that names a capability the written package does not ask for is refused, so a grant that
/// is not the package's own is not installed.
#[test]
fn a_written_package_is_not_installed_with_a_grant_for_a_capability_it_does_not_request() {
    let (plugin, command, shape) = SYNTHETIC[1];
    let base = scratch("extra-grant");
    let subject = subject_of(&base.join("release"), plugin, command, shape);
    let written = write(&subject, &base.join("release"), &base.join("package"))
        .unwrap_or_else(|why| panic!("{plugin}: {why}"));
    let mut grant = grant_of(&written);
    grant.push(PluginCapability::TerminalInput);
    let refused = installs(&base, &base.join("package"), &written, &grant, "extra")
        .expect_err("an install with a grant the package did not ask for");
    match &refused {
        CatalogueError::GrantRequired {
            capability,
            requirement,
        } => {
            assert_eq!(*capability, PluginCapability::TerminalInput, "{plugin}");
            assert!(
                requirement.contains("a package that asks for it"),
                "{requirement}"
            );
        }
        other => panic!("{plugin}: refused for another reason: {other}"),
    }
    let _ = std::fs::remove_dir_all(&base);
}

/// An environment of its own below `base`, whose state holds nothing yet.
fn environment_in(base: &Path) -> EnvironmentPaths {
    HostPaths::new(base.join("run"), base.join("state"))
        .expect("absolute host roots")
        .environment(EnvironmentId::new(kr_ipc::new_uuid()))
}

/// The identifiers of `actions`, in order.
fn action_ids(actions: Vec<kr_e2e_agents::build::Action>) -> Vec<String> {
    actions.into_iter().map(|action| action.id).collect()
}

/// The actions that the two staged parts read for a subject made from a release are the ones the
/// release declares, and not the actions of the Codex package this crate keeps.
#[test]
fn the_actions_of_a_subject_made_from_a_release_are_the_releases_own() {
    for (plugin, command, shape) in SYNTHETIC {
        let base = scratch("actions");
        let subject = selected_subject(&base.join("release"), plugin, command, shape);
        let environment = environment_in(&base);
        write(
            &subject,
            &base.join("release"),
            &written_place(&environment),
        )
        .unwrap_or_else(|why| panic!("{plugin}: {why}"));
        let released: PluginManifest = serde_json::from_slice(
            &std::fs::read(base.join("release").join(MANIFEST_FILE)).expect("the release"),
        )
        .expect("a manifest");
        let declared: Vec<String> = released
            .actions
            .iter()
            .map(|action| action.id.to_string())
            .collect();
        assert_eq!(
            action_ids(super::staged_a::package_actions(&subject, &environment)),
            declared,
            "{plugin}: staged A"
        );
        assert_eq!(
            action_ids(super::staged_c::package_actions(&subject, &environment)),
            declared,
            "{plugin}: staged C"
        );
        if matches!(shape, Shape::Observed) {
            assert_eq!(declared, ["status.refresh"], "{plugin}");
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// The actions that the two staged parts read are those of the package written from the release,
/// and a change of the release after the write does not change them.
#[test]
fn the_actions_the_staged_parts_read_are_those_of_the_written_package_whatever_its_release_says_later()
 {
    for (plugin, command, shape) in SYNTHETIC {
        let base = scratch("actions-written");
        let subject = selected_subject(&base.join("release"), plugin, command, shape);
        let environment = environment_in(&base);
        let written = write(
            &subject,
            &base.join("release"),
            &written_place(&environment),
        )
        .unwrap_or_else(|why| panic!("{plugin}: {why}"));
        let kept: Vec<String> = written
            .actions
            .iter()
            .map(|action| action.id.to_string())
            .collect();
        assert!(!kept.is_empty(), "{plugin}: the release declares an action");
        let path = base.join("release").join(MANIFEST_FILE);
        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("the release's manifest"))
                .expect("a manifest");
        json["actions"] = serde_json::json!([]);
        std::fs::write(&path, serde_json::to_vec_pretty(&json).expect("a manifest"))
            .expect("the changed release");
        assert_eq!(
            action_ids(super::staged_a::package_actions(&subject, &environment)),
            kept,
            "{plugin}: staged A reads the written package's actions, not those of the release changed after the write"
        );
        assert_eq!(
            action_ids(super::staged_c::package_actions(&subject, &environment)),
            kept,
            "{plugin}: staged C reads the written package's actions, not those of the release changed after the write"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// The entry and the generation a run names for the real-package check, given the values of the
/// variables that name them and whether the run requires the agents: none where it names neither
/// and need not. A variable that is not set, or is empty, names nothing.
///
/// # Errors
///
/// Returns why the run cannot skip the check and cannot make it: it names an entry and no
/// generation or a generation and no entry, or it requires the agents and names neither.
fn named(
    entry: Option<OsString>,
    generation: Option<OsString>,
    required: bool,
) -> Result<Option<(PathBuf, PathBuf)>, String> {
    let given =
        |value: Option<OsString>| value.filter(|value| !value.is_empty()).map(PathBuf::from);
    let (build, generations) = (super::BUILD_VARIABLE, super::GENERATION_VARIABLE);
    match (given(entry), given(generation)) {
        (Some(entry), Some(generation)) => Ok(Some((entry, generation))),
        (None, None) if required => Err(format!(
            "{}=1, and the run names no entry ({build}) and no generation ({generations})",
            kr_e2e_agents::REQUIRE_VARIABLE
        )),
        (None, None) => Ok(None),
        (None, Some(_)) => Err(format!(
            "{generations} names a generation, and {build} names no entry (it is not set or is empty)"
        )),
        (Some(_), None) => Err(format!(
            "{build} names an entry, and {generations} names no generation (it is not set or is empty)"
        )),
    }
}

/// Checks that the package the generation at `generation` holds for the entry `build` is one the
/// stand-in route can write its own package from: a match rule of the package recognises a program
/// named by the entry's command, and the package written from it declares the actions and asks for
/// the capabilities that the generation's package does.
///
/// # Errors
///
/// Returns why the generation's package is not one the stand-in route can write its package from.
///
/// # Panics
///
/// Panics where the generation's index does not name the package exactly once, or the package's
/// manifest does not have the digest the index names.
pub fn check_real_package(build: &Build, generation: &Path) -> Result<(), String> {
    let plugin = PluginId::new(&build.package).map_err(|why| {
        format!(
            "the entry's package {} is not a plugin identifier: {why}",
            build.package
        )
    })?;
    let manifest = super::generation_manifest(generation, &plugin);
    let recognised = manifest.match_rules.iter().any(|rule| {
        let directory = rule.executable.path_suffix.join("/");
        rule.executable
            .matches_path(&format!("/{directory}/{}", build.command))
    });
    if !recognised {
        return Err(format!(
            "no match rule of the package {plugin} in the generation recognises a program named {}",
            build.command
        ));
    }
    let subject = Subject::from_build(build, &manifest)?;
    let release = generation
        .join("targets/packages")
        .join(manifest.publisher_id.to_string())
        .join(manifest.plugin_name.to_string())
        .join(super::generation_entry(generation, &plugin).version);
    let into = scratch("real");
    let written = write(&subject, &release, &into.join("package"));
    let _ = std::fs::remove_dir_all(&into);
    let written = written.map_err(|why| {
        format!("the stand-in route cannot write its package from the generation's package {plugin}: {why}")
    })?;
    if written.actions != manifest.actions {
        return Err(format!(
            "the package written from the generation's package {plugin} declares other actions \
             than the generation's"
        ));
    }
    if written.capabilities != manifest.capabilities {
        return Err(format!(
            "the package written from the generation's package {plugin} asks for other \
             capabilities than the generation's"
        ));
    }
    Ok(())
}

/// The package a generation holds for the entry the run names is one the stand-in route can write
/// its own package from. It is skipped only when the run names neither an entry nor a generation
/// and does not require the agents; a run of a real agent names both.
#[test]
fn the_package_a_generation_holds_for_the_entry_is_one_the_stand_in_route_writes_from() {
    let required = std::env::var(kr_e2e_agents::REQUIRE_VARIABLE).is_ok_and(|value| value == "1");
    let Some((entry, generation)) = named(
        std::env::var_os(super::BUILD_VARIABLE),
        std::env::var_os(super::GENERATION_VARIABLE),
        required,
    )
    .unwrap_or_else(|why| panic!("{why}")) else {
        eprintln!(
            "skipping: the run names no entry ({}) and no generation ({})",
            super::BUILD_VARIABLE,
            super::GENERATION_VARIABLE
        );
        return;
    };
    check_real_package(&kr_e2e_agents::build::read_build(&entry), &generation)
        .unwrap_or_else(|why| panic!("{why}"));
}

/// A run that names an entry and a generation has them to check, and a run that names neither, and
/// does not require the agents, has nothing to check.
#[test]
fn the_real_package_check_reads_what_a_run_names_and_skips_a_run_that_names_neither() {
    let value = |text: &str| Some(OsString::from(text));
    let pair = Some((PathBuf::from("entry.json"), PathBuf::from("/generation")));
    for required in [false, true] {
        assert_eq!(
            named(value("entry.json"), value("/generation"), required),
            Ok(pair.clone()),
            "required: {required}"
        );
    }
    assert_eq!(named(None, None, false), Ok(None));
    assert_eq!(named(value(""), value(""), false), Ok(None));
}

/// A run that names an entry and no generation, or a generation and no entry, is refused, naming
/// what it does not name; an empty value names nothing.
#[test]
fn the_real_package_check_refuses_a_run_that_names_an_entry_or_a_generation_and_not_both() {
    let value = |text: &str| Some(OsString::from(text));
    let no_generation = format!("{} names no generation", super::GENERATION_VARIABLE);
    let no_entry = format!("{} names no entry", super::BUILD_VARIABLE);
    for required in [false, true] {
        for generation in [None, value("")] {
            let refused = named(value("entry.json"), generation, required);
            assert!(
                matches!(&refused, Err(why) if why.contains(&no_generation)),
                "an entry and no generation: {refused:?}"
            );
        }
        for entry in [None, value("")] {
            let refused = named(entry, value("/generation"), required);
            assert!(
                matches!(&refused, Err(why) if why.contains(&no_entry)),
                "a generation and no entry: {refused:?}"
            );
        }
    }
}

/// A run that requires the agents is refused where the check would be skipped.
#[test]
fn the_real_package_check_is_not_skipped_by_a_run_that_requires_the_agents() {
    let value = |text: &str| Some(OsString::from(text));
    for (entry, generation) in [(None, None), (value(""), value(""))] {
        let refused = named(entry, generation, true);
        assert!(
            matches!(&refused, Err(why) if why.contains(kr_e2e_agents::REQUIRE_VARIABLE)),
            "a run that requires the agents and names neither: {refused:?}"
        );
    }
}

/// A generation of its own below `base` that holds the package written for `plugin`, typed as
/// `command`, from a release of `shape`; returns the generation's directory.
fn generation_holding(base: &Path, plugin: &str, command: &str, shape: Shape) -> PathBuf {
    let subject = subject_of(&base.join("release"), plugin, command, shape);
    write(&subject, &base.join("release"), &base.join("package"))
        .unwrap_or_else(|why| panic!("{plugin}: {why}"));
    let home = base.join("home");
    std::fs::create_dir_all(&home).expect("a directory for the generation");
    super::runtime()
        .block_on(generations::Generation::build(
            &home,
            generations::GenerationSpec {
                package: Some(base.join("package")),
                ..generations::GenerationSpec::default()
            },
        ))
        .directory()
}

/// A generation that holds the package written for each synthetic entry passes the real-package
/// check for that entry.
#[test]
fn a_generation_that_holds_the_package_written_for_an_entry_passes_the_real_package_check() {
    for (plugin, command, shape) in SYNTHETIC {
        let base = scratch("real-passes");
        let generation = generation_holding(&base, plugin, command, shape);
        check_real_package(&entry(plugin, command), &generation)
            .unwrap_or_else(|why| panic!("{plugin}: {why}"));
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// An entry whose command no match rule of the generation's package recognises fails the check,
/// naming the command.
#[test]
fn an_entry_whose_command_no_rule_of_the_generations_package_recognises_fails_the_real_package_check()
 {
    let (plugin, command, shape) = SYNTHETIC[0];
    let base = scratch("real-refuses");
    let generation = generation_holding(&base, plugin, command, shape);
    let refused = check_real_package(&entry(plugin, "other-command"), &generation)
        .expect_err("an entry whose command no rule recognises");
    assert!(refused.contains("other-command"), "{refused}");
    assert!(refused.contains(plugin), "{refused}");
    let _ = std::fs::remove_dir_all(&base);
}
