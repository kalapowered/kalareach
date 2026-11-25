//! The claude-code package's native bridge recipe, applied by the daemon of the harness's host over
//! the run's own home.
//!
//! The agent is the stand-in route's program placed under the name `claude`, and the package is the
//! one the repository bundles, published in a signed generation of the case's own whose index names
//! the digest of the one build it qualifies. The host makes the directory the recipe is written in
//! before its daemon starts and gives the daemon a search path that holds that program and no other
//! `claude`. Nothing here starts a forwarder, and nothing reads or writes the person's own
//! `~/.claude`. Each case starts the placed program once, with `--version`, when it places it, and
//! the cases that type `claude` start it again under that name.

use super::*;

/// Where the stand-in is placed in the run as `claude`, below its directory.
pub(super) const CLAUDE_PLACE: &str = "t/claude";

/// The directory below the run's home where Claude Code keeps its configuration, and where the
/// host's daemon writes the recipe.
pub(super) const CLAUDE_CONFIGURATION: &str = ".claude";

/// The program built here that is placed as `claude` where a case starts no agent: the stand-in of
/// the Codex route, which is a native program that starts.
const CLAUDE_PROGRAM: &str = "codex-stand-in";

/// The program built here that is placed as `claude` where a person types the command: it says the
/// arguments it was started with.
const TYPED_PROGRAM: &str = "argv-stand-in";

/// The version the generation lists the placed program as: the one the pinned build reports.
pub(super) const CLAUDE_VERSION: &str = "2.1.278";

/// The key the recipe adds to `settings.json`.
const RECIPE_KEY: &str = "kalareach-channels@skills-dir";

/// The files the recipe writes, below the configuration directory.
const RECIPE_FILES: [&str; 3] = [
    "skills/kalareach-channels/.claude-plugin/plugin.json",
    "skills/kalareach-channels/.mcp.json",
    "skills/kalareach-channels/hooks/hooks.json",
];

/// The settings a person's directory already holds when the recipe is applied: none of them is the
/// recipe's. They are indented and end in a newline, so that a rewrite of the file that compacts it
/// or drops its last byte is not the bytes they were.
const SEEDED_SETTINGS: &str = r#"{
  "theme": "dark",
  "enabledPlugins": {
    "other@elsewhere": true
  },
  "permissions": {
    "allow": [
      "Read"
    ]
  }
}
"#;

fn claude_code() -> PluginId {
    PluginId::new("kalareach/claude-code").expect("a plugin identifier")
}

/// The directory of the claude-code package the repository bundles: the one release it holds.
fn claude_code_package() -> PathBuf {
    let versions = kr_e2e_m1b::catalogue::workspace()
        .join("bundled-plugins/targets/packages/kalareach/claude-code");
    let mut releases: Vec<PathBuf> = std::fs::read_dir(&versions)
        .unwrap_or_else(|error| panic!("{}: {error}", versions.display()))
        .map(|entry| entry.expect("an entry").path())
        .collect();
    assert_eq!(
        releases.len(),
        1,
        "the bundle holds one release of the claude-code package"
    );
    releases.remove(0)
}

/// What a case changes in the preparation of its host.
#[derive(Clone, Debug)]
pub(super) struct Variant {
    /// Whether the generation names the digest of another file, which is not on the daemon's path,
    /// and not the placed program's.
    names_another: bool,
    /// Whether the placed program is a script.
    script: bool,
    /// The capabilities the installation is given beyond the repository's ceiling.
    grants: Vec<PluginCapability>,
    /// Whether a person types `claude` in a managed shell of the host: the program placed is the one
    /// that says its arguments, and the host's configuration turns the package's command
    /// integration on.
    typed: bool,
    /// The capabilities the installation holds once the owner has changed it after the install,
    /// where the owner took some of them away.
    after_install: Option<Vec<PluginCapability>>,
}

impl Variant {
    /// A variant whose installation was given every capability the release asks for, and whose
    /// owner then withdrew `capability`.
    fn withdrawn(capability: PluginCapability) -> Self {
        let installed = Self::default();
        let after_install = installed
            .grants
            .iter()
            .copied()
            .filter(|held| *held != capability)
            .collect();
        Self {
            after_install: Some(after_install),
            ..installed
        }
    }
}

impl Default for Variant {
    fn default() -> Self {
        Self {
            names_another: false,
            script: false,
            grants: vec![
                PluginCapability::NativeBridgeInstall,
                PluginCapability::CommandIntegrationLaunch,
                PluginCapability::ApprovalDecode,
                PluginCapability::ApprovalRespond,
                PluginCapability::UpstreamAction,
            ],
            after_install: None,
            typed: false,
        }
    }
}

/// Publishes the claude-code package in a signed generation of its own, whose index names the
/// digest of `qualified` as the one build it qualifies, and installs and enables it in the
/// environment with `grants`, as the owner's confirmation of that exact installation does.
async fn install_claude_code(
    environment: &EnvironmentPaths,
    qualified: &Path,
    grants: Vec<PluginCapability>,
) {
    let package = claude_code_package();
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(package.join("plugin.json")).expect("the package's manifest"),
    )
    .expect("a manifest");
    let version = kr_plugin_sdk::version::PackageVersion::parse(
        manifest["version"].as_str().expect("the package's version"),
    )
    .expect("a version");
    let build = QualifiedBuild {
        application: Label::new("claude-code").expect("a label"),
        distribution: Label::new("test stand-in").expect("a label"),
        version: kr_plugin_sdk::version::PackageVersion::parse(CLAUDE_VERSION).expect("a version"),
        os: if cfg!(target_os = "macos") {
            OperatingSystem::MacOs
        } else {
            OperatingSystem::Linux
        },
        architecture: if std::env::consts::ARCH == "aarch64" {
            Architecture::Aarch64
        } else {
            Architecture::X86_64
        },
        executable_digest: PayloadDigest::of(
            &std::fs::read(qualified).expect("the program the generation names"),
        ),
    };
    let home = environment.state_dir().join("generation-source");
    std::fs::create_dir_all(&home).expect("a directory for the generation");
    let fixture = generations::Generation::build(
        &home,
        generations::GenerationSpec {
            package: Some(package),
            builds: vec![build],
            ..generations::GenerationSpec::default()
        },
    )
    .await;
    let mut catalogue = Catalogue::open(
        &environment.state_dir().join("catalogue"),
        Arc::new(RepositoryTransport::local_only(
            "this test reads its repository from disk",
        )),
    )
    .expect("an openable catalogue");
    let id = RepositoryId::new("development").expect("an identifier");
    catalogue
        .enrol(
            Enrolment::new(
                id.clone(),
                RepositoryKind::Local,
                generations::directory_url(&fixture.metadata_dir()),
                generations::directory_url(&fixture.targets_dir()),
                fixture.root_bytes(),
                kr_plugin_sdk::limits::RepositoryBudgets::defaults(),
                CapabilityCeiling::default_ceiling(),
            )
            .expect("an enrollable repository"),
            true,
        )
        .expect("the owner adopted the root");
    catalogue.sync(&id).await.expect("a generation");
    let digest = catalogue
        .index(&id)
        .expect("activated")
        .find(&claude_code(), &version)
        .expect("the package")
        .manifest_digest;
    catalogue
        .install_with(
            &id,
            environment.environment_id(),
            &claude_code(),
            &version,
            digest,
            InstallationGrant::with(grants),
            None,
            &mut Change::new(&Owner::confirming()),
        )
        .await
        .expect("installed");
    catalogue
        .set_enabled(environment.environment_id(), &claude_code(), true)
        .await
        .expect("enabled");
}

/// Replaces the grant of the claude-code installation with `grants`, as the owner's change of that
/// installation does.
fn narrow_claude_code(environment: &EnvironmentPaths, grants: Vec<PluginCapability>) {
    let mut catalogue = Catalogue::open(
        &environment.state_dir().join("catalogue"),
        Arc::new(RepositoryTransport::local_only(
            "this test reads its repository from disk",
        )),
    )
    .expect("an openable catalogue");
    catalogue
        .set_grant(
            environment.environment_id(),
            &claude_code(),
            InstallationGrant::with(grants),
        )
        .expect("the grant is replaced");
}

/// The program as a leg places it for the host: the directory below the run's home where the
/// recipe is written and the program the daemon finds by its name.
fn claude_application() -> Application {
    Application {
        program: PathBuf::from(CLAUDE_PLACE),
        configuration: PathBuf::from(CLAUDE_CONFIGURATION),
    }
}

/// A host whose daemon applies the claude-code recipe over the run's home, prepared as `variant`
/// says, after the program was placed by [`Context::place`].
pub(super) fn host<'a>(ctx: &'a Context, variant: &Variant) -> Host<'a> {
    let configuration = ctx.run.home().join(CLAUDE_CONFIGURATION);
    let qualified = if variant.names_another {
        kr_ipc::paths::create_private_tree(ctx.run.root(), &ctx.run.root().join("q"))
            .expect("a directory for the other program");
        let other = ctx.run.root().join("q/claude");
        std::fs::write(&other, b"another build\n").expect("another program");
        other
    } else {
        ctx.executable.clone()
    };
    Host::start_prepared(
        &ctx.run,
        &HostOptions {
            shell_packages: Some(ctx.shell.prefix.clone()),
        },
        &Preparation {
            application: Some(claude_application()),
            command_integrations: if variant.typed {
                vec![claude_code().to_string()]
            } else {
                Vec::new()
            },
            ..Preparation::default()
        },
        |environment| {
            if configuration.is_dir() {
                std::fs::write(configuration.join("settings.json"), SEEDED_SETTINGS)
                    .expect("the person's settings");
            }
            ctx.runtime.block_on(install_claude_code(
                environment,
                &qualified,
                variant.grants.clone(),
            ));
            if let Some(held) = &variant.after_install {
                narrow_claude_code(environment, held.clone());
            }
        },
    )
}

/// Runs `body` over a host prepared as `variant` says, on the stand-in route, and closes the host.
/// Where the case cannot run on this machine it says so and returns.
fn in_a_host(case: &str, variant: &Variant, body: impl FnOnce(&Context, &Host<'_>)) {
    if kr_ipc::testing::account_launchd::stands_down("the host start") {
        return;
    }
    let shell = match shells::managed_zsh() {
        Ok(shell) => shell,
        Err(why) if shells::required() => panic!("the managed shell: {why}"),
        Err(why) => {
            eprintln!("skipping: {why}");
            return;
        }
    };
    let mut ctx = Context::new(shell, Route::StandIn, Run::start(case), runtime());
    ctx.claude_code = Some(if variant.typed {
        TYPED_PROGRAM
    } else {
        CLAUDE_PROGRAM
    });
    ctx.place();
    if variant.script {
        std::fs::write(&ctx.executable, "#!/bin/sh\nexit 0\n").expect("a script as the program");
    }
    let host = host(&ctx, variant);
    body(&ctx, &host);
    ctx.close(&host);
}

/// Every file below `directory`, by its path below it, in order.
fn files_below(directory: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(next) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.push(
                    path.strip_prefix(directory)
                        .expect("below the directory")
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    found.sort();
    found
}

/// What the doctor says where it names a bridge the host refused.
const REFUSED: &str = "was refused, and nothing of it is in place";

/// What the doctor says where no package has a bridge in place on the host.
const NONE_IN_PLACE: &str = "no package has put a native bridge in place on this host";

/// What the doctor says where it names a bridge the host applied.
const APPLIED: &str = "is applied";

/// What the host's doctor says of the native bridges.
fn bridges_said(host: &Host<'_>) -> String {
    let output = host
        .kr_within(&["doctor", "--json"], LIVENESS)
        .expect("the doctor answers");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The processes the run started that run the forwarder.
fn forwarders(ctx: &Context) -> Vec<String> {
    kr_e2e_m1b::run::processes_under(ctx.run.root())
        .expect("the process table")
        .into_iter()
        .map(|(_, command)| command)
        .filter(|command| command.contains("kr-hook"))
        .collect()
}

/// Nothing of the recipe is in place: no file beside the person's settings, the settings are the
/// bytes they were, no forwarder runs, and the doctor says the bridge was refused.
fn assert_nothing_was_applied(ctx: &Context, host: &Host<'_>) {
    let configuration = ctx.run.home().join(CLAUDE_CONFIGURATION);
    assert_eq!(
        files_below(&configuration),
        ["settings.json"],
        "nothing was written beside the person's settings"
    );
    assert_eq!(
        std::fs::read_to_string(configuration.join("settings.json")).expect("the settings"),
        SEEDED_SETTINGS,
        "the person's settings are the bytes they were"
    );
    assert_eq!(forwarders(ctx), Vec::<String>::new(), "no forwarder runs");
    let said = bridges_said(host);
    assert!(
        said.contains(REFUSED),
        "the doctor says the bridge was refused: {said}"
    );
}

/// The recipe is in place below the run's home: exactly its three files beside the person's
/// settings, the one key set and every other setting as it was, and the registration names the
/// forwarder the host placed.
fn assert_the_recipe_is_in_place(ctx: &Context) {
    let configuration = ctx.run.home().join(CLAUDE_CONFIGURATION);
    let mut expected: Vec<String> = RECIPE_FILES.iter().map(|file| (*file).to_owned()).collect();
    expected.push("settings.json".to_owned());
    expected.sort();
    assert_eq!(
        files_below(&configuration),
        expected,
        "the recipe wrote exactly its three files beside the person's settings"
    );
    let mut settings: serde_json::Value = serde_json::from_slice(
        &std::fs::read(configuration.join("settings.json")).expect("the settings"),
    )
    .expect("settings in JSON");
    assert_eq!(
        settings["enabledPlugins"][RECIPE_KEY],
        serde_json::Value::Bool(true),
        "the recipe's key is set"
    );
    settings["enabledPlugins"]
        .as_object_mut()
        .expect("the plugins")
        .remove(RECIPE_KEY);
    assert_eq!(
        settings,
        serde_json::from_str::<serde_json::Value>(SEEDED_SETTINGS).expect("the seed"),
        "every other setting is as it was"
    );
    let registration: serde_json::Value = serde_json::from_slice(
        &std::fs::read(configuration.join(RECIPE_FILES[1])).expect("the registration"),
    )
    .expect("a registration in JSON");
    let forwarder = registration["mcpServers"]["kalareach"]["command"]
        .as_str()
        .expect("the forwarder the registration starts");
    assert!(
        Path::new(forwarder).is_file() && forwarder.ends_with("b/kr-hook"),
        "the registration names the forwarder the host placed, not {forwarder}"
    );
}

/// A stand-in whose digest a signed record names has the recipe applied: exactly the three files
/// and the one settings key, with every other setting as it was, and the registration names the
/// forwarder the host placed.
#[test]
fn gateway_claude_recipe_a_stand_in_a_record_names_has_the_recipe_applied() {
    in_a_host("claude-recipe-named", &Variant::default(), |ctx, host| {
        assert_the_recipe_is_in_place(ctx);
        let said = bridges_said(host);
        assert!(
            said.contains(APPLIED),
            "the doctor says the bridge is applied: {said}"
        );
    });
}

/// A stand-in whose digest no signed record names has nothing written under the configuration
/// directory, the person's settings are the bytes they were, no forwarder runs, and the doctor
/// says the bridge was refused.
#[test]
fn gateway_claude_recipe_a_stand_in_no_record_names_writes_nothing_and_starts_no_forwarder() {
    let variant = Variant {
        names_another: true,
        ..Variant::default()
    };
    in_a_host(
        "claude-recipe-unnamed",
        &variant,
        assert_nothing_was_applied,
    );
}

/// A stand-in that is a script is refused though a record names its digest: nothing is written, the
/// person's settings are the bytes they were, no forwarder runs, and the doctor says the bridge was
/// refused.
#[test]
fn gateway_claude_recipe_a_stand_in_that_is_a_script_is_refused() {
    let variant = Variant {
        script: true,
        ..Variant::default()
    };
    in_a_host("claude-recipe-script", &variant, assert_nothing_was_applied);
}

/// The variable a session is given for Claude Code's configuration directory names the directory
/// the recipe was written in, so that Claude Code reads the registration the daemon wrote.
#[test]
fn gateway_claude_recipe_the_sessions_configuration_variable_names_the_directory_the_recipe_was_written_in()
 {
    in_a_host(
        "claude-recipe-directory",
        &Variant::default(),
        |ctx, host| {
            let named = ctx
                .prepare_variables(host)
                .into_iter()
                .find(|(name, _)| name == "CLAUDE_CONFIG_DIR")
                .map(|(_, value)| value)
                .expect("the session is given the variable");
            assert!(
                Path::new(&named).join(RECIPE_FILES[1]).is_file(),
                "the directory CLAUDE_CONFIG_DIR names holds the registration the recipe wrote: {named}"
            );
        },
    );
}

/// Disables the claude-code package in the environment, as the owner's change of that installation
/// does.
async fn disable_claude_code(environment: &EnvironmentPaths) {
    let mut catalogue = Catalogue::open(
        &environment.state_dir().join("catalogue"),
        Arc::new(RepositoryTransport::local_only(
            "this test reads its repository from disk",
        )),
    )
    .expect("an openable catalogue");
    catalogue
        .set_enabled(environment.environment_id(), &claude_code(), false)
        .await
        .expect("disabled");
}

/// Taking the package out of use removes the recipe's three files and its settings key, and the
/// person's settings are the bytes they were.
#[test]
fn gateway_claude_recipe_the_removal_leaves_the_settings_as_they_were() {
    in_a_host("claude-recipe-removal", &Variant::default(), |ctx, host| {
        let configuration = ctx.run.home().join(CLAUDE_CONFIGURATION);
        assert!(
            configuration.join(RECIPE_FILES[1]).is_file(),
            "the recipe is applied before it is removed"
        );
        host.kill_daemon();
        ctx.runtime
            .block_on(disable_claude_code(host.environment()));
        host.start_daemon();
        assert_eq!(
            files_below(&configuration),
            ["settings.json"],
            "the recipe's files are gone"
        );
        assert_eq!(
            std::fs::read_to_string(configuration.join("settings.json")).expect("the settings"),
            SEEDED_SETTINGS,
            "the person's settings are the bytes they were"
        );
    });
}

/// An installation whose owner withdrew `native_bridge.install` has nothing written under the
/// configuration directory, the person's settings are the bytes they were, and no forwarder runs.
#[test]
fn gateway_claude_recipe_an_installation_that_withdrew_the_bridge_grant_writes_nothing() {
    let variant = Variant::withdrawn(PluginCapability::NativeBridgeInstall);
    in_a_host("claude-recipe-no-bridge-grant", &variant, |ctx, host| {
        let configuration = ctx.run.home().join(CLAUDE_CONFIGURATION);
        assert_eq!(
            files_below(&configuration),
            ["settings.json"],
            "nothing was written beside the person's settings"
        );
        assert_eq!(
            std::fs::read_to_string(configuration.join("settings.json")).expect("the settings"),
            SEEDED_SETTINGS,
            "the person's settings are the bytes they were"
        );
        assert_eq!(forwarders(ctx), Vec::<String>::new(), "no forwarder runs");
        let said = bridges_said(host);
        assert!(
            said.contains(NONE_IN_PLACE),
            "the doctor says no package has a bridge in place: {said}"
        );
    });
}

/// An installation whose owner withdrew `command_integration.launch` has the recipe applied as one
/// that holds it does: the launch grant is not the bridge's.
#[test]
fn gateway_claude_recipe_an_installation_that_withdrew_the_launch_grant_has_the_recipe_applied() {
    let variant = Variant::withdrawn(PluginCapability::CommandIntegrationLaunch);
    in_a_host("claude-recipe-no-launch-grant", &variant, |ctx, host| {
        assert_the_recipe_is_in_place(ctx);
        let said = bridges_said(host);
        assert!(
            said.contains(APPLIED),
            "the doctor says the bridge is applied: {said}"
        );
    });
}

/// What the program that says its arguments prints before each one.
const ARGUMENT: &str = "argv-stand-in: argument ";

/// What the program that says its arguments prints when it has said them all.
const SAID_THEM_ALL: &str = "argv-stand-in: ends";

/// The words the package's command integration adds to a typed `claude`.
const DEVELOPMENT_FLAG: [&str; 2] = [
    "--dangerously-load-development-channels",
    "plugin:kalareach-channels@skills-dir",
];

/// The arguments the program placed as `claude` says it was started with, where a person types
/// `claude` and nothing else in a managed shell of the host.
fn typed_arguments(ctx: &Context, host: &Host<'_>) -> Vec<String> {
    let person = Person::enters(ctx, host, &[], &[]);
    person.types("claude");
    person
        .sees(
            SAID_THEM_ALL,
            "the program started by its name says its arguments",
        )
        .iter()
        .filter_map(|row| row.trim().strip_prefix(ARGUMENT))
        .map(str::to_owned)
        .collect()
}

/// A typed `claude` is given the development flag and the plugin it names where the installation
/// holds `command_integration.launch`.
#[test]
fn gateway_claude_recipe_a_typed_claude_is_given_the_development_flag_where_the_launch_grant_is_held()
 {
    let variant = Variant {
        typed: true,
        ..Variant::default()
    };
    in_a_host("claude-recipe-typed", &variant, |ctx, host| {
        assert_the_recipe_is_in_place(ctx);
        assert_eq!(
            typed_arguments(ctx, host),
            DEVELOPMENT_FLAG,
            "the program was given the flag and the plugin the package declares"
        );
    });
}

/// A typed `claude` is given no flag where the installation withdrew `command_integration.launch`,
/// and the recipe is in place all the same.
#[test]
fn gateway_claude_recipe_a_typed_claude_is_given_no_flag_where_the_launch_grant_was_withdrawn() {
    let variant = Variant {
        typed: true,
        ..Variant::withdrawn(PluginCapability::CommandIntegrationLaunch)
    };
    in_a_host("claude-recipe-typed-no-launch", &variant, |ctx, host| {
        assert_the_recipe_is_in_place(ctx);
        assert_eq!(
            typed_arguments(ctx, host),
            Vec::<String>::new(),
            "the program was given nothing the person did not type"
        );
    });
}
