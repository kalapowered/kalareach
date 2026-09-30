//! `kr plugin` and `kr plugin repo`: plugin packages, and the repositories they come from.
//!
//! Every operation is a client of the method the control daemon serves for it, and the daemon's
//! catalogue decides each answer. Two decisions are not this user's to make at a terminal, because
//! section 10 makes each the owner's and says the account's own identity is not that owner's
//! confirmation:
//!
//! * **Adopting a repository's trust root.** A request to add a repository carries the owner's
//!   signed confirmation of exactly that root, and only an owner device produces one. So
//!   `kr plugin repo add` does not send a request it cannot complete: it says where a repository is
//!   added instead.
//! * **An installation that enlarges what a package may do,** beyond the installation it replaces
//!   or, with none to replace, beyond what its repository permits by itself, and every release that
//!   installs a native bridge or declares a command integration. `kr plugin install` asks without
//!   a confirmation, which is enough for an installation inside what is already permitted. When the
//!   daemon answers that the owner has to confirm this one, the command says so and stops: the
//!   confirmation is an owner device's own, given with the installation it confirms, so nothing is
//!   left waiting here for it.

use kr_client::error::refusal;
use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::paths::HostPaths;
use kr_protocol::catalogue::{
    CatalogueListParams, CatalogueListResult, CataloguePinParams, CataloguePinResult,
    CatalogueRemoveParams, CatalogueRemoveResult, CatalogueSummary, CatalogueSyncParams,
    CatalogueSyncResult, PluginAdmission, PluginEnableParams, PluginEnableResult,
    PluginInstallParams, PluginInstallResult, PluginLeftOutReason, PluginListParams,
    PluginListResult, PluginPinParams, PluginPinResult, PluginRemoveParams, PluginRemoveResult,
    PluginSummary,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{PluginId, RepositoryGeneration};
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;

use crate::cli::{
    PluginArguments, PluginCommand, PluginInstallArguments, PluginIntegrationCommand,
    PluginListArguments, PluginPinArguments, PluginRepoArguments, PluginRepoCommand,
    PluginRepoPinArguments,
};
use crate::daemon::{Daemon, identifier};
use crate::error::{CliError, Result};
use crate::output::{self, Asked, Document, Line, Request, left};
use crate::{answer, stdout_line};

/// Runs one `kr plugin` command and prints its result.
///
/// # Errors
///
/// Returns a usage mistake, the daemon's refusal, a refusal for a decision only an owner device
/// makes, or a transport failure.
pub async fn run(paths: &HostPaths, command: PluginCommand, json: bool) -> Result<()> {
    match command {
        PluginCommand::List(arguments) => list(paths, &arguments, json).await,
        PluginCommand::Install(arguments) => install(paths, &arguments, json).await,
        PluginCommand::Remove(arguments) => remove(paths, &arguments, json).await,
        PluginCommand::Pin(arguments) => pin(paths, &arguments, json).await,
        PluginCommand::Enable(arguments) => enable(paths, &arguments, true, json).await,
        PluginCommand::Disable(arguments) => enable(paths, &arguments, false, json).await,
        PluginCommand::Integration(command) => integration(paths, &command, json).await,
        PluginCommand::Repo(command) => repo(paths, command, json).await,
    }
}

/// `kr plugin integration enable` and `disable`.
///
/// One validated edit of the host's own `command_integrations` list in this environment's
/// configuration, written the way every preference is, and then the daemon's diagnostics, which is
/// what puts the document in force and says what a new session now applies and from which rung: a
/// profile's list, where one is selected, decides over the host's.
async fn integration(
    paths: &HostPaths,
    command: &PluginIntegrationCommand,
    json: bool,
) -> Result<()> {
    use kr_protocol::hostinfo::HostDoctorResult;
    use kr_protocol::hostinfo::configuration::{COMMAND_INTEGRATIONS, Change, ValueSource};

    let (arguments, enabled) = match command {
        PluginIntegrationCommand::Enable(arguments) => (arguments, true),
        PluginIntegrationCommand::Disable(arguments) => (arguments, false),
    };
    let plugin = plugin_identifier(&arguments.plugin)?;
    let environment = crate::resolve::select(paths, arguments.selector.environment.as_deref())?;
    let revision = crate::doctor::configuration::apply(
        &environment.paths,
        &Change::CommandIntegration {
            plugin_id: plugin.as_str().to_owned(),
            enabled,
        },
    )?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let diagnosed: HostDoctorResult = daemon.read(Method::HostDoctor, &()).await?;
    let in_force = diagnosed
        .configuration
        .values
        .iter()
        .find(|value| value.key == COMMAND_INTEGRATIONS.key);
    let reported = diagnosed
        .command_integrations
        .iter()
        .find(|report| report.plugin_id == plugin.as_str());
    if json {
        output::document(
            &Document::new()
                .with("ok", true)
                .with("environment_id", output::said(&daemon.environment_id()))
                .with("plugin_id", Asked::text(Request::Plugins, plugin.as_str()))
                .with("enabled", enabled)
                .with("revision", output::said(&revision))
                .with(
                    "in_force",
                    in_force.map(|value| {
                        Document::new()
                            .with("value", crate::doctor::value_said(value))
                            .with("source", value.source.as_str())
                            .with(
                                "origin",
                                value
                                    .origin
                                    .as_ref()
                                    .map(|origin| crate::doctor::origin_of(value.source, origin)),
                            )
                    }),
                )
                .with("integration", reported.map(crate::doctor::integration)),
        );
        return Ok(());
    }
    output::line(&stdout_line!(
        "{}'s command integration is {} in this host's list, for sessions created from now on \
         (configuration revision {})",
        Asked::text(Request::Plugins, plugin.as_str()),
        if enabled { "on" } else { "off" },
        revision
    ));
    if let Some(value) = in_force {
        output::line(&stdout_line!(
            "a new session applies the command integrations of: {}",
            crate::doctor::value_said(value)
        ));
        if value.source == ValueSource::Profile {
            output::line(&stdout_line!(
                "the selected profile's list decides that, over this host's own list; change the \
                 profile in the configuration document to change it"
            ));
        }
    }
    // What a session created now gets of this package's integration, as the doctor reports it.
    if let Some(reported) = reported {
        output::lines(&crate::doctor::integration_lines(reported, "", ""));
    }
    Ok(())
}

/// Runs one `kr plugin repo` command.
async fn repo(paths: &HostPaths, command: PluginRepoCommand, json: bool) -> Result<()> {
    match command {
        PluginRepoCommand::List(arguments) => repo_list(paths, &arguments, json).await,
        PluginRepoCommand::Add(_) => Err(repo_add()),
        PluginRepoCommand::Sync(arguments) => repo_sync(paths, &arguments, json).await,
        PluginRepoCommand::Pin(arguments) => repo_pin(paths, &arguments, json).await,
        PluginRepoCommand::Remove(arguments) => repo_remove(paths, &arguments, json).await,
    }
}

/// `kr plugin list`.
async fn list(paths: &HostPaths, arguments: &PluginListArguments, json: bool) -> Result<()> {
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let listed: PluginListResult = daemon
        .read(
            Method::PluginList,
            &PluginListParams {
                environment_id: daemon.environment_id(),
            },
        )
        .await?;
    if json {
        output::document(&answer::plugin_list_result(&listed));
    } else if listed.plugins.is_empty() {
        output::say(&Shown::said("no plugins installed"));
    } else {
        for plugin in &listed.plugins {
            output::line(&line(plugin));
        }
    }
    Ok(())
}

/// `kr plugin install`.
async fn install(paths: &HostPaths, arguments: &PluginInstallArguments, json: bool) -> Result<()> {
    let plugin = plugin_identifier(&arguments.plugin)?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let installed: std::result::Result<PluginInstallResult, CliError> = daemon
        .mutate(
            Method::PluginInstall,
            &PluginInstallParams {
                environment_id: daemon.environment_id(),
                catalogue_id: arguments.catalogue.clone(),
                plugin_id: plugin,
                version: arguments.version.clone(),
                package_digest: arguments.digest.clone(),
                grant: arguments.grant.clone(),
                // Nothing at this terminal can confirm on the owner's behalf. An installation that
                // needs the owner's confirmation is refused, and said to be refused, below.
                owner_confirmation: Nullable::null(),
            },
        )
        .await;
    let installed = match installed {
        Ok(installed) => installed,
        Err(CliError::Refused(refusal)) if refusal.code == ErrorCode::OwnerConfirmationRequired => {
            return Err(needs_owner_device(&refusal));
        }
        Err(error) => return Err(error),
    };
    if json {
        output::document(&answer::plugin_install_result(&installed));
        return Ok(());
    }
    output::line(&stdout_line!("Installed {}.", line(&installed.plugin)));
    for capability in &installed.capabilities {
        output::line(&stdout_line!(
            "  {} {} {}",
            left(
                32,
                &Asked::text(Request::Plugins, capability.capability.as_str())
            ),
            left(30, &crate::shown::wire_word(capability.requirement)),
            if capability.permitted {
                "permitted"
            } else {
                "not permitted"
            }
        ));
    }
    Ok(())
}

/// The refusal an installation that needs the owner's confirmation ends with.
fn needs_owner_device(host: &ProtocolError) -> CliError {
    CliError::Refused(refusal(
        ErrorCode::OwnerConfirmationRequired,
        shown!(
            "installing this release enlarges what the package may do, which only the owner \
             confirms: confirm it and install it from an owner device. Nothing was installed ({})",
            Shown::protocol(host)
        ),
    ))
}

/// `kr plugin remove`.
async fn remove(paths: &HostPaths, arguments: &PluginArguments, json: bool) -> Result<()> {
    let plugin = plugin_identifier(&arguments.plugin)?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let removed: PluginRemoveResult = daemon
        .mutate(
            Method::PluginRemove,
            &PluginRemoveParams {
                environment_id: daemon.environment_id(),
                plugin_id: plugin,
            },
        )
        .await?;
    if json {
        output::document(&answer::plugin_remove_result(&removed));
    } else {
        let plugin = Asked::text(Request::Plugins, &removed.plugin_id.to_string());
        match removed.affected_bindings.0 {
            Some(count) => output::line(&stdout_line!(
                "Removed {}; {} live binding{} told to end.",
                plugin,
                count.get(),
                if count.get() == 1 { "" } else { "s" }
            )),
            None => output::line(&stdout_line!(
                "Removed {}; a session has not yet said whether a live binding held it, and any \
                 that did is told to end.",
                plugin
            )),
        }
    }
    Ok(())
}

/// `kr plugin pin`.
async fn pin(paths: &HostPaths, arguments: &PluginPinArguments, json: bool) -> Result<()> {
    let plugin = plugin_identifier(&arguments.plugin)?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let pinned: PluginPinResult = daemon
        .mutate(
            Method::PluginPin,
            &PluginPinParams {
                environment_id: daemon.environment_id(),
                plugin_id: plugin,
                package_digest: arguments
                    .digest
                    .clone()
                    .map_or_else(Nullable::null, Nullable::some),
            },
        )
        .await?;
    if json {
        output::document(&answer::plugin_pin_result(&pinned));
    } else {
        output::line(&line(&pinned.plugin));
    }
    Ok(())
}

/// `kr plugin enable` and `kr plugin disable`.
async fn enable(
    paths: &HostPaths,
    arguments: &PluginArguments,
    enabled: bool,
    json: bool,
) -> Result<()> {
    let plugin = plugin_identifier(&arguments.plugin)?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let changed: PluginEnableResult = daemon
        .mutate(
            if enabled {
                Method::PluginEnable
            } else {
                Method::PluginDisable
            },
            &PluginEnableParams {
                environment_id: daemon.environment_id(),
                plugin_id: plugin,
            },
        )
        .await?;
    if json {
        output::document(&answer::plugin_enable_result(&changed));
    } else {
        output::line(&line(&changed.plugin));
    }
    Ok(())
}

/// `kr plugin repo list`.
async fn repo_list(paths: &HostPaths, arguments: &PluginListArguments, json: bool) -> Result<()> {
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let listed: CatalogueListResult = daemon
        .read(
            Method::CatalogueList,
            &CatalogueListParams {
                environment_id: daemon.environment_id(),
            },
        )
        .await?;
    if json {
        output::document(&answer::catalogue_list_result(&listed));
    } else if listed.catalogues.is_empty() {
        output::say(&Shown::said("no plugin repositories"));
    } else {
        for catalogue in &listed.catalogues {
            output::line(&repo_line(catalogue));
        }
    }
    Ok(())
}

/// `kr plugin repo add`, which is refused before anything is sent.
///
/// A request to add a repository carries the owner's signed confirmation of the exact root it
/// adopts, and there is no such request without one. Only an owner device signs one.
fn repo_add() -> CliError {
    CliError::Refused(refusal(
        ErrorCode::OwnerConfirmationRequired,
        Shown::said(
            "adding a repository adopts its trust root, which only the owner confirms, on an \
             owner device: add it from an owner device. Nothing was sent to this host",
        ),
    ))
}

/// `kr plugin repo sync`.
async fn repo_sync(paths: &HostPaths, arguments: &PluginRepoArguments, json: bool) -> Result<()> {
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let synced: CatalogueSyncResult = daemon
        .mutate(
            Method::CatalogueSync,
            &CatalogueSyncParams {
                environment_id: daemon.environment_id(),
                catalogue_id: arguments.catalogue.clone(),
            },
        )
        .await?;
    if json {
        output::document(&answer::catalogue_sync_result(&synced));
    } else {
        output::line(&stdout_line!(
            "{} is at generation {}, with {} entries.",
            Asked::text(Request::Plugins, &arguments.catalogue),
            output::closed_word(&synced.generation),
            synced.entries.get()
        ));
    }
    Ok(())
}

/// `kr plugin repo pin`.
async fn repo_pin(paths: &HostPaths, arguments: &PluginRepoPinArguments, json: bool) -> Result<()> {
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let pinned: CataloguePinResult = daemon
        .mutate(
            Method::CataloguePin,
            &CataloguePinParams {
                environment_id: daemon.environment_id(),
                catalogue_id: arguments.catalogue.clone(),
                generation: arguments
                    .generation
                    .map(RepositoryGeneration::new)
                    .map_or_else(Nullable::null, Nullable::some),
            },
        )
        .await?;
    if json {
        output::document(&answer::catalogue_pin_result(&pinned));
    } else {
        output::line(&repo_line(&pinned.catalogue));
    }
    Ok(())
}

/// `kr plugin repo remove`.
async fn repo_remove(paths: &HostPaths, arguments: &PluginRepoArguments, json: bool) -> Result<()> {
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let removed: CatalogueRemoveResult = daemon
        .mutate(
            Method::CatalogueRemove,
            &CatalogueRemoveParams {
                environment_id: daemon.environment_id(),
                catalogue_id: arguments.catalogue.clone(),
            },
        )
        .await?;
    if json {
        output::document(&answer::catalogue_remove_result(&removed));
        return Ok(());
    }
    output::line(&stdout_line!(
        "Removed {}; its root is no longer trusted.",
        Asked::text(Request::Plugins, &removed.catalogue_id)
    ));
    for plugin in &removed.installed_packages {
        output::line(&stdout_line!(
            "still installed from it: {}",
            Asked::text(Request::Plugins, &plugin.to_string())
        ));
    }
    Ok(())
}

fn plugin_identifier(text: &str) -> Result<PluginId> {
    identifier(text, "a plugin")
}

/// One installed plugin as a line for a person: its identifier, version and repository are what
/// the person asked about.
fn line(plugin: &PluginSummary) -> Line {
    let mut states = vec![if plugin.enabled {
        "enabled"
    } else {
        "disabled"
    }];
    if plugin.pinned {
        states.push("pinned");
    }
    if plugin.revoked {
        states.push("revoked by its repository");
    }
    if let Some(PluginAdmission::LeftOut { reason, .. }) = &plugin.admission.0 {
        match reason {
            // What the states above already say.
            PluginLeftOutReason::Disabled | PluginLeftOutReason::Revoked => {}
            PluginLeftOutReason::NotAllowed => {
                states.push("not admitted: not among the adapters the organisation allows");
            }
            PluginLeftOutReason::Unsupported => states.push("not admitted: not for this host"),
            PluginLeftOutReason::Incomplete => {
                states.push("not admitted: not whole in this host's store");
            }
            PluginLeftOutReason::PastALimit => states.push("not admitted: past a package limit"),
            PluginLeftOutReason::Unrecordable => {
                states.push("not admitted: cannot be handed to a session");
            }
        }
    }
    stdout_line!(
        "{} {} from {} ({})",
        Asked::text(Request::Plugins, &plugin.plugin_id.to_string()),
        Asked::text(Request::Plugins, &plugin.version),
        Asked::text(Request::Plugins, &plugin.catalogue_id),
        Shown::joined(states.into_iter().map(Shown::said), ", ")
    )
}

/// One repository as a line for a person: its identifier and its metadata's location, which is
/// said without user information, a query or a fragment.
fn repo_line(catalogue: &CatalogueSummary) -> Line {
    let generation = catalogue.generation.as_ref().map_or_else(
        || Shown::said("no generation yet"),
        |generation| shown!("generation {}", output::closed_word(generation)),
    );
    let pinned = catalogue.pinned_generation.as_ref().map_or_else(
        || Shown::said(""),
        |generation| shown!(", pinned at {}", output::closed_word(generation)),
    );
    stdout_line!(
        "{}  {}  {}{}, {} entries  {}",
        Asked::text(Request::Plugins, &catalogue.catalogue_id),
        crate::shown::wire_word(catalogue.kind),
        generation,
        pinned,
        catalogue.entries.get(),
        Asked::location(Request::Plugins, &catalogue.metadata_url)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KR-REQ-23.25: planted text in a plugin's or a repository's line shows only where the person
    /// asked for it: the plugin, its version and its repository, and a repository's metadata
    /// location without user information, a query or a fragment.
    #[test]
    fn planted_text_in_plugin_lines_shows_only_where_it_was_asked_for() {
        for plugin in crate::output::planted::planted::<PluginSummary>() {
            crate::output::planted::only_asked_lines("kr plugin list", &[line(&plugin)]);
        }
        for catalogue in crate::output::planted::planted::<CatalogueSummary>() {
            crate::output::planted::only_asked_lines(
                "kr plugin repo list",
                &[repo_line(&catalogue)],
            );
        }
    }

    fn summary(admission: Nullable<PluginAdmission>) -> PluginSummary {
        PluginSummary {
            plugin_id: PluginId::new("kalareach/example-declarative").expect("a package"),
            catalogue_id: "development".to_owned(),
            version: "0.1.0".to_owned(),
            package_digest: "00".repeat(32),
            environment_id: kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid()),
            enabled: true,
            pinned: false,
            revoked: false,
            live_bindings: Nullable::null(),
            admission,
        }
    }

    /// A package the host leaves out says so beside its other states, and one it admits, or whose
    /// admission the answer does not say, says nothing more.
    #[test]
    fn a_line_says_why_the_host_leaves_a_package_out() {
        let past = summary(Nullable::some(PluginAdmission::LeftOut {
            reason: PluginLeftOutReason::PastALimit,
            detail: "past package_bytes".to_owned(),
        }));
        assert_eq!(
            line(&past).text(),
            "kalareach/example-declarative 0.1.0 from development (enabled, not admitted: past a \
             package limit)"
        );
        for admission in [Nullable::some(PluginAdmission::Admitted), Nullable::null()] {
            assert_eq!(
                line(&summary(admission)).text(),
                "kalareach/example-declarative 0.1.0 from development (enabled)"
            );
        }
    }
}
