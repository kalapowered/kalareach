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
//!   installs a native bridge. `kr plugin install` asks without a confirmation, which is enough for
//!   an installation inside what is already permitted. When the daemon answers that the owner has to
//!   confirm this one, the command says so and stops: the confirmation is an owner device's own,
//!   given with the installation it confirms, so nothing is left waiting here for it.

use kr_ipc::paths::HostPaths;
use kr_protocol::catalogue::{
    CatalogueListParams, CatalogueListResult, CataloguePinParams, CataloguePinResult,
    CatalogueRemoveParams, CatalogueRemoveResult, CatalogueSummary, CatalogueSyncParams,
    CatalogueSyncResult, PluginEnableParams, PluginEnableResult, PluginInstallParams,
    PluginInstallResult, PluginListParams, PluginListResult, PluginPinParams, PluginPinResult,
    PluginRemoveParams, PluginRemoveResult, PluginSummary,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{PluginId, RepositoryGeneration};
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;

use crate::cli::{
    PluginArguments, PluginCommand, PluginInstallArguments, PluginListArguments,
    PluginPinArguments, PluginRepoAddArguments, PluginRepoArguments, PluginRepoCommand,
    PluginRepoPinArguments,
};
use crate::daemon::{Daemon, identifier};
use crate::error::{CliError, Result};
use crate::report;

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
        PluginCommand::Repo(command) => repo(paths, command, json).await,
    }
}

/// Runs one `kr plugin repo` command.
async fn repo(paths: &HostPaths, command: PluginRepoCommand, json: bool) -> Result<()> {
    match command {
        PluginRepoCommand::List(arguments) => repo_list(paths, &arguments, json).await,
        PluginRepoCommand::Add(arguments) => Err(repo_add(&arguments)),
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
        report::print_json(&report::answer(&listed)?);
    } else if listed.plugins.is_empty() {
        println!("no plugins installed");
    } else {
        for plugin in &listed.plugins {
            println!("{}", line(plugin));
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
            return Err(needs_owner_device(arguments, &refusal));
        }
        Err(error) => return Err(error),
    };
    if json {
        report::print_json(&report::answer(&installed)?);
        return Ok(());
    }
    println!("Installed {}.", line(&installed.plugin));
    for capability in &installed.capabilities {
        println!(
            "  {:<32} {:<30} {}",
            capability.capability.as_str(),
            report::wire_name(&capability.requirement),
            if capability.permitted {
                "permitted"
            } else {
                "not permitted"
            }
        );
    }
    Ok(())
}

/// The refusal an installation that needs the owner's confirmation ends with.
fn needs_owner_device(arguments: &PluginInstallArguments, host: &ProtocolError) -> CliError {
    CliError::Refused(ProtocolError::new(
        ErrorCode::OwnerConfirmationRequired,
        format!(
            "installing {} {} from {} enlarges what it may do, which only the owner confirms: \
             confirm it and install it from an owner device. Nothing was installed ({})",
            arguments.plugin, arguments.version, arguments.catalogue, host.message
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
        report::print_json(&report::answer(&removed)?);
    } else {
        println!(
            "Removed {}; {} live binding{} closed.",
            removed.plugin_id,
            removed.closed_bindings.get(),
            if removed.closed_bindings.get() == 1 {
                ""
            } else {
                "s"
            }
        );
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
        report::print_json(&report::answer(&pinned)?);
    } else {
        println!("{}", line(&pinned.plugin));
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
        report::print_json(&report::answer(&changed)?);
    } else {
        println!("{}", line(&changed.plugin));
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
        report::print_json(&report::answer(&listed)?);
    } else if listed.catalogues.is_empty() {
        println!("no plugin repositories");
    } else {
        for catalogue in &listed.catalogues {
            println!("{}", repo_line(catalogue));
        }
    }
    Ok(())
}

/// `kr plugin repo add`, which is refused before anything is sent.
///
/// A request to add a repository carries the owner's signed confirmation of the exact root it
/// adopts, and there is no such request without one. Only an owner device signs one.
fn repo_add(arguments: &PluginRepoAddArguments) -> CliError {
    CliError::Refused(ProtocolError::new(
        ErrorCode::OwnerConfirmationRequired,
        format!(
            "adding the repository {} adopts its trust root, which only the owner confirms, on an \
             owner device: add it from an owner device. Nothing was sent to this host",
            arguments.catalogue
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
        report::print_json(&report::answer(&synced)?);
    } else {
        println!(
            "{} is at generation {}, with {} entries.",
            arguments.catalogue,
            synced.generation,
            synced.entries.get()
        );
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
        report::print_json(&report::answer(&pinned)?);
    } else {
        println!("{}", repo_line(&pinned.catalogue));
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
        report::print_json(&report::answer(&removed)?);
        return Ok(());
    }
    println!(
        "Removed {}; its root is no longer trusted.",
        removed.catalogue_id
    );
    for plugin in &removed.installed_packages {
        println!("still installed from it: {plugin}");
    }
    Ok(())
}

fn plugin_identifier(text: &str) -> Result<PluginId> {
    identifier(text, "a plugin")
}

/// One installed plugin as a line for a person.
fn line(plugin: &PluginSummary) -> String {
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
    format!(
        "{} {} from {} ({})",
        plugin.plugin_id,
        plugin.version,
        plugin.catalogue_id,
        states.join(", ")
    )
}

/// One repository as a line for a person.
fn repo_line(catalogue: &CatalogueSummary) -> String {
    let generation = catalogue.generation.as_ref().map_or_else(
        || "no generation yet".to_owned(),
        |generation| format!("generation {generation}"),
    );
    let pinned = catalogue
        .pinned_generation
        .as_ref()
        .map_or_else(String::new, |generation| {
            format!(", pinned at {generation}")
        });
    format!(
        "{}  {}  {generation}{pinned}, {} entries  {}",
        catalogue.catalogue_id,
        report::wire_name(&catalogue.kind),
        catalogue.entries.get(),
        catalogue.metadata_url
    )
}
