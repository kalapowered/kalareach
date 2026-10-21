//! The shell packages of a release tree, held to the pins they were built from.
//!
//! A package's directory under `shells/<shell>/<identity>/` holds a build and the identity record
//! the build wrote. The release states what the package is made of: the upstream release, every
//! reader patch with its own revision and the upstream revision it applies to, the bridge sources,
//! the module trees and how a host starts it. Each of those is read from the repository's pins for
//! the shell and held to the record. A package whose record disagrees with a pin, whose build was
//! made from other inputs than the checkout holds, or whose module directory is missing is refused
//! before the manifest is written, so it cannot be signed.

use std::path::{Path, PathBuf};

use kr_protocol::update::{
    ReleaseModule, ReleasePatch, ReleasePath, ReleaseShell, ReleaseSource, ShellUpstream,
};
use kr_shell_integration::host::package::ShellPackage;
use serde_json::Value;

use crate::profile::profile_order;
use crate::refusal::{
    Refusal, Result, digest_file, digest_from_hex, hex, read_json, read_text, refuse, scalar,
};

/// The shells whose packages this tool builds a release from.
const BUILT: [&str; 3] = ["zsh", "bash", "fish"];

/// Every shell package of the tree, sorted by shell.
///
/// # Errors
///
/// Returns a refusal naming the package and the first thing it disagrees with.
pub fn packages(tree: &Path, checkout: &Path) -> Result<Vec<ReleaseShell>> {
    let directory = tree.join("shells");
    let mut shells = Vec::new();
    let Ok(entries) = std::fs::read_dir(&directory) else {
        return Ok(shells);
    };
    let mut names: Vec<String> = entries
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    for name in names {
        // The PowerShell package is files only: a host qualifies it against the editor it finds, so
        // there is no build to state, and its files are listed with the release's own.
        if name == "psreadline" {
            continue;
        }
        if !BUILT.contains(&name.as_str()) {
            refuse!("shells/{name} is not a shell package this tool assembles");
        }
        shells.push(package(tree, checkout, &name)?);
    }
    Ok(shells)
}

/// One package, held to its pins.
fn package(tree: &Path, checkout: &Path, shell: &str) -> Result<ReleaseShell> {
    let shell_directory = tree.join("shells").join(shell);
    let identity = read_text(&shell_directory.join("current"))?
        .trim()
        .to_owned();
    if identity.is_empty() || identity.contains('/') {
        refuse!("shells/{shell}/current names no identity");
    }
    let package_directory = shell_directory.join(&identity);
    let record = read_json(&package_directory.join("kr-shell-identity.json"))?;
    let pins_directory = checkout.join("shells").join(shell);
    let pins = read_json(&pins_directory.join("manifest.json"))?;
    let named = format!("shells/{shell}/{identity}");
    let at = |what: &str| format!("{named}: {what}");

    if record["identity"] != identity.as_str() || record["shell"]["kind"] != shell {
        refuse!("{}", at("its record names another package"));
    }

    // The upstream release.
    let upstream = &pins["upstream"];
    let pinned_sha = text(&upstream["sha256"])?;
    if record["build"]["upstream"]["sha256"] != pinned_sha.as_str()
        || record["build"]["upstream"]["archive"] != upstream["archive"]
    {
        refuse!(
            "{}",
            at("it was built from another upstream archive than the one the pins name")
        );
    }
    if record["shell"]["upstream_version"] != upstream["version"] {
        refuse!("{}", at("it says another upstream version than the pins"));
    }
    let base_revision = text(&upstream["revision"])?;

    // The reader patches, in order.
    let pinned_patches = array(&pins["patches"])?;
    let recorded_patches = array(&record["shell"]["patches"])?;
    if pinned_patches.len() != recorded_patches.len() {
        refuse!(
            "{}",
            at(&format!(
                "it was built with {} reader patches and the pins name {}",
                recorded_patches.len(),
                pinned_patches.len()
            ))
        );
    }
    let mut patches = Vec::new();
    for (pinned, recorded) in pinned_patches.iter().zip(recorded_patches) {
        let name = text(&pinned["name"])?;
        if recorded["name"] != name.as_str()
            || recorded["revision"] != pinned["revision"]
            || recorded["upstream_revision"] != base_revision.as_str()
        {
            refuse!(
                "{}",
                at(&format!(
                    "reader patch {name} is not the patch revision and upstream revision the \
                     pins name"
                ))
            );
        }
        patches.push(ReleasePatch {
            name,
            revision: text(&pinned["revision"])?,
            base_revision: base_revision.clone(),
            source_commit: pinned
                .get("upstream_revision")
                .and_then(Value::as_str)
                .map(str::to_owned),
            sha256: scalar(digest_file(&pins_directory.join(text(&pinned["file"])?))?),
        });
    }

    // The sources the build added, and that the build was made from this checkout's.
    let mut sources = Vec::new();
    for pinned in array(&pins["sources"])? {
        let file = text(&pinned["file"])?;
        sources.push(ReleaseSource {
            sha256: scalar(digest_file(&pins_directory.join(&file))?),
            file,
        });
    }
    held_to_the_checkout(checkout, &pins_directory, shell, &pins, &record)
        .map_err(|Refusal(why)| Refusal(at(&why)))?;

    // The startup entry in the tree is the checkout's.
    let entry = text(&pins["startup"]["file"])?;
    if digest_file(&package_directory.join(&entry))? != digest_file(&pins_directory.join(&entry))? {
        refuse!(
            "{}",
            at(&format!("its startup entry {entry} is not the checkout's"))
        );
    }

    // The module trees, where the shell searches for them.
    let build_root = build_root(&record, shell, &identity)?;
    let mut modules = Vec::new();
    for module in array(&record["shell"]["modules"])? {
        let recorded = PathBuf::from(text(&module["search_path"])?);
        let relative = recorded.strip_prefix(&build_root).map_err(|_| {
            Refusal(at(&format!(
                "module {} is searched for in {}, outside the package",
                text(&module["name"]).unwrap_or_default(),
                recorded.display()
            )))
        })?;
        let directory = package_directory.join(relative);
        if !has_a_file(&directory) {
            refuse!(
                "{}",
                at(&format!(
                    "the module directory {} is missing or empty",
                    relative.display()
                ))
            );
        }
        if module["editor_abi"] != pins["editor_abi"] {
            refuse!(
                "{}",
                at(&format!(
                    "module {} was built for another editor ABI than the package's",
                    text(&module["name"])?
                ))
            );
        }
        let in_release = format!(
            "shells/{shell}/{identity}/{}",
            relative.to_string_lossy().trim_end_matches('/')
        );
        modules.push(ReleaseModule {
            name: text(&module["name"])?,
            search_path: ReleasePath::new(in_release)
                .map_err(|error| Refusal(at(&error.to_string())))?,
            editor_abi: text(&module["editor_abi"])?,
        });
    }

    let launched = ShellPackage::read(&package_directory)
        .map_err(|fault| Refusal(at(&format!("a worker cannot read the package: {fault}"))))?;
    Ok(ReleaseShell {
        shell: shell.to_owned(),
        identity,
        upstream: ShellUpstream {
            version: text(&upstream["version"])?,
            revision: base_revision,
            archive: text(&upstream["archive"])?,
            sha256: scalar(digest_from_hex(&pinned_sha)?),
        },
        patches,
        sources,
        modules,
        profile_order: profile_order(&launched).map_err(|Refusal(why)| Refusal(at(&why)))?,
    })
}

/// Holds the inputs the build recorded to the checkout's: the build script, the manifest, every
/// patch, every source and the startup entry.
///
/// A package is the checkout's only when it was built from these; the identity is a digest of
/// them, so a package of other inputs would carry another identity, but a record can be edited and
/// a cache can hold a build of another tree.
fn held_to_the_checkout(
    checkout: &Path,
    pins_directory: &Path,
    shell: &str,
    pins: &Value,
    record: &Value,
) -> Result<()> {
    let mut expected = vec![
        format!("shell={shell}"),
        format!(
            "manifest={}",
            hex(&digest_file(&pins_directory.join("manifest.json"))?)
        ),
        format!(
            "script={}",
            hex(&digest_file(&checkout.join("scripts/build-shells.sh"))?)
        ),
        format!(
            "upstream={} {}",
            text(&pins["upstream"]["sha256"])?,
            text(&pins["upstream"]["archive"])?
        ),
    ];
    for patch in array(&pins["patches"])? {
        let file = text(&patch["file"])?;
        expected.push(format!(
            "patch={} {file}",
            hex(&digest_file(&pins_directory.join(&file))?)
        ));
    }
    for source in array(&pins["sources"])? {
        expected.push(format!(
            "source={} {}",
            hex(&digest_file(&pins_directory.join(text(&source["file"])?))?),
            text(&source["install"])?
        ));
    }
    let startup = text(&pins["startup"]["file"])?;
    expected.push(format!(
        "startup={} {startup}",
        hex(&digest_file(&pins_directory.join(&startup))?)
    ));

    let inputs = record["build"]["inputs"].as_str().ok_or_else(|| {
        Refusal("its record does not hold the inputs it was built from".to_owned())
    })?;
    let kept = [
        "shell=",
        "manifest=",
        "script=",
        "upstream=",
        "patch=",
        "source=",
        "startup=",
    ];
    let recorded: Vec<&str> = inputs
        .lines()
        .filter(|line| kept.iter().any(|key| line.starts_with(key)))
        .collect();
    for (index, line) in expected.iter().enumerate() {
        if recorded.get(index) != Some(&line.as_str()) {
            refuse!(
                "it was built from other inputs than this checkout's: the build recorded `{}` \
                 where the checkout has `{line}`",
                recorded.get(index).copied().unwrap_or("nothing")
            );
        }
    }
    if recorded.len() != expected.len() {
        refuse!("it was built from more inputs than this checkout's");
    }
    Ok(())
}

/// The directory the build installed the package in, from the executable it recorded.
fn build_root(record: &Value, shell: &str, identity: &str) -> Result<PathBuf> {
    let executable = PathBuf::from(text(&record["shell"]["executable"])?);
    let mut ancestor = executable.as_path();
    while let Some(parent) = ancestor.parent() {
        let named = parent.file_name().is_some_and(|name| name == identity);
        let under = parent
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == shell);
        if named && under {
            return Ok(parent.to_path_buf());
        }
        ancestor = parent;
    }
    refuse!(
        "shells/{shell}/{identity}: its record's executable is in no directory of that identity"
    )
}

/// Whether a directory holds a file at any depth.
fn has_a_file(directory: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return false;
    };
    entries.filter_map(std::result::Result::ok).any(|entry| {
        entry
            .file_type()
            .is_ok_and(|kind| kind.is_file() || (kind.is_dir() && has_a_file(&entry.path())))
    })
}

fn text(value: &Value) -> Result<String> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| Refusal(format!("`{value}` is not text")))
}

fn array(value: &Value) -> Result<&Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| Refusal(format!("`{value}` is not a list")))
}
