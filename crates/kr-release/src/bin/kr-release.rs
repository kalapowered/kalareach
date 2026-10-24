//! Builds a release's manifest from its tree, signs it and checks it.
//!
//! ```text
//! kr-release manifest --tree T --checkout C --release R --sequence N --commit SHA --target TRIPLE --floor macos=14.0
//! kr-release record   --tree T --checkout C --target TRIPLE [--plugins DIR] [--web DIR]
//! kr-release check    --tree T --checkout C [--plugins DIR] [--web DIR]
//! kr-release sign     --tree T --checkout C --key KEY... [--plugins DIR] [--web DIR]
//! kr-release verify   --tree T --root ROOT
//! kr-release dev-keys --out DIR --signers N
//! ```
//!
//! `manifest` writes `release.json` with no signature. `sign` assembles the manifest again, refuses
//! to sign a `release.json` that is not what the tree now makes, and signs it with each key.
//! `verify` is a host's own check of a release: the signatures against the update channel's root,
//! then every file against the manifest. `dev-keys` makes a root and the keys that sign for it, for
//! a run that signs with nothing but keys of its own: a key for each of the root, snapshot and
//! timestamp roles, and as many for the targets role as must sign.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use kr_protocol::update::{
    CommitId, FloorSystem, FloorVersion, MANIFEST_FILE, OsFloor, ReleaseManifest, ReleaseName,
    SignedMembers,
};
use kr_release::assemble::{Inputs, assemble};
use kr_release::record;
use kr_release::{Refusal, Result};

#[derive(Parser)]
#[command(
    name = "kr-release",
    about = "Builds, signs and checks a KalaReach release"
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Writes `release.json`, unsigned, for a tree.
    Manifest {
        #[arg(long)]
        tree: PathBuf,
        #[arg(long)]
        checkout: PathBuf,
        #[arg(long)]
        release: String,
        #[arg(long)]
        sequence: u64,
        #[arg(long)]
        commit: String,
        #[arg(long)]
        target: String,
        /// The oldest operating system: `macos=14.0`, `glibc=2.35` or `windows=10.0`.
        #[arg(long)]
        floor: String,
    },
    /// Writes the release record into a tree.
    Record {
        #[arg(long)]
        tree: PathBuf,
        #[arg(long)]
        checkout: PathBuf,
        #[arg(long)]
        target: String,
        #[command(flatten)]
        elsewhere: Elsewhere,
        /// Lets a class of the record stay pending, which a release does not.
        #[arg(long)]
        development: bool,
    },
    /// Refuses a tree whose `release.json` is not what the tree now makes.
    Check {
        #[arg(long)]
        tree: PathBuf,
        #[arg(long)]
        checkout: PathBuf,
        #[command(flatten)]
        elsewhere: Elsewhere,
        #[arg(long)]
        development: bool,
    },
    /// Checks the tree, and signs `release.json` with each key.
    Sign {
        #[arg(long)]
        tree: PathBuf,
        #[arg(long)]
        checkout: PathBuf,
        /// A signing key: a PKCS #8 key file.
        #[arg(long = "key", required = true)]
        keys: Vec<PathBuf>,
        #[command(flatten)]
        elsewhere: Elsewhere,
        /// Signs a record that has a class pending, which only a development run does.
        #[arg(long)]
        development: bool,
    },
    /// Checks a signed release the way a host does.
    Verify {
        #[arg(long)]
        tree: PathBuf,
        /// The update channel's root.
        #[arg(long)]
        root: PathBuf,
    },
    /// Makes a root and the keys that sign for it, in a directory of their own. Each role of the
    /// root has a key of its own.
    DevKeys {
        #[arg(long)]
        out: PathBuf,
        /// How many keys must sign a release, and how many are made.
        #[arg(long, default_value_t = 2)]
        signers: u64,
    },
}

/// The other repositories' checkouts, where they are at hand.
#[derive(clap::Args)]
struct Elsewhere {
    /// A checkout of the plugins repository, to read the records cited from it.
    #[arg(long)]
    plugins: Option<PathBuf>,
    /// A checkout of the web repository, to read the records cited from it.
    #[arg(long)]
    web: Option<PathBuf>,
}

impl Elsewhere {
    fn at_hand(self) -> record::Elsewhere {
        record::Elsewhere {
            plugins: self.plugins,
            web: self.web,
        }
    }
}

fn main() -> ExitCode {
    match run(Arguments::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Refusal(why)) => {
            eprintln!("kr-release: {why}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<()> {
    match command {
        Command::Manifest {
            tree,
            checkout,
            release,
            sequence,
            commit,
            target,
            floor,
        } => {
            let inputs = Inputs {
                tree: tree.clone(),
                checkout,
                release: ReleaseName::new(release)
                    .map_err(|error| Refusal(format!("the release name: {error}")))?,
                sequence,
                commit: CommitId::new(commit)
                    .map_err(|error| Refusal(format!("the commit: {error}")))?,
                target,
                os_floor: floor_of(&floor)?,
            };
            let manifest = assemble(&inputs)?;
            write(&tree, &SignedMembers::of(&manifest).map_err(refusal)?, &[])
        }
        Command::Record {
            tree,
            checkout,
            target,
            elsewhere,
            development,
        } => record::write(
            &tree,
            &record::build(&checkout, &target, &elsewhere.at_hand(), development)?,
        ),
        Command::Check {
            tree,
            checkout,
            elsewhere,
            development,
        } => {
            let (document, _) = read_release(&tree)?;
            fresh(
                &tree,
                &checkout,
                &document,
                &elsewhere.at_hand(),
                development,
            )?;
            Ok(())
        }
        Command::Sign {
            tree,
            checkout,
            keys,
            elsewhere,
            development,
        } => {
            let (document, _) = read_release(&tree)?;
            let members = fresh(
                &tree,
                &checkout,
                &document,
                &elsewhere.at_hand(),
                development,
            )?;
            let signed = sign(&members, &keys)?;
            std::fs::write(tree.join(MANIFEST_FILE), signed).map_err(refusal)
        }
        Command::Verify { tree, root } => verify(&tree, &root),
        Command::DevKeys { out, signers } => dev_keys(&out, signers),
    }
}

fn refusal(error: impl std::fmt::Display) -> Refusal {
    Refusal(error.to_string())
}

fn floor_of(text: &str) -> Result<OsFloor> {
    let (system, version) = text
        .split_once('=')
        .ok_or_else(|| Refusal(format!("`{text}` is not `<system>=<version>`")))?;
    let system = match system {
        "macos" => FloorSystem::Macos,
        "glibc" => FloorSystem::Glibc,
        "windows" => FloorSystem::Windows,
        other => return Err(Refusal(format!("`{other}` is not a system with a floor"))),
    };
    let version = FloorVersion::leading(version)
        .ok_or_else(|| Refusal(format!("`{version}` is not a version")))?;
    Ok(OsFloor { system, version })
}

/// A tree's `release.json`: the members it holds, whatever signatures it carries.
#[derive(serde::Deserialize)]
struct Document {
    signed: SignedMembers,
}

fn read_release(tree: &Path) -> Result<(Document, Vec<u8>)> {
    let path = tree.join(MANIFEST_FILE);
    let bytes = std::fs::read(&path)
        .map_err(|error| Refusal(format!("{} cannot be read: {error}", path.display())))?;
    let document = serde_json::from_slice(&bytes)
        .map_err(|error| Refusal(format!("{} is not a manifest: {error}", path.display())))?;
    Ok((document, bytes))
}

fn write(tree: &Path, members: &SignedMembers, signatures: &[serde_json::Value]) -> Result<()> {
    let text = serde_json::to_string_pretty(&serde_json::json!({
        "signed": members,
        "signatures": signatures,
    }))
    .map_err(refusal)?;
    std::fs::write(tree.join(MANIFEST_FILE), text).map_err(refusal)
}

/// The members the tree makes now, refused unless they are the ones `release.json` holds.
fn fresh(
    tree: &Path,
    checkout: &Path,
    document: &Document,
    elsewhere: &record::Elsewhere,
    development: bool,
) -> Result<SignedMembers> {
    let written: ReleaseManifest = document
        .signed
        .manifest()
        .map_err(|error| Refusal(format!("release.json is not a release's manifest: {error}")))?;
    record::held(tree, checkout, &written.target, elsewhere, development)?;
    let manifest = assemble(&Inputs {
        tree: tree.to_path_buf(),
        checkout: checkout.to_path_buf(),
        release: written.release,
        sequence: written.sequence.get(),
        commit: written.commit,
        target: written.target,
        os_floor: written.os_floor,
    })?;
    let members = SignedMembers::of(&manifest).map_err(refusal)?;
    if members != document.signed {
        return Err(Refusal(
            "release.json is not what the tree and the repository now make: something changed \
             after the manifest was written, and a manifest for it is written again before it is \
             signed"
                .to_owned(),
        ));
    }
    Ok(members)
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(refusal)
}

fn sign(members: &SignedMembers, keys: &[PathBuf]) -> Result<String> {
    use tough::key_source::{KeySource as _, LocalKeySource};

    let runtime = runtime()?;
    let mut signers = Vec::new();
    for path in keys {
        let source = LocalKeySource { path: path.clone() };
        signers.push(runtime.block_on(source.as_sign()).map_err(|error| {
            Refusal(format!("{} is not a signing key: {error}", path.display()))
        })?);
    }
    let borrowed: Vec<&dyn tough::sign::Sign> = signers.iter().map(AsRef::as_ref).collect();
    runtime
        .block_on(kr_release::sign_manifest(members, &borrowed))
        .map_err(refusal)
}

fn verify(tree: &Path, root: &Path) -> Result<()> {
    let root_bytes = std::fs::read(root)
        .map_err(|error| Refusal(format!("{} cannot be read: {error}", root.display())))?;
    let signed_root: tough::schema::Signed<tough::schema::Root> =
        serde_json::from_slice(&root_bytes)
            .map_err(|error| Refusal(format!("{} is not a root: {error}", root.display())))?;
    kr_release::verify_root_itself(&signed_root).map_err(refusal)?;
    let (_, bytes) = read_release(tree)?;
    let members = kr_release::verify_manifest(&signed_root.signed, &bytes).map_err(refusal)?;
    let manifest = members
        .manifest()
        .map_err(|error| Refusal(format!("release.json is not a release's manifest: {error}")))?;
    kr_release::assemble::check_files(tree, &manifest)
}

fn dev_keys(out: &Path, signers: u64) -> Result<()> {
    kr_release::dev::write_keys(out, signers)
}
