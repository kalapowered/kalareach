//! What the control daemon admitted, as this worker holds it, and the reports it makes about its
//! live bindings.
//!
//! The daemon decides what is admitted; this worker reads each admitted package itself, from its
//! checked copy, once per package hash, with the same package check a publisher's build runs, and
//! takes the match rules, the actions, the connector table and the command integration from that
//! verified manifest. A snapshot is applied whole and only when its frame is above the one held,
//! comparing the daemon generation, then the admission revision, then the round; an older one
//! changes nothing and is answered with the frame held.
//!
//! What a package's hash names (its verified files) is read once and kept. What its installation
//! grants (the capabilities, the native bridge, the signed builds) is taken from each snapshot and
//! never kept from an earlier one, so a withdrawal reaches the connector with the next snapshot,
//! and a refusal that belongs to one snapshot (two connectors claiming one command) goes with it.
//!
//! Each report is numbered, and the number rises with every report this process makes, so two
//! reports that name one applied frame are ordered too. Free text in a report (why a package was
//! refused) is cut at a character boundary to [`MAX_REPORT_DETAIL_BYTES`] and marked as cut, so a
//! report's records are bounded like the snapshot's, and a report is at most
//! [`MAX_ADMISSION_PARTS`] parts.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::plugin::{PayloadRole, PluginManifest};
use kr_protocol::admission::{
    AdmissionsHeader, AdmittedPackage, FrameId, LiveBinding, PackageRefusal, PluginAdmissions,
    PluginAdmissionsAck, ReleaseState, RevocationPolicy,
};
use kr_protocol::envelope::ControlFrame;
use kr_protocol::ids::{ControllerGeneration, SessionId};
use kr_protocol::limits::{MAX_ADMISSION_PARTS, MAX_CONTROL_FRAME_LEN, MAX_REPORT_DETAIL_BYTES};
use kr_protocol::scalars::{Digest256, U64};

use crate::broker::bridge::BridgeSurface;
use crate::broker::connectors::{
    BridgeFacts, ConnectorSource, ConnectorSources, InstalledConnector, QualifiedExecutable,
};

/// What room a report part leaves for the frame's own encoding beyond its records.
const PART_SLACK: usize = 1024;

/// One admitted package as this worker read it.
#[derive(Clone, Debug)]
pub enum ReadPackage {
    /// A package with a connector table, read and checked as a connector.
    Connector(Arc<InstalledConnector>),
    /// A package with no connector table: its manifest, checked against its hash.
    Declarative(Arc<PluginManifest>),
}

impl ReadPackage {
    /// Returns the verified manifest.
    #[must_use]
    pub fn manifest(&self) -> &PluginManifest {
        match self {
            Self::Connector(connector) => connector.manifest(),
            Self::Declarative(manifest) => manifest,
        }
    }
}

/// What this host does with a package's component, whatever a binding stands at: it registers the
/// component with the plugin runtime for a binding, and calls none of its other exports.
///
/// The words are always true of the package, whether or not a binding holds it now; where each
/// binding's component stands is in that binding's own report.
pub const COMPONENT_NOT_CALLED: &str =
    "this host calls none of its component's exports beyond registering it for a binding";

/// Whether a snapshot was applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    /// Its frame was above the one held, and it is held now.
    Newer,
    /// Its frame was not above the one held, and nothing changed.
    Older,
}

/// What one admitted hash names, checked: its verified files, or why they failed.
type Verified = Result<Arc<kr_plugin_sdk::package::Package>, String>;

/// What each admitted hash reads as: a connector, a declarative package, or why it was refused.
type PackageReads = BTreeMap<Digest256, Result<ReadPackage, String>>;

/// A snapshot whose packages are read and checked, waiting to be applied.
#[derive(Debug)]
pub struct Prepared {
    frame: FrameId,
    policy: RevocationPolicy,
    packages: Vec<AdmittedPackage>,
    releases: Vec<ReleaseState>,
    verified: BTreeMap<Digest256, Verified>,
}

#[derive(Debug, Default)]
struct Held {
    frame: Option<FrameId>,
    policy: Option<RevocationPolicy>,
    packages: Vec<AdmittedPackage>,
    releases: Vec<ReleaseState>,
    /// What each admitted hash names, checked once: its verified files, or why they failed.
    verified: BTreeMap<Digest256, Verified>,
    /// What this snapshot makes of each admitted package, with its grants: a connector, a
    /// declarative package, or why it was refused.
    read: BTreeMap<Digest256, Result<ReadPackage, String>>,
    report_seq: u64,
}

/// This worker's admissions: the snapshot it holds and what it read of each admitted package.
#[derive(Debug, Default)]
pub struct Admissions {
    held: Mutex<Held>,
    /// A pause at the start of a snapshot's package reads, which this host's own tests arm to
    /// stand inside a read that has stalled. It is compiled away in every shipped build.
    #[cfg(feature = "testing")]
    read_pause: Mutex<
        Option<(
            std::sync::mpsc::SyncSender<()>,
            std::sync::mpsc::Receiver<()>,
        )>,
    >,
}

impl Admissions {
    /// No admissions: nothing is admitted until a snapshot arrives.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn held(&self) -> std::sync::MutexGuard<'_, Held> {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Stops the next snapshot that has a package to read at the start of its reads, for this
    /// host's own tests: no lock is held there, which is what a read that stalls must not hold.
    ///
    /// Returns the end that says the reads have begun, and the end that lets them go on. The
    /// pause fires once.
    #[cfg(feature = "testing")]
    pub fn pause_reads(
        &self,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        let (arrived, watch) = std::sync::mpsc::sync_channel(1);
        let (release, go) = std::sync::mpsc::sync_channel(1);
        *self
            .read_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((arrived, go));
        (watch, release)
    }

    /// Waits at the pause above, where one is armed. Compiled away in every shipped build.
    #[cfg(feature = "testing")]
    fn wait_before_reads(&self) {
        let armed = self
            .read_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some((arrived, go)) = armed {
            let _ = arrived.send(());
            let _ = go.recv();
        }
    }

    /// The same, without the feature: there is no pause.
    #[cfg(not(feature = "testing"))]
    #[expect(
        clippy::unused_self,
        reason = "it is the shipped form of a method that reads this worker's own pause"
    )]
    const fn wait_before_reads(&self) {}

    /// Returns the frame held, where one is.
    #[must_use]
    pub fn frame(&self) -> Option<FrameId> {
        self.held().frame
    }

    /// Returns the revocation policy the held snapshot carries.
    #[must_use]
    pub fn policy(&self) -> Option<RevocationPolicy> {
        self.held().policy
    }

    /// Returns one admitted package and what this worker read of it, where the held snapshot
    /// admits that hash and the read succeeded.
    #[must_use]
    pub fn admitted(&self, package_digest: Digest256) -> Option<(AdmittedPackage, ReadPackage)> {
        let held = self.held();
        let package = held
            .packages
            .iter()
            .find(|package| package.package_digest == package_digest)?
            .clone();
        let read = held.read.get(&package_digest)?.as_ref().ok()?.clone();
        Some((package, read))
    }

    /// Returns every admitted package this worker read, with what it read.
    #[must_use]
    pub fn all_admitted(&self) -> Vec<(AdmittedPackage, ReadPackage)> {
        let held = self.held();
        held.packages
            .iter()
            .filter_map(|package| {
                let read = held.read.get(&package.package_digest)?.as_ref().ok()?;
                Some((package.clone(), read.clone()))
            })
            .collect()
    }

    /// Returns the state the held snapshot gives each release.
    #[must_use]
    pub fn releases(&self) -> Vec<ReleaseState> {
        self.held().releases.clone()
    }

    /// Reads a complete snapshot's packages where its frame is above the one held: every package
    /// hash not checked before is checked here, with no lock held, so a package slow to read holds
    /// this snapshot and nothing a connection needs. `None` for a frame not above the one held.
    ///
    /// `parts` are the snapshot's parts, in order; the caller has checked that they are all of
    /// one frame and complete.
    #[must_use]
    pub fn prepare(&self, parts: &[PluginAdmissions]) -> Option<Prepared> {
        let first = parts.first()?;
        let frame = first.frame;
        let packages: Vec<AdmittedPackage> = parts
            .iter()
            .flat_map(|part| part.packages.iter().cloned())
            .collect();
        let releases: Vec<ReleaseState> = parts
            .iter()
            .flat_map(|part| part.releases.iter().cloned())
            .collect();
        let known: BTreeMap<Digest256, Verified> = {
            let held = self.held();
            if held.frame.is_some_and(|held| frame <= held) {
                return None;
            }
            packages
                .iter()
                .filter_map(|package| {
                    held.verified
                        .get(&package.package_digest)
                        .map(|verified| (package.package_digest, verified.clone()))
                })
                .collect()
        };
        if packages
            .iter()
            .any(|package| !known.contains_key(&package.package_digest))
        {
            self.wait_before_reads();
        }
        let verified = packages
            .iter()
            .map(|package| {
                let checked = known
                    .get(&package.package_digest)
                    .cloned()
                    .unwrap_or_else(|| verify(package));
                (package.package_digest, checked)
            })
            .collect();
        Some(Prepared {
            frame,
            policy: first.policy,
            packages,
            releases,
            verified,
        })
    }

    /// Applies a prepared snapshot where its frame is still above the one held: what each
    /// installation grants is taken from this snapshot, `sources` is replaced with the admitted
    /// connectors, and the snapshot is installed in `broker`, which brings every live binding to
    /// the state of the release it holds, all under one lock, so two snapshots applied at once
    /// never leave one's packages beside the other's connectors or bindings.
    pub fn publish(
        &self,
        prepared: Prepared,
        sources: &ConnectorSources,
        broker: &crate::broker::Broker,
        now: kr_protocol::scalars::TimestampMs,
    ) -> Applied {
        let mut held = self.held();
        let applied = Self::publish_held(&mut held, prepared, sources);
        if applied == Applied::Newer {
            Self::install(&held, broker, now);
        }
        applied
    }

    /// Installs the snapshot held in `broker`: for the first snapshot, which this worker applies
    /// before its broker exists.
    pub fn install_into(
        &self,
        broker: &crate::broker::Broker,
        now: kr_protocol::scalars::TimestampMs,
    ) {
        Self::install(&self.held(), broker, now);
    }

    /// Installs a held snapshot in `broker`, with every package it admits that this worker read.
    fn install(
        held: &Held,
        broker: &crate::broker::Broker,
        now: kr_protocol::scalars::TimestampMs,
    ) {
        let (Some(frame), Some(policy)) = (held.frame, held.policy) else {
            return;
        };
        let packages = held
            .packages
            .iter()
            .filter_map(|package| {
                let read = held.read.get(&package.package_digest)?.as_ref().ok()?;
                Some((package.clone(), read.clone()))
            })
            .collect();
        broker.install_admissions(frame, policy, packages, held.releases.clone(), now);
    }

    /// Applies a prepared snapshot to what is held where its frame is above the one held.
    fn publish_held(held: &mut Held, prepared: Prepared, sources: &ConnectorSources) -> Applied {
        if held.frame.is_some_and(|held| prepared.frame <= held) {
            return Applied::Older;
        }
        let (read, _) = read_packages(
            &prepared.packages,
            &prepared.verified,
            sources,
            Some(prepared.frame),
        );
        held.frame = Some(prepared.frame);
        held.policy = Some(prepared.policy);
        held.packages = prepared.packages;
        held.releases = prepared.releases;
        held.verified = prepared.verified;
        held.read = read;
        Applied::Newer
    }

    /// Prepares and applies a snapshot at once, where nothing else can be waiting: the first
    /// snapshot, read before this worker serves any connection and before its broker exists,
    /// which [`Self::install_into`] then installs it in.
    pub fn apply(&self, parts: &[PluginAdmissions], sources: &ConnectorSources) -> Applied {
        match self.prepare(parts) {
            Some(prepared) => Self::publish_held(&mut self.held(), prepared, sources),
            None => Applied::Older,
        }
    }

    /// Makes a report on `bindings` for the frame held, numbered above every earlier report of
    /// this process, cut into parts that each fit a control frame.
    ///
    /// # Errors
    ///
    /// Returns why, by name, when the report would need more than [`MAX_ADMISSION_PARTS`] parts:
    /// a report is never cut short, since a shorter one would say fewer bindings are live.
    pub fn report(
        &self,
        session_id: SessionId,
        bindings: Vec<LiveBinding>,
        action_refusals: &BTreeMap<Digest256, Vec<String>>,
    ) -> Result<Vec<PluginAdmissionsAck>, String> {
        let mut held = self.held();
        held.report_seq = held.report_seq.saturating_add(1);
        let report_seq = U64::new(held.report_seq);
        let frame = held.frame.unwrap_or(FrameId {
            generation: kr_protocol::ids::ControllerGeneration::new(0),
            revision: U64::new(0),
            round: U64::new(0),
        });
        let refusals: Vec<PackageRefusal> = held
            .read
            .iter()
            .filter_map(|(digest, read)| match read {
                Err(why) => Some((*digest, why.clone())),
                // A package read is named too for the parts of it this worker does not use: a
                // component, which nothing here calls beyond binding it, and each declared action
                // that could not be registered.
                Ok(read) => {
                    let mut unused = Vec::new();
                    if read.manifest().has_component() {
                        unused.push(COMPONENT_NOT_CALLED.to_owned());
                    }
                    if let Some(refused) = action_refusals
                        .get(digest)
                        .filter(|refused| !refused.is_empty())
                    {
                        unused.push(format!(
                            "some of its declared actions were not registered: {}",
                            refused.join("; ")
                        ));
                    }
                    (!unused.is_empty()).then(|| (*digest, unused.join("; ")))
                }
            })
            .map(|(digest, why)| {
                let (detail, detail_cut) = cut(&why, MAX_REPORT_DETAIL_BYTES);
                PackageRefusal {
                    package_digest: digest,
                    detail,
                    detail_cut,
                }
            })
            .collect();
        drop(held);
        let parts = page(session_id, frame, report_seq, bindings, refusals);
        if parts.len() > MAX_ADMISSION_PARTS as usize {
            return Err(format!(
                "the report on this worker's bindings needs {} parts, and a report is at most \
                 {MAX_ADMISSION_PARTS}",
                parts.len()
            ));
        }
        Ok(parts)
    }
}

/// Checks the header of a first snapshot before any part of it is read: at least one part and no
/// more than a snapshot may have, of the generation that spawned this worker.
///
/// # Errors
///
/// Returns why, by name, when the header breaks either.
pub fn check_header(
    header: &AdmissionsHeader,
    generation: ControllerGeneration,
) -> Result<(), String> {
    if header.parts == 0 || header.parts > MAX_ADMISSION_PARTS {
        return Err(format!(
            "the first snapshot of plugin admissions announces {} parts, and a snapshot has one \
             to {MAX_ADMISSION_PARTS}",
            header.parts
        ));
    }
    if header.frame.generation != generation {
        return Err(
            "the first snapshot of plugin admissions names another controller generation than the \
             one that spawned this worker"
                .to_owned(),
        );
    }
    Ok(())
}

/// Cuts `text` at a character boundary to at most `max` bytes, and says whether it was cut.
#[must_use]
pub fn cut(text: &str, max: usize) -> (String, bool) {
    if text.len() <= max {
        return (text.to_owned(), false);
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_owned(), true)
}

/// Returns the encoded size of a value, as a frame carries it.
fn measure<T: serde::Serialize + ?Sized>(value: &T) -> usize {
    kr_cbor::to_canonical_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

/// Cuts a report into parts that each fit a control frame, whole records only.
fn page(
    session_id: SessionId,
    frame: FrameId,
    report_seq: U64,
    bindings: Vec<LiveBinding>,
    refusals: Vec<PackageRefusal>,
) -> Vec<PluginAdmissionsAck> {
    let empty = PluginAdmissionsAck {
        session_id,
        frame,
        report_seq,
        part: u32::MAX,
        parts: u32::MAX,
        bindings: Vec::new(),
        refusals: Vec::new(),
    };
    let budget = MAX_CONTROL_FRAME_LEN
        .saturating_sub(4)
        .saturating_sub(measure(&ControlFrame::PluginAdmissionsAck(Box::new(
            empty.clone(),
        ))))
        .saturating_sub(PART_SLACK);
    let mut parts = vec![empty.clone()];
    let mut used = 0usize;
    let mut room = |cost: usize, parts: &mut Vec<PluginAdmissionsAck>| {
        let last = parts.last().expect("there is always a part");
        if (!last.bindings.is_empty() || !last.refusals.is_empty())
            && used.saturating_add(cost) > budget
        {
            parts.push(empty.clone());
            used = 0;
        }
        used = used.saturating_add(cost);
    };
    for binding in bindings {
        room(measure(&binding), &mut parts);
        parts
            .last_mut()
            .expect("there is always a part")
            .bindings
            .push(binding);
    }
    for refusal in refusals {
        room(measure(&refusal), &mut parts);
        parts
            .last_mut()
            .expect("there is always a part")
            .refusals
            .push(refusal);
    }
    let count = u32::try_from(parts.len()).unwrap_or(u32::MAX);
    for (index, part) in parts.iter_mut().enumerate() {
        part.part = u32::try_from(index + 1).unwrap_or(u32::MAX);
        part.parts = count;
    }
    parts
}

/// Reads the capabilities a record names, by their wire names; one this build does not know
/// grants nothing.
#[must_use]
pub fn capabilities(names: &[String]) -> BTreeSet<PluginCapability> {
    names
        .iter()
        .filter_map(|name| {
            PluginCapability::ALL
                .iter()
                .copied()
                .find(|capability| capability.as_str() == name)
        })
        .collect()
}

/// What each admitted package reads as under the grants its admissions give it, from its verified
/// files: a connector, a declarative package, or why it was refused. `sources` is replaced with the
/// connectors, which leaves out any two that integrate one command; those are refused too, and
/// returned beside the rest.
fn read_packages(
    packages: &[AdmittedPackage],
    verified: &BTreeMap<Digest256, Verified>,
    sources: &ConnectorSources,
    frame: Option<FrameId>,
) -> (PackageReads, Vec<Arc<InstalledConnector>>) {
    let mut read = BTreeMap::new();
    for package in packages {
        let outcome = match verified.get(&package.package_digest) {
            Some(Ok(checked)) => derive(package, checked),
            Some(Err(why)) => Err(why.clone()),
            None => Err("the package was not read".to_owned()),
        };
        read.insert(package.package_digest, outcome);
    }
    let connectors: Vec<Arc<InstalledConnector>> = read
        .values()
        .filter_map(|outcome| match outcome {
            Ok(ReadPackage::Connector(connector)) => Some(Arc::clone(connector)),
            _ => None,
        })
        .collect();
    // A refusal of this kind belongs to these admissions alone: the next ones read again.
    let mut conflicting = Vec::new();
    for (connector, refusal) in sources.replace_read(connectors, frame) {
        read.insert(connector.package_digest(), Err(refusal.detail));
        conflicting.push(connector);
    }
    (read, conflicting)
}

/// The checks of admitted packages, kept by hash, for a reader of admissions outside a worker.
///
/// A hash names the same verified files for good, so each package is checked once and kept. A
/// check that failed is not kept: a package's copy can be put right under the same hash.
#[derive(Debug, Default)]
pub struct CheckedPackages {
    checked: Mutex<BTreeMap<Digest256, Arc<kr_plugin_sdk::package::Package>>>,
}

/// One set of admitted packages, read the way a worker handed them in one snapshot reads them.
#[derive(Debug)]
pub struct Reading {
    /// Each admitted package, with what it reads as or why it was refused.
    pub packages: Vec<(AdmittedPackage, Result<ReadPackage, String>)>,
    /// The connectors whose command integration applies, by the command each resolves.
    pub sources: ConnectorSources,
    /// The connectors left out because another admitted package integrates the same command.
    pub conflicting: Vec<Arc<InstalledConnector>>,
}

impl CheckedPackages {
    /// Nothing checked yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads `packages` by a worker's rules: each package checked (a hash checked before is not
    /// checked again), each read under the grants these admissions give it, and one command
    /// resolving to one connector. It reads files, so it belongs on a thread that may block.
    #[must_use]
    pub fn read(&self, packages: &[AdmittedPackage]) -> Reading {
        let verified: BTreeMap<Digest256, Verified> = packages
            .iter()
            .map(|package| {
                let known = self
                    .checked
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&package.package_digest)
                    .cloned();
                let checked = known.map_or_else(
                    || {
                        let checked = verify(package);
                        if let Ok(checked) = &checked {
                            self.checked
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .insert(package.package_digest, Arc::clone(checked));
                        }
                        checked
                    },
                    Ok,
                );
                (package.package_digest, checked)
            })
            .collect();
        let sources = ConnectorSources::new();
        let (mut read, conflicting) = read_packages(packages, &verified, &sources, None);
        Reading {
            packages: packages
                .iter()
                .map(|package| {
                    let outcome = read
                        .remove(&package.package_digest)
                        .unwrap_or_else(|| Err("the package was not read".to_owned()));
                    (package.clone(), outcome)
                })
                .collect(),
            sources,
            conflicting,
        }
    }
}

/// What an installation hands the connector reader for one admitted package.
#[must_use]
pub fn source_of(package: &AdmittedPackage) -> ConnectorSource {
    ConnectorSource {
        package_digest: package.package_digest,
        package_dir: PathBuf::from(&package.package_dir),
        bridge: package.bridge.0.as_ref().map(|bridge| BridgeFacts {
            application: bridge.application.clone(),
            surfaces: bridge
                .surfaces
                .iter()
                .filter_map(|surface| match surface.as_str() {
                    "hook" => Some(BridgeSurface::Hook),
                    "channel" => Some(BridgeSurface::Channel),
                    _ => None,
                })
                .collect(),
            forwarder: PathBuf::from(&bridge.forwarder),
        }),
        granted: capabilities(&package.grants),
        qualified: package
            .builds
            .iter()
            .map(|build| QualifiedExecutable {
                digest: build.executable_digest,
                version: build.version.clone(),
            })
            .collect(),
    }
}

/// Checks what one admitted package's hash names: its copy passes the SDK's package check, its
/// manifest hashes to the admitted hash, and it is the admitted package.
fn verify(package: &AdmittedPackage) -> Result<Arc<kr_plugin_sdk::package::Package>, String> {
    let directory = PathBuf::from(&package.package_dir);
    let checked = InstalledConnector::check(&directory, package.package_digest)
        .map_err(|refusal| refusal.detail)?;
    if checked.manifest.plugin_id() != package.plugin_id {
        return Err(format!(
            "the package in {} is {}, not the admitted {}",
            directory.display(),
            checked.manifest.plugin_id(),
            package.plugin_id
        ));
    }
    Ok(Arc::new(checked))
}

/// What one checked package is under this snapshot's grants: a connector where it carries a
/// connector table, and otherwise its manifest.
fn derive(
    package: &AdmittedPackage,
    checked: &kr_plugin_sdk::package::Package,
) -> Result<ReadPackage, String> {
    if checked.manifest.payload(PayloadRole::Connector).is_some() {
        return InstalledConnector::assemble(source_of(package), checked.clone())
            .map(|connector| ReadPackage::Connector(Arc::new(connector)))
            .map_err(|refusal| refusal.detail);
    }
    Ok(ReadPackage::Declarative(Arc::new(checked.manifest.clone())))
}

/// Admissions for packages this host's own tests wrote, handed over the way the control daemon
/// hands a worker its admissions. Compiled away in every shipped build.
#[cfg(feature = "testing")]
pub mod testing {
    use super::*;

    /// What an installation hands over for one package a test wrote: its identity read from its
    /// verified manifest, and its grants, its bridge and its builds as the source names them.
    ///
    /// # Panics
    ///
    /// When the package does not pass its check, which a test that wrote it wrote wrongly.
    #[must_use]
    pub fn admitted(source: &ConnectorSource) -> AdmittedPackage {
        let checked = InstalledConnector::check(&source.package_dir, source.package_digest)
            .expect("the package a test wrote passes its check");
        let manifest = &checked.manifest;
        AdmittedPackage {
            plugin_id: kr_protocol::ids::PluginId::new(manifest.plugin_id().to_string())
                .expect("a plugin identifier"),
            publisher_id: kr_protocol::ids::PublisherId::new(manifest.publisher_id.as_str())
                .expect("a publisher identifier"),
            version: manifest.version.to_string(),
            package_digest: source.package_digest,
            origin: kr_protocol::admission::ReleaseOrigin {
                repository_id: "official".to_owned(),
                enrolment_key: "0123456789abcdef0123456789abcdef".to_owned(),
            },
            package_dir: source.package_dir.display().to_string(),
            grants: source
                .granted
                .iter()
                .map(|capability| capability.as_str().to_owned())
                .collect(),
            bridge: source.bridge.as_ref().map_or_else(
                kr_protocol::scalars::Nullable::null,
                |bridge| {
                    kr_protocol::scalars::Nullable::some(kr_protocol::admission::AdmittedBridge {
                        application: bridge.application.clone(),
                        surfaces: bridge
                            .surfaces
                            .iter()
                            .map(|surface| surface.as_str().to_owned())
                            .collect(),
                        forwarder: bridge.forwarder.display().to_string(),
                    })
                },
            ),
            builds: source
                .qualified
                .iter()
                .map(|qualified| kr_protocol::admission::AdmittedBuild {
                    executable_digest: qualified.digest,
                    version: qualified.version.clone(),
                })
                .collect(),
            component: kr_protocol::scalars::Nullable(
                manifest
                    .payload(kr_plugin_sdk::plugin::PayloadRole::Component)
                    .map(|payload| kr_protocol::admission::AdmittedComponent {
                        path: format!(
                            "0123456789abcdef0123456789abcdef/packages/{}/{}",
                            kr_plugin_sdk::digest::PayloadDigest::from_bytes(
                                *source.package_digest.as_bytes()
                            ),
                            payload.path.as_str()
                        ),
                        digest: Digest256::from_bytes(*payload.digest.as_bytes()),
                        bytes: payload.size_bytes,
                    }),
            ),
        }
    }

    /// The state a snapshot gives an admitted release: not revoked, capped at the installation's
    /// grants, and not ending.
    #[must_use]
    pub fn release_of(package: &AdmittedPackage) -> ReleaseState {
        ReleaseState {
            plugin_id: package.plugin_id.clone(),
            package_digest: package.package_digest,
            origin: package.origin.clone(),
            revocation: kr_protocol::scalars::Nullable::null(),
            grant_cap: package.grants.clone(),
            ends_at_next_boundary: false,
        }
    }

    /// One snapshot as a test hands it over: at round `round` of revision `round` of the
    /// controller generation 1.
    #[derive(Clone, Debug)]
    pub struct Snapshot {
        /// Its round and its revision.
        pub round: u64,
        /// The administrator's revocation policy.
        pub policy: RevocationPolicy,
        /// The packages it admits.
        pub packages: Vec<AdmittedPackage>,
        /// The state of each release it covers.
        pub releases: Vec<ReleaseState>,
    }

    impl Snapshot {
        /// A snapshot admitting `packages`, with the state [`release_of`] gives each, under the
        /// policy that only warns.
        #[must_use]
        pub fn admitting(round: u64, packages: Vec<AdmittedPackage>) -> Self {
            let releases = packages.iter().map(release_of).collect();
            Self {
                round,
                policy: RevocationPolicy::WarnOnly,
                packages,
                releases,
            }
        }

        /// Its frame.
        #[must_use]
        pub fn frame(&self) -> FrameId {
            FrameId {
                generation: ControllerGeneration::new(1),
                revision: U64::new(self.round),
                round: U64::new(self.round),
            }
        }
    }

    /// Hands a worker one snapshot, applied as the worker applies every snapshot, and returns its
    /// frame.
    ///
    /// # Panics
    ///
    /// When the snapshot's round is not above the frame held.
    pub fn hand_over(
        admissions: &Admissions,
        sources: &ConnectorSources,
        broker: &crate::broker::Broker,
        snapshot: Snapshot,
    ) -> FrameId {
        let frame = snapshot.frame();
        let parts = vec![PluginAdmissions {
            environment_id: kr_protocol::ids::EnvironmentId::new(kr_protocol::scalars::Uuid::NIL),
            frame,
            part: 1,
            parts: 1,
            policy: snapshot.policy,
            packages: snapshot.packages,
            releases: snapshot.releases,
        }];
        let prepared = admissions
            .prepare(&parts)
            .expect("the snapshot is above the frame held");
        admissions.publish(prepared, sources, broker, kr_ipc::now_ms());
        frame
    }

    /// Hands a worker one snapshot admitting `packages` ([`Snapshot::admitting`]), and returns its
    /// frame.
    ///
    /// # Panics
    ///
    /// When `round` is not above the frame held.
    pub fn admit(
        admissions: &Admissions,
        sources: &ConnectorSources,
        broker: &crate::broker::Broker,
        packages: Vec<AdmittedPackage>,
        round: u64,
    ) -> FrameId {
        hand_over(
            admissions,
            sources,
            broker,
            Snapshot::admitting(round, packages),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_detail_is_cut_at_a_character_boundary_and_marked() {
        let text = format!("{}é tail", "a".repeat(MAX_REPORT_DETAIL_BYTES - 1));
        let (cut_text, was_cut) = cut(&text, MAX_REPORT_DETAIL_BYTES);
        assert!(was_cut);
        assert!(cut_text.len() <= MAX_REPORT_DETAIL_BYTES);
        assert!(text.starts_with(&cut_text));
        let (whole, was_cut) = cut("short", MAX_REPORT_DETAIL_BYTES);
        assert_eq!((whole.as_str(), was_cut), ("short", false));
    }

    fn header(parts: u32, generation: u64) -> AdmissionsHeader {
        AdmissionsHeader {
            frame: FrameId {
                generation: ControllerGeneration::new(generation),
                revision: U64::new(1),
                round: U64::new(1),
            },
            parts,
        }
    }

    /// A first snapshot is one to the bound's parts, of the generation that spawned the worker.
    #[test]
    fn a_first_header_outside_its_bounds_or_of_another_generation_is_refused() {
        let spawned = ControllerGeneration::new(3);
        assert_eq!(check_header(&header(1, 3), spawned), Ok(()));
        assert_eq!(
            check_header(&header(MAX_ADMISSION_PARTS, 3), spawned),
            Ok(())
        );
        for (bad, why) in [
            (header(0, 3), "parts"),
            (header(MAX_ADMISSION_PARTS + 1, 3), "parts"),
            (header(1, 4), "generation"),
        ] {
            let refusal = check_header(&bad, spawned).expect_err("refused");
            assert!(refusal.contains(why), "{refusal}");
        }
    }

    /// A report of the bound's parts is made; one that would need more is refused whole, never
    /// cut short.
    #[test]
    fn a_report_past_the_part_bound_is_refused_whole() {
        let admissions = Admissions::new();
        let refusal = |n: u32| PackageRefusal {
            package_digest: Digest256::from_bytes([u8::try_from(n % 256).unwrap_or(0); 32]),
            detail: "d".repeat(MAX_REPORT_DETAIL_BYTES),
            detail_cut: true,
        };
        let one = measure(&refusal(0));
        let per_part = MAX_CONTROL_FRAME_LEN / one;
        let binding = |n: u32| LiveBinding {
            binding_id: kr_protocol::ids::BrokerBindingId::new(kr_protocol::scalars::Uuid::NIL),
            application_instance_id: kr_protocol::ids::ApplicationInstanceId::new(
                kr_protocol::scalars::Uuid::NIL,
            ),
            release: kr_protocol::admission::LiveRelease {
                plugin_id: kr_protocol::ids::PluginId::new(format!("kalareach/p{n}"))
                    .expect("an identifier"),
                publisher_id: kr_protocol::ids::PublisherId::new("kalareach").expect("an id"),
                version: "d".repeat(900),
                package_digest: Digest256::from_bytes([1; 32]),
                origin: kr_protocol::admission::ReleaseOrigin {
                    repository_id: "official".to_owned(),
                    enrolment_key: "k".to_owned(),
                },
            },
            ending: false,
            component: kr_protocol::scalars::Nullable::null(),
        };
        let bindings = |count: usize| -> Vec<LiveBinding> {
            (0..u32::try_from(count).unwrap_or(u32::MAX))
                .map(binding)
                .collect()
        };
        let session = SessionId::new(kr_protocol::scalars::Uuid::NIL);
        let _ = per_part;
        let many = admissions
            .report(session, bindings(70 * 1024), &BTreeMap::new())
            .map(|parts| parts.len());
        assert!(
            matches!(&many, Err(why) if why.contains("parts")),
            "{many:?}"
        );
        let fits = admissions
            .report(session, bindings(1024), &BTreeMap::new())
            .expect("within the bound");
        assert!(fits.len() <= MAX_ADMISSION_PARTS as usize);
        assert!(
            fits.windows(2)
                .all(|pair| pair[0].report_seq == pair[1].report_seq),
            "one report, one number"
        );
    }

    /// What an installation hands over, as an admitted package.
    fn admitted(source: &ConnectorSource, plugin_id: &str) -> AdmittedPackage {
        AdmittedPackage {
            plugin_id: kr_protocol::ids::PluginId::new(plugin_id).expect("an identifier"),
            publisher_id: kr_protocol::ids::PublisherId::new("kalareach").expect("an identifier"),
            version: "1.0.0".to_owned(),
            package_digest: source.package_digest,
            origin: kr_protocol::admission::ReleaseOrigin {
                repository_id: "official".to_owned(),
                enrolment_key: "key".to_owned(),
            },
            package_dir: source.package_dir.display().to_string(),
            grants: source
                .granted
                .iter()
                .map(|capability| capability.as_str().to_owned())
                .collect(),
            bridge: source.bridge.as_ref().map_or_else(
                kr_protocol::scalars::Nullable::null,
                |bridge| {
                    kr_protocol::scalars::Nullable::some(kr_protocol::admission::AdmittedBridge {
                        application: bridge.application.clone(),
                        surfaces: bridge
                            .surfaces
                            .iter()
                            .map(|surface| surface.as_str().to_owned())
                            .collect(),
                        forwarder: bridge.forwarder.display().to_string(),
                    })
                },
            ),
            builds: Vec::new(),
            component: kr_protocol::scalars::Nullable::null(),
        }
    }

    /// A one-part snapshot at revision and round `step`.
    fn snapshot(step: u64, packages: Vec<AdmittedPackage>) -> Vec<PluginAdmissions> {
        vec![PluginAdmissions {
            environment_id: kr_protocol::ids::EnvironmentId::new(kr_protocol::scalars::Uuid::NIL),
            frame: FrameId {
                generation: ControllerGeneration::new(1),
                revision: U64::new(step),
                round: U64::new(step),
            },
            part: 1,
            parts: 1,
            policy: RevocationPolicy::WarnOnly,
            packages,
            releases: Vec::new(),
        }]
    }

    /// What an installation grants is taken from each snapshot, while the package its hash names
    /// is read once: a withdrawn launch grant, a removed bridge and a changed build list each
    /// reach the connector with the next snapshot, and a restored grant comes back with it.
    #[test]
    fn grants_bridges_and_builds_follow_each_snapshot_under_one_hash() {
        use crate::broker::connectors::fixture;
        let root = tempfile::tempdir().expect("a directory");
        // A forwarder path that is absolute on every platform, which a bridge's must be.
        let source = fixture::claude_code_package(root.path(), &root.path().join("kr-hook"))
            .expect("the package is written");
        let digest = source.package_digest;
        let full = admitted(&source, "kalareach/claude-code");
        let admissions = Admissions::new();
        let sources = ConnectorSources::new();
        let launch = kr_plugin_sdk::capability::PluginCapability::CommandIntegrationLaunch;
        let command = |sources: &ConnectorSources| sources.for_command(fixture::COMMAND);

        assert_eq!(
            admissions.apply(&snapshot(1, vec![full.clone()]), &sources),
            Applied::Newer
        );
        let connector = command(&sources).expect("the launch grant integrates the command");
        assert!(connector.installed_bridge().is_some());

        let mut withdrawn = full.clone();
        withdrawn.grants.retain(|grant| grant != launch.as_str());
        admissions.apply(&snapshot(2, vec![withdrawn]), &sources);
        assert!(
            command(&sources).is_none(),
            "a withdrawn grant ends the integration"
        );
        let (_, read) = admissions.admitted(digest).expect("still admitted");
        assert!(matches!(read, ReadPackage::Connector(connector) if !connector.granted(launch)));

        admissions.apply(&snapshot(3, vec![full.clone()]), &sources);
        assert!(command(&sources).is_some(), "a restored grant restores it");

        let mut unbridged = full.clone();
        unbridged.bridge = kr_protocol::scalars::Nullable::null();
        admissions.apply(&snapshot(4, vec![unbridged]), &sources);
        assert!(
            command(&sources)
                .expect("still integrated")
                .installed_bridge()
                .is_none(),
            "a removed bridge is gone from the connector"
        );

        let build = Digest256::from_bytes(fixture::QUALIFIED_DIGEST);
        let mut built = full.clone();
        built.builds = vec![kr_protocol::admission::AdmittedBuild {
            executable_digest: build,
            version: fixture::QUALIFIED_VERSION.to_owned(),
        }];
        admissions.apply(&snapshot(5, vec![built]), &sources);
        assert_eq!(
            command(&sources)
                .expect("integrated")
                .qualified_version(&build),
            Some(fixture::QUALIFIED_VERSION)
        );
        admissions.apply(&snapshot(6, vec![full]), &sources);
        assert_eq!(
            command(&sources)
                .expect("integrated")
                .qualified_version(&build),
            None,
            "a build the snapshot no longer names qualifies nothing"
        );
    }

    /// Two packages that integrate one command are both refused in the snapshot that admits them
    /// both, and the one left resolves the command once the other is no longer admitted.
    #[test]
    fn a_command_conflict_ends_with_the_snapshot_that_holds_it() {
        use crate::broker::connectors::fixture;
        let root = tempfile::tempdir().expect("a directory");
        let forwarder = std::path::Path::new("/opt/kalareach/bin/kr-hook");
        let gemini = fixture::package(root.path(), forwarder, &fixture::Shape::gemini_cli(&[]))
            .expect("the package is written");
        let other = fixture::package(
            root.path(),
            forwarder,
            &fixture::Shape {
                plugin_name: "gemini-other",
                display_name: "Gemini Other",
                ..fixture::Shape::gemini_cli(&[])
            },
        )
        .expect("the package is written");
        let admissions = Admissions::new();
        let sources = ConnectorSources::new();
        let both = vec![
            admitted(&gemini, "kalareach/gemini-cli"),
            admitted(&other, "kalareach/gemini-other"),
        ];
        admissions.apply(&snapshot(1, both), &sources);
        assert!(sources.for_command("gemini").is_none());
        assert!(admissions.admitted(gemini.package_digest).is_none());
        let refusals = admissions
            .report(
                SessionId::new(kr_protocol::scalars::Uuid::NIL),
                Vec::new(),
                &BTreeMap::new(),
            )
            .expect("a report")
            .into_iter()
            .flat_map(|part| part.refusals)
            .count();
        assert_eq!(refusals, 2);

        admissions.apply(
            &snapshot(2, vec![admitted(&gemini, "kalareach/gemini-cli")]),
            &sources,
        );
        assert_eq!(
            sources
                .for_command("gemini")
                .map(|connector| connector.plugin_id().to_string()),
            Some("kalareach/gemini-cli".to_owned())
        );
        assert!(admissions.admitted(gemini.package_digest).is_some());
    }

    /// A snapshot prepared while a newer one was applied applies nothing: the frame order is
    /// checked again when a prepared snapshot is published.
    #[test]
    fn a_prepared_snapshot_overtaken_before_publication_applies_nothing() {
        use crate::broker::connectors::fixture;
        let root = tempfile::tempdir().expect("a directory");
        let source = fixture::claude_code_package(
            root.path(),
            std::path::Path::new("/opt/kalareach/bin/kr-hook"),
        )
        .expect("the package is written");
        let admissions = Admissions::new();
        let sources = ConnectorSources::new();
        let older = admissions
            .prepare(&snapshot(
                2,
                vec![admitted(&source, "kalareach/claude-code")],
            ))
            .expect("above nothing");
        assert_eq!(
            admissions.apply(&snapshot(3, Vec::new()), &sources),
            Applied::Newer
        );
        let broker = crate::broker::Broker::open(
            None,
            SessionId::new(kr_protocol::scalars::Uuid::NIL),
            crate::persistence::fault::JournalHealth::shared(),
        )
        .expect("the broker opens");
        assert_eq!(
            admissions.publish(older, &sources, &broker, kr_ipc::now_ms()),
            Applied::Older
        );
        assert_eq!(admissions.frame().map(|frame| frame.round.get()), Some(3));
        assert!(sources.for_command(fixture::COMMAND).is_none());
        assert!(admissions.prepare(&snapshot(3, Vec::new())).is_none());
    }

    /// A report of exactly the bound's parts is made; one binding more is refused whole.
    #[test]
    fn a_report_of_the_bound_is_made_and_one_record_more_is_refused() {
        let binding = |n: usize| LiveBinding {
            binding_id: kr_protocol::ids::BrokerBindingId::new(kr_protocol::scalars::Uuid::NIL),
            application_instance_id: kr_protocol::ids::ApplicationInstanceId::new(
                kr_protocol::scalars::Uuid::NIL,
            ),
            release: kr_protocol::admission::LiveRelease {
                plugin_id: kr_protocol::ids::PluginId::new(format!("kalareach/p{n:08}"))
                    .expect("an identifier"),
                publisher_id: kr_protocol::ids::PublisherId::new("kalareach").expect("an id"),
                version: "v".repeat(900),
                package_digest: Digest256::from_bytes([1; 32]),
                origin: kr_protocol::admission::ReleaseOrigin {
                    repository_id: "official".to_owned(),
                    enrolment_key: "k".to_owned(),
                },
            },
            ending: false,
            component: kr_protocol::scalars::Nullable::null(),
        };
        let session = SessionId::new(kr_protocol::scalars::Uuid::NIL);
        let frame = FrameId {
            generation: ControllerGeneration::new(0),
            revision: U64::new(0),
            round: U64::new(0),
        };
        // Every record costs the same, so every full part holds the same count of them.
        let paged = page(
            session,
            frame,
            U64::new(1),
            (0..4096).map(binding).collect(),
            Vec::new(),
        );
        assert!(paged.len() > 2);
        let per_part = paged[0].bindings.len();
        assert_eq!(paged[1].bindings.len(), per_part);
        let bound = per_part * MAX_ADMISSION_PARTS as usize;
        let admissions = Admissions::new();
        let made = admissions
            .report(session, (0..bound).map(binding).collect(), &BTreeMap::new())
            .expect("a report of the bound is made");
        assert_eq!(made.len(), MAX_ADMISSION_PARTS as usize);
        assert!(made.iter().all(|part| part.parts == MAX_ADMISSION_PARTS));
        let refused = admissions
            .report(
                session,
                (0..=bound).map(binding).collect(),
                &BTreeMap::new(),
            )
            .map(|parts| parts.len());
        assert!(
            matches!(&refused, Err(why) if why.contains("parts")),
            "{refused:?}"
        );
    }

    #[test]
    fn a_report_far_past_one_frame_is_cut_into_whole_records() {
        let refusals: Vec<PackageRefusal> = (0..4000u32)
            .map(|n| PackageRefusal {
                package_digest: Digest256::from_bytes([u8::try_from(n % 256).unwrap_or(0); 32]),
                detail: "d".repeat(MAX_REPORT_DETAIL_BYTES),
                detail_cut: true,
            })
            .collect();
        let frame = FrameId {
            generation: kr_protocol::ids::ControllerGeneration::new(1),
            revision: U64::new(1),
            round: U64::new(1),
        };
        let parts = page(
            SessionId::new(kr_protocol::scalars::Uuid::NIL),
            frame,
            U64::new(1),
            Vec::new(),
            refusals,
        );
        assert!(parts.len() > 1);
        let carried: usize = parts.iter().map(|part| part.refusals.len()).sum();
        assert_eq!(carried, 4000);
        for part in &parts {
            assert!(
                measure(&ControlFrame::PluginAdmissionsAck(Box::new(part.clone())))
                    <= MAX_CONTROL_FRAME_LEN - 4
            );
        }
    }
}
