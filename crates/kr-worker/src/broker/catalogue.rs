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
//! Each report is numbered, and the number rises with every report this process makes, so two
//! reports that name one applied frame are ordered too. Free text in a report (why a package was
//! refused) is cut at a character boundary to [`MAX_REPORT_DETAIL_BYTES`] and marked as cut, so a
//! report's records are bounded like the snapshot's.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::plugin::{PayloadRole, PluginManifest};
use kr_protocol::admission::{
    AdmittedPackage, FrameId, LiveBinding, PackageRefusal, PluginAdmissions, PluginAdmissionsAck,
    ReleaseState, RevocationPolicy,
};
use kr_protocol::envelope::ControlFrame;
use kr_protocol::ids::SessionId;
use kr_protocol::limits::{MAX_CONTROL_FRAME_LEN, MAX_REPORT_DETAIL_BYTES};
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

/// Whether a snapshot was applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    /// Its frame was above the one held, and it is held now.
    Newer,
    /// Its frame was not above the one held, and nothing changed.
    Older,
}

#[derive(Debug, Default)]
struct Held {
    frame: Option<FrameId>,
    policy: Option<RevocationPolicy>,
    packages: Vec<AdmittedPackage>,
    releases: Vec<ReleaseState>,
    read: BTreeMap<Digest256, Result<ReadPackage, String>>,
    report_seq: u64,
}

/// This worker's admissions: the snapshot it holds and what it read of each admitted package.
#[derive(Debug, Default)]
pub struct Admissions {
    held: Mutex<Held>,
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

    /// Applies a complete snapshot, where its frame is above the one held: every package hash
    /// not read before is read and checked, and `sources` is replaced with the admitted
    /// connectors.
    ///
    /// `parts` are the snapshot's parts, in order; the caller has checked that they are all of
    /// one frame and complete.
    pub fn apply(&self, parts: &[PluginAdmissions], sources: &ConnectorSources) -> Applied {
        let Some(first) = parts.first() else {
            return Applied::Older;
        };
        let frame = first.frame;
        let mut held = self.held();
        if held.frame.is_some_and(|held| frame <= held) {
            return Applied::Older;
        }
        let packages: Vec<AdmittedPackage> = parts
            .iter()
            .flat_map(|part| part.packages.iter().cloned())
            .collect();
        let releases: Vec<ReleaseState> = parts
            .iter()
            .flat_map(|part| part.releases.iter().cloned())
            .collect();
        let mut read = BTreeMap::new();
        for package in &packages {
            let known = held.read.remove(&package.package_digest);
            let outcome = known.unwrap_or_else(|| read_package(package));
            read.insert(package.package_digest, outcome);
        }
        held.frame = Some(frame);
        held.policy = Some(first.policy);
        held.packages = packages;
        held.releases = releases;
        held.read = read;
        let connectors: Vec<Arc<InstalledConnector>> = held
            .packages
            .iter()
            .filter_map(|package| match held.read.get(&package.package_digest) {
                Some(Ok(ReadPackage::Connector(connector))) => Some(Arc::clone(connector)),
                _ => None,
            })
            .collect();
        drop(held);
        for (connector, refusal) in sources.replace_read(connectors) {
            let mut held = self.held();
            held.read
                .insert(connector.package_digest(), Err(refusal.detail));
        }
        Applied::Newer
    }

    /// Makes a report on `bindings` for the frame held, numbered above every earlier report of
    /// this process, cut into parts that each fit a control frame.
    #[must_use]
    pub fn report(
        &self,
        session_id: SessionId,
        bindings: Vec<LiveBinding>,
    ) -> Vec<PluginAdmissionsAck> {
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
            .filter_map(|(digest, read)| {
                read.as_ref().err().map(|why| {
                    let (detail, detail_cut) = cut(why, MAX_REPORT_DETAIL_BYTES);
                    PackageRefusal {
                        package_digest: *digest,
                        detail,
                        detail_cut,
                    }
                })
            })
            .collect();
        drop(held);
        page(session_id, frame, report_seq, bindings, refusals)
    }
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

/// Reads one admitted package from its checked copy: a connector where it has a connector table,
/// and otherwise its manifest, checked against the admitted hash with the SDK's package check.
fn read_package(package: &AdmittedPackage) -> Result<ReadPackage, String> {
    let directory = PathBuf::from(&package.package_dir);
    let validated = kr_plugin_sdk::validate::validate_package_directory(&directory);
    if !validated.report.is_valid() {
        let findings: Vec<String> = validated
            .report
            .findings
            .iter()
            .map(ToString::to_string)
            .collect();
        return Err(format!(
            "the package in {} does not pass the package check: {}",
            directory.display(),
            findings.join("; ")
        ));
    }
    let checked = validated
        .package
        .ok_or_else(|| format!("the package in {} could not be read", directory.display()))?;
    let manifest_file = checked
        .files
        .iter()
        .find(|file| file.path.as_str() == kr_plugin_sdk::package::MANIFEST_FILE)
        .ok_or_else(|| format!("the package in {} has no manifest", directory.display()))?;
    if manifest_file.digest.as_bytes() != package.package_digest.as_bytes() {
        return Err(format!(
            "the package in {} is not the admitted one: its manifest does not hash to the \
             admitted hash",
            directory.display()
        ));
    }
    if checked.manifest.plugin_id() != package.plugin_id {
        return Err(format!(
            "the package in {} is {}, not the admitted {}",
            directory.display(),
            checked.manifest.plugin_id(),
            package.plugin_id
        ));
    }
    if checked.manifest.payload(PayloadRole::Connector).is_some() {
        return InstalledConnector::read(source_of(package))
            .map(|connector| ReadPackage::Connector(Arc::new(connector)))
            .map_err(|refusal| refusal.detail);
    }
    Ok(ReadPackage::Declarative(Arc::new(checked.manifest)))
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
