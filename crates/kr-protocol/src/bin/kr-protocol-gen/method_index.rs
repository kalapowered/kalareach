//! The documentation's side of the method registry.
//!
//! A reader who meets a method on the wire has to be able to find it in `docs/`. Two things here
//! make sure of that. The method index is generated from the registry, so it lists every method in
//! the registry's groups and order and cannot list one the registry does not have. The check reads
//! the registry and every Markdown document under the documentation root other than the index,
//! which names every method by construction. It names each method that no other document mentions
//! and each index link whose document or section is not there any more.
//!
//! What a link points at is decided here, in [`described_in`], one arm per method. The match is
//! exhaustive, so a method added to the registry does not build until somebody has decided which
//! section describes it.
//!
//! A link goes to the document and names the section in its words. The check reads lines, not
//! Markdown: a section is there when the document has a line that is one to six `#`, a space and
//! exactly the section's heading. Nothing here depends on how a page renders or anchors a heading.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kr_protocol::method::{Method, MethodGroup, REGISTRY};

/// Where the index is written, relative to the documentation root.
pub(crate) const INDEX_PATH: &str = "protocol/methods.md";

/// A hand-written document under the documentation root.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Document {
    /// Its path relative to the documentation root.
    pub(crate) path: &'static str,
    /// What the index calls it.
    pub(crate) label: &'static str,
}

/// One section of a hand-written document, named by its heading.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Section {
    /// The document it is in.
    pub(crate) document: Document,
    /// The heading's text, exactly as the document writes it.
    pub(crate) heading: &'static str,
}

const PROTOCOL: Document = Document {
    path: "protocol/README.md",
    label: "Protocol",
};
const HOST: Document = Document {
    path: "host/README.md",
    label: "Host",
};
const DESCRIBE: Document = Document {
    path: "describe/README.md",
    label: "Descriptions",
};
const PLATFORMS: Document = Document {
    path: "host/platforms.md",
    label: "Platforms",
};
const PAIRING: Document = Document {
    path: "pairing/README.md",
    label: "Pairing",
};
const DELIVERY: Document = Document {
    path: "delivery/README.md",
    label: "Delivery",
};
const CATALOGUE: Document = Document {
    path: "plugins/catalogue.md",
    label: "Plugin catalogue",
};
const PLUGIN_APPROVALS: Document = Document {
    path: "plugins/sdk.md",
    label: "Plugin approvals",
};
const CONTACT: Document = Document {
    path: "contact/README.md",
    label: "Agent contact",
};
const TRANSFER: Document = Document {
    path: "transfer/README.md",
    label: "Transfer",
};
const PROJECT: Document = Document {
    path: "project/README.md",
    label: "Project",
};
const VOICE: Document = Document {
    path: "voice/README.md",
    label: "Voice",
};
const AUTOMATION: Document = Document {
    path: "automation/README.md",
    label: "Automation",
};
const HOST_UPDATES: Document = Document {
    path: "host/updates.md",
    label: "Host updates",
};

const METHOD_REFERENCE: Document = Document {
    path: "protocol/method-reference.md",
    label: "Method reference",
};

const fn at(document: Document, heading: &'static str) -> Section {
    Section { document, heading }
}

/// The section that describes what a method does.
///
/// A guide of the part of the product a method belongs to describes it where that guide has a
/// section that does. The method reference describes the rest.
pub(crate) const fn described_in(method: Method) -> Section {
    match method {
        Method::HostInfo | Method::EnvironmentList | Method::HostDoctor => {
            at(METHOD_REFERENCE, "Host and environment reads")
        }
        Method::EnvironmentEnrol | Method::EnvironmentInventory | Method::EnvironmentRefresh => {
            at(HOST, "The enrolled environments, and the cached inventory")
        }
        Method::EnvironmentForget => at(METHOD_REFERENCE, "Forgetting an environment"),
        Method::EnvironmentCapabilities | Method::EnvironmentCapabilitiesCheck => {
            at(PLATFORMS, "What may be done on a desktop")
        }
        Method::DeliveryDestinationConfigure
        | Method::DeliveryDestinationRemove
        | Method::DeliveryDestinationList => at(DELIVERY, "Configuring and removing a destination"),
        Method::DeliveryDestinationSecretSet => at(DELIVERY, "Credentials"),
        Method::PrivacySet | Method::PrivacyStatus => at(HOST, "Privacy mode"),
        Method::BackupRead | Method::BackupBundleWrite => {
            at(HOST, "Reading a backup for a restore")
        }
        Method::BackupStatus | Method::BackupEnable => at(HOST, "Setting up backups"),
        Method::AccountSignIn | Method::AccountSignOut | Method::AccountStatus => {
            at(HOST, "Account sign-in")
        }
        Method::HostUpdateHandover => at(HOST_UPDATES, "The handover"),
        Method::OrganisationEnrol
        | Method::OrganisationList
        | Method::OrganisationPolicyApply
        | Method::OrganisationExclusiveSet
        | Method::OrganisationWithdraw
        | Method::MembershipPresent => at(HOST, "Organisation policy"),
        Method::DescriptionSetup | Method::DescriptionConfigure | Method::DescriptionDownload => {
            at(DESCRIBE, "Setup")
        }
        Method::MachineJoin | Method::MachineMerge | Method::MachineSplit => {
            at(HOST, "Machine groups")
        }

        Method::PairInvite | Method::PairFinish | Method::PairConfirm => {
            at(PAIRING, "The exchange")
        }
        Method::PairRedeem | Method::PairCancel | Method::PairStatus => at(PAIRING, "Direct QR"),

        Method::DeviceList => at(HOST, "Grants, sharing and revocation"),
        Method::DeviceRevoke => at(HOST, "Revocation"),
        Method::DeviceKeysComplete => at(METHOD_REFERENCE, "Completing a device's keys"),
        Method::DevicePreviewKeyUpdate => at(DELIVERY, "What travels, and what does not"),
        Method::DevicePushRegister => at(DELIVERY, "A paired device becomes a destination"),

        Method::CatalogueList | Method::PluginList | Method::PluginRemove => {
            at(HOST, "The plugin catalogue")
        }
        Method::CataloguePin | Method::PluginPin => {
            at(METHOD_REFERENCE, "Pinning a repository or a package")
        }
        Method::CatalogueAdd | Method::CatalogueRemove => at(CATALOGUE, "Enrolment comes first"),
        Method::CatalogueSync => at(CATALOGUE, "What a sync does"),

        Method::PluginInstall => at(CATALOGUE, "Two activations, each atomic on its own"),
        Method::PluginEnable | Method::PluginDisable => {
            at(CATALOGUE, "Matching, enabling and binding")
        }
        Method::PluginGrant | Method::PluginCapabilities => {
            at(CATALOGUE, "Capabilities and qualification")
        }

        Method::PluginActionInvoke => at(PLUGIN_APPROVALS, "The call names the request"),

        Method::QuestionCreate => at(CONTACT, "What binds a helper to a session"),
        Method::QuestionReadOwn => at(CONTACT, "The caller token"),
        Method::QuestionCancelOwn | Method::QuestionCancel => at(CONTACT, "Cancellation"),
        Method::AlertCreate => at(CONTACT, "The four tools"),
        Method::QuestionRead => at(CONTACT, "Answering from the terminal"),
        Method::QuestionAnswer => at(CONTACT, "Questions"),

        Method::AgentToolsInstall | Method::AgentToolsStatus | Method::AgentToolsRemove => {
            at(CONTACT, "Installing the skill")
        }

        Method::SessionList | Method::SessionRead => at(METHOD_REFERENCE, "Reading sessions"),
        Method::SessionCreate => at(HOST, "Creating a session"),
        Method::SessionClose => at(HOST, "Closure"),
        Method::SessionDescribe | Method::SessionRename => {
            at(HOST, "Session names and descriptions")
        }
        Method::SessionOpen => at(HOST, "Grants, sharing and revocation"),
        Method::SessionScreenPreview => at(HOST, "Grants, sharing and revocation"),

        Method::SessionAttach => at(PROTOCOL, "Rights and capabilities are not the same thing"),
        Method::SessionDetach | Method::AttachmentConfigure => at(METHOD_REFERENCE, "Attachments"),
        Method::AttachmentViewport | Method::TerminalResize | Method::TerminalGeometryTransfer => {
            at(HOST, "Who owns the size")
        }
        Method::TerminalPaletteSet => at(METHOD_REFERENCE, "The terminal palette"),

        Method::InputAcquire | Method::InputRelease | Method::InputWrite => {
            at(HOST, "Who may type")
        }
        Method::InputInterrupt => at(METHOD_REFERENCE, "Interrupting the foreground"),

        Method::RootEditorEnter
        | Method::RootEditorLeave
        | Method::RootEditorFence
        | Method::RootEofDetach
        | Method::RootCommandAccepted
        | Method::ShellLaunch => at(PROTOCOL, "The root integration"),

        Method::AgentCapabilities
        | Method::AgentSnapshot
        | Method::AgentCommands
        | Method::AgentPromptSubmit
        | Method::AgentPromptQueue
        | Method::AgentTurnSteer
        | Method::AgentTurnCancel
        | Method::AgentApprovalRespond
        | Method::AgentApprovalInspect => at(METHOD_REFERENCE, "The agent methods"),

        Method::DraftCreate | Method::DraftUpdate | Method::AgentDraftAddAttachment => {
            at(TRANSFER, "Attachments, drafts and insertion")
        }
        Method::UploadBegin
        | Method::UploadStatus
        | Method::UploadChunk
        | Method::UploadFinish
        | Method::UploadCancel
        | Method::DownloadBegin
        | Method::DownloadChunk => at(TRANSFER, "The seven methods"),

        Method::ProjectList
        | Method::ProjectRead
        | Method::ProjectInit
        | Method::ProjectClone
        | Method::ProjectAdopt
        | Method::ProjectOperationCancel
        | Method::WorkspaceList
        | Method::WorkspaceCreate
        | Method::WorkspaceRead
        | Method::WorkspaceRemove => at(PROJECT, "The ten methods"),
        Method::ProjectLocationList
        | Method::ProjectLocationAuthorise
        | Method::ProjectLocationWithdraw
        | Method::ProjectLocationAttach => at(PROJECT, "Authorised locations"),

        Method::DiffRead
        | Method::DiffApply
        | Method::DiffRevert
        | Method::ChangesetCapture
        | Method::ChangesetRead
        | Method::ChangesetMaterialize => at(PROJECT, "Change sets"),

        Method::ReviewRead => at(METHOD_REFERENCE, "Reading review state"),
        Method::ReviewAcknowledge => at(HOST, "Review, and what it does not do"),
        Method::AttentionRead => at(HOST, "What a caller is served"),
        Method::AttentionAcknowledge => at(HOST, "Acknowledgement"),
        Method::AttentionQuietHours | Method::VisitAcknowledge => {
            at(METHOD_REFERENCE, "Quiet hours and visits")
        }
        Method::VisitChanged => at(HOST, "Changed since a visit"),

        Method::ActionCancel | Method::ActionRead => {
            at(METHOD_REFERENCE, "Reading and cancelling an action")
        }

        Method::OwnerConfirmationRequest
        | Method::OwnerConfirmationPending
        | Method::OwnerConfirmationComplete => at(PAIRING, "Owner confirmation"),
        Method::HostClockEstablish => at(HOST, "The host time contract"),

        Method::EventsSubscribe
        | Method::EventsSnapshot
        | Method::AgentInstances
        | Method::HistoryPage => at(METHOD_REFERENCE, "Events, snapshots and history"),

        Method::GrantCreate | Method::GrantRedeem | Method::GrantTransfer | Method::GrantHeld => {
            at(PAIRING, "Grants")
        }
        Method::GrantRevoke => at(HOST, "Revocation"),
        Method::GrantList => at(HOST, "Grants, sharing and revocation"),

        Method::PushInstallationRegister
        | Method::PushSenderIssue
        | Method::PushSenderRenew
        | Method::PushSenderRevoke => at(PROTOCOL, "Push objects"),
        Method::MailboxRead | Method::MailboxDeliver | Method::MailboxAcknowledge => {
            at(METHOD_REFERENCE, "The mailbox")
        }
        Method::AuthoritySync => at(METHOD_REFERENCE, "The authority feed"),
        Method::SyncCompareExchange => at(METHOD_REFERENCE, "Settings sync"),
        Method::BackupManifest => at(METHOD_REFERENCE, "The backup manifest"),
        Method::StorageStatus
        | Method::StorageRetentionSet
        | Method::StorageUploadCreate
        | Method::StorageUploadPart
        | Method::StorageUploadComplete
        | Method::StorageUploadAbort
        | Method::StorageObjectRead
        | Method::StorageObjectDelete => at(METHOD_REFERENCE, "Managed storage"),

        Method::VoicePrepare | Method::VoiceStart => at(VOICE, "The rate a call runs under"),
        Method::VoiceStop => at(VOICE, "A voice session is not a terminal session"),
        Method::VoiceGrant => at(VOICE, "The voice grant"),
        Method::VoiceDelegate => at(VOICE, "What is never authority"),
        Method::VoiceContext => at(VOICE, "What the coordinator may send back"),

        Method::WorkflowInstall
        | Method::WorkflowEnable
        | Method::WorkflowPause
        | Method::WorkflowRun
        | Method::WorkflowRearm
        | Method::WorkflowRead => at(AUTOMATION, "The six methods"),
    }
}

/// Returns a link from the index to a section: to its document, naming the section.
fn link(section: &Section) -> String {
    let target = match section.document.path.strip_prefix("protocol/") {
        Some(sibling) => sibling.to_owned(),
        None => format!("../{}", section.document.path),
    };
    format!(
        "[{}: {}]({target})",
        section.document.label, section.heading
    )
}

/// Returns true when a document has a heading line with exactly this text.
pub(crate) fn has_heading(text: &str, heading: &str) -> bool {
    text.lines().any(|line| {
        let level = line.bytes().take_while(|byte| *byte == b'#').count();
        (1..=6).contains(&level) && line[level..].strip_prefix(' ') == Some(heading)
    })
}

/// Returns a group's title, from its wire name.
fn group_title(group: MethodGroup) -> String {
    let value = serde_json::to_value(group).expect("a method group serialises");
    let name = value.as_str().expect("a method group is a string");
    let mut title = name.replace('_', " ");
    title[..1].make_ascii_uppercase();
    title
}

/// Returns a registry value's wire name.
fn wire_name(value: impl serde::Serialize) -> String {
    let value = serde_json::to_value(value).expect("a registry value serialises");
    value
        .as_str()
        .expect("a registry value is a string")
        .to_owned()
}

/// The index's opening, one line of Markdown each.
const HEADER: &[&str] = &[
    "# Method index",
    "",
    "<!-- Generated by kr-protocol-gen from crates/kr-protocol/src/method.rs. Do not edit by hand. -->",
    "",
    "Every method in the method registry, in the registry's groups and in its order. Anything not",
    "listed is denied.",
    "",
    "Each row gives the method's effect, the ingress classes that may reach it and the registry's own",
    "summary. The complete authority entry of every method is in",
    "[`packages/protocol/schema/method-authority.json`](../../packages/protocol/schema/method-authority.json),",
    "and [the method and authority table](README.md#the-method-and-authority-table) explains its fields.",
    "The last column names the section that describes what the method does and links to its",
    "document.",
];

/// Returns the method index.
pub(crate) fn render() -> String {
    let mut out = HEADER.join("\n");
    out.push('\n');
    let mut group = None;
    for entry in REGISTRY {
        if group != Some(entry.group) {
            group = Some(entry.group);
            out.push_str(&format!(
                "\n## {}\n\n| Method | Effect | Ingress | Summary | Described in |\n\
                 | --- | --- | --- | --- | --- |\n",
                group_title(entry.group)
            ));
        }
        let ingress: Vec<String> = entry
            .ingress
            .iter()
            .map(|ingress| format!("`{}`", ingress.as_str()))
            .collect();
        let described = link(&described_in(entry.method));
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} |\n",
            entry.name,
            wire_name(entry.effect),
            ingress.join(", "),
            entry.summary.replace('|', "\\|"),
            described
        ));
    }
    out
}

/// Returns a description of every index link whose document or section is not there.
pub(crate) fn broken_links(docs: &Path) -> Vec<String> {
    let mut documents: BTreeMap<&str, Option<String>> = BTreeMap::new();
    let mut broken = Vec::new();
    for entry in REGISTRY {
        let section = described_in(entry.method);
        let path = section.document.path;
        let text = documents
            .entry(path)
            .or_insert_with(|| std::fs::read_to_string(docs.join(path)).ok());
        match text {
            None => broken.push(format!(
                "{}: {path} is not a document under {}",
                entry.name,
                docs.display()
            )),
            Some(text) if !has_heading(text, section.heading) => broken.push(format!(
                "{}: {path} has no heading line \"{}\"",
                entry.name, section.heading
            )),
            Some(_) => {}
        }
    }
    broken
}

/// Returns every Markdown document under `root`, in path order.
///
/// Symbolic links are not followed: a document is a file in the tree.
pub(crate) fn markdown_documents(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            let path = entry.path();
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() && path.extension().is_some_and(|extension| extension == "md")
            {
                found.push(path);
            }
        }
    }
    found.sort();
    Ok(found)
}

/// Returns true when `text` names `name` as a whole method name.
///
/// `session.read` inside `session.read_own`, or `pair.status` inside a longer dotted name, is not
/// a mention of it. A full stop that ends a sentence is.
pub(crate) fn names(text: &str, name: &str) -> bool {
    let bytes = text.as_bytes();
    let continues = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    text.match_indices(name).any(|(start, _)| {
        let end = start + name.len();
        let opens = start == 0 || !(continues(bytes[start - 1]) || bytes[start - 1] == b'.');
        let closes = match bytes.get(end) {
            None => true,
            Some(&b'.') => !bytes.get(end + 1).copied().is_some_and(continues),
            Some(&byte) => !continues(byte),
        };
        opens && closes
    })
}

/// Returns the registry methods that no Markdown document under `docs` names, in registry order.
///
/// The index is not one of the documents: it lists every method, so counting it would leave
/// nothing to find.
pub(crate) fn unnamed_methods(docs: &Path) -> std::io::Result<Vec<&'static str>> {
    let mut texts = Vec::new();
    for document in markdown_documents(docs)? {
        if document
            .strip_prefix(docs)
            .is_ok_and(|relative| relative == Path::new(INDEX_PATH))
        {
            continue;
        }
        texts.push(std::fs::read_to_string(&document)?);
    }
    Ok(REGISTRY
        .iter()
        .map(|entry| entry.name)
        .filter(|name| !texts.iter().any(|text| names(text, name)))
        .collect())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use kr_protocol::method::REGISTRY;

    use super::{
        INDEX_PATH, broken_links, described_in, has_heading, markdown_documents, names, render,
        unnamed_methods,
    };

    fn docs() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs")
    }

    /// A copy of the documentation in a directory of the test's own, removed when it is dropped.
    struct DocsCopy(PathBuf);

    impl DocsCopy {
        fn of_the_documentation(name: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("kr-protocol-gen-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let source = docs();
            for document in markdown_documents(&source).expect("read the documentation") {
                let relative = document.strip_prefix(&source).expect("under the root");
                let target = root.join(relative);
                std::fs::create_dir_all(target.parent().expect("a parent")).expect("create");
                std::fs::copy(&document, &target).expect("copy");
            }
            Self(root)
        }

        fn edit(&self, document: &str, from: &str, to: &str) {
            let path = self.0.join(document);
            let text = std::fs::read_to_string(&path).expect("read");
            assert!(text.contains(from), "{document} holds {from:?}");
            std::fs::write(&path, text.replacen(from, to, 1)).expect("write");
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for DocsCopy {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_name_is_found_only_as_a_whole_method_name() {
        assert!(names("call `session.read` first", "session.read"));
        assert!(names("session.read", "session.read"));
        assert!(names("it answers session.read.", "session.read"));
        assert!(!names("`session.read_own`", "session.read"));
        assert!(!names("`xsession.read`", "session.read"));
        assert!(!names("`plugin.session.read`", "session.read"));
        assert!(!names("`session.read.page`", "session.read"));
    }

    #[test]
    fn the_committed_index_is_what_the_registry_generates() {
        let path = docs().join(INDEX_PATH);
        let committed = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        assert!(
            committed == render(),
            "{} is out of date; run `cargo run -p kr-protocol --bin kr-protocol-gen`",
            path.display()
        );
    }

    #[test]
    fn every_index_link_lands_on_its_heading() {
        assert_eq!(broken_links(&docs()), Vec::<String>::new());
    }

    #[test]
    fn every_registry_method_is_named_in_a_document() {
        assert_eq!(
            unnamed_methods(&docs()).expect("read the documentation"),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn a_link_whose_heading_changed_is_broken() {
        let copy = DocsCopy::of_the_documentation("renamed-heading");
        copy.edit(
            "plugins/catalogue.md",
            "## What a sync does\n",
            "## What synchronising does\n",
        );
        assert_eq!(
            broken_links(copy.path()),
            ["catalogue.sync: plugins/catalogue.md has no heading line \"What a sync does\""]
        );
    }

    #[test]
    fn a_heading_line_is_one_to_six_hashes_a_space_and_exactly_the_text() {
        let text = "# Title\n## The exchange\n### Budgets\n### Spaced  \n####### Seven\n#Tight\n\
                    The exchange, again\n";
        assert!(has_heading(text, "Title"));
        assert!(has_heading(text, "The exchange"));
        assert!(has_heading(text, "Budgets"));
        assert!(!has_heading(text, "Spaced"));
        assert!(!has_heading(text, "Seven"));
        assert!(!has_heading(text, "Tight"));
        assert!(!has_heading(text, "The exchange, again"));
        assert!(!has_heading(text, "exchange"));
    }

    #[test]
    fn a_link_to_a_missing_document_is_broken() {
        let copy = DocsCopy::of_the_documentation("missing-document");
        std::fs::remove_file(copy.path().join("automation/README.md")).expect("remove");
        let broken = broken_links(copy.path());
        let described_there = REGISTRY
            .iter()
            .filter(|entry| described_in(entry.method).document.path == "automation/README.md")
            .count();
        assert!(
            described_there > 0,
            "the automation methods are described there"
        );
        assert_eq!(broken.len(), described_there, "{broken:?}");
        assert!(
            broken
                .iter()
                .all(|line| line.contains("automation/README.md is not a document")),
            "{broken:?}"
        );
    }

    #[test]
    fn the_index_does_not_count_as_a_document_that_names_a_method() {
        let root =
            std::env::temp_dir().join(format!("kr-protocol-gen-index-only-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let copy = DocsCopy(root);
        std::fs::create_dir_all(copy.path().join("protocol")).expect("create");
        std::fs::create_dir_all(copy.path().join("host")).expect("create");
        std::fs::write(copy.path().join(INDEX_PATH), render()).expect("write the index");
        std::fs::write(
            copy.path().join("host/README.md"),
            "`session.read` answers one session.\n",
        )
        .expect("write");
        let unnamed = unnamed_methods(copy.path()).expect("read the documentation");
        assert!(!unnamed.contains(&"session.read"), "{unnamed:?}");
        assert!(unnamed.contains(&"session.list"), "{unnamed:?}");
        assert_eq!(unnamed.len(), REGISTRY.len() - 1, "{unnamed:?}");
    }
}
