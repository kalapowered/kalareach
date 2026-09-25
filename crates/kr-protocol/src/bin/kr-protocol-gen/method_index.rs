//! The documentation's side of the method registry.
//!
//! A reader who meets a method on the wire has to be able to find it in `docs/`. Two things here
//! make sure of that. The method index is generated from the registry, so it lists every method in
//! the registry's groups and order and cannot list one the registry does not have. The check reads
//! the registry and every Markdown document under the documentation root, names each method that no
//! document mentions, and names each index link whose document or heading is not there any more.
//!
//! What a link points at is decided here, in [`described_in`], one arm per method. The match is
//! exhaustive, so a method added to the registry does not build until somebody has decided which
//! section describes it, or that none does.

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

const fn at(document: Document, heading: &'static str) -> Option<Section> {
    Some(Section { document, heading })
}

/// The section that describes what a method does, where a document outside the index does.
pub(crate) const fn described_in(method: Method) -> Option<Section> {
    match method {
        Method::HostInfo
        | Method::EnvironmentList
        | Method::EnvironmentCapabilities
        | Method::HostDoctor
        | Method::EnvironmentEnrol
        | Method::EnvironmentForget
        | Method::EnvironmentInventory
        | Method::EnvironmentRefresh => None,
        Method::DeliveryDestinationSecretSet => at(DELIVERY, "Credentials"),

        Method::PairInvite | Method::PairFinish | Method::PairConfirm => {
            at(PAIRING, "The exchange")
        }
        Method::PairRedeem | Method::PairCancel | Method::PairStatus => at(PAIRING, "Direct QR"),

        Method::DeviceList | Method::DeviceRevoke | Method::DeviceKeysComplete => None,
        Method::DevicePreviewKeyUpdate => at(DELIVERY, "What travels, and what does not"),

        Method::CatalogueList | Method::CataloguePin => None,
        Method::CatalogueAdd | Method::CatalogueRemove => at(CATALOGUE, "Enrolment comes first"),
        Method::CatalogueSync => at(CATALOGUE, "What a sync does"),

        Method::PluginList | Method::PluginRemove | Method::PluginPin => None,
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

        Method::SessionList
        | Method::SessionCreate
        | Method::SessionRead
        | Method::SessionClose
        | Method::SessionDescribe
        | Method::SessionRename => None,

        Method::SessionAttach => at(PROTOCOL, "Rights and capabilities are not the same thing"),
        Method::SessionDetach
        | Method::AttachmentConfigure
        | Method::AttachmentViewport
        | Method::TerminalResize
        | Method::TerminalGeometryTransfer
        | Method::TerminalPaletteSet => None,

        Method::InputAcquire
        | Method::InputRelease
        | Method::InputInterrupt
        | Method::InputWrite => None,

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
        | Method::AgentApprovalRespond => None,

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

        Method::ReviewRead
        | Method::ReviewAcknowledge
        | Method::AttentionRead
        | Method::AttentionAcknowledge
        | Method::AttentionQuietHours
        | Method::VisitAcknowledge
        | Method::VisitChanged => None,

        Method::ActionCancel => None,

        Method::OwnerConfirmationRequest
        | Method::OwnerConfirmationPending
        | Method::OwnerConfirmationComplete => at(PAIRING, "Owner confirmation"),

        Method::EventsSubscribe
        | Method::EventsSnapshot
        | Method::HistoryPage
        | Method::ActionRead => None,

        Method::GrantCreate => at(PAIRING, "Grants"),
        Method::GrantRevoke | Method::GrantList => None,

        Method::PushInstallationRegister
        | Method::PushSenderIssue
        | Method::PushSenderRenew
        | Method::PushSenderRevoke => at(PROTOCOL, "Push objects"),
        Method::MailboxRead
        | Method::MailboxDeliver
        | Method::MailboxAcknowledge
        | Method::AuthoritySync
        | Method::SyncCompareExchange
        | Method::BackupManifest
        | Method::StorageStatus
        | Method::StorageRetentionSet
        | Method::StorageUploadCreate
        | Method::StorageUploadPart
        | Method::StorageUploadComplete
        | Method::StorageUploadAbort
        | Method::StorageObjectRead
        | Method::StorageObjectDelete => None,

        Method::VoicePrepare | Method::VoiceStart => at(VOICE, "The rate a call runs under"),
        Method::VoiceStop => at(VOICE, "A voice session is not a terminal session"),
        Method::VoiceGrant => at(VOICE, "The voice grant"),
        Method::VoiceDelegate => at(VOICE, "What is never authority"),
        Method::VoiceContext => at(VOICE, "What the coordinator may send back"),

        Method::WorkflowInstall
        | Method::WorkflowEnable
        | Method::WorkflowPause
        | Method::WorkflowRun
        | Method::WorkflowRead => at(AUTOMATION, "The five methods"),
    }
}

/// Returns the anchor a heading gets on the page it is rendered on.
///
/// Letters, digits, hyphens and underscores are kept, spaces become hyphens, and everything else
/// is dropped, after lower-casing. A second heading with the same anchor on one page gets a
/// numbered one instead, which [`broken_links`] refuses to point at.
pub(crate) fn anchor(heading: &str) -> String {
    heading
        .to_lowercase()
        .chars()
        .filter_map(|character| match character {
            ' ' => Some('-'),
            '-' | '_' => Some(character),
            other if other.is_alphanumeric() => Some(other),
            _ => None,
        })
        .collect()
}

/// Returns the text of every heading in a Markdown document, in order.
///
/// Only headings written with `#` count, and a line inside a fenced code block is not a heading.
pub(crate) fn headings(text: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut fence: Option<&str> = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if indent <= 3 {
            let marker = ["```", "~~~"]
                .into_iter()
                .find(|marker| trimmed.starts_with(marker));
            match (fence, marker) {
                (None, Some(marker)) => {
                    fence = Some(marker);
                    continue;
                }
                (Some(open), Some(marker)) if open == marker => {
                    fence = None;
                    continue;
                }
                _ => {}
            }
        }
        if fence.is_some() || indent > 3 {
            continue;
        }
        let level = trimmed.bytes().take_while(|byte| *byte == b'#').count();
        if !(1..=6).contains(&level) {
            continue;
        }
        let rest = &trimmed[level..];
        if !(rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t')) {
            continue;
        }
        let mut heading = rest.trim();
        let closing = heading.trim_end_matches('#');
        if closing.is_empty() || closing.ends_with(' ') || closing.ends_with('\t') {
            heading = closing.trim_end();
        }
        found.push(heading);
    }
    found
}

/// Returns a link from the index to a section.
fn link(section: &Section) -> String {
    let target = match section.document.path.strip_prefix("protocol/") {
        Some(sibling) => sibling.to_owned(),
        None => format!("../{}", section.document.path),
    };
    format!(
        "[{}: {}]({target}#{})",
        section.document.label,
        section.heading,
        anchor(section.heading)
    )
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
    "The last column links to the section that describes what the method does, where one does.",
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
        let described = described_in(entry.method)
            .map(|section| link(&section))
            .unwrap_or_default();
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

/// Returns a description of every index link whose document or heading is not there.
///
/// A link is sound when its document exists under `docs` and the first heading there with the
/// link's anchor is the heading the link names. An earlier heading with the same anchor would take
/// the anchor, and the link would land on it instead.
pub(crate) fn broken_links(docs: &Path) -> Vec<String> {
    let mut texts: BTreeMap<&str, Option<String>> = BTreeMap::new();
    let mut broken = Vec::new();
    for entry in REGISTRY {
        let Some(section) = described_in(entry.method) else {
            continue;
        };
        let text = texts
            .entry(section.document.path)
            .or_insert_with(|| std::fs::read_to_string(docs.join(section.document.path)).ok());
        let Some(text) = text else {
            broken.push(format!(
                "{}: {} is not a document under {}",
                entry.name,
                section.document.path,
                docs.display()
            ));
            continue;
        };
        let wanted = anchor(section.heading);
        match headings(text)
            .into_iter()
            .find(|heading| anchor(heading) == wanted)
        {
            Some(heading) if heading == section.heading => {}
            Some(heading) => broken.push(format!(
                "{}: #{wanted} in {} is the anchor of \"{heading}\", not of \"{}\"",
                entry.name, section.document.path, section.heading
            )),
            None => broken.push(format!(
                "{}: {} has no heading \"{}\"",
                entry.name, section.document.path, section.heading
            )),
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
pub(crate) fn unnamed_methods(docs: &Path) -> std::io::Result<Vec<&'static str>> {
    let mut texts = Vec::new();
    for document in markdown_documents(docs)? {
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

    use super::{
        INDEX_PATH, anchor, broken_links, headings, markdown_documents, names, render,
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
    fn an_anchor_is_the_heading_lower_cased_with_punctuation_dropped() {
        assert_eq!(anchor("What a reboot does"), "what-a-reboot-does");
        assert_eq!(anchor("The `kr` command line"), "the-kr-command-line");
        assert_eq!(
            anchor("An owner's confirmations"),
            "an-owners-confirmations"
        );
        assert_eq!(
            anchor("Two activations, each atomic on its own"),
            "two-activations-each-atomic-on-its-own"
        );
        assert_eq!(
            anchor("Shown before a call (KR-REQ-15.19)"),
            "shown-before-a-call-kr-req-1519"
        );
        assert_eq!(anchor("Café — déjà vu"), "café--déjà-vu");
        assert_eq!(anchor("snake_case stays"), "snake_case-stays");
    }

    #[test]
    fn a_heading_is_a_hash_line_outside_a_fence() {
        let text = "# Title\n\
                    text\n\
                    ## Section ##\n\
                    ```bash\n\
                    # a comment\n\
                    ```\n\
                    ~~~\n\
                    ## Also code\n\
                    ~~~\n\
                    #hashtag\n    \
                    ## indented code\n\
                    ### Last\n";
        assert_eq!(headings(text), ["Title", "Section", "Last"]);
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
            ["catalogue.sync: plugins/catalogue.md has no heading \"What a sync does\""]
        );
    }

    #[test]
    fn a_link_whose_anchor_an_earlier_heading_takes_is_broken() {
        let copy = DocsCopy::of_the_documentation("taken-anchor");
        copy.edit(
            "plugins/catalogue.md",
            "## Enrolment comes first\n",
            "## What a sync does?\n\n## Enrolment comes first\n",
        );
        assert_eq!(
            broken_links(copy.path()),
            [
                "catalogue.sync: #what-a-sync-does in plugins/catalogue.md is the anchor of \
                 \"What a sync does?\", not of \"What a sync does\""
            ]
        );
    }

    #[test]
    fn a_link_to_a_missing_document_is_broken() {
        let copy = DocsCopy::of_the_documentation("missing-document");
        std::fs::remove_file(copy.path().join("automation/README.md")).expect("remove");
        let broken = broken_links(copy.path());
        assert_eq!(broken.len(), 5, "{broken:?}");
        assert!(
            broken
                .iter()
                .all(|line| line.contains("automation/README.md is not a document")),
            "{broken:?}"
        );
    }

    #[test]
    fn a_method_only_the_index_named_is_undocumented_without_it() {
        let copy = DocsCopy::of_the_documentation("no-index");
        std::fs::remove_file(copy.path().join(INDEX_PATH)).expect("remove");
        let unnamed = unnamed_methods(copy.path()).expect("read the documentation");
        assert!(unnamed.contains(&"storage.upload.part"), "{unnamed:?}");
        assert!(!unnamed.contains(&"upload.begin"), "{unnamed:?}");
    }
}
