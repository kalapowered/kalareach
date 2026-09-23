//! The portable document node union, against the committed presentation documents.
//!
//! Section 11 fixes the union: `message`, `markdown`, `tool`, `diff`, `progress`, `form`,
//! `attachment`, `approval_ref` and `terminal_ref`, plus `action_button`, `action_group`,
//! `command_palette` and `attachment_entry`. Every node has a stable identifier and a revision, a
//! snapshot or delta names the base revision it applies to, and a node a client does not know
//! renders as an unsupported-content block that cannot invoke a hidden action.

use std::path::{Path, PathBuf};

use kr_plugin_sdk::effect::ParameterSchema;
use kr_plugin_sdk::ids::NodeId;
use kr_plugin_sdk::presentation::{
    Control, DiffFile, DocumentNode, NodeBody, NodeRevision, PresentationManifest, ProgressState,
    ToolOutcome, read_node,
};
use kr_plugin_sdk::scalars::Count;
use kr_plugin_sdk::text::{Label, Summary};
use kr_protocol::ids::{ApprovalRequestId, AttachmentId, SessionId};
use kr_protocol::scalars::{U64, Uuid};
use serde_json::{Value, json};

/// The node kinds section 11 names, in the order it names them.
const SPECIFIED: [&str; 13] = [
    "message",
    "markdown",
    "tool",
    "diff",
    "progress",
    "form",
    "attachment",
    "approval_ref",
    "terminal_ref",
    "action_button",
    "action_group",
    "command_palette",
    "attachment_entry",
];

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every presentation document a committed package carries.
fn committed_documents() -> Vec<(PathBuf, Value)> {
    let root = repository_root();
    let mut paths = vec![root.join("bundled-plugins/fixture/presentation.json")];
    let valid = root.join("fixtures/plugins/valid");
    let mut packages: Vec<PathBuf> = std::fs::read_dir(&valid)
        .unwrap_or_else(|error| panic!("{}: {error}", valid.display()))
        .map(|entry| entry.expect("a directory entry").path())
        .collect();
    packages.sort();
    paths.extend(
        packages
            .into_iter()
            .map(|package| package.join("presentation.json")),
    );
    paths
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            let value: Value = serde_json::from_str(&text).expect("a document is JSON");
            (path, value)
        })
        .collect()
}

/// A control taken from a committed document, so the nodes that carry one carry a real one.
fn committed_control() -> Control {
    let (_, document) = committed_documents()
        .into_iter()
        .find(|(_, document)| {
            document["nodes"]
                .as_array()
                .expect("nodes")
                .iter()
                .any(|node| node["body"]["kind"] == "action_group")
        })
        .expect("a committed document with an action group");
    let group = document["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .find(|node| node["body"]["kind"] == "action_group")
        .expect("the action group");
    serde_json::from_value(group["body"]["controls"][0].clone()).expect("a control")
}

fn label(text: &str) -> Label {
    Label::new(text).expect("a label")
}

/// KR-REQ-11.45: the node union is exactly the thirteen specified kinds, and a node of each kind
/// writes under its specified name and reads back as itself, with its identifier and revision.
#[test]
fn the_union_is_exactly_the_thirteen_specified_kinds() {
    assert_eq!(NodeBody::KINDS, SPECIFIED);

    let control = committed_control();
    let bodies = vec![
        NodeBody::Message {
            author: label("Agent"),
            text: Summary::new("The tests pass.").expect("a summary"),
        },
        NodeBody::Markdown {
            source: "# Status".to_owned(),
        },
        NodeBody::Tool {
            name: label("bash"),
            outcome: ToolOutcome::Succeeded,
            summary: Summary::new("Ran the test suite").expect("a summary"),
        },
        NodeBody::Diff {
            files: vec![DiffFile {
                path: "src/lib.rs".to_owned(),
                added: Count::new(3),
                removed: Count::new(1),
            }],
        },
        NodeBody::Progress {
            label: label("Building"),
            state: ProgressState::Determinate {
                completed: U64::new(2),
                total: U64::new(5),
            },
        },
        NodeBody::Form {
            title: label("Ask"),
            fields: ParameterSchema::default(),
            submit: control.clone(),
        },
        NodeBody::Attachment {
            attachment_id: AttachmentId::new(Uuid::from_bytes([7; 16])),
            name: label("screenshot.png"),
            size_bytes: U64::new(1_024),
        },
        NodeBody::ApprovalRef {
            approval_request_id: ApprovalRequestId::new("upstream-request-1")
                .expect("a ledger resource"),
        },
        NodeBody::TerminalRef {
            session_id: SessionId::new(Uuid::from_bytes([8; 16])),
        },
        NodeBody::ActionButton {
            control: control.clone(),
        },
        NodeBody::ActionGroup {
            label: label("Prompt"),
            controls: vec![control.clone()],
        },
        NodeBody::CommandPalette {
            controls: vec![control.clone()],
        },
        NodeBody::AttachmentEntry {
            label: label("Attach"),
            contribute: control,
        },
    ];
    let mut written = Vec::new();
    for (index, body) in bodies.into_iter().enumerate() {
        let node = DocumentNode {
            id: NodeId::new(format!("node-{index}")).expect("a node identifier"),
            revision: NodeRevision::new(index as u64 + 1),
            body,
        };
        let value = serde_json::to_value(&node).expect("a node serialises");
        assert_eq!(value["body"]["kind"], node.body.kind());
        assert_eq!(value["id"], format!("node-{index}"));
        assert_eq!(
            read_node(&value).as_ref(),
            Ok(&node),
            "{} reads back as itself",
            node.body.kind()
        );
        written.push(node.body.kind());
    }
    assert_eq!(written, SPECIFIED);
}

/// KR-REQ-11.45: every node of every committed presentation document reads, has a stable
/// identifier unique within its document and a revision, and each document names the base revision
/// a delta applies to.
#[test]
fn every_committed_node_has_a_stable_identifier_and_a_revision() {
    let documents = committed_documents();
    assert!(
        documents.len() >= 3,
        "the committed packages carry documents"
    );
    for (path, value) in documents {
        let document: PresentationManifest = serde_json::from_value(value.clone())
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        assert!(
            value.get("base_revision").is_some(),
            "{} names its base revision",
            path.display()
        );
        assert!(!document.nodes.is_empty(), "{}", path.display());
        let mut identifiers = std::collections::BTreeSet::new();
        for node in value["nodes"].as_array().expect("nodes") {
            let read = read_node(node)
                .unwrap_or_else(|unsupported| panic!("{}: {unsupported:?}", path.display()));
            assert!(
                identifiers.insert(read.id.clone()),
                "{}: {} is not unique",
                path.display(),
                read.id
            );
            assert!(
                node.get("revision").is_some(),
                "{}: {} carries a revision",
                path.display(),
                read.id
            );
        }
    }
}

/// KR-REQ-11.45: a node whose kind this build does not know, placed inside a committed document,
/// reads as an unsupported-content block that keeps its identifier and revision and can invoke
/// nothing, and every other node of that document still reads.
#[test]
fn an_unknown_node_is_an_unsupported_block_and_the_rest_of_the_document_reads() {
    let (path, mut value) = committed_documents()
        .into_iter()
        .next()
        .expect("a committed document");
    let known = value["nodes"].as_array().expect("nodes").len();
    value["nodes"].as_array_mut().expect("nodes").insert(
        1,
        json!({
            "id": "from-a-newer-package",
            "revision": "4",
            "body": {
                "kind": "hologram",
                "action_id": "delete.everything",
                "controls": [serde_json::to_value(committed_control()).expect("a control")]
            }
        }),
    );

    let mut readable = 0;
    let mut unsupported = Vec::new();
    for node in value["nodes"].as_array().expect("nodes") {
        match read_node(node) {
            Ok(_) => readable += 1,
            Err(block) => unsupported.push(block),
        }
    }
    assert_eq!(
        readable,
        known,
        "{}: every known node still reads",
        path.display()
    );
    assert_eq!(unsupported.len(), 1);
    let block = &unsupported[0];
    assert_eq!(block.id.as_str(), "from-a-newer-package");
    assert_eq!(block.revision.get(), 4);
    assert_eq!(block.kind, "hologram");
    assert!(
        block.action_ids().is_empty(),
        "an unsupported block invokes no action, whatever the unknown node carried"
    );
}
