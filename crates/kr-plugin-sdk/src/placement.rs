//! Where a package's native bridge is placed, and the shape of the files placed there.
//!
//! A bridge's recipe lists the files it installs and the application it installs them for. An
//! application reads such files from a folder of its own, under the account's home, in a layout of
//! its own. A package whose table carries a [`Placement`] names that layout: the directory under the
//! home, the area in it that holds one folder for each plugin, the files each folder holds and the
//! closed shape of each. A package that carries none gets the layout this crate holds for the
//! application's label, [`Placement::for_label`]: Claude Code's and Gemini CLI's, as data.
//!
//! The host places the files a declared placement names, so the declaration gives the application
//! files it reads, and an application can run what it reads. What the host checks is what is
//! written here, and no more: every file is JSON with no repeated member and has exactly the
//! members its shape names, with the kinds of value it names ([`Shape::check`]); every member named
//! `command` is the forwarder, which the controller reads independently of any shape; and no name
//! or text in a file holds a character that makes it a path or an expansion ([`Shape::text_refusal`]).
//! The host does not check what an application does with the members that stay.
//!
//! The same value is checked in the package check, by the controller before it reads a table to
//! place a bridge, and again before anything is written, by the functions here.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::forwarder;

/// Most components in a declared directory.
pub const MAX_DIRECTORY_COMPONENTS: usize = 3;

/// Most components in the tail of a placed file.
pub const MAX_TAIL_COMPONENTS: usize = 3;

/// Most files a placement names.
pub const MAX_FILES: usize = 8;

/// Deepest a shape may nest.
pub const MAX_SHAPE_DEPTH: usize = 8;

/// Most bytes in a component of a directory, an area or a tail.
pub const MAX_COMPONENT_BYTES: usize = 64;

/// Most characters the host's reading of a placement may have: the text with every field at its
/// largest (eight tails of three 64-byte components, a three-component directory, a 64-byte area,
/// a 64-byte application label, a 128-byte folder name, the key and the record clause).
pub const MAX_PLACEMENT_STATEMENT_CHARS: usize = 3_746;

/// Most bytes the value may take when it is written as JSON.
pub const MAX_SERIALISED_BYTES: usize = 16 * 1024;

/// Most bytes a text value of a placed file may have, where its shape does not say less.
pub const MAX_TEXT_BYTES: u32 = 4096;

/// The characters that make a string a path or an expansion for a program that reads it.
pub const REFUSED_MARKS: [char; 6] = ['/', '\\', ':', '~', '$', '`'];

/// Where a package says its native bridge is placed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Placement {
    /// The application's directory under the account's home, as plain components (one to three),
    /// each of a directory that exists. The host makes none and follows no link in it, except the
    /// first component of a compiled default that the package does not declare.
    pub directory: Vec<String>,
    /// The folder of the directory that holds one folder for each plugin: one plain component.
    pub area: String,
    /// The files each plugin's folder holds, one to eight, each tail named once.
    pub files: Vec<PlacedFile>,
    /// How the forwarder is written in a command of these files.
    pub command_form: CommandForm,
    /// How the application keeps one plugin for each name, where it does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub one_per_name: Option<NameCheck>,
}

/// One file of a placement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PlacedFile {
    /// Its path in the plugin's folder, one to three plain components.
    pub tail: String,
    /// What the file holds.
    pub shape: Shape,
}

/// How a command that starts the forwarder is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CommandForm {
    /// One line a shell runs: the command holds the forwarder and its words, and no `args`.
    Line,
    /// A program with its arguments in a list beside it: the command is the forwarder alone.
    ArgumentList,
}

/// How the application keeps one plugin for each name: the first it reads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct NameCheck {
    /// The tail of the manifest that gives a plugin its name. Its shape has a required `name`
    /// member of the kind `directory_name`.
    pub manifest: String,
    /// Whether the application does not read a folder whose name starts with a dot as a plugin.
    pub skips_hidden: bool,
}

/// The closed shape of a JSON value a placed file holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Shape {
    /// An object with exactly the members named, each of the shape given.
    Object {
        /// The members that may be there.
        members: Vec<ShapeMember>,
    },
    /// An object of any member names, each value of one shape.
    Map {
        /// What each value is.
        values: Box<Shape>,
    },
    /// A list, each item of one shape.
    Array {
        /// What each item is.
        items: Box<Shape>,
    },
    /// Text of at most this many bytes.
    Text {
        /// The most bytes.
        max_bytes: u32,
    },
    /// True or false.
    Boolean {},
    /// A number.
    Number {},
    /// Text that is exactly this.
    Exact {
        /// The text.
        value: String,
    },
    /// Text that is the name of the plugin's folder.
    DirectoryName {},
    /// Text that is `/dev/null/` and the name of the plugin's folder: where an application is told
    /// the plugin was installed from, which leads nowhere.
    RecordPath {},
    /// A hook handler that runs a command: `type` `command`, the command, and a name, arguments
    /// and a time limit. The command is the forwarder, in the placement's command form.
    CommandHandler {},
    /// A server that starts a program with a command: an optional `type` `stdio`, the command and
    /// its arguments. The command is the forwarder, in the placement's command form.
    StdioServer {},
}

/// One member of an object shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ShapeMember {
    /// Its name.
    pub name: String,
    /// Whether the object has to hold it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub required: bool,
    /// What it is.
    pub shape: Shape,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

/// One refusal of a placement, by its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementRefusal {
    /// A directory component is not plain.
    DirectoryNotPlain,
    /// A directory has more than three components, or none.
    DirectoryTooDeep,
    /// A declared placement is not the layout its label's compiled default has.
    DirectoryNotTheLabels,
    /// The area is not one plain component.
    AreaNotPlain,
    /// A tail is not one to three plain components.
    TailNotPlain,
    /// A tail is named twice.
    TailDuplicate,
    /// The placement names no file, or more than eight.
    NoFile,
    /// A shape nests deeper than eight.
    ShapeTooDeep,
    /// An object shape names a member twice.
    ShapeMemberDuplicate,
    /// The placement has no file that holds a command.
    ShapeHasNoCommand,
    /// A name or text the table declares holds a character that makes it a place.
    TextNamesAPlace,
    /// The name check does not name a manifest with a `name` of the kind `directory_name`.
    NameCheckBad,
    /// The placement written as JSON is over 16 KiB.
    TooLarge,
    /// The application's label is not one plain component, so it cannot be quoted in the reading.
    ApplicationNotPlain,
    /// The host's reading of the placement is longer than an owner is shown whole.
    StatementTooLong,
}

impl PlacementRefusal {
    /// The name the package check and the host give the refusal.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::DirectoryNotPlain => "placement.directory_not_plain",
            Self::DirectoryTooDeep => "placement.directory_too_deep",
            Self::DirectoryNotTheLabels => "placement.directory_not_the_labels",
            Self::AreaNotPlain => "placement.area_not_plain",
            Self::TailNotPlain => "placement.tail_not_plain",
            Self::TailDuplicate => "placement.tail_duplicate",
            Self::NoFile => "placement.no_file",
            Self::ShapeTooDeep => "placement.shape_too_deep",
            Self::ShapeMemberDuplicate => "placement.shape_member_duplicate",
            Self::ShapeHasNoCommand => "placement.shape_has_no_command",
            Self::TextNamesAPlace => "placement.text_names_a_place",
            Self::NameCheckBad => "placement.name_check_bad",
            Self::TooLarge => "placement.too_large",
            Self::ApplicationNotPlain => "placement.application_not_plain",
            Self::StatementTooLong => "placement.statement_too_long",
        }
    }
}

/// A refusal and what it is about.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{}: {detail}", .refusal.name())]
pub struct PlacementError {
    /// Which refusal.
    pub refusal: PlacementRefusal,
    /// What it is about.
    pub detail: String,
}

impl PlacementError {
    fn new(refusal: PlacementRefusal, detail: impl Into<String>) -> Self {
        Self {
            refusal,
            detail: detail.into(),
        }
    }
}

/// Reads the placement a connector table declares, from the table's own bytes, for a bridge for
/// `application`: `None` for a table that declares none, and why a table cannot be used for one
/// that cannot be read or whose placement is refused.
///
/// The controller and the installation statement both read a package's placement through this one
/// function, over the bytes the verified manifest pins.
///
/// # Errors
///
/// Returns the first refusal, or why the table cannot be read.
pub fn declared_in(table: &[u8], application: &str) -> Result<Option<Placement>, String> {
    let table: crate::connector::ConnectorManifest = serde_json::from_slice(table)
        .map_err(|error| format!("the connector table cannot be read: {error}"))?;
    let Some(placement) = table.placement else {
        return Ok(None);
    };
    let mut found = placement.refusals();
    found.extend(placement.refusals_for_label(application));
    found
        .first()
        .map_or(Ok(Some(placement)), |first| Err(first.to_string()))
}

/// True for a component of a directory, an area or a tail: one to 64 bytes of ASCII letters,
/// digits, space, `.`, `_` and `-`, not `.` or `..`, and no space at either end.
#[must_use]
pub fn is_plain_component(component: &str) -> bool {
    !component.is_empty()
        && component.len() <= MAX_COMPONENT_BYTES
        && component != "."
        && component != ".."
        && !component.starts_with(' ')
        && !component.ends_with(' ')
        && component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'.' | b'_' | b'-'))
}

/// True when a string is a place for a program that reads it: it holds a character of
/// [`REFUSED_MARKS`], or it is `.` or `..`.
#[must_use]
pub fn names_a_place(text: &str) -> bool {
    text == "." || text == ".." || text.contains(REFUSED_MARKS)
}

fn manifest_shape(members: &[&str], with_channels: bool) -> Shape {
    let text = Shape::Text {
        max_bytes: MAX_TEXT_BYTES,
    };
    let mut held = vec![ShapeMember {
        name: "name".to_owned(),
        required: true,
        shape: Shape::DirectoryName {},
    }];
    for member in members {
        held.push(ShapeMember {
            name: (*member).to_owned(),
            required: false,
            shape: text.clone(),
        });
    }
    if with_channels {
        held.push(ShapeMember {
            name: "channels".to_owned(),
            required: false,
            shape: Shape::Array {
                items: Box::new(Shape::Object {
                    members: vec![ShapeMember {
                        name: "server".to_owned(),
                        required: true,
                        shape: text,
                    }],
                }),
            },
        });
        held.push(ShapeMember {
            name: "defaultEnabled".to_owned(),
            required: false,
            shape: Shape::Boolean {},
        });
    }
    Shape::Object { members: held }
}

fn hooks_shape() -> Shape {
    let group = Shape::Object {
        members: vec![
            ShapeMember {
                name: "matcher".to_owned(),
                required: false,
                shape: Shape::Text {
                    max_bytes: MAX_TEXT_BYTES,
                },
            },
            ShapeMember {
                name: "hooks".to_owned(),
                required: true,
                shape: Shape::Array {
                    items: Box::new(Shape::CommandHandler {}),
                },
            },
        ],
    };
    Shape::Object {
        members: vec![ShapeMember {
            name: "hooks".to_owned(),
            required: true,
            shape: Shape::Map {
                values: Box::new(Shape::Array {
                    items: Box::new(group),
                }),
            },
        }],
    }
}

fn file(tail: &str, shape: Shape) -> PlacedFile {
    PlacedFile {
        tail: tail.to_owned(),
        shape,
    }
}

impl Placement {
    /// Claude Code's layout: `.claude/skills/<name>/` with its plugin manifest, its server file and
    /// its hooks file. A package that declares no placement for the label gets this.
    ///
    /// This is data for the installed 0.5.0 packages, which declare none and which a release never
    /// replaces. It goes when the oldest level the host reads has no package without a table.
    #[must_use]
    pub fn claude_code() -> Self {
        Self {
            directory: vec![".claude".to_owned()],
            area: "skills".to_owned(),
            files: vec![
                file(
                    ".claude-plugin/plugin.json",
                    manifest_shape(&["displayName", "version", "description"], true),
                ),
                file(
                    ".mcp.json",
                    Shape::Object {
                        members: vec![ShapeMember {
                            name: "mcpServers".to_owned(),
                            required: true,
                            shape: Shape::Map {
                                values: Box::new(Shape::StdioServer {}),
                            },
                        }],
                    },
                ),
                file("hooks/hooks.json", hooks_shape()),
            ],
            command_form: CommandForm::ArgumentList,
            one_per_name: Some(NameCheck {
                manifest: ".claude-plugin/plugin.json".to_owned(),
                skips_hidden: true,
            }),
        }
    }

    /// Gemini CLI's layout: `.gemini/extensions/<name>/` with its install record, its extension
    /// manifest and its hooks file. A package that declares no placement for the label gets this.
    ///
    /// This is data for the installed 0.5.0 packages, as [`Self::claude_code`] is.
    #[must_use]
    pub fn gemini_cli() -> Self {
        Self {
            directory: vec![".gemini".to_owned()],
            area: "extensions".to_owned(),
            files: vec![
                file(
                    ".gemini-extension-install.json",
                    Shape::Object {
                        members: vec![
                            ShapeMember {
                                name: "type".to_owned(),
                                required: true,
                                shape: Shape::Exact {
                                    value: "local".to_owned(),
                                },
                            },
                            ShapeMember {
                                name: "source".to_owned(),
                                required: true,
                                shape: Shape::RecordPath {},
                            },
                        ],
                    },
                ),
                file(
                    "gemini-extension.json",
                    manifest_shape(&["version", "description"], false),
                ),
                file("hooks/hooks.json", hooks_shape()),
            ],
            command_form: CommandForm::Line,
            one_per_name: Some(NameCheck {
                manifest: "gemini-extension.json".to_owned(),
                skips_hidden: false,
            }),
        }
    }

    /// The layout this crate holds for an application's label, where it holds one.
    #[must_use]
    pub fn for_label(application: &str) -> Option<Self> {
        match application {
            "Claude Code" => Some(Self::claude_code()),
            "Gemini CLI" => Some(Self::gemini_cli()),
            _ => None,
        }
    }

    /// The compiled labels and their layouts.
    #[must_use]
    pub fn defaults() -> [(&'static str, Self); 2] {
        [
            ("Claude Code", Self::claude_code()),
            ("Gemini CLI", Self::gemini_cli()),
        ]
    }

    /// The shape of the file at `tail`.
    #[must_use]
    pub fn shape_of(&self, tail: &str) -> Option<&Shape> {
        self.files
            .iter()
            .find(|placed| placed.tail == tail)
            .map(|placed| &placed.shape)
    }

    /// The directory as one relative path, `.claude` or `Library/Application Support`.
    #[must_use]
    pub fn directory_path(&self) -> String {
        self.directory.join("/")
    }

    /// Every way this placement is not one a host places, in the order a reader meets them.
    #[must_use]
    pub fn refusals(&self) -> Vec<PlacementError> {
        let mut found = Vec::new();
        if self.directory.is_empty() || self.directory.len() > MAX_DIRECTORY_COMPONENTS {
            found.push(PlacementError::new(
                PlacementRefusal::DirectoryTooDeep,
                format!(
                    "the directory has {} components, and a placement names one to \
                     {MAX_DIRECTORY_COMPONENTS}",
                    self.directory.len()
                ),
            ));
        }
        for component in &self.directory {
            if !is_plain_component(component) {
                found.push(PlacementError::new(
                    PlacementRefusal::DirectoryNotPlain,
                    format!("{component:?} is not a plain component of a directory"),
                ));
            }
        }
        if !is_plain_component(&self.area) {
            found.push(PlacementError::new(
                PlacementRefusal::AreaNotPlain,
                format!("{:?} is not one plain component", self.area),
            ));
        }
        if self.files.is_empty() || self.files.len() > MAX_FILES {
            found.push(PlacementError::new(
                PlacementRefusal::NoFile,
                format!(
                    "the placement names {} files, and a placement names one to {MAX_FILES}",
                    self.files.len()
                ),
            ));
        }
        let mut seen = BTreeSet::new();
        for placed in &self.files {
            let components: Vec<&str> = placed.tail.split('/').collect();
            if components.len() > MAX_TAIL_COMPONENTS
                || !components.iter().all(|part| is_plain_component(part))
            {
                found.push(PlacementError::new(
                    PlacementRefusal::TailNotPlain,
                    format!("{:?} is not one to three plain components", placed.tail),
                ));
            }
            if !seen.insert(placed.tail.as_str()) {
                found.push(PlacementError::new(
                    PlacementRefusal::TailDuplicate,
                    format!("{:?} is named twice", placed.tail),
                ));
            }
            placed.shape.refusals(1, &mut found);
        }
        if !self.files.iter().any(|placed| placed.shape.holds_command()) {
            found.push(PlacementError::new(
                PlacementRefusal::ShapeHasNoCommand,
                "no file of the placement holds a command, so it registers no forwarder",
            ));
        }
        if let Some(check) = &self.one_per_name {
            let named = self
                .shape_of(&check.manifest)
                .is_some_and(Shape::names_the_directory);
            if !named {
                found.push(PlacementError::new(
                    PlacementRefusal::NameCheckBad,
                    format!(
                        "{:?} is not a file of the placement whose shape has a required `name` of \
                         the kind directory_name",
                        check.manifest
                    ),
                ));
            }
        }
        let size = serde_json::to_vec(self).map_or(usize::MAX, |bytes| bytes.len());
        if size > MAX_SERIALISED_BYTES {
            found.push(PlacementError::new(
                PlacementRefusal::TooLarge,
                format!(
                    "it is {size} bytes as JSON, and a placement may be {MAX_SERIALISED_BYTES}"
                ),
            ));
        }
        found
    }

    /// Every way this placement is not one a bridge for `application` may declare. A label this
    /// crate holds a layout for declares that layout's directory, area and name check; and the
    /// directory of a compiled layout is declared only under its own label.
    #[must_use]
    pub fn refusals_for_label(&self, application: &str) -> Vec<PlacementError> {
        let mut found = Vec::new();
        for (label, default) in Self::defaults() {
            if label == application {
                if self.directory != default.directory
                    || self.area != default.area
                    || self.one_per_name != default.one_per_name
                {
                    found.push(PlacementError::new(
                        PlacementRefusal::DirectoryNotTheLabels,
                        format!(
                            "a placement for {application} declares the directory {}, the area {} \
                             and the name check {application} has: {}, {} and its own",
                            self.directory_path(),
                            self.area,
                            default.directory_path(),
                            default.area
                        ),
                    ));
                }
            } else if self.directory == default.directory {
                found.push(PlacementError::new(
                    PlacementRefusal::DirectoryNotTheLabels,
                    format!(
                        "the directory {} is {label}'s, and a placement for {application} does \
                         not declare it",
                        self.directory_path()
                    ),
                ));
            }
        }
        found
    }

    /// The host's exact reading of this placement for a bridge's recipe, as one line of plain text
    /// that the installation statement carries after
    /// [`kr_protocol::confirmation::PLACEMENT_STATEMENT_LABEL`]. The application is the recipe's
    /// label, the folder is the plugin's folder in the recipe's destinations and the key is the one
    /// the recipe adds, where it adds one.
    ///
    /// # Errors
    ///
    /// Returns [`PlacementRefusal::ApplicationNotPlain`] for a label that is not one plain
    /// component, and [`PlacementRefusal::StatementTooLong`] for a reading over
    /// [`MAX_PLACEMENT_STATEMENT_CHARS`].
    pub fn statement(
        &self,
        bridge: &crate::plugin::NativeBridge,
    ) -> Result<String, PlacementError> {
        let application = bridge.application.as_str();
        if !is_plain_component(application) {
            return Err(PlacementError::new(
                PlacementRefusal::ApplicationNotPlain,
                format!(
                    "{application:?} is not one plain component, so the reading cannot quote it"
                ),
            ));
        }
        let folder = bridge
            .install
            .iter()
            .find_map(|step| match step {
                crate::plugin::BridgeStep::InstallFile { destination, .. } => destination
                    .as_str()
                    .strip_prefix(self.area.as_str())
                    .and_then(|rest| rest.strip_prefix('/'))
                    .and_then(|rest| rest.split_once('/'))
                    .map(|(folder, _)| folder.to_owned()),
                crate::plugin::BridgeStep::AddConfigurationKey { .. } => None,
            })
            .unwrap_or_default();
        let directory = self.directory_path();
        let tails: Vec<&str> = self
            .files
            .iter()
            .map(|placed| placed.tail.as_str())
            .collect();
        let key = bridge.install.iter().find_map(|step| match step {
            crate::plugin::BridgeStep::AddConfigurationKey { file, key, .. } => Some(format!(
                "It also sets {key} to true in {directory}/{file}, and keeps your other \
                     settings in that file. "
            )),
            crate::plugin::BridgeStep::InstallFile { .. } => None,
        });
        let record = self
            .files
            .iter()
            .any(|placed| placed.shape.holds_record_path())
            .then(|| {
                format!(
                    ", except that an entry that records where the files were installed from \
                     must be the path /dev/null/{folder}, which leads nowhere and is not where \
                     the files are"
                )
            });
        let removed = if key.is_some() {
            " and the key it set"
        } else {
            ""
        };
        let text = format!(
            "This package places files for \"{application}\" in a folder it chose: \
             {directory}/{area}/{folder}/ under your home folder, files {tails}. \
             \"{application}\", or any other program that reads that folder, can run what the \
             files hold, as you, with your permissions and outside the plugin sandbox. {key}The \
             host places these files only after it has checked that each is JSON with no \
             repeated member name, that every entry named command in them starts the KalaReach \
             forwarder by its path, and that no other name or text in them holds a slash, a \
             backslash, a colon, a tilde, a dollar sign or a backtick or is a lone dot or two \
             dots{record}. The host does not check what \"{application}\", or another program, \
             does with the other settings in these files, and a plain file name in them can be \
             read by a program as a path. Removing the package takes out only what this host \
             placed{removed}; a file that has changed since stays in place, and the host reports \
             what it cannot remove.",
            area = self.area,
            tails = tails.join(", "),
            key = key.unwrap_or_default(),
            record = record.unwrap_or_default(),
        );
        if text.chars().count() > MAX_PLACEMENT_STATEMENT_CHARS {
            return Err(PlacementError::new(
                PlacementRefusal::StatementTooLong,
                format!(
                    "the host's reading of it is {} characters, and an owner is shown at most \
                     {MAX_PLACEMENT_STATEMENT_CHARS} whole",
                    text.chars().count()
                ),
            ));
        }
        Ok(text)
    }

    /// Checks one placed file's JSON against its shape, then against the text rule, in the order
    /// the controller checks them. `folder` is the plugin's folder name. A file that is not one of
    /// the placement's tails is refused.
    ///
    /// # Errors
    ///
    /// Returns why the file is not one the placement permits.
    pub fn check_file(&self, tail: &str, folder: &str, value: &Value) -> Result<(), String> {
        let shape = self
            .shape_of(tail)
            .ok_or_else(|| "this host names no shape for it".to_owned())?;
        shape.check(value, folder, self.command_form)?;
        shape.text_refusal(value).map_or(Ok(()), Err)
    }
}

impl Shape {
    fn refusals(&self, depth: usize, found: &mut Vec<PlacementError>) {
        if depth > MAX_SHAPE_DEPTH {
            found.push(PlacementError::new(
                PlacementRefusal::ShapeTooDeep,
                format!("a shape nests deeper than {MAX_SHAPE_DEPTH}"),
            ));
            return;
        }
        match self {
            Self::Object { members } => {
                let mut seen = BTreeSet::new();
                for member in members {
                    if !seen.insert(member.name.as_str()) {
                        found.push(PlacementError::new(
                            PlacementRefusal::ShapeMemberDuplicate,
                            format!("{:?} is named twice in one object", member.name),
                        ));
                    }
                    if names_a_place(&member.name) {
                        found.push(PlacementError::new(
                            PlacementRefusal::TextNamesAPlace,
                            format!(
                                "the member name {:?} holds a character of a place",
                                member.name
                            ),
                        ));
                    }
                    member.shape.refusals(depth + 1, found);
                }
            }
            Self::Map { values } => values.refusals(depth + 1, found),
            Self::Array { items } => items.refusals(depth + 1, found),
            Self::Exact { value } if names_a_place(value) => found.push(PlacementError::new(
                PlacementRefusal::TextNamesAPlace,
                format!("the exact text {value:?} holds a character of a place"),
            )),
            Self::Exact { .. }
            | Self::Text { .. }
            | Self::Boolean {}
            | Self::Number {}
            | Self::DirectoryName {}
            | Self::RecordPath {}
            | Self::CommandHandler {}
            | Self::StdioServer {} => {}
        }
    }

    /// Whether this shape or one below it is a command.
    fn holds_command(&self) -> bool {
        match self {
            Self::CommandHandler {} | Self::StdioServer {} => true,
            Self::Object { members } => members.iter().any(|member| member.shape.holds_command()),
            Self::Map { values } => values.holds_command(),
            Self::Array { items } => items.holds_command(),
            _ => false,
        }
    }

    /// Whether this is an object with a required `name` of the kind `directory_name`.
    fn names_the_directory(&self) -> bool {
        matches!(self, Self::Object { members } if members.iter().any(|member| {
            member.name == "name" && member.required && member.shape == Self::DirectoryName {}
        }))
    }

    /// Whether this shape or one below it is the record path.
    #[must_use]
    pub fn holds_record_path(&self) -> bool {
        match self {
            Self::RecordPath {} => true,
            Self::Object { members } => members
                .iter()
                .any(|member| member.shape.holds_record_path()),
            Self::Map { values } => values.holds_record_path(),
            Self::Array { items } => items.holds_record_path(),
            _ => false,
        }
    }

    /// Checks that `value` has this shape, for the plugin folder `folder`, with the forwarder in
    /// the command form `form`.
    ///
    /// # Errors
    ///
    /// Returns why the value is not of the shape.
    pub fn check(&self, value: &Value, folder: &str, form: CommandForm) -> Result<(), String> {
        match self {
            Self::Object { members } => {
                let Value::Object(held) = value else {
                    return Err("an object is expected and the file holds another kind".to_owned());
                };
                if let Some(other) = held
                    .keys()
                    .find(|key| !members.iter().any(|member| member.name == **key))
                {
                    return Err(format!(
                        "an object holds {other}, which this host does not name for it"
                    ));
                }
                for member in members {
                    match held.get(&member.name) {
                        Some(inner) => member.shape.check(inner, folder, form)?,
                        None if member.required => {
                            return Err(format!("an object has no {}", member.name));
                        }
                        None => {}
                    }
                }
                Ok(())
            }
            Self::Map { values } => match value {
                Value::Object(held) => held
                    .values()
                    .try_for_each(|inner| values.check(inner, folder, form)),
                _ => Err("an object is expected and the file holds another kind".to_owned()),
            },
            Self::Array { items } => match value {
                Value::Array(held) => held
                    .iter()
                    .try_for_each(|inner| items.check(inner, folder, form)),
                _ => Err("a list is expected and the file holds another kind".to_owned()),
            },
            Self::Text { max_bytes } => match value.as_str() {
                Some(text) if text.len() <= *max_bytes as usize => Ok(()),
                Some(_) => Err(format!("a text is longer than {max_bytes} bytes")),
                None => Err("a text is expected and the file holds another kind".to_owned()),
            },
            Self::Boolean {} => value
                .is_boolean()
                .then_some(())
                .ok_or_else(|| "true or false is expected".to_owned()),
            Self::Number {} => value
                .is_number()
                .then_some(())
                .ok_or_else(|| "a number is expected".to_owned()),
            Self::Exact { value: wanted } => (value.as_str() == Some(wanted.as_str()))
                .then_some(())
                .ok_or_else(|| format!("the text {wanted} is expected")),
            Self::DirectoryName {} => {
                (value.as_str() == Some(folder))
                    .then_some(())
                    .ok_or_else(|| {
                        format!("the name {folder}, the directory it is installed in, is expected")
                    })
            }
            Self::RecordPath {} => (value.as_str() == Some(format!("/dev/null/{folder}").as_str()))
                .then_some(())
                .ok_or_else(|| format!("the source /dev/null/{folder} is expected")),
            Self::CommandHandler {} => command_object(
                value,
                &["type", "name", "command", "args", "timeout"],
                Some("command"),
                form,
            ),
            Self::StdioServer {} => command_object(value, &["type", "command", "args"], None, form),
        }
    }

    /// The first name or text of a value of this shape that holds a character of a place, where
    /// the value has the shape. The record path is the one text that is let through. A value that
    /// has not the shape is read as plain JSON, every string refused alike.
    #[must_use]
    pub fn text_refusal(&self, value: &Value) -> Option<String> {
        match (self, value) {
            (Self::RecordPath {}, Value::String(_)) => None,
            (Self::Object { members }, Value::Object(held)) => {
                held.iter().find_map(|(key, inner)| {
                    string_refusal(key, "a member name").or_else(|| {
                        members
                            .iter()
                            .find(|member| member.name == *key)
                            .map_or_else(
                                || any_text(inner),
                                |member| member.shape.text_refusal(inner),
                            )
                    })
                })
            }
            (Self::Map { values }, Value::Object(held)) => held.iter().find_map(|(key, inner)| {
                string_refusal(key, "a member name").or_else(|| values.text_refusal(inner))
            }),
            (Self::Array { items }, Value::Array(held)) => {
                held.iter().find_map(|inner| items.text_refusal(inner))
            }
            _ => any_text(value),
        }
    }
}

/// A command object: the members allowed, a `type` that is `command` or `stdio`, the command as
/// text and the arguments as a list of text, in the form the placement registers the forwarder in.
fn command_object(
    value: &Value,
    allowed: &[&str],
    required_type: Option<&str>,
    form: CommandForm,
) -> Result<(), String> {
    let Value::Object(held) = value else {
        return Err("a command is expected and the file holds another kind".to_owned());
    };
    if let Some(other) = held.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!(
            "a command holds {other}, which this host does not name for it"
        ));
    }
    let kind_fits = match (required_type, held.get("type")) {
        (Some(wanted), Some(kind)) => kind == wanted,
        (Some(_), None) => false,
        (None, Some(kind)) => kind == "stdio",
        (None, None) => true,
    };
    let text = |member: &str| held.get(member).is_none_or(Value::is_string);
    let fits = kind_fits
        && held.get("command").is_some_and(Value::is_string)
        && text("name")
        && held.get("args").is_none_or(|args| {
            args.as_array()
                .is_some_and(|args| args.iter().all(Value::is_string))
        })
        && held.get("timeout").is_none_or(Value::is_number);
    if !fits {
        return Err("a command is not one this host names".to_owned());
    }
    let starts = held
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(|command| command.starts_with(forwarder::PLACEHOLDER));
    if starts {
        let line = form == CommandForm::Line;
        if line == held.contains_key("args") {
            let (written, registered) = if line {
                (
                    "a program with its arguments in a list",
                    "one line a shell runs",
                )
            } else {
                ("one line", "a program with its arguments in a list")
            };
            return Err(format!(
                "the forwarder is written as {written}, and this placement registers it as \
                 {registered}"
            ));
        }
    }
    Ok(())
}

fn string_refusal(text: &str, what: &str) -> Option<String> {
    names_a_place(text).then(|| {
        format!(
            "{what} {text:?} holds a slash, a backslash, a colon, a tilde, a dollar sign or a \
             backtick, or is a dot or two dots"
        )
    })
}

fn any_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => string_refusal(text, "a text"),
        Value::Array(held) => held.iter().find_map(any_text),
        Value::Object(held) => held.iter().find_map(|(key, inner)| {
            string_refusal(key, "a member name").or_else(|| any_text(inner))
        }),
        _ => None,
    }
}
