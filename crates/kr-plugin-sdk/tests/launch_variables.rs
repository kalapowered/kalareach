//! The launch variables a package declares for its command integration, as the package validator
//! reads them.
//!
//! Each case builds a package directory around the example connector, changes its plugin name, its
//! `sdk_range`, the `launch_variables` member of its connector table and its command integration,
//! and asserts on the findings the validator returns. The helper returns the findings and asserts
//! nothing, so every assertion is in a case's own body.

use std::path::{Path, PathBuf};

use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::schema::package_contract;
use kr_plugin_sdk::validate::{Finding, FindingCode, validate_package_directory};
use kr_plugin_sdk::version::SDK_VERSION;
use serde_json::{Value, json};

fn example_connector() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plugins/valid/example-connector")
}

/// The reason every declared entry states, which a reviewer reads.
const REASON: &str = "Stops the application from replacing itself while a session runs";

/// One package: the example connector with a plugin name, an `sdk_range`, a `launch_variables`
/// member and a command integration of the case's choosing.
struct Package {
    plugin_name: String,
    range: String,
    /// The member as the connector table's JSON states it; `None` leaves it out.
    declared: Option<Value>,
    /// The variables the manifest's command integration sets; `None` for a manifest with none.
    integration: Option<Vec<(String, String)>>,
}

impl Package {
    /// The example connector, whose plugin name `example-connector` gives the vendor word
    /// `EXAMPLE`, under a range that starts at the SDK this crate implements.
    fn new() -> Self {
        Self {
            plugin_name: "example-connector".to_owned(),
            range: format!(">={SDK_VERSION}, <0.2.0"),
            declared: None,
            integration: None,
        }
    }

    fn named(mut self, plugin_name: &str) -> Self {
        self.plugin_name = plugin_name.to_owned();
        self
    }

    fn range(mut self, range: &str) -> Self {
        self.range = range.to_owned();
        self
    }

    /// The table declares these (name, value) pairs, each with a reason.
    fn declaring(mut self, entries: &[(&str, &str)]) -> Self {
        self.declared = Some(Value::Array(
            entries
                .iter()
                .map(|(name, value)| json!({ "name": name, "value": value, "reason": REASON }))
                .collect(),
        ));
        self
    }

    /// The table's member as this JSON, whatever it is.
    fn declaring_json(mut self, member: Value) -> Self {
        self.declared = Some(member);
        self
    }

    /// The manifest has a command integration that sets these (name, value) pairs.
    fn setting(mut self, variables: &[(&str, &str)]) -> Self {
        self.integration = Some(
            variables
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        );
        self
    }

    /// Writes the package, brings the manifest's digest and size up to the changed table, and
    /// returns what the package check found.
    fn findings(&self) -> Vec<Finding> {
        let home = tempfile::tempdir().expect("a directory");
        let directory = home.path().join("package");
        std::fs::create_dir_all(&directory).expect("a directory");
        for name in ["plugin.json", "presentation.json", "connector.json"] {
            std::fs::copy(example_connector().join(name), directory.join(name)).expect("copies");
        }
        let mut table: Value = serde_json::from_slice(
            &std::fs::read(directory.join("connector.json")).expect("reads"),
        )
        .expect("JSON");
        table["plugin_id"] = json!(format!("kalareach/{}", self.plugin_name));
        if let Some(declared) = &self.declared {
            table["launch_variables"] = declared.clone();
        }
        let bytes = serde_json::to_vec_pretty(&table).expect("writes");
        std::fs::write(directory.join("connector.json"), &bytes).expect("writes");

        let mut manifest: Value =
            serde_json::from_slice(&std::fs::read(directory.join("plugin.json")).expect("reads"))
                .expect("JSON");
        manifest["plugin_name"] = json!(self.plugin_name);
        manifest["sdk_range"] = json!(self.range);
        let record = manifest["payloads"]
            .as_array_mut()
            .expect("payloads")
            .iter_mut()
            .find(|payload| payload["path"] == "connector.json")
            .expect("the connector payload");
        record["digest"] = json!(PayloadDigest::of(&bytes).to_string());
        record["size_bytes"] = json!(bytes.len().to_string());
        if let Some(variables) = &self.integration {
            manifest["capabilities"]
                .as_array_mut()
                .expect("capabilities")
                .push(json!({
                    "capability": "command_integration.launch",
                    "reason": "Start the agent with the variables its integration sets"
                }));
            manifest["command_integration"] = json!({
                "command": "example-agent",
                "flags": ["--example-flag"],
                "variables": variables
                    .iter()
                    .map(|(name, value)| json!({ "name": name, "value": value }))
                    .collect::<Vec<_>>(),
                "grant_statement": "Starts the agent in KalaReach sessions with what it needs",
            });
        }
        std::fs::write(
            directory.join("plugin.json"),
            serde_json::to_vec_pretty(&manifest).expect("writes"),
        )
        .expect("writes");
        validate_package_directory(&directory).report.findings
    }
}

/// The names of the launch variable refusals among `findings`, in order.
fn reasons(findings: &[Finding]) -> Vec<&str> {
    findings
        .iter()
        .filter(|finding| finding.detail.starts_with("launch_variables."))
        .filter_map(|finding| finding.detail.split(':').next())
        .collect()
}

/// The name reasons among them: the ones that are about one declared name.
const NAME_REASONS: [&str; 5] = [
    "launch_variables.name_shape",
    "launch_variables.name_not_the_vendor",
    "launch_variables.name_reserved_first_word",
    "launch_variables.name_reserved_word",
    "launch_variables.name_twice",
];

/// A package that declares `name` with `value` and whose integration sets it, under the example
/// connector's plugin name.
fn declaring_and_setting(name: &str, value: &str) -> Package {
    Package::new()
        .declaring(&[(name, value)])
        .setting(&[(name, value)])
}

#[test]
fn a_declared_launch_variable_validates_when_the_range_starts_at_the_arrival() {
    for value in ["1", "0"] {
        let findings = declaring_and_setting("EXAMPLE_NO_SELF_UPDATE", value).findings();
        assert_eq!(findings, Vec::<Finding>::new(), "value {value}");
    }
    // Four entries, the most one package declares, each of them set.
    let names = [
        "EXAMPLE_NO_A",
        "EXAMPLE_NO_B",
        "EXAMPLE_NO_C",
        "EXAMPLE_NO_D",
    ];
    let pairs: Vec<(&str, &str)> = names.iter().map(|name| (*name, "1")).collect();
    let findings = Package::new().declaring(&pairs).setting(&pairs).findings();
    assert_eq!(findings, Vec::<Finding>::new());
}

#[test]
fn a_declared_value_other_than_one_or_zero_is_refused_by_name() {
    for value in [
        "true",
        "false",
        "yes",
        "TRUE",
        "2",
        " 1",
        "1 ",
        "",
        "/tmp/x",
        "--require /tmp/x.js",
    ] {
        let findings = declaring_and_setting("EXAMPLE_NO_X", value).findings();
        assert!(
            reasons(&findings).contains(&"launch_variables.value_not_permitted"),
            "{value:?}: {findings:#?}"
        );
    }
}

#[test]
fn a_gemini_release_from_the_arrival_may_declare_its_compiled_pair() {
    let findings = Package::new()
        .named("gemini-cli")
        .declaring(&[("GEMINI_CLI_NO_RELAUNCH", "true")])
        .setting(&[("GEMINI_CLI_NO_RELAUNCH", "true")])
        .findings();
    assert_eq!(findings, Vec::<Finding>::new());
}

#[test]
fn a_package_of_another_vendor_cannot_declare_the_compiled_pair() {
    let findings = declaring_and_setting("GEMINI_CLI_NO_RELAUNCH", "true").findings();
    let reasons = reasons(&findings);
    assert!(
        reasons.contains(&"launch_variables.name_not_the_vendor"),
        "{findings:#?}"
    );
    assert!(
        !reasons.contains(&"launch_variables.value_not_permitted"),
        "the value is excused, the name is not: {findings:#?}"
    );
}

#[test]
fn a_declared_name_outside_the_shape_is_refused_by_name() {
    let longest = format!("EXAMPLE_{}", "X".repeat(56));
    assert_eq!(longest.len(), 64);
    let too_long = format!("EXAMPLE_{}", "X".repeat(57));
    assert_eq!(too_long.len(), 65);
    for name in [
        "example_no_x",
        "EXAMPLE",
        "PATH",
        "HOME",
        too_long.as_str(),
        "EXAMPLE__X",
        "EXAMPLE_X_",
        "_EXAMPLE_X",
        "1EXAMPLE_X",
        "EXAMPLE-X",
        "EXAMPLE=X",
        "EXAMPLE_É",
    ] {
        let findings = declaring_and_setting(name, "1").findings();
        let reasons = reasons(&findings);
        assert!(
            reasons.contains(&"launch_variables.name_shape"),
            "{name}: {findings:#?}"
        );
        assert!(
            NAME_REASONS[1..]
                .iter()
                .all(|other| !reasons.contains(other)),
            "{name}: a name with no shape has no word to read: {findings:#?}"
        );
    }
    // The longest name the shape allows passes every name check.
    let findings = declaring_and_setting(&longest, "1").findings();
    assert_eq!(findings, Vec::<Finding>::new());
}

#[test]
fn a_declared_name_that_is_not_the_vendors_is_refused_by_name() {
    // The plugin name, the declared name and whether the vendor rule accepts it.
    for (plugin, name, accepted) in [
        ("qoder-cli", "QODER_NO_X", true),
        ("gemini-cli", "GEMINI_NO_X", true),
        ("gemini-cli", "QODER_NO_X", false),
        ("example-connector", "EXAMPLE_NO_X", true),
        ("example-connector", "EXAMPLE_CONNECTOR_NO_X", true),
        ("example-connector", "DISABLE_AUTOUPDATER", false),
        ("vendor.tool", "VENDOR_NO_X", true),
        ("vendor.tool", "TOOL_NO_X", false),
    ] {
        let findings = Package::new()
            .named(plugin)
            .declaring(&[(name, "1")])
            .setting(&[(name, "1")])
            .findings();
        assert_eq!(
            reasons(&findings).contains(&"launch_variables.name_not_the_vendor"),
            !accepted,
            "{plugin} declaring {name}: {findings:#?}"
        );
    }
    // A plugin name that begins with a digit has a first word no name can begin with.
    let findings = Package::new()
        .named("1password-cli")
        .declaring(&[("1PASSWORD_NO_X", "1")])
        .setting(&[("1PASSWORD_NO_X", "1")])
        .findings();
    assert!(
        reasons(&findings).contains(&"launch_variables.name_shape"),
        "{findings:#?}"
    );
    let findings = Package::new()
        .named("1password-cli")
        .declaring(&[("PASSWORD_NO_X", "1")])
        .setting(&[("PASSWORD_NO_X", "1")])
        .findings();
    assert!(
        findings.iter().any(|finding| finding.detail.starts_with(
            "launch_variables.name_not_the_vendor: \"PASSWORD_NO_X\" does not begin with \
             1PASSWORD, the upper-case first word of the plugin name 1password-cli; a name \
             cannot begin with a digit, so a package whose plugin name begins with one declares \
             no launch variable"
        )),
        "{findings:#?}"
    );
}

/// The floor's two lists, written out here so that a word taken off the host's list is noticed.
const FLOOR_FIRST_WORDS: [&str; 23] = [
    "KR", "LD", "DYLD", "BASH", "NODE", "NPM", "BUN", "DENO", "PYTHON", "PERL", "RUBY", "LUA",
    "JAVA", "JDK", "GIT", "GCONV", "SSL", "CURL", "REQUESTS", "COMPLUS", "DOTNET", "CORECLR",
    "COR",
];
const FLOOR_WORDS: [&str; 27] = [
    "PATH",
    "HOME",
    "SHELL",
    "ENV",
    "RC",
    "INIT",
    "STARTUP",
    "PRELOAD",
    "LIBRARY",
    "LIBRARIES",
    "OPTIONS",
    "OPTS",
    "ARGS",
    "PROXY",
    "CERT",
    "CERTS",
    "CA",
    "BUNDLE",
    "TLS",
    "SSL",
    "NODE",
    "CONFIG",
    "DIR",
    "FILE",
    "ROOT",
    "TMP",
    "TEMP",
];

#[test]
fn a_declared_name_the_floor_refuses_is_refused_by_name() {
    // Each first word, as the first word of a name, with the witnesses the vendor rule hides.
    for word in FLOOR_FIRST_WORDS {
        let name = format!("{word}_NO_X");
        let findings = declaring_and_setting(&name, "1").findings();
        assert!(
            reasons(&findings).contains(&"launch_variables.name_reserved_first_word"),
            "{name}: {findings:#?}"
        );
    }
    for name in [
        "LD_AUDIT",
        "DYLD_LIBRARY_PATH",
        "NODE_OPTIONS",
        "JAVA_TOOL_OPTIONS",
        "COMPLUS_ETWENABLED",
        "DOTNET_X",
        "CORECLR_X",
        "COR_ENABLE_PROFILING",
    ] {
        let findings = declaring_and_setting(name, "1").findings();
        assert!(
            reasons(&findings).contains(&"launch_variables.name_reserved_first_word"),
            "{name}: {findings:#?}"
        );
    }
    // Each word, in the second place, where only the any-word list reads it, with the vendor word
    // right and nothing else to refuse.
    for word in FLOOR_WORDS {
        let name = format!("EXAMPLE_{word}");
        let findings = declaring_and_setting(&name, "1").findings();
        let reasons = reasons(&findings);
        assert!(
            reasons.contains(&"launch_variables.name_reserved_word"),
            "{name}: {findings:#?}"
        );
        assert!(
            !reasons.contains(&"launch_variables.name_not_the_vendor")
                && !reasons.contains(&"launch_variables.name_reserved_first_word"),
            "{name} is refused for the word alone: {findings:#?}"
        );
    }
    // A first word of the first-word list refuses a name only in the first place, and a word of
    // the any-word list refuses it anywhere.
    let findings = declaring_and_setting("EXAMPLE_JAVA_X", "1").findings();
    assert_eq!(findings, Vec::<Finding>::new(), "JAVA is a first word only");
    let findings = declaring_and_setting("EXAMPLE_NO_CONFIG", "1").findings();
    assert!(
        reasons(&findings).contains(&"launch_variables.name_reserved_word"),
        "{findings:#?}"
    );
    // The floor refuses a name where the vendor word is right: a package named for it.
    let findings = Package::new()
        .named("node-helper")
        .declaring(&[("NODE_NO_X", "1")])
        .setting(&[("NODE_NO_X", "1")])
        .findings();
    let reasons = reasons(&findings);
    assert!(
        reasons.contains(&"launch_variables.name_reserved_first_word")
            && reasons.contains(&"launch_variables.name_reserved_word")
            && !reasons.contains(&"launch_variables.name_not_the_vendor"),
        "{findings:#?}"
    );
}

#[test]
fn the_package_contract_lists_the_floor_the_case_holds() {
    let contract = package_contract();
    let rules = &contract["command_integration"]["launch_variable_rules"];
    assert_eq!(rules["floor_first_words"], json!(FLOOR_FIRST_WORDS));
    assert_eq!(rules["floor_words"], json!(FLOOR_WORDS));
}

#[test]
fn a_declared_name_that_a_vendor_rule_stops_is_refused_by_name() {
    for name in [
        "ELECTRON_RUN_AS_NODE",
        "YARN_ENABLE_STRICT_SSL",
        "COREPACK_INTEGRITY_KEYS",
        "HUSKY_SKIP_HOOKS",
        "OPENSSL_CONF",
        "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER",
    ] {
        let findings = declaring_and_setting(name, "1").findings();
        assert!(
            reasons(&findings).contains(&"launch_variables.name_not_the_vendor"),
            "{name}: {findings:#?}"
        );
    }
}

#[test]
fn an_integration_variable_the_table_does_not_declare_is_refused_by_name() {
    // A table that declares nothing, and a table that declares other variables.
    for package in [
        Package::new().setting(&[("EXAMPLE_NO_X", "1")]),
        Package::new()
            .declaring(&[("EXAMPLE_NO_Y", "1")])
            .setting(&[("EXAMPLE_NO_X", "1"), ("EXAMPLE_NO_Y", "1")]),
    ] {
        let findings = package.findings();
        assert!(
            findings.iter().any(|finding| {
                finding.code == FindingCode::IntegrationInvalid
                    && finding.detail.starts_with(
                        "launch_variables.not_declared: \"EXAMPLE_NO_X\"=\"1\" is not a variable \
                         a command integration may set: declare it, with a reason, in the \
                         launch_variables member of the connector table under an sdk_range \
                         written in release versions only that admits no SDK version before ",
                    )
            }),
            "{findings:#?}"
        );
    }
}

#[test]
fn a_package_that_declares_a_variable_cannot_also_use_the_compiled_pair() {
    // The member is present under a range that admits an older SDK: the arrival finding, and the
    // pair is not given beside the entry.
    let findings = Package::new()
        .named("gemini-cli")
        .range(">=0.1.3, <0.2.0")
        .declaring(&[("GEMINI_NO_X", "1")])
        .setting(&[("GEMINI_NO_X", "1"), ("GEMINI_CLI_NO_RELAUNCH", "true")])
        .findings();
    assert!(
        findings.iter().any(|finding| {
            finding.code == FindingCode::ConnectorTableInvalid
                && finding
                    .detail
                    .contains("ConnectorManifest.launch_variables")
                && finding.detail.contains("admits an SDK version below it")
        }),
        "{findings:#?}"
    );
    assert!(
        findings.iter().any(|finding| {
            finding.detail.starts_with(
                "launch_variables.not_declared: \"GEMINI_CLI_NO_RELAUNCH\"=\"true\" is not a \
                 variable",
            )
        }),
        "{findings:#?}"
    );
}

#[test]
fn a_declared_pair_whose_value_differs_from_the_set_one_is_refused_both_ways() {
    // Both values are valid, so only the exact match decides.
    let findings = Package::new()
        .declaring(&[("EXAMPLE_NO_X", "0")])
        .setting(&[("EXAMPLE_NO_X", "1")])
        .findings();
    let reasons = reasons(&findings);
    assert!(
        reasons.contains(&"launch_variables.not_declared"),
        "the pair that is set: {findings:#?}"
    );
    assert!(
        reasons.contains(&"launch_variables.unused"),
        "the pair that is declared: {findings:#?}"
    );
}

#[test]
fn a_declared_variable_the_integration_does_not_set_is_refused_by_name() {
    let findings = Package::new()
        .declaring(&[("EXAMPLE_NO_X", "1"), ("EXAMPLE_NO_Y", "1")])
        .setting(&[("EXAMPLE_NO_X", "1")])
        .findings();
    assert!(
        findings.iter().any(|finding| {
            finding.code == FindingCode::IntegrationInvalid
                && finding.detail
                    == "launch_variables.unused: the table declares \"EXAMPLE_NO_Y\"=\"1\" and no \
                        variable of the command integration equals it"
        }),
        "{findings:#?}"
    );
    assert!(
        reasons(&findings)
            .iter()
            .all(|reason| *reason != "launch_variables.not_declared"),
        "{findings:#?}"
    );
}

#[test]
fn a_declaration_in_a_package_with_no_integration_is_refused_by_name() {
    let findings = Package::new()
        .declaring(&[("EXAMPLE_NO_X", "1")])
        .findings();
    assert!(
        findings.iter().any(|finding| {
            finding.code == FindingCode::IntegrationInvalid
                && finding.detail
                    == "launch_variables.without_integration: the table declares launch variables \
                        and the manifest declares no command integration, so nothing sets them"
        }),
        "{findings:#?}"
    );
}

#[test]
fn a_declaration_of_five_entries_a_repeated_name_or_a_blank_reason_is_refused_by_name() {
    let five = [
        ("EXAMPLE_NO_A", "1"),
        ("EXAMPLE_NO_B", "1"),
        ("EXAMPLE_NO_C", "1"),
        ("EXAMPLE_NO_D", "1"),
        ("EXAMPLE_NO_E", "1"),
    ];
    let findings = Package::new().declaring(&five).setting(&five).findings();
    assert!(
        findings.iter().any(|finding| {
            finding.code == FindingCode::ConnectorTableInvalid
                && finding.detail
                    == "launch_variables.too_many: the table declares 5 launch variables, over \
                        the 4 a package may declare"
        }),
        "{findings:#?}"
    );
    let twice = [("EXAMPLE_NO_A", "1"), ("EXAMPLE_NO_A", "0")];
    let findings = Package::new().declaring(&twice).setting(&twice).findings();
    assert!(
        reasons(&findings).contains(&"launch_variables.name_twice"),
        "{findings:#?}"
    );
    // A reason of spaces is a reason the host reads as blank; an empty text and a missing member
    // are the table's own reading, in the next case.
    let blank = json!([{ "name": "EXAMPLE_NO_X", "value": "1", "reason": "   " }]);
    let findings = Package::new()
        .declaring_json(blank)
        .setting(&[("EXAMPLE_NO_X", "1")])
        .findings();
    assert!(
        reasons(&findings).contains(&"launch_variables.reason_missing"),
        "{findings:#?}"
    );
    let findings = Package::new().declaring_json(json!([])).findings();
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == FindingCode::ConnectorTableInvalid
                && finding.detail
                    == "launch_variables.empty: the table declares launch_variables with no entry; \
                    leave the member out to declare none"),
        "{findings:#?}"
    );
}

#[test]
fn a_missing_and_an_empty_reason_are_refused_by_the_table_s_own_reading() {
    let empty = json!([{ "name": "EXAMPLE_NO_X", "value": "1", "reason": "" }]);
    let findings = Package::new()
        .declaring_json(empty)
        .setting(&[("EXAMPLE_NO_X", "1")])
        .findings();
    assert!(
        findings
            .iter()
            .any(|finding| finding.detail.contains("summary is empty")),
        "{findings:#?}"
    );
    let missing = json!([{ "name": "EXAMPLE_NO_X", "value": "1" }]);
    let findings = Package::new()
        .declaring_json(missing)
        .setting(&[("EXAMPLE_NO_X", "1")])
        .findings();
    assert!(
        findings
            .iter()
            .any(|finding| finding.detail.contains("missing field `reason`")),
        "{findings:#?}"
    );
}

#[test]
fn an_explicit_null_reads_as_absent_and_an_old_range_still_refuses_it() {
    // Under a range from the arrival, a null member is the member left out.
    let findings = Package::new()
        .declaring_json(Value::Null)
        .setting(&[])
        .findings();
    assert_eq!(findings, Vec::<Finding>::new());
    // Under a range that admits an older SDK, the arrival check sees the member and refuses it.
    let findings = Package::new()
        .range(">=0.1.3, <0.2.0")
        .declaring_json(Value::Null)
        .setting(&[])
        .findings();
    assert!(
        findings.iter().any(|finding| {
            finding.code == FindingCode::ConnectorTableInvalid
                && finding
                    .detail
                    .contains("ConnectorManifest.launch_variables")
                && finding.detail.contains("admits an SDK version below it")
        }),
        "{findings:#?}"
    );
}

/// The range a published Gemini CLI 0.5.0 states.
const RELEASED_RANGE: &str = ">=0.1.3, <0.2.0";

#[test]
fn a_release_that_declares_nothing_and_admits_older_sdks_keeps_geminis_pair() {
    let findings = Package::new()
        .named("gemini-cli")
        .range(RELEASED_RANGE)
        .setting(&[("GEMINI_CLI_NO_RELAUNCH", "true")])
        .findings();
    assert_eq!(findings, Vec::<Finding>::new());
}

#[test]
fn a_release_from_the_arrival_that_sets_geminis_pair_undeclared_is_refused_by_name() {
    // The range starts at the SDK this crate implements, which is the arrival once the member
    // exists, so no older SDK is admitted and the pair is not given.
    let findings = Package::new()
        .named("gemini-cli")
        .setting(&[("GEMINI_CLI_NO_RELAUNCH", "true")])
        .findings();
    assert!(
        reasons(&findings).contains(&"launch_variables.not_declared"),
        "{findings:#?}"
    );
}

#[test]
fn a_release_whose_range_has_a_prerelease_part_never_gets_geminis_pair() {
    // A range with a prerelease part is one the check cannot decide, so it never gets the pair.
    let findings = Package::new()
        .named("gemini-cli")
        .range(">=0.1.3-alpha, <0.2.0")
        .setting(&[("GEMINI_CLI_NO_RELAUNCH", "true")])
        .findings();
    assert!(
        reasons(&findings).contains(&"launch_variables.not_declared"),
        "{findings:#?}"
    );
}
