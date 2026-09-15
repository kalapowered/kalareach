//! Every union in the package contract is closed.
//!
//! A closed schema rejects two things: a variant nobody defined, and an extra member inside a
//! variant that is defined. The second matters as much as the first. A manifest that carries a
//! member the host silently ignores reads, to a reviewer, as a manifest that does something.

use kr_plugin_sdk::connector::{FieldSegment, Framing, ResponseCorrelation};
use kr_plugin_sdk::effect::{ArgumentValue, ParameterKind};
use kr_plugin_sdk::matching::DistributionMatch;
use kr_plugin_sdk::plugin::{BridgeStep, PluginManifest};
use kr_plugin_sdk::predicate::Predicate;
use kr_plugin_sdk::presentation::{NodeBody, PresentationManifest, ProgressState};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn rejects<T: DeserializeOwned>(value: Value, what: &str) {
    assert!(
        serde_json::from_value::<T>(value.clone()).is_err(),
        "{what} accepted {value}"
    );
}

#[test]
fn an_undefined_variant_is_rejected() {
    rejects::<Predicate>(json!({"op": "eval", "source": "1 == 1"}), "Predicate");
    rejects::<NodeBody>(json!({"kind": "webview", "url": "https://x"}), "NodeBody");
    rejects::<ParameterKind>(json!({"type": "regex", "pattern": ".*"}), "ParameterKind");
    rejects::<Framing>(json!({"type": "custom", "script": "f"}), "Framing");
    rejects::<BridgeStep>(json!({"type": "run_script", "command": "sh"}), "BridgeStep");
    rejects::<DistributionMatch>(
        json!({"registry": "anywhere", "id": "x"}),
        "DistributionMatch",
    );
}

#[test]
fn an_extra_member_inside_a_defined_variant_is_rejected() {
    rejects::<Predicate>(json!({"op": "always", "source": "1 == 1"}), "Predicate");
    rejects::<Predicate>(json!({"op": "never", "then": "show"}), "Predicate");
    rejects::<ProgressState>(
        json!({"kind": "indeterminate", "percent": 40}),
        "ProgressState",
    );
    rejects::<ParameterKind>(json!({"type": "boolean", "default": true}), "ParameterKind");
    rejects::<ResponseCorrelation>(
        json!({"type": "ordered", "window": 4}),
        "ResponseCorrelation",
    );
    rejects::<FieldSegment>(
        json!({"type": "member", "name": "id", "wildcard": true}),
        "FieldSegment",
    );
    rejects::<ArgumentValue>(
        json!({"type": "boolean", "value": true, "force": true}),
        "ArgumentValue",
    );
    rejects::<NodeBody>(
        json!({"kind": "markdown", "source": "#", "html": "<script>"}),
        "NodeBody",
    );
}

#[test]
fn a_manifest_with_an_unknown_member_is_rejected() {
    let mut manifest: Value =
        serde_json::to_value(kr_plugin_sdk::example::example_manifest()).expect("serialisable");
    manifest["escalate"] = json!(true);
    rejects::<PluginManifest>(manifest, "PluginManifest");

    let mut presentation: Value =
        serde_json::to_value(kr_plugin_sdk::example::example_presentation()).expect("serialisable");
    presentation["script"] = json!("alert(1)");
    rejects::<PresentationManifest>(presentation, "PresentationManifest");
}

#[test]
fn the_example_still_round_trips() {
    let manifest = kr_plugin_sdk::example::example_manifest();
    let text = serde_json::to_string(&manifest).expect("serialisable");
    let parsed: PluginManifest = serde_json::from_str(&text).expect("deserialisable");
    assert_eq!(manifest, parsed);

    let presentation = kr_plugin_sdk::example::example_presentation();
    let text = serde_json::to_string(&presentation).expect("serialisable");
    let parsed: PresentationManifest = serde_json::from_str(&text).expect("deserialisable");
    assert_eq!(presentation, parsed);
}
