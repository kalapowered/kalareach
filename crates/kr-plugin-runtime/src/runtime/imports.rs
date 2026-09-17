//! What a component is allowed to import, checked before it is instantiated.
//!
//! The list is derived from the SDK rather than written out here: the four host interfaces the WIT
//! world imports, plus the type interface they all `use`. Nothing else is admitted. A component
//! that imports `wasi:filesystem`, `wasi:sockets`, `wasi:cli/environment`, a clock or a random
//! source is refused with that import named, because "this component wants more than the sandbox
//! offers" is not something a publisher or a person reading a disabled reason can act on.
//!
//! The check runs on the compiled component's own type, not on the manifest. A manifest says what
//! a publisher declared; the component type says what the code actually asks for, and only the
//! second is worth refusing on.
//!
//! # Why this is a refusal rather than an empty implementation
//!
//! Wasmtime can satisfy an unknown import with a stub that traps when called. That would let a
//! component with a filesystem import instantiate and fail later, somewhere in the middle of an
//! observation, as a trap with no explanation. Refusing at preparation makes the reason exact and
//! keeps the instance from existing at all.

use std::collections::BTreeSet;

use kr_plugin_sdk::version::WIT_VERSION;
use kr_plugin_sdk::wit::{EXPORT_INTERFACE, IMPORTS, PACKAGE_NAME};

use crate::runtime::error::{RuntimeError, RuntimeResult};

/// The type interface every other interface in the package uses.
///
/// It declares types and no functions, so importing it grants nothing; a component that uses a
/// record from the contract imports it whether or not it calls anything.
pub const TYPES_INTERFACE: &str = "types";

/// Returns the fully qualified name of one interface in the plugin package.
#[must_use]
pub fn interface_name(interface: &str) -> String {
    format!("{PACKAGE_NAME}/{interface}@{WIT_VERSION}")
}

/// Returns every import a component may have.
#[must_use]
pub fn permitted_imports() -> BTreeSet<String> {
    IMPORTS
        .iter()
        .copied()
        .chain(core::iter::once(TYPES_INTERFACE))
        .map(interface_name)
        .collect()
}

/// Returns the export a component must have.
#[must_use]
pub fn required_export() -> String {
    interface_name(EXPORT_INTERFACE)
}

/// Checks a compiled component's imports and exports against the contract.
///
/// # Errors
///
/// Returns [`RuntimeError::ForbiddenImport`] naming the first import outside the contract, or
/// [`RuntimeError::MissingExport`] when the adapter interface is absent.
pub fn check(
    component: &wasmtime::component::Component,
    engine: &wasmtime::Engine,
) -> RuntimeResult<()> {
    let permitted = permitted_imports();
    let component_type = component.component_type();
    for (name, _item) in component_type.imports(engine) {
        if !permitted.contains(name) {
            return Err(RuntimeError::ForbiddenImport {
                import: name.to_owned(),
            });
        }
    }
    let export = required_export();
    let mut exports = component_type.exports(engine);
    if !exports.any(|(name, _item)| name == export) {
        return Err(RuntimeError::MissingExport { missing: export });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_permitted_list_is_the_four_host_interfaces_and_their_types() {
        let permitted = permitted_imports();
        assert_eq!(permitted.len(), 5);
        for interface in [
            "source-events",
            "upstream",
            "attachments",
            "document",
            "types",
        ] {
            assert!(
                permitted.contains(&interface_name(interface)),
                "{interface} is not permitted"
            );
        }
    }

    #[test]
    fn nothing_ambient_is_permitted() {
        let permitted = permitted_imports();
        for ambient in [
            "wasi:filesystem/types@0.2.9",
            "wasi:filesystem/preopens@0.2.9",
            "wasi:sockets/tcp@0.2.9",
            "wasi:sockets/udp@0.2.9",
            "wasi:sockets/ip-name-lookup@0.2.9",
            "wasi:cli/environment@0.2.9",
            "wasi:cli/exit@0.2.9",
            "wasi:cli/stdout@0.2.9",
            "wasi:clocks/wall-clock@0.2.9",
            "wasi:clocks/monotonic-clock@0.2.9",
            "wasi:random/random@0.2.9",
            "wasi:io/streams@0.2.9",
            "wasi:http/outgoing-handler@0.2.9",
        ] {
            assert!(!permitted.contains(ambient), "{ambient} is permitted");
        }
    }

    #[test]
    fn a_different_contract_version_is_not_the_same_interface() {
        let permitted = permitted_imports();
        assert!(!permitted.contains("kalareach:plugin/document@0.2.0"));
        assert!(permitted.contains(&interface_name("document")));
    }

    #[test]
    fn the_required_export_is_the_adapter_interface() {
        assert_eq!(required_export(), "kalareach:plugin/adapter@0.1.0");
    }

    #[test]
    fn the_permitted_names_carry_the_package_and_version_the_sdk_publishes() {
        assert_eq!(
            interface_name("document"),
            format!("{PACKAGE_NAME}/document@{WIT_VERSION}")
        );
    }
}
