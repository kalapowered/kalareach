//! The `kalareach:plugin` WIT package.
//!
//! The WIT text is the canonical component interface. It is compiled into this crate so that a
//! host, a build tool and a test all read the same bytes, and so the published SDK package and
//! the Rust crate cannot disagree about what a component implements.
//!
//! The eight exports are the whole component contract:
//!
//! | Export | What it does | Deadline |
//! | --- | --- | --- |
//! | `bind` | Prepares the instance for one binding | compilation budget |
//! | `observe` | Receives one scoped source event | 10 ms |
//! | `snapshot` | Emits the complete current document | 100 ms |
//! | `prepare-action` | Turns an invoked control into a proposed effect | 10 ms |
//! | `decode-request` | Interprets a native request into a proposed resource | 50 ms |
//! | `encode-response` | Encodes a validated decision | 50 ms |
//! | `checkpoint` | Returns resumable component state | 100 ms |
//! | `restore` | Restores state from a checkpoint | 100 ms |
//!
//! `decode-request` and `encode-response` return values. Neither sends anything: the broker
//! rechecks the pending request, the actor grant and the binding revision, then atomically claims
//! and dispatches. A pure declarative package implements none of these, because a package that
//! only contributes match rules, a document and controls needs no component at all.

/// The WIT package text.
pub const PACKAGE: &str = include_str!("../wit/kalareach-plugin.wit");

/// The WIT package name.
pub const PACKAGE_NAME: &str = "kalareach:plugin";

/// The file name the WIT package is published under.
pub const PACKAGE_FILE_NAME: &str = "kalareach-plugin.wit";

/// The world a component targets.
pub const WORLD: &str = "plugin";

/// The interface a component exports.
pub const EXPORT_INTERFACE: &str = "adapter";

/// The functions a component exports, in the order section 11 lists them.
pub const EXPORTS: &[&str] = &[
    "bind",
    "observe",
    "snapshot",
    "prepare-action",
    "decode-request",
    "encode-response",
    "checkpoint",
    "restore",
];

/// The interfaces the host supplies.
pub const IMPORTS: &[&str] = &["source-events", "upstream", "attachments", "document"];

/// What each host import is for.
pub const IMPORT_PURPOSES: &[(&str, &str)] = &[
    (
        "source-events",
        "Immutable source events scoped to the binding, read through a handle the host supplied",
    ),
    (
        "upstream",
        "Facts about the bound execution and the rights the actor holds. There is no send function",
    ),
    (
        "attachments",
        "Completed attachment handles from the shared transfer service, never the bytes",
    ),
    (
        "document",
        "Safe document output from the closed node union, bounded at 1 MiB per call",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_package_declares_its_name_and_version() {
        assert!(PACKAGE.contains(&format!(
            "package {PACKAGE_NAME}@{};",
            crate::version::WIT_VERSION
        )));
    }

    #[test]
    fn the_package_text_declares_every_export_and_import() {
        for export in EXPORTS {
            assert!(
                PACKAGE.contains(&format!("{export}: func")),
                "the WIT package does not export {export}"
            );
        }
        for import in IMPORTS {
            assert!(
                PACKAGE.contains(&format!("import {import};")),
                "the world does not import {import}"
            );
            assert!(
                PACKAGE.contains(&format!("interface {import} {{")),
                "the package does not define {import}"
            );
        }
        assert!(PACKAGE.contains(&format!("world {WORLD} {{")));
        assert!(PACKAGE.contains(&format!("interface {EXPORT_INTERFACE} {{")));
        assert!(PACKAGE.contains(&format!("export {EXPORT_INTERFACE};")));
    }

    #[test]
    fn every_import_has_a_stated_purpose() {
        assert_eq!(IMPORT_PURPOSES.len(), IMPORTS.len());
        for (name, purpose) in IMPORT_PURPOSES {
            assert!(IMPORTS.contains(name));
            assert!(!purpose.is_empty());
        }
    }

    #[test]
    fn the_package_documents_the_execution_limits() {
        for number in ["64 MiB", "10 ms", "50 ms", "100 ms", "1 MiB"] {
            assert!(
                PACKAGE.contains(number),
                "the WIT package does not document {number}"
            );
        }
    }
}
