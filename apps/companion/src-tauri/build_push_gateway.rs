//! The build step's part for the push gateway: what a build may be given, and the record the
//! library reads it from.
//!
//! The package's build script and the test that builds a package around it both run this, so the
//! test builds with the code that ships. It needs `push_origin` beside it at the crate root.

use std::path::Path;

use crate::push_origin;

/// What the packaged library carries beside the origin, which `store-bundle.mjs` looks for in a
/// store bundle's library. The two name the same text.
const RECORD_NAME: &str = "kr-push-gateway-origin";

/// Decides what the build is given, writes the record the library includes, and says which gateway
/// the build registers with. A value the build may not be given stops the build.
///
/// A build given nothing talks to the managed service's gateway, so its record holds no origin and
/// it is told nothing here: its requests are the ones it made before the input existed.
pub fn run() {
    println!("cargo:rerun-if-env-changed={}", push_origin::BUILD_INPUT);
    println!(
        "cargo:rerun-if-env-changed={}",
        push_origin::OFFICIAL_BUILD_MARK
    );
    println!("cargo:rerun-if-changed=src/push_origin.rs");
    let given = match std::env::var(push_origin::BUILD_INPUT) {
        Ok(given) => Some(given),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("{} is refused: it is not text", push_origin::BUILD_INPUT)
        }
    };
    let official =
        std::env::var_os(push_origin::OFFICIAL_BUILD_MARK).is_some_and(|mark| !mark.is_empty());
    let origin = match push_origin::accept(given.as_deref(), official) {
        Ok(origin) => origin,
        Err(words) => panic!("{} is refused: {words}", push_origin::BUILD_INPUT),
    };
    let text = origin.as_ref().map_or("", |origin| origin.as_str());
    if let Some(origin) = &origin {
        println!(
            "cargo:warning=this build registers with the push gateway at {}",
            origin.as_str()
        );
    }
    write_record(text);
}

/// Writes the record, unless the file already holds it: the library is compiled again when the file
/// is newer, and a build that changed nothing has no reason to.
fn write_record(origin: &str) {
    let separator = push_origin::RECORD_SEPARATOR;
    let record = format!("{separator}{RECORD_NAME}{separator}{origin}{separator}");
    let out = std::env::var_os("OUT_DIR").expect("the build's output directory");
    let file = Path::new(&out).join(push_origin::record_file!());
    if std::fs::read_to_string(&file).is_ok_and(|held| held == record) {
        return;
    }
    std::fs::write(&file, record).expect("the push gateway record");
}
