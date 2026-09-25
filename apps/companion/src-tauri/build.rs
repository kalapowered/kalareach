//! The build step, and the two things it guarantees before Tauri reads the bundle.

use std::path::Path;

fn main() {
    ensure_frontend_placeholder();
    tauri_build::try_build(attributes()).expect("the Tauri build step");
}

/// Tauri's build attributes, with the Windows application manifest in every binary.
///
/// The native dialogs need version 6 of Windows' common controls, and only an application
/// manifest selects it. Tauri links its manifest into the application alone, so a test binary that
/// reaches a dialog is loaded against version 5, which lacks the dialog's entry point, and Windows
/// refuses to start it. With Microsoft's linker the same manifest is linked into every binary
/// this package builds instead, the application included, so each is the same to the loader.
fn attributes() -> tauri_build::Attributes {
    let attributes = tauri_build::Attributes::new();
    let target = |key: &str, value: &str| std::env::var(key).is_ok_and(|found| found == value);
    if !(target("CARGO_CFG_TARGET_OS", "windows") && target("CARGO_CFG_TARGET_ENV", "msvc")) {
        return attributes;
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("windows-app-manifest.xml");
    println!("cargo:rerun-if-changed={}", manifest.display());
    println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
    attributes.windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest())
}

/// Makes sure the front-end output directory exists before the context is generated.
///
/// `pnpm build` writes the real interface there, and `tauri build` runs it first. A plain
/// `cargo build`, `cargo test` or `cargo clippy` of this workspace does not, and Tauri refuses to
/// generate a context for a directory that is not there. Rather than make every workspace-wide
/// command depend on a Node build, this writes a page that says plainly what is missing. It is
/// never what a built application contains, because building one runs the front end first.
fn ensure_frontend_placeholder() {
    let dist = Path::new(env!("CARGO_MANIFEST_DIR")).join("../dist");
    let index = dist.join("index.html");
    if index.exists() {
        return;
    }
    if std::fs::create_dir_all(&dist).is_err() {
        return;
    }
    let _ = std::fs::write(
        &index,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>KalaReach</title></head><body><p>The interface has not been built. \
         Run <code>pnpm -C apps/companion build</code>.</p></body></html>",
    );
}
