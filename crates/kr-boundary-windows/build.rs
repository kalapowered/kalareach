//! Asks Windows for an administrator prompt when the setup program starts, in the program's own
//! manifest. The broker and the credential helper carry no such request.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if os == "windows" && env == "msvc" {
        println!("cargo:rustc-link-arg-bin=kr-boundary-setup=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg-bin=kr-boundary-setup=/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
        );
    }
}
