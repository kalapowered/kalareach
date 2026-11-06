//! A macro that writes a file into the output directory of the crate it expands in, if the file is
//! not there yet, and expands to the file's bytes. The file is named for a digest of its content,
//! as Tauri's context macro names what it writes, so what the name holds is always the same.

use proc_macro::TokenStream;

/// What the name stands for: a digest of the content, which does not change.
const NAME: &str = "5d4140c1a3b2c9d6e7f80a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5";

#[proc_macro]
pub fn embed(_input: TokenStream) -> TokenStream {
    let directory = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("a build script"));
    let file = directory.join(NAME);
    if !file.exists() {
        std::fs::write(&file, b"written").expect("the file is written");
        // A file system whose times are whole seconds would give this file and the start of the
        // compile the same time. This file is newer than the compile by a minute on any of them.
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(60);
        std::fs::File::options()
            .write(true)
            .open(&file)
            .and_then(|written| written.set_modified(later))
            .expect("the file is dated");
    }
    format!("include_bytes!({:?})", file.to_string_lossy())
        .parse()
        .expect("tokens")
}
