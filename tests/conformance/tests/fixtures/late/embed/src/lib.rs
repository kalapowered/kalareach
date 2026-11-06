//! A macro that writes a file into the output directory of the crate it expands in, if the file is
//! not there yet, and expands to the file's bytes.

use proc_macro::TokenStream;

#[proc_macro]
pub fn embed(_input: TokenStream) -> TokenStream {
    let directory = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("a build script"));
    let file = directory.join("written");
    if !file.exists() {
        std::fs::write(&file, b"written").expect("the file is written");
    }
    format!("include_bytes!({:?})", file.to_string_lossy())
        .parse()
        .expect("tokens")
}
