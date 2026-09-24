//! Registers the plugin's Swift package and Android library with Tauri. The plugin adds no
//! command the page may call: its native methods are reached from Rust only.

const COMMANDS: &[&str] = &[];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();
}
