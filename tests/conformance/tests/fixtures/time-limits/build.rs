//! Waits when a case asks it to: while the step builds (`KR_BLOCK=build`) or while it lists its
//! tests (`KR_BLOCK=listing`). It records its pid in the file `KR_BLOCK_PIDS` names, and waits
//! with `sleep`.

fn main() {
    println!("cargo:rerun-if-env-changed=KR_BLOCK");
    println!("cargo:rerun-if-env-changed=KR_BLOCK_PIDS");
    // The listing and the run set this variable, and the build before them does not, so the script
    // runs again when the listing begins.
    println!("cargo:rerun-if-env-changed=KR_CONFORMANCE_STEP");
    let listing = std::env::var_os("KR_CONFORMANCE_STEP").is_some();
    match std::env::var("KR_BLOCK").as_deref() {
        Ok("build") if !listing => {}
        Ok("listing") if listing => {}
        _ => return,
    }
    if let Ok(file) = std::env::var("KR_BLOCK_PIDS") {
        std::fs::write(file, format!("{}\n", std::process::id())).expect("the pid file");
    }
    std::thread::sleep(std::time::Duration::from_secs(300));
}
