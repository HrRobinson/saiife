//! Sets `cfg(saiife_ci)` when `CI` is set, so a test that writes to the machine's real
//! Credential Manager runs in CI and stays `#[ignore]`d on anyone's own `cargo test`.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CI");
    println!("cargo:rustc-check-cfg=cfg(saiife_ci)");
    if std::env::var_os("CI").is_some() {
        println!("cargo:rustc-cfg=saiife_ci");
    }
}
