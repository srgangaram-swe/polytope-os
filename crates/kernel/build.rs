//! Emits the target-specific `PolytopeOS` kernel linker script and map options.

use std::env;
use std::path::PathBuf;

fn main() {
    let target = env::var("TARGET").expect("Cargo always supplies TARGET");
    if target != "x86_64-unknown-none" {
        return;
    }

    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo always supplies CARGO_MANIFEST_DIR"),
    );
    let workspace = manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .expect("kernel crate must remain two levels below the workspace root");
    let linker_script = workspace.join("arch/x86_64/kernel/linker.ld");
    let output_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo always supplies OUT_DIR"));
    let profile_dir = output_dir
        .ancestors()
        .nth(3)
        .expect("OUT_DIR must reside below the Cargo profile directory");
    let linker_map = profile_dir.join("polytope-kernel-x86_64.map");

    println!("cargo:rerun-if-changed={}", linker_script.display());
    println!(
        "cargo:rustc-link-arg-bin=polytope-kernel-x86_64=-T{}",
        linker_script.display()
    );
    println!(
        "cargo:rustc-link-arg-bin=polytope-kernel-x86_64=-Map={}",
        linker_map.display()
    );
}
