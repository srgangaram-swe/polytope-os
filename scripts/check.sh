#!/bin/sh
set -eu

sh -n "$0"
cargo metadata --format-version 1 --locked --no-deps >/dev/null
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo check --manifest-path fuzz/Cargo.toml --locked --bins
clang --target=x86_64-unknown-none-elf -c arch/x86_64/boot/entry.S -o /dev/null
cargo clippy --locked --target x86_64-unknown-uefi \
    --package polytope-boot-uefi --bin polytope-boot-uefi \
    --features uefi-binary -- -D warnings
cargo clippy --locked --target x86_64-unknown-none \
    --package polytope-kernel --bin polytope-kernel-x86_64 \
    --features boot-binary -- -D warnings
check_artifact_dir=target/polytope/check-artifacts
CARGO_TARGET_DIR="$check_artifact_dir" cargo rustc --locked --profile boot --package polytope-boot-uefi \
    --bin polytope-boot-uefi --target x86_64-unknown-uefi \
    --features uefi-binary -- \
    --remap-path-prefix="$(pwd)"=/workspace/polytope-os
CARGO_TARGET_DIR="$check_artifact_dir" cargo rustc --locked --profile boot --package polytope-kernel \
    --bin polytope-kernel-x86_64 --target x86_64-unknown-none \
    --features boot-binary -- \
    --remap-path-prefix="$(pwd)"=/workspace/polytope-os
cargo xtask inspect-kernel \
    --kernel "$check_artifact_dir/x86_64-unknown-none/boot/polytope-kernel-x86_64" \
    --map "$check_artifact_dir/x86_64-unknown-none/boot/polytope-kernel-x86_64.map" >/dev/null
