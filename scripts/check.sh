#!/bin/sh
set -eu

sh -n "$0"
cargo metadata --format-version 1 --locked --no-deps >/dev/null
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
clang --target=x86_64-unknown-none-elf -c arch/x86_64/boot/entry.S -o /dev/null
