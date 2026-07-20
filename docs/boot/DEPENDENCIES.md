# Sprint 02 boot dependency review

This review covers the dependencies introduced by the x86_64 reference boot path. `Cargo.lock` is
the authoritative, checksummed resolution; manifest version requirements alone are not evidence of
the versions tested. Re-run the MSRV, license, and advisory checks whenever that resolution changes.

## Trusted-computing-base dependencies

| Dependency | Locked policy | Enabled features | Reason and boundary | License |
|---|---|---|---|---|
| `uefi` | exactly `0.35.0` | `alloc`, `global_allocator`; defaults disabled | Supplies reviewed UEFI protocol/ABI bindings and a boot-services allocator. Firmware values are converted into project-owned bounded types before handoff. The project supplies its own panic and QEMU-exit paths. | MIT OR Apache-2.0 |
| `uefi-raw`, `uefi-macros`, `uguid`, `ucs2`, `ptr_meta` | transitive through the exact `uefi` pin | dependency-selected | Required implementation support for the same firmware boundary; no project policy is delegated to these crates. | Permissive, except `ucs2` is MPL-2.0 |

`ucs2` is used unmodified as a library. MPL-2.0 is file-level copyleft and is compatible with this
Apache-2.0 repository in this use; its notices and source availability obligations remain in force.
No third-party crate parses the project boot contract or kernel ELF profile, owns kernel entry, or
implements kernel policy.

## Host-only build and evidence dependencies

| Dependency | Reason | Runtime trust impact | License |
|---|---|---|---|
| `fatfs` | Create and independently read back the fixed FAT32 ESP | Build host only; never linked into loader/kernel | MIT |
| `gpt` and `uuid` | Create and validate fixed GPT geometry/identifiers | Build host only | MIT / MIT OR Apache-2.0 |
| `ovmf-prebuilt = 0.2.8` | Fetch and checksum a pinned firmware archive | QEMU test input only; firmware remains untrusted by the kernel | MIT OR Apache-2.0 |
| `sha2` | Artifact, image, lockfile, and firmware evidence digests | Build host only; hashes are integrity evidence, not signatures | MIT OR Apache-2.0 |
| `serde` and `serde_json` | Stable machine-readable reports | Build host only | MIT OR Apache-2.0 |
| `anyhow` | Context-rich host-tool errors | Build host only; structured guest errors remain project types | MIT OR Apache-2.0 |
| `libfuzzer-sys` | Drive bounded mutation campaigns for boot-contract and ELF byte parsers | Separate `fuzz/` manifest only; never linked into production artifacts | MIT OR Apache-2.0 |

`ovmf-prebuilt` 0.2.8 is pinned because 0.2.9 no longer compiles with the declared Rust 1.85 MSRV.
The host tool constructs the public `Source` value for `edk2-stable202605-r1` explicitly and pins
archive SHA-256 `8ae4d2d73161cc2335f5675d3b8b6edfa0642301679764a246940488ea3ce20d`.
The downloaded firmware code and pristine variable template are hashed again in every boot report.

## Required review commands

From the repository root:

```sh
cargo metadata --format-version 1 --locked --no-deps
cargo tree --workspace --locked
cargo tree --workspace --locked -d
cargo +1.85.0 test --workspace --locked
cargo audit
cargo audit --file fuzz/Cargo.lock
```

The full test gate also cross-compiles and lints the UEFI loader and freestanding kernel. Advisory
results are point-in-time evidence. A retained review record must include UTC time, `cargo-audit`
version, advisory-database source/revision, `Cargo.lock` SHA-256, exact command, findings, and the
rationale plus tracking issue for every exception. Never suppress an applicable vulnerability solely
to make CI green. Generated license/advisory reports belong with build evidence under `target/`, not
as hand-edited claims in source control.

The current GitHub Actions workflow verifies locked builds, the Rust 1.85 MSRV, and compilation of
the separately locked fuzz harness, but does **not** run an advisory or license scanner. Consequently,
a green remote workflow is not by itself dependency-review evidence, and a locally passing
`cargo audit` is not a remote CI result. State both separately in the PR and sprint handoff.

## Known limitations

- Checksums detect drift but do not authenticate the source repository, compiler, build host, or
  firmware publisher.
- `ovmf-prebuilt` uses a TLS/network stack only in the host fetch path. It is not part of the guest
  trusted computing base.
- The current workflow does not publish advisory/license evidence, a release SBOM, or signed
  provenance; those remain explicit manual-review and release-engineering work.
- The complete transitive license set also contains ISC, BSD-3-Clause, Unlicense, Unicode-3.0,
  CDLA-Permissive-2.0, and Apache-2.0-with-LLVM-exception alternatives. None was identified as
  incompatible in the Sprint 02 review; release packaging must still preserve required notices.
