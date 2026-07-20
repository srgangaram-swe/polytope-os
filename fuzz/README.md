# Boot-parser fuzzing

These `cargo-fuzz` targets exercise the two untrusted byte parsers introduced by Sprint 02:

- `boot_contract` re-encodes every accepted `POLYBOOT` contract and requires an exact round trip;
- `kernel_elf` rechecks the accepted load-plan bounds, identity mapping, ordering, W^X, and entry
  containment invariants.

The harness manifest and lockfile are separate from the production workspace so libFuzzer and its
native build dependencies never enter the boot image or trusted computing base. Generated corpora,
crash artifacts, and fuzz build outputs are local state and are ignored; only deliberately reviewed
seed/regression inputs are tracked.

Run bounded local campaigns with a current pinned nightly identity recorded in the PR evidence:

```sh
cargo +nightly fuzz run boot_contract -- -max_total_time=60 -timeout=5 -rss_limit_mb=2048
cargo +nightly fuzz run kernel_elf -- -max_total_time=60 -timeout=5 -rss_limit_mb=2048
```

Any crash or timeout is a release blocker until its minimized input is reviewed, added as a named
regression fixture, and covered by the ordinary stable-toolchain test gate. Never commit raw fuzz
artifacts without checking them for host paths or sensitive data.

Before a bounded `kernel_elf` campaign, also run the target once against the exact kernel selected by
the reproducibility report. That positive oracle check prevents the fuzz assertions from drifting to
a stricter, incompatible profile than the parser and real linker output:

```sh
cargo +nightly fuzz run kernel_elf target/polytope/verified/polytope-kernel-x86_64 -- -runs=1
```
