# PolytopeOS x86_64 boot reference

Sprint 02 defines a reproducible two-stage boot path for one reference environment: x86_64 QEMU
with pinned OVMF. A Rust UEFI loader validates and loads a separate Rust ELF kernel, exits boot
services, and hands a bounded project-owned contract to the kernel entry shim.

PolytopeOS is pre-alpha research software. The architecture and interfaces documented here are the
required design; support and performance claims require the revision-specific reports listed in the
support matrix. Documentation or a successful host unit test alone is not proof that an image boots.

## Documents

- [ADR 0004](../adr/0004-x86_64-boot-and-unsafe-boundaries.md) records the two-stage decision,
  strict ELF/contract policy, entry ABI, unsafe inventory, and residual risks.
- [IMAGE_LAYOUT.md](IMAGE_LAYOUT.md) defines deterministic GPT/FAT geometry and canonical payload
  paths.
- [DIAGNOSTICS.md](DIAGNOSTICS.md) defines serial markers, scenarios, timeouts, and QEMU exit values.
- [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md) distinguishes the reference target from verified,
  experimental, and unsupported configurations.
- [DEPENDENCIES.md](DEPENDENCIES.md) records the trusted boundary, feature selection, licenses,
  MSRV rationale, and repeatable advisory-review commands for boot-specific dependencies.
- [THREAT_MODEL.md](../security/THREAT_MODEL.md) describes the boot trust boundaries, abuse cases,
  controls, and limitations.

## Architecture

```text
source + Cargo.lock + pinned tools
              |
              v
  +-----------------------+      +-------------------------+
  | polytope-boot-uefi    |      | polytope-kernel         |
  | x86_64-unknown-uefi   |      | x86_64-unknown-none     |
  +-----------+-----------+      +------------+------------+
              |                               |
              | BOOTX64.EFI                   | KERNEL.ELF
              +---------------+---------------+
                              v
          deterministic 64 MiB GPT/FAT32 image
                              |
                     QEMU q35 + pinned OVMF
                              |
                              v
     UEFI loader -> safe ELF load plan -> ExitBootServices
                              |
                 RDI = contract pointer, RSI = exact length
                              |
                              v
       x86_64 entry shim -> safe contract validation -> marker/exit
```

The components and dependency direction are:

| Component | Responsibility | Safety boundary |
|---|---|---|
| `xtask` host tooling | Build orchestration, deterministic GPT/FAT creation, independent read-back, QEMU execution, reproducibility and baseline reports | Host-side safe Rust; generated artifacts remain outside the repository |
| `polytope-boot-elf` | Parse the bounded ELF64 profile and produce an immutable borrowed load plan | `no_std`, allocation-free, `#![forbid(unsafe_code)]` |
| `polytope-boot-contract` | Define and safely validate the fixed `POLYBOOT` ABI 1.0 byte layout | `no_std`, allocation-free, `#![forbid(unsafe_code)]` |
| `polytope-boot-uefi` | Adapt `uefi-rs` 0.35 firmware services, parse the bounded scenario, load validated segments, exit boot services, and transfer control | Unsafe allowed only at ADR-inventoried physical-memory/entry operations; policy helpers stay safe |
| `polytope-arch-x86_64` | Bounded COM1/debugcon output and typed QEMU exit | Narrow, architecture-local port-I/O unsafe operations |
| Kernel entry assembly | Disable interrupts, clear DF, select linker stack, prove BSS clear with a retained sentinel, preserve handoff arguments, call safe Rust, reject return | Minimal inspected assembly with explicit pre/postconditions |
| Kernel safe entry | Validate the exact contract before semantic use and choose ready/reject/panic behavior | Safe Rust after one reviewed pointer/length-to-byte-slice boundary |

Firmware-facing code must not leak into kernel policy. Safe validators do not allocate, dereference
machine addresses, cast untrusted bytes to Rust references, or contain architecture I/O.

## Boot sequence

1. OVMF reads `EFI/BOOT/BOOTX64.EFI` from the deterministic ESP.
2. The loader reads `POLYTOPE/BOOT.CFG` with a 32-byte cap and `POLYTOPE/KERNEL.ELF` with a 16 MiB
   cap, using bounded 64 KiB reads rather than trusting firmware-reported file size.
3. The safe ELF parser accepts only the profile in ADR 0004 and returns checked, sorted,
   non-overlapping load segments.
4. The loader allocates only the validated physical ranges in
   `[0x0020_0000, 0x4000_0000)`, copies file-backed bytes, and zeroes each remaining memory range.
5. The loader constructs the fixed-size `POLYBOOT` ABI 1.0 contract, including a bounded normalized
   memory map, typed UEFI/x86_64 platform data, optional ACPI RSDP location, boot CPU ID, and typed
   test scenario.
6. It delegates final-memory-map acquisition and `ExitBootServices` to the exact-versioned
   `uefi-rs` boundary. That implementation makes at most two attempts and cold-resets the machine
   if map allocation, map retrieval, or the firmware transition still fails. No firmware service or
   firmware-owned reference is used after a successful return.
7. The loader calls the validated ELF entry using SysV64 with `RDI` as the contract address and
   `RSI` as the exact contract length. The incoming stack is valid and DF is clear; incoming IF is
   unspecified.
8. The first kernel instructions execute `cli`, execute `cld` defensively, preserve `RDI`/`RSI`,
   switch to the 16-byte-aligned linker bootstrap stack, write a non-zero sentinel into the retained
   `.bss.boot` probe, zero all of BSS, verify that probe is zero, and call safe Rust. A failed probe
   exits through the loader-failure debug-exit value before safe Rust; therefore a terminal kernel
   record proves this entry shim performed the clear rather than merely inheriting zeroed pages from
   the loader.
9. The kernel creates a bounded read-only byte view at the one machine boundary, validates every
   contract field in safe Rust, and emits one exact diagnostic/exit classification.

The linker and loader reserve `[0x047f_f000, 0x0480_0000)` next to the 64 KiB bootstrap stack at
`[0x0480_0000, 0x0481_0000)`, and ELF/range validation prevents another owner from using either
range. Firmware mappings remain in place, so the reserved range is **not yet unmapped** and is not a
hardware-enforced guard page. Sprint 03 owns that enforcement.

## Contract and ELF summary

`POLYBOOT` ABI 1.0 is fixed-size, `repr(C)`, and little-endian. It carries only fixed-width integers;
no Rust enum, `bool`, `usize`, reference, slice, UEFI type, or interior pointer crosses the ABI. The
header includes magic, major/minor version, header and total sizes, memory-record size/count, and
flags. At most 128 4 KiB-aligned memory records are live, and every unused record is zero.

The parser reads byte offsets rather than casting bytes to `BootContract`. It requires the supplied
outer length and every declared size to equal the version-one constants, validates typed raw values,
uses checked range arithmetic, and rejects unsorted, overlapping, empty, misaligned, unknown, or
inconsistent data.

The kernel ELF must be little-endian ELF64 v1, `ET_EXEC`, `EM_X86_64`, with no more than eight
program headers and four load segments (text, read-only data, writable data, and stack). Only
`PT_LOAD` is loaded; `PT_NULL` may be ignored. Load ranges are page-aligned, within the fixed
physical window, sorted, non-overlapping, and never W+X. The entry must fall in exactly one
executable segment. PIE, relocation, interpreters, dynamic linking, and other program-header types
are rejected.

See ADR 0004 for the complete validation and unsafe-boundary requirements.

## Host tooling

The pinned Rust toolchain installs `x86_64-unknown-uefi` and `x86_64-unknown-none`. QEMU must be
available as `qemu-system-x86_64`, through `--qemu`, or through `POLYTOPE_QEMU`. The reference OVMF
input is fetched through the checksum-pinned `edk2-stable202605-r1` source unless both
`POLYTOPE_OVMF_CODE` and `POLYTOPE_OVMF_VARS` identify explicit files.

Inspect the current command contract with:

```sh
cargo xtask help
```

Run the fast workspace gate before boot work:

```sh
./scripts/check.sh
```

Run the complete Sprint 02 reference gate—layout inspection, clean-room reproducibility, all four
QEMU scenarios, a real watchdog-expiration probe, and a 10-run baseline—with:

```sh
./scripts/boot-check.sh
```

This full gate requires QEMU and the pinned OVMF input. It writes ignored JSON beneath
`target/polytope/evidence/`; its presence proves only the local invocation unless a completed remote
job publishes the corresponding artifact.

Build the loader and kernel twice in independent target directories, compare both artifacts and
both images byte for byte, and keep the verified normal image at the default path:

```sh
cargo xtask repro-check --scenario normal
```

The default verified image is `target/polytope/polytope-x86_64.img`. The command prints a schema-3
reproducibility report; it is evidence for that invocation only. The clean builds pass an encoded
rustflag contract to every target crate and dependency. It preserves each artifact's required
linker/code-generation flags while remapping workspace, Cargo-home/registry, user-home, and clean
target-directory paths to stable destinations. The command then scans both artifact copies and both
images for the exact original path bytes and fails closed before writing the verified image.

`scripts/boot-check.sh` additionally requests verified loader, kernel, and linker-map outputs from
the first clean build. It inspects that exact kernel/map pair and constructs every scenario image
from those exact payload bytes. These ignored internal outputs bind the inspector and QEMU evidence
to the artifacts whose digests appear in the reproducibility report; they are not release outputs.

With a matching image present, run one bounded headless boot:

```sh
cargo xtask boot-test \
  --image target/polytope/polytope-x86_64.img \
  --scenario normal \
  --timeout-secs 15
```

Exercise the host watchdog itself with a normal image and no QEMU debug-exit device:

```sh
cargo xtask timeout-probe \
  --image target/polytope/polytope-x86_64.img \
  --timeout-secs 2
```

The normal kernel reaches `KERNEL_READY` and then remains halted, so a passing probe must report
`mode: "timeout-probe"`, `classification: "timeout"`, no process exit status, and evidence that the
ready marker was observed before the exact child was killed and reaped. This is deliberately
separate from a scenario test: a timeout can pass only in timeout-probe mode.

To test a rejection or panic path, first build an image with the same scenario token, then pass that
scenario to the harness. For example:

```sh
cargo xtask repro-check \
  --scenario bad-version \
  --output target/polytope/bad-version.img
cargo xtask boot-test \
  --image target/polytope/bad-version.img \
  --scenario bad-version \
  --timeout-secs 15
```

Repeat for `truncated` and `panic`. The harness validates the marker/exit pairing in
`DIAGNOSTICS.md`; expected non-zero QEMU process statuses are decoded by the host tool and are not
ordinary shell failures.

After a normal image boots reliably, collect repeated reference measurements:

```sh
cargo xtask baseline \
  --image target/polytope/polytope-x86_64.img \
  --scenario normal \
  --runs 10 \
  --output target/polytope/boot-baseline.json
```

The schema-2 baseline aggregates time to the first exact `KERNEL_READY` record and sampled peak QEMU
RSS. It retains every schema-2 boot sample, including total duration, image/firmware identities,
QEMU version, and sanitized launch arguments. These are QEMU regression measurements, not real-
hardware performance claims.

To assemble an image from already built explicit artifacts instead of running the clean-room check:

```sh
cargo xtask image \
  --loader PATH_TO_BOOTX64_EFI \
  --kernel PATH_TO_KERNEL_ELF \
  --scenario normal \
  --output target/polytope/polytope-x86_64.img
```

`image` validates and reads back the completed disk but does not prove that the input binaries are
reproducible. Prefer `repro-check` when producing evidence.

### Machine-readable evidence contracts

Report schemas are versioned independently from the serial diagnostic schema and from one another.
Matching `schema_version` values do not make two different report types interchangeable.

- A schema-3 reproducibility report records the Cargo profile and scenario; verbose `rustc` and
  Cargo identities; optional Git revision and clean-tree result; `Cargo.lock` SHA-256; both target
  triples and exact retained non-path rustc arguments; loader, kernel, and image SHA-256 values and
  byte sizes; the fixed source epoch; stable workspace, Cargo-home, user-home, and target-directory
  remap destinations; and per-artifact exact-byte path-privacy evidence. A publishable clean-source
  claim requires a non-null revision and `source_tree_clean: true`; equality from a dirty or
  unidentified tree remains useful local evidence but is not release provenance.
- A schema-2 boot-run report records the execution mode, expected scenario, configured timeout,
  terminal classification and process status; total duration and optional time-to-ready/peak-RSS
  samples; image size/digest; OVMF code
  and pristine-variable-template digests; OVMF source identifier; QEMU version; sanitized argument
  vector; exact marker observations, terminal code, protocol error, and bounded combined log. The
  embedded log is diagnostic context, not a substitute for the strict marker state machine.
- A schema-2 baseline report records run count; min, median, nearest-rank p95, max, mean, and
  population standard deviation for time-to-ready and peak RSS; the peak-RSS sample count must equal
  the run count; host OS family and architecture; OVMF source identifier; and every underlying boot
  run. It does not record CPU model, host kernel version, host load, temperature, or power policy, so
  those must be supplied separately before making a performance claim.

The schema-1 image manifest and schema-1 kernel-layout inspection complement these reports: they bind
payload digests/scenario to exact image geometry and prove the ELF/linker layout, respectively. Keep
the complete set together when evaluating a revision. Generated JSON remains ignored under
`target/`; the `boot-reference` GitHub Actions job publishes bounded JSON only when that remote job
actually starts and completes. A local report, workflow configuration, queued job, or provider-side
startup failure is not remote CI evidence.

### Baseline comparison and regression approval

Use at least 10 successful normal boots for each side of a comparison. Before and after samples are
comparable only when collected on the same otherwise-idle host with the same QEMU executable and
version, OVMF release and code/variable-template digests, sanitized QEMU argument vector, run count,
timeout, and measurement method. Record intentional toolchain or profile changes. If those conditions
do not match, collect a matched pair rather than treating environment drift as a product regression
or improvement.

A change is flagged for engineering review when any of the following is true:

- median or p95 time-to-ready increases by more than 10% and more than 5 ms;
- median or p95 peak RSS increases by more than 10% and more than 4,096 KiB, provided every run has
  an RSS sample; or
- the loader or kernel artifact grows by more than 1% and more than 4,096 bytes in the paired
  schema-3 reproducibility reports.

The raw version-one image is always 67,108,864 bytes; `image_bytes` detects format drift rather than
payload footprint. Any raw-image size change is an image-format decision, not a performance waiver.

An above-threshold regression requires before/after JSON, the affected user or engineering outcome,
cause, correctness/security tradeoff, alternatives considered, and explicit approval in the PR.
Record a mitigation or follow-up issue when the cost is accepted. Shared CI timing is informative and
must not become a flaky correctness gate; byte reproducibility, strict validation, and scenario
classification remain hard gates. A measured improvement never authorizes weakening a safety check.

## Scenario and result model

The builder writes exactly one canonical token plus newline to `POLYTOPE/BOOT.CFG`:

- `normal\n`
- `bad-version\n`
- `truncated\n`
- `panic\n`

The loader accepts exactly those byte strings. Scenarios are deterministic test controls and do not
weaken ELF validation or grant runtime authority. See `DIAGNOSTICS.md` for exact serial records,
QEMU exit values, and timeout rules.

Every boot has a hard monotonic timeout, bounded captured logs, a disposable OVMF variable-store
copy, no display/monitor/network device, and an expected scenario. A missing marker, contradictory
marker, unexpected status, signal, timeout, or scenario mismatch is failure.

## Troubleshooting

### Cargo or a target is unavailable

Use the repository's pinned toolchain. On this macOS checkout, Rustup proxies may require
`/opt/homebrew/opt/rustup/bin` in `PATH`. Do not commit a user-specific tool path. Confirm both target
triples appear in the active toolchain before diagnosing source code.

### QEMU is unavailable

Install a host QEMU package or pass an explicit executable with `--qemu`/`POLYTOPE_QEMU`. Record the
override and `qemu-system-x86_64 --version`; an override is not the reference environment merely
because it boots.

### OVMF cannot be fetched

Provide both `POLYTOPE_OVMF_CODE` and `POLYTOPE_OVMF_VARS` from the intended pinned release. Never
provide only one, reuse a mutable variable store, commit firmware binaries, or call arbitrary local
firmware reference evidence.

### Reproducibility fails

Start from the first reported differing stage and byte offset. Check the source revision, lockfile,
toolchain, target, build profile, source-path remapping, incremental compilation, scenario, and
explicit overrides. Do not mask differences by excluding bytes or copying one build into both sides.
The verifier discovers Cargo storage through only `CARGO_HOME` or `HOME/.cargo`, canonicalizes it,
and refuses missing, root, non-UTF-8, or rustflag-delimiter-bearing paths. A path-privacy failure
names the artifact, path category, and first byte offset without copying a user-specific path into
the report. Ensure custom artifact specifications retain required target/linker flags because the
encoded reproducibility rustflags intentionally take precedence over `.cargo/config.toml` rustflags.

### QEMU times out or exits unexpectedly

Preserve the bounded JSON/log result and classify marker and exit status independently. Confirm the
image scenario matches `--scenario`, OVMF is booting the disk in UEFI mode, and the debug-exit device
is present. Do not add blind retries or lengthen the timeout until the state transition is understood.

## Security and evidence limitations

- The image, loader, kernel, and scenario are not signed, measured, encrypted, or rollback protected.
- Pinned dependencies and OVMF reduce accidental drift but do not prove the build host or firmware is
  trustworthy.
- Serial/debugcon output and the QEMU exit device are visible to and controlled by the host.
- UEFI-established mappings remain active; W^X rejection is an ELF policy check, not yet hardware
  enforcement.
- The bootstrap-stack guard is reserved, not unmapped.
- Generated images, manifests, firmware caches, logs, variable stores, and baseline files must remain
  ignored build evidence and must not be committed.
- A passing local suite is not a passing GitHub Actions run. Report provider-side failures separately
  and never weaken checks to route around an outage.

When changing the boot ABI, ELF profile, linker layout, scenario format, image geometry, diagnostic
schema, exit values, dependency version, or unsafe inventory, update the relevant ADR, threat model,
negative fixtures, and inspection tests in the same review.
