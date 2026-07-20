# Deterministic x86_64 reference image

This document defines the version-one logical disk layout for the Sprint 02 QEMU/OVMF reference
path. It is an architecture contract for the image builder and its inspection tests. A matching
document does not by itself demonstrate that a current artifact was built reproducibly; that claim
requires two isolated builds and byte-for-byte evidence.

## Raw-disk geometry

All arithmetic uses 512-byte logical blocks. The image is exactly 64 MiB (67,108,864 bytes or
131,072 LBAs numbered 0 through 131,071).

| LBA range | Size | Purpose |
|---|---:|---|
| 0 | 1 sector | Protective MBR |
| 1 | 1 sector | Primary GPT header |
| 2–33 | 32 sectors | Primary GPT entry array: 128 entries of 128 bytes |
| 34–2047 | 2,014 sectors | Zero-filled alignment space |
| 2048–129023 | 126,976 sectors | EFI System Partition (ESP), inclusive |
| 129024–131038 | 2,015 sectors | Zero-filled deterministic tail space |
| 131039–131070 | 32 sectors | Backup GPT entry array |
| 131071 | 1 sector | Backup GPT header |

The ESP therefore starts at the 1 MiB boundary and ends at exclusive LBA 129,024. Primary and
backup GPT headers and entry arrays must agree, and all header and entry-array CRCs must validate.
No second partition, hybrid MBR entry, host filesystem metadata, or trailing data is permitted.

The version-one disk GUID is `4ed83d8f-20d8-4c3d-9a4c-25bccd13a6a1`; the ESP unique GUID is
`f607134d-0901-4d7b-a512-5a49d6ba66bf`. Their fixed values are for reproducibility only; they must
never be interpreted as machine identity, installation identity, entropy, or proof of authenticity.
Changing geometry or either GUID is a versioned image-format change and requires inspection-fixture
and documentation updates.

## Protective MBR and GPT rules

- The MBR contains one protective `0xEE` partition and the conventional `0x55AA` signature.
- GPT header fields, usable-LBA bounds, entry count/size, and CRCs are written explicitly rather
  than inherited from a host disk utility's defaults.
- The ESP uses the standardized EFI System Partition type GUID and the fixed project partition GUID.
- Unused GPT entries and every padding sector are zero-filled.
- CHS compatibility fields and other legacy bytes have one canonical value.
- The backup header points to the primary header and entry array according to the fixed geometry.

An image-layout test must parse the resulting bytes independently of the builder and reject an
incorrect length, partition boundary, GUID, entry count, CRC, non-zero reserved range, or misplaced
backup table.

## FAT32 parameters

The ESP is formatted from empty state as FAT32 with these deterministic inputs:

| Property | Version-one value |
|---|---|
| Filesystem | FAT32, forced rather than selected by host heuristics |
| Bytes per sector | 512 |
| Cluster size | 512 bytes (one sector) |
| FAT copies | 2 |
| Volume ID | `0x50544F53` |
| Volume label | `POLYTOPEOS ` (11 bytes, including the trailing space) |
| File timestamps | `2000-01-01T00:00:00` in representable FAT fields |

All reserved fields, free-space hints, directory-entry padding, short-name case bits, and unused
clusters must have canonical values. Long-file-name records are not needed for the version-one
paths. The builder must not mount the image or use a copy tool that imports host ownership,
timestamps, locale, traversal order, extended attributes, or allocation decisions.

Integrated read-back validates FAT32 type, volume label/ID, the exact directory tree and entry kinds,
file sizes/content through complete reads, and strict payload/scenario identities. The clean-room
check separately compares every raw image byte, including FAT mirrors, backup metadata, timestamps,
and unused space. This does not semantically decode every one of those fields with an independently
implemented FAT parser; that distinction must be preserved in evidence claims.

## File tree and insertion order

Files are inserted into a newly formatted ESP in exactly this order:

```text
EFI/
└── BOOT/
    └── BOOTX64.EFI
POLYTOPE/
├── KERNEL.ELF
└── BOOT.CFG
```

The logical paths and roles are:

| Order | Path | Role |
|---:|---|---|
| 1 | `EFI/BOOT/BOOTX64.EFI` | Rust `x86_64-unknown-uefi` loader using the `uefi-rs` 0.35 API |
| 2 | `POLYTOPE/KERNEL.ELF` | Separately linked `x86_64-unknown-none` kernel in the strict ELF profile from ADR 0004 |
| 3 | `POLYTOPE/BOOT.CFG` | Bounded test-scenario input used to select a documented boot-test path |

Directory creation and file allocation also follow a fixed order. `BOOT.CFG` contains exactly one
ASCII token followed by one newline. The accepted complete byte strings are `normal\n`,
`bad-version\n`, `truncated\n`, and `panic\n`. The loader rejects an absent newline, extra lines,
whitespace, unknown tokens, non-ASCII bytes, and oversized input. Scenario data grants no authority
and is not an arbitrary command channel.

Changing a path or insertion order changes image bytes and therefore requires an intentional layout
version decision. Case-insensitive FAT lookup does not make alternate spellings canonical.

Integrated read-back treats the diagram above as the complete tree, not a list of required entries.
It rejects an extra, missing, renamed, reordered, or wrong-kind entry at the root, `EFI`, `EFI/BOOT`,
or `POLYTOPE` level. It then re-reads all three files, applies the bounded PE identity check and the
strict ELF/scenario validators, and compares payload digests. This exact-tree check prevents an image
from passing merely because the canonical paths also exist; it does not authenticate any payload or
constitute a complete PE/COFF verifier.

## Artifact and firmware inputs

The default raw image path is:

```text
target/polytope/polytope-x86_64.img
```

`target/` is build output and is never committed. The image consumes explicit loader, kernel, and
scenario inputs. It must not search broad directories or select whichever artifact happens to be
newest. A host-side manifest records SHA-256 digests for the image and its explicit inputs; the
manifest is evidence output and is not stored on the ESP or treated as a signature.

The QEMU reference uses the pinned/checksummed OVMF source identified by the host tool as
`edk2-stable202605-r1`. OVMF code and variable-store files are external test inputs, not files in the
raw disk image. Each QEMU run uses a disposable copy of the variable store so mutable firmware state
cannot alter the checked image or contaminate the next run. Environment overrides for QEMU or OVMF
paths are operational conveniences and must be reported in evidence; they cannot silently redefine
the pinned reference configuration.

## Reproducibility procedure

The host tooling owns six logical operations: `image`, `inspect-kernel`, `repro-check`, `boot-test`,
`timeout-probe`, and `baseline`. Their invocation syntax belongs in `docs/boot/README.md`.
The reproducibility operation must:

1. start two builds from independently empty output directories;
2. use the same source tree, locked dependency resolution, Rust/Cargo identities, boot profile,
   target triples, source epoch, layout version, scenario, and environment contract;
3. supply one `CARGO_ENCODED_RUSTFLAGS` contract to every target crate and dependency, combining the
   artifact's required target/linker flags with deterministic remaps for the workspace, Cargo home,
   user home, and otherwise-distinct target directory;
4. build or consume explicit loader and kernel artifacts;
5. scan both artifacts and images for every original host-path byte prefix and fail before reporting
   success if a workspace, Cargo-home/registry, user-home, or target-directory path remains;
6. create each image without mounting it or copying host metadata;
7. compare exact byte length and every byte;
8. report the shared cryptographic digest after each exact comparison; and
9. on mismatch, identify the first differing stage and byte offset without normalizing the failure
   away after the fact.

Cargo-home discovery is deliberately bounded: use an explicit `CARGO_HOME`, or exactly `HOME/.cargo`
when the override is absent. Both directories are canonicalized and must exist; the verifier does
not search arbitrary parent directories. Because `CARGO_ENCODED_RUSTFLAGS` takes precedence over
target rustflags from Cargo configuration, each artifact specification also carries the target
flags that remain mandatory: `/debug:none` for the UEFI PE/COFF image, and static relocation plus
`-no-pie` for the fixed-address kernel.

The schema-3 reproducibility report records the optional Git revision/clean-tree state, target
triples, verbose Rust and Cargo identities, build profile, dependency-lockfile digest, scenario,
artifact/image digests and sizes, exact retained target rustc arguments, source epoch, all four
remap destinations, and exact-byte path privacy evidence for the loader, kernel, and image. Privacy
evidence states how many original path patterns were scanned, records zero unremapped matches, and
counts each normalized destination. The source revision identifies the checked-out host-tool
implementation; there is no separate host-tool version field.
OVMF is not an input to artifact or image byte comparison and therefore belongs in boot-run evidence,
not the reproducibility report. The image builder may use fixed values by design, but it must not hide
an uncontrolled source of nondeterminism by ignoring bytes during comparison.

## Security limitations

- A deterministic image is not a signed or authenticated image.
- The fixed GUIDs and volume ID are public constants, not secrets or unique identifiers.
- The kernel and scenario are untrusted inputs to the loader until their respective safe validators
  accept the supported profiles.
- The FAT and GPT parsers used by tooling or firmware remain attack surfaces; read-back inspection
  reduces builder-error risk but does not establish firmware trust.
- Integrated read-back is a separate validation pass but reuses the host `gpt` and `fatfs` libraries;
  it is not an independently implemented filesystem parser. Exact clean-build comparison detects
  byte drift, but neither mechanism authenticates the image or proves those libraries correct.
- Secure/measured boot, release signing, rollback protection, SBOM/provenance attestations, and an
  installer-specific identity model are future work.
- Only the QEMU/OVMF reference configuration is in Sprint 02 scope. Copying the image to physical
  media does not make real hardware supported.
