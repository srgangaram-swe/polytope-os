# Sprint 02 boot support matrix

This matrix distinguishes the designed reference target from environments that have reproducible
boot evidence. PolytopeOS is pre-alpha research software. “Design target” means the architecture is
intentionally scoped to that environment; it does not mean the current branch has completed or
passed the corresponding integration suite.

## Status vocabulary

- **Design target:** the Sprint 02 contracts are written for this configuration; qualification
  evidence is still required for each implementation revision.
- **Verified at revision:** a linked, machine-readable boot report identifies a commit, pinned
  inputs, scenarios, and passing evidence. This status must never be inferred from documentation
  alone.
- **Experimental:** the design may work, but the project does not maintain a required test and makes
  no compatibility promise.
- **Unsupported:** outside the accepted Sprint 02 scope; failure is expected and should be explicit
  where detection is possible.

No row should be changed to “verified” without a durable evidence artifact and exact reproduction
instructions.

## Firmware, machine, and boot mode

| Environment | Sprint 02 status | Required evidence or limitation |
|---|---|---|
| QEMU `x86_64` system emulator | Design target | Headless normal/rejection/panic scenarios, timeout classification, exact QEMU command and version |
| OVMF source `edk2-stable202605-r1` | Design target | Download identity and checksum, immutable code image, disposable variable store per run |
| 64-bit UEFI boot from GPT/FAT32 ESP | Design target | Independent GPT/FAT inspection plus OVMF boot through `EFI/BOOT/BOOTX64.EFI` |
| Legacy BIOS/CSM | Unsupported | No MBR boot code, 16-bit entry, or BIOS service adapter is planned |
| Secure Boot enabled | Unsupported | The image and kernel are unsigned; secure/measured boot is later security work |
| Physical x86_64 machines | Unsupported | No firmware, chipset, serial-port, storage, or safety qualification; do not write the image to hardware and claim support |
| Other x86_64 hypervisors | Experimental | UEFI behavior, device model, and exit mechanism are not in the required suite |
| AArch64/ARM64, RISC-V, or 32-bit x86 | Unsupported | No target, entry ABI, image path, or firmware adapter exists in this sprint |

The reference launch must not silently fall back from OVMF/UEFI to BIOS or substitute an arbitrary
firmware file found on the host.

## Loader and kernel formats

| Interface | Sprint 02 status | Accepted profile |
|---|---|---|
| EFI loader | Design target | Rust `x86_64-unknown-uefi`, canonical removable-media path, `uefi-rs` 0.35 API |
| Kernel image | Design target | Separate Rust `x86_64-unknown-none` ELF64 v1, little-endian, `ET_EXEC`, `EM_X86_64` |
| Program headers | Design target | At most eight total and at most four `PT_LOAD` records (text, read-only data, writable data, stack); `PT_NULL` may be ignored |
| Physical load range | Design target | Half-open `[0x0020_0000, 0x4000_0000)`, 4 KiB page alignment, sorted non-overlapping ranges |
| Writable-executable segment | Unsupported/rejected | Safe ELF validation rejects W+X; hardware page-permission enforcement is not yet claimed |
| PIE, relocation, interpreter, dynamic linking | Unsupported/rejected | No relocation processor, dynamic loader, or ELF interpreter exists in Sprint 02 |
| Embedded kernel in the EFI binary | Unsupported | Two-stage independence is an accepted architecture decision |
| Boot contract | Design target | Fixed-size little-endian `POLYBOOT` ABI 1.0, exact byte length, at most 128 memory records |
| Other contract versions | Unsupported/rejected | Version compatibility must be designed and tested explicitly; it is not inferred |

Malformed, truncated, oversized, overlapping, wrongly aligned, unknown-version, or wrong-machine
inputs are expected rejection cases, not alternate compatibility paths.

## Host and toolchain environments

| Environment | Sprint 02 status | Notes |
|---|---|---|
| macOS development host | Design target | Current owner environment; host tooling must not rely on mounting Linux-only filesystems |
| Linux GitHub-hosted runner | Design target | Remote job startup is provider-dependent; local success must not be reported as remote CI success |
| Rust 1.97.1 development toolchain | Repository default | Pin exact tool and component versions in evidence |
| Rust 1.85 MSRV | Repository policy; verification required | A passing host and target build is required before claiming Sprint 02 compatibility at the MSRV |
| Unpinned system QEMU/OVMF | Experimental | Allowed only as an explicit override whose versions/checksums are reported; not reference evidence |
| Windows host | Unsupported | No maintained build/image/QEMU workflow in this sprint |

The raw image is created by typed host tooling without mounting it. Generated images, firmware
caches, logs, and variable stores belong under ignored build/output directories and are not source
artifacts.

## Kernel capability at the handoff

The Sprint 02 success point is intentionally early: control reaches safe Rust with a validated boot
contract and emits the expected bounded diagnostic marker. The following are not implied by that
success point:

| Capability | Sprint 02 status | Ownership |
|---|---|---|
| New kernel page tables and enforced W^X/NX | Unsupported | Sprint 03 memory foundation |
| Hardware-unmapped stack guard | Unsupported | Range is reserved only; firmware mappings may still make it accessible |
| Heap/dynamic kernel allocation | Unsupported | Sprint 03 memory foundation |
| Interrupt dispatch and scheduler timers | Unsupported | Sprint 04 execution core |
| Userspace/process isolation/syscalls | Unsupported | Sprint 05 userspace boundary |
| Block storage/filesystem | Unsupported | Sprint 06 storage/device slice |
| Network stack/distributed transport | Unsupported | Sprint 07 network/distributed slice |
| GUI/GOP presentation | Unsupported | Headless serial diagnostics are the Sprint 02 interface |
| General ACPI/topology policy | Unsupported | The contract may carry validated optional RSDP location data; semantic table use is later work |
| Secure/measured boot and signed update | Unsupported | Sprint 15 hardening/release work |

The entry path disables interrupts before safe Rust and clears the direction flag. It writes a
non-zero sentinel to retained BSS, clears the complete BSS range, and verifies the sentinel became
zero before entering Rust. It inherits UEFI-established long mode and mappings until later
architecture work deliberately replaces them.

## Evidence checklist

A revision can claim the reference target is verified only when its report includes:

- loader, kernel, image, scenario, lockfile, and firmware SHA-256 identities;
- Rust, Cargo, QEMU, OVMF, target triples, build profile, source revision/cleanliness, and lockfile
  details;
- independent GPT, FAT, ELF, boot-contract, and linker-layout inspection results;
- `normal`, `bad-version`, `truncated`, and `panic` scenario classification;
- a hard timeout/hang result and deterministic QEMU exit classification;
- two isolated image builds with exact-byte comparison;
- repeated time-to-kernel-entry samples, image/binary sizes, host peak memory, and limitations; and
- an explicit statement of local versus remote execution status.

QEMU measurements are regression and reproducibility evidence for the reference emulator. They are
not bare-metal boot-time, memory-efficiency, security, or hardware-compatibility claims. Schema-2
baseline output supplies host OS family and architecture but not kernel version, CPU model, power
state, or load; performance evidence must supplement those environmental facts and follow the
matched-host approval policy in `README.md`.
