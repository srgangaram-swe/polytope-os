# ADR 0004: x86_64 UEFI boot and unsafe boundaries

- Status: Accepted
- Date: 2026-07-19
- Scope: Sprint 02 reference boot path

## Context

PolytopeOS needs a boot path that is small enough to audit, deterministic enough to compare across
clean builds, and explicit about the transition from firmware-owned state to kernel-owned state.
The kernel must remain independent of UEFI APIs and data layouts. At the same time, parsing an ELF
kernel, interpreting firmware memory data, copying bytes to physical pages, and transferring control
cannot all be expressed safely without a narrow machine boundary.

The Sprint 02 target is a research reference platform: x86_64 QEMU with pinned OVMF firmware. It is
not a general boot manager, a real-hardware qualification effort, or a secure-boot implementation.
The design must therefore be strict and measurable without implying protections that are planned for
later milestones.

## Decision

### Use a two-stage UEFI design

The reference image contains two independently built programs:

1. `EFI/BOOT/BOOTX64.EFI`, a minimal Rust loader built for `x86_64-unknown-uefi` using the
   `uefi-rs` 0.35 API; and
2. `POLYTOPE/KERNEL.ELF`, a separately linked Rust kernel built for
   `x86_64-unknown-none`.

The loader is a firmware adapter, not part of kernel policy. It locates the kernel, validates the
supported ELF subset through a safe parser, allocates all handoff memory, loads the accepted
segments, obtains the final firmware memory map, exits UEFI boot services, and transfers control.
After a successful `ExitBootServices`, neither the loader nor the kernel may call boot services or
retain UEFI-owned references.

The kernel receives only the project-owned boot contract described below. It does not receive
`uefi-rs` types or raw UEFI descriptor pointers as its semantic interface.

### Make sequencing an explicit state machine

The loader design has the following ordered phases:

1. initialize bounded diagnostics;
2. open the fixed image paths and read bounded inputs;
3. validate the kernel ELF without mutating destination memory;
4. allocate the validated kernel ranges and contract storage while preserving the linker-reserved
   stack and guard layout;
5. copy file-backed bytes and zero each accepted segment's remaining memory;
6. finish all pre-transition state without retaining boot-service allocator users;
7. delegate final-map acquisition and `ExitBootServices` to pinned `uefi-rs`, which makes at most two
   attempts and cold-resets on a terminal allocation, map, or transition failure;
8. switch to loader-owned diagnostics and establish a valid ABI call stack; and
9. transfer control to the validated entry point, whose first shim selects the linker bootstrap
   stack and which must not return.

Skipped, repeated, or out-of-order project-owned phases are errors. A project-observed failure before
step 7 may report through firmware and serial facilities that are valid in that phase. The pinned
dependency owns terminal step-7 failure behavior and may reset without a project marker. A failure
after a successful step 7 must use only loader-owned state and architecture-local diagnostics.

### Use a versioned, bounded, fixed-size boot contract

The version-one handoff has a fixed `repr(C)` wire layout, little-endian integer encoding, magic
`POLYBOOT`, and ABI version 1.0. Its header contains the magic, ABI major and minor versions,
`header_size`, `total_size`, `memory_region_size`, `region_count`, and flags. The remaining fixed
layout carries platform and scenario data plus storage for at most 128 project-defined memory-region
records. The exact supplied byte length, header size, total size, and record size must all match the
version-one constants; unused records are zero.

Platform, flag, memory-kind, and scenario-kind values cross the ABI as fixed-width raw integers with
typed newtype validation on each side. The platform data identifies UEFI on x86_64, optional ACPI
RSDP address/length data, and the boot CPU identifier. Scenario data consists of a typed raw kind,
raw flags, and one `u64` argument. No Rust enum, `bool`, `usize`, reference, slice, UEFI type, or
interior pointer crosses the ABI. A memory-region record uses fixed-width integers to describe a
4 KiB-aligned physical range, its validated classification, and attributes.

The outer architecture handoff provides both the contract address and the byte length of its backing
allocation. The first kernel operation at this boundary creates a read-only byte view under the
loader's lifetime and mapping invariant. All subsequent parsing is safe Rust. Before semantic use,
the validator reads fields from byte offsets rather than casting the bytes to a Rust reference. It
checks:

- `POLYBOOT` magic and exact ABI version 1.0;
- exact header, total, memory-record, and independently supplied outer lengths;
- `region_count <= 128` and all unused record bytes equal to zero;
- known platform, memory-kind, scenario-kind, and flag values;
- every index, multiplication, addition, and integer conversion with checked arithmetic;
- non-empty 4 KiB-aligned physical ranges, end-address overflow, sorted order, and non-overlap; and
- internally consistent optional ACPI and scenario fields.

Sprint 02 accepts exactly its declared contract version. Forward/backward compatibility is not
inferred from a larger header or ignored bytes; a later compatibility rule requires a superseding
ADR and explicit negative tests.

The loader is responsible for constructing a contract that passes the same validator used by the
kernel. Loader validation does not replace kernel validation: corruption or an implementation defect
at the handoff boundary must still fail closed.

### Support one strict ELF64 profile

The loader accepts only a statically linked, little-endian ELF64 version-one `ET_EXEC` for
`EM_X86_64`. It accepts at most eight program headers and at most four load segments: text,
read-only data, writable data, and the bootstrap stack. `PT_NULL` is ignored; `PT_LOAD` is the only
load-bearing type. Interpreters, dynamic linking, relocations, and all other program-header types are
rejected for this profile.

Before allocation or copying, the safe ELF validator checks at least:

- file/header/program-table bounds and all integer conversions;
- no more than eight program headers, four load segments, and a bounded aggregate loaded size;
- `p_filesz <= p_memsz`, valid power-of-two alignment, and required offset/address congruence;
- 4 KiB page-rounded, sorted, non-overlapping physical ranges wholly contained in the half-open
  Sprint 02 load window `[0x0020_0000, 0x4000_0000)`;
- the Sprint 02 fixed-address/identity-mapped assumptions and collision checks against loader-owned
  state;
- no segment requesting writable and executable permissions simultaneously;
- an entry point contained by exactly one accepted executable load segment; and
- complete zero initialization of the memory after each segment's file-backed bytes.

The validated load plan is an immutable safe value. The later copy boundary consumes that plan and
must not re-read unchecked ELF fields. Rejecting writable-plus-executable segments is a format
control; it is not a claim that the inherited UEFI page tables enforce final W^X permissions.
Sprint 03 owns kernel page-table construction and enforcement.

### Define one kernel-entry ABI

The architecture handoff uses the x86_64 System V convention: `RDI` contains the boot-contract
pointer and `RSI` contains its exact byte length. The loader provides a valid incoming call stack and
clears the direction flag. The incoming interrupt-enable flag is deliberately unspecified. The
kernel's first entry instructions execute `cli`, execute `cld` again defensively, preserve the two
arguments, switch to the linker-defined kernel stack, zero the required BSS ranges, and call the safe
Rust entry. The exported symbol and these register requirements are architecture interfaces and must
be asserted by inspection and integration tests. At transfer:

- long mode and paging remain in the UEFI-established state;
- the incoming stack is valid for the transition and the linker stack selected before safe Rust has
  the documented 16-byte alignment;
- safe Rust is reached only with interrupts disabled and the direction flag clear;
- the contract and every referenced physical range remain live;
- no firmware-owned pointer is passed as a project semantic type; and
- returning from the kernel entry is a deterministic boot failure.

The linker layout reserves a page-sized range next to the initial kernel stack, and loader range
validation excludes it from conflicting ownership. Sprint 02 does **not** install a new page table,
so that range may remain mapped by the firmware page tables. It is an ownership guard and future
mapping input, not yet a hardware-enforced guard page. Documentation and diagnostics must not claim
otherwise.

### Constrain and inventory unsafe operations

Workspace code remains safe by default. The boot-contract and ELF-validation crates retain
`#![forbid(unsafe_code)]`. This ADR permits a crate or module to lower the workspace
unsafe lint only for the reviewed boundaries below. It does not authorize unsafe code in the boot-
contract validator, ELF parser, image builder, scenario parser, or other policy code.

| Boundary | Why unsafe is unavoidable | Required invariant and safe surface |
|---|---|---|
| Allocated-page initialization | Rust cannot prove that a firmware-allocated physical range is valid writable memory | The validated load plan is in range; allocation ownership and size cover the destination; source and destination do not overlap; copy and zero lengths were checked. Expose only a load operation over the safe plan. |
| Contract-address import | The kernel initially receives a machine address and byte length | Loader-owned pages remain live and identity-accessible; the outer length is bounded; only a read-only byte slice is created. Pass that slice immediately to the safe contract validator. |
| Kernel entry transfer | A dynamically validated ELF entry and new stack require an architecture transition | Entry lies in an accepted executable segment; ABI registers, stack alignment, interrupt state, and direction flag match the contract; the function never returns. Keep the assembly/trampoline lexical scope minimal. |
| Early x86_64 port I/O | COM1 and the QEMU test-exit device use privileged I/O instructions | Ports and widths are compile-time allow-listed; output is bounded and contains no secrets or unnecessary addresses. Wrap each operation in a narrow diagnostic API. |
| Third-party firmware boundary | `uefi-rs` encapsulates firmware pointers and calls using its reviewed unsafe internals | Pin version/features, review dependency provenance and advisories, do not extend firmware lifetimes past `ExitBootServices`, and convert to project-owned values before kernel handoff. |

Every local unsafe block must have an adjacent `SAFETY:` explanation covering pointer validity,
bounds, alignment, initialization, aliasing, lifetime, privilege state, and concurrency as
applicable. The final implementation inventory, source locations, and tests must be reviewed against
this table; an operation that does not fit requires an ADR amendment rather than a broad exception.

### Make the reference image deterministic, not implicitly trusted

The version-one image is a fixed 64 MiB raw disk with a protective MBR, primary and backup GPT, and
one fixed-geometry FAT32 EFI System Partition. Geometry, disk and partition GUIDs, FAT volume ID and
label, timestamps, allocation parameters, file paths, and insertion order are constants. The builder
must create the filesystem from empty state rather than copy host metadata into it. Two isolated
clean builds are compared byte for byte and by digest.

Fixed identifiers exist only to make the research artifact reproducible. They are not device
identity, entropy, an authenticity signal, or a substitute for signing. Secure/measured boot,
signed updates, rollback protection, and release provenance remain Sprint 15 work.

### Use structured, bounded early diagnostics

Loader and kernel markers use a versioned ASCII grammar with stable phase/category/code fields.
Formatting is allocation-free after the relevant boundary, lines and dynamic fields have hard byte
limits, and unexpected bytes are escaped or replaced. Normal entry, expected rejection, deliberate
panic, timeout, and unexpected return have distinct machine classifications. The detailed protocol
is defined in `docs/boot/DIAGNOSTICS.md`.

Serial output is an observability interface, not a confidentiality boundary. It must not include
keys, file contents, full memory maps, host paths, or unnecessary physical addresses.

## Alternatives considered

### Embed the kernel in the EFI executable

Rejected for the reference design. A single binary is simpler initially but couples firmware-facing
code to the kernel link/load model and weakens independent ELF validation and kernel reproducibility
evidence.

### Implement UEFI bindings locally

Rejected. Reimplementing firmware bindings would enlarge the least-audited unsafe surface without
contributing to the project's kernel or resource-plane thesis. A pinned, narrowly featured
`uefi-rs` dependency is the more defensible boundary.

### Use BIOS or a general third-party boot protocol

Rejected for Sprint 02. BIOS adds legacy architecture scope; a general boot protocol adds
capabilities and compatibility commitments outside this vertical slice. Either can be reconsidered
through a later ADR with concrete user value and test capacity.

### Pass raw UEFI structures or unchecked Rust references

Rejected. Firmware layouts and lifetimes must not enter kernel policy, and an unchecked typed
reference could make malformed length, alignment, or version data undefined behavior before safe
validation can run.

## Consequences

The design keeps firmware integration replaceable, makes the kernel artifact independently
inspectable, and concentrates machine-level unsafety in reviewable locations. Deterministic images,
stable diagnostics, and negative scenarios make the boundary suitable for automated research
evidence.

The cost is more explicit format and lifecycle code, a project-owned ABI that must be versioned, and
two artifacts whose compatibility must be tested. The initial ELF and platform support is
intentionally narrow. Changes to the entry ABI, contract layout, image geometry, accepted ELF
profile, or unsafe inventory require an ADR update and corresponding negative evidence.

## Residual risks and non-goals

- The reference path is designed for QEMU x86_64 with pinned OVMF; real firmware and hardware are
  unqualified.
- Malicious firmware, CPU/firmware implants, physical attacks, and compromised host tools remain
  outside the current threat boundary.
- The disk and kernel are not authenticated, encrypted, measured, or rollback protected.
- OVMF pinning/checksums improve input control but do not establish firmware trust.
- Firmware-established mappings remain active. Final W^X/NX policy, an actually unmapped stack guard,
  address-space isolation, and KASLR are not Sprint 02 claims.
- Deterministic output demonstrates equality for the tested inputs and environment; it does not by
  itself prove source provenance or compiler correctness.
- Early serial diagnostics are observable by the host and are not confidential or authenticated.
- BIOS, ARM64, graphical boot, networking, storage drivers, interrupts, a heap, and general boot
  management are explicitly unsupported in this sprint.
