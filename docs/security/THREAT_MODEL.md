# Foundation threat model

## Assets and trust boundaries

Critical assets include boot integrity, kernel memory, process isolation, credentials, update
keys, build provenance, workload data, compiler correctness, and resource-allocation policy.
Initial boundaries are firmware/bootloader to kernel, architecture code to safe Rust, kernel to
userspace, compiler input to compiler process, CI to release artifacts, and control plane to
worker nodes.

## Baseline threats

Malformed binaries or source, memory corruption, confused-deputy resource access, privilege
escalation, timing/side-channel leakage, supply-chain substitution, rollback, malicious device
input, denial of service, and policy tampering are in scope. Physical attacks and a malicious
CPU/firmware are initially out of scope but must not be misrepresented as solved.

## Control plan

| Control | Foundation status | Planned evidence |
|---|---|---|
| Minimize unsafe/privileged code | Unsafe denied by default; Sprint 02 exceptions are limited by ADR 0004 | Source inventory, wrapper tests, architecture inspection, and QEMU negative paths |
| Validate inputs and fail closed | Safe bounded boot-contract and ELF profiles are specified; end-to-end evidence remains revision-specific | Unit/property/fuzz tests and negative QEMU scenarios |
| Pin build inputs | Toolchain and CI actions pinned; UEFI dependency exact-versioned; reference OVMF source checksum-pinned | Independent clean-build artifact and image comparison |
| Dependency review | Lockfile, minimal feature sets, Dependabot, and boundary rationale required; current CI does not run the advisory/license scanners | Point-in-time license/advisory report and reviewed transitive tree for each release, reported separately from CI |
| Least privilege and audit events | Architecture requirement | Capability and event-schema milestones |
| Artifact integrity | Not implemented | Signed releases, updates, SBOM, and provenance in Sprint 15 |
| Secret isolation | CI has read-only contents permission | Release-environment and key-management design |

Every subsystem ADR must update its control status and document residual risk.

## Sprint 02 x86_64 boot extension

ADR 0004 adds a two-stage boot boundary for the QEMU/OVMF reference platform. A Rust UEFI loader
reads a canonical test configuration and a separate ELF kernel, validates the supported profiles,
loads physical pages, exits boot services, and calls the kernel entry with a fixed-size project-owned
contract. This section defines the required threat controls; it does not claim the current revision
has completed every test or remote integration run.

### Additional assets

- the exact loader, kernel, image, scenario, OVMF, lockfile, and toolchain identities;
- the integrity and availability of loaded kernel pages and the boot contract;
- the final normalized firmware memory map and ownership classifications;
- the kernel entry address, bootstrap stack, BSS initialization, and ABI register values;
- the distinction between expected rejection, panic, loader failure, unexpected return, and hang;
  and
- reproducibility and baseline reports whose environment and digests support public claims.

### Trust flow and required controls

| Boundary or input | Threats | Required control and evidence | Residual limitation |
|---|---|---|---|
| Source/toolchain to host image builder | Artifact substitution, workspace/registry/user paths, timestamps, nondeterministic iteration, stale artifact selection | Locked dependencies; explicit artifacts; fixed GPT/FAT constants; canonical file order/time; encoded all-crate remaps for workspace, Cargo home, user home, and target output; exact-byte rejection of original host paths; independent read-back; two isolated byte comparisons and SHA-256 reports | Equality and path absence do not authenticate the source, compiler, or host |
| OVMF to UEFI loader | Malicious/incorrect firmware data, invalid lifetimes, boot-service misuse | `uefi-rs` 0.35 boundary; copy firmware facts into project-owned fixed-width values; bound counts/ranges; obtain final memory map; no firmware call/reference after successful `ExitBootServices` | Pinned/checksummed OVMF controls drift, not malicious firmware; firmware/CPU compromise is out of scope |
| GPT/FAT image to loader | Missing, replaced, oversized, extra, or ambiguous paths/configuration | Fixed canonical paths; bounded reads; host read-back rejects any extra/missing/reordered/wrong-kind tree entry; `BOOT.CFG` accepts exactly four complete ASCII byte strings; no search/fallback path; structured loader failure | FAT/firmware filesystem parsing remains in the trusted boot chain; exact-tree validation is not authentication; image is unsigned |
| Kernel ELF bytes to load plan | Truncation, integer overflow, segment overlap, wrong machine, W+X, entry outside executable memory, memory exhaustion | Safe allocation-free parser; ELF64/LE/v1/`ET_EXEC`/`EM_X86_64`; at most eight program headers and four loads (text, read-only data, writable data, stack); checked file/memory arithmetic; 4 KiB-aligned sorted non-overlapping ranges in `[0x0020_0000, 0x4000_0000)`; entry in exactly one executable load; negative/property/fuzz evidence | UEFI mappings may not enforce the accepted R/W/X flags; final W^X/NX is Sprint 03 work |
| Validated load plan to physical pages | Invalid pointer, undersized allocation, copy overlap, partial initialization, stale untrusted fields | Allocate exact checked ranges; consume only immutable validated plan; prove destination ownership/size; bounded non-overlapping copy; zero `p_memsz - p_filesz`; local `SAFETY:` invariant and wrapper tests | Physical-memory initialization is a local unsafe boundary; compromised firmware mappings can violate its premise |
| Loader to kernel contract | ABI confusion, truncated length, forged enum/boolean/reference, record overflow, unknown flags, overlapping memory ranges | `POLYBOOT` ABI 1.0; fixed `repr(C)` little-endian wire layout; independent pointer plus exact length; only fixed-width integers; at most 128 regions; exact sizes; zero unused entries; byte-offset parsing without casting; checked alignment/range/order/overlap/type validation in `#![forbid(unsafe_code)]` code | The first address/length-to-byte-slice operation depends on loader-provided lifetime and mapping invariants |
| Loader to kernel machine entry | Wrong entry/stack/register/flags, kernel return, BSS contamination | SysV64 `RDI` pointer and `RSI` exact length; valid incoming stack and DF clear; entry executes `cli` then `cld`, selects the linker stack, writes a non-zero retained BSS sentinel, clears all BSS, verifies the sentinel is zero, preserves arguments, and calls safe Rust; sentinel failure and unexpected return use distinct enumerated protocol exits | Firmware page tables and long-mode state are inherited; there is no KASLR or new isolation boundary; the sentinel proves this clear executed but is not a general RAM-integrity test |
| Bootstrap stack reservation | Stack collision or overflow into adjacent kernel data | Linker/range assertions reserve one page and exclude conflicting ELF ownership; document exact stack bounds; later page-table work consumes the reservation | The guard range is **reserved but may remain mapped**. Sprint 02 must not call it an unmapped or hardware-enforced guard page |
| Early COM1/debugcon and QEMU exit | Secret/address disclosure, unbounded output/polling, arbitrary privileged port writes, spoofed host classification | Typed allow-listed ports/widths; allocation-free records no longer than 256 payload bytes; bounded UART polling; fixed schema/codes; typed exit enum; hard host timeout; marker/status consistency tests | Serial/debug output is unauthenticated and host-visible; QEMU exit is a test mechanism, not a production security boundary |
| QEMU/OVMF execution harness | Hang, mutable firmware state, host-network exposure, misleading retries, unbounded logs | Headless isolated launch; no network/monitor; disposable variable store; fixed timeout; bounded logs; exact scenario; schema-2 report with QEMU/OVMF/image identities, sanitized arguments, marker state, and classification; classify provider outage separately | QEMU measurements do not establish bare-metal compatibility, performance, or security; the report omits CPU/kernel/power/load details needed for cross-revision performance claims |

### Boot-specific abuse cases

The Sprint 02 executed evidence includes these failures:

- missing or malformed `BOOT.CFG`, missing kernel, wrong PE/ELF format, and oversized payload;
- incompatible contract version, exact-length truncation, wrong magic/size/flags/platform/scenario,
  more than 128 regions, non-zero unused entries, and misaligned/overflowing/overlapping regions;
- ELF table truncation, too many headers, unsupported header type, invalid alignment or congruence,
  `p_filesz > p_memsz`, out-of-window/overlapping load ranges, W+X, and entry outside an executable
  load;
- deliberate panic, marker/exit mismatch, malformed/truncated/contradictory diagnostic streams, and
  a real hard-timeout process-termination probe; and
- two clean builds that differ in loader, kernel, filesystem metadata, GPT bytes, scenario, or the
  complete image.

No parser may truncate an over-limit firmware map or ELF table and continue as if it were complete.
Ambiguous ownership and unknown required values fail closed. Fuzz/property tests must bound input
size, memory, recursion, diagnostics, and run time and retain minimized regressions.

Project-observed page-allocation/contract-allocation failures and the assembly unexpected-return
exit have defined terminal values and host parser fixtures, but Sprint 02 has no end-to-end QEMU
fault injector that forces those guest branches. Final-map/`ExitBootServices` failure is owned by the
pinned dependency and has the reset limitation described below. These are explicit residual test
gaps, not passing-path claims; a later fault-injection facility must exercise them without adding
production scenario behavior.

### Unsafe inventory and containment

The boot-contract and ELF-validation crates forbid unsafe code. Host image/QEMU policy and the
bounded scenario parser also remain safe. ADR 0004 permits local unsafe operations only for:

- writing/zeroing firmware-allocated physical pages under an immutable validated load plan;
- importing the loader-provided address/length as one read-only byte slice before safe parsing;
- transferring to the validated entry with the specified machine state;
- allow-listed COM1, QEMU debugcon, and QEMU exit port I/O; and
- unsafe internals encapsulated by the exact-versioned UEFI dependency.

Each local unsafe operation needs an adjacent complete `SAFETY:` explanation and a safe typed
wrapper. Broad crate-level permission, unchecked ABI casting, or unsafe code inside format
validators is outside the accepted decision. A new operation requires an ADR/threat-model amendment
and negative evidence.

Before invoking the final firmware transition, a project-observed loader failure may use valid
firmware facilities and must end in a defined loader-failure state. The exact-versioned `uefi-rs`
transition obtains the final map, attempts `ExitBootServices` at most twice, and cold-resets if map
allocation, retrieval, or the transition fails; that dependency-owned failure path may not emit a
project marker and has not received an executed firmware fault-injection test in Sprint 02. After a
successful exit, project failure paths use only owned serial/debug/exit mechanisms and must not
attempt firmware recovery. A contract rejection must not consume rejected memory-map or platform
values. There is no fallback kernel, alternate path search, automatic repair, or recovery shell in
Sprint 02.

### Residual risk and explicit non-claims

- The raw image, loader, kernel, contract, and scenario are not signed, measured, encrypted, or
  rollback protected. Fixed GUIDs, volume ID, timestamps, and hashes are reproducibility inputs, not
  trust anchors.
- Secure/measured boot, signed releases/updates, provenance attestations, SBOM publication, and key
  lifecycle are planned later and must not be implied by SHA-256 evidence.
- A malicious firmware, CPU/firmware implant, physical attacker, compromised build host, or compiler
  backdoor can violate assumptions below the current boundary.
- UEFI-established page tables remain active. W^X/NX enforcement, an unmapped stack guard, KASLR,
  kernel/userspace isolation, and crash containment are not present at the Sprint 02 success point.
- ACPI RSDP address/length data is only bounded handoff metadata; it is not semantically trusted or
  parsed as platform policy in this sprint.
- COM1/debugcon output may be observed, modified, replayed, or dropped by the host. Diagnostics must
  not contain secrets, full maps, arbitrary memory, host paths, or unnecessary physical addresses.
- QEMU/OVMF is the only design target. Booting an image elsewhere does not create real-hardware or
  alternate-hypervisor support.
- Local passing evidence and GitHub Actions evidence are distinct. Provider-side job startup failure
  must not be described as code validation or bypassed by weakening branch protection.
