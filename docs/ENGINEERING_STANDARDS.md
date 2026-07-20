# PolytopeOS engineering standards

This document is the public engineering contract for PolytopeOS. It defines the quality bar shared
by kernel, compiler, tools, services, benchmarks, CLI, and future graphical-shell work. Contribution
mechanics are in [CONTRIBUTING.md](../CONTRIBUTING.md), security reporting is in
[SECURITY.md](../SECURITY.md), and decisions that change architecture belong in
[architecture decision records](adr/).

## Product and research bar

PolytopeOS is a from-scratch research operating system for software engineering, AI/ML, scientific
and distributed computing, data and database systems, cloud infrastructure, and quantitative
workloads. It is not a Linux distribution or a production-ready security boundary. Familiar Unix
interfaces are a usability choice, not a substitute for independent architecture.

The differentiator is a constraint-aware and observable resource plane. Workloads should eventually
be able to declare resource budgets and objectives across CPU, GPU, memory, latency, throughput,
energy, locality, isolation, and reproducibility. The system must expose why a placement or
scheduling decision occurred. Novelty, security, compatibility, and performance are empirical
claims: each needs a reproducible comparison and clearly stated limitations.

The system is designed for demanding professional workflows:

- topology, NUMA, accelerators, collectives, and fault handling for HPC and distributed ML;
- efficient compilation, debugging, profiling, remote development, and reproducible workspaces for
  software engineers;
- explicit I/O, cache, durability, provenance, and backpressure behavior for data/database work;
- low jitter, deterministic replay, auditable timing, and tail-latency measurement for quantitative
  workloads;
- isolation, workload identity, observability, orchestration, and secure lifecycle for cloud work;
  and
- a composable Unix-like CLI plus an accessible, functional graphical shell that preserves headless
  operation and strict latency/resource budgets.

The Polytope compiler is developed from scratch alongside the OS. The project owns language
semantics, diagnostics, parsing, recovery, typing, IR, optimization, lowering, and code generation.
Bootstrap assemblers, linkers, firmware interfaces, and carefully selected libraries may be used
when their boundary is documented; they do not replace the project-defining implementation.

## Architecture and code organization

- Separate policy from mechanism and portable logic from architecture/device adapters.
- Point dependencies inward toward small, stable, typed contracts. Firmware, device, host, network,
  and UI integrations are boundary layers.
- Prefer cohesive modules with one reason to change. Avoid functions that combine parsing,
  validation, allocation, I/O, policy, diagnostics, and process control.
- Use types and state machines to reject invalid states. Avoid magic values, stringly typed state,
  hidden global mutation, boolean-flag clusters, and silent fallback.
- Bound privileged data structures and untrusted operations. Use checked arithmetic for sizes,
  addresses, counts, durations, offsets, and conversions.
- Keep public APIs narrow. Document inputs, outputs, errors, invariants, side effects, allocation,
  blocking, privilege, and panic behavior.
- Prefer deterministic iteration and serialization whenever output can affect artifacts, tests, or
  scientific reproducibility.
- Generalize only after the current vertical slice is correct. Extension points must preserve real
  invariants rather than predict hypothetical implementations.

Rust is the default for kernel, services, compiler, CLI, and UI infrastructure. `no_std` is required
where the runtime is unavailable. Assembly is limited to unavoidable architecture and ABI
transitions. C is accepted only for a necessary external ABI and is isolated behind reviewed Rust
interfaces. Python is suitable for experiments and analysis outside the trusted computing base;
shell is limited to short, portable orchestration. A new language or toolchain requires an
architecture and supply-chain justification, not merely convenience.

## Correctness and error handling

Correctness includes failure behavior. Implementations must:

- validate structure and semantics before use, especially for firmware, ELF, compiler, syscall,
  device, filesystem, packet, and control-plane inputs;
- check magic/version/length/count/alignment/range/overflow/overlap/state/lifetime invariants;
- keep errors structured internally and add contextual information at subsystem boundaries without
  erasing the original cause;
- fail closed for malformed, unsupported, ambiguous, stale, or unauthenticated data;
- bound retries, recursion, queues, allocation, execution time, and diagnostic output;
- avoid swallowing errors, panicking for recoverable host-side failures, or returning unclassified
  catch-all errors; and
- make fatal early-kernel failures observable without relying on allocation or a functioning UI.

Stable automation-facing diagnostics use explicit phase, status, category, and code fields. Human
messages should identify the problem, relevant safe context, and remediation. Secrets, credentials,
unnecessary raw memory addresses, and user data do not belong in logs.

## Unsafe and privileged code

The workspace denies unsafe Rust by default. Pure parsing, validation, policy, and contract crates
should forbid it. An architecture/FFI crate may opt in only under an accepted security ADR that
enumerates its invariants and residual risk.

Every unsafe operation has a nearby `SAFETY:` explanation covering the applicable pointer validity,
bounds, alignment, initialization, aliasing, lifetime, ABI, privilege, and concurrency assumptions.
Unsafe code must be lexically small, preceded by validation, hidden behind a safe typed interface,
and covered by positive and negative tests. Unsafe is never an acceptable shortcut around API
design or measurement.

## Security engineering

Security is an architectural property, not a final milestone. Apply least privilege, explicit
authority, deny-by-default behavior, isolation, and auditable state transitions. Design toward:

- memory-safe privileged code and minimal trusted computing base;
- W^X and non-executable data, control-flow protection, isolated address spaces, and capability-
  scoped handles;
- authenticated protocols, secure/measured boot, signed updates, rollback resistance, and artifact
  provenance;
- reproducible builds, dependency transparency, pinned CI actions, and minimal workflow permissions;
- bounded resource consumption and fault containment; and
- explicit analysis of timing, speculative-execution, and other side-channel exposure where secrets
  are involved.

Threat-model each new trust boundary and add abuse/negative tests. Do not claim a control is present
until it is enforced. Untrusted PR code must not receive repository secrets or release authority.
Dependencies require a clear need, compatible license, acceptable MSRV, minimal features, lockfile
pinning, and advisory review.

## Verification matrix

Choose tests according to the risk and layer:

| Evidence | Required use |
|---|---|
| Unit tests | Pure state, parsing, validation, policy, transforms, and error classification |
| Property tests | Arithmetic/range invariants, round trips, conservation, and normalization |
| Fuzzing | Every parser and externally controlled binary/protocol format |
| Integration tests | Subsystem contracts and real host/guest workflows |
| QEMU tests | Boot success, expected rejection, panic, timeout, and exit classification |
| Fault injection | Allocation/I/O failure, truncation, corruption, invalid state, and partial work |
| Concurrency verification | Model checking where practical, deterministic stress otherwise |
| Golden/differential tests | Diagnostics, compiler artifacts, protocols, and reference behavior |
| Benchmarks | Every material speed, memory, throughput, latency, jitter, or efficiency claim |

Tests have hard timeouts, bounded logs, and deterministic inputs. Retrying a flaky test is not a
fix. Skips require an explicit environmental reason and a restoration issue. Golden output changes
must be reviewed as behavior changes.

The baseline repository gate is:

```sh
./scripts/check.sh
```

Subsystem documentation must list any additional build, boot, fuzz, or benchmark commands. CI and
local evidence are reported separately; a provider outage must never be described as a successful
or failed code check.

## Performance and reproducibility

“Fast,” “lightweight,” and “optimized” are not acceptance criteria. Record applicable CPU/wall
time, memory/stack/heap footprint, artifact size, throughput, tail latency, jitter, context switches,
I/O, network cost, accelerator utilization, and energy. Separate cold-start, steady-state, and
saturation behavior.

Every benchmark identifies hardware or VM, firmware, toolchain, flags, workload/data, warmup, sample
count, variance/percentiles, and comparison baseline. QEMU measurements are emulator evidence and
must not be extrapolated to physical hardware. Keep raw machine-readable evidence and define a
review process for regressions.

Reproducible artifacts use pinned inputs, normalized paths/timestamps, deterministic ordering, fixed
identifiers where appropriate, and byte comparison from independent clean build directories. If
byte identity is not possible, automatically normalize the exact documented nondeterministic field
and fail on any other difference.

## Boot and kernel rules

- Firmware and kernel are distinct trust/runtime epochs. Boot services are exited before kernel
  ownership is asserted.
- The handoff is versioned, bounded, layout-stable, and validated before dereferencing or using
  supplied addresses.
- ELF loading validates architecture, executable type, header/table bounds, segments, entry point,
  page alignment, W^X, range overflow/overlap, fixed-address assumptions, and zero-fill behavior.
- Linker scripts define and assert executable, read-only, writable, BSS, guard, and stack placement;
  emitted artifacts are independently inspected.
- Entry code documents calling convention, registers, stack alignment, direction flag, interrupt
  state, and non-return behavior.
- Early diagnostics allocate nothing, remain bounded, and provide stable automation markers.
- Supported emulator paths distinguish success, expected rejection, panic, loader failure, and hang
  with deterministic exits.

## Compiler rules

Keep lexing, parsing, syntax, resolution, typing, IR, optimization, lowering, and emission as distinct
layers with explicit contracts. Diagnostics preserve precise spans and recovery context. Each
optimization documents legality and has positive, negative, and differential tests. Parser and IR
inputs are fuzzed and resource-bounded. Reproducible input must not acquire host paths, wall time,
map-order nondeterminism, or machine identity in output.

## CLI and graphical-shell rules

CLI commands have consistent verbs/options, useful help, stable exit codes, clean stdout/stderr
separation, non-interactive support, and stable machine-readable output where automation needs it.
Destructive actions default safely and expose scope or dry-run behavior where practical.

CLI and graphical clients consume shared typed services; system policy is not duplicated in a UI.
The graphical shell is keyboard accessible, scalable, contrast-aware, responsive under load, and
provides reduced-motion and headless fallbacks. Visual effects have measured latency, memory, and
power budgets.

## Documentation and review

Update documentation in the same change as behavior. README content must reflect current support,
not roadmap aspiration. ADRs record durable decisions, considered alternatives, security and
performance consequences, and supersession; accepted history is not rewritten to hide a changed
choice. Code comments explain invariants and intent.

A reviewable PR has one coherent purpose, links its issue, maps evidence to acceptance criteria,
describes risk and rollback, identifies security/unsafe changes, and lists residual limitations.
Before merge, review the complete diff for unrelated changes, stale naming, secrets, generated
artifacts, disabled checks, placeholders, undocumented unsafe code, and accidental compatibility
claims.

## Definition of done

Work is complete when its acceptance criteria are demonstrated; proportional positive, negative,
and boundary tests pass; diagnostics and errors are actionable; security and performance impacts are
documented; dependencies and unsafe boundaries are justified; docs and ADRs are current; generated
artifacts and secrets are absent; and the full required local/CI evidence is reported accurately.
Sprint completion additionally requires promotion through `dev -> prod -> main` and deletion of
merged work branches as defined in [CONTRIBUTING.md](../CONTRIBUTING.md).
