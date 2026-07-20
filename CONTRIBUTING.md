# Contributing to AxiomOS

## Branch and release flow

`main` is the released, production-quality history. `prod` is the sprint release-candidate
branch. `dev` is the integration branch. Work branches start from current `dev`, use a
short prefix such as `feat/`, `fix/`, `docs/`, or `security/`, and return to `dev` through
a pull request. At sprint close, `dev` is promoted to `prod`; after release validation,
`prod` is promoted to `main`. Never develop directly on the three long-lived branches.

GitHub calls these pull requests; “PR” and “merge request” are equivalent in this project.
Delete work branches after merge. Keep commits small, signed when local signing is
configured, attributable to the repository owner, and free of generated binaries or secrets.

## Pull-request rules

Each PR must have one coherent purpose, link its issue, explain risk and rollback, include
tests at the correct layer, and update docs/ADRs when behavior or architecture changes.
Before review, run `./scripts/check.sh`. Security-sensitive code requires threat modeling;
`unsafe` Rust requires a dedicated ADR, a stated invariant, targeted tests, and reviewer
attention. No merge may weaken warnings, skip tests, or silently swallow errors.

Use squash merges for work branches. Promotion PRs preserve sprint history. Required CI,
resolved conversations, and the configured history policy are enforced. A sole repository
owner cannot approve their own PR, so protection requires green automated evidence and zero
approvals until an independent maintainer is intentionally added.

## Engineering standard

- Prefer Rust for kernel, drivers, services, tooling, and compiler implementation. Unsafe Rust
  is prohibited during the foundation phase; introducing a narrowly scoped exception requires
  a security ADR, explicit invariants, tests, and a deliberate lint-policy change.
- Use assembly only for reset/interrupt/context-switch boundaries and C only for necessary
  firmware, hardware, or ecosystem ABIs. Document every boundary.
- Keep policy separate from mechanism; use narrow modules and typed interfaces.
- Return structured errors with context. Kernel failures fail closed and remain observable.
- Unit-test pure logic, integration-test subsystem contracts, boot-test in QEMU, fuzz parsers
  and untrusted inputs, and benchmark performance claims against recorded baselines.
- Measure CPU, memory, latency, throughput, and energy where relevant. “Fast” is not an
  acceptance criterion without a reproducible benchmark.

## Sprint discipline

A sprint is two weeks unless its milestone says otherwise. Issues must state outcome,
acceptance criteria, dependencies, tests, security considerations, and documentation impact.
At close: all committed issues are done or explicitly moved with rationale; CI is green;
release notes and benchmark/security deltas are recorded; `dev` is promoted through `prod`
to `main`; and merged work branches are deleted.
