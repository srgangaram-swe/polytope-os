# ADR 0001: Project thesis and implementation languages

- Status: Accepted
- Date: 2026-07-19

## Decision

AxiomOS will investigate an intent-aware resource plane: workloads declare measurable
objectives and constraints, while kernel and user-space policies expose why resources were
allocated. Unix-like interfaces remain familiar where useful, but compatibility is not allowed
to obscure measurable scheduling and provenance.

Rust is the default systems and compiler language because memory safety and zero-cost
abstractions fit the threat and performance model. Assembly is permitted only at unavoidable
architecture boundaries. C is permitted for constrained external ABIs and must be isolated
behind reviewed wrappers. Python may orchestrate experiments and analysis but is not part of
the kernel trusted computing base. The graphical shell will use the same Rust service model.

During the foundation phase, workspace lints forbid unsafe Rust. A future architecture boundary
may use it only after a security ADR changes that policy and defines auditable invariants.

## Consequences

Language choice is decided per boundary rather than novelty or convenience. Any future unsafe
code and all foreign interfaces require explicit invariants, tests, and a follow-up ADR. Performance and
novelty claims require reproducible evidence.
