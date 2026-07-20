# ADR 0003: PolytopeOS project identity

- Status: Accepted
- Date: 2026-07-19

## Decision

Name the project PolytopeOS and its from-scratch toolchain the Polytope compiler. In convex geometry, a
polytope is the feasible region defined by simultaneous constraints. That is a direct model
for the project's differentiator: workloads declare CPU, GPU, memory, latency, energy,
locality, and reproducibility constraints; resource policy finds and explains a feasible
allocation. A separate compiler sub-brand is intentionally avoided until it provides user value
and passes the same collision review.

## Context

The repository's initial working name collided with an existing bare-metal Rust operating
system discovered during public-name due diligence. The identity changed before an alpha or
release artifact existed. Early commit messages retain the working name as an honest record;
all source, package, issue, and repository-facing names use PolytopeOS going forward.

## Consequences

Performance claims still require evidence; the geometric language is a design model, not a
claim that every policy is a convex optimization problem. New naming must use `polytope-os`
for the repository, `polyctl` for the developer CLI, and Polytope compiler/language for toolchain work.
