# PolytopeOS

[![CI](https://github.com/srgangaram-swe/polytope-os/actions/workflows/ci.yml/badge.svg)](https://github.com/srgangaram-swe/polytope-os/actions/workflows/ci.yml)

PolytopeOS is a research operating system for software engineering, scientific computing,
AI/ML, data systems, cloud infrastructure, and quantitative workloads. It explores a
specific thesis: an OS can treat workload intent, reproducibility, and resource budgets
as first-class kernel/runtime concepts without sacrificing Unix familiarity.

This repository is intentionally honest about its maturity: it is a bootstrapping-stage
research project, not yet an operating system suitable for production use.

## Distinguishing direction

- **Intent-aware resource plane:** declarative CPU, GPU, memory, latency, energy, and
  locality objectives with observable scheduling decisions.
- **Reproducible workspaces:** hermetic environments and provenance integrated into the
  platform instead of layered on as an afterthought.
- **Scientific/distributed primitives:** topology and accelerator awareness designed for
  HPC, distributed training/inference, databases, and low-jitter quantitative systems.
- **Safe systems core:** Rust for memory-safe kernel and service code; narrowly scoped C
  and assembly only at ABI, firmware, and architecture boundaries.
- **Polytope compiler:** a from-scratch compiler toolchain developed alongside the OS, with
  explicit intermediate representations and diagnostics.

The name comes from convex geometry: a polytope is the feasible region cut out by many
constraints. PolytopeOS applies that model to CPU, GPU, memory, latency, energy, locality,
and reproducibility objectives, making resource tradeoffs explicit and explainable.

## Current foundation

The Cargo workspace contains a `no_std` kernel state model, an initial Polytope compiler lexer,
and the host-side `polyctl` developer CLI. Run the fast local quality gate with:

```sh
./scripts/check.sh
cargo run -p polyctl -- doctor
```

The developer toolchain is pinned to Rust 1.97.1. Rust 1.85 is the declared and CI-tested
minimum supported Rust version (MSRV), not the preferred development compiler.

See [ROADMAP.md](ROADMAP.md), [CONTRIBUTING.md](CONTRIBUTING.md), and the architecture
decisions under [docs/adr](docs/adr) before proposing changes.

## License and security

Licensed under Apache-2.0. Please report vulnerabilities according to
[SECURITY.md](SECURITY.md); do not disclose exploitable issues publicly.
