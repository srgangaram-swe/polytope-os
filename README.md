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

The repository currently has a deterministic x86_64 UEFI reference path: a Rust UEFI loader
strictly validates and loads a separately linked, freestanding Rust kernel, exits boot services,
and transfers a bounded project-owned contract. The kernel validates that contract in safe Rust and
emits structured allocation-free diagnostics. The Cargo workspace also contains the initial
Polytope compiler lexer and the host-side `polyctl` developer CLI.

Supported boot execution is deliberately narrow: headless QEMU x86_64 using checksum-pinned OVMF.
BIOS, ARM64, real hardware, paging ownership, a heap, interrupts, userspace, and production security
are not yet supported.

Run the fast local quality gate with:

```sh
./scripts/check.sh
cargo run -p polyctl -- doctor
```

From a clean checkout, build the loader and kernel twice, prove byte-for-byte reproducibility, and
emit the verified GPT/FAT image with one command:

```sh
cargo xtask repro-check --scenario normal
```

With `qemu-system-x86_64` available, boot that image under a hard timeout:

```sh
cargo xtask boot-test \
  --image target/polytope/polytope-x86_64.img \
  --scenario normal \
  --timeout-secs 15
```

See [docs/boot/README.md](docs/boot/README.md) for the architecture, negative scenarios, exact
diagnostic contract, reproducibility procedure, measured-baseline method, and current limitations.

The developer toolchain is pinned to Rust 1.97.1. Rust 1.85 is the declared minimum supported Rust
version (MSRV) and has a dedicated CI job; only a completed run is remote MSRV evidence. It is not
the preferred development compiler.

See [ROADMAP.md](ROADMAP.md), [CONTRIBUTING.md](CONTRIBUTING.md), and the architecture
decisions under [docs/adr](docs/adr) before proposing changes.

## License and security

Licensed under Apache-2.0. Please report vulnerabilities according to
[SECURITY.md](SECURITY.md); do not disclose exploitable issues publicly.
