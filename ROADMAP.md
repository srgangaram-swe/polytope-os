# PolytopeOS roadmap

The roadmap is outcome-driven, and dates beyond the active sprint are forecasts rather than
promises. Each milestone should deliver a demonstrable vertical slice.

| Sprint | Outcome | Principal work |
|---|---|---|
| 1 | Repository and architecture foundation | Workspace, governance, CI, security baseline, kernel/compiler skeletons |
| 2 | Reproducible x86_64 boot | UEFI/QEMU boot, serial diagnostics, linker/image pipeline, boot tests |
| 3 | Memory foundation | Physical allocator, paging, heap, address-space invariants, fault diagnostics |
| 4 | Execution core | Interrupts, timers, tasks, preemption, synchronization, scheduler benchmarks |
| 5 | Userspace boundary | Syscall ABI, ELF loader, process isolation, capabilities, init service |
| 6 | Storage and device model | VFS, initramfs, block abstraction, safe driver lifecycle, persistence tests |
| 7 | Network and distributed substrate | NIC path, TCP/IP baseline, zero-copy messaging experiments, observability |
| 8 | Polytope compiler front end | Language spec, parser, typed AST, diagnostics, fuzzing, golden tests |
| 9 | Polytope compiler middle/back end | SSA IR, optimization passes, code generation, debugger metadata |
| 10 | Intent-aware resource plane | Workload contracts, topology model, scheduler policy API, traceable decisions |
| 11 | Accelerator/HPC vertical slice | GPU abstraction, NUMA/huge pages, collective primitives, MPI-compatible study |
| 12 | Developer experience | Shell, package/workspace manifests, reproducible environments, remote workflows |
| 13 | Data/quant profiles | Low-jitter mode, database I/O profile, deterministic replay, benchmark suite |
| 14 | Functional graphical shell | GPU-composited UI, accessible terminal, profiling dashboard, graceful fallback |
| 15 | Security hardening and alpha | Secure/measured boot, sandboxing, update signing, adversarial testing, alpha SDK |

Post-alpha candidates include ARM64, broader POSIX/Linux compatibility, production vendor GPU
drivers, compiler self-hosting, container-orchestrator compatibility, and certification work.
They are deliberately excluded from the first 15 sprints so the active plan remains credible.

## Success measures

Claims will be compared with Linux baselines on pinned hardware and published harnesses.
Measures include boot time, idle footprint, compile throughput, tail latency, scheduler jitter,
collective communication throughput, accelerator utilization, energy per task, reproducibility,
crash containment, and time-to-diagnosis. Novel intent-aware policies must beat or explain
their tradeoffs against conventional cgroup/container and batch-scheduler configurations.
