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
| Minimize unsafe/privileged code | Enforced: unsafe Rust forbidden | Boundary-specific ADRs and tests |
| Validate inputs and fail closed | Started in kernel/compiler skeletons | Fuzzing and negative integration tests |
| Pin build inputs | Toolchain and CI actions pinned | Reproducible image comparison |
| Dependency review | Dependabot enabled; no third-party Rust crates | License/advisory policy as dependencies land |
| Least privilege and audit events | Architecture requirement | Capability and event-schema milestones |
| Artifact integrity | Not implemented | Signed releases, updates, SBOM, and provenance in Sprint 15 |
| Secret isolation | CI has read-only contents permission | Release-environment and key-management design |

Every subsystem ADR must update its control status and document residual risk.
