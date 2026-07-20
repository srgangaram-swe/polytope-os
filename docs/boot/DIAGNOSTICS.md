# Early boot diagnostics and exit protocol

Sprint 02 uses a deliberately small machine-readable serial protocol plus QEMU's test-exit device.
This is an observability and automation contract for the x86_64 QEMU/OVMF reference path. It is not
a general logging framework, a stable user-facing API, or a confidentiality channel.

The records below are normative design requirements. A boot result is not considered implemented or
verified until the corresponding loader/kernel output and host harness tests agree with them.

## Serial transport

Reference automation captures COM1 (initialized as 38,400 baud, 8-N-1) and QEMU debugcon through
non-interactive backends. Boot components must emit ASCII only. Each record payload is at most 256
bytes; LF or CRLF framing is emitted in addition to that bound. The host parser removes at most one
CR immediately before LF and preserves all other bytes.

After boot services are exited, formatting and transmission are allocation-free and use only owned
state. The COM1 port and width are compile-time allow-listed inside the architecture diagnostic
boundary. A stalled or absent UART must not cause an unbounded wait; the writer has a documented
bounded polling policy and may report loss through the final exit classification where possible.

## Marker grammar

The stable marker has exactly these space-separated fields and key order:

```text
POLYTOPE_BOOT schema=1 seq=NNNN phase=PHASE level=LEVEL code=CODE
```

- `POLYTOPE_BOOT` is the literal protocol discriminator.
- `schema=1` is the exact diagnostic schema. Unknown schemas are not accepted as this protocol.
- `seq` is a zero-padded, four-digit, monotonically increasing sequence within one boot.
- `phase` is a lowercase ASCII identifier containing only `a-z`, `0-9`, and `_`.
- `level` is one of `info`, `error`, or `fatal` for the Sprint 02 records.
- `code` is an uppercase ASCII identifier containing only `A-Z`, `0-9`, and `_`.

There are no optional fields, quoting rules, key reordering, duplicate keys, or trailing text in
schema 1. A future field requires a new schema or an explicitly backward-compatible parsing rule;
test code must not infer compatibility by splitting arbitrary `key=value` text.

Human-oriented lines may exist while bringing up the implementation, but they are not evidence and
the harness must never derive pass/fail from them. They remain subject to the same bounded-output and
redaction rules.

## Required kernel records

The first safe-Rust entry result follows the three loader/handoff records and uses sequence `0004`:

```text
POLYTOPE_BOOT schema=1 seq=0004 phase=kernel_entry level=info code=KERNEL_READY
POLYTOPE_BOOT schema=1 seq=0004 phase=kernel_entry level=error code=ABI_VERSION
POLYTOPE_BOOT schema=1 seq=0004 phase=kernel_entry level=error code=CONTRACT_LENGTH
POLYTOPE_BOOT schema=1 seq=0004 phase=kernel_entry level=error code=CONTRACT_INVALID
```

Their meanings are:

| Code | Meaning |
|---|---|
| `KERNEL_READY` | The outer pointer/length boundary and complete `POLYBOOT` ABI 1.0 contract passed safe validation, and control reached the Sprint 02 safe-Rust success point |
| `ABI_VERSION` | Magic/layout were readable enough to classify an unsupported ABI major/minor version; no contract contents were semantically consumed |
| `CONTRACT_LENGTH` | The independent supplied length or a fixed header/total/record size was truncated, oversized, or inconsistent |
| `CONTRACT_INVALID` | Another contract invariant failed, including magic, flags, platform/scenario values, record count, zero-fill, range alignment/overflow/order/overlap, or optional-field consistency |

The deliberate panic scenario emits exactly this fatal record and does not emit `KERNEL_READY`:

```text
POLYTOPE_BOOT schema=1 seq=0005 phase=panic level=fatal code=KERNEL_PANIC
```

`KERNEL_READY` means only that the Sprint 02 handoff reached safe Rust with an accepted contract. It
does not mean paging, a heap, interrupts, userspace, devices, secure boot, or production readiness
exists.

The loader emits `LOADER_START` at sequence `0001`. A successful path then emits `ELF_VALID` at
`0002` and `HANDOFF_READY` at `0003`. Terminal loader codes are:

| Code | Sequence/level | Meaning |
|---|---|---|
| `FILE_READ` | `0002` / `error` | A required path could not be opened or read to completion |
| `CONFIG_INVALID` | `0002` / `error` | `BOOT.CFG` was oversized or did not match one canonical token |
| `ELF_INVALID` | `0002` / `error` | The kernel exceeded its file bound or failed strict ELF validation |
| `ALLOCATION` | `0002` / `error` | Bounded loader memory allocation or size accounting failed |
| `KERNEL_ADDRESS` | `0002` / `error` | A fixed kernel or stack-guard page could not be reserved at its validated address |
| `CONTRACT_STORAGE` | `0002` / `error` | Fixed-size boot-contract pages could not be allocated |
| `CONTRACT_BUILD` | `0003` / `error` | The final memory map could not be encoded into the bounded contract |
| `LOADER_PANIC` after `LOADER_START` | `0002` / `fatal` | The allocation-free panic handler ran in phase `loader` before `ELF_VALID` |
| `LOADER_PANIC` after `ELF_VALID` | `0003` / `fatal` | The panic handler ran in phase `handoff` before `HANDOFF_READY` |
| `LOADER_PANIC` after `HANDOFF_READY` | `0004` / `fatal` | The panic handler ran in phase `handoff` during the final transfer transition |

Host automation uses exact records plus the exit protocol. Unrecognized prose and partial code names
never become acceptance evidence. A loader panic at `0002` is in phase `loader`; panics at `0003`
or `0004` are in phase `handoff`. The parser accepts each only from the corresponding protocol
state.

## QEMU exit classification

Reference QEMU is launched with an `isa-debug-exit` device using the documented 32-bit I/O boundary.
Writing guest value `g` causes the host process status `(g << 1) | 1`.

| Result | Guest write | Expected host status | Required marker relationship |
|---|---:|---:|---|
| Normal success | `0x10` | 33 | `KERNEL_READY` is present and no later fatal marker exists |
| Expected contract rejection | `0x20` | 65 | One of `ABI_VERSION`, `CONTRACT_LENGTH`, or `CONTRACT_INVALID` is present; `KERNEL_READY` is absent |
| Deliberate kernel panic | `0x21` | 67 | `KERNEL_PANIC` is present and `KERNEL_READY` is absent |
| Loader/entry failure | `0x22` | 69 | Kernel-entry records are absent; loader diagnostics provide bounded context where available. The assembly BSS-sentinel self-test can use this exit before safe diagnostics exist |
| Unexpected kernel return | `0x23` | 71 | The loader's non-return invariant was violated; this is always failure |

These non-zero host statuses are expected protocol values, not generic shell success. The harness
must decode the table before deciding pass/fail. A raw status of zero, a signal, an unknown status,
or a status/marker mismatch is an unexpected harness or guest failure.

The I/O write is privileged unsafe code. Its safe wrapper accepts only the enumerated result type;
callers cannot select an arbitrary port, width, or integer.

## Scenario expectations

`POLYTOPE/BOOT.CFG` contains exactly one supported ASCII token and newline:

| Token | Intended guest behavior | Passing host observation |
|---|---|---|
| `normal` | Construct and hand off an unmodified ABI 1.0 contract | `KERNEL_READY`, then guest `0x10` / host 33 |
| `bad-version` | Deliberately provide an incompatible contract version without changing unrelated bytes | `ABI_VERSION`, then guest `0x20` / host 65 |
| `truncated` | Supply a length smaller than the fixed ABI 1.0 contract | `CONTRACT_LENGTH`, then guest `0x20` / host 65 |
| `panic` | Validate the handoff and invoke the deliberate test panic before reporting normal readiness | `KERNEL_PANIC` without `KERNEL_READY`, then guest `0x21` / host 67 |

Malformed ELF, missing files, invalid `BOOT.CFG`, or a project-observed pre-transition allocation
failure is a loader failure (`0x22` / host 69), not an expected contract rejection. The pinned
`uefi-rs` boundary owns final-map acquisition and `ExitBootServices`: after at most two attempts it
cold-resets on allocation, map, or transition failure, so that dependency-owned path may emit no
project marker or debug-exit value. The harness consequently classifies the observed unexpected
exit or timeout; Sprint 02 does not claim executed fault injection for that firmware path. A
dedicated malformed-contract fixture may use `CONTRACT_INVALID` with the expected-rejection exit.

Scenario behavior is test control, not a privilege or recovery interface. Unknown tokens, whitespace,
extra lines, non-ASCII data, and oversized configuration must fail closed before kernel handoff.

## Timeout and hang handling

The host owns a hard monotonic deadline. If no recognized exit occurs before the deadline, it must
terminate the specific QEMU child, preserve bounded serial output, and classify the result as a
timeout/hang. It must not invent a guest exit code, retry until passing, or treat a partial marker as
success.

A test fixture should cover at least:

- deadline expiration with no output;
- a valid marker without an exit;
- an exit without the required marker;
- contradictory success and fatal markers;
- duplicate or out-of-order sequence values;
- malformed, overlong, non-ASCII, CRLF, and truncated records; and
- unrelated serial prose containing words such as “ready” or “panic.”

Retries may be used only for a classified external infrastructure error. They may not conceal guest
nondeterminism or a timeout.

## Data-handling and failure rules

Early diagnostics must not print:

- full firmware memory maps or arbitrary memory contents;
- cryptographic keys, credentials, update material, or host environment values;
- source/build paths, user names, or other host identity;
- kernel/contract bytes or unbounded file names; or
- unnecessary full physical addresses.

When a range or address is necessary to diagnose a developer build, prefer a stable region category,
checked length, and error code. Any optional detailed address mode must be compile-time/test-only,
explicitly requested, bounded, and excluded from public evidence artifacts.

Serial output is visible to the host and may be modified, dropped, or replayed. The host combines
markers with the QEMU process status and pinned launch configuration for test classification; none
of those mechanisms authenticates a release artifact.

## Versioning and change control

Changing the prefix, field order, schema, required codes, sequence semantics, maximum line length,
or exit values is a protocol change. Update this document, the host parser fixtures, guest tests,
QEMU launch configuration, and affected ADR/threat-model entries in one reviewed change. Never keep
an undocumented compatibility alias merely to make stale tests pass.
