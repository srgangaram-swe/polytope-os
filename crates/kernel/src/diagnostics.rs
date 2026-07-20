//! Stable, allocation-free early-boot diagnostic records.

/// Schema identifier shared with the QEMU harness.
pub const DIAGNOSTIC_SCHEMA: u16 = 1;

/// Kernel-ready marker for a valid handoff.
pub const KERNEL_READY: &[u8] =
    b"POLYTOPE_BOOT schema=1 seq=0004 phase=kernel_entry level=info code=KERNEL_READY";

/// Kernel rejection marker for an unsupported contract ABI.
pub const ABI_VERSION_REJECTED: &[u8] =
    b"POLYTOPE_BOOT schema=1 seq=0004 phase=kernel_entry level=error code=ABI_VERSION";

/// Kernel rejection marker for a truncated contract.
pub const CONTRACT_LENGTH_REJECTED: &[u8] =
    b"POLYTOPE_BOOT schema=1 seq=0004 phase=kernel_entry level=error code=CONTRACT_LENGTH";

/// Kernel rejection marker for any other malformed contract.
pub const CONTRACT_INVALID: &[u8] =
    b"POLYTOPE_BOOT schema=1 seq=0004 phase=kernel_entry level=error code=CONTRACT_INVALID";

/// Deliberate or unexpected early-kernel panic marker.
pub const KERNEL_PANIC: &[u8] =
    b"POLYTOPE_BOOT schema=1 seq=0005 phase=panic level=fatal code=KERNEL_PANIC";

#[cfg(test)]
mod tests {
    use super::{
        ABI_VERSION_REJECTED, CONTRACT_INVALID, CONTRACT_LENGTH_REJECTED, DIAGNOSTIC_SCHEMA,
        KERNEL_PANIC, KERNEL_READY,
    };

    #[test]
    fn automation_markers_are_ascii_single_line_and_bounded() {
        for marker in [
            KERNEL_READY,
            ABI_VERSION_REJECTED,
            CONTRACT_LENGTH_REJECTED,
            CONTRACT_INVALID,
            KERNEL_PANIC,
        ] {
            assert!(marker.is_ascii());
            assert!(!marker.contains(&b'\n'));
            assert!(marker.len() <= 256);
            assert!(marker.starts_with(b"POLYTOPE_BOOT schema=1 "));
        }
        assert_eq!(DIAGNOSTIC_SCHEMA, 1);
    }
}
