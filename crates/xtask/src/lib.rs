#![forbid(unsafe_code)]
#![doc = "Deterministic host tooling for `PolytopeOS` images and boot validation."]

pub mod image;
pub mod inspect;
pub mod qemu;
pub mod repro;

mod temporary;

use sha2::{Digest, Sha256};

/// Returns the lowercase SHA-256 digest of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Describes the first byte at which two artifacts differ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteDifference {
    /// Zero-based byte offset.
    pub offset: usize,
    /// Byte from the first artifact, or `None` when it ended first.
    pub left: Option<u8>,
    /// Byte from the second artifact, or `None` when it ended first.
    pub right: Option<u8>,
}

/// Returns the first difference between two byte sequences.
#[must_use]
pub fn first_difference(left: &[u8], right: &[u8]) -> Option<ByteDifference> {
    if let Some((offset, (&left_byte, &right_byte))) = left
        .iter()
        .zip(right)
        .enumerate()
        .find(|(_, (left_byte, right_byte))| left_byte != right_byte)
    {
        return Some(ByteDifference {
            offset,
            left: Some(left_byte),
            right: Some(right_byte),
        });
    }

    (left.len() != right.len()).then(|| {
        let offset = left.len().min(right.len());
        ByteDifference {
            offset,
            left: left.get(offset).copied(),
            right: right.get(offset).copied(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{ByteDifference, first_difference, sha256_hex};

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"polytope"),
            "66d398029d99fef7102b51531e1426d08b29adf78e66e795937b3929f59403e5"
        );
    }

    #[test]
    fn first_difference_reports_changed_and_missing_bytes() {
        assert_eq!(first_difference(b"same", b"same"), None);
        assert_eq!(
            first_difference(b"left", b"leXt"),
            Some(ByteDifference {
                offset: 2,
                left: Some(b'f'),
                right: Some(b'X'),
            })
        );
        assert_eq!(
            first_difference(b"short", b"shorter"),
            Some(ByteDifference {
                offset: 5,
                left: None,
                right: Some(b'e'),
            })
        );
    }
}
