#![no_std]
#![forbid(unsafe_code)]
#![doc = "Safe policy shared by the `PolytopeOS` UEFI loader and host tests."]

/// Maximum accepted size of the boot-test scenario configuration.
pub const MAX_SCENARIO_BYTES: usize = 32;

/// Controlled Sprint 02 boot paths.
///
/// Non-normal values exist solely to exercise kernel rejection and panic
/// behavior in deterministic QEMU integration tests. They do not bypass ELF
/// or firmware validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootScenario {
    /// A valid boot contract reaches the kernel-ready marker.
    Normal,
    /// The loader supplies an unsupported boot-contract major version.
    IncompatibleVersion,
    /// The loader supplies a length one byte shorter than the contract.
    TruncatedContract,
    /// A valid contract asks the kernel to exercise its panic path.
    DeliberatePanic,
}

impl BootScenario {
    /// Parses the complete bounded contents of `POLYTOPE/BOOT.CFG`.
    ///
    /// The file must contain exactly one supported ASCII token followed by one
    /// newline. Unknown, empty, non-canonical, non-ASCII, and oversized values
    /// fail closed.
    ///
    /// # Errors
    ///
    /// Returns a classified [`ScenarioError`] for malformed or unsupported
    /// input.
    pub fn parse(bytes: &[u8]) -> Result<Self, ScenarioError> {
        if bytes.len() > MAX_SCENARIO_BYTES {
            return Err(ScenarioError::TooLong);
        }
        if !bytes.is_ascii() {
            return Err(ScenarioError::NonAscii);
        }

        match bytes {
            b"normal\n" => Ok(Self::Normal),
            b"bad-version\n" => Ok(Self::IncompatibleVersion),
            b"truncated\n" => Ok(Self::TruncatedContract),
            b"panic\n" => Ok(Self::DeliberatePanic),
            [] => Err(ScenarioError::Empty),
            _ => Err(ScenarioError::Unknown),
        }
    }
}

/// Classified boot-scenario configuration failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScenarioError {
    /// The configuration contained no token.
    Empty,
    /// The configuration exceeded [`MAX_SCENARIO_BYTES`].
    TooLong,
    /// The configuration contained a non-ASCII byte.
    NonAscii,
    /// The token was well formed but unsupported.
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::{BootScenario, MAX_SCENARIO_BYTES, ScenarioError};

    #[test]
    fn parses_every_supported_scenario() {
        assert_eq!(BootScenario::parse(b"normal\n"), Ok(BootScenario::Normal));
        assert_eq!(
            BootScenario::parse(b"bad-version\n"),
            Ok(BootScenario::IncompatibleVersion)
        );
        assert_eq!(
            BootScenario::parse(b"truncated\n"),
            Ok(BootScenario::TruncatedContract)
        );
        assert_eq!(
            BootScenario::parse(b"panic\n"),
            Ok(BootScenario::DeliberatePanic)
        );
    }

    #[test]
    fn rejects_untrusted_configuration_failures() {
        assert_eq!(BootScenario::parse(b""), Err(ScenarioError::Empty));
        assert_eq!(
            BootScenario::parse(b"surprise"),
            Err(ScenarioError::Unknown)
        );
        assert_eq!(BootScenario::parse(b"normal"), Err(ScenarioError::Unknown));
        assert_eq!(
            BootScenario::parse(b" normal\n"),
            Err(ScenarioError::Unknown)
        );
        assert_eq!(BootScenario::parse(b"panic\0"), Err(ScenarioError::Unknown));
        assert_eq!(BootScenario::parse(&[0xff]), Err(ScenarioError::NonAscii));
        assert_eq!(
            BootScenario::parse(&[b'a'; MAX_SCENARIO_BYTES + 1]),
            Err(ScenarioError::TooLong)
        );
    }
}
