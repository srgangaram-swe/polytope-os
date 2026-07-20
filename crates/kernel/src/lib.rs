#![no_std]
#![doc = "Architecture-independent `PolytopeOS` kernel foundations."]

/// Allocation-free records emitted during the earliest kernel phases.
pub mod diagnostics;

/// Ordered phases of a kernel boot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootPhase {
    /// No architecture state has been established.
    Reset,
    /// Minimal CPU and memory state is available.
    EarlyArchitecture,
    /// Physical and virtual memory managers are available.
    MemoryReady,
    /// The scheduler and core services may start.
    RuntimeReady,
}

/// Errors produced by invalid boot transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootError {
    /// The requested phase does not immediately follow the current phase.
    InvalidTransition {
        /// Phase active when the transition was requested.
        from: BootPhase,
        /// Rejected destination phase.
        to: BootPhase,
    },
}

/// Explicit boot state machine; skipped or repeated initialization is rejected.
#[derive(Debug)]
pub struct BootState {
    phase: BootPhase,
}

impl BootState {
    /// Creates a reset-state kernel.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            phase: BootPhase::Reset,
        }
    }

    /// Returns the current initialization phase.
    #[must_use]
    pub const fn phase(&self) -> BootPhase {
        self.phase
    }

    /// Advances exactly one phase, failing closed for invalid ordering.
    ///
    /// # Errors
    ///
    /// Returns [`BootError::InvalidTransition`] when `next` is not the immediate
    /// successor of the current phase.
    pub fn transition(&mut self, next: BootPhase) -> Result<(), BootError> {
        let valid = matches!(
            (self.phase, next),
            (BootPhase::Reset, BootPhase::EarlyArchitecture)
                | (BootPhase::EarlyArchitecture, BootPhase::MemoryReady)
                | (BootPhase::MemoryReady, BootPhase::RuntimeReady)
        );
        if !valid {
            return Err(BootError::InvalidTransition {
                from: self.phase,
                to: next,
            });
        }
        self.phase = next;
        Ok(())
    }
}

impl Default for BootState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{BootError, BootPhase, BootState};

    #[test]
    fn boot_requires_ordered_transitions() {
        let mut state = BootState::new();
        assert_eq!(
            state.transition(BootPhase::MemoryReady),
            Err(BootError::InvalidTransition {
                from: BootPhase::Reset,
                to: BootPhase::MemoryReady,
            })
        );
        state.transition(BootPhase::EarlyArchitecture).unwrap();
        state.transition(BootPhase::MemoryReady).unwrap();
        state.transition(BootPhase::RuntimeReady).unwrap();
        assert_eq!(state.phase(), BootPhase::RuntimeReady);
    }
}
