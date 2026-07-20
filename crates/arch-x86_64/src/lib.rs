#![no_std]
#![doc = "Audited `x86_64` architecture mechanisms used during early `PolytopeOS` boot."]
#![cfg_attr(not(target_arch = "x86_64"), forbid(unsafe_code))]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use core::arch::asm;

    const COM1: u16 = 0x03f8;
    const DEBUGCON: u16 = 0x00e9;
    const QEMU_EXIT: u16 = 0x00f4;
    const TRANSMIT_READY: u8 = 0x20;
    const MAX_TRANSMIT_POLLS: usize = 4_096;

    /// Maximum number of bytes emitted by one early diagnostic record.
    pub const MAX_RECORD_BYTES: usize = 256;

    /// Guest values written to QEMU's `isa-debug-exit` device.
    ///
    /// QEMU turns a guest value into host status `(value << 1) | 1`.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u32)]
    pub enum QemuExitCode {
        /// Kernel boot completed successfully.
        Success = 0x10,
        /// The kernel rejected an invalid boot contract as expected.
        ContractRejected = 0x20,
        /// The deliberate or unexpected early panic path ran.
        KernelPanic = 0x21,
        /// The UEFI loader or architecture handoff failed.
        LoaderFailure = 0x22,
        /// Kernel entry unexpectedly returned to the handoff shim.
        KernelReturned = 0x23,
    }

    /// Allocation-free COM1 and QEMU debug-console writer.
    ///
    /// Construction initializes COM1 for 38,400 baud, 8-N-1 operation. Every
    /// byte is also sent to QEMU debugcon so boot tests remain observable when
    /// a UART is absent. UART polling is bounded; a stuck device drops its
    /// serial copy instead of hanging the kernel.
    #[derive(Debug, Default)]
    pub struct EarlyConsole {
        initialized: bool,
    }

    impl EarlyConsole {
        /// Creates and initializes the early console.
        #[must_use]
        pub fn new() -> Self {
            let mut console = Self { initialized: false };
            console.initialize();
            console
        }

        /// Emits one bounded diagnostic record followed by a newline.
        ///
        /// Records longer than [`MAX_RECORD_BYTES`] are deterministically
        /// truncated. The caller should use stable ASCII fields so the same
        /// line can be consumed by people and the boot-test harness.
        pub fn write_record(&mut self, record: &[u8]) {
            for &byte in record.iter().take(MAX_RECORD_BYTES) {
                self.write_byte(byte);
            }
            self.write_byte(b'\n');
        }

        #[allow(unsafe_code)]
        fn initialize(&mut self) {
            // SAFETY: These are the standard 16550 COM1 ports on the supported
            // QEMU x86_64 machine. The writes do not access memory, and early
            // boot is single-threaded before any other UART owner exists.
            unsafe {
                out_u8(COM1 + 1, 0x00);
                out_u8(COM1 + 3, 0x80);
                out_u8(COM1, 0x03);
                out_u8(COM1 + 1, 0x00);
                out_u8(COM1 + 3, 0x03);
                out_u8(COM1 + 2, 0xc7);
                out_u8(COM1 + 4, 0x0b);
            }
            self.initialized = true;
        }

        #[allow(unsafe_code)]
        fn write_byte(&mut self, byte: u8) {
            if !self.initialized {
                self.initialize();
            }

            if byte == b'\n' {
                Self::write_serial_byte(b'\r');
            }
            Self::write_serial_byte(byte);

            // SAFETY: Port 0xe9 is the configured QEMU debug-console byte
            // device. On unsupported physical hardware this write has no
            // memory-safety effect; real hardware is outside Sprint 02 scope.
            unsafe { out_u8(DEBUGCON, byte) };
        }

        #[allow(unsafe_code)]
        fn write_serial_byte(byte: u8) {
            for _ in 0..MAX_TRANSMIT_POLLS {
                // SAFETY: Reading the COM1 line-status register is an isolated
                // architecture I/O operation and does not dereference memory.
                if unsafe { in_u8(COM1 + 5) } & TRANSMIT_READY != 0 {
                    // SAFETY: The transmitter is ready and COM1 was initialized
                    // by this single-threaded console owner.
                    unsafe { out_u8(COM1, byte) };
                    return;
                }
                core::hint::spin_loop();
            }
        }
    }

    /// Terminates the supported QEMU guest with a deterministic outcome.
    ///
    /// If the debug-exit device is absent, interrupts are disabled and the CPU
    /// halts forever rather than executing an invalid continuation path.
    #[allow(unsafe_code)]
    pub fn qemu_exit(code: QemuExitCode) -> ! {
        // SAFETY: Port 0xf4 is reserved for the configured QEMU
        // `isa-debug-exit` device. A 32-bit write is the device's specified
        // interface and does not touch Rust-managed memory.
        unsafe { out_u32(QEMU_EXIT, code as u32) };
        loop {
            // SAFETY: This is the fail-closed terminal state if the emulator did
            // not terminate. No Rust references cross or outlive this block.
            unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
        }
    }

    #[inline]
    #[allow(unsafe_code)]
    unsafe fn out_u8(port: u16, value: u8) {
        // SAFETY: Callers establish that the port and access width belong to
        // the architecture device they are controlling.
        unsafe {
            asm!(
                "out dx, al",
                in("dx") port,
                in("al") value,
                options(nomem, nostack, preserves_flags)
            );
        }
    }

    #[inline]
    #[allow(unsafe_code)]
    unsafe fn out_u32(port: u16, value: u32) {
        // SAFETY: Callers establish that the port and access width belong to
        // the architecture device they are controlling.
        unsafe {
            asm!(
                "out dx, eax",
                in("dx") port,
                in("eax") value,
                options(nomem, nostack, preserves_flags)
            );
        }
    }

    #[inline]
    #[allow(unsafe_code)]
    unsafe fn in_u8(port: u16) -> u8 {
        let value: u8;
        // SAFETY: Callers establish that the port and access width belong to
        // the architecture device they are controlling.
        unsafe {
            asm!(
                "in al, dx",
                in("dx") port,
                out("al") value,
                options(nomem, nostack, preserves_flags)
            );
        }
        value
    }
}

#[cfg(target_arch = "x86_64")]
pub use x86_64::{EarlyConsole, MAX_RECORD_BYTES, QemuExitCode, qemu_exit};
