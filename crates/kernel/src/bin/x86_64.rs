#![no_std]
#![no_main]
#![doc = "Freestanding `x86_64` `PolytopeOS` kernel entry image."]
#![deny(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;
use core::slice;

use polytope_arch_x86_64::{EarlyConsole, QemuExitCode, qemu_exit};
use polytope_boot_contract::{
    BOOT_INFO_SIZE, PAGE_SIZE_BYTES, ScenarioKind, ValidationError, parse,
};
use polytope_kernel::diagnostics::{
    ABI_VERSION_REJECTED, CONTRACT_INVALID, CONTRACT_LENGTH_REJECTED, KERNEL_PANIC, KERNEL_READY,
};

#[allow(unsafe_code)]
mod entry_assembly {
    use core::arch::global_asm;

    global_asm!(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../arch/x86_64/boot/entry.S"
        )),
        options(att_syntax)
    );
}

/// Safe-Rust destination of the `x86_64` assembly entry shim.
///
/// The assembly boundary supplies the contract allocation's raw pointer and
/// exact byte length using the System V AMD64 ABI. This function validates the
/// outer range before constructing a slice and then delegates all format and
/// semantic checks to the safe boot-contract parser.
///
/// # Safety
///
/// `contract` must identify `length` bytes of readable, exclusively retained
/// boot-contract storage for the entire non-returning call. The caller must
/// have exited boot services and established the entry state documented in
/// `arch/x86_64/boot/entry.S`.
///
/// # Panics
///
/// Panics only when the validated contract selects the explicit, test-only
/// deliberate-panic scenario; the allocation-free panic handler terminates
/// QEMU with the documented failure code.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "sysv64" fn polytope_kernel_main(contract: *const u8, length: usize) -> ! {
    let mut console = EarlyConsole::new();

    if length != BOOT_INFO_SIZE {
        console.write_record(CONTRACT_LENGTH_REJECTED);
        qemu_exit(QemuExitCode::ContractRejected);
    }
    let address = contract as usize;
    if contract.is_null() || address % PAGE_SIZE_BYTES != 0 || address.checked_add(length).is_none()
    {
        console.write_record(CONTRACT_INVALID);
        qemu_exit(QemuExitCode::ContractRejected);
    }

    // SAFETY: The UEFI loader allocated and retained `length` readable bytes
    // at this page-aligned address, encoded the contract there, exited boot
    // services without releasing it, and transferred its exact pointer/length
    // under ADR 0004. The checks above prevent null, misaligned, overflowing,
    // or non-version-sized ranges. No mutable reference to this storage is
    // created in the kernel.
    let bytes = unsafe { slice::from_raw_parts(contract, length) };
    let boot_info = match parse(bytes) {
        Ok(info) => info,
        Err(ValidationError::UnsupportedVersion { .. }) => {
            console.write_record(ABI_VERSION_REJECTED);
            qemu_exit(QemuExitCode::ContractRejected);
        }
        Err(ValidationError::Truncated { .. } | ValidationError::LengthMismatch { .. }) => {
            console.write_record(CONTRACT_LENGTH_REJECTED);
            qemu_exit(QemuExitCode::ContractRejected);
        }
        Err(_) => {
            console.write_record(CONTRACT_INVALID);
            qemu_exit(QemuExitCode::ContractRejected);
        }
    };

    match boot_info.as_ref().scenario.kind {
        ScenarioKind::NORMAL => {
            console.write_record(KERNEL_READY);
            qemu_exit(QemuExitCode::Success);
        }
        ScenarioKind::DELIBERATE_PANIC => panic!("deliberate Sprint 02 early-panic test"),
        _ => {
            console.write_record(CONTRACT_INVALID);
            qemu_exit(QemuExitCode::ContractRejected);
        }
    }
}

#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
    let mut console = EarlyConsole::new();
    console.write_record(KERNEL_PANIC);
    qemu_exit(QemuExitCode::KernelPanic)
}
