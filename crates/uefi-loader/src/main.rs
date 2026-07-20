#![no_std]
#![no_main]
#![doc = "`PolytopeOS` `x86_64` UEFI loader executable."]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec::Vec;
use core::arch::asm;
use core::mem;
use core::panic::PanicInfo;
use core::ptr::{self, NonNull};
use core::slice;
use core::sync::atomic::{AtomicU8, Ordering};

use polytope_arch_x86_64::{EarlyConsole, QemuExitCode, qemu_exit};
use polytope_boot_contract::{
    BOOT_INFO_SIZE, BootInfo, MemoryKind, MemoryRegion, PlatformInfo, ScenarioInfo, ScenarioKind,
};
use polytope_boot_elf::{
    LoadSegment, MAX_ELF_FILE_SIZE, STACK_GUARD_ADDRESS, ValidatedElf, parse as parse_elf,
};
use polytope_boot_uefi::{BootScenario, MAX_SCENARIO_BYTES};
use uefi::CStr16;
use uefi::boot::{self, AllocateType, MemoryDescriptor, MemoryType};
use uefi::mem::memory_map::{MemoryMap, MemoryMapMut};
use uefi::prelude::*;
use uefi::proto::media::file::{Directory, File, FileAttribute, FileMode};

const PAGE_BYTES: usize = 4_096;
const FILE_READ_CHUNK_BYTES: usize = 64 * 1_024;
const KERNEL_MEMORY_TYPE: MemoryType = MemoryType(0x8000_0000);
const CONTRACT_MEMORY_TYPE: MemoryType = MemoryType(0x8000_0001);
const STACK_GUARD_MEMORY_TYPE: MemoryType = MemoryType(0x8000_0002);

const LOADER_START: &[u8] =
    b"POLYTOPE_BOOT schema=1 seq=0001 phase=loader level=info code=LOADER_START";
const ELF_VALID: &[u8] = b"POLYTOPE_BOOT schema=1 seq=0002 phase=loader level=info code=ELF_VALID";
const HANDOFF_READY: &[u8] =
    b"POLYTOPE_BOOT schema=1 seq=0003 phase=handoff level=info code=HANDOFF_READY";
const FILE_READ_FAILURE: &[u8] =
    b"POLYTOPE_BOOT schema=1 seq=0002 phase=loader level=error code=FILE_READ";
const CONFIG_INVALID_FAILURE: &[u8] =
    b"POLYTOPE_BOOT schema=1 seq=0002 phase=loader level=error code=CONFIG_INVALID";
const ELF_INVALID_FAILURE: &[u8] =
    b"POLYTOPE_BOOT schema=1 seq=0002 phase=loader level=error code=ELF_INVALID";
const ALLOCATION_FAILURE: &[u8] =
    b"POLYTOPE_BOOT schema=1 seq=0002 phase=loader level=error code=ALLOCATION";
const KERNEL_ADDRESS_FAILURE: &[u8] =
    b"POLYTOPE_BOOT schema=1 seq=0002 phase=loader level=error code=KERNEL_ADDRESS";
const CONTRACT_STORAGE_FAILURE: &[u8] =
    b"POLYTOPE_BOOT schema=1 seq=0002 phase=loader level=error code=CONTRACT_STORAGE";
const CONTRACT_FAILURE: &[u8] =
    b"POLYTOPE_BOOT schema=1 seq=0003 phase=handoff level=error code=CONTRACT_BUILD";
const LOADER_PANIC_SEQUENCE_2: &[u8] =
    b"POLYTOPE_BOOT schema=1 seq=0002 phase=loader level=fatal code=LOADER_PANIC";
const LOADER_PANIC_SEQUENCE_3: &[u8] =
    b"POLYTOPE_BOOT schema=1 seq=0003 phase=handoff level=fatal code=LOADER_PANIC";
const LOADER_PANIC_SEQUENCE_4: &[u8] =
    b"POLYTOPE_BOOT schema=1 seq=0004 phase=handoff level=fatal code=LOADER_PANIC";

static NEXT_PANIC_SEQUENCE: AtomicU8 = AtomicU8::new(2);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoaderError {
    FileRead,
    ConfigInvalid,
    ElfInvalid,
    Allocation,
    KernelAddress,
    ContractStorage,
    Contract,
}

impl LoaderError {
    const fn marker(self) -> &'static [u8] {
        match self {
            Self::FileRead => FILE_READ_FAILURE,
            Self::ConfigInvalid => CONFIG_INVALID_FAILURE,
            Self::ElfInvalid => ELF_INVALID_FAILURE,
            Self::Allocation => ALLOCATION_FAILURE,
            Self::KernelAddress => KERNEL_ADDRESS_FAILURE,
            Self::ContractStorage => CONTRACT_STORAGE_FAILURE,
            Self::Contract => CONTRACT_FAILURE,
        }
    }
}

#[entry]
#[allow(unsafe_code)]
fn main() -> Status {
    let mut console = EarlyConsole::new();
    console.write_record(LOADER_START);

    let (entry_point, mut contract_storage, scenario) = match prepare_kernel() {
        Ok(prepared) => prepared,
        Err(error) => fail(&mut console, error),
    };
    console.write_record(ELF_VALID);
    NEXT_PANIC_SEQUENCE.store(3, Ordering::SeqCst);

    // SAFETY: All firmware protocols, file handles, and allocator-backed
    // buffers are confined to `prepare_kernel` and have been dropped. The only
    // retained values are physical page allocations, integers, and the test
    // scenario. `uefi-rs` obtains a fresh memory map, makes at most two
    // ExitBootServices attempts, cold-resets on terminal failure, and disables
    // its boot-services-backed helpers before returning successfully.
    let mut memory_map = unsafe { boot::exit_boot_services(None) };
    memory_map.sort();

    let contract_length = match encode_contract(&memory_map, &mut contract_storage, scenario) {
        Ok(length) => length,
        Err(error) => fail(&mut console, error),
    };
    console.write_record(HANDOFF_READY);
    NEXT_PANIC_SEQUENCE.store(4, Ordering::SeqCst);

    let contract_address = contract_storage.as_ptr();
    mem::forget(memory_map);

    // SAFETY: The safe ELF parser proved the entry is inside a loaded,
    // executable, identity-mapped x86_64 segment. The contract allocation is
    // page aligned, initialized for `contract_length` readable bytes, retained
    // after ExitBootServices, and passed using the documented SysV64 ABI. The
    // entry shim is non-returning and establishes its own kernel stack before
    // safe Rust executes.
    unsafe { transfer_to_kernel(entry_point, contract_address, contract_length) }
}

#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
    let mut console = EarlyConsole::new();
    let marker = match NEXT_PANIC_SEQUENCE.load(Ordering::SeqCst) {
        2 => LOADER_PANIC_SEQUENCE_2,
        3 => LOADER_PANIC_SEQUENCE_3,
        _ => LOADER_PANIC_SEQUENCE_4,
    };
    console.write_record(marker);
    qemu_exit(QemuExitCode::LoaderFailure)
}

fn prepare_kernel() -> Result<(u64, ContractStorage, BootScenario), LoaderError> {
    let (kernel, scenario) = {
        let mut protocol =
            boot::get_image_file_system(boot::image_handle()).map_err(|_| LoaderError::FileRead)?;
        let mut root = protocol.open_volume().map_err(|_| LoaderError::FileRead)?;
        let kernel = read_bounded_file(
            &mut root,
            cstr16!(r"\POLYTOPE\KERNEL.ELF"),
            MAX_ELF_FILE_SIZE,
            LoaderError::ElfInvalid,
        )?;
        let scenario_bytes = read_bounded_file(
            &mut root,
            cstr16!(r"\POLYTOPE\BOOT.CFG"),
            MAX_SCENARIO_BYTES,
            LoaderError::ConfigInvalid,
        )?;
        let scenario =
            BootScenario::parse(&scenario_bytes).map_err(|_| LoaderError::ConfigInvalid)?;
        (kernel, scenario)
    };

    let elf = parse_elf(&kernel).map_err(|_| LoaderError::ElfInvalid)?;
    load_segments(elf)?;
    reserve_stack_guard()?;
    let entry_point = elf.entry_point();
    let contract_storage = ContractStorage::allocate()?;

    // Drop every boot-services allocator user before ExitBootServices.
    drop(kernel);
    Ok((entry_point, contract_storage, scenario))
}

fn read_bounded_file(
    root: &mut Directory,
    path: &CStr16,
    maximum: usize,
    limit_error: LoaderError,
) -> Result<Vec<u8>, LoaderError> {
    let handle = root
        .open(path, FileMode::Read, FileAttribute::empty())
        .map_err(|_| LoaderError::FileRead)?;
    let mut file = handle.into_regular_file().ok_or(LoaderError::FileRead)?;
    let chunk_length = maximum.clamp(1, FILE_READ_CHUNK_BYTES);
    let mut chunk = Vec::new();
    chunk
        .try_reserve_exact(chunk_length)
        .map_err(|_| LoaderError::Allocation)?;
    chunk.resize(chunk_length, 0);
    let mut bytes = Vec::new();

    loop {
        let count = file.read(&mut chunk).map_err(|_| LoaderError::FileRead)?;
        if count == 0 {
            break;
        }
        let new_length = bytes.len().checked_add(count).ok_or(limit_error)?;
        if new_length > maximum {
            return Err(limit_error);
        }
        bytes
            .try_reserve_exact(count)
            .map_err(|_| LoaderError::Allocation)?;
        bytes.extend_from_slice(&chunk[..count]);
    }
    Ok(bytes)
}

fn reserve_stack_guard() -> Result<(), LoaderError> {
    let allocation = boot::allocate_pages(
        AllocateType::Address(STACK_GUARD_ADDRESS),
        STACK_GUARD_MEMORY_TYPE,
        1,
    )
    .map_err(|_| LoaderError::KernelAddress)?;
    if allocation.as_ptr() as u64 != STACK_GUARD_ADDRESS {
        return Err(LoaderError::KernelAddress);
    }
    Ok(())
}

fn load_segments(elf: ValidatedElf<'_>) -> Result<(), LoaderError> {
    for segment in elf.segments() {
        load_segment(segment)?;
    }
    Ok(())
}

#[allow(unsafe_code)]
fn load_segment(segment: LoadSegment<'_>) -> Result<(), LoaderError> {
    let destination =
        usize::try_from(segment.physical_address()).map_err(|_| LoaderError::KernelAddress)?;
    let memory_size =
        usize::try_from(segment.memory_size()).map_err(|_| LoaderError::Allocation)?;
    let pages = memory_size.div_ceil(PAGE_BYTES);
    let allocation = boot::allocate_pages(
        AllocateType::Address(segment.physical_address()),
        KERNEL_MEMORY_TYPE,
        pages,
    )
    .map_err(|_| LoaderError::KernelAddress)?;
    if allocation.as_ptr() as usize != destination {
        return Err(LoaderError::KernelAddress);
    }
    let allocation_bytes = pages
        .checked_mul(PAGE_BYTES)
        .ok_or(LoaderError::Allocation)?;

    // SAFETY: `parse_elf` established a nonempty, bounded, page-aligned,
    // nonoverlapping load plan and file_data <= memory_size. UEFI allocated
    // exactly `pages` writable pages at this physical address using a
    // project-specific loader memory type. The source slice is live and cannot
    // overlap the fixed destination window. Zeroing the complete allocation
    // canonicalizes BSS and page padding before copying initialized bytes.
    unsafe {
        ptr::write_bytes(allocation.as_ptr(), 0, allocation_bytes);
        ptr::copy_nonoverlapping(
            segment.file_data().as_ptr(),
            allocation.as_ptr(),
            segment.file_data().len(),
        );
    }
    Ok(())
}

fn encode_contract(
    memory_map: &impl MemoryMap,
    storage: &mut ContractStorage,
    scenario: BootScenario,
) -> Result<usize, LoaderError> {
    let scenario_info = match scenario {
        BootScenario::Normal => ScenarioInfo::normal(),
        BootScenario::IncompatibleVersion => {
            ScenarioInfo::test(ScenarioKind::INCOMPATIBLE_VERSION, 0)
        }
        BootScenario::TruncatedContract => ScenarioInfo::test(ScenarioKind::MALFORMED_METADATA, 0),
        BootScenario::DeliberatePanic => ScenarioInfo::test(ScenarioKind::DELIBERATE_PANIC, 0),
    };
    let mut info = BootInfo::new(PlatformInfo::x86_64_uefi(0), scenario_info);
    let mut region_index = 0_usize;
    for descriptor in memory_map.entries() {
        if descriptor.page_count == 0 {
            continue;
        }
        let length = descriptor
            .page_count
            .checked_mul(polytope_boot_contract::PAGE_SIZE)
            .ok_or(LoaderError::Contract)?;
        let region = MemoryRegion::new(
            descriptor.phys_start,
            length,
            normalize_memory_kind(descriptor),
            descriptor.ty.0,
            descriptor.att.bits(),
        );
        info.set_memory_region(region_index, region)
            .map_err(|_| LoaderError::Contract)?;
        region_index = region_index.checked_add(1).ok_or(LoaderError::Contract)?;
    }

    let output = storage.as_mut_bytes();
    output.fill(0);
    let encoded = info.encode(output).map_err(|_| LoaderError::Contract)?;

    if scenario == BootScenario::IncompatibleVersion {
        let version = polytope_boot_contract::ABI_MAJOR_OFFSET;
        output[version..version + 2]
            .copy_from_slice(&(polytope_boot_contract::ABI_MAJOR + 1).to_le_bytes());
    }
    if scenario == BootScenario::TruncatedContract {
        return encoded.checked_sub(1).ok_or(LoaderError::Contract);
    }
    Ok(encoded)
}

/// Unique, retained pages reserved for the encoded boot contract.
///
/// The type intentionally has no `Drop` implementation: its pages cross
/// `ExitBootServices` and become kernel-owned through the boot contract.
#[derive(Debug)]
struct ContractStorage {
    base: NonNull<u8>,
    byte_length: usize,
}

impl ContractStorage {
    fn allocate() -> Result<Self, LoaderError> {
        let pages = BOOT_INFO_SIZE.div_ceil(PAGE_BYTES);
        let byte_length = pages
            .checked_mul(PAGE_BYTES)
            .ok_or(LoaderError::ContractStorage)?;
        let base = boot::allocate_pages(AllocateType::AnyPages, CONTRACT_MEMORY_TYPE, pages)
            .map_err(|_| LoaderError::ContractStorage)?;
        Ok(Self { base, byte_length })
    }

    #[allow(unsafe_code)]
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        // SAFETY: The private constructor exclusively acquires `byte_length`
        // writable pages at `base`. The allocation is retained, this mutable
        // borrow is tied to the unique storage token, and no alias is exposed
        // until encoding completes and the immutable pointer is transferred.
        unsafe { slice::from_raw_parts_mut(self.base.as_ptr(), self.byte_length) }
    }

    const fn as_ptr(&self) -> *const u8 {
        self.base.as_ptr().cast_const()
    }
}

fn normalize_memory_kind(descriptor: &MemoryDescriptor) -> MemoryKind {
    if descriptor.ty == STACK_GUARD_MEMORY_TYPE {
        return MemoryKind::RESERVED;
    }
    match descriptor.ty {
        KERNEL_MEMORY_TYPE => MemoryKind::KERNEL_IMAGE,
        CONTRACT_MEMORY_TYPE => MemoryKind::BOOT_CONTRACT,
        MemoryType::CONVENTIONAL => MemoryKind::USABLE,
        MemoryType::LOADER_CODE
        | MemoryType::LOADER_DATA
        | MemoryType::BOOT_SERVICES_CODE
        | MemoryType::BOOT_SERVICES_DATA => MemoryKind::RECLAIMABLE,
        MemoryType::RUNTIME_SERVICES_CODE | MemoryType::RUNTIME_SERVICES_DATA => {
            MemoryKind::FIRMWARE_RUNTIME
        }
        MemoryType::ACPI_RECLAIM => MemoryKind::ACPI_RECLAIMABLE,
        MemoryType::ACPI_NON_VOLATILE => MemoryKind::ACPI_NVS,
        MemoryType::MMIO | MemoryType::MMIO_PORT_SPACE => MemoryKind::MMIO,
        _ => MemoryKind::RESERVED,
    }
}

fn fail(console: &mut EarlyConsole, error: LoaderError) -> ! {
    console.write_record(error.marker());
    qemu_exit(QemuExitCode::LoaderFailure)
}

#[allow(unsafe_code)]
unsafe fn transfer_to_kernel(entry_point: u64, contract: *const u8, length: usize) -> ! {
    type Entry = unsafe extern "sysv64" fn(*const u8, usize) -> !;
    let address = usize::try_from(entry_point).unwrap_or_else(|_| {
        let mut console = EarlyConsole::new();
        fail(&mut console, LoaderError::ElfInvalid)
    });
    // SAFETY: `entry_point` was validated as an x86_64 executable-segment
    // address and loaded at that exact identity-mapped address. Function and
    // data pointers have equal width on the supported target.
    let entry: Entry = unsafe { mem::transmute(address) };
    // SAFETY: The SysV ABI requires the direction flag to be clear; this has no
    // memory operand or stack effect and is repeated by kernel entry.
    unsafe { asm!("cld", options(nomem, nostack)) };
    // SAFETY: The caller established the validated entry, live immutable
    // contract allocation, exact bounded length, and non-returning ABI.
    unsafe { entry(contract, length) }
}

// Compile-time guard: the fixed contract requires at least two pages today.
const _: () = assert!(BOOT_INFO_SIZE > PAGE_BYTES && BOOT_INFO_SIZE <= 2 * PAGE_BYTES);
