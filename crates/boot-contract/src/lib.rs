#![no_std]
#![forbid(unsafe_code)]
#![doc = "A bounded, versioned loader-to-kernel ABI for `PolytopeOS`."]
//!
//! Architecture code receives the handoff as a raw address and an exact byte
//! length. That boundary must first establish that the range is readable and
//! create a byte slice. [`prevalidate`] and [`parse`] can then validate the
//! bytes without casting or dereferencing ABI fields. No unsafe operation is
//! required by this crate.

use core::mem::{align_of, offset_of, size_of};

/// Boot-contract magic encoded at the start of every handoff.
pub const BOOT_MAGIC: [u8; 8] = *b"POLYBOOT";
/// Supported boot-contract major version.
pub const ABI_MAJOR: u16 = 1;
/// Supported boot-contract minor version.
pub const ABI_MINOR: u16 = 0;
/// `x86_64` page size required by all memory-region boundaries.
pub const PAGE_SIZE: u64 = 4_096;
/// Host-pointer representation of [`PAGE_SIZE`] for checked alignment logic.
pub const PAGE_SIZE_BYTES: usize = 4_096;
/// Maximum number of normalized memory regions in a handoff.
pub const MAX_MEMORY_REGIONS: usize = 128;
/// Serialized size of [`BootHeader`].
pub const BOOT_HEADER_SIZE: usize = 32;
/// Serialized size of one [`MemoryRegion`].
pub const MEMORY_REGION_SIZE: usize = 32;
/// Exact serialized size of the current [`BootInfo`] ABI.
pub const BOOT_INFO_SIZE: usize = size_of::<BootInfo>();
/// Byte offset of `abi_major`, used only by deliberate corruption tests.
pub const ABI_MAJOR_OFFSET: usize =
    offset_of!(BootInfo, header) + offset_of!(BootHeader, abi_major);
/// Byte offset of `total_size`, used only by deliberate truncation tests.
pub const TOTAL_SIZE_OFFSET: usize =
    offset_of!(BootInfo, header) + offset_of!(BootHeader, total_size);

const KNOWN_HEADER_FLAGS: u32 = 0;
const BOOT_HEADER_SIZE_U32: u32 = 32;
const BOOT_INFO_SIZE_U32: u32 = 4_176;
const MEMORY_REGION_SIZE_U32: u32 = 32;
const MAX_MEMORY_REGIONS_U32: u32 = 128;
const PLATFORM_FLAG_RSDP_PRESENT: u64 = 1;
const KNOWN_PLATFORM_FLAGS: u64 = PLATFORM_FLAG_RSDP_PRESENT;
const SCENARIO_FLAG_TEST_ONLY: u32 = 1;
const KNOWN_SCENARIO_FLAGS: u32 = SCENARIO_FLAG_TEST_ONLY;
const MIN_RSDP_LENGTH: u32 = 20;
const MAX_RSDP_LENGTH: u32 = 4_096;

/// Fixed header common to every boot-contract version 1 handoff.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootHeader {
    /// Constant [`BOOT_MAGIC`] signature.
    pub magic: [u8; 8],
    /// Incompatible ABI changes increment this value.
    pub abi_major: u16,
    /// Backward-compatible ABI changes increment this value.
    pub abi_minor: u16,
    /// Size of this header in bytes.
    pub header_size: u32,
    /// Exact byte length supplied to the kernel.
    pub total_size: u32,
    /// Size of each memory-region entry.
    pub memory_region_size: u32,
    /// Number of initialized entries in the bounded region array.
    pub memory_region_count: u32,
    /// Reserved ABI flags. Unknown bits are rejected.
    pub flags: u32,
}

impl BootHeader {
    const fn current() -> Self {
        Self {
            magic: BOOT_MAGIC,
            abi_major: ABI_MAJOR,
            abi_minor: ABI_MINOR,
            header_size: BOOT_HEADER_SIZE_U32,
            total_size: BOOT_INFO_SIZE_U32,
            memory_region_size: MEMORY_REGION_SIZE_U32,
            memory_region_count: 0,
            flags: 0,
        }
    }
}

/// Firmware environment identifier with stable `u32` representation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirmwareKind(pub u32);

impl FirmwareKind {
    /// UEFI firmware.
    pub const UEFI: Self = Self(1);
}

/// Processor architecture identifier with stable `u32` representation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Architecture(pub u32);

impl Architecture {
    /// `AMD64/x86_64` long mode.
    pub const X86_64: Self = Self(1);
}

/// Typed platform facts copied from firmware before boot services exit.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformInfo {
    /// Firmware interface used by the loader.
    pub firmware: FirmwareKind,
    /// Boot processor architecture.
    pub architecture: Architecture,
    /// Presence flags for optional platform fields.
    pub flags: u64,
    /// Physical address of the ACPI RSDP when its presence flag is set.
    pub rsdp_address: u64,
    /// Validated byte length of the RSDP.
    pub rsdp_length: u32,
    /// Firmware-provided identifier for the boot CPU.
    pub boot_cpu_id: u32,
}

impl PlatformInfo {
    /// Creates an `x86_64` UEFI platform without optional tables.
    #[must_use]
    pub const fn x86_64_uefi(boot_cpu_id: u32) -> Self {
        Self {
            firmware: FirmwareKind::UEFI,
            architecture: Architecture::X86_64,
            flags: 0,
            rsdp_address: 0,
            rsdp_length: 0,
            boot_cpu_id,
        }
    }

    /// Adds a bounded ACPI RSDP range to the platform record.
    #[must_use]
    pub const fn with_rsdp(mut self, address: u64, length: u32) -> Self {
        self.flags |= PLATFORM_FLAG_RSDP_PRESENT;
        self.rsdp_address = address;
        self.rsdp_length = length;
        self
    }
}

/// Boot-test scenario identifier with stable `u32` representation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScenarioKind(pub u32);

impl ScenarioKind {
    /// Normal production boot.
    pub const NORMAL: Self = Self(0);
    /// Test image deliberately supplies an incompatible contract version.
    pub const INCOMPATIBLE_VERSION: Self = Self(1);
    /// Test image deliberately supplies malformed metadata.
    pub const MALFORMED_METADATA: Self = Self(2);
    /// Test image deliberately triggers the early panic path.
    pub const DELIBERATE_PANIC: Self = Self(3);
}

/// Typed scenario data used by the deterministic QEMU harness.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScenarioInfo {
    /// Scenario requested by the image.
    pub kind: ScenarioKind,
    /// Scenario flags; non-normal scenarios require the test-only bit.
    pub flags: u32,
    /// Scenario-specific bounded integer argument.
    pub argument: u64,
}

impl ScenarioInfo {
    /// Creates a normal, non-test handoff.
    #[must_use]
    pub const fn normal() -> Self {
        Self {
            kind: ScenarioKind::NORMAL,
            flags: 0,
            argument: 0,
        }
    }

    /// Creates an explicitly test-only scenario.
    #[must_use]
    pub const fn test(kind: ScenarioKind, argument: u64) -> Self {
        Self {
            kind,
            flags: SCENARIO_FLAG_TEST_ONLY,
            argument,
        }
    }
}

/// Normalized memory type with stable `u32` representation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryKind(pub u32);

impl MemoryKind {
    /// Zero value reserved for unused array entries.
    pub const EMPTY: Self = Self(0);
    /// Memory that must not be allocated or accessed speculatively.
    pub const RESERVED: Self = Self(1);
    /// Conventional memory available to the future allocator.
    pub const USABLE: Self = Self(2);
    /// Loader or boot-service memory that requires explicit reclamation.
    pub const RECLAIMABLE: Self = Self(3);
    /// Loaded kernel image memory.
    pub const KERNEL_IMAGE: Self = Self(4);
    /// Boot-contract storage retained through kernel entry.
    pub const BOOT_CONTRACT: Self = Self(5);
    /// Firmware runtime code or data.
    pub const FIRMWARE_RUNTIME: Self = Self(6);
    /// ACPI reclaimable memory.
    pub const ACPI_RECLAIMABLE: Self = Self(7);
    /// ACPI non-volatile storage.
    pub const ACPI_NVS: Self = Self(8);
    /// Memory-mapped device range.
    pub const MMIO: Self = Self(9);

    const fn is_known(self) -> bool {
        matches!(self.0, 1..=9)
    }
}

/// One normalized, page-aligned physical-memory range.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryRegion {
    /// Inclusive physical start address.
    pub start: u64,
    /// Range length in bytes.
    pub length: u64,
    /// PolytopeOS-normalized memory kind.
    pub kind: MemoryKind,
    /// Original firmware memory-type value for diagnostics.
    pub source_kind: u32,
    /// Firmware memory attributes preserved without interpretation.
    pub attributes: u64,
}

impl MemoryRegion {
    /// Canonical zero value for unused bounded-array entries.
    pub const EMPTY: Self = Self {
        start: 0,
        length: 0,
        kind: MemoryKind::EMPTY,
        source_kind: 0,
        attributes: 0,
    };

    /// Creates a memory-region record.
    #[must_use]
    pub const fn new(
        start: u64,
        length: u64,
        kind: MemoryKind,
        source_kind: u32,
        attributes: u64,
    ) -> Self {
        Self {
            start,
            length,
            kind,
            source_kind,
            attributes,
        }
    }
}

/// Complete fixed-capacity boot handoff.
#[repr(C, align(8))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootInfo {
    /// Version, sizes, flags, and active region count.
    pub header: BootHeader,
    /// Validated platform facts.
    pub platform: PlatformInfo,
    /// Normal or explicit test scenario.
    pub scenario: ScenarioInfo,
    /// Sorted active regions followed by canonical empty records.
    pub memory_regions: [MemoryRegion; MAX_MEMORY_REGIONS],
}

impl BootInfo {
    /// Creates an empty current-version contract.
    #[must_use]
    pub const fn new(platform: PlatformInfo, scenario: ScenarioInfo) -> Self {
        Self {
            header: BootHeader::current(),
            platform,
            scenario,
            memory_regions: [MemoryRegion::EMPTY; MAX_MEMORY_REGIONS],
        }
    }

    /// Sets a bounded region and extends the active count to include it.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::RegionIndexOutOfBounds`] when `index` is not
    /// representable by the ABI.
    pub fn set_memory_region(
        &mut self,
        index: usize,
        region: MemoryRegion,
    ) -> Result<(), ValidationError> {
        if index >= MAX_MEMORY_REGIONS {
            return Err(ValidationError::RegionIndexOutOfBounds { index });
        }
        self.memory_regions[index] = region;
        let count = index + 1;
        if count > self.header.memory_region_count as usize {
            self.header.memory_region_count = u32::try_from(count)
                .map_err(|_| ValidationError::RegionIndexOutOfBounds { index })?;
        }
        Ok(())
    }

    /// Validates a constructed contract and returns a proof wrapper.
    ///
    /// # Errors
    ///
    /// Returns a structured [`ValidationError`] for every rejected invariant.
    pub fn validate(self) -> Result<ValidatedBootInfo, ValidationError> {
        validate_ref(&self)?;
        Ok(ValidatedBootInfo(self))
    }

    /// Encodes a valid contract using the exact little-endian ABI layout.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::Invalid`] for invalid state or
    /// [`EncodeError::BufferTooSmall`] when `output` cannot hold the ABI.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        validate_ref(self).map_err(EncodeError::Invalid)?;
        if output.len() < BOOT_INFO_SIZE {
            return Err(EncodeError::BufferTooSmall {
                provided: output.len(),
                required: BOOT_INFO_SIZE,
            });
        }

        let mut writer = Writer::new(&mut output[..BOOT_INFO_SIZE]);
        writer.bytes(&self.header.magic);
        writer.u16(self.header.abi_major);
        writer.u16(self.header.abi_minor);
        writer.u32(self.header.header_size);
        writer.u32(self.header.total_size);
        writer.u32(self.header.memory_region_size);
        writer.u32(self.header.memory_region_count);
        writer.u32(self.header.flags);
        writer.u32(self.platform.firmware.0);
        writer.u32(self.platform.architecture.0);
        writer.u64(self.platform.flags);
        writer.u64(self.platform.rsdp_address);
        writer.u32(self.platform.rsdp_length);
        writer.u32(self.platform.boot_cpu_id);
        writer.u32(self.scenario.kind.0);
        writer.u32(self.scenario.flags);
        writer.u64(self.scenario.argument);
        for region in &self.memory_regions {
            writer.u64(region.start);
            writer.u64(region.length);
            writer.u32(region.kind.0);
            writer.u32(region.source_kind);
            writer.u64(region.attributes);
        }
        debug_assert_eq!(writer.position, BOOT_INFO_SIZE);
        Ok(BOOT_INFO_SIZE)
    }
}

/// Header facts established before decoding the complete handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrevalidatedHeader {
    /// Supported ABI major version.
    pub abi_major: u16,
    /// Supported ABI minor version.
    pub abi_minor: u16,
    /// Exact byte length required by this ABI.
    pub total_size: u32,
    /// Number of active memory regions.
    pub memory_region_count: u32,
}

/// Owned contract whose structural and semantic invariants have been checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedBootInfo(BootInfo);

impl ValidatedBootInfo {
    /// Borrows the validated contract.
    #[must_use]
    pub const fn as_ref(&self) -> &BootInfo {
        &self.0
    }

    /// Returns only the initialized, validated memory regions.
    #[must_use]
    pub fn memory_regions(&self) -> &[MemoryRegion] {
        &self.0.memory_regions[..self.0.header.memory_region_count as usize]
    }

    /// Consumes the proof wrapper and returns the contract.
    #[must_use]
    pub fn into_inner(self) -> BootInfo {
        self.0
    }
}

/// Structured reasons a handoff was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    /// The supplied range is shorter than a required prefix or contract.
    Truncated {
        /// Bytes supplied by the architecture boundary.
        provided: usize,
        /// Minimum bytes required.
        required: usize,
    },
    /// The supplied range is not the exact declared contract length.
    LengthMismatch {
        /// Bytes supplied by the architecture boundary.
        provided: usize,
        /// Bytes declared by the header.
        declared: usize,
    },
    /// Header magic does not identify `PolytopeOS` boot metadata.
    BadMagic,
    /// Contract version is not supported.
    UnsupportedVersion {
        /// Supplied major version.
        major: u16,
        /// Supplied minor version.
        minor: u16,
    },
    /// Header size differs from the current fixed ABI.
    HeaderSize {
        /// Supplied byte size.
        found: u32,
        /// Required byte size.
        expected: u32,
    },
    /// Total size differs from the current fixed ABI.
    TotalSize {
        /// Supplied byte size.
        found: u32,
        /// Required byte size.
        expected: u32,
    },
    /// Memory-region stride differs from the current fixed ABI.
    MemoryRegionSize {
        /// Supplied entry stride.
        found: u32,
        /// Required entry stride.
        expected: u32,
    },
    /// Region count exceeds the fixed-capacity array.
    TooManyMemoryRegions {
        /// Supplied active count.
        count: u32,
        /// ABI capacity.
        maximum: u32,
    },
    /// Unknown header flag bits were supplied.
    UnknownHeaderFlags {
        /// Supplied flag bits.
        flags: u32,
    },
    /// Requested builder index exceeds the fixed-capacity array.
    RegionIndexOutOfBounds {
        /// Requested array index.
        index: usize,
    },
    /// Firmware kind is unsupported.
    UnsupportedFirmware {
        /// Supplied firmware identifier.
        kind: u32,
    },
    /// Architecture kind is unsupported.
    UnsupportedArchitecture {
        /// Supplied architecture identifier.
        architecture: u32,
    },
    /// Unknown optional-platform flag bits were supplied.
    UnknownPlatformFlags {
        /// Supplied platform flag bits.
        flags: u64,
    },
    /// RSDP fields and the presence flag disagree.
    InconsistentRsdpPresence,
    /// RSDP range is malformed or unreasonably large.
    InvalidRsdpRange {
        /// Supplied physical address.
        address: u64,
        /// Supplied table length.
        length: u32,
    },
    /// Scenario kind is not defined by the current ABI.
    UnknownScenario {
        /// Supplied scenario identifier.
        kind: u32,
    },
    /// Unknown scenario flag bits were supplied.
    UnknownScenarioFlags {
        /// Supplied scenario flag bits.
        flags: u32,
    },
    /// A test scenario was supplied without explicit test-only marking.
    ScenarioNotMarkedTestOnly {
        /// Supplied non-normal scenario identifier.
        kind: u32,
    },
    /// Normal boot carried test-only state.
    NormalScenarioHasTestState,
    /// An active memory entry uses the reserved empty kind.
    ActiveMemoryRegionIsEmpty {
        /// Active array index.
        index: u32,
    },
    /// Active memory region has zero length.
    EmptyMemoryRegion {
        /// Active array index.
        index: u32,
    },
    /// Start or length is not page aligned.
    UnalignedMemoryRegion {
        /// Active array index.
        index: u32,
        /// Supplied physical start.
        start: u64,
        /// Supplied byte length.
        length: u64,
    },
    /// Memory-range end overflowed `u64`.
    MemoryRegionOverflow {
        /// Active array index.
        index: u32,
    },
    /// Memory kind is not defined by the current ABI.
    UnknownMemoryKind {
        /// Active array index.
        index: u32,
        /// Supplied normalized kind.
        kind: u32,
    },
    /// Active regions are not ordered by increasing physical start.
    UnsortedMemoryRegions {
        /// Previous active array index.
        previous: u32,
        /// Current active array index.
        current: u32,
    },
    /// Active memory regions overlap.
    OverlappingMemoryRegions {
        /// Previous active array index.
        previous: u32,
        /// Current active array index.
        current: u32,
    },
    /// An unused bounded-array slot was not fully zeroed.
    NonZeroUnusedMemoryRegion {
        /// Unused array index containing data.
        index: u32,
    },
}

/// Errors emitted while serializing a contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// Contract failed semantic validation.
    Invalid(ValidationError),
    /// Destination buffer is too small.
    BufferTooSmall {
        /// Destination byte capacity.
        provided: usize,
        /// Required ABI byte capacity.
        required: usize,
    },
}

/// Validates the fixed header directly from bytes before typed decoding.
///
/// The caller must first establish that the raw handoff pointer and length
/// describe readable memory. This function deliberately accepts a slice so
/// pointer provenance and lifetime remain in the architecture boundary.
///
/// # Errors
///
/// Returns a structured [`ValidationError`] for truncated, malformed, or
/// unsupported input.
pub fn prevalidate(bytes: &[u8]) -> Result<PrevalidatedHeader, ValidationError> {
    if bytes.len() < BOOT_HEADER_SIZE {
        return Err(ValidationError::Truncated {
            provided: bytes.len(),
            required: BOOT_HEADER_SIZE,
        });
    }
    let mut reader = Reader::new(bytes);
    let magic = reader.array_8();
    let abi_major = reader.u16();
    let abi_minor = reader.u16();
    let header_size = reader.u32();
    let total_size = reader.u32();
    let memory_region_size = reader.u32();
    let memory_region_count = reader.u32();
    let flags = reader.u32();

    if magic != BOOT_MAGIC {
        return Err(ValidationError::BadMagic);
    }
    if (abi_major, abi_minor) != (ABI_MAJOR, ABI_MINOR) {
        return Err(ValidationError::UnsupportedVersion {
            major: abi_major,
            minor: abi_minor,
        });
    }
    if header_size != BOOT_HEADER_SIZE_U32 {
        return Err(ValidationError::HeaderSize {
            found: header_size,
            expected: BOOT_HEADER_SIZE_U32,
        });
    }
    if total_size != BOOT_INFO_SIZE_U32 {
        return Err(ValidationError::TotalSize {
            found: total_size,
            expected: BOOT_INFO_SIZE_U32,
        });
    }
    if memory_region_size != MEMORY_REGION_SIZE_U32 {
        return Err(ValidationError::MemoryRegionSize {
            found: memory_region_size,
            expected: MEMORY_REGION_SIZE_U32,
        });
    }
    if memory_region_count > MAX_MEMORY_REGIONS_U32 {
        return Err(ValidationError::TooManyMemoryRegions {
            count: memory_region_count,
            maximum: MAX_MEMORY_REGIONS_U32,
        });
    }
    if flags & !KNOWN_HEADER_FLAGS != 0 {
        return Err(ValidationError::UnknownHeaderFlags { flags });
    }

    let declared = total_size as usize;
    if bytes.len() < declared {
        return Err(ValidationError::Truncated {
            provided: bytes.len(),
            required: declared,
        });
    }
    if bytes.len() != declared {
        return Err(ValidationError::LengthMismatch {
            provided: bytes.len(),
            declared,
        });
    }

    Ok(PrevalidatedHeader {
        abi_major,
        abi_minor,
        total_size,
        memory_region_count,
    })
}

/// Safely decodes and validates a complete handoff from its byte ABI.
///
/// # Errors
///
/// Returns a structured [`ValidationError`] without partially exposing input.
pub fn parse(bytes: &[u8]) -> Result<ValidatedBootInfo, ValidationError> {
    prevalidate(bytes)?;
    let mut reader = Reader::new(bytes);
    let header = BootHeader {
        magic: reader.array_8(),
        abi_major: reader.u16(),
        abi_minor: reader.u16(),
        header_size: reader.u32(),
        total_size: reader.u32(),
        memory_region_size: reader.u32(),
        memory_region_count: reader.u32(),
        flags: reader.u32(),
    };
    let platform = PlatformInfo {
        firmware: FirmwareKind(reader.u32()),
        architecture: Architecture(reader.u32()),
        flags: reader.u64(),
        rsdp_address: reader.u64(),
        rsdp_length: reader.u32(),
        boot_cpu_id: reader.u32(),
    };
    let scenario = ScenarioInfo {
        kind: ScenarioKind(reader.u32()),
        flags: reader.u32(),
        argument: reader.u64(),
    };
    let mut memory_regions = [MemoryRegion::EMPTY; MAX_MEMORY_REGIONS];
    for region in &mut memory_regions {
        *region = MemoryRegion {
            start: reader.u64(),
            length: reader.u64(),
            kind: MemoryKind(reader.u32()),
            source_kind: reader.u32(),
            attributes: reader.u64(),
        };
    }
    debug_assert_eq!(reader.position, BOOT_INFO_SIZE);
    BootInfo {
        header,
        platform,
        scenario,
        memory_regions,
    }
    .validate()
}

fn validate_ref(info: &BootInfo) -> Result<(), ValidationError> {
    validate_header(&info.header)?;
    validate_platform(&info.platform)?;
    validate_scenario(&info.scenario)?;
    validate_regions(info)?;
    Ok(())
}

fn validate_header(header: &BootHeader) -> Result<(), ValidationError> {
    if header.magic != BOOT_MAGIC {
        return Err(ValidationError::BadMagic);
    }
    if (header.abi_major, header.abi_minor) != (ABI_MAJOR, ABI_MINOR) {
        return Err(ValidationError::UnsupportedVersion {
            major: header.abi_major,
            minor: header.abi_minor,
        });
    }
    if header.header_size != BOOT_HEADER_SIZE_U32 {
        return Err(ValidationError::HeaderSize {
            found: header.header_size,
            expected: BOOT_HEADER_SIZE_U32,
        });
    }
    if header.total_size != BOOT_INFO_SIZE_U32 {
        return Err(ValidationError::TotalSize {
            found: header.total_size,
            expected: BOOT_INFO_SIZE_U32,
        });
    }
    if header.memory_region_size != MEMORY_REGION_SIZE_U32 {
        return Err(ValidationError::MemoryRegionSize {
            found: header.memory_region_size,
            expected: MEMORY_REGION_SIZE_U32,
        });
    }
    if header.memory_region_count > MAX_MEMORY_REGIONS_U32 {
        return Err(ValidationError::TooManyMemoryRegions {
            count: header.memory_region_count,
            maximum: MAX_MEMORY_REGIONS_U32,
        });
    }
    if header.flags & !KNOWN_HEADER_FLAGS != 0 {
        return Err(ValidationError::UnknownHeaderFlags {
            flags: header.flags,
        });
    }
    Ok(())
}

fn validate_platform(platform: &PlatformInfo) -> Result<(), ValidationError> {
    if platform.firmware != FirmwareKind::UEFI {
        return Err(ValidationError::UnsupportedFirmware {
            kind: platform.firmware.0,
        });
    }
    if platform.architecture != Architecture::X86_64 {
        return Err(ValidationError::UnsupportedArchitecture {
            architecture: platform.architecture.0,
        });
    }
    if platform.flags & !KNOWN_PLATFORM_FLAGS != 0 {
        return Err(ValidationError::UnknownPlatformFlags {
            flags: platform.flags,
        });
    }
    let rsdp_present = platform.flags & PLATFORM_FLAG_RSDP_PRESENT != 0;
    if !rsdp_present {
        if platform.rsdp_address != 0 || platform.rsdp_length != 0 {
            return Err(ValidationError::InconsistentRsdpPresence);
        }
        return Ok(());
    }
    let valid_length = (MIN_RSDP_LENGTH..=MAX_RSDP_LENGTH).contains(&platform.rsdp_length);
    let valid_address = platform.rsdp_address != 0 && platform.rsdp_address % 16 == 0;
    let has_end = platform
        .rsdp_address
        .checked_add(u64::from(platform.rsdp_length))
        .is_some();
    if !valid_length || !valid_address || !has_end {
        return Err(ValidationError::InvalidRsdpRange {
            address: platform.rsdp_address,
            length: platform.rsdp_length,
        });
    }
    Ok(())
}

fn validate_scenario(scenario: &ScenarioInfo) -> Result<(), ValidationError> {
    if !matches!(scenario.kind.0, 0..=3) {
        return Err(ValidationError::UnknownScenario {
            kind: scenario.kind.0,
        });
    }
    if scenario.flags & !KNOWN_SCENARIO_FLAGS != 0 {
        return Err(ValidationError::UnknownScenarioFlags {
            flags: scenario.flags,
        });
    }
    if scenario.kind == ScenarioKind::NORMAL {
        if scenario.flags != 0 || scenario.argument != 0 {
            return Err(ValidationError::NormalScenarioHasTestState);
        }
    } else if scenario.flags & SCENARIO_FLAG_TEST_ONLY == 0 {
        return Err(ValidationError::ScenarioNotMarkedTestOnly {
            kind: scenario.kind.0,
        });
    }
    Ok(())
}

fn validate_regions(info: &BootInfo) -> Result<(), ValidationError> {
    let count = info.header.memory_region_count as usize;
    let mut previous: Option<(u32, u64, u64)> = None;
    for (index, region) in (0_u32..).zip(info.memory_regions[..count].iter()) {
        if region.kind == MemoryKind::EMPTY {
            return Err(ValidationError::ActiveMemoryRegionIsEmpty { index });
        }
        if !region.kind.is_known() {
            return Err(ValidationError::UnknownMemoryKind {
                index,
                kind: region.kind.0,
            });
        }
        if region.length == 0 {
            return Err(ValidationError::EmptyMemoryRegion { index });
        }
        if region.start % PAGE_SIZE != 0 || region.length % PAGE_SIZE != 0 {
            return Err(ValidationError::UnalignedMemoryRegion {
                index,
                start: region.start,
                length: region.length,
            });
        }
        let end = region
            .start
            .checked_add(region.length)
            .ok_or(ValidationError::MemoryRegionOverflow { index })?;
        if let Some((previous_index, previous_start, previous_end)) = previous {
            if region.start < previous_start {
                return Err(ValidationError::UnsortedMemoryRegions {
                    previous: previous_index,
                    current: index,
                });
            }
            if region.start < previous_end {
                return Err(ValidationError::OverlappingMemoryRegions {
                    previous: previous_index,
                    current: index,
                });
            }
        }
        previous = Some((index, region.start, end));
    }

    for (offset, region) in (0_u32..).zip(info.memory_regions[count..].iter()) {
        if *region != MemoryRegion::EMPTY {
            return Err(ValidationError::NonZeroUnusedMemoryRegion {
                index: info.header.memory_region_count + offset,
            });
        }
    }
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn array_8(&mut self) -> [u8; 8] {
        let mut value = [0; 8];
        value.copy_from_slice(&self.bytes[self.position..self.position + 8]);
        self.position += 8;
        value
    }

    fn u16(&mut self) -> u16 {
        let mut value = [0; 2];
        value.copy_from_slice(&self.bytes[self.position..self.position + 2]);
        self.position += 2;
        u16::from_le_bytes(value)
    }

    fn u32(&mut self) -> u32 {
        let mut value = [0; 4];
        value.copy_from_slice(&self.bytes[self.position..self.position + 4]);
        self.position += 4;
        u32::from_le_bytes(value)
    }

    fn u64(&mut self) -> u64 {
        let mut value = [0; 8];
        value.copy_from_slice(&self.bytes[self.position..self.position + 8]);
        self.position += 8;
        u64::from_le_bytes(value)
    }
}

struct Writer<'a> {
    bytes: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn bytes(&mut self, value: &[u8]) {
        let end = self.position + value.len();
        self.bytes[self.position..end].copy_from_slice(value);
        self.position = end;
    }

    fn u16(&mut self, value: u16) {
        self.bytes(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_le_bytes());
    }
}

const _: () = assert!(size_of::<BootHeader>() == BOOT_HEADER_SIZE);
const _: () = assert!(size_of::<PlatformInfo>() == 32);
const _: () = assert!(size_of::<ScenarioInfo>() == 16);
const _: () = assert!(size_of::<MemoryRegion>() == MEMORY_REGION_SIZE);
const _: () = assert!(align_of::<BootInfo>() == 8);
const _: () = assert!(BOOT_INFO_SIZE == 4_176);

#[cfg(test)]
mod tests {
    use super::*;

    const PLATFORM_FLAGS_OFFSET: usize =
        offset_of!(BootInfo, platform) + offset_of!(PlatformInfo, flags);
    const RSDP_ADDRESS_OFFSET: usize =
        offset_of!(BootInfo, platform) + offset_of!(PlatformInfo, rsdp_address);
    const RSDP_LENGTH_OFFSET: usize =
        offset_of!(BootInfo, platform) + offset_of!(PlatformInfo, rsdp_length);
    const SCENARIO_KIND_OFFSET: usize =
        offset_of!(BootInfo, scenario) + offset_of!(ScenarioInfo, kind);
    const FIRST_REGION_START_OFFSET: usize =
        offset_of!(BootInfo, memory_regions) + offset_of!(MemoryRegion, start);
    const FIRST_REGION_LENGTH_OFFSET: usize =
        offset_of!(BootInfo, memory_regions) + offset_of!(MemoryRegion, length);

    fn valid_info() -> BootInfo {
        let mut info = BootInfo::new(PlatformInfo::x86_64_uefi(0), ScenarioInfo::normal());
        info.set_memory_region(
            0,
            MemoryRegion::new(0x10_0000, 0x20_0000, MemoryKind::RESERVED, 0, 0),
        )
        .unwrap();
        info.set_memory_region(
            1,
            MemoryRegion::new(0x30_0000, 0x40_0000, MemoryKind::USABLE, 7, 8),
        )
        .unwrap();
        info
    }

    fn encoded(info: &BootInfo) -> [u8; BOOT_INFO_SIZE] {
        let mut bytes = [0; BOOT_INFO_SIZE];
        assert_eq!(info.encode(&mut bytes), Ok(BOOT_INFO_SIZE));
        bytes
    }

    fn mutation_mask(index: usize) -> u8 {
        let mut value = (index as u64).wrapping_add(0x9e37_79b9_7f4a_7c15);
        value ^= value >> 30;
        value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value ^= value >> 27;
        value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^= value >> 31;
        value.to_le_bytes()[0] | 1
    }

    fn assert_validated_invariants(bytes: &[u8], validated: &ValidatedBootInfo) {
        let info = validated.as_ref();
        assert_eq!(bytes.len(), BOOT_INFO_SIZE);
        assert_eq!(info.header.magic, BOOT_MAGIC);
        assert_eq!(
            (info.header.abi_major, info.header.abi_minor),
            (ABI_MAJOR, ABI_MINOR)
        );
        assert_eq!(info.header.header_size, BOOT_HEADER_SIZE_U32);
        assert_eq!(info.header.total_size, BOOT_INFO_SIZE_U32);
        assert_eq!(info.header.memory_region_size, MEMORY_REGION_SIZE_U32);
        assert!(info.header.memory_region_count <= MAX_MEMORY_REGIONS_U32);
        assert_eq!(info.header.flags, 0);
        assert_eq!(info.platform.firmware, FirmwareKind::UEFI);
        assert_eq!(info.platform.architecture, Architecture::X86_64);

        let regions = validated.memory_regions();
        assert_eq!(regions.len(), info.header.memory_region_count as usize);
        let mut previous_end = None;
        for region in regions {
            assert!(region.kind.is_known());
            assert_ne!(region.length, 0);
            assert_eq!(region.start % PAGE_SIZE, 0);
            assert_eq!(region.length % PAGE_SIZE, 0);
            let end = region.start.checked_add(region.length).unwrap();
            if let Some(end_before) = previous_end {
                assert!(region.start >= end_before);
            }
            previous_end = Some(end);
        }
        assert!(
            info.memory_regions[regions.len()..]
                .iter()
                .all(|region| *region == MemoryRegion::EMPTY)
        );

        let mut reencoded = [0; BOOT_INFO_SIZE];
        assert_eq!(info.encode(&mut reencoded), Ok(BOOT_INFO_SIZE));
        assert_eq!(reencoded.as_slice(), bytes);
    }

    #[test]
    fn current_layout_is_fixed_and_round_trips() {
        let info = valid_info();
        let bytes = encoded(&info);
        let validated = parse(&bytes).unwrap();
        assert_eq!(validated.as_ref(), &info);
        assert_eq!(validated.memory_regions().len(), 2);
    }

    #[test]
    fn prevalidation_rejects_truncation_before_decode() {
        let bytes = encoded(&valid_info());
        assert_eq!(
            prevalidate(&bytes[..BOOT_HEADER_SIZE - 1]),
            Err(ValidationError::Truncated {
                provided: BOOT_HEADER_SIZE - 1,
                required: BOOT_HEADER_SIZE,
            })
        );
        assert_eq!(
            prevalidate(&bytes[..BOOT_INFO_SIZE - 1]),
            Err(ValidationError::Truncated {
                provided: BOOT_INFO_SIZE - 1,
                required: BOOT_INFO_SIZE,
            })
        );
    }

    #[test]
    fn every_truncated_prefix_is_rejected_without_decoding() {
        let bytes = encoded(&valid_info());
        for length in 0..BOOT_INFO_SIZE {
            let expected_required = if length < BOOT_HEADER_SIZE {
                BOOT_HEADER_SIZE
            } else {
                BOOT_INFO_SIZE
            };
            assert_eq!(
                parse(&bytes[..length]),
                Err(ValidationError::Truncated {
                    provided: length,
                    required: expected_required,
                }),
                "prefix length {length} unexpectedly passed"
            );
        }
    }

    #[test]
    fn deterministic_single_byte_mutations_never_escape_validation() {
        let original = encoded(&valid_info());
        let mut accepted = 0;
        let mut rejected = 0;
        for index in 0..BOOT_INFO_SIZE {
            let mut candidate = original;
            candidate[index] ^= mutation_mask(index);
            match parse(&candidate) {
                Ok(validated) => {
                    accepted += 1;
                    assert_validated_invariants(&candidate, &validated);
                }
                Err(_) => rejected += 1,
            }
        }

        // Some opaque diagnostic fields are intentionally mutable, while
        // structural and canonical-zero mutations must fail closed.
        assert!(accepted > 0);
        assert!(rejected > 0);
    }

    #[test]
    fn malformed_contract_regression_seeds_fail_closed() {
        let original = encoded(&valid_info());

        let mut impossible_total_size = original;
        impossible_total_size[TOTAL_SIZE_OFFSET..TOTAL_SIZE_OFFSET + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse(&impossible_total_size).is_err());

        let mut overflowing_rsdp = original;
        overflowing_rsdp[PLATFORM_FLAGS_OFFSET..PLATFORM_FLAGS_OFFSET + size_of::<u64>()]
            .copy_from_slice(&PLATFORM_FLAG_RSDP_PRESENT.to_le_bytes());
        overflowing_rsdp[RSDP_ADDRESS_OFFSET..RSDP_ADDRESS_OFFSET + size_of::<u64>()]
            .copy_from_slice(&(u64::MAX - 15).to_le_bytes());
        overflowing_rsdp[RSDP_LENGTH_OFFSET..RSDP_LENGTH_OFFSET + size_of::<u32>()]
            .copy_from_slice(&MIN_RSDP_LENGTH.to_le_bytes());
        assert!(parse(&overflowing_rsdp).is_err());

        let mut unknown_scenario = original;
        unknown_scenario[SCENARIO_KIND_OFFSET..SCENARIO_KIND_OFFSET + size_of::<u32>()]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse(&unknown_scenario).is_err());

        let mut overflowing_region = original;
        overflowing_region[FIRST_REGION_START_OFFSET..FIRST_REGION_START_OFFSET + size_of::<u64>()]
            .copy_from_slice(&(u64::MAX - (PAGE_SIZE - 1)).to_le_bytes());
        overflowing_region
            [FIRST_REGION_LENGTH_OFFSET..FIRST_REGION_LENGTH_OFFSET + size_of::<u64>()]
            .copy_from_slice(&PAGE_SIZE.to_le_bytes());
        assert!(parse(&overflowing_region).is_err());

        let mut active_zero_region = original;
        let count_offset =
            offset_of!(BootInfo, header) + offset_of!(BootHeader, memory_region_count);
        active_zero_region[count_offset..count_offset + size_of::<u32>()]
            .copy_from_slice(&3_u32.to_le_bytes());
        assert!(parse(&active_zero_region).is_err());
    }

    #[test]
    fn unsupported_versions_fail_closed() {
        let mut bytes = encoded(&valid_info());
        bytes[8..10].copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(
            parse(&bytes),
            Err(ValidationError::UnsupportedVersion { major: 2, minor: 0 })
        );
    }

    #[test]
    fn supplied_length_must_be_exact() {
        let source = encoded(&valid_info());
        let mut bytes = [0; BOOT_INFO_SIZE + 1];
        bytes[..BOOT_INFO_SIZE].copy_from_slice(&source);
        assert_eq!(
            parse(&bytes),
            Err(ValidationError::LengthMismatch {
                provided: BOOT_INFO_SIZE + 1,
                declared: BOOT_INFO_SIZE,
            })
        );
    }

    #[test]
    fn regions_must_be_aligned_sorted_and_nonoverlapping() {
        let mut unaligned = valid_info();
        unaligned.memory_regions[0].start += 1;
        assert!(matches!(
            unaligned.validate(),
            Err(ValidationError::UnalignedMemoryRegion { index: 0, .. })
        ));

        let mut unsorted = valid_info();
        unsorted.memory_regions.swap(0, 1);
        assert_eq!(
            unsorted.validate(),
            Err(ValidationError::UnsortedMemoryRegions {
                previous: 0,
                current: 1,
            })
        );

        let mut overlapping = valid_info();
        overlapping.memory_regions[1].start = 0x20_0000;
        assert_eq!(
            overlapping.validate(),
            Err(ValidationError::OverlappingMemoryRegions {
                previous: 0,
                current: 1,
            })
        );
    }

    #[test]
    fn range_overflow_and_unknown_kind_are_rejected() {
        let mut overflow = valid_info();
        overflow.memory_regions[1].start = u64::MAX - (PAGE_SIZE - 1);
        overflow.memory_regions[1].length = PAGE_SIZE;
        assert_eq!(
            overflow.validate(),
            Err(ValidationError::MemoryRegionOverflow { index: 1 })
        );

        let mut unknown = valid_info();
        unknown.memory_regions[0].kind = MemoryKind(99);
        assert_eq!(
            unknown.validate(),
            Err(ValidationError::UnknownMemoryKind { index: 0, kind: 99 })
        );
    }

    #[test]
    fn physical_range_and_rsdp_arithmetic_boundaries_are_exact() {
        let largest_page_end = u64::MAX - (PAGE_SIZE - 1);
        let mut valid_range = BootInfo::new(
            PlatformInfo::x86_64_uefi(0).with_rsdp(0x1000, MIN_RSDP_LENGTH),
            ScenarioInfo::normal(),
        );
        valid_range
            .set_memory_region(
                0,
                MemoryRegion::new(
                    largest_page_end - PAGE_SIZE,
                    PAGE_SIZE,
                    MemoryKind::RESERVED,
                    0,
                    0,
                ),
            )
            .unwrap();
        assert!(valid_range.clone().validate().is_ok());
        assert_validated_invariants(
            &encoded(&valid_range),
            &parse(&encoded(&valid_range)).unwrap(),
        );

        let mut overflowing_range = valid_range.clone();
        overflowing_range.memory_regions[0].start = largest_page_end;
        assert_eq!(
            overflowing_range.validate(),
            Err(ValidationError::MemoryRegionOverflow { index: 0 })
        );

        let mut largest_rsdp = valid_info();
        largest_rsdp.platform = largest_rsdp.platform.with_rsdp(0x1000, MAX_RSDP_LENGTH);
        assert!(largest_rsdp.validate().is_ok());

        let mut overflowing_rsdp = valid_info();
        overflowing_rsdp.platform = overflowing_rsdp
            .platform
            .with_rsdp(u64::MAX - 15, MIN_RSDP_LENGTH);
        assert_eq!(
            overflowing_rsdp.validate(),
            Err(ValidationError::InvalidRsdpRange {
                address: u64::MAX - 15,
                length: MIN_RSDP_LENGTH,
            })
        );
    }

    #[test]
    fn maximum_region_capacity_round_trips_with_adjacent_ranges() {
        let mut info = BootInfo::new(PlatformInfo::x86_64_uefi(7), ScenarioInfo::normal());
        for index in 0..MAX_MEMORY_REGIONS {
            let index_u32 = u32::try_from(index).unwrap();
            let index_u64 = u64::try_from(index).unwrap();
            info.set_memory_region(
                index,
                MemoryRegion::new(
                    (index_u64 + 1) * PAGE_SIZE,
                    PAGE_SIZE,
                    MemoryKind::USABLE,
                    index_u32,
                    index_u64,
                ),
            )
            .unwrap();
        }
        let bytes = encoded(&info);
        let validated = parse(&bytes).unwrap();
        assert_validated_invariants(&bytes, &validated);
        assert_eq!(validated.memory_regions().len(), MAX_MEMORY_REGIONS);
    }

    #[test]
    fn unused_entries_must_be_canonical_zeroes() {
        let mut info = valid_info();
        info.memory_regions[2].attributes = 1;
        assert_eq!(
            info.validate(),
            Err(ValidationError::NonZeroUnusedMemoryRegion { index: 2 })
        );
    }

    #[test]
    fn rsdp_presence_and_bounds_are_validated() {
        let mut info = valid_info();
        info.platform.rsdp_address = 0x1000;
        assert_eq!(
            info.validate(),
            Err(ValidationError::InconsistentRsdpPresence)
        );

        let mut info = valid_info();
        info.platform = info.platform.with_rsdp(0x1001, 36);
        assert!(matches!(
            info.validate(),
            Err(ValidationError::InvalidRsdpRange { .. })
        ));
    }

    #[test]
    fn scenario_controls_are_explicitly_test_only() {
        let mut info = valid_info();
        info.scenario.kind = ScenarioKind::DELIBERATE_PANIC;
        assert_eq!(
            info.validate(),
            Err(ValidationError::ScenarioNotMarkedTestOnly { kind: 3 })
        );

        let mut info = valid_info();
        info.scenario = ScenarioInfo::test(ScenarioKind::DELIBERATE_PANIC, 7);
        assert!(info.validate().is_ok());
    }

    #[test]
    fn encoder_checks_state_and_capacity() {
        let info = valid_info();
        let mut short = [0; BOOT_INFO_SIZE - 1];
        assert_eq!(
            info.encode(&mut short),
            Err(EncodeError::BufferTooSmall {
                provided: BOOT_INFO_SIZE - 1,
                required: BOOT_INFO_SIZE,
            })
        );
    }

    #[test]
    fn every_header_shape_and_flag_is_bounded() {
        let mut bytes = encoded(&valid_info());
        bytes[0] = b'X';
        assert_eq!(parse(&bytes), Err(ValidationError::BadMagic));

        let mut bytes = encoded(&valid_info());
        bytes[12..16].copy_from_slice(&31_u32.to_le_bytes());
        assert_eq!(
            parse(&bytes),
            Err(ValidationError::HeaderSize {
                found: 31,
                expected: BOOT_HEADER_SIZE_U32,
            })
        );

        let mut bytes = encoded(&valid_info());
        bytes[20..24].copy_from_slice(&16_u32.to_le_bytes());
        assert_eq!(
            parse(&bytes),
            Err(ValidationError::MemoryRegionSize {
                found: 16,
                expected: MEMORY_REGION_SIZE_U32,
            })
        );

        let mut bytes = encoded(&valid_info());
        bytes[24..28].copy_from_slice(&(MAX_MEMORY_REGIONS_U32 + 1).to_le_bytes());
        assert_eq!(
            parse(&bytes),
            Err(ValidationError::TooManyMemoryRegions {
                count: MAX_MEMORY_REGIONS_U32 + 1,
                maximum: MAX_MEMORY_REGIONS_U32,
            })
        );

        let mut bytes = encoded(&valid_info());
        bytes[28..32].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            parse(&bytes),
            Err(ValidationError::UnknownHeaderFlags { flags: 1 })
        );
    }

    #[test]
    fn platform_and_scenario_discriminants_fail_closed() {
        let mut info = valid_info();
        info.platform.firmware = FirmwareKind(99);
        assert_eq!(
            info.validate(),
            Err(ValidationError::UnsupportedFirmware { kind: 99 })
        );

        let mut info = valid_info();
        info.platform.architecture = Architecture(99);
        assert_eq!(
            info.validate(),
            Err(ValidationError::UnsupportedArchitecture { architecture: 99 })
        );

        let mut info = valid_info();
        info.platform.flags = 2;
        assert_eq!(
            info.validate(),
            Err(ValidationError::UnknownPlatformFlags { flags: 2 })
        );

        let mut info = valid_info();
        info.scenario.kind = ScenarioKind(99);
        assert_eq!(
            info.validate(),
            Err(ValidationError::UnknownScenario { kind: 99 })
        );

        let mut info = valid_info();
        info.scenario.flags = 2;
        assert_eq!(
            info.validate(),
            Err(ValidationError::UnknownScenarioFlags { flags: 2 })
        );
    }

    #[test]
    fn active_and_builder_region_bounds_fail_closed() {
        let mut info = valid_info();
        info.memory_regions[0] = MemoryRegion::EMPTY;
        assert_eq!(
            info.validate(),
            Err(ValidationError::ActiveMemoryRegionIsEmpty { index: 0 })
        );

        let mut info = valid_info();
        info.memory_regions[0].length = 0;
        assert_eq!(
            info.validate(),
            Err(ValidationError::EmptyMemoryRegion { index: 0 })
        );

        let mut info = valid_info();
        assert_eq!(
            info.set_memory_region(MAX_MEMORY_REGIONS, MemoryRegion::EMPTY),
            Err(ValidationError::RegionIndexOutOfBounds {
                index: MAX_MEMORY_REGIONS,
            })
        );
    }
}
