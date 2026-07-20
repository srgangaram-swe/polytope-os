#![no_std]
#![forbid(unsafe_code)]
#![doc = "Strict, allocation-free validation of the `PolytopeOS` kernel ELF subset."]
//!
//! This crate intentionally accepts much less than general-purpose ELF. The
//! UEFI loader needs only sorted `PT_LOAD` records for a fixed-address,
//! identity-mapped `x86_64` kernel. Every value is validated before a caller may
//! observe a [`LoadSegment`].

#[cfg(test)]
extern crate std;

/// Lowest permitted physical and virtual kernel load address (2 MiB).
pub const MIN_LOAD_ADDRESS: u64 = 0x20_0000;
/// Exclusive upper bound of the Sprint 02 kernel load window (1 GiB).
pub const MAX_LOAD_ADDRESS_EXCLUSIVE: u64 = 0x4000_0000;
/// Fixed Sprint 02 kernel link/load base.
pub const KERNEL_BASE_ADDRESS: u64 = 0x0400_0000;
/// Exclusive end of the kernel image's pre-stack link window.
pub const KERNEL_LOAD_LIMIT: u64 = 0x0480_0000;
/// Physical address of the page reserved beside the bootstrap stack.
pub const STACK_GUARD_ADDRESS: u64 = 0x047f_f000;
/// Physical base of the bootstrap stack.
pub const STACK_BASE_ADDRESS: u64 = 0x0480_0000;
/// Bootstrap-stack size in bytes.
pub const STACK_SIZE_BYTES: u64 = 0x0001_0000;
/// Maximum accepted ELF file size (16 MiB).
pub const MAX_ELF_FILE_SIZE: usize = 16 * 1024 * 1024;
/// Maximum number of program headers inspected.
pub const MAX_PROGRAM_HEADERS: u16 = 8;
/// Maximum loadable segments: text, read-only data, writable data, and stack.
pub const MAX_LOAD_SEGMENTS: u16 = 4;
/// Maximum combined in-memory segment size (64 MiB).
pub const MAX_TOTAL_LOAD_SIZE: u64 = 64 * 1024 * 1024;
/// Minimum supported segment alignment.
pub const PAGE_SIZE: u64 = 4_096;
/// Maximum supported segment alignment.
pub const MAX_SEGMENT_ALIGNMENT: u64 = 2 * 1024 * 1024;

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const ELF_HEADER_SIZE_U16: u16 = 64;
const PROGRAM_HEADER_SIZE_U16: u16 = 56;
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT_U8: u8 = 1;
const EV_CURRENT_U32: u32 = 1;
const ELFOSABI_SYSV: u8 = 0;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const KNOWN_SEGMENT_FLAGS: u32 = PF_X | PF_W | PF_R;

/// Validated ELF segment permission bits.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentFlags(u32);

impl SegmentFlags {
    /// Returns the original ELF flag bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether the segment may be read.
    #[must_use]
    pub const fn is_readable(self) -> bool {
        self.0 & PF_R != 0
    }

    /// Whether the segment may be written.
    #[must_use]
    pub const fn is_writable(self) -> bool {
        self.0 & PF_W != 0
    }

    /// Whether instructions may execute from the segment.
    #[must_use]
    pub const fn is_executable(self) -> bool {
        self.0 & PF_X != 0
    }
}

/// One loadable segment borrowed from a fully validated ELF image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadSegment<'a> {
    index: u16,
    flags: SegmentFlags,
    file_offset: u64,
    virtual_address: u64,
    physical_address: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
    file_data: &'a [u8],
}

impl<'a> LoadSegment<'a> {
    /// Original program-header index.
    #[must_use]
    pub const fn index(self) -> u16 {
        self.index
    }

    /// Validated R/W/X permissions.
    #[must_use]
    pub const fn flags(self) -> SegmentFlags {
        self.flags
    }

    /// Byte offset of initialized data in the ELF file.
    #[must_use]
    pub const fn file_offset(self) -> u64 {
        self.file_offset
    }

    /// Identity-mapped virtual address.
    #[must_use]
    pub const fn virtual_address(self) -> u64 {
        self.virtual_address
    }

    /// Physical load address.
    #[must_use]
    pub const fn physical_address(self) -> u64 {
        self.physical_address
    }

    /// Initialized byte count copied from the file.
    #[must_use]
    pub const fn file_size(self) -> u64 {
        self.file_size
    }

    /// Total in-memory byte count after zero fill.
    #[must_use]
    pub const fn memory_size(self) -> u64 {
        self.memory_size
    }

    /// ELF segment alignment.
    #[must_use]
    pub const fn alignment(self) -> u64 {
        self.alignment
    }

    /// Initialized bytes to copy to the physical load address.
    #[must_use]
    pub const fn file_data(self) -> &'a [u8] {
        self.file_data
    }

    /// Number of bytes the loader must zero after the file data.
    #[must_use]
    pub const fn zero_fill_size(self) -> u64 {
        self.memory_size - self.file_size
    }
}

/// Proof that an ELF image satisfies the bounded `PolytopeOS` kernel policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedElf<'a> {
    bytes: &'a [u8],
    entry_point: u64,
    program_header_offset: usize,
    program_header_count: u16,
    load_segment_count: u16,
}

impl<'a> ValidatedElf<'a> {
    /// Validated kernel entry point within an executable segment.
    #[must_use]
    pub const fn entry_point(self) -> u64 {
        self.entry_point
    }

    /// Number of validated `PT_LOAD` records.
    #[must_use]
    pub const fn segment_count(self) -> u16 {
        self.load_segment_count
    }

    /// Iterates over validated loadable segments without allocation.
    #[must_use]
    pub const fn segments(self) -> LoadSegments<'a> {
        LoadSegments {
            bytes: self.bytes,
            program_header_offset: self.program_header_offset,
            program_header_count: self.program_header_count,
            next_index: 0,
        }
    }
}

/// Allocation-free iterator over validated load segments.
#[derive(Clone, Debug)]
pub struct LoadSegments<'a> {
    bytes: &'a [u8],
    program_header_offset: usize,
    program_header_count: u16,
    next_index: u16,
}

impl<'a> Iterator for LoadSegments<'a> {
    type Item = LoadSegment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next_index < self.program_header_count {
            let index = self.next_index;
            self.next_index += 1;
            let header = decode_program_header(self.bytes, self.program_header_offset, index)?;
            if header.kind == PT_LOAD {
                return load_segment_from_header(self.bytes, index, header);
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (
            0,
            Some(usize::from(self.program_header_count - self.next_index)),
        )
    }
}

/// Structured reasons a kernel ELF image was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// Input does not contain a complete ELF header.
    Truncated {
        /// Supplied byte count.
        provided: usize,
        /// Minimum required byte count.
        required: usize,
    },
    /// Input exceeds the loader's fixed file-size bound.
    FileTooLarge {
        /// Supplied byte count.
        size: usize,
        /// Loader byte-count limit.
        maximum: usize,
    },
    /// ELF magic is invalid.
    BadMagic,
    /// ELF class is not 64-bit.
    UnsupportedClass {
        /// Supplied ELF class.
        class: u8,
    },
    /// ELF byte order is not little-endian.
    UnsupportedByteOrder {
        /// Supplied ELF data encoding.
        encoding: u8,
    },
    /// Identification version is unsupported.
    UnsupportedIdentificationVersion {
        /// Supplied identification version.
        version: u8,
    },
    /// Operating-system ABI is not System V.
    UnsupportedOsAbi {
        /// Supplied OS ABI identifier.
        os_abi: u8,
    },
    /// ABI version is not zero.
    UnsupportedAbiVersion {
        /// Supplied ABI revision.
        version: u8,
    },
    /// Identification padding contains nonzero data.
    NonZeroIdentificationPadding,
    /// ELF object type is not executable.
    UnsupportedObjectType {
        /// Supplied ELF object type.
        object_type: u16,
    },
    /// ELF machine is not `x86_64`.
    UnsupportedMachine {
        /// Supplied ELF machine identifier.
        machine: u16,
    },
    /// Main ELF version is unsupported.
    UnsupportedVersion {
        /// Supplied ELF version.
        version: u32,
    },
    /// Architecture-specific flags are not zero.
    UnsupportedElfFlags {
        /// Supplied architecture-specific flags.
        flags: u32,
    },
    /// ELF header size differs from the ELF64 definition.
    InvalidHeaderSize {
        /// Supplied header size.
        found: u16,
        /// ELF64 header size.
        expected: u16,
    },
    /// Program-header stride differs from the ELF64 definition.
    InvalidProgramHeaderSize {
        /// Supplied program-header stride.
        found: u16,
        /// ELF64 program-header stride.
        expected: u16,
    },
    /// Program-header count is zero or exceeds the fixed bound.
    InvalidProgramHeaderCount {
        /// Supplied program-header count.
        count: u16,
        /// Loader count limit.
        maximum: u16,
    },
    /// Program-header table offset overlaps the ELF header.
    ProgramHeaderTableOverlapsHeader {
        /// Supplied program-header-table offset.
        offset: u64,
    },
    /// Program-header table length overflowed.
    ProgramHeaderTableOverflow,
    /// Program-header table extends past the file.
    ProgramHeaderTableOutOfBounds {
        /// Exclusive requested table end.
        end: u64,
        /// Actual ELF byte count.
        file_size: u64,
    },
    /// Program-header kind is outside the accepted `PT_NULL`/`PT_LOAD` subset.
    UnsupportedProgramHeaderType {
        /// Program-header index.
        index: u16,
        /// Supplied header type.
        kind: u32,
    },
    /// More loadable segments were supplied than the loader can track.
    TooManyLoadSegments {
        /// Observed load-segment count.
        count: u16,
        /// Loader count limit.
        maximum: u16,
    },
    /// No loadable segment was supplied.
    NoLoadSegments,
    /// Segment contains unknown permission bits.
    UnknownSegmentFlags {
        /// Program-header index.
        index: u16,
        /// Supplied flag bits.
        flags: u32,
    },
    /// Loadable segment is not readable.
    NonReadableSegment {
        /// Program-header index.
        index: u16,
    },
    /// Loadable segment violates write-xor-execute.
    WriteExecuteSegment {
        /// Program-header index.
        index: u16,
    },
    /// Segment has no in-memory extent.
    EmptyMemorySegment {
        /// Program-header index.
        index: u16,
    },
    /// Initialized file data is larger than the memory extent.
    FileLargerThanMemory {
        /// Program-header index.
        index: u16,
        /// Initialized file bytes.
        file_size: u64,
        /// In-memory bytes.
        memory_size: u64,
    },
    /// Segment file range overflowed.
    SegmentFileRangeOverflow {
        /// Program-header index.
        index: u16,
    },
    /// Segment file range extends past the ELF image.
    SegmentFileRangeOutOfBounds {
        /// Program-header index.
        index: u16,
        /// Exclusive requested file end.
        end: u64,
        /// Actual file size.
        file_size: u64,
    },
    /// Segment physical range overflowed.
    SegmentMemoryRangeOverflow {
        /// Program-header index.
        index: u16,
    },
    /// Segment lies outside the fixed physical load window.
    SegmentOutsideLoadWindow {
        /// Program-header index.
        index: u16,
        /// Segment physical start.
        start: u64,
        /// Segment exclusive physical end.
        end: u64,
    },
    /// Sprint 02 requires identity-mapped virtual and physical addresses.
    VirtualPhysicalAddressMismatch {
        /// Program-header index.
        index: u16,
        /// ELF virtual address.
        virtual_address: u64,
        /// ELF physical address.
        physical_address: u64,
    },
    /// Segment alignment is not a supported power of two.
    InvalidSegmentAlignment {
        /// Program-header index.
        index: u16,
        /// Supplied alignment.
        alignment: u64,
    },
    /// Segment address and file offset violate ELF alignment congruence.
    MisalignedSegment {
        /// Program-header index.
        index: u16,
        /// Physical start address.
        address: u64,
        /// File offset.
        file_offset: u64,
        /// Declared alignment.
        alignment: u64,
    },
    /// Loadable program headers are not sorted by physical address.
    UnsortedSegments {
        /// Previous loadable program-header index.
        previous: u16,
        /// Current loadable program-header index.
        current: u16,
    },
    /// Page-rounded in-memory segment ranges overlap.
    OverlappingSegments {
        /// Previous loadable program-header index.
        previous: u16,
        /// Current loadable program-header index.
        current: u16,
    },
    /// Combined segment memory sizes overflowed.
    TotalLoadSizeOverflow,
    /// Combined segment memory exceeds the fixed loader budget.
    TotalLoadSizeTooLarge {
        /// Combined in-memory byte count.
        size: u64,
        /// Loader byte-count limit.
        maximum: u64,
    },
    /// Entry point lies outside the fixed kernel window.
    EntryOutsideLoadWindow {
        /// Supplied entry address.
        entry: u64,
    },
    /// Entry point is not contained by an executable load segment.
    EntryNotExecutable {
        /// Supplied entry address.
        entry: u64,
    },
}

/// Parses and validates an ELF64 kernel image without allocation.
///
/// # Errors
///
/// Returns a structured [`ParseError`] for every rejected file, address,
/// permission, alignment, or resource-bound invariant.
pub fn parse(bytes: &[u8]) -> Result<ValidatedElf<'_>, ParseError> {
    if bytes.len() < ELF_HEADER_SIZE {
        return Err(ParseError::Truncated {
            provided: bytes.len(),
            required: ELF_HEADER_SIZE,
        });
    }
    if bytes.len() > MAX_ELF_FILE_SIZE {
        return Err(ParseError::FileTooLarge {
            size: bytes.len(),
            maximum: MAX_ELF_FILE_SIZE,
        });
    }
    validate_identification(bytes)?;
    let header = parse_header(bytes)?;
    let load_segment_count = validate_program_headers(bytes, header)?;
    Ok(ValidatedElf {
        bytes,
        entry_point: header.entry,
        program_header_offset: header.program_header_offset,
        program_header_count: header.program_header_count,
        load_segment_count,
    })
}

fn parse_header(bytes: &[u8]) -> Result<ElfHeader, ParseError> {
    let truncated = ParseError::Truncated {
        provided: bytes.len(),
        required: ELF_HEADER_SIZE,
    };
    let object_type = read_u16(bytes, 16).ok_or(truncated)?;
    let machine = read_u16(bytes, 18).ok_or(truncated)?;
    let version = read_u32(bytes, 20).ok_or(truncated)?;
    let entry = read_u64(bytes, 24).ok_or(truncated)?;
    let program_header_offset = read_u64(bytes, 32).ok_or(truncated)?;
    let flags = read_u32(bytes, 48).ok_or(truncated)?;
    let header_size = read_u16(bytes, 52).ok_or(truncated)?;
    let program_header_size = read_u16(bytes, 54).ok_or(truncated)?;
    let program_header_count = read_u16(bytes, 56).ok_or(truncated)?;
    if object_type != ET_EXEC {
        return Err(ParseError::UnsupportedObjectType { object_type });
    }
    if machine != EM_X86_64 {
        return Err(ParseError::UnsupportedMachine { machine });
    }
    if version != EV_CURRENT_U32 {
        return Err(ParseError::UnsupportedVersion { version });
    }
    if flags != 0 {
        return Err(ParseError::UnsupportedElfFlags { flags });
    }
    if header_size != ELF_HEADER_SIZE_U16 {
        return Err(ParseError::InvalidHeaderSize {
            found: header_size,
            expected: ELF_HEADER_SIZE_U16,
        });
    }
    if program_header_size != PROGRAM_HEADER_SIZE_U16 {
        return Err(ParseError::InvalidProgramHeaderSize {
            found: program_header_size,
            expected: PROGRAM_HEADER_SIZE_U16,
        });
    }
    if program_header_count == 0 || program_header_count > MAX_PROGRAM_HEADERS {
        return Err(ParseError::InvalidProgramHeaderCount {
            count: program_header_count,
            maximum: MAX_PROGRAM_HEADERS,
        });
    }
    if program_header_offset < 64 {
        return Err(ParseError::ProgramHeaderTableOverlapsHeader {
            offset: program_header_offset,
        });
    }
    let table_size = u64::from(program_header_count)
        .checked_mul(56)
        .ok_or(ParseError::ProgramHeaderTableOverflow)?;
    let program_header_table_end = program_header_offset
        .checked_add(table_size)
        .ok_or(ParseError::ProgramHeaderTableOverflow)?;
    let file_size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if program_header_table_end > file_size {
        return Err(ParseError::ProgramHeaderTableOutOfBounds {
            end: program_header_table_end,
            file_size,
        });
    }
    let program_header_offset = usize::try_from(program_header_offset).map_err(|_| {
        ParseError::ProgramHeaderTableOutOfBounds {
            end: program_header_table_end,
            file_size,
        }
    })?;
    if !(MIN_LOAD_ADDRESS..MAX_LOAD_ADDRESS_EXCLUSIVE).contains(&entry) {
        return Err(ParseError::EntryOutsideLoadWindow { entry });
    }
    Ok(ElfHeader {
        entry,
        program_header_offset,
        program_header_count,
        program_header_table_end,
        file_size,
    })
}

fn validate_program_headers(bytes: &[u8], elf: ElfHeader) -> Result<u16, ParseError> {
    let mut load_count = 0_u16;
    let mut total_load_size = 0_u64;
    let mut previous: Option<(u16, u64, u64)> = None;
    let mut entry_is_executable = false;
    for index in 0..elf.program_header_count {
        let header = decode_program_header(bytes, elf.program_header_offset, index).ok_or(
            ParseError::ProgramHeaderTableOutOfBounds {
                end: elf.program_header_table_end,
                file_size: elf.file_size,
            },
        )?;
        if header.kind == PT_NULL {
            continue;
        }
        if header.kind != PT_LOAD {
            return Err(ParseError::UnsupportedProgramHeaderType {
                index,
                kind: header.kind,
            });
        }
        load_count += 1;
        if load_count > MAX_LOAD_SEGMENTS {
            return Err(ParseError::TooManyLoadSegments {
                count: load_count,
                maximum: MAX_LOAD_SEGMENTS,
            });
        }
        let end = validate_load_segment(index, header, elf.file_size)?;
        let page_end =
            align_up(end, PAGE_SIZE).ok_or(ParseError::SegmentMemoryRangeOverflow { index })?;
        if let Some((previous_index, previous_start, previous_end)) = previous {
            if header.physical_address < previous_start {
                return Err(ParseError::UnsortedSegments {
                    previous: previous_index,
                    current: index,
                });
            }
            if header.physical_address < previous_end {
                return Err(ParseError::OverlappingSegments {
                    previous: previous_index,
                    current: index,
                });
            }
        }
        previous = Some((index, header.physical_address, page_end));
        total_load_size = total_load_size
            .checked_add(header.memory_size)
            .ok_or(ParseError::TotalLoadSizeOverflow)?;
        if total_load_size > MAX_TOTAL_LOAD_SIZE {
            return Err(ParseError::TotalLoadSizeTooLarge {
                size: total_load_size,
                maximum: MAX_TOTAL_LOAD_SIZE,
            });
        }
        if header.flags & PF_X != 0
            && elf.entry >= header.virtual_address
            && elf.entry < header.virtual_address + header.memory_size
        {
            entry_is_executable = true;
        }
    }
    if load_count == 0 {
        return Err(ParseError::NoLoadSegments);
    }
    if !entry_is_executable {
        return Err(ParseError::EntryNotExecutable { entry: elf.entry });
    }
    Ok(load_count)
}

#[derive(Clone, Copy)]
struct ElfHeader {
    entry: u64,
    program_header_offset: usize,
    program_header_count: u16,
    program_header_table_end: u64,
    file_size: u64,
}

fn validate_identification(bytes: &[u8]) -> Result<(), ParseError> {
    if bytes.get(0..4) != Some(ELF_MAGIC.as_slice()) {
        return Err(ParseError::BadMagic);
    }
    if bytes[4] != ELFCLASS64 {
        return Err(ParseError::UnsupportedClass { class: bytes[4] });
    }
    if bytes[5] != ELFDATA2LSB {
        return Err(ParseError::UnsupportedByteOrder { encoding: bytes[5] });
    }
    if bytes[6] != EV_CURRENT_U8 {
        return Err(ParseError::UnsupportedIdentificationVersion { version: bytes[6] });
    }
    if bytes[7] != ELFOSABI_SYSV {
        return Err(ParseError::UnsupportedOsAbi { os_abi: bytes[7] });
    }
    if bytes[8] != 0 {
        return Err(ParseError::UnsupportedAbiVersion { version: bytes[8] });
    }
    if bytes[9..16].iter().any(|byte| *byte != 0) {
        return Err(ParseError::NonZeroIdentificationPadding);
    }
    Ok(())
}

fn validate_load_segment(
    index: u16,
    header: ProgramHeader,
    file_size: u64,
) -> Result<u64, ParseError> {
    if header.flags & !KNOWN_SEGMENT_FLAGS != 0 {
        return Err(ParseError::UnknownSegmentFlags {
            index,
            flags: header.flags,
        });
    }
    if header.flags & PF_R == 0 {
        return Err(ParseError::NonReadableSegment { index });
    }
    if header.flags & (PF_W | PF_X) == (PF_W | PF_X) {
        return Err(ParseError::WriteExecuteSegment { index });
    }
    if header.memory_size == 0 {
        return Err(ParseError::EmptyMemorySegment { index });
    }
    if header.file_size > header.memory_size {
        return Err(ParseError::FileLargerThanMemory {
            index,
            file_size: header.file_size,
            memory_size: header.memory_size,
        });
    }
    let file_end = header
        .file_offset
        .checked_add(header.file_size)
        .ok_or(ParseError::SegmentFileRangeOverflow { index })?;
    if file_end > file_size {
        return Err(ParseError::SegmentFileRangeOutOfBounds {
            index,
            end: file_end,
            file_size,
        });
    }
    if header.virtual_address != header.physical_address {
        return Err(ParseError::VirtualPhysicalAddressMismatch {
            index,
            virtual_address: header.virtual_address,
            physical_address: header.physical_address,
        });
    }
    if !header.alignment.is_power_of_two()
        || !(PAGE_SIZE..=MAX_SEGMENT_ALIGNMENT).contains(&header.alignment)
    {
        return Err(ParseError::InvalidSegmentAlignment {
            index,
            alignment: header.alignment,
        });
    }
    if header.physical_address % PAGE_SIZE != 0
        || header.physical_address % header.alignment != header.file_offset % header.alignment
    {
        return Err(ParseError::MisalignedSegment {
            index,
            address: header.physical_address,
            file_offset: header.file_offset,
            alignment: header.alignment,
        });
    }
    let end = header
        .physical_address
        .checked_add(header.memory_size)
        .ok_or(ParseError::SegmentMemoryRangeOverflow { index })?;
    if header.physical_address < MIN_LOAD_ADDRESS || end > MAX_LOAD_ADDRESS_EXCLUSIVE {
        return Err(ParseError::SegmentOutsideLoadWindow {
            index,
            start: header.physical_address,
            end,
        });
    }
    Ok(end)
}

fn load_segment_from_header(
    bytes: &[u8],
    index: u16,
    header: ProgramHeader,
) -> Option<LoadSegment<'_>> {
    let start = usize::try_from(header.file_offset).ok()?;
    let end = usize::try_from(header.file_offset.checked_add(header.file_size)?).ok()?;
    let file_data = bytes.get(start..end)?;
    Some(LoadSegment {
        index,
        flags: SegmentFlags(header.flags),
        file_offset: header.file_offset,
        virtual_address: header.virtual_address,
        physical_address: header.physical_address,
        file_size: header.file_size,
        memory_size: header.memory_size,
        alignment: header.alignment,
        file_data,
    })
}

#[derive(Clone, Copy)]
struct ProgramHeader {
    kind: u32,
    flags: u32,
    file_offset: u64,
    virtual_address: u64,
    physical_address: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
}

fn decode_program_header(bytes: &[u8], table_offset: usize, index: u16) -> Option<ProgramHeader> {
    let offset = table_offset.checked_add(usize::from(index).checked_mul(PROGRAM_HEADER_SIZE)?)?;
    Some(ProgramHeader {
        kind: read_u32(bytes, offset)?,
        flags: read_u32(bytes, offset + 4)?,
        file_offset: read_u64(bytes, offset + 8)?,
        virtual_address: read_u64(bytes, offset + 16)?,
        physical_address: read_u64(bytes, offset + 24)?,
        file_size: read_u64(bytes, offset + 32)?,
        memory_size: read_u64(bytes, offset + 40)?,
        alignment: read_u64(bytes, offset + 48)?,
    })
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment - 1)
        .map(|sum| sum & !(alignment - 1))
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(read_array(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(read_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(read_array(bytes, offset)?))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    let source = bytes.get(offset..end)?;
    let mut value = [0; N];
    value.copy_from_slice(source);
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn write_program_header(
        bytes: &mut [u8],
        index: usize,
        flags: u32,
        file_offset: u64,
        address: u64,
        file_size: u64,
        memory_size: u64,
    ) {
        let offset = ELF_HEADER_SIZE + index * PROGRAM_HEADER_SIZE;
        write_u32(bytes, offset, PT_LOAD);
        write_u32(bytes, offset + 4, flags);
        write_u64(bytes, offset + 8, file_offset);
        write_u64(bytes, offset + 16, address);
        write_u64(bytes, offset + 24, address);
        write_u64(bytes, offset + 32, file_size);
        write_u64(bytes, offset + 40, memory_size);
        write_u64(bytes, offset + 48, PAGE_SIZE);
    }

    fn valid_elf() -> Vec<u8> {
        let mut bytes = vec![0; 0x3000];
        bytes[..4].copy_from_slice(&ELF_MAGIC);
        bytes[4] = ELFCLASS64;
        bytes[5] = ELFDATA2LSB;
        bytes[6] = EV_CURRENT_U8;
        write_u16(&mut bytes, 16, ET_EXEC);
        write_u16(&mut bytes, 18, EM_X86_64);
        write_u32(&mut bytes, 20, EV_CURRENT_U32);
        write_u64(&mut bytes, 24, MIN_LOAD_ADDRESS);
        write_u64(&mut bytes, 32, ELF_HEADER_SIZE as u64);
        write_u16(&mut bytes, 52, ELF_HEADER_SIZE_U16);
        write_u16(&mut bytes, 54, PROGRAM_HEADER_SIZE_U16);
        write_u16(&mut bytes, 56, 2);
        write_program_header(
            &mut bytes,
            0,
            PF_R | PF_X,
            0x1000,
            MIN_LOAD_ADDRESS,
            0x100,
            0x800,
        );
        write_program_header(
            &mut bytes,
            1,
            PF_R | PF_W,
            0x2000,
            MIN_LOAD_ADDRESS + PAGE_SIZE,
            0x80,
            PAGE_SIZE,
        );
        bytes[0x1000] = 0xaa;
        bytes[0x2000] = 0xbb;
        bytes
    }

    fn fully_covered_elf() -> Vec<u8> {
        let mut bytes = valid_elf();
        let second = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE;
        write_u64(&mut bytes, second + 32, PAGE_SIZE);
        write_u64(&mut bytes, second + 40, PAGE_SIZE);
        bytes
    }

    fn mutation_mask(index: usize) -> u8 {
        let mut value = (index as u64).wrapping_add(0x243f_6a88_85a3_08d3);
        value ^= value >> 30;
        value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value ^= value >> 27;
        value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^= value >> 31;
        value.to_le_bytes()[0] | 1
    }

    fn assert_validated_invariants(bytes: &[u8], elf: ValidatedElf<'_>) {
        assert!((MIN_LOAD_ADDRESS..MAX_LOAD_ADDRESS_EXCLUSIVE).contains(&elf.entry_point()));
        let mut count = 0_u16;
        let mut total_memory_size = 0_u64;
        let mut previous_page_end = None;
        let mut entry_is_executable = false;
        for segment in elf.segments() {
            count += 1;
            assert!(segment.index() < MAX_PROGRAM_HEADERS);
            assert!(segment.flags().is_readable());
            assert!(!(segment.flags().is_writable() && segment.flags().is_executable()));
            assert_eq!(segment.flags().bits() & !KNOWN_SEGMENT_FLAGS, 0);
            assert_eq!(segment.virtual_address(), segment.physical_address());
            assert!(segment.memory_size() > 0);
            assert!(segment.file_size() <= segment.memory_size());
            assert!(segment.alignment().is_power_of_two());
            assert!((PAGE_SIZE..=MAX_SEGMENT_ALIGNMENT).contains(&segment.alignment()));
            assert_eq!(segment.physical_address() % PAGE_SIZE, 0);
            assert_eq!(
                segment.physical_address() % segment.alignment(),
                segment.file_offset() % segment.alignment()
            );

            let file_start = usize::try_from(segment.file_offset()).unwrap();
            let file_end = file_start
                .checked_add(usize::try_from(segment.file_size()).unwrap())
                .unwrap();
            assert!(file_end <= bytes.len());
            assert_eq!(segment.file_data(), &bytes[file_start..file_end]);
            assert_eq!(
                segment.zero_fill_size(),
                segment.memory_size() - segment.file_size()
            );

            let end = segment
                .physical_address()
                .checked_add(segment.memory_size())
                .unwrap();
            assert!(segment.physical_address() >= MIN_LOAD_ADDRESS);
            assert!(end <= MAX_LOAD_ADDRESS_EXCLUSIVE);
            let page_end = end
                .checked_add(PAGE_SIZE - 1)
                .map(|value| value & !(PAGE_SIZE - 1))
                .unwrap();
            if let Some(end_before) = previous_page_end {
                assert!(segment.physical_address() >= end_before);
            }
            previous_page_end = Some(page_end);
            total_memory_size = total_memory_size
                .checked_add(segment.memory_size())
                .unwrap();
            if segment.flags().is_executable()
                && (segment.virtual_address()..segment.virtual_address() + segment.memory_size())
                    .contains(&elf.entry_point())
            {
                entry_is_executable = true;
            }
        }
        assert_eq!(count, elf.segment_count());
        assert!(count > 0 && count <= MAX_LOAD_SEGMENTS);
        assert!(total_memory_size <= MAX_TOTAL_LOAD_SIZE);
        assert!(entry_is_executable);
    }

    #[test]
    fn validates_and_exposes_borrowed_segments() {
        let bytes = valid_elf();
        let elf = parse(&bytes).unwrap();
        assert_eq!(elf.entry_point(), MIN_LOAD_ADDRESS);
        assert_eq!(elf.segment_count(), 2);
        let segments: Vec<_> = elf.segments().collect();
        assert_eq!(segments.len(), 2);
        assert!(segments[0].flags().is_executable());
        assert!(!segments[0].flags().is_writable());
        assert_eq!(segments[0].file_data()[0], 0xaa);
        assert_eq!(segments[0].zero_fill_size(), 0x700);
        assert_eq!(segments[1].physical_address(), MIN_LOAD_ADDRESS + PAGE_SIZE);
    }

    #[test]
    fn every_required_byte_prefix_is_rejected_without_panicking() {
        let bytes = fully_covered_elf();
        assert!(parse(&bytes).is_ok());
        for length in 0..bytes.len() {
            assert!(
                parse(&bytes[..length]).is_err(),
                "prefix length {length} unexpectedly passed"
            );
        }
    }

    #[test]
    fn deterministic_single_byte_mutations_preserve_proven_invariants() {
        let original = fully_covered_elf();
        let mut accepted = 0;
        let mut rejected = 0;
        for index in 0..original.len() {
            let mut candidate = original.clone();
            candidate[index] ^= mutation_mask(index);
            match parse(&candidate) {
                Ok(elf) => {
                    accepted += 1;
                    assert_validated_invariants(&candidate, elf);
                }
                Err(_) => rejected += 1,
            }
        }

        // Payload mutations may remain valid, but structural mutations must
        // exercise rejection paths in the same deterministic corpus.
        assert!(accepted > 0);
        assert!(rejected > 0);
    }

    #[test]
    fn rejects_truncated_and_oversized_files() {
        assert_eq!(
            parse(&[0; ELF_HEADER_SIZE - 1]),
            Err(ParseError::Truncated {
                provided: ELF_HEADER_SIZE - 1,
                required: ELF_HEADER_SIZE,
            })
        );
        let huge = vec![0; MAX_ELF_FILE_SIZE + 1];
        assert_eq!(
            parse(&huge),
            Err(ParseError::FileTooLarge {
                size: MAX_ELF_FILE_SIZE + 1,
                maximum: MAX_ELF_FILE_SIZE,
            })
        );
    }

    #[test]
    fn rejects_wrong_identity_and_machine() {
        let mut bytes = valid_elf();
        bytes[0] = 0;
        assert_eq!(parse(&bytes), Err(ParseError::BadMagic));

        let mut bytes = valid_elf();
        bytes[5] = 2;
        assert_eq!(
            parse(&bytes),
            Err(ParseError::UnsupportedByteOrder { encoding: 2 })
        );

        let mut bytes = valid_elf();
        write_u16(&mut bytes, 18, 183);
        assert_eq!(
            parse(&bytes),
            Err(ParseError::UnsupportedMachine { machine: 183 })
        );
    }

    #[test]
    fn rejects_bad_program_header_table_bounds() {
        let mut bytes = valid_elf();
        write_u64(&mut bytes, 32, u64::MAX);
        assert_eq!(parse(&bytes), Err(ParseError::ProgramHeaderTableOverflow));

        let mut bytes = valid_elf();
        write_u16(&mut bytes, 56, MAX_PROGRAM_HEADERS + 1);
        assert_eq!(
            parse(&bytes),
            Err(ParseError::InvalidProgramHeaderCount {
                count: MAX_PROGRAM_HEADERS + 1,
                maximum: MAX_PROGRAM_HEADERS,
            })
        );
    }

    #[test]
    fn rejects_unknown_program_header_types() {
        let mut bytes = valid_elf();
        write_u32(&mut bytes, ELF_HEADER_SIZE, 3);
        assert_eq!(
            parse(&bytes),
            Err(ParseError::UnsupportedProgramHeaderType { index: 0, kind: 3 })
        );
    }

    #[test]
    fn rejects_file_and_memory_range_faults() {
        let mut bytes = valid_elf();
        write_u64(&mut bytes, ELF_HEADER_SIZE + 32, 0x900);
        write_u64(&mut bytes, ELF_HEADER_SIZE + 40, 0x800);
        assert_eq!(
            parse(&bytes),
            Err(ParseError::FileLargerThanMemory {
                index: 0,
                file_size: 0x900,
                memory_size: 0x800,
            })
        );

        let mut bytes = valid_elf();
        write_u64(&mut bytes, ELF_HEADER_SIZE + 8, u64::MAX);
        assert_eq!(
            parse(&bytes),
            Err(ParseError::SegmentFileRangeOverflow { index: 0 })
        );

        let mut bytes = valid_elf();
        write_u64(
            &mut bytes,
            ELF_HEADER_SIZE + 24,
            MIN_LOAD_ADDRESS - PAGE_SIZE,
        );
        write_u64(
            &mut bytes,
            ELF_HEADER_SIZE + 16,
            MIN_LOAD_ADDRESS - PAGE_SIZE,
        );
        assert!(matches!(
            parse(&bytes),
            Err(ParseError::SegmentOutsideLoadWindow { index: 0, .. })
        ));
    }

    #[test]
    fn file_and_load_window_boundaries_are_exact() {
        let mut bytes = valid_elf();
        write_u16(&mut bytes, 56, 1);
        let last_page = MAX_LOAD_ADDRESS_EXCLUSIVE - PAGE_SIZE;
        write_u64(&mut bytes, 24, last_page);
        write_program_header(
            &mut bytes,
            0,
            PF_R | PF_X,
            0x2000,
            last_page,
            PAGE_SIZE,
            PAGE_SIZE,
        );
        let elf = parse(&bytes).unwrap();
        assert_validated_invariants(&bytes, elf);
        assert_eq!(
            elf.segments().next().unwrap().file_data().len(),
            usize::try_from(PAGE_SIZE).unwrap()
        );

        let mut overflowing = valid_elf();
        write_u16(&mut overflowing, 56, 1);
        let overflowing_start = u64::MAX - (PAGE_SIZE - 1);
        write_program_header(
            &mut overflowing,
            0,
            PF_R | PF_X,
            0x1000,
            overflowing_start,
            1,
            PAGE_SIZE,
        );
        assert_eq!(
            parse(&overflowing),
            Err(ParseError::SegmentMemoryRangeOverflow { index: 0 })
        );

        for entry in [MIN_LOAD_ADDRESS - 1, MAX_LOAD_ADDRESS_EXCLUSIVE] {
            let mut invalid_entry = valid_elf();
            write_u64(&mut invalid_entry, 24, entry);
            assert_eq!(
                parse(&invalid_entry),
                Err(ParseError::EntryOutsideLoadWindow { entry })
            );
        }
    }

    #[test]
    fn aggregate_load_budget_accepts_limit_and_rejects_one_page_more() {
        let mut at_limit = valid_elf();
        write_u16(&mut at_limit, 56, 1);
        write_program_header(
            &mut at_limit,
            0,
            PF_R | PF_X,
            0,
            MIN_LOAD_ADDRESS,
            0,
            MAX_TOTAL_LOAD_SIZE,
        );
        let elf = parse(&at_limit).unwrap();
        assert_validated_invariants(&at_limit, elf);

        let mut over_limit = at_limit.clone();
        write_u16(&mut over_limit, 56, 2);
        write_program_header(
            &mut over_limit,
            1,
            PF_R | PF_W,
            0,
            MIN_LOAD_ADDRESS + MAX_TOTAL_LOAD_SIZE,
            0,
            PAGE_SIZE,
        );
        assert_eq!(
            parse(&over_limit),
            Err(ParseError::TotalLoadSizeTooLarge {
                size: MAX_TOTAL_LOAD_SIZE + PAGE_SIZE,
                maximum: MAX_TOTAL_LOAD_SIZE,
            })
        );
    }

    #[test]
    fn malformed_header_and_segment_regression_seeds_fail_closed() {
        let mut seeds = Vec::new();

        let mut zero_headers = valid_elf();
        write_u16(&mut zero_headers, 56, 0);
        seeds.push(("zero program headers", zero_headers));

        let mut overlapping_header = valid_elf();
        write_u64(&mut overlapping_header, 32, ELF_HEADER_SIZE as u64 - 1);
        seeds.push(("header table overlap", overlapping_header));

        let mut no_load_segments = valid_elf();
        write_u32(&mut no_load_segments, ELF_HEADER_SIZE, PT_NULL);
        write_u32(
            &mut no_load_segments,
            ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE,
            PT_NULL,
        );
        seeds.push(("no load segments", no_load_segments));

        let mut unknown_flags = valid_elf();
        write_u32(&mut unknown_flags, ELF_HEADER_SIZE + 4, 1 << 31);
        seeds.push(("unknown permission flag", unknown_flags));

        let mut empty_memory = valid_elf();
        write_u64(&mut empty_memory, ELF_HEADER_SIZE + 40, 0);
        seeds.push(("zero memory extent", empty_memory));

        let mut file_overflow = valid_elf();
        write_u64(&mut file_overflow, ELF_HEADER_SIZE + 8, u64::MAX);
        write_u64(&mut file_overflow, ELF_HEADER_SIZE + 32, 2);
        seeds.push(("file range overflow", file_overflow));

        for (name, seed) in seeds {
            let outcome = std::panic::catch_unwind(|| parse(&seed).is_err());
            match outcome {
                Ok(true) => {}
                Ok(false) => panic!("regression seed `{name}` was accepted"),
                Err(payload) => {
                    drop(payload);
                    panic!("regression seed `{name}` caused a parser panic");
                }
            }
        }
    }

    #[test]
    fn enforces_identity_alignment_and_write_xor_execute() {
        let mut bytes = valid_elf();
        write_u64(
            &mut bytes,
            ELF_HEADER_SIZE + 16,
            MIN_LOAD_ADDRESS + PAGE_SIZE,
        );
        assert!(matches!(
            parse(&bytes),
            Err(ParseError::VirtualPhysicalAddressMismatch { index: 0, .. })
        ));

        let mut bytes = valid_elf();
        write_u64(&mut bytes, ELF_HEADER_SIZE + 48, 3);
        assert_eq!(
            parse(&bytes),
            Err(ParseError::InvalidSegmentAlignment {
                index: 0,
                alignment: 3,
            })
        );

        let mut bytes = valid_elf();
        write_u32(&mut bytes, ELF_HEADER_SIZE + 4, PF_R | PF_W | PF_X);
        assert_eq!(
            parse(&bytes),
            Err(ParseError::WriteExecuteSegment { index: 0 })
        );
    }

    #[test]
    fn rejects_unsorted_and_page_overlapping_segments() {
        let mut bytes = valid_elf();
        let first = MIN_LOAD_ADDRESS + 2 * PAGE_SIZE;
        write_u64(&mut bytes, ELF_HEADER_SIZE + 16, first);
        write_u64(&mut bytes, ELF_HEADER_SIZE + 24, first);
        write_u64(&mut bytes, 24, first);
        assert_eq!(
            parse(&bytes),
            Err(ParseError::UnsortedSegments {
                previous: 0,
                current: 1,
            })
        );

        let mut bytes = valid_elf();
        let second = MIN_LOAD_ADDRESS;
        let offset = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE;
        write_u64(&mut bytes, offset + 16, second);
        write_u64(&mut bytes, offset + 24, second);
        assert_eq!(
            parse(&bytes),
            Err(ParseError::OverlappingSegments {
                previous: 0,
                current: 1,
            })
        );
    }

    #[test]
    fn entry_must_be_in_an_executable_segment() {
        let mut bytes = valid_elf();
        write_u64(&mut bytes, 24, MIN_LOAD_ADDRESS + PAGE_SIZE);
        assert_eq!(
            parse(&bytes),
            Err(ParseError::EntryNotExecutable {
                entry: MIN_LOAD_ADDRESS + PAGE_SIZE,
            })
        );
    }

    #[test]
    fn load_segment_count_accepts_limit_and_rejects_one_more() {
        let mut bytes = vec![0; 0xb000];
        bytes[..ELF_HEADER_SIZE].copy_from_slice(&valid_elf()[..ELF_HEADER_SIZE]);
        write_u16(&mut bytes, 56, MAX_LOAD_SEGMENTS);
        for index in 0..usize::from(MAX_LOAD_SEGMENTS) {
            write_program_header(
                &mut bytes,
                index,
                PF_R | if index == 0 { PF_X } else { PF_W },
                0x1000 + index as u64 * PAGE_SIZE,
                MIN_LOAD_ADDRESS + index as u64 * PAGE_SIZE,
                1,
                PAGE_SIZE,
            );
        }
        let at_limit = parse(&bytes).unwrap();
        assert_eq!(at_limit.segment_count(), MAX_LOAD_SEGMENTS);
        assert_validated_invariants(&bytes, at_limit);

        write_u16(&mut bytes, 56, MAX_LOAD_SEGMENTS + 1);
        let index = usize::from(MAX_LOAD_SEGMENTS);
        write_program_header(
            &mut bytes,
            index,
            PF_R | PF_W,
            0x1000 + index as u64 * PAGE_SIZE,
            MIN_LOAD_ADDRESS + index as u64 * PAGE_SIZE,
            1,
            PAGE_SIZE,
        );
        assert_eq!(
            parse(&bytes),
            Err(ParseError::TooManyLoadSegments {
                count: MAX_LOAD_SEGMENTS + 1,
                maximum: MAX_LOAD_SEGMENTS,
            })
        );
    }
}
