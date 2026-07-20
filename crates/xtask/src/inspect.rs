//! Host-side kernel ELF and linker-map inspection.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use polytope_boot_elf::{
    KERNEL_BASE_ADDRESS, KERNEL_LOAD_LIMIT, MAX_ELF_FILE_SIZE, PAGE_SIZE, STACK_BASE_ADDRESS,
    STACK_GUARD_ADDRESS, STACK_SIZE_BYTES, parse,
};
use serde::{Deserialize, Serialize};

use crate::sha256_hex;

const MAX_MAP_FILE_SIZE: usize = 4 * 1024 * 1024;
const EXPECTED_SEGMENTS: usize = 4;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// Inputs to the host-side kernel layout inspector.
#[derive(Clone, Debug)]
pub struct InspectionRequest {
    /// Linked `x86_64` kernel ELF.
    pub kernel: PathBuf,
    /// LLD textual linker map emitted for that kernel build.
    pub map: PathBuf,
}

/// One validated `PT_LOAD` record included in inspection evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SegmentInspection {
    /// Original ELF program-header index.
    pub index: u16,
    /// ELF R/W/X flag bits.
    pub flags: u32,
    /// Initialized data offset in the ELF file.
    pub file_offset: u64,
    /// Identity-mapped virtual address.
    pub virtual_address: u64,
    /// Physical load address.
    pub physical_address: u64,
    /// Initialized byte count.
    pub file_size: u64,
    /// In-memory byte count.
    pub memory_size: u64,
    /// Zero-filled byte count.
    pub zero_fill_size: u64,
    /// Required load alignment.
    pub alignment: u64,
}

/// One output section recovered from the linker map.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SectionInspection {
    /// Linker output-section name.
    pub name: String,
    /// Section virtual address.
    pub address: u64,
    /// Section byte length.
    pub size: u64,
}

/// Machine-readable proof of the kernel layout invariants.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KernelInspection {
    /// Report schema version.
    pub schema_version: u32,
    /// SHA-256 digest of the inspected ELF.
    pub kernel_sha256: String,
    /// SHA-256 digest of the inspected linker map.
    pub map_sha256: String,
    /// ELF file byte length.
    pub kernel_bytes: u64,
    /// Linker-map byte length.
    pub map_bytes: u64,
    /// Validated kernel entry point.
    pub entry_point: u64,
    /// Fixed kernel base.
    pub kernel_base: u64,
    /// Page-rounded end of initialized kernel sections.
    pub kernel_load_end: u64,
    /// First byte of the reserved stack guard (hardware unmapping is Sprint 03).
    pub stack_guard_base: u64,
    /// Guard-page byte length.
    pub stack_guard_bytes: u64,
    /// First stack byte.
    pub stack_base: u64,
    /// Exclusive stack end.
    pub stack_top: u64,
    /// `.bss` start from the linker map.
    pub bss_start: u64,
    /// Exclusive `.bss` end.
    pub bss_end: u64,
    /// Bytes zero-filled by the data segment, including alignment padding.
    pub data_zero_fill_bytes: u64,
    /// Whether every segment has its exact expected non-W+X role.
    pub write_xor_execute: bool,
    /// Validated load segments in physical-address order.
    pub segments: Vec<SegmentInspection>,
    /// Required linker output sections in map order.
    pub sections: Vec<SectionInspection>,
}

/// Reads bounded artifacts and validates their combined linker/ELF contract.
///
/// # Errors
///
/// Returns an error when either input is missing, oversized, malformed, or
/// violates an address, permission, entry, BSS, guard, stack, or ordering
/// invariant.
pub fn inspect_kernel(request: &InspectionRequest) -> Result<KernelInspection> {
    let kernel = read_bounded(&request.kernel, MAX_ELF_FILE_SIZE, "kernel ELF")?;
    let map = read_bounded(&request.map, MAX_MAP_FILE_SIZE, "kernel linker map")?;
    inspect_kernel_bytes(&kernel, &map)
}

/// Validates a kernel and linker map already resident in memory.
///
/// # Errors
///
/// Returns an error for the same malformed or inconsistent inputs as
/// [`inspect_kernel`].
pub fn inspect_kernel_bytes(kernel: &[u8], map: &[u8]) -> Result<KernelInspection> {
    ensure!(
        kernel.len() <= MAX_ELF_FILE_SIZE,
        "kernel ELF is {} bytes; maximum is {MAX_ELF_FILE_SIZE}",
        kernel.len()
    );
    ensure!(
        map.len() <= MAX_MAP_FILE_SIZE,
        "kernel linker map is {} bytes; maximum is {MAX_MAP_FILE_SIZE}",
        map.len()
    );
    ensure!(!map.contains(&0), "kernel linker map contains a NUL byte");
    let map_text = std::str::from_utf8(map).context("kernel linker map is not valid UTF-8")?;
    let elf = parse(kernel).map_err(|error| anyhow::anyhow!("kernel ELF rejected: {error:?}"))?;
    let map_layout = MapLayout::parse(map_text)?;
    let segments: Vec<SegmentInspection> = elf
        .segments()
        .map(|segment| SegmentInspection {
            index: segment.index(),
            flags: segment.flags().bits(),
            file_offset: segment.file_offset(),
            virtual_address: segment.virtual_address(),
            physical_address: segment.physical_address(),
            file_size: segment.file_size(),
            memory_size: segment.memory_size(),
            zero_fill_size: segment.zero_fill_size(),
            alignment: segment.alignment(),
        })
        .collect();
    validate_combined(elf.entry_point(), &segments, &map_layout)?;

    let bss = map_layout.section(".bss")?;
    let kernel_load_end = align_up(bss.end()?, PAGE_SIZE)?;
    Ok(KernelInspection {
        schema_version: 1,
        kernel_sha256: sha256_hex(kernel),
        map_sha256: sha256_hex(map),
        kernel_bytes: u64::try_from(kernel.len()).context("kernel byte count does not fit u64")?,
        map_bytes: u64::try_from(map.len()).context("map byte count does not fit u64")?,
        entry_point: elf.entry_point(),
        kernel_base: KERNEL_BASE_ADDRESS,
        kernel_load_end,
        stack_guard_base: STACK_GUARD_ADDRESS,
        stack_guard_bytes: PAGE_SIZE,
        stack_base: STACK_BASE_ADDRESS,
        stack_top: STACK_BASE_ADDRESS + STACK_SIZE_BYTES,
        bss_start: bss.address,
        bss_end: bss.end()?,
        data_zero_fill_bytes: segments[2].zero_fill_size,
        write_xor_execute: true,
        segments,
        sections: map_layout.report_sections(),
    })
}

fn validate_combined(
    entry_point: u64,
    segments: &[SegmentInspection],
    map: &MapLayout,
) -> Result<()> {
    ensure!(
        segments.len() == EXPECTED_SEGMENTS,
        "kernel has {} PT_LOAD records; expected {EXPECTED_SEGMENTS}",
        segments.len()
    );
    ensure!(
        entry_point == KERNEL_BASE_ADDRESS,
        "kernel entry point is {entry_point:#x}; expected {KERNEL_BASE_ADDRESS:#x}"
    );
    map.validate_constants_and_symbols(entry_point)?;
    validate_section_order(map)?;

    let text = map.section(".text")?;
    let rodata = map.section(".rodata")?;
    let data = map.section(".data")?;
    let bss = map.section(".bss")?;
    let guard = map.section(".stack_guard")?;
    let stack = map.section(".stack")?;
    ensure!(
        text.address == KERNEL_BASE_ADDRESS && text.size > 0,
        ".text does not start at the non-empty kernel base"
    );
    ensure!(
        rodata.address % PAGE_SIZE == 0 && rodata.size > 0,
        ".rodata is empty or misaligned"
    );
    ensure!(
        data.address % PAGE_SIZE == 0 && data.size > 0,
        ".data is empty or misaligned"
    );
    ensure!(
        bss.address % PAGE_SIZE == 0 && bss.size > 0,
        ".bss is empty or misaligned"
    );
    ensure!(text.end()? <= rodata.address, ".text overlaps .rodata");
    ensure!(rodata.end()? <= data.address, ".rodata overlaps .data");
    ensure!(data.end()? <= bss.address, ".data overlaps .bss");
    ensure!(
        guard.address == STACK_GUARD_ADDRESS && guard.size == PAGE_SIZE,
        "stack guard must be one page at {STACK_GUARD_ADDRESS:#x}"
    );
    ensure!(
        stack.address == STACK_BASE_ADDRESS && stack.size == STACK_SIZE_BYTES,
        "bootstrap stack must be {STACK_SIZE_BYTES:#x} bytes at {STACK_BASE_ADDRESS:#x}"
    );
    ensure!(
        align_up(bss.end()?, PAGE_SIZE)? <= STACK_GUARD_ADDRESS,
        "kernel load sections overlap the stack guard"
    );

    validate_segment(&segments[0], text, PF_R | PF_X, true)?;
    validate_segment(&segments[1], rodata, PF_R, true)?;
    validate_data_segment(&segments[2], data, bss)?;
    validate_stack_segment(&segments[3], stack)?;
    ensure!(
        segments.iter().all(|segment| {
            segment
                .physical_address
                .checked_add(segment.memory_size)
                .is_some_and(|end| {
                    end <= STACK_GUARD_ADDRESS || segment.physical_address >= STACK_BASE_ADDRESS
                })
        }),
        "a PT_LOAD range maps the bootstrap-stack guard page"
    );
    Ok(())
}

fn validate_segment(
    segment: &SegmentInspection,
    section: &MapSection,
    flags: u32,
    exact_memory_size: bool,
) -> Result<()> {
    ensure!(
        segment.flags == flags,
        "{} PT_LOAD flags are {:#x}; expected {flags:#x}",
        section.name,
        segment.flags
    );
    ensure!(
        segment.physical_address == section.address,
        "{} PT_LOAD address differs from the linker map",
        section.name
    );
    ensure!(
        segment.virtual_address == segment.physical_address,
        "{} PT_LOAD is not identity mapped",
        section.name
    );
    ensure!(
        segment.file_size == section.size,
        "{} initialized size differs from the linker map",
        section.name
    );
    if exact_memory_size {
        ensure!(
            segment.memory_size == section.size,
            "{} memory size contains unexpected zero fill",
            section.name
        );
    }
    ensure!(
        segment.alignment == PAGE_SIZE,
        "{} PT_LOAD is not page aligned",
        section.name
    );
    Ok(())
}

fn validate_data_segment(
    segment: &SegmentInspection,
    data: &MapSection,
    bss: &MapSection,
) -> Result<()> {
    validate_segment(segment, data, PF_R | PF_W, false)?;
    ensure!(
        segment.zero_fill_size >= bss.size,
        "data PT_LOAD does not reserve all .bss bytes"
    );
    ensure!(
        segment.physical_address.checked_add(segment.memory_size) == Some(bss.end()?),
        "data PT_LOAD memory end differs from .bss end"
    );
    ensure!(
        segment.physical_address.checked_add(segment.file_size) == Some(data.end()?),
        "data PT_LOAD file end differs from .data end"
    );
    Ok(())
}

fn validate_stack_segment(segment: &SegmentInspection, stack: &MapSection) -> Result<()> {
    ensure!(
        segment.flags == PF_R | PF_W,
        "stack PT_LOAD must be readable, writable, and non-executable"
    );
    ensure!(
        segment.physical_address == STACK_BASE_ADDRESS
            && segment.virtual_address == STACK_BASE_ADDRESS,
        "stack PT_LOAD starts at the wrong address"
    );
    ensure!(
        segment.file_size == 0,
        "stack PT_LOAD must not consume initialized file bytes"
    );
    ensure!(
        segment.memory_size == STACK_SIZE_BYTES && segment.zero_fill_size == STACK_SIZE_BYTES,
        "stack PT_LOAD has the wrong reservation size"
    );
    ensure!(
        segment.alignment == PAGE_SIZE,
        "stack PT_LOAD is not page aligned"
    );
    ensure!(
        stack.end()? == STACK_BASE_ADDRESS + STACK_SIZE_BYTES,
        "linker-map stack end is incorrect"
    );
    Ok(())
}

fn validate_section_order(map: &MapLayout) -> Result<()> {
    let names = [
        ".text",
        ".rodata",
        ".data",
        ".bss",
        ".stack_guard",
        ".stack",
    ];
    let mut previous_line = None;
    for name in names {
        let section = map.section(name)?;
        if let Some(previous) = previous_line {
            ensure!(
                section.line > previous,
                "linker-map section {name} is out of order"
            );
        }
        previous_line = Some(section.line);
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct MapSection {
    name: String,
    address: u64,
    size: u64,
    line: usize,
}

impl MapSection {
    fn end(&self) -> Result<u64> {
        self.address
            .checked_add(self.size)
            .with_context(|| format!("{} end address overflowed", self.name))
    }

    fn report(&self) -> SectionInspection {
        SectionInspection {
            name: self.name.clone(),
            address: self.address,
            size: self.size,
        }
    }
}

struct MapLayout {
    sections: BTreeMap<String, MapSection>,
    constants: BTreeMap<String, u64>,
    symbols: BTreeMap<String, u64>,
    saw_load_end_expression: bool,
}

impl MapLayout {
    fn parse(text: &str) -> Result<Self> {
        let section_names = [
            ".text",
            ".rodata",
            ".data",
            ".bss",
            ".stack_guard",
            ".stack",
        ];
        let constant_names = [
            "KERNEL_BASE",
            "KERNEL_LOAD_LIMIT",
            "KERNEL_STACK_GUARD_BASE",
            "KERNEL_STACK_BASE",
            "KERNEL_STACK_SIZE",
            "PAGE_SIZE",
        ];
        let symbol_names = [
            "__kernel_start",
            "__text_start",
            "__text_end",
            "__rodata_start",
            "__rodata_end",
            "__data_start",
            "__data_end",
            "__bss_start",
            "__bss_end",
            "__bootstrap_stack_guard_start",
            "__bootstrap_stack_guard_end",
            "__bootstrap_stack_bottom",
            "__bootstrap_stack_top",
            "__kernel_end",
            "polytope_kernel_entry",
        ];
        let mut sections = BTreeMap::new();
        let mut constants = BTreeMap::new();
        let mut symbols = BTreeMap::new();
        let mut saw_load_end_expression = false;
        for (line_index, line) in text.lines().enumerate() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 5 {
                continue;
            }
            let name = fields[4];
            ensure!(
                !matches!(
                    name,
                    ".interp"
                        | ".dynamic"
                        | ".dynsym"
                        | ".dynstr"
                        | ".rela.dyn"
                        | ".rel.dyn"
                        | ".plt"
                        | ".got.plt"
                ),
                "kernel linker map contains forbidden dynamic output section {name}"
            );
            if section_names.contains(&name) {
                let section = MapSection {
                    name: String::from(name),
                    address: parse_hex(fields[0], line_index + 1)?,
                    size: parse_hex(fields[2], line_index + 1)?,
                    line: line_index + 1,
                };
                insert_unique(&mut sections, name, section, "section")?;
            } else if constant_names.contains(&name) && fields.get(5) == Some(&"=") {
                let value = fields.get(6).with_context(|| {
                    format!("map line {} omits value for {name}", line_index + 1)
                })?;
                insert_unique(
                    &mut constants,
                    name,
                    parse_hex(value, line_index + 1)?,
                    "constant",
                )?;
            } else if symbol_names.contains(&name) {
                insert_unique(
                    &mut symbols,
                    name,
                    parse_hex(fields[0], line_index + 1)?,
                    "symbol",
                )?;
            }
            if is_kernel_load_end_expression(&fields) {
                saw_load_end_expression = true;
            }
        }
        let layout = Self {
            sections,
            constants,
            symbols,
            saw_load_end_expression,
        };
        for name in section_names {
            let _ = layout.section(name)?;
        }
        Ok(layout)
    }

    fn section(&self, name: &str) -> Result<&MapSection> {
        self.sections
            .get(name)
            .with_context(|| format!("linker map is missing output section {name}"))
    }

    fn report_sections(&self) -> Vec<SectionInspection> {
        let names = [
            ".text",
            ".rodata",
            ".data",
            ".bss",
            ".stack_guard",
            ".stack",
        ];
        names
            .iter()
            .filter_map(|name| self.sections.get(*name))
            .map(MapSection::report)
            .collect()
    }

    fn validate_constants_and_symbols(&self, entry_point: u64) -> Result<()> {
        let expected_constants = [
            ("KERNEL_BASE", KERNEL_BASE_ADDRESS),
            ("KERNEL_LOAD_LIMIT", KERNEL_LOAD_LIMIT),
            ("KERNEL_STACK_GUARD_BASE", STACK_GUARD_ADDRESS),
            ("KERNEL_STACK_BASE", STACK_BASE_ADDRESS),
            ("KERNEL_STACK_SIZE", STACK_SIZE_BYTES),
            ("PAGE_SIZE", PAGE_SIZE),
        ];
        for (name, expected) in expected_constants {
            let actual = self
                .constants
                .get(name)
                .with_context(|| format!("linker map is missing constant {name}"))?;
            ensure!(
                *actual == expected,
                "linker constant {name} is {actual:#x}; expected {expected:#x}"
            );
        }
        let text = self.section(".text")?;
        let rodata = self.section(".rodata")?;
        let data = self.section(".data")?;
        let bss = self.section(".bss")?;
        let expected_symbols = [
            ("__kernel_start", KERNEL_BASE_ADDRESS),
            ("__text_start", text.address),
            ("__text_end", text.end()?),
            ("__rodata_start", rodata.address),
            ("__rodata_end", rodata.end()?),
            ("__data_start", data.address),
            ("__data_end", data.end()?),
            ("__bss_start", bss.address),
            ("__bss_end", bss.end()?),
            ("__bootstrap_stack_guard_start", STACK_GUARD_ADDRESS),
            ("__bootstrap_stack_guard_end", STACK_BASE_ADDRESS),
            ("__bootstrap_stack_bottom", STACK_BASE_ADDRESS),
            (
                "__bootstrap_stack_top",
                STACK_BASE_ADDRESS + STACK_SIZE_BYTES,
            ),
            ("__kernel_end", STACK_BASE_ADDRESS + STACK_SIZE_BYTES),
            ("polytope_kernel_entry", entry_point),
        ];
        for (name, expected) in expected_symbols {
            let actual = self
                .symbols
                .get(name)
                .with_context(|| format!("linker map is missing symbol {name}"))?;
            ensure!(
                *actual == expected,
                "linker symbol {name} is {actual:#x}; expected {expected:#x}"
            );
        }
        ensure!(
            self.saw_load_end_expression,
            "linker map is missing the page-aligned __kernel_load_end expression"
        );
        Ok(())
    }
}

fn is_kernel_load_end_expression(fields: &[&str]) -> bool {
    fields
        .windows(3)
        .any(|window| window == ["__kernel_load_end", "=", "ALIGN(PAGE_SIZE)"])
        || fields
            .windows(6)
            .any(|window| window == ["__kernel_load_end", "=", "ALIGN", "(", "PAGE_SIZE", ")"])
}

fn insert_unique<T>(
    values: &mut BTreeMap<String, T>,
    name: &str,
    value: T,
    description: &str,
) -> Result<()> {
    ensure!(
        values.insert(String::from(name), value).is_none(),
        "linker map contains duplicate {description} {name}"
    );
    Ok(())
}

fn parse_hex(value: &str, line: usize) -> Result<u64> {
    let digits = value.strip_prefix("0x").unwrap_or(value);
    ensure!(
        !digits.is_empty(),
        "empty hexadecimal value on map line {line}"
    );
    u64::from_str_radix(digits, 16)
        .with_context(|| format!("invalid hexadecimal value {value:?} on map line {line}"))
}

fn align_up(value: u64, alignment: u64) -> Result<u64> {
    ensure!(
        alignment.is_power_of_two(),
        "alignment must be a power of two"
    );
    value
        .checked_add(alignment - 1)
        .map(|sum| sum & !(alignment - 1))
        .context("address alignment overflowed")
}

fn read_bounded(path: &Path, maximum: usize, description: &str) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to inspect {description} {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "{description} is not a regular file: {}",
        path.display()
    );
    ensure!(
        metadata.len() <= u64::try_from(maximum).context("input size bound does not fit u64")?,
        "{description} is {} bytes; maximum is {maximum}",
        metadata.len()
    );
    fs::read(path).with_context(|| format!("failed to read {description} {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::{KERNEL_BASE_ADDRESS, STACK_GUARD_ADDRESS, inspect_kernel_bytes};

    const ELF_HEADER_SIZE: usize = 64;
    const PROGRAM_HEADER_SIZE: usize = 56;

    #[test]
    fn validates_exact_elf_and_map_contract() {
        let report = inspect_kernel_bytes(&valid_elf(), valid_map().as_bytes()).unwrap();
        assert_eq!(report.entry_point, KERNEL_BASE_ADDRESS);
        assert_eq!(report.segments.len(), 4);
        assert_eq!(report.stack_guard_base, STACK_GUARD_ADDRESS);
        assert!(report.write_xor_execute);
    }

    #[test]
    fn rejects_missing_and_duplicate_map_records() {
        let missing = valid_map().replace("__bss_end", "__wrong_bss_end");
        let error = inspect_kernel_bytes(&valid_elf(), missing.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(error.contains("missing symbol __bss_end"));

        let duplicate = format!("{}4000000 4000000 100 16 .text\n", valid_map());
        let error = inspect_kernel_bytes(&valid_elf(), duplicate.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(error.contains("duplicate section .text"));
    }

    #[test]
    fn rejects_guard_and_map_syntax_faults() {
        let wrong_guard = valid_map().replace(
            "47ff000 47ff000 1000 1 .stack_guard",
            "47ff000 47ff000 2000 1 .stack_guard",
        );
        let error = inspect_kernel_bytes(&valid_elf(), wrong_guard.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(error.contains("stack guard must be one page"));

        let bad_hex = valid_map().replace(
            "0 0 0 1 KERNEL_BASE = 0x04000000",
            "0 0 0 1 KERNEL_BASE = xyz",
        );
        let error = inspect_kernel_bytes(&valid_elf(), bad_hex.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(error.contains("invalid hexadecimal"));
    }

    fn valid_map() -> String {
        String::from(
            "VMA LMA Size Align Out In Symbol\n\
0 0 0 1 KERNEL_BASE = 0x04000000\n\
0 0 0 1 KERNEL_LOAD_LIMIT = 0x04800000\n\
0 0 0 1 KERNEL_STACK_GUARD_BASE = 0x047ff000\n\
0 0 0 1 KERNEL_STACK_BASE = 0x04800000\n\
0 0 0 1 KERNEL_STACK_SIZE = 0x00010000\n\
0 0 0 1 PAGE_SIZE = 0x1000\n\
4000000 0 0 1 __kernel_start = .\n\
4000000 4000000 100 16 .text\n\
4000000 4000000 0 1 __text_start = .\n\
4000000 4000000 40 1 polytope_kernel_entry\n\
4000100 4000100 0 1 __text_end = .\n\
4001000 4001000 80 8 .rodata\n\
4001000 4001000 0 1 __rodata_start = .\n\
4001080 4001080 0 1 __rodata_end = .\n\
4002000 4002000 20 8 .data\n\
4002000 4002000 0 1 __data_start = .\n\
4002020 4002020 0 1 __data_end = .\n\
4003000 4003000 8 8 .bss\n\
4003000 4003000 0 1 __bss_start = .\n\
4003008 4003008 0 1 __bss_end = .\n\
4003008 4003008 0 1 __kernel_load_end = ALIGN ( PAGE_SIZE )\n\
47ff000 47ff000 1000 1 .stack_guard\n\
47ff000 47ff000 0 1 __bootstrap_stack_guard_start = .\n\
4800000 4800000 0 1 __bootstrap_stack_guard_end = .\n\
4800000 4800000 10000 1 .stack\n\
4800000 4800000 0 1 __bootstrap_stack_bottom = .\n\
4810000 4810000 0 1 __bootstrap_stack_top = .\n\
4810000 4810000 0 1 __kernel_end = ALIGN(PAGE_SIZE)\n",
        )
    }

    fn valid_elf() -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x4000];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        write_u16(&mut bytes, 16, 2);
        write_u16(&mut bytes, 18, 62);
        write_u32(&mut bytes, 20, 1);
        write_u64(&mut bytes, 24, KERNEL_BASE_ADDRESS);
        write_u64(&mut bytes, 32, ELF_HEADER_SIZE as u64);
        write_u16(&mut bytes, 52, u16::try_from(ELF_HEADER_SIZE).unwrap());
        write_u16(&mut bytes, 54, u16::try_from(PROGRAM_HEADER_SIZE).unwrap());
        write_u16(&mut bytes, 56, 4);
        write_program_header(&mut bytes, 0, 5, 0x1000, KERNEL_BASE_ADDRESS, 0x100, 0x100);
        write_program_header(
            &mut bytes,
            1,
            4,
            0x2000,
            KERNEL_BASE_ADDRESS + 0x1000,
            0x80,
            0x80,
        );
        write_program_header(
            &mut bytes,
            2,
            6,
            0x3000,
            KERNEL_BASE_ADDRESS + 0x2000,
            0x20,
            0x1008,
        );
        write_program_header(&mut bytes, 3, 6, 0x4000, 0x0480_0000, 0, 0x1_0000);
        bytes
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
        write_u32(bytes, offset, 1);
        write_u32(bytes, offset + 4, flags);
        write_u64(bytes, offset + 8, file_offset);
        write_u64(bytes, offset + 16, address);
        write_u64(bytes, offset + 24, address);
        write_u64(bytes, offset + 32, file_size);
        write_u64(bytes, offset + 40, memory_size);
        write_u64(bytes, offset + 48, 0x1000);
    }

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
