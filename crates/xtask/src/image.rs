//! Deterministic GPT/FAT image construction and validation.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, bail, ensure};
use fatfs::{
    Date, DateTime, FatType, FileSystem, FormatVolumeOptions, FsOptions, Time, TimeProvider,
};
use gpt::disk::LogicalBlockSize;
use gpt::mbr::ProtectiveMBR;
use gpt::partition::Partition;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::sha256_hex;

/// Exact raw disk size emitted by the image builder.
pub const DISK_BYTES: usize = 64 * 1024 * 1024;
/// Logical block size used by both GPT and FAT.
pub const LOGICAL_BLOCK_BYTES: usize = 512;
/// First ESP LBA, aligned to one MiB.
pub const ESP_FIRST_LBA: u64 = 2_048;
/// Last ESP LBA, inclusive. The exclusive end is also one-MiB aligned.
pub const ESP_LAST_LBA: u64 = 129_023;
/// Stable FAT volume identifier (`PTOS`).
pub const FAT_VOLUME_ID: u32 = 0x5054_4f53;
/// Stable FAT volume label, padded to the required eleven bytes.
pub const FAT_VOLUME_LABEL: [u8; 11] = *b"POLYTOPEOS ";
const FAT_VOLUME_LABEL_VISIBLE: &[u8] = b"POLYTOPEOS";
const FAT32_VOLUME_LABEL_OFFSET: usize = 71;
/// UEFI removable-media loader path inside the ESP.
pub const LOADER_IMAGE_PATH: &str = "EFI/BOOT/BOOTX64.EFI";
/// Kernel payload path inside the ESP.
pub const KERNEL_IMAGE_PATH: &str = "POLYTOPE/KERNEL.ELF";
/// Boot-test scenario path inside the ESP.
pub const SCENARIO_IMAGE_PATH: &str = "POLYTOPE/BOOT.CFG";

const MAX_PAYLOAD_BYTES: usize = 24 * 1024 * 1024;
const MAX_SCENARIO_FILE_BYTES: usize = 32;
const GPT_ENTRY_COUNT: usize = 128;
const GPT_ENTRY_BYTES: usize = 128;
const GPT_ENTRY_ARRAY_SECTORS: u64 = 32;
const BACKUP_GPT_ENTRIES_LBA: u64 = 131_039;
const BACKUP_GPT_HEADER_LBA: u64 = 131_071;
const DISK_GUID: &str = "4ed83d8f-20d8-4c3d-9a4c-25bccd13a6a1";
const ESP_GUID: &str = "f607134d-0901-4d7b-a512-5a49d6ba66bf";
const FAT_TIMESTAMP_YEAR: u16 = 2000;

/// Boot behavior encoded in the deterministic scenario file.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BootScenario {
    /// Perform the ordinary validated handoff and reach the kernel-ready marker.
    Normal,
    /// Present an unsupported boot-contract version.
    BadVersion,
    /// Present a boot-contract header shorter than its declared layout.
    Truncated,
    /// Exercise the structured kernel panic path.
    Panic,
}

impl FromStr for BootScenario {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "normal" => Ok(Self::Normal),
            "bad-version" => Ok(Self::BadVersion),
            "truncated" => Ok(Self::Truncated),
            "panic" => Ok(Self::Panic),
            _ => bail!(
                "unknown boot scenario {value:?}; expected normal, bad-version, truncated, or panic"
            ),
        }
    }
}

impl BootScenario {
    /// Returns the stable command-line representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::BadVersion => "bad-version",
            Self::Truncated => "truncated",
            Self::Panic => "panic",
        }
    }
}

/// Inputs for deterministic disk-image construction.
#[derive(Clone, Debug)]
pub struct ImageRequest {
    /// `x86_64` PE/COFF UEFI application.
    pub loader: PathBuf,
    /// `x86_64` ELF kernel payload.
    pub kernel: PathBuf,
    /// Destination raw disk image.
    pub output: PathBuf,
    /// Test scenario encoded into the image.
    pub scenario: BootScenario,
}

/// Stable manifest describing a constructed disk image.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImageManifest {
    /// Manifest schema version.
    pub schema_version: u32,
    /// Image size in bytes.
    pub image_bytes: u64,
    /// SHA-256 digest of the complete raw image.
    pub image_sha256: String,
    /// SHA-256 digest of the UEFI loader.
    pub loader_sha256: String,
    /// SHA-256 digest of the kernel payload.
    pub kernel_sha256: String,
    /// Scenario found in the image.
    pub scenario: BootScenario,
    /// First ESP LBA.
    pub esp_first_lba: u64,
    /// Last ESP LBA, inclusive.
    pub esp_last_lba: u64,
    /// Fixed GPT disk GUID.
    pub disk_guid: String,
    /// Fixed GPT ESP partition GUID.
    pub esp_guid: String,
}

/// Builds and atomically writes one deterministic image.
///
/// # Errors
///
/// Returns an error for malformed input artifacts, invalid layout, filesystem
/// failures, or an output that fails read-back validation.
pub fn build_image(request: &ImageRequest) -> Result<ImageManifest> {
    let loader = read_host_artifact(&request.loader, "UEFI loader")?;
    let kernel = read_host_artifact(&request.kernel, "kernel")?;
    let (image, manifest) = build_image_bytes(&loader, &kernel, request.scenario)?;
    write_atomic(&request.output, &image)?;
    Ok(manifest)
}

/// Constructs a deterministic image entirely in memory.
///
/// # Errors
///
/// Returns an error when either artifact is malformed, too large, or cannot be
/// represented in the fixed image layout.
pub fn build_image_bytes(
    loader: &[u8],
    kernel: &[u8],
    scenario: BootScenario,
) -> Result<(Vec<u8>, ImageManifest)> {
    validate_uefi_loader(loader)?;
    validate_kernel_elf(kernel)?;
    ensure!(
        loader.len() <= MAX_PAYLOAD_BYTES,
        "UEFI loader is {} bytes; maximum is {MAX_PAYLOAD_BYTES}",
        loader.len()
    );
    ensure!(
        kernel.len() <= MAX_PAYLOAD_BYTES,
        "kernel is {} bytes; maximum is {MAX_PAYLOAD_BYTES}",
        kernel.len()
    );

    let loader_sha256 = sha256_hex(loader);
    let kernel_sha256 = sha256_hex(kernel);
    let mut scenario_bytes = scenario.as_str().as_bytes().to_vec();
    scenario_bytes.push(b'\n');

    let mut disk = create_gpt_disk()?;
    format_esp(&mut disk, loader, kernel, &scenario_bytes)?;
    let validated = validate_image_bytes(&disk)?;
    ensure!(
        validated.loader_sha256 == loader_sha256,
        "read-back loader digest differs from input"
    );
    ensure!(
        validated.kernel_sha256 == kernel_sha256,
        "read-back kernel digest differs from input"
    );
    ensure!(
        validated.scenario == scenario,
        "read-back scenario differs from requested scenario"
    );

    Ok((disk, validated))
}

/// Validates GPT, FAT, payload formats, hashes, paths, and scenario metadata.
///
/// # Errors
///
/// Returns an error when any structural or integrity invariant is violated.
pub fn validate_image_bytes(image: &[u8]) -> Result<ImageManifest> {
    ensure!(
        image.len() == DISK_BYTES,
        "image size is {}; expected {DISK_BYTES}",
        image.len()
    );
    validate_raw_gpt_layout(image)?;

    let disk_guid = parse_uuid(DISK_GUID)?;
    let esp_guid = parse_uuid(ESP_GUID)?;
    let cursor = Cursor::new(image.to_vec());
    let gpt_disk = gpt::GptConfig::new()
        .logical_block_size(LogicalBlockSize::Lb512)
        .only_valid_headers(true)
        .open_from_device(cursor)
        .context("image has invalid primary or backup GPT metadata")?;
    ensure!(gpt_disk.guid() == &disk_guid, "unexpected GPT disk GUID");
    ensure!(
        gpt_disk.partitions().len() == 1,
        "expected one GPT partition, found {}",
        gpt_disk.partitions().len()
    );
    let partition = gpt_disk
        .partitions()
        .get(&1)
        .context("GPT partition 1 is missing")?;
    ensure!(
        partition.part_type_guid == gpt::partition_types::EFI,
        "partition 1 is not an ESP"
    );
    ensure!(partition.part_guid == esp_guid, "unexpected ESP GUID");
    ensure!(
        partition.first_lba == ESP_FIRST_LBA,
        "unexpected ESP first LBA"
    );
    ensure!(
        partition.last_lba == ESP_LAST_LBA,
        "unexpected ESP last LBA"
    );
    drop(gpt_disk);

    let start = lba_to_offset(ESP_FIRST_LBA)?;
    let end = lba_to_offset(ESP_LAST_LBA + 1)?;
    let partition_bytes = image[start..end].to_vec();
    validate_raw_fat32_layout(&partition_bytes)?;
    ensure!(
        partition_bytes.get(FAT32_VOLUME_LABEL_OFFSET..FAT32_VOLUME_LABEL_OFFSET + 11)
            == Some(FAT_VOLUME_LABEL.as_slice()),
        "unexpected raw FAT volume label"
    );
    let filesystem = FileSystem::new(
        Cursor::new(partition_bytes),
        FsOptions::new().time_provider(&FIXED_TIME_PROVIDER),
    )
    .context("ESP is not a valid FAT filesystem")?;
    ensure!(filesystem.fat_type() == FatType::Fat32, "ESP is not FAT32");
    ensure!(
        filesystem.volume_id() == FAT_VOLUME_ID,
        "unexpected FAT volume ID"
    );
    ensure!(
        filesystem.volume_label_as_bytes() == FAT_VOLUME_LABEL_VISIBLE,
        "unexpected FAT volume label"
    );

    let root = filesystem.root_dir();
    validate_directory(&root, &[("EFI", true), ("POLYTOPE", true)])?;
    let efi = root
        .open_dir("EFI")
        .context("required ESP directory EFI is missing")?;
    validate_directory(&efi, &[("BOOT", true)])?;
    let boot = efi
        .open_dir("BOOT")
        .context("required ESP directory EFI/BOOT is missing")?;
    validate_directory(&boot, &[("BOOTX64.EFI", false)])?;
    let polytope = root
        .open_dir("POLYTOPE")
        .context("required ESP directory POLYTOPE is missing")?;
    validate_directory(&polytope, &[("KERNEL.ELF", false), ("BOOT.CFG", false)])?;
    let loader = read_fat_file(&root, LOADER_IMAGE_PATH, MAX_PAYLOAD_BYTES)?;
    let kernel = read_fat_file(
        &root,
        KERNEL_IMAGE_PATH,
        polytope_boot_elf::MAX_ELF_FILE_SIZE,
    )?;
    let scenario_bytes = read_fat_file(&root, SCENARIO_IMAGE_PATH, MAX_SCENARIO_FILE_BYTES)?;
    validate_uefi_loader(&loader)?;
    validate_kernel_elf(&kernel)?;
    let scenario = parse_scenario(&scenario_bytes)?;
    let loader_sha256 = sha256_hex(&loader);
    let kernel_sha256 = sha256_hex(&kernel);

    Ok(ImageManifest {
        schema_version: 1,
        image_bytes: u64::try_from(image.len()).context("image length does not fit u64")?,
        image_sha256: sha256_hex(image),
        loader_sha256,
        kernel_sha256,
        scenario,
        esp_first_lba: ESP_FIRST_LBA,
        esp_last_lba: ESP_LAST_LBA,
        disk_guid: disk_guid.to_string(),
        esp_guid: esp_guid.to_string(),
    })
}

fn validate_raw_gpt_layout(image: &[u8]) -> Result<()> {
    const PROTECTIVE_ENTRY: [u8; 16] = [
        0x00, 0x00, 0x02, 0x00, 0xee, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01,
        0x00,
    ];
    ensure_zero(&image[..446], "protective MBR bootstrap area")?;
    ensure!(
        image.get(446..462) == Some(PROTECTIVE_ENTRY.as_slice()),
        "protective MBR entry is not canonical"
    );
    ensure_zero(&image[462..510], "unused protective MBR entries")?;
    ensure!(
        &image[510..512] == b"\x55\xaa",
        "protective MBR signature is invalid"
    );

    let primary_header = sector(image, 1)?;
    let backup_header = sector(image, BACKUP_GPT_HEADER_LBA)?;
    validate_raw_gpt_header(primary_header, 1, BACKUP_GPT_HEADER_LBA, 2)?;
    validate_raw_gpt_header(
        backup_header,
        BACKUP_GPT_HEADER_LBA,
        1,
        BACKUP_GPT_ENTRIES_LBA,
    )?;
    ensure!(
        primary_header[56..72] == backup_header[56..72]
            && primary_header[88..92] == backup_header[88..92],
        "primary and backup GPT identity or entry-array CRC differs"
    );

    let primary_entries = lba_range(image, 2, 2 + GPT_ENTRY_ARRAY_SECTORS)?;
    let backup_entries = lba_range(
        image,
        BACKUP_GPT_ENTRIES_LBA,
        BACKUP_GPT_ENTRIES_LBA + GPT_ENTRY_ARRAY_SECTORS,
    )?;
    ensure!(
        primary_entries == backup_entries,
        "primary and backup GPT entry arrays differ"
    );
    ensure!(
        primary_entries[..GPT_ENTRY_BYTES]
            .iter()
            .any(|byte| *byte != 0),
        "GPT partition entry 1 is empty"
    );
    ensure_zero(
        &primary_entries[GPT_ENTRY_BYTES..GPT_ENTRY_COUNT * GPT_ENTRY_BYTES],
        "unused GPT partition entries",
    )?;
    ensure_zero(
        lba_range(image, 34, ESP_FIRST_LBA)?,
        "pre-ESP alignment sectors",
    )?;
    ensure_zero(
        lba_range(image, ESP_LAST_LBA + 1, BACKUP_GPT_ENTRIES_LBA)?,
        "post-ESP alignment sectors",
    )
}

fn validate_raw_gpt_header(
    header: &[u8],
    current_lba: u64,
    backup_lba: u64,
    entries_lba: u64,
) -> Result<()> {
    ensure!(
        &header[..8] == b"EFI PART",
        "GPT header signature is invalid"
    );
    ensure!(
        read_u32(header, 8) == Some(0x0001_0000),
        "unsupported GPT revision"
    );
    ensure!(
        read_u32(header, 12) == Some(92),
        "GPT header size is not 92 bytes"
    );
    ensure!(
        read_u32(header, 20) == Some(0),
        "GPT reserved header field is nonzero"
    );
    ensure!(
        read_u64(header, 24) == Some(current_lba),
        "GPT current-LBA mismatch"
    );
    ensure!(
        read_u64(header, 32) == Some(backup_lba),
        "GPT backup-LBA mismatch"
    );
    ensure!(
        read_u64(header, 40) == Some(34),
        "GPT first-usable LBA mismatch"
    );
    ensure!(
        read_u64(header, 48) == Some(BACKUP_GPT_ENTRIES_LBA - 1),
        "GPT last-usable LBA mismatch"
    );
    ensure!(
        read_u64(header, 72) == Some(entries_lba),
        "GPT entry-array LBA mismatch"
    );
    ensure!(
        read_u32(header, 80) == Some(u32::try_from(GPT_ENTRY_COUNT).expect("count fits u32"))
            && read_u32(header, 84)
                == Some(u32::try_from(GPT_ENTRY_BYTES).expect("entry size fits u32")),
        "GPT entry count or size is not canonical"
    );
    ensure_zero(&header[92..], "GPT header sector padding")
}

fn validate_raw_fat32_layout(partition: &[u8]) -> Result<()> {
    let boot = sector(partition, 0)?;
    ensure!(&boot[3..11] == b"MSWIN4.1", "unexpected FAT OEM identity");
    ensure!(
        read_u16(boot, 11) == Some(512),
        "FAT sector size is not 512 bytes"
    );
    ensure!(boot[13] == 1, "FAT cluster size is not one sector");
    ensure!(
        read_u16(boot, 14) == Some(8),
        "FAT reserved-sector count is not 8"
    );
    ensure!(boot[16] == 2, "FAT does not contain two mirrors");
    ensure!(
        read_u16(boot, 17) == Some(0),
        "FAT32 root-entry field is nonzero"
    );
    ensure!(
        read_u16(boot, 19) == Some(0),
        "FAT32 16-bit sector count is nonzero"
    );
    ensure!(boot[21] == 0xf8, "FAT media descriptor is not fixed-disk");
    ensure!(
        read_u16(boot, 22) == Some(0),
        "FAT32 16-bit FAT size is nonzero"
    );
    let expected_sectors = u32::try_from(partition.len() / LOGICAL_BLOCK_BYTES)
        .context("ESP sector count does not fit u32")?;
    ensure!(
        read_u32(boot, 32) == Some(expected_sectors),
        "FAT32 total-sector count is inconsistent"
    );
    let fat_sectors = read_u32(boot, 36).context("FAT32 FAT-sector count is truncated")?;
    ensure!(fat_sectors > 0, "FAT32 FAT-sector count is zero");
    ensure!(
        read_u16(boot, 40) == Some(0),
        "FAT mirroring flags are not canonical"
    );
    ensure!(
        read_u16(boot, 42) == Some(0),
        "FAT32 version is unsupported"
    );
    ensure!(read_u32(boot, 44) == Some(2), "FAT32 root cluster is not 2");
    ensure!(
        read_u16(boot, 48) == Some(1),
        "FAT32 FSInfo sector is not 1"
    );
    ensure!(
        read_u16(boot, 50) == Some(6),
        "FAT32 backup boot sector is not 6"
    );
    ensure!(&boot[510..] == b"\x55\xaa", "FAT boot signature is invalid");
    ensure!(
        boot == sector(partition, 6)?,
        "FAT backup boot sector differs"
    );
    ensure_zero(lba_range(partition, 2, 6)?, "unused FAT reserved sectors")?;
    ensure_zero(sector(partition, 7)?, "unused FAT backup-adjacent sector")?;

    let fs_info = sector(partition, 1)?;
    ensure!(
        read_u32(fs_info, 0) == Some(0x4161_5252),
        "FSInfo lead signature is invalid"
    );
    ensure!(
        read_u32(fs_info, 484) == Some(0x6141_7272),
        "FSInfo structure signature is invalid"
    );
    ensure!(
        read_u32(fs_info, 488) == Some(u32::MAX),
        "FSInfo free count is not canonical"
    );
    ensure!(
        &fs_info[508..512] == b"\x00\x00\x55\xaa",
        "FSInfo trail signature is invalid"
    );

    let first_fat_lba = 8_u64;
    let second_fat_lba = first_fat_lba + u64::from(fat_sectors);
    let data_lba = second_fat_lba + u64::from(fat_sectors);
    ensure!(
        data_lba < u64::from(expected_sectors),
        "FAT32 data region lies outside the ESP"
    );
    let first_fat = lba_range(partition, first_fat_lba, second_fat_lba)?;
    let second_fat = lba_range(partition, second_fat_lba, data_lba)?;
    ensure!(first_fat == second_fat, "FAT mirror copies differ");
    validate_canonical_fat_entries(first_fat, expected_sectors, data_lba, fs_info)
}

fn validate_canonical_fat_entries(
    fat: &[u8],
    total_sectors: u32,
    data_lba: u64,
    fs_info: &[u8],
) -> Result<()> {
    let total_clusters = u64::from(total_sectors)
        .checked_sub(data_lba)
        .context("FAT32 data-cluster count underflowed")?;
    let entry_count =
        usize::try_from(total_clusters + 2).context("FAT entry count is too large")?;
    ensure!(
        entry_count
            .checked_mul(4)
            .is_some_and(|bytes| bytes <= fat.len()),
        "FAT is too short for the declared data clusters"
    );
    ensure!(
        read_u32(fat, 0).is_some_and(|value| value & 0xff == 0xf8)
            && read_u32(fat, 4).is_some_and(|value| value & 0x0fff_ffff >= 0x0fff_fff8),
        "FAT reserved entries are invalid"
    );
    let mut first_free = None;
    for cluster in 2..entry_count {
        let value =
            read_u32(fat, cluster * 4).context("FAT cluster entry is truncated")? & 0x0fff_ffff;
        if value == 0 {
            first_free.get_or_insert(cluster);
        } else {
            ensure!(
                first_free.is_none(),
                "FAT allocated clusters are not one canonical prefix"
            );
            ensure!(
                (2..entry_count).contains(&usize::try_from(value).unwrap_or(usize::MAX))
                    || value >= 0x0fff_fff8,
                "FAT cluster {cluster} has an invalid successor {value:#x}"
            );
        }
    }
    ensure!(
        fat[entry_count * 4..]
            .chunks_exact(4)
            .all(|entry| entry == [0xff, 0xff, 0xff, 0x0f]),
        "out-of-range FAT entries are not canonical end-of-chain sentinels"
    );
    let expected_next = u32::try_from(first_free.context("FAT contains no free cluster")?)
        .context("first free cluster does not fit u32")?;
    ensure!(
        read_u32(fs_info, 492) == Some(expected_next),
        "FSInfo next-free hint does not identify the canonical first free cluster"
    );
    Ok(())
}

fn sector(bytes: &[u8], lba: u64) -> Result<&[u8]> {
    lba_range(
        bytes,
        lba,
        lba.checked_add(1).context("sector LBA overflowed")?,
    )
}

fn lba_range(bytes: &[u8], start_lba: u64, end_lba: u64) -> Result<&[u8]> {
    ensure!(start_lba <= end_lba, "invalid descending LBA range");
    let start = lba_to_offset(start_lba)?;
    let end = lba_to_offset(end_lba)?;
    bytes
        .get(start..end)
        .with_context(|| format!("LBA range {start_lba}..{end_lba} is outside the artifact"))
}

fn ensure_zero(bytes: &[u8], description: &str) -> Result<()> {
    ensure!(
        bytes.iter().all(|byte| *byte == 0),
        "{description} contains nonzero data"
    );
    Ok(())
}

fn parse_scenario(bytes: &[u8]) -> Result<BootScenario> {
    let text = std::str::from_utf8(bytes).context("scenario file is not valid UTF-8")?;
    ensure!(
        text.ends_with('\n') && text.lines().count() == 1,
        "scenario file must contain exactly one token followed by a newline"
    );
    text.trim_end_matches('\n').parse()
}

fn create_gpt_disk() -> Result<Vec<u8>> {
    let total_lbas = DISK_BYTES / LOGICAL_BLOCK_BYTES;
    let protective_lbas = u32::try_from(total_lbas - 1).context("disk has too many LBAs")?;
    let mut cursor = Cursor::new(vec![0_u8; DISK_BYTES]);
    ProtectiveMBR::with_lb_size(protective_lbas)
        .overwrite_lba0(&mut cursor)
        .context("failed to write protective MBR")?;

    let disk_guid = parse_uuid(DISK_GUID)?;
    let esp_guid = parse_uuid(ESP_GUID)?;
    let mut gpt_disk = gpt::GptConfig::new()
        .writable(true)
        .change_partition_count(true)
        .logical_block_size(LogicalBlockSize::Lb512)
        .create_from_device(cursor, Some(disk_guid))
        .context("failed to initialize GPT")?;
    let mut partitions = BTreeMap::new();
    partitions.insert(
        1,
        Partition {
            part_type_guid: gpt::partition_types::EFI,
            part_guid: esp_guid,
            first_lba: ESP_FIRST_LBA,
            last_lba: ESP_LAST_LBA,
            flags: 0,
            name: String::from("PolytopeOS ESP"),
        },
    );
    gpt_disk
        .update_partitions(partitions)
        .context("failed to install deterministic GPT partition table")?;
    let cursor = gpt_disk.write().context("failed to write GPT headers")?;
    Ok(cursor.into_inner())
}

fn format_esp(disk: &mut [u8], loader: &[u8], kernel: &[u8], scenario: &[u8]) -> Result<()> {
    let start = lba_to_offset(ESP_FIRST_LBA)?;
    let end = lba_to_offset(ESP_LAST_LBA + 1)?;
    let esp = disk
        .get_mut(start..end)
        .context("ESP byte range is outside the raw image")?;

    fatfs::format_volume(
        Cursor::new(&mut *esp),
        FormatVolumeOptions::new()
            .bytes_per_sector(u16::try_from(LOGICAL_BLOCK_BYTES).expect("512 fits u16"))
            .bytes_per_cluster(512)
            .fat_type(FatType::Fat32)
            .fats(2)
            .volume_id(FAT_VOLUME_ID)
            .volume_label(FAT_VOLUME_LABEL),
    )
    .context("failed to format deterministic FAT32 ESP")?;

    let filesystem = FileSystem::new(
        Cursor::new(esp),
        FsOptions::new().time_provider(&FIXED_TIME_PROVIDER),
    )
    .context("failed to mount newly formatted ESP")?;
    let root = filesystem.root_dir();
    root.create_dir("EFI").context("failed to create EFI")?;
    root.create_dir("EFI/BOOT")
        .context("failed to create EFI/BOOT")?;
    root.create_dir("POLYTOPE")
        .context("failed to create POLYTOPE")?;
    write_fat_file(&root, LOADER_IMAGE_PATH, loader)?;
    write_fat_file(&root, KERNEL_IMAGE_PATH, kernel)?;
    write_fat_file(&root, SCENARIO_IMAGE_PATH, scenario)?;
    drop(root);
    filesystem.unmount().context("failed to flush ESP")
}

fn validate_uefi_loader(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() >= 0x40,
        "UEFI loader is too small for a DOS header"
    );
    ensure!(&bytes[..2] == b"MZ", "UEFI loader lacks the MZ signature");
    let pe_offset = read_u32(bytes, 0x3c).context("UEFI loader lacks a PE header offset")?;
    let pe_offset = usize::try_from(pe_offset).context("PE header offset does not fit usize")?;
    let signature_end = pe_offset
        .checked_add(4)
        .context("PE signature offset overflowed")?;
    ensure!(
        bytes.get(pe_offset..signature_end) == Some(b"PE\0\0"),
        "UEFI loader lacks the PE signature"
    );
    ensure!(
        read_u16(bytes, pe_offset + 4) == Some(0x8664),
        "UEFI loader is not x86_64"
    );
    let optional = pe_offset
        .checked_add(24)
        .context("PE optional-header offset overflowed")?;
    ensure!(
        read_u16(bytes, optional) == Some(0x20b),
        "UEFI loader is not PE32+"
    );
    ensure!(
        read_u16(bytes, optional + 68) == Some(10),
        "PE subsystem is not EFI_APPLICATION"
    );
    Ok(())
}

fn read_host_artifact(path: &Path, description: &str) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to inspect {description} {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "{description} is not a regular file: {}",
        path.display()
    );
    ensure!(
        metadata.len() <= u64::try_from(MAX_PAYLOAD_BYTES).expect("payload cap fits u64"),
        "{description} is {} bytes; maximum is {MAX_PAYLOAD_BYTES}",
        metadata.len()
    );
    fs::read(path).with_context(|| format!("failed to read {description} {}", path.display()))
}

fn validate_kernel_elf(bytes: &[u8]) -> Result<()> {
    polytope_boot_elf::parse(bytes)
        .map_err(|error| anyhow::anyhow!("kernel ELF rejected: {error:?}"))?;
    Ok(())
}

fn write_fat_file<T: fatfs::ReadWriteSeek>(
    root: &fatfs::Dir<'_, T>,
    path: &str,
    bytes: &[u8],
) -> Result<()> {
    let mut file = root
        .create_file(path)
        .with_context(|| format!("failed to create {path} in ESP"))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {path} in ESP"))?;
    file.flush()
        .with_context(|| format!("failed to flush {path} in ESP"))
}

fn read_fat_file<T: fatfs::ReadWriteSeek>(
    root: &fatfs::Dir<'_, T>,
    path: &str,
    maximum: usize,
) -> Result<Vec<u8>> {
    let mut file = root
        .open_file(path)
        .with_context(|| format!("required ESP file {path} is missing"))?;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        let read = file
            .read(&mut chunk)
            .with_context(|| format!("failed to read ESP file {path}"))?;
        if read == 0 {
            break;
        }
        let new_length = bytes
            .len()
            .checked_add(read)
            .with_context(|| format!("ESP file {path} length overflowed"))?;
        ensure!(
            new_length <= maximum,
            "ESP file {path} exceeds its {maximum}-byte limit"
        );
        bytes
            .try_reserve_exact(read)
            .with_context(|| format!("failed to reserve bounded storage for ESP file {path}"))?;
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(bytes)
}

fn validate_directory<T: fatfs::ReadWriteSeek>(
    directory: &fatfs::Dir<'_, T>,
    expected: &[(&str, bool)],
) -> Result<()> {
    let mut observed = 0_usize;
    let mut raw_entries = 0_usize;
    for entry in directory.iter() {
        let entry = entry.context("failed to enumerate deterministic ESP directory")?;
        raw_entries = raw_entries
            .checked_add(1)
            .context("ESP directory entry count overflowed")?;
        ensure!(
            raw_entries <= expected.len() + 2,
            "ESP directory enumeration exceeded its deterministic bound"
        );
        let name = entry.file_name();
        if matches!(name.as_str(), "." | "..") {
            continue;
        }
        let (expected_name, expected_is_directory) = expected
            .get(observed)
            .context("ESP directory contains an unexpected extra entry")?;
        ensure!(
            &name == expected_name && entry.is_dir() == *expected_is_directory,
            "unexpected ESP directory entry {name:?}"
        );
        ensure_fixed_timestamp(&entry, &name)?;
        observed = observed
            .checked_add(1)
            .context("ESP observed-entry count overflowed")?;
    }
    ensure!(
        observed == expected.len(),
        "ESP directory has {observed} entries; expected {}",
        expected.len()
    );
    Ok(())
}

fn ensure_fixed_timestamp<T: fatfs::ReadWriteSeek>(
    entry: &fatfs::DirEntry<'_, T>,
    name: &str,
) -> Result<()> {
    let expected_date = FIXED_TIME_PROVIDER.get_current_date();
    let expected_date_time = FIXED_TIME_PROVIDER.get_current_date_time();
    ensure!(
        entry.created() == expected_date_time
            && entry.modified() == expected_date_time
            && entry.accessed() == expected_date,
        "ESP directory entry {name:?} has a noncanonical timestamp"
    );
    Ok(())
}

fn write_atomic(output: &Path, bytes: &[u8]) -> Result<()> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    let file_name = output
        .file_name()
        .context("image output must include a file name")?
        .to_string_lossy();
    let temporary = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    let write_result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .with_context(|| format!("failed to create {}", temporary.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("failed to write {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync {}", temporary.display()))?;
        fs::rename(&temporary, output).with_context(|| {
            format!(
                "failed to atomically rename {} to {}",
                temporary.display(),
                output.display()
            )
        })?;
        sync_directory(parent)
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("failed to open output directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync output directory {}", path.display()))
}

fn parse_uuid(value: &str) -> Result<Uuid> {
    Uuid::parse_str(value).with_context(|| format!("invalid built-in UUID {value}"))
}

fn lba_to_offset(lba: u64) -> Result<usize> {
    let bytes = lba
        .checked_mul(u64::try_from(LOGICAL_BLOCK_BYTES).expect("sector size fits u64"))
        .context("LBA byte offset overflowed u64")?;
    usize::try_from(bytes).context("LBA byte offset does not fit usize")
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw: [u8; 2] = bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let raw: [u8; 8] = bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(raw))
}

#[derive(Debug)]
struct FixedTimeProvider;

impl TimeProvider for FixedTimeProvider {
    fn get_current_date(&self) -> Date {
        Date {
            year: FAT_TIMESTAMP_YEAR,
            month: 1,
            day: 1,
        }
    }

    fn get_current_date_time(&self) -> DateTime {
        DateTime {
            date: self.get_current_date(),
            time: Time {
                hour: 0,
                min: 0,
                sec: 0,
                millis: 0,
            },
        }
    }
}

static FIXED_TIME_PROVIDER: FixedTimeProvider = FixedTimeProvider;

#[cfg(test)]
mod tests {
    use super::{
        BootScenario, DISK_BYTES, ESP_FIRST_LBA, ESP_LAST_LBA, build_image_bytes,
        validate_image_bytes,
    };
    use crate::first_difference;
    use std::io::{Cursor, Write};

    #[test]
    fn image_is_byte_identical_across_repeated_builds() {
        let loader = fake_loader();
        let kernel = fake_kernel();
        let (first, first_manifest) =
            build_image_bytes(&loader, &kernel, BootScenario::Normal).unwrap();
        let (second, second_manifest) =
            build_image_bytes(&loader, &kernel, BootScenario::Normal).unwrap();
        assert_eq!(first.len(), DISK_BYTES);
        assert_eq!(first_difference(&first, &second), None);
        assert_eq!(first_manifest, second_manifest);
        assert_eq!(validate_image_bytes(&first).unwrap(), first_manifest);
        assert_eq!(first_manifest.esp_first_lba, ESP_FIRST_LBA);
        assert_eq!(first_manifest.esp_last_lba, ESP_LAST_LBA);
    }

    #[test]
    fn scenario_changes_have_a_deterministic_effect() {
        let loader = fake_loader();
        let kernel = fake_kernel();
        let (normal, _) = build_image_bytes(&loader, &kernel, BootScenario::Normal).unwrap();
        let (negative, manifest) =
            build_image_bytes(&loader, &kernel, BootScenario::BadVersion).unwrap();
        assert_ne!(normal, negative);
        assert_eq!(manifest.scenario, BootScenario::BadVersion);
    }

    #[test]
    fn malformed_artifacts_fail_closed() {
        let error = build_image_bytes(b"not PE", &fake_kernel(), BootScenario::Normal)
            .unwrap_err()
            .to_string();
        assert!(error.contains("DOS header"));
        let error = build_image_bytes(&fake_loader(), b"not ELF", BootScenario::Normal)
            .unwrap_err()
            .to_string();
        assert!(error.contains("kernel ELF rejected"));
    }

    #[test]
    fn unexpected_esp_entries_fail_closed() {
        let (mut image, _) =
            build_image_bytes(&fake_loader(), &fake_kernel(), BootScenario::Normal).unwrap();
        let start = usize::try_from(ESP_FIRST_LBA * 512).unwrap();
        let end = usize::try_from((ESP_LAST_LBA + 1) * 512).unwrap();
        let filesystem =
            fatfs::FileSystem::new(Cursor::new(&mut image[start..end]), fatfs::FsOptions::new())
                .unwrap();
        let root = filesystem.root_dir();
        let mut extra = root.create_file("EXTRA.TXT").unwrap();
        extra.write_all(b"unexpected").unwrap();
        drop(extra);
        drop(root);
        filesystem.unmount().unwrap();

        let error = validate_image_bytes(&image).unwrap_err().to_string();
        assert!(error.contains("unexpected extra entry"), "{error}");
    }

    #[test]
    fn raw_layout_mutations_fail_closed() {
        let (image, _) =
            build_image_bytes(&fake_loader(), &fake_kernel(), BootScenario::Normal).unwrap();
        let esp = usize::try_from(ESP_FIRST_LBA * 512).unwrap();
        let fat_sectors = usize::try_from(super::read_u32(&image, esp + 36).unwrap()).unwrap();
        let mutations = [
            (0_usize, "protective MBR bootstrap area"),
            (34 * 512, "pre-ESP alignment sectors"),
            (
                usize::try_from(super::BACKUP_GPT_ENTRIES_LBA * 512).unwrap(),
                "primary and backup GPT entry arrays differ",
            ),
            (esp + 6 * 512, "FAT backup boot sector differs"),
            (esp + (8 + fat_sectors) * 512, "FAT mirror copies differ"),
        ];
        for (offset, expected) in mutations {
            let mut corrupted = image.clone();
            corrupted[offset] ^= 1;
            let error = validate_image_bytes(&corrupted).unwrap_err().to_string();
            assert!(
                error.contains(expected),
                "mutation at {offset} produced {error:?}, expected {expected:?}"
            );
        }
    }

    fn fake_loader() -> Vec<u8> {
        let mut bytes = vec![0_u8; 256];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
        bytes[0xdc..0xde].copy_from_slice(&10_u16.to_le_bytes());
        bytes
    }

    fn fake_kernel() -> Vec<u8> {
        const HEADER_SIZE: usize = 64;
        const PROGRAM_HEADER_SIZE: usize = 56;
        const KERNEL_BASE: u64 = 0x0400_0000;

        let mut bytes = vec![0_u8; 0x3000];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        write_u16(&mut bytes, 16, 2);
        write_u16(&mut bytes, 18, 62);
        write_u32(&mut bytes, 20, 1);
        write_u64(&mut bytes, 24, KERNEL_BASE);
        write_u64(&mut bytes, 32, HEADER_SIZE as u64);
        write_u16(&mut bytes, 52, u16::try_from(HEADER_SIZE).unwrap());
        write_u16(&mut bytes, 54, u16::try_from(PROGRAM_HEADER_SIZE).unwrap());
        write_u16(&mut bytes, 56, 2);
        write_program_header(&mut bytes, 0, 5, 0x1000, KERNEL_BASE, 0x100, 0x100);
        write_program_header(&mut bytes, 1, 6, 0x2000, KERNEL_BASE + 0x1000, 0x80, 0x1000);
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
        const HEADER_SIZE: usize = 64;
        const PROGRAM_HEADER_SIZE: usize = 56;

        let offset = HEADER_SIZE + index * PROGRAM_HEADER_SIZE;
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
