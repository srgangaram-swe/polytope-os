//! Clean-room artifact and image reproducibility verification.

use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::image::{BootScenario, build_image_bytes};
use crate::temporary::TemporaryDirectory;
use crate::{ByteDifference, first_difference, sha256_hex};

const SOURCE_DATE_EPOCH: u64 = 946_684_800;
const WORKSPACE_REMAP_DESTINATION: &str = "/workspace/polytope-os";
const CARGO_HOME_REMAP_DESTINATION: &str = "/build/cargo-home";
const USER_HOME_REMAP_DESTINATION: &str = "/build/user-home";
const TARGET_REMAP_DESTINATION: &str = "/build/target";
const RUSTFLAG_SEPARATOR: char = '\u{1f}';
const RUSTFLAG_SEPARATOR_TEXT: &str = "\u{1f}";
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

/// Required target-specific compiler behavior retained when reproducible
/// builds replace Cargo's configured target rustflags.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactRustcFlag {
    /// Emit position-dependent code for the fixed-address kernel contract.
    StaticRelocationModel,
    /// Pass one exact argument through rustc to the target linker.
    LinkArgument(String),
}

/// Cargo artifact description used by a clean build.
#[derive(Clone, Debug)]
pub struct ArtifactSpec {
    /// Cargo package name.
    pub package: String,
    /// Cargo binary target name.
    pub binary: String,
    /// Rust compilation target triple.
    pub target: String,
    /// Artifact path relative to `CARGO_TARGET_DIR`.
    pub relative_path: PathBuf,
    /// Cargo features required to materialize the binary target.
    pub features: Vec<String>,
    /// Target-specific rustc flags required in addition to path remapping.
    pub rustc_flags: Vec<ArtifactRustcFlag>,
}

/// Configuration for a two-build reproducibility check.
#[derive(Clone, Debug)]
pub struct ReproRequest {
    /// Repository workspace containing `Cargo.toml`.
    pub workspace: PathBuf,
    /// Cargo executable override. Environment and PATH discovery are used when absent.
    pub cargo: Option<PathBuf>,
    /// Deterministic UEFI loader build description.
    pub loader: ArtifactSpec,
    /// Deterministic kernel build description.
    pub kernel: ArtifactSpec,
    /// Output path receiving the verified image from the first build.
    pub output: PathBuf,
    /// Optional path receiving the exact verified loader from the first build.
    pub verified_loader_output: Option<PathBuf>,
    /// Optional path receiving the exact verified kernel from the first build.
    pub verified_kernel_output: Option<PathBuf>,
    /// Optional path receiving the first build's map for that exact kernel.
    pub verified_kernel_map_output: Option<PathBuf>,
    /// Linker-map path relative to each clean target directory.
    pub kernel_map_relative_path: Option<PathBuf>,
    /// Scenario encoded into both images.
    pub scenario: BootScenario,
}

impl ReproRequest {
    /// Creates the repository-default `x86_64` boot build request.
    #[must_use]
    pub fn polytope_defaults(workspace: PathBuf, output: PathBuf) -> Self {
        Self {
            workspace,
            cargo: None,
            loader: ArtifactSpec {
                package: String::from("polytope-boot-uefi"),
                binary: String::from("polytope-boot-uefi"),
                target: String::from("x86_64-unknown-uefi"),
                relative_path: PathBuf::from("x86_64-unknown-uefi/boot/polytope-boot-uefi.efi"),
                features: vec![String::from("uefi-binary")],
                rustc_flags: vec![ArtifactRustcFlag::LinkArgument(String::from("/debug:none"))],
            },
            kernel: ArtifactSpec {
                package: String::from("polytope-kernel"),
                binary: String::from("polytope-kernel-x86_64"),
                target: String::from("x86_64-unknown-none"),
                relative_path: PathBuf::from("x86_64-unknown-none/boot/polytope-kernel-x86_64"),
                features: vec![String::from("boot-binary")],
                rustc_flags: vec![
                    ArtifactRustcFlag::StaticRelocationModel,
                    ArtifactRustcFlag::LinkArgument(String::from("-no-pie")),
                ],
            },
            output,
            verified_loader_output: None,
            verified_kernel_output: None,
            verified_kernel_map_output: None,
            kernel_map_relative_path: Some(PathBuf::from(
                "x86_64-unknown-none/boot/polytope-kernel-x86_64.map",
            )),
            scenario: BootScenario::Normal,
        }
    }
}

/// Machine-readable evidence from a successful clean-room comparison.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReproReport {
    /// Report schema version.
    pub schema_version: u32,
    /// Cargo profile used for both builds.
    pub cargo_profile: String,
    /// Scenario encoded in the compared images.
    pub scenario: BootScenario,
    /// Rust compiler identity used by Cargo.
    pub rustc_version: String,
    /// Cargo identity used for both builds.
    pub cargo_version: String,
    /// Git revision of the source tree when available.
    pub source_revision: Option<String>,
    /// Whether Git reported no tracked or untracked source changes.
    pub source_tree_clean: Option<bool>,
    /// SHA-256 digest of the locked dependency resolution.
    pub cargo_lock_sha256: String,
    /// Loader target triple.
    pub loader_target: String,
    /// Kernel target triple.
    pub kernel_target: String,
    /// Exact non-path rustc arguments retained for the loader target.
    pub loader_required_rustc_flags: Vec<String>,
    /// Exact non-path rustc arguments retained for the kernel target.
    pub kernel_required_rustc_flags: Vec<String>,
    /// Loader digest shared by both builds.
    pub loader_sha256: String,
    /// Loader artifact size in bytes.
    pub loader_bytes: u64,
    /// Kernel digest shared by both builds.
    pub kernel_sha256: String,
    /// Kernel artifact size in bytes.
    pub kernel_bytes: u64,
    /// Complete image digest shared by both builds.
    pub image_sha256: String,
    /// Number of bytes in the verified image.
    pub image_bytes: u64,
    /// Fixed source epoch passed to both Cargo invocations.
    pub source_date_epoch: u64,
    /// Stable destination used for workspace source paths.
    pub workspace_remap_destination: String,
    /// Stable destination used for Cargo registry, Git, and cache paths.
    pub cargo_home_remap_destination: String,
    /// Stable destination used for remaining user-home paths, including Rustup.
    pub user_home_remap_destination: String,
    /// Stable destination used for each otherwise-distinct target directory.
    pub target_directory_remap_destination: String,
    /// Exact-byte path scan evidence for the loader artifact.
    pub loader_path_privacy: PathPrivacyEvidence,
    /// Exact-byte path scan evidence for the kernel artifact.
    pub kernel_path_privacy: PathPrivacyEvidence,
    /// Exact-byte path scan evidence for the completed disk image.
    pub image_path_privacy: PathPrivacyEvidence,
}

/// Exact-byte evidence that host paths were absent and normalized paths were counted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PathPrivacyEvidence {
    /// Number of distinct unremapped host-path byte patterns checked.
    pub host_patterns_scanned: u32,
    /// Unremapped matches; successful verification always reports zero.
    pub unremapped_matches: u32,
    /// Occurrences of the normalized workspace destination.
    pub workspace_destination_occurrences: u64,
    /// Occurrences of the normalized Cargo-home destination.
    pub cargo_home_destination_occurrences: u64,
    /// Occurrences of the normalized user-home destination.
    pub user_home_destination_occurrences: u64,
    /// Occurrences of the normalized target-directory destination.
    pub target_destination_occurrences: u64,
}

/// Builds the loader and kernel twice in independent target directories and
/// stops at the first byte difference.
///
/// # Errors
///
/// Returns an error when path discovery or a build fails, an artifact is absent,
/// unremapped host bytes remain, image assembly fails, or any stage differs.
pub fn verify(request: &ReproRequest) -> Result<ReproReport> {
    let workspace = request
        .workspace
        .canonicalize()
        .with_context(|| format!("workspace {} does not exist", request.workspace.display()))?;
    let cargo = resolve_cargo(request.cargo.as_deref())?;
    let rustc = resolve_rustc()?;
    let host_paths = HostPaths::discover(&workspace)?;
    let cargo_version = tool_version(&cargo, &["--version"])?;
    let rustc_version = tool_version(&rustc, &["--version", "--verbose"])?;
    let cargo_lock = fs::read(workspace.join("Cargo.lock"))
        .context("reproducibility check requires a readable Cargo.lock")?;
    let (source_revision, source_tree_clean) = git_source_state(&workspace);
    let temporary_parent = request
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("target"));
    let temporary = TemporaryDirectory::create(temporary_parent, "repro")?;
    let first_target = temporary.path().join("build-a");
    let second_target = temporary.path().join("build-b");

    let first = build_once(&cargo, &workspace, &first_target, request, &host_paths)?;
    let second = build_once(&cargo, &workspace, &second_target, request, &host_paths)?;
    require_identical("loader", &first.loader, &second.loader)?;
    require_identical("kernel", &first.kernel, &second.kernel)?;
    require_privacy_evidence_identical(
        "loader",
        &first.loader_path_privacy,
        &second.loader_path_privacy,
    )?;
    require_privacy_evidence_identical(
        "kernel",
        &first.kernel_path_privacy,
        &second.kernel_path_privacy,
    )?;

    let (first_image, first_manifest) =
        build_image_bytes(&first.loader, &first.kernel, request.scenario)
            .context("first clean build could not be assembled into an image")?;
    let (second_image, _) = build_image_bytes(&second.loader, &second.kernel, request.scenario)
        .context("second clean build could not be assembled into an image")?;
    require_identical("disk image", &first_image, &second_image)?;
    let first_image_privacy =
        verify_path_privacy("first disk image", &first_image, &first.path_contract)?;
    let second_image_privacy =
        verify_path_privacy("second disk image", &second_image, &second.path_contract)?;
    require_privacy_evidence_identical("disk image", &first_image_privacy, &second_image_privacy)?;
    write_verified_image(&request.output, &first_image)?;
    if let Some(output) = &request.verified_loader_output {
        write_verified_file(output, &first.loader, "loader")?;
    }
    if let Some(output) = &request.verified_kernel_output {
        write_verified_file(output, &first.kernel, "kernel")?;
    }
    if let Some(output) = &request.verified_kernel_map_output {
        let map = first.kernel_map.as_deref().context(
            "verified kernel-map output was requested without a kernel-map artifact contract",
        )?;
        write_verified_file(output, map, "kernel linker map")?;
    }

    Ok(ReproReport {
        schema_version: 3,
        cargo_profile: String::from("boot"),
        scenario: request.scenario,
        rustc_version,
        cargo_version,
        source_revision,
        source_tree_clean,
        cargo_lock_sha256: sha256_hex(&cargo_lock),
        loader_target: request.loader.target.clone(),
        kernel_target: request.kernel.target.clone(),
        loader_required_rustc_flags: artifact_rustc_arguments(&request.loader)?,
        kernel_required_rustc_flags: artifact_rustc_arguments(&request.kernel)?,
        loader_sha256: sha256_hex(&first.loader),
        loader_bytes: u64::try_from(first.loader.len()).context("loader size does not fit u64")?,
        kernel_sha256: sha256_hex(&first.kernel),
        kernel_bytes: u64::try_from(first.kernel.len()).context("kernel size does not fit u64")?,
        image_sha256: first_manifest.image_sha256,
        image_bytes: first_manifest.image_bytes,
        source_date_epoch: SOURCE_DATE_EPOCH,
        workspace_remap_destination: String::from(WORKSPACE_REMAP_DESTINATION),
        cargo_home_remap_destination: String::from(CARGO_HOME_REMAP_DESTINATION),
        user_home_remap_destination: String::from(USER_HOME_REMAP_DESTINATION),
        target_directory_remap_destination: String::from(TARGET_REMAP_DESTINATION),
        loader_path_privacy: first.loader_path_privacy,
        kernel_path_privacy: first.kernel_path_privacy,
        image_path_privacy: first_image_privacy,
    })
}

#[derive(Clone, Debug)]
struct HostPaths {
    cargo_home: PathBuf,
    user_home: PathBuf,
}

impl HostPaths {
    fn discover(workspace: &Path) -> Result<Self> {
        let user_home_value = env::var_os("HOME")
            .context("HOME is unavailable; reproducible path privacy cannot be verified")?;
        let user_home = canonical_directory(Path::new(&user_home_value), workspace, "HOME")?;
        if user_home.parent().is_none() {
            bail!("HOME resolves to a filesystem root; refusing an unbounded path remap");
        }

        let cargo_home_value =
            env::var_os("CARGO_HOME").map_or_else(|| user_home.join(".cargo"), PathBuf::from);
        let cargo_home = canonical_directory(&cargo_home_value, workspace, "Cargo home")?;
        if cargo_home.parent().is_none() {
            bail!("Cargo home resolves to a filesystem root; refusing an unbounded path remap");
        }

        Ok(Self {
            cargo_home,
            user_home,
        })
    }
}

fn canonical_directory(path: &Path, base: &Path, description: &str) -> Result<PathBuf> {
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let canonical = candidate.canonicalize().with_context(|| {
        format!(
            "{description} {} is not a readable directory",
            candidate.display()
        )
    })?;
    if !canonical.is_dir() {
        bail!("{description} is not a directory: {}", canonical.display());
    }
    validate_remap_path(&canonical, description)?;
    Ok(canonical)
}

fn validate_remap_path(path: &Path, description: &str) -> Result<()> {
    let value = path
        .to_str()
        .with_context(|| format!("{description} is not valid UTF-8"))?;
    if value.contains(RUSTFLAG_SEPARATOR) || value.contains('=') {
        bail!("{description} contains a character unsupported by the rustflag contract");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PathKind {
    Target,
    Workspace,
    CargoHome,
    UserHome,
}

impl PathKind {
    const fn description(self) -> &'static str {
        match self {
            Self::Target => "target-directory",
            Self::Workspace => "workspace",
            Self::CargoHome => "Cargo-home",
            Self::UserHome => "user-home",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PathRemap {
    kind: PathKind,
    source: PathBuf,
    destination: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BuildPathContract {
    remaps: Vec<PathRemap>,
}

impl BuildPathContract {
    fn new(workspace: &Path, target_directory: &Path, host_paths: &HostPaths) -> Result<Self> {
        for (path, description) in [
            (workspace, "workspace"),
            (target_directory, "target directory"),
            (&host_paths.cargo_home, "Cargo home"),
            (&host_paths.user_home, "user home"),
        ] {
            validate_remap_path(path, description)?;
        }
        let remaps = vec![
            PathRemap {
                kind: PathKind::Target,
                source: target_directory.to_path_buf(),
                destination: TARGET_REMAP_DESTINATION,
            },
            PathRemap {
                kind: PathKind::Workspace,
                source: workspace.to_path_buf(),
                destination: WORKSPACE_REMAP_DESTINATION,
            },
            PathRemap {
                kind: PathKind::CargoHome,
                source: host_paths.cargo_home.clone(),
                destination: CARGO_HOME_REMAP_DESTINATION,
            },
            PathRemap {
                kind: PathKind::UserHome,
                source: host_paths.user_home.clone(),
                destination: USER_HOME_REMAP_DESTINATION,
            },
        ];
        for (index, remap) in remaps.iter().enumerate() {
            if remaps[..index]
                .iter()
                .any(|existing| existing.source == remap.source)
            {
                bail!(
                    "{} path duplicates a more-specific remap source",
                    remap.kind.description()
                );
            }
        }
        Ok(Self { remaps })
    }
}

fn encoded_rustflags(artifact: &ArtifactSpec, contract: &BuildPathContract) -> Result<OsString> {
    let mut arguments = artifact_rustc_arguments(artifact)?;
    // rustc gives the last matching remap precedence. Emit broad prefixes
    // first so Cargo-home, workspace, and target mappings win over HOME.
    for remap in contract.remaps.iter().rev() {
        let source = remap
            .source
            .to_str()
            .context("validated remap source unexpectedly became non-UTF-8")?;
        arguments.push(format!(
            "--remap-path-prefix={source}={}",
            remap.destination
        ));
    }
    for argument in &arguments {
        validate_rustflag_value(argument, "rustc argument")?;
    }
    Ok(OsString::from(arguments.join(RUSTFLAG_SEPARATOR_TEXT)))
}

fn artifact_rustc_arguments(artifact: &ArtifactSpec) -> Result<Vec<String>> {
    validate_artifact_rustc_contract(artifact)?;
    let mut arguments = Vec::new();
    for flag in &artifact.rustc_flags {
        match flag {
            ArtifactRustcFlag::StaticRelocationModel => {
                arguments.push(String::from("-C"));
                arguments.push(String::from("relocation-model=static"));
            }
            ArtifactRustcFlag::LinkArgument(argument) => {
                validate_rustflag_value(argument, "link argument")?;
                arguments.push(String::from("-C"));
                arguments.push(format!("link-arg={argument}"));
            }
        }
    }
    for argument in &arguments {
        validate_rustflag_value(argument, "artifact rustc argument")?;
    }
    Ok(arguments)
}

fn validate_artifact_rustc_contract(artifact: &ArtifactSpec) -> Result<()> {
    let has_link_argument = |expected: &str| {
        artifact
            .rustc_flags
            .iter()
            .any(|flag| matches!(flag, ArtifactRustcFlag::LinkArgument(value) if value == expected))
    };
    match artifact.target.as_str() {
        "x86_64-unknown-uefi" if !has_link_argument("/debug:none") => {
            bail!("UEFI artifact contract must disable the nondeterministic CodeView record");
        }
        "x86_64-unknown-none"
            if !artifact
                .rustc_flags
                .contains(&ArtifactRustcFlag::StaticRelocationModel)
                || !has_link_argument("-no-pie") =>
        {
            bail!("kernel artifact contract must retain static relocation and -no-pie");
        }
        _ => {}
    }
    Ok(())
}

fn validate_rustflag_value(value: &str, description: &str) -> Result<()> {
    if value.is_empty() || value.contains(RUSTFLAG_SEPARATOR) {
        bail!("{description} is empty or contains the Cargo rustflag separator");
    }
    Ok(())
}

fn verify_path_privacy(
    stage: &str,
    bytes: &[u8],
    contract: &BuildPathContract,
) -> Result<PathPrivacyEvidence> {
    for remap in &contract.remaps {
        let pattern = remap
            .source
            .to_str()
            .context("validated remap source unexpectedly became non-UTF-8")?
            .as_bytes();
        if let Some(offset) = first_subslice(bytes, pattern) {
            bail!(
                "path-privacy failure in {stage}: unremapped {} path starts at byte {offset}",
                remap.kind.description()
            );
        }
    }
    Ok(PathPrivacyEvidence {
        host_patterns_scanned: u32::try_from(contract.remaps.len())
            .context("path-pattern count does not fit u32")?,
        unremapped_matches: 0,
        workspace_destination_occurrences: count_subslices(
            bytes,
            WORKSPACE_REMAP_DESTINATION.as_bytes(),
        ),
        cargo_home_destination_occurrences: count_subslices(
            bytes,
            CARGO_HOME_REMAP_DESTINATION.as_bytes(),
        ),
        user_home_destination_occurrences: count_subslices(
            bytes,
            USER_HOME_REMAP_DESTINATION.as_bytes(),
        ),
        target_destination_occurrences: count_subslices(bytes, TARGET_REMAP_DESTINATION.as_bytes()),
    })
}

fn first_subslice(bytes: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.is_empty() || pattern.len() > bytes.len() {
        return None;
    }
    bytes
        .windows(pattern.len())
        .position(|window| window == pattern)
}

fn count_subslices(bytes: &[u8], pattern: &[u8]) -> u64 {
    if pattern.is_empty() || pattern.len() > bytes.len() {
        return 0;
    }
    bytes
        .windows(pattern.len())
        .filter(|window| *window == pattern)
        .fold(0_u64, |count, _| count.saturating_add(1))
}

fn require_privacy_evidence_identical(
    stage: &str,
    first: &PathPrivacyEvidence,
    second: &PathPrivacyEvidence,
) -> Result<()> {
    if first != second {
        bail!("reproducibility failure: {stage} path-privacy evidence differs between builds");
    }
    Ok(())
}

struct BuiltArtifacts {
    loader: Vec<u8>,
    kernel: Vec<u8>,
    kernel_map: Option<Vec<u8>>,
    loader_path_privacy: PathPrivacyEvidence,
    kernel_path_privacy: PathPrivacyEvidence,
    path_contract: BuildPathContract,
}

fn build_once(
    cargo: &Path,
    workspace: &Path,
    target_directory: &Path,
    request: &ReproRequest,
    host_paths: &HostPaths,
) -> Result<BuiltArtifacts> {
    fs::create_dir_all(target_directory).with_context(|| {
        format!(
            "failed to create clean target directory {}",
            target_directory.display()
        )
    })?;
    let target_directory = target_directory.canonicalize().with_context(|| {
        format!(
            "failed to resolve clean target directory {}",
            target_directory.display()
        )
    })?;
    let path_contract = BuildPathContract::new(workspace, &target_directory, host_paths)
        .context("failed to construct the deterministic path-remapping contract")?;
    build_artifact(
        cargo,
        workspace,
        &target_directory,
        &request.loader,
        &path_contract,
        host_paths,
    )?;
    build_artifact(
        cargo,
        workspace,
        &target_directory,
        &request.kernel,
        &path_contract,
        host_paths,
    )?;

    let loader = read_artifact(&target_directory, &request.loader)?;
    let kernel = read_artifact(&target_directory, &request.kernel)?;
    let kernel_map = request
        .kernel_map_relative_path
        .as_ref()
        .map(|relative| read_bounded_path(&target_directory.join(relative), "kernel linker map"))
        .transpose()?;
    let loader_path_privacy = verify_path_privacy("loader", &loader, &path_contract)?;
    let kernel_path_privacy = verify_path_privacy("kernel", &kernel, &path_contract)?;

    Ok(BuiltArtifacts {
        loader,
        kernel,
        kernel_map,
        loader_path_privacy,
        kernel_path_privacy,
        path_contract,
    })
}

fn build_artifact(
    cargo: &Path,
    workspace: &Path,
    target_directory: &Path,
    artifact: &ArtifactSpec,
    path_contract: &BuildPathContract,
    host_paths: &HostPaths,
) -> Result<()> {
    let manifest = workspace.join("Cargo.toml");
    let encoded_rustflags = encoded_rustflags(artifact, path_contract)?;
    let mut command = Command::new(cargo);
    command
        .current_dir(workspace)
        .arg("rustc")
        .arg("--locked")
        .arg("--profile")
        .arg("boot")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--package")
        .arg(&artifact.package)
        .arg("--bin")
        .arg(&artifact.binary)
        .arg("--target")
        .arg(&artifact.target);
    if !artifact.features.is_empty() {
        command.arg("--features").arg(artifact.features.join(","));
    }
    let output = command
        .env("CARGO_TARGET_DIR", target_directory)
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_HOME", &host_paths.cargo_home)
        .env("HOME", &host_paths.user_home)
        .env("CARGO_ENCODED_RUSTFLAGS", encoded_rustflags)
        .env_remove("RUSTFLAGS")
        .env("SOURCE_DATE_EPOCH", SOURCE_DATE_EPOCH.to_string())
        .output()
        .with_context(|| format!("failed to execute Cargo for {}", artifact.package))?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "clean build failed for {} ({})\nstdout:\n{}\nstderr:\n{}",
            artifact.package,
            output.status,
            stdout.trim_end(),
            stderr.trim_end()
        );
    }
    Ok(())
}

fn read_artifact(target_directory: &Path, artifact: &ArtifactSpec) -> Result<Vec<u8>> {
    let path = target_directory.join(&artifact.relative_path);
    let metadata = fs::metadata(&path).with_context(|| {
        format!(
            "Cargo completed but expected {} artifact is absent at {}",
            artifact.package,
            path.display()
        )
    })?;
    if !metadata.is_file() || metadata.len() > MAX_ARTIFACT_BYTES {
        bail!(
            "{} artifact is not a regular file within the {MAX_ARTIFACT_BYTES}-byte bound",
            artifact.package
        );
    }
    fs::read(&path).with_context(|| {
        format!(
            "Cargo completed but expected {} artifact is absent at {}",
            artifact.package,
            path.display()
        )
    })
}

fn read_bounded_path(path: &Path, description: &str) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to inspect {description} {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_ARTIFACT_BYTES {
        bail!(
            "{description} is not a regular file within the {MAX_ARTIFACT_BYTES}-byte bound: {}",
            path.display()
        );
    }
    fs::read(path).with_context(|| format!("failed to read {description} {}", path.display()))
}

fn require_identical(stage: &str, left: &[u8], right: &[u8]) -> Result<()> {
    if let Some(difference) = first_difference(left, right) {
        return Err(reproducibility_error(
            stage,
            difference,
            left.len(),
            right.len(),
        ));
    }
    Ok(())
}

fn reproducibility_error(
    stage: &str,
    difference: ByteDifference,
    left_len: usize,
    right_len: usize,
) -> anyhow::Error {
    anyhow::anyhow!(
        "reproducibility failure at {stage} byte {}: build-a={:?}, build-b={:?}, lengths={left_len}/{right_len}",
        difference.offset,
        difference.left,
        difference.right
    )
}

fn write_verified_image(output: &Path, image: &[u8]) -> Result<()> {
    write_verified_file(output, image, "disk image")
}

fn write_verified_file(output: &Path, bytes: &[u8], description: &str) -> Result<()> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let temporary = parent.join(format!(
        ".{}.repro-{}",
        output
            .file_name()
            .with_context(|| format!("verified {description} output must include a file name"))?
            .to_string_lossy(),
        std::process::id()
    ));
    let result = (|| -> Result<()> {
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
                "failed to move verified {description} {} to {}",
                temporary.display(),
                output.display()
            )
        })?;
        File::open(parent)
            .with_context(|| format!("failed to open output directory {}", parent.display()))?
            .sync_all()
            .with_context(|| format!("failed to sync output directory {}", parent.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn resolve_cargo(override_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        return require_executable(path, "Cargo override");
    }
    if let Some(path) = env::var_os("POLYTOPE_CARGO") {
        return require_executable(Path::new(&path), "POLYTOPE_CARGO");
    }
    if let Some(path) = find_on_path("cargo") {
        return Ok(path);
    }
    let homebrew = Path::new("/opt/homebrew/opt/rustup/bin/cargo");
    if homebrew.is_file() {
        return Ok(homebrew.to_path_buf());
    }
    bail!("could not find Cargo; set POLYTOPE_CARGO or pass --cargo")
}

fn resolve_rustc() -> Result<PathBuf> {
    if let Some(path) = env::var_os("RUSTC") {
        return require_executable(Path::new(&path), "RUSTC");
    }
    if let Some(path) = find_on_path("rustc") {
        return Ok(path);
    }
    let homebrew = Path::new("/opt/homebrew/opt/rustup/bin/rustc");
    if homebrew.is_file() {
        return Ok(homebrew.to_path_buf());
    }
    bail!("could not find rustc; set RUSTC or place the Rustup proxy on PATH")
}

fn tool_version(tool: &Path, arguments: &[&str]) -> Result<String> {
    let output = Command::new(tool)
        .args(arguments)
        .output()
        .with_context(|| format!("failed to query {} version", tool.display()))?;
    if !output.status.success() {
        bail!(
            "{} version query failed with {}",
            tool.display(),
            output.status
        );
    }
    let version = String::from_utf8(output.stdout)
        .with_context(|| format!("{} version output is not UTF-8", tool.display()))?;
    Ok(version.trim().to_owned())
}

fn git_source_state(workspace: &Path) -> (Option<String>, Option<bool>) {
    let revision = Command::new("git")
        .current_dir(workspace)
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned());
    let clean = Command::new("git")
        .current_dir(workspace)
        .args(["status", "--porcelain=v1", "--untracked-files=normal"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| output.stdout.is_empty());
    (revision, clean)
}

fn require_executable(path: &Path, source: &str) -> Result<PathBuf> {
    if path.is_file() {
        Ok(path.to_path_buf())
    } else {
        bail!("{source} does not identify a file: {}", path.display())
    }
}

fn find_on_path(program: &str) -> Option<PathBuf> {
    let path: OsString = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactRustcFlag, BuildPathContract, CARGO_HOME_REMAP_DESTINATION, PathKind, PathRemap,
        ReproRequest, TARGET_REMAP_DESTINATION, USER_HOME_REMAP_DESTINATION,
        WORKSPACE_REMAP_DESTINATION, encoded_rustflags, require_identical, verify_path_privacy,
    };
    use std::path::PathBuf;

    fn path_contract() -> BuildPathContract {
        BuildPathContract {
            remaps: vec![
                PathRemap {
                    kind: PathKind::Target,
                    source: PathBuf::from("/private/build-a"),
                    destination: TARGET_REMAP_DESTINATION,
                },
                PathRemap {
                    kind: PathKind::Workspace,
                    source: PathBuf::from("/Users/example/work/polytope-os"),
                    destination: WORKSPACE_REMAP_DESTINATION,
                },
                PathRemap {
                    kind: PathKind::CargoHome,
                    source: PathBuf::from("/Users/example/.cargo"),
                    destination: CARGO_HOME_REMAP_DESTINATION,
                },
                PathRemap {
                    kind: PathKind::UserHome,
                    source: PathBuf::from("/Users/example"),
                    destination: USER_HOME_REMAP_DESTINATION,
                },
            ],
        }
    }

    #[test]
    fn difference_error_identifies_stage_and_offset() {
        let error = require_identical("kernel", b"abc", b"abx")
            .unwrap_err()
            .to_string();
        assert!(error.contains("kernel byte 2"));
    }

    #[test]
    fn encoded_flags_cover_dependencies_without_dropping_target_link_contracts() {
        let request = ReproRequest::polytope_defaults(PathBuf::from("."), PathBuf::from("out.img"));
        let contract = path_contract();

        let loader = encoded_rustflags(&request.loader, &contract).expect("loader flags");
        let loader: Vec<&str> = loader
            .to_str()
            .expect("test flags are UTF-8")
            .split('\u{1f}')
            .collect();
        assert!(
            loader
                .windows(2)
                .any(|pair| pair == ["-C", "link-arg=/debug:none"])
        );
        assert_eq!(
            loader
                .iter()
                .filter(|argument| argument.starts_with("--remap-path-prefix="))
                .count(),
            4
        );
        assert!(loader.iter().any(|argument| {
            *argument == "--remap-path-prefix=/Users/example/.cargo=/build/cargo-home"
        }));
        let user_remap = loader
            .iter()
            .position(|argument| argument.ends_with("=/build/user-home"))
            .expect("user-home remap");
        let cargo_remap = loader
            .iter()
            .position(|argument| argument.ends_with("=/build/cargo-home"))
            .expect("Cargo-home remap");
        let workspace_remap = loader
            .iter()
            .position(|argument| argument.ends_with("=/workspace/polytope-os"))
            .expect("workspace remap");
        let target_remap = loader
            .iter()
            .position(|argument| argument.ends_with("=/build/target"))
            .expect("target-directory remap");
        assert!(user_remap < cargo_remap);
        assert!(cargo_remap < workspace_remap);
        assert!(workspace_remap < target_remap);

        let kernel = encoded_rustflags(&request.kernel, &contract).expect("kernel flags");
        let kernel: Vec<&str> = kernel
            .to_str()
            .expect("test flags are UTF-8")
            .split('\u{1f}')
            .collect();
        assert!(
            kernel
                .windows(2)
                .any(|pair| pair == ["-C", "relocation-model=static"])
        );
        assert!(
            kernel
                .windows(2)
                .any(|pair| pair == ["-C", "link-arg=-no-pie"])
        );
    }

    #[test]
    fn encoded_flags_reject_separator_injection() {
        let mut request =
            ReproRequest::polytope_defaults(PathBuf::from("."), PathBuf::from("out.img"));
        request
            .loader
            .rustc_flags
            .push(ArtifactRustcFlag::LinkArgument(String::from(
                "bad\u{1f}flag",
            )));
        let error = encoded_rustflags(&request.loader, &path_contract())
            .expect_err("separator must fail")
            .to_string();
        assert!(error.contains("separator"));
    }

    #[test]
    fn known_targets_fail_closed_when_required_flags_are_removed() {
        let mut request =
            ReproRequest::polytope_defaults(PathBuf::from("."), PathBuf::from("out.img"));
        request.loader.rustc_flags.clear();
        let loader_error = encoded_rustflags(&request.loader, &path_contract())
            .expect_err("missing UEFI flag must fail")
            .to_string();
        assert!(loader_error.contains("CodeView"));

        request.kernel.rustc_flags.clear();
        let kernel_error = encoded_rustflags(&request.kernel, &path_contract())
            .expect_err("missing kernel flags must fail")
            .to_string();
        assert!(kernel_error.contains("static relocation"));
    }

    #[test]
    fn privacy_scan_fails_on_exact_unremapped_host_path() {
        let bytes = b"prefix:/Users/example/.cargo/registry/src/dependency.rs:suffix";
        let error = verify_path_privacy("loader", bytes, &path_contract())
            .expect_err("host path must fail")
            .to_string();
        assert!(error.contains("loader"));
        assert!(error.contains("Cargo-home"));
        assert!(error.contains("byte 7"));
    }

    #[test]
    fn privacy_scan_reports_exact_normalized_destination_occurrences() {
        let bytes = format!(
            "{WORKSPACE_REMAP_DESTINATION}/src/main.rs\0{CARGO_HOME_REMAP_DESTINATION}/registry/a.rs\0{CARGO_HOME_REMAP_DESTINATION}/registry/b.rs\0{USER_HOME_REMAP_DESTINATION}/.rustup/lib.rs\0{TARGET_REMAP_DESTINATION}/release/out"
        );
        let evidence = verify_path_privacy("kernel", bytes.as_bytes(), &path_contract())
            .expect("normalized paths must pass");
        assert_eq!(evidence.host_patterns_scanned, 4);
        assert_eq!(evidence.unremapped_matches, 0);
        assert_eq!(evidence.workspace_destination_occurrences, 1);
        assert_eq!(evidence.cargo_home_destination_occurrences, 2);
        assert_eq!(evidence.user_home_destination_occurrences, 1);
        assert_eq!(evidence.target_destination_occurrences, 1);
    }
}
