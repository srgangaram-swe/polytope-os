//! Bounded, headless QEMU boot execution and baseline reporting.

use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use ovmf_prebuilt::{Arch, FileType, Prebuilt, Source};
use serde::{Deserialize, Serialize};

use crate::image::{BootScenario, DISK_BYTES, validate_image_bytes};
use crate::sha256_hex;
use crate::temporary::TemporaryDirectory;

/// Pinned OVMF release used when firmware paths are not supplied explicitly.
pub const OVMF_RELEASE: &str = "edk2-stable202605-r1";
const OVMF_SOURCE: Source = Source {
    tag: OVMF_RELEASE,
    sha256: "8ae4d2d73161cc2335f5675d3b8b6edfa0642301679764a246940488ea3ce20d",
};
/// Marker emitted after a successful kernel handoff.
pub const READY_MARKER: &str =
    "POLYTOPE_BOOT schema=1 seq=0004 phase=kernel_entry level=info code=KERNEL_READY";
/// Marker emitted for an unsupported contract version.
pub const BAD_VERSION_MARKER: &str =
    "POLYTOPE_BOOT schema=1 seq=0004 phase=kernel_entry level=error code=ABI_VERSION";
/// Marker emitted for a truncated contract.
pub const TRUNCATED_MARKER: &str =
    "POLYTOPE_BOOT schema=1 seq=0004 phase=kernel_entry level=error code=CONTRACT_LENGTH";
/// Marker emitted by a kernel panic path.
pub const PANIC_MARKER: &str =
    "POLYTOPE_BOOT schema=1 seq=0005 phase=panic level=fatal code=KERNEL_PANIC";
const CONTRACT_INVALID_MARKER: &str =
    "POLYTOPE_BOOT schema=1 seq=0004 phase=kernel_entry level=error code=CONTRACT_INVALID";
const LOADER_START_MARKER: &str =
    "POLYTOPE_BOOT schema=1 seq=0001 phase=loader level=info code=LOADER_START";
const ELF_VALID_MARKER: &str =
    "POLYTOPE_BOOT schema=1 seq=0002 phase=loader level=info code=ELF_VALID";
const HANDOFF_READY_MARKER: &str =
    "POLYTOPE_BOOT schema=1 seq=0003 phase=handoff level=info code=HANDOFF_READY";
/// QEMU process status produced by guest debug-exit value `0x10`.
pub const READY_EXIT_STATUS: i32 = 33;
/// QEMU process status produced by guest debug-exit value `0x20`.
pub const REJECT_EXIT_STATUS: i32 = 65;
/// QEMU process status produced by guest debug-exit value `0x21`.
pub const PANIC_EXIT_STATUS: i32 = 67;

/// Inputs for one bounded QEMU boot.
#[derive(Clone, Debug)]
pub struct BootRequest {
    /// Raw GPT/FAT image to boot.
    pub image: PathBuf,
    /// Scenario expected from the image.
    pub scenario: BootScenario,
    /// Hard guest timeout.
    pub timeout: Duration,
    /// QEMU executable override.
    pub qemu: Option<PathBuf>,
    /// Directory used for checksum-pinned OVMF downloads.
    pub ovmf_cache: PathBuf,
}

/// Classified result of a bounded boot attempt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BootClassification {
    /// Kernel reached its ready marker.
    Ready,
    /// Kernel rejected an invalid boot contract.
    Rejected,
    /// Kernel emitted its panic marker.
    Panic,
    /// QEMU exceeded the hard timeout and was terminated.
    Timeout,
    /// QEMU emitted conflicting terminal markers or otherwise violated the protocol.
    UnexpectedExit,
    /// QEMU exited without emitting any terminal marker.
    MissingMarker,
    /// The loader reported a pre-kernel failure through its dedicated exit value.
    LoaderFailure,
}

/// Purpose of a bounded QEMU execution.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BootMode {
    /// Validate the terminal marker and exit status selected by the image scenario.
    Scenario,
    /// Omit the debug-exit device and prove the harness terminates and reaps a hung guest.
    TimeoutProbe,
}

/// Distribution statistics for repeated unsigned measurements.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SampleStatistics {
    /// Lowest observed value.
    pub min: u64,
    /// Arithmetic median; fractional for an even number of samples.
    pub median: f64,
    /// Nearest-rank 95th percentile.
    pub p95: u64,
    /// Highest observed value.
    pub max: u64,
    /// Arithmetic mean.
    pub mean: f64,
    /// Population standard deviation.
    pub population_stddev: f64,
}

/// Machine-readable evidence from one QEMU run.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BootRun {
    /// Report schema version.
    pub schema_version: u32,
    /// Execution purpose and corresponding validation contract.
    pub mode: BootMode,
    /// Expected scenario.
    pub scenario: BootScenario,
    /// Terminal classification inferred from logs and timeout state.
    pub classification: BootClassification,
    /// QEMU process exit status, absent when terminated by signal.
    pub exit_status: Option<i32>,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Configured hard timeout in milliseconds.
    pub timeout_ms: u64,
    /// Wall-clock time until `KERNEL_READY` was first observed, when present.
    pub time_to_ready_marker_ms: Option<u64>,
    /// Highest sampled resident set size in KiB.
    pub peak_rss_kib: Option<u64>,
    /// SHA-256 digest of the boot image.
    pub image_sha256: String,
    /// Exact boot-image size in bytes.
    pub image_bytes: u64,
    /// SHA-256 digest of the OVMF code image.
    pub ovmf_code_sha256: String,
    /// SHA-256 digest of the pristine OVMF variable template.
    pub ovmf_vars_sha256: String,
    /// First line returned by `qemu-system-x86_64 --version`.
    pub qemu_version: String,
    /// Checksum-pinned OVMF release, or `environment-override` for explicit paths.
    pub ovmf_release: String,
    /// Executed QEMU argument vector with host-specific paths replaced by labels.
    pub qemu_argv: Vec<String>,
    /// Whether the ready marker was observed.
    pub saw_ready_marker: bool,
    /// Whether the rejection marker was observed.
    pub saw_reject_marker: bool,
    /// Whether the panic marker was observed.
    pub saw_panic_marker: bool,
    /// Canonical terminal diagnostic code, when exactly one was observed.
    pub terminal_code: Option<String>,
    /// Strict diagnostic protocol violation, when classification rejected the stream.
    pub diagnostic_protocol_error: Option<String>,
    /// Combined serial, debugcon, stderr, and stdout output.
    pub log: String,
}

/// Request for repeated boot measurements.
#[derive(Clone, Debug)]
pub struct BaselineRequest {
    /// Shared boot configuration.
    pub boot: BootRequest,
    /// Number of measured runs.
    pub runs: usize,
    /// Machine-readable JSON report destination.
    pub output: PathBuf,
}

/// Repeated-run boot-time and memory baseline.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BaselineReport {
    /// Report schema version.
    pub schema_version: u32,
    /// Number of successful runs.
    pub runs: usize,
    /// Distribution of time-to-`KERNEL_READY` observations in milliseconds.
    pub time_to_ready_marker_ms: SampleStatistics,
    /// Distribution of per-process peak resident set size in KiB.
    pub peak_rss_kib: SampleStatistics,
    /// Number of runs that yielded a peak-RSS sample.
    pub peak_rss_sample_count: usize,
    /// Host operating system.
    pub host_os: String,
    /// Host CPU architecture.
    pub host_arch: String,
    /// Firmware release/source identifier shared by all samples.
    pub ovmf_release: String,
    /// Individual run evidence.
    pub samples: Vec<BootRun>,
}

/// Executes one isolated, bounded, headless QEMU boot and validates its outcome.
///
/// # Errors
///
/// Returns an error when tools or firmware are missing, QEMU cannot start, or
/// observed markers and exit status do not match the requested scenario.
pub fn run_boot(request: &BootRequest) -> Result<BootRun> {
    let run = observe_boot(request, BootMode::Scenario)?;
    validate_boot_outcome(&run)?;
    Ok(run)
}

/// Observes one isolated QEMU execution without discarding a mismatched report.
///
/// Callers must serialize the returned report before applying
/// [`validate_boot_outcome`] or [`validate_timeout_probe`] when failure
/// evidence must survive a nonzero command exit.
///
/// # Errors
///
/// Returns an error only when inputs, tools, firmware, process control, or
/// evidence collection fail before a complete observation can be produced.
pub fn observe_boot(request: &BootRequest, mode: BootMode) -> Result<BootRun> {
    ensure!(
        request.timeout > Duration::ZERO,
        "boot timeout must be positive"
    );
    let image = read_bounded(&request.image, DISK_BYTES, "boot image")?;
    ensure!(
        image.len() == DISK_BYTES,
        "boot image is {} bytes; expected {DISK_BYTES}",
        image.len()
    );
    let image_manifest =
        validate_image_bytes(&image).context("refusing to execute an invalid image")?;
    ensure!(
        image_manifest.scenario == request.scenario,
        "requested scenario {} does not match image scenario {}",
        request.scenario.as_str(),
        image_manifest.scenario.as_str()
    );
    let qemu = resolve_qemu(request.qemu.as_deref())?;
    let qemu_version = qemu_version(&qemu)?;
    let firmware = resolve_firmware(&request.ovmf_cache)?;
    let ovmf_code = read_bounded(&firmware.code, 64 * 1024 * 1024, "OVMF code")?;
    let ovmf_vars = read_bounded(&firmware.vars, 64 * 1024 * 1024, "OVMF vars")?;

    let temporary = TemporaryDirectory::create(&env::temp_dir(), "qemu")?;
    let image_copy = temporary.path().join("validated-boot.img");
    let code_copy = temporary.path().join("validated-code.fd");
    let vars_copy = temporary.path().join("vars.fd");
    fs::write(&image_copy, &image).context("failed to stage validated boot-image bytes")?;
    fs::write(&code_copy, &ovmf_code).context("failed to stage validated OVMF-code bytes")?;
    fs::write(&vars_copy, &ovmf_vars).with_context(|| {
        format!(
            "failed to create mutable OVMF vars at {}",
            vars_copy.display()
        )
    })?;
    let serial_path = temporary.path().join("serial.log");
    let debug_path = temporary.path().join("debug.log");
    let stdout_path = temporary.path().join("stdout.log");
    let stderr_path = temporary.path().join("stderr.log");
    let stdout = File::create(&stdout_path).context("failed to create QEMU stdout log")?;
    let stderr = File::create(&stderr_path).context("failed to create QEMU stderr log")?;

    let invocation = qemu_invocation(
        &qemu,
        &code_copy,
        &vars_copy,
        &image_copy,
        &serial_path,
        &debug_path,
        mode == BootMode::Scenario,
    );
    let mut command = Command::new(&qemu);
    command
        .args(&invocation.arguments)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));

    let execution =
        execute_bounded_qemu(command, &qemu, &image_copy, request.timeout, &debug_path)?;

    let (debug_bytes, debug_truncated) = read_log_bounded(&debug_path)?;
    let trace = parse_protocol_stream(&debug_bytes, debug_truncated);
    let log = collect_logs(&[&serial_path, &debug_path, &stderr_path, &stdout_path])?;
    let classification = classify_boot(execution.timed_out, execution.exit_status, &trace);
    let image_bytes = u64::try_from(image.len()).context("disk image length does not fit u64")?;

    let run = BootRun {
        schema_version: 2,
        mode,
        scenario: request.scenario,
        classification,
        exit_status: execution.exit_status,
        duration_ms: execution.duration_ms,
        timeout_ms: u64::try_from(request.timeout.as_millis()).unwrap_or(u64::MAX),
        time_to_ready_marker_ms: execution.time_to_ready_marker_ms,
        peak_rss_kib: execution.peak_rss_kib,
        image_sha256: sha256_hex(&image),
        image_bytes,
        ovmf_code_sha256: sha256_hex(&ovmf_code),
        ovmf_vars_sha256: sha256_hex(&ovmf_vars),
        qemu_version,
        ovmf_release: String::from(firmware.release),
        qemu_argv: invocation.sanitized_argv,
        saw_ready_marker: trace.markers.ready,
        saw_reject_marker: trace.markers.rejected,
        saw_panic_marker: trace.markers.panic,
        terminal_code: trace.markers.terminal_code.map(String::from),
        diagnostic_protocol_error: trace.violation.map(String::from),
        log,
    };
    Ok(run)
}

/// Validates a scenario run against its exact marker/exit contract.
///
/// # Errors
///
/// Returns an error when the report is not a scenario run or its observed
/// result does not exactly match the selected image scenario.
pub fn validate_boot_outcome(run: &BootRun) -> Result<()> {
    ensure!(
        run.mode == BootMode::Scenario,
        "scenario validation received a timeout-probe report"
    );
    validate_scenario_outcome(run)
}

/// Validates evidence that the harness killed and reaped a deliberately hung guest.
///
/// # Errors
///
/// Returns an error unless the report is a timeout probe whose elapsed time
/// reached the configured bound and whose terminal classification is timeout.
pub fn validate_timeout_probe(run: &BootRun) -> Result<()> {
    ensure!(
        run.mode == BootMode::TimeoutProbe
            && run.classification == BootClassification::Timeout
            && run.duration_ms >= run.timeout_ms,
        "timeout probe failed: classification={:?}, duration_ms={}, timeout_ms={}\n{}",
        run.classification,
        run.duration_ms,
        run.timeout_ms,
        run.log
    );
    Ok(())
}

/// Executes repeated successful boots and writes a JSON baseline atomically.
///
/// # Errors
///
/// Returns an error when the run count is invalid, any boot fails, or the report
/// cannot be written.
pub fn run_baseline(request: &BaselineRequest) -> Result<BaselineReport> {
    ensure!(request.runs > 0, "baseline requires at least one run");
    ensure!(request.runs <= 100, "baseline run count is capped at 100");
    ensure!(
        request.boot.scenario == BootScenario::Normal,
        "boot-time baselines require the normal scenario"
    );
    let mut samples = Vec::with_capacity(request.runs);
    for _ in 0..request.runs {
        samples.push(run_boot(&request.boot)?);
    }
    let marker_times: Vec<u64> = samples
        .iter()
        .map(|sample| {
            sample
                .time_to_ready_marker_ms
                .context("a validated normal boot did not retain its KERNEL_READY observation time")
        })
        .collect::<Result<_>>()?;
    let peak_rss_samples: Vec<u64> = samples
        .iter()
        .enumerate()
        .map(|(index, sample)| {
            sample.peak_rss_kib.with_context(|| {
                format!(
                    "baseline run {} has no peak-RSS sample; ensure the host `ps` command supports RSS reporting",
                    index + 1
                )
            })
        })
        .collect::<Result<_>>()?;
    let first = samples
        .first()
        .context("the baseline unexpectedly has no samples")?;
    for (index, sample) in samples.iter().enumerate().skip(1) {
        ensure!(
            sample.mode == first.mode
                && sample.scenario == first.scenario
                && sample.timeout_ms == first.timeout_ms
                && sample.image_sha256 == first.image_sha256
                && sample.image_bytes == first.image_bytes
                && sample.ovmf_code_sha256 == first.ovmf_code_sha256
                && sample.ovmf_vars_sha256 == first.ovmf_vars_sha256
                && sample.qemu_version == first.qemu_version
                && sample.ovmf_release == first.ovmf_release
                && sample.qemu_argv == first.qemu_argv,
            "baseline run {} does not share the first run's complete execution identity",
            index + 1
        );
    }
    let ovmf_release = first.ovmf_release.clone();
    let time_to_ready_marker_ms = sample_statistics(&marker_times)
        .context("the non-empty baseline unexpectedly has no marker-time samples")?;
    let report = BaselineReport {
        schema_version: 2,
        runs: samples.len(),
        time_to_ready_marker_ms,
        peak_rss_kib: sample_statistics(&peak_rss_samples)
            .context("the non-empty baseline unexpectedly has no RSS samples")?,
        peak_rss_sample_count: peak_rss_samples.len(),
        host_os: String::from(env::consts::OS),
        host_arch: String::from(env::consts::ARCH),
        ovmf_release,
        samples,
    };
    write_json_atomic(&request.output, &report)?;
    Ok(report)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QemuExecution {
    exit_status: Option<i32>,
    duration_ms: u64,
    time_to_ready_marker_ms: Option<u64>,
    peak_rss_kib: Option<u64>,
    timed_out: bool,
}

fn execute_bounded_qemu(
    mut command: Command,
    qemu: &Path,
    image: &Path,
    timeout: Duration,
    debug_log: &Path,
) -> Result<QemuExecution> {
    let started = Instant::now();
    let child = command.spawn().with_context(|| {
        format!(
            "failed to start {} for image {}",
            qemu.display(),
            image.display()
        )
    })?;
    let mut child = ChildGuard::new(child);
    let mut timed_out = false;
    let mut ready_observer = ReadyMarkerObserver::new([debug_log]);
    let mut rss_sampler = RssSampler::new();
    let status = loop {
        let elapsed = started.elapsed();
        ready_observer.observe(started)?;
        if let Some(status) = child.try_wait().context("failed to query QEMU status")? {
            child.disarm();
            break status;
        }
        if elapsed >= timeout {
            timed_out = true;
            break child
                .terminate()
                .context("failed to terminate and reap timed-out QEMU")?;
        }
        rss_sampler.poll(child.id(), elapsed);
        thread::sleep(Duration::from_millis(5));
    };
    ready_observer.observe(started)?;
    rss_sampler.poll(child.id(), started.elapsed());
    let peak_rss_kib = rss_sampler.finish();
    Ok(QemuExecution {
        exit_status: status.code(),
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        time_to_ready_marker_ms: ready_observer.observed_ms(),
        peak_rss_kib,
        timed_out,
    })
}

const RSS_SAMPLE_INTERVAL: Duration = Duration::from_millis(25);
const RSS_SAMPLE_TIMEOUT: Duration = Duration::from_millis(20);

struct RssSampler {
    process: Option<SamplerProcess>,
    next_sample: Duration,
    peak_kib: Option<u64>,
    disabled: bool,
}

struct SamplerProcess {
    child: ChildGuard,
    started: Instant,
}

impl RssSampler {
    const fn new() -> Self {
        Self {
            process: None,
            next_sample: Duration::ZERO,
            peak_kib: None,
            disabled: false,
        }
    }

    fn poll(&mut self, pid: u32, elapsed: Duration) {
        if let Some(process) = &mut self.process {
            match process.child.try_wait() {
                Ok(Some(_)) => {
                    process.child.disarm();
                    let sample = process.child.take_stdout().and_then(parse_rss_output);
                    self.peak_kib = max_option(self.peak_kib, sample);
                    self.process = None;
                    self.next_sample = elapsed.saturating_add(RSS_SAMPLE_INTERVAL);
                }
                Ok(None) if process.started.elapsed() < RSS_SAMPLE_TIMEOUT => return,
                Ok(None) | Err(_) => {
                    let _ = process.child.terminate();
                    self.process = None;
                    self.next_sample = elapsed.saturating_add(RSS_SAMPLE_INTERVAL);
                    return;
                }
            }
        }
        if self.process.is_some() || self.disabled || elapsed < self.next_sample {
            return;
        }
        let mut command = Command::new("ps");
        command
            .args(["-o", "rss=", "-p"])
            .arg(pid.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        match command.spawn() {
            Ok(child) => {
                self.process = Some(SamplerProcess {
                    child: ChildGuard::new(child),
                    started: Instant::now(),
                });
            }
            Err(_) => self.disabled = true,
        }
    }

    fn finish(mut self) -> Option<u64> {
        if let Some(process) = &mut self.process {
            if matches!(process.child.try_wait(), Ok(Some(_))) {
                process.child.disarm();
                let sample = process.child.take_stdout().and_then(parse_rss_output);
                self.peak_kib = max_option(self.peak_kib, sample);
            } else {
                let _ = process.child.terminate();
            }
        }
        self.peak_kib
    }
}

fn parse_rss_output(mut output: impl Read) -> Option<u64> {
    let mut bytes = Vec::new();
    output.by_ref().take(128).read_to_end(&mut bytes).ok()?;
    std::str::from_utf8(&bytes).ok()?.trim().parse().ok()
}

/// Ensures every spawned QEMU process is killed and reaped on early return.
struct ChildGuard {
    child: Child,
    armed: bool,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child, armed: true }
    }

    fn id(&self) -> u32 {
        self.child.id()
    }

    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn terminate(&mut self) -> std::io::Result<ExitStatus> {
        self.child.kill()?;
        let status = self.child.wait()?;
        self.disarm();
        Ok(status)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[derive(Clone, Debug)]
struct QemuInvocation {
    arguments: Vec<OsString>,
    sanitized_argv: Vec<String>,
}

impl QemuInvocation {
    fn new(qemu: &Path) -> Self {
        let executable = qemu.file_name().map_or_else(
            || String::from("<QEMU_EXECUTABLE>"),
            |name| name.to_string_lossy().into_owned(),
        );
        Self {
            arguments: Vec::new(),
            sanitized_argv: vec![executable],
        }
    }

    fn push(&mut self, argument: impl Into<OsString>, sanitized: impl Into<String>) {
        self.arguments.push(argument.into());
        self.sanitized_argv.push(sanitized.into());
    }

    fn push_literal(&mut self, argument: &str) {
        self.push(argument, argument);
    }
}

fn qemu_invocation(
    qemu: &Path,
    ovmf_code: &Path,
    ovmf_vars: &Path,
    image: &Path,
    serial_log: &Path,
    debug_log: &Path,
    attach_debug_exit: bool,
) -> QemuInvocation {
    let mut invocation = QemuInvocation::new(qemu);
    for argument in [
        "-machine",
        "q35,accel=tcg",
        "-cpu",
        "max",
        "-smp",
        "1",
        "-m",
        "256M",
        "-display",
        "none",
        "-monitor",
        "none",
        "-nic",
        "none",
        "-no-reboot",
        "-boot",
        "order=c,strict=on",
        "-snapshot",
        "-drive",
    ] {
        invocation.push_literal(argument);
    }
    invocation.push(
        format!(
            "if=pflash,format=raw,unit=0,readonly=on,file={}",
            qemu_option_path(ovmf_code)
        ),
        "if=pflash,format=raw,unit=0,readonly=on,file=<OVMF_CODE>",
    );
    invocation.push_literal("-drive");
    invocation.push(
        format!(
            "if=pflash,format=raw,unit=1,file={}",
            qemu_option_path(ovmf_vars)
        ),
        "if=pflash,format=raw,unit=1,file=<OVMF_VARS_MUTABLE>",
    );
    invocation.push_literal("-drive");
    invocation.push(
        format!(
            "format=raw,if=virtio,readonly=on,file={}",
            qemu_option_path(image)
        ),
        "format=raw,if=virtio,readonly=on,file=<BOOT_IMAGE>",
    );
    invocation.push_literal("-serial");
    invocation.push(
        format!("file:{}", serial_log.display()),
        "file:<SERIAL_LOG>",
    );
    invocation.push_literal("-debugcon");
    invocation.push(
        format!("file:{}", debug_log.display()),
        "file:<DEBUGCON_LOG>",
    );
    for argument in ["-global", "isa-debugcon.iobase=0xe9"] {
        invocation.push_literal(argument);
    }
    if attach_debug_exit {
        invocation.push_literal("-device");
        invocation.push_literal("isa-debug-exit,iobase=0xf4,iosize=0x04");
    }
    if cfg!(target_os = "linux") {
        invocation.push_literal("-sandbox");
        invocation.push_literal(
            "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        );
    }
    debug_assert_eq!(
        invocation.arguments.len() + 1,
        invocation.sanitized_argv.len()
    );
    invocation
}

const MAX_OBSERVED_LOG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DIAGNOSTIC_RECORD_BYTES: usize = 256;

#[derive(Debug)]
struct ReadyMarkerObserver {
    cursors: Vec<LogCursor>,
    observed_at: Option<Duration>,
}

impl ReadyMarkerObserver {
    fn new<const N: usize>(paths: [&Path; N]) -> Self {
        Self {
            cursors: paths.into_iter().map(LogCursor::new).collect(),
            observed_at: None,
        }
    }

    fn observe(&mut self, started: Instant) -> Result<()> {
        if self.observed_at.is_some() {
            return Ok(());
        }
        for cursor in &mut self.cursors {
            if cursor.contains_new(READY_MARKER.as_bytes())? {
                self.observed_at = Some(started.elapsed());
                break;
            }
        }
        Ok(())
    }

    fn observed_ms(&self) -> Option<u64> {
        self.observed_at
            .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
    }
}

#[derive(Debug)]
struct LogCursor {
    path: PathBuf,
    offset: u64,
    scanned: u64,
    pending_line: Vec<u8>,
    discarding_overlong_line: bool,
}

impl LogCursor {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            offset: 0,
            scanned: 0,
            pending_line: Vec::new(),
            discarding_overlong_line: false,
        }
    }

    fn contains_new(&mut self, needle: &[u8]) -> Result<bool> {
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to monitor {}", self.path.display()));
            }
        };
        let length = file
            .metadata()
            .with_context(|| format!("failed to inspect {}", self.path.display()))?
            .len();
        if length < self.offset {
            self.offset = 0;
            self.scanned = 0;
            self.pending_line.clear();
            self.discarding_overlong_line = false;
        }
        if self.scanned >= MAX_OBSERVED_LOG_BYTES {
            return Ok(false);
        }
        file.seek(SeekFrom::Start(self.offset))
            .with_context(|| format!("failed to seek {}", self.path.display()))?;

        let mut buffer = [0_u8; 4096];
        while self.scanned < MAX_OBSERVED_LOG_BYTES {
            let remaining = MAX_OBSERVED_LOG_BYTES - self.scanned;
            let buffer_length = u64::try_from(buffer.len()).expect("buffer length fits u64");
            let maximum = usize::try_from(remaining.min(buffer_length))
                .expect("bounded read length fits usize");
            let read = file
                .read(&mut buffer[..maximum])
                .with_context(|| format!("failed to read {}", self.path.display()))?;
            if read == 0 {
                break;
            }
            let read_u64 = u64::try_from(read).expect("bounded read length fits u64");
            self.offset = self.offset.saturating_add(read_u64);
            self.scanned = self.scanned.saturating_add(read_u64);
            for &byte in &buffer[..read] {
                if byte == b'\n' {
                    let line = self
                        .pending_line
                        .strip_suffix(b"\r")
                        .unwrap_or(&self.pending_line);
                    let found = !self.discarding_overlong_line && line == needle;
                    self.pending_line.clear();
                    self.discarding_overlong_line = false;
                    if found {
                        return Ok(true);
                    }
                } else if !self.discarding_overlong_line {
                    if self.pending_line.len() < MAX_DIAGNOSTIC_RECORD_BYTES + 1 {
                        self.pending_line.push(byte);
                    } else {
                        self.pending_line.clear();
                        self.discarding_overlong_line = true;
                    }
                }
            }
        }
        Ok(false)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct MarkerEvidence {
    ready: bool,
    rejected: bool,
    panic: bool,
    terminal_code: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProtocolTrace {
    markers: MarkerEvidence,
    violation: Option<&'static str>,
}

impl ProtocolTrace {
    fn new(log_truncated: bool) -> Self {
        Self {
            markers: MarkerEvidence::default(),
            violation: log_truncated.then_some("debugcon exceeded the bounded protocol log size"),
        }
    }

    fn reject(&mut self, reason: &'static str) {
        if self.violation.is_none() {
            self.violation = Some(reason);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TraceState {
    Start,
    LoaderStarted,
    ElfValidated,
    HandoffReady,
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordKind {
    LoaderStart,
    ElfValid,
    HandoffReady,
    Ready,
    AbiVersion,
    ContractLength,
    ContractInvalid,
    Panic,
    LoaderFailureSequence2,
    LoaderFailureSequence3,
    LoaderFailureSequence4,
}

fn parse_protocol_stream(bytes: &[u8], log_truncated: bool) -> ProtocolTrace {
    let mut trace = ProtocolTrace::new(log_truncated);
    let mut state = TraceState::Start;
    let mut last_sequence = None;
    let mut line_start = 0;
    for (index, &byte) in bytes.iter().enumerate() {
        if byte != b'\n' {
            continue;
        }
        let line = bytes[line_start..index]
            .strip_suffix(b"\r")
            .unwrap_or(&bytes[line_start..index]);
        process_protocol_line(line, &mut state, &mut last_sequence, &mut trace);
        line_start = index + 1;
    }
    if line_start < bytes.len() {
        let partial = &bytes[line_start..];
        if partial.starts_with(b"POLYTOPE_BOOT") {
            trace.reject("truncated diagnostic record");
        }
    }
    trace
}

fn process_protocol_line(
    line: &[u8],
    state: &mut TraceState,
    last_sequence: &mut Option<u16>,
    trace: &mut ProtocolTrace,
) {
    if !line.starts_with(b"POLYTOPE_BOOT") {
        return;
    }
    if line.len() > MAX_DIAGNOSTIC_RECORD_BYTES {
        trace.reject("overlong diagnostic record");
        return;
    }
    if !valid_record_grammar(line) {
        trace.reject("malformed diagnostic record");
        return;
    }
    let Some(sequence) = record_sequence(line) else {
        trace.reject("malformed diagnostic sequence");
        return;
    };
    if last_sequence.is_some_and(|previous| sequence <= previous) {
        trace.reject("duplicate or out-of-order diagnostic sequence");
        return;
    }
    *last_sequence = Some(sequence);
    let Some(kind) = record_kind(line) else {
        trace.reject("unknown schema-1 diagnostic record");
        return;
    };
    let transition = match (*state, kind) {
        (TraceState::Start, RecordKind::LoaderStart) => Some(TraceState::LoaderStarted),
        (TraceState::LoaderStarted, RecordKind::ElfValid) => Some(TraceState::ElfValidated),
        (TraceState::LoaderStarted, RecordKind::LoaderFailureSequence2)
        | (TraceState::ElfValidated, RecordKind::LoaderFailureSequence3)
        | (TraceState::HandoffReady, RecordKind::LoaderFailureSequence4) => {
            Some(TraceState::Terminal)
        }
        (TraceState::ElfValidated, RecordKind::HandoffReady) => Some(TraceState::HandoffReady),
        (TraceState::HandoffReady, RecordKind::Ready) => {
            trace.markers.ready = true;
            trace.markers.terminal_code = Some("KERNEL_READY");
            Some(TraceState::Terminal)
        }
        (TraceState::HandoffReady, RecordKind::AbiVersion) => {
            trace.markers.rejected = true;
            trace.markers.terminal_code = Some("ABI_VERSION");
            Some(TraceState::Terminal)
        }
        (TraceState::HandoffReady, RecordKind::ContractLength) => {
            trace.markers.rejected = true;
            trace.markers.terminal_code = Some("CONTRACT_LENGTH");
            Some(TraceState::Terminal)
        }
        (TraceState::HandoffReady, RecordKind::ContractInvalid) => {
            trace.markers.rejected = true;
            trace.markers.terminal_code = Some("CONTRACT_INVALID");
            Some(TraceState::Terminal)
        }
        (TraceState::HandoffReady, RecordKind::Panic) => {
            trace.markers.panic = true;
            trace.markers.terminal_code = Some("KERNEL_PANIC");
            Some(TraceState::Terminal)
        }
        _ => None,
    };
    if let Some(next) = transition {
        *state = next;
    } else {
        trace.reject("duplicate or out-of-order diagnostic record");
    }
}

fn record_sequence(line: &[u8]) -> Option<u16> {
    let field = line.split(|byte| *byte == b' ').nth(2)?;
    let digits = field.strip_prefix(b"seq=")?;
    let text = std::str::from_utf8(digits).ok()?;
    text.parse().ok()
}

fn valid_record_grammar(line: &[u8]) -> bool {
    if !line.is_ascii() {
        return false;
    }
    let fields: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
    if fields.len() != 6
        || fields[0] != b"POLYTOPE_BOOT"
        || fields[1] != b"schema=1"
        || !fields[2].starts_with(b"seq=")
        || !fields[3].starts_with(b"phase=")
        || !fields[4].starts_with(b"level=")
        || !fields[5].starts_with(b"code=")
    {
        return false;
    }
    let sequence = &fields[2][4..];
    let phase = &fields[3][6..];
    let level = &fields[4][6..];
    let code = &fields[5][5..];
    sequence.len() == 4
        && sequence.iter().all(u8::is_ascii_digit)
        && !phase.is_empty()
        && phase
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
        && matches!(level, b"info" | b"error" | b"fatal")
        && !code.is_empty()
        && code
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn record_kind(line: &[u8]) -> Option<RecordKind> {
    match line {
        value if value == LOADER_START_MARKER.as_bytes() => Some(RecordKind::LoaderStart),
        value if value == ELF_VALID_MARKER.as_bytes() => Some(RecordKind::ElfValid),
        value if value == HANDOFF_READY_MARKER.as_bytes() => Some(RecordKind::HandoffReady),
        value if value == READY_MARKER.as_bytes() => Some(RecordKind::Ready),
        value if value == BAD_VERSION_MARKER.as_bytes() => Some(RecordKind::AbiVersion),
        value if value == TRUNCATED_MARKER.as_bytes() => Some(RecordKind::ContractLength),
        value if value == CONTRACT_INVALID_MARKER.as_bytes() => Some(RecordKind::ContractInvalid),
        value if value == PANIC_MARKER.as_bytes() => Some(RecordKind::Panic),
        value => loader_failure_kind(value),
    }
}

fn loader_failure_kind(line: &[u8]) -> Option<RecordKind> {
    const SEQUENCE_2_RECORDS: &[&[u8]] = &[
        b"POLYTOPE_BOOT schema=1 seq=0002 phase=loader level=error code=FILE_READ",
        b"POLYTOPE_BOOT schema=1 seq=0002 phase=loader level=error code=CONFIG_INVALID",
        b"POLYTOPE_BOOT schema=1 seq=0002 phase=loader level=error code=ELF_INVALID",
        b"POLYTOPE_BOOT schema=1 seq=0002 phase=loader level=error code=ALLOCATION",
        b"POLYTOPE_BOOT schema=1 seq=0002 phase=loader level=error code=KERNEL_ADDRESS",
        b"POLYTOPE_BOOT schema=1 seq=0002 phase=loader level=error code=CONTRACT_STORAGE",
        b"POLYTOPE_BOOT schema=1 seq=0002 phase=loader level=fatal code=LOADER_PANIC",
    ];
    const SEQUENCE_3_RECORDS: &[&[u8]] = &[
        b"POLYTOPE_BOOT schema=1 seq=0003 phase=handoff level=error code=CONTRACT_BUILD",
        b"POLYTOPE_BOOT schema=1 seq=0003 phase=handoff level=fatal code=LOADER_PANIC",
    ];
    const SEQUENCE_4_RECORDS: &[&[u8]] =
        &[b"POLYTOPE_BOOT schema=1 seq=0004 phase=handoff level=fatal code=LOADER_PANIC"];

    if SEQUENCE_2_RECORDS.contains(&line) {
        Some(RecordKind::LoaderFailureSequence2)
    } else if SEQUENCE_3_RECORDS.contains(&line) {
        Some(RecordKind::LoaderFailureSequence3)
    } else if SEQUENCE_4_RECORDS.contains(&line) {
        Some(RecordKind::LoaderFailureSequence4)
    } else {
        None
    }
}

fn classify_boot(
    timed_out: bool,
    exit_status: Option<i32>,
    trace: &ProtocolTrace,
) -> BootClassification {
    if timed_out {
        return BootClassification::Timeout;
    }
    if trace.violation.is_some() {
        return BootClassification::UnexpectedExit;
    }
    match (
        trace.markers.ready,
        trace.markers.rejected,
        trace.markers.panic,
        exit_status,
    ) {
        (true, false, false, Some(READY_EXIT_STATUS)) => BootClassification::Ready,
        (false, true, false, Some(REJECT_EXIT_STATUS)) => BootClassification::Rejected,
        (false, false, true, Some(PANIC_EXIT_STATUS)) => BootClassification::Panic,
        (false, false, false, Some(69)) => BootClassification::LoaderFailure,
        (false, false, false, Some(READY_EXIT_STATUS | REJECT_EXIT_STATUS | PANIC_EXIT_STATUS)) => {
            BootClassification::MissingMarker
        }
        _ => BootClassification::UnexpectedExit,
    }
}

fn sample_statistics(samples: &[u64]) -> Option<SampleStatistics> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let middle = sorted.len() / 2;
    let median = if sorted.len() % 2 == 0 {
        f64::midpoint(u64_to_f64(sorted[middle - 1]), u64_to_f64(sorted[middle]))
    } else {
        u64_to_f64(sorted[middle])
    };
    let p95_index = sorted
        .len()
        .saturating_mul(95)
        .div_ceil(100)
        .saturating_sub(1);
    let count = f64::from(u32::try_from(sorted.len()).ok()?);
    let mean = sorted.iter().map(|value| u64_to_f64(*value)).sum::<f64>() / count;
    let population_variance = sorted
        .iter()
        .map(|value| {
            let difference = u64_to_f64(*value) - mean;
            difference * difference
        })
        .sum::<f64>()
        / count;
    Some(SampleStatistics {
        min: sorted[0],
        median,
        p95: sorted[p95_index],
        max: sorted[sorted.len() - 1],
        mean,
        population_stddev: population_variance.sqrt(),
    })
}

fn u64_to_f64(value: u64) -> f64 {
    const TWO_TO_32: f64 = 4_294_967_296.0;

    let bytes = value.to_le_bytes();
    let low = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let high = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    f64::from(high).mul_add(TWO_TO_32, f64::from(low))
}

struct FirmwarePaths {
    code: PathBuf,
    vars: PathBuf,
    release: &'static str,
}

fn resolve_firmware(cache: &Path) -> Result<FirmwarePaths> {
    let code_override = env::var_os("POLYTOPE_OVMF_CODE");
    let vars_override = env::var_os("POLYTOPE_OVMF_VARS");
    match (code_override, vars_override) {
        (Some(code), Some(vars)) => {
            let code = PathBuf::from(code);
            let vars = PathBuf::from(vars);
            ensure!(
                code.is_file(),
                "POLYTOPE_OVMF_CODE is not a file: {}",
                code.display()
            );
            ensure!(
                vars.is_file(),
                "POLYTOPE_OVMF_VARS is not a file: {}",
                vars.display()
            );
            Ok(FirmwarePaths {
                code,
                vars,
                release: "environment-override",
            })
        }
        (None, None) => {
            let prebuilt = Prebuilt::fetch(OVMF_SOURCE, cache)
                .context("failed to fetch checksum-pinned OVMF edk2-stable202605-r1")?;
            Ok(FirmwarePaths {
                code: prebuilt.get_file(Arch::X64, FileType::Code),
                vars: prebuilt.get_file(Arch::X64, FileType::Vars),
                release: OVMF_RELEASE,
            })
        }
        _ => bail!("POLYTOPE_OVMF_CODE and POLYTOPE_OVMF_VARS must be set together"),
    }
}

fn resolve_qemu(override_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        return require_file(path, "QEMU override");
    }
    if let Some(path) = env::var_os("POLYTOPE_QEMU") {
        return require_file(Path::new(&path), "POLYTOPE_QEMU");
    }
    if let Some(path) = find_on_path("qemu-system-x86_64") {
        return Ok(path);
    }
    for candidate in [
        Path::new("/opt/homebrew/bin/qemu-system-x86_64"),
        Path::new("/usr/local/bin/qemu-system-x86_64"),
        Path::new("/usr/bin/qemu-system-x86_64"),
    ] {
        if candidate.is_file() {
            return Ok(candidate.to_path_buf());
        }
    }
    bail!("qemu-system-x86_64 is unavailable; install QEMU or set POLYTOPE_QEMU")
}

fn qemu_version(qemu: &Path) -> Result<String> {
    let output = Command::new(qemu)
        .arg("--version")
        .output()
        .with_context(|| format!("failed to query {} version", qemu.display()))?;
    ensure!(
        output.status.success(),
        "QEMU version command failed with {}",
        output.status
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .next()
        .unwrap_or("unknown QEMU version")
        .to_owned())
}

fn validate_scenario_outcome(run: &BootRun) -> Result<()> {
    match run.scenario {
        BootScenario::Normal => {
            ensure!(
                run.classification == BootClassification::Ready
                    && run.exit_status == Some(READY_EXIT_STATUS)
                    && run.saw_ready_marker
                    && !run.saw_reject_marker
                    && !run.saw_panic_marker
                    && run.time_to_ready_marker_ms.is_some()
                    && run.terminal_code.as_deref() == Some("KERNEL_READY")
                    && run.diagnostic_protocol_error.is_none(),
                "normal boot failed: classification={:?}, exit={:?}\n{}",
                run.classification,
                run.exit_status,
                run.log
            );
        }
        BootScenario::BadVersion => {
            ensure!(
                run.classification == BootClassification::Rejected
                    && run.exit_status == Some(REJECT_EXIT_STATUS)
                    && run.log.contains(BAD_VERSION_MARKER)
                    && !run.log.contains(TRUNCATED_MARKER)
                    && !run.saw_ready_marker
                    && !run.saw_panic_marker
                    && run.time_to_ready_marker_ms.is_none()
                    && run.terminal_code.as_deref() == Some("ABI_VERSION")
                    && run.diagnostic_protocol_error.is_none(),
                "bad-version boot did not produce the exact rejection: classification={:?}, exit={:?}\n{}",
                run.classification,
                run.exit_status,
                run.log
            );
        }
        BootScenario::Truncated => {
            ensure!(
                run.classification == BootClassification::Rejected
                    && run.exit_status == Some(REJECT_EXIT_STATUS)
                    && run.log.contains(TRUNCATED_MARKER)
                    && !run.log.contains(BAD_VERSION_MARKER)
                    && !run.saw_ready_marker
                    && !run.saw_panic_marker
                    && run.time_to_ready_marker_ms.is_none()
                    && run.terminal_code.as_deref() == Some("CONTRACT_LENGTH")
                    && run.diagnostic_protocol_error.is_none(),
                "truncated boot did not produce the exact rejection: classification={:?}, exit={:?}\n{}",
                run.classification,
                run.exit_status,
                run.log
            );
        }
        BootScenario::Panic => {
            ensure!(
                run.classification == BootClassification::Panic
                    && run.exit_status == Some(PANIC_EXIT_STATUS)
                    && !run.saw_ready_marker
                    && !run.saw_reject_marker
                    && run.time_to_ready_marker_ms.is_none()
                    && run.terminal_code.as_deref() == Some("KERNEL_PANIC")
                    && run.diagnostic_protocol_error.is_none(),
                "panic scenario did not terminate through the panic path: classification={:?}, exit={:?}\n{}",
                run.classification,
                run.exit_status,
                run.log
            );
        }
    }
    Ok(())
}

fn max_option(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

const MAX_CAPTURED_LOG_BYTES: u64 = 4 * 1024 * 1024;

fn read_log_bounded(path: &Path) -> Result<(Vec<u8>, bool)> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Vec::new(), false));
        }
        Err(error) => {
            return Err(error).with_context(|| format!("failed to open {}", path.display()));
        }
    };
    let mut bytes = Vec::new();
    file.take(MAX_CAPTURED_LOG_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let truncated = bytes.len()
        > usize::try_from(MAX_CAPTURED_LOG_BYTES).expect("captured log bound fits usize");
    if truncated {
        bytes.truncate(
            usize::try_from(MAX_CAPTURED_LOG_BYTES).expect("captured log bound fits usize"),
        );
    }
    Ok((bytes, truncated))
}

fn collect_logs(paths: &[&Path]) -> Result<String> {
    let mut combined = String::new();
    for path in paths {
        let (bytes, truncated) = read_log_bounded(path)?;
        combined.push_str(&String::from_utf8_lossy(&bytes));
        if !combined.is_empty() && !combined.ends_with('\n') {
            combined.push('\n');
        }
        if truncated {
            combined.push_str("[host: log truncated at 4194304 bytes]\n");
        }
    }
    Ok(combined)
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
        metadata.len() <= u64::try_from(maximum).expect("size bound fits u64"),
        "{description} is {} bytes; maximum is {maximum}",
        metadata.len()
    );
    fs::read(path).with_context(|| format!("failed to read {description} {}", path.display()))
}

fn qemu_option_path(path: &Path) -> String {
    path.to_string_lossy().replace(',', ",,")
}

fn write_json_atomic<T: Serialize>(output: &Path, value: &T) -> Result<()> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        output
            .file_name()
            .context("baseline output must include a file name")?
            .to_string_lossy(),
        std::process::id()
    ));
    let serialized = serde_json::to_vec_pretty(value).context("failed to serialize baseline")?;
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .with_context(|| format!("failed to create {}", temporary.display()))?;
        file.write_all(&serialized)
            .with_context(|| format!("failed to write {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync {}", temporary.display()))?;
        fs::rename(&temporary, output).with_context(|| {
            format!(
                "failed to move baseline {} to {}",
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

fn require_file(path: &Path, source: &str) -> Result<PathBuf> {
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
        BAD_VERSION_MARKER, BootClassification, ELF_VALID_MARKER, HANDOFF_READY_MARKER,
        LOADER_START_MARKER, PANIC_EXIT_STATUS, PANIC_MARKER, READY_EXIT_STATUS, READY_MARKER,
        REJECT_EXIT_STATUS, TRUNCATED_MARKER, classify_boot, max_option, parse_protocol_stream,
        qemu_invocation, qemu_option_path, sample_statistics,
    };
    use std::path::Path;

    fn trace(marker: Option<&str>, line_ending: &str) -> Vec<u8> {
        let mut lines = vec![LOADER_START_MARKER, ELF_VALID_MARKER, HANDOFF_READY_MARKER];
        if let Some(marker) = marker {
            lines.push(marker);
        }
        format!("{}{}", lines.join(line_ending), line_ending).into_bytes()
    }

    #[test]
    fn rss_samples_merge_without_losing_values() {
        assert_eq!(max_option(None, None), None);
        assert_eq!(max_option(Some(10), None), Some(10));
        assert_eq!(max_option(Some(10), Some(20)), Some(20));
    }

    #[test]
    fn qemu_drive_paths_escape_commas() {
        assert_eq!(qemu_option_path(Path::new("a,b.img")), "a,,b.img");
    }

    #[test]
    fn exact_terminal_records_classify_every_expected_result() {
        for (marker, status, expected) in [
            (READY_MARKER, READY_EXIT_STATUS, BootClassification::Ready),
            (
                BAD_VERSION_MARKER,
                REJECT_EXIT_STATUS,
                BootClassification::Rejected,
            ),
            (
                TRUNCATED_MARKER,
                REJECT_EXIT_STATUS,
                BootClassification::Rejected,
            ),
            (PANIC_MARKER, PANIC_EXIT_STATUS, BootClassification::Panic),
        ] {
            let parsed = parse_protocol_stream(&trace(Some(marker), "\n"), false);
            assert_eq!(parsed.violation, None);
            assert_eq!(classify_boot(false, Some(status), &parsed), expected);
        }
    }

    #[test]
    fn timeout_loader_failure_missing_marker_and_unexpected_exit_are_distinct() {
        let ready = parse_protocol_stream(&trace(Some(READY_MARKER), "\n"), false);
        assert_eq!(
            classify_boot(true, Some(READY_EXIT_STATUS), &ready),
            BootClassification::Timeout
        );
        assert_eq!(
            classify_boot(false, Some(0), &ready),
            BootClassification::UnexpectedExit
        );
        assert_eq!(
            classify_boot(false, Some(71), &ready),
            BootClassification::UnexpectedExit
        );

        let missing = parse_protocol_stream(&trace(None, "\n"), false);
        assert_eq!(
            classify_boot(false, Some(READY_EXIT_STATUS), &missing),
            BootClassification::MissingMarker
        );
        assert_eq!(
            classify_boot(false, Some(71), &missing),
            BootClassification::UnexpectedExit
        );

        for code in ["FILE_READ", "ALLOCATION", "CONTRACT_STORAGE"] {
            let loader_failure = format!(
                "{LOADER_START_MARKER}\nPOLYTOPE_BOOT schema=1 seq=0002 phase=loader level=error code={code}\n"
            );
            let loader_failure = parse_protocol_stream(loader_failure.as_bytes(), false);
            assert_eq!(loader_failure.violation, None);
            assert_eq!(
                classify_boot(false, Some(69), &loader_failure),
                BootClassification::LoaderFailure
            );
        }

        for fixture in [
            format!(
                "{LOADER_START_MARKER}\n{ELF_VALID_MARKER}\nPOLYTOPE_BOOT schema=1 seq=0003 phase=handoff level=error code=CONTRACT_BUILD\n"
            ),
            format!(
                "{LOADER_START_MARKER}\n{ELF_VALID_MARKER}\n{HANDOFF_READY_MARKER}\nPOLYTOPE_BOOT schema=1 seq=0004 phase=handoff level=fatal code=LOADER_PANIC\n"
            ),
        ] {
            let parsed = parse_protocol_stream(fixture.as_bytes(), false);
            assert_eq!(parsed.violation, None);
            assert_eq!(
                classify_boot(false, Some(69), &parsed),
                BootClassification::LoaderFailure
            );
        }
    }

    #[test]
    fn parser_accepts_crlf_and_ignores_unrelated_prose() {
        let mut bytes = b"firmware ready panic code=KERNEL_READY\r\n".to_vec();
        bytes.extend(trace(Some(READY_MARKER), "\r\n"));
        let parsed = parse_protocol_stream(&bytes, false);
        assert_eq!(parsed.violation, None);
        assert!(parsed.markers.ready);
    }

    #[test]
    fn parser_rejects_malformed_overlong_non_ascii_and_truncated_records() {
        let malformed =
            b"POLYTOPE_BOOT seq=0001 schema=1 phase=loader level=info code=LOADER_START\n";
        let mut overlong = b"POLYTOPE_BOOT ".to_vec();
        overlong.extend(std::iter::repeat_n(b'X', 300));
        overlong.push(b'\n');
        let mut non_ascii =
            b"POLYTOPE_BOOT schema=1 seq=0001 phase=loader level=info code=".to_vec();
        non_ascii.push(0xff);
        non_ascii.push(b'\n');
        let truncated = LOADER_START_MARKER.as_bytes();

        for fixture in [malformed.as_slice(), &overlong, &non_ascii, truncated] {
            let parsed = parse_protocol_stream(fixture, false);
            assert!(
                parsed.violation.is_some(),
                "fixture was accepted: {fixture:?}"
            );
            assert_eq!(
                classify_boot(false, Some(READY_EXIT_STATUS), &parsed),
                BootClassification::UnexpectedExit
            );
        }
    }

    #[test]
    fn parser_rejects_duplicates_conflicts_and_out_of_order_records() {
        let duplicate = format!(
            "{LOADER_START_MARKER}\n{ELF_VALID_MARKER}\n{HANDOFF_READY_MARKER}\n{READY_MARKER}\n{READY_MARKER}\n"
        );
        let conflicting = format!(
            "{LOADER_START_MARKER}\n{ELF_VALID_MARKER}\n{HANDOFF_READY_MARKER}\n{READY_MARKER}\n{PANIC_MARKER}\n"
        );
        let out_of_order = format!(
            "{LOADER_START_MARKER}\n{HANDOFF_READY_MARKER}\n{ELF_VALID_MARKER}\n{READY_MARKER}\n"
        );
        let panic_sequence_does_not_match_state = format!(
            "{LOADER_START_MARKER}\nPOLYTOPE_BOOT schema=1 seq=0003 phase=handoff level=fatal code=LOADER_PANIC\n"
        );
        for (fixture, expected_error) in [
            (duplicate, "duplicate or out-of-order diagnostic sequence"),
            (conflicting, "duplicate or out-of-order diagnostic record"),
            (out_of_order, "duplicate or out-of-order diagnostic record"),
            (
                panic_sequence_does_not_match_state,
                "duplicate or out-of-order diagnostic record",
            ),
        ] {
            let parsed = parse_protocol_stream(fixture.as_bytes(), false);
            assert_eq!(parsed.violation, Some(expected_error));
            assert_eq!(
                classify_boot(false, Some(READY_EXIT_STATUS), &parsed),
                BootClassification::UnexpectedExit
            );
        }
    }

    #[test]
    fn protocol_log_size_limit_is_classified_as_unexpected() {
        let parsed = parse_protocol_stream(&trace(Some(READY_MARKER), "\n"), true);
        assert_eq!(
            parsed.violation,
            Some("debugcon exceeded the bounded protocol log size")
        );
        assert_eq!(
            classify_boot(false, Some(READY_EXIT_STATUS), &parsed),
            BootClassification::UnexpectedExit
        );
    }

    #[test]
    fn baseline_statistics_cover_full_distribution() {
        let statistics = sample_statistics(&[10, 20, 30, 40]).expect("non-empty samples");
        assert_eq!(statistics.min, 10);
        assert!((statistics.median - 25.0).abs() < f64::EPSILON);
        assert_eq!(statistics.p95, 40);
        assert_eq!(statistics.max, 40);
        assert!((statistics.mean - 25.0).abs() < f64::EPSILON);
        assert!((statistics.population_stddev - 125.0_f64.sqrt()).abs() < 1e-12);
        assert_eq!(sample_statistics(&[]), None);
    }

    #[test]
    fn qemu_evidence_preserves_arguments_and_redacts_host_paths() {
        let invocation = qemu_invocation(
            Path::new("/tools/qemu-system-x86_64"),
            Path::new("/private/ovmf,code.fd"),
            Path::new("/private/vars.fd"),
            Path::new("/private/image.img"),
            Path::new("/private/serial.log"),
            Path::new("/private/debug.log"),
            true,
        );
        assert_eq!(
            invocation.arguments.len() + 1,
            invocation.sanitized_argv.len()
        );
        assert_eq!(invocation.sanitized_argv[0], "qemu-system-x86_64");
        assert!(
            invocation
                .sanitized_argv
                .iter()
                .all(|argument| !argument.contains("/private"))
        );
        assert!(
            invocation
                .sanitized_argv
                .iter()
                .any(|argument| argument.contains("<BOOT_IMAGE>"))
        );
    }
}
