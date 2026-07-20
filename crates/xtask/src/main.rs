#![forbid(unsafe_code)]
#![doc = "Command-line entry for deterministic `PolytopeOS` boot tooling."]

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use xtask::image::{BootScenario, ImageRequest, build_image};
use xtask::inspect::{InspectionRequest, inspect_kernel};
use xtask::qemu::{
    BaselineRequest, BootMode, BootRequest, observe_boot, run_baseline, validate_boot_outcome,
    validate_timeout_probe,
};
use xtask::repro::{ReproRequest, verify};

const DEFAULT_IMAGE: &str = "target/polytope/polytope-x86_64.img";
const DEFAULT_BASELINE: &str = "target/polytope/boot-baseline.json";
const DEFAULT_OVMF_CACHE: &str = "target/ovmf";

fn main() {
    if let Err(error) = run() {
        eprintln!("xtask failed: {error:#}");
        eprintln!("run `cargo xtask help` for command usage");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let Some(command) = arguments.next() else {
        print_usage();
        return Ok(());
    };
    let command = command
        .to_str()
        .context("command name must be valid UTF-8")?;
    if matches!(command, "help" | "--help" | "-h") {
        print_usage();
        return Ok(());
    }
    let mut options = Options::parse(arguments)?;
    match command {
        "image" => command_image(&mut options),
        "inspect-kernel" => command_inspect_kernel(&mut options),
        "repro-check" => command_repro(&mut options),
        "boot-test" => command_boot_test(&mut options),
        "timeout-probe" => command_timeout_probe(&mut options),
        "baseline" => command_baseline(&mut options),
        _ => bail!("unknown xtask command {command:?}"),
    }
}

fn command_inspect_kernel(options: &mut Options) -> Result<()> {
    let request = InspectionRequest {
        kernel: options.required_path("--kernel")?,
        map: options.required_path("--map")?,
    };
    options.finish()?;
    print_json(&inspect_kernel(&request)?)
}

fn command_image(options: &mut Options) -> Result<()> {
    let request = ImageRequest {
        loader: options.required_path("--loader")?,
        kernel: options.required_path("--kernel")?,
        output: options
            .optional_path("--output")
            .unwrap_or_else(|| PathBuf::from(DEFAULT_IMAGE)),
        scenario: options.scenario()?,
    };
    options.finish()?;
    print_json(&build_image(&request)?)
}

fn command_repro(options: &mut Options) -> Result<()> {
    let workspace = options
        .optional_path("--workspace")
        .unwrap_or_else(|| PathBuf::from("."));
    let output = options
        .optional_path("--output")
        .unwrap_or_else(|| PathBuf::from(DEFAULT_IMAGE));
    let mut request = ReproRequest::polytope_defaults(workspace, output);
    request.cargo = options.optional_path("--cargo");
    request.scenario = options.scenario()?;
    request.verified_loader_output = options.optional_path("--verified-loader-output");
    request.verified_kernel_output = options.optional_path("--verified-kernel-output");
    request.verified_kernel_map_output = options.optional_path("--verified-kernel-map-output");
    override_string(options, "--loader-package", &mut request.loader.package)?;
    override_string(options, "--loader-bin", &mut request.loader.binary)?;
    override_string(options, "--loader-target", &mut request.loader.target)?;
    if let Some(path) = options.optional_path("--loader-artifact") {
        request.loader.relative_path = path;
    }
    override_features(options, "--loader-features", &mut request.loader.features)?;
    override_string(options, "--kernel-package", &mut request.kernel.package)?;
    override_string(options, "--kernel-bin", &mut request.kernel.binary)?;
    override_string(options, "--kernel-target", &mut request.kernel.target)?;
    if let Some(path) = options.optional_path("--kernel-artifact") {
        request.kernel.relative_path = path;
    }
    if let Some(path) = options.optional_path("--kernel-map-artifact") {
        request.kernel_map_relative_path = Some(path);
    }
    override_features(options, "--kernel-features", &mut request.kernel.features)?;
    options.finish()?;
    print_json(&verify(&request)?)
}

fn command_boot_test(options: &mut Options) -> Result<()> {
    let request = boot_request(options)?;
    options.finish()?;
    let run = observe_boot(&request, BootMode::Scenario)?;
    print_json(&run)?;
    validate_boot_outcome(&run)
}

fn command_timeout_probe(options: &mut Options) -> Result<()> {
    let request = boot_request(options)?;
    ensure!(
        request.scenario == BootScenario::Normal,
        "timeout probes require the normal image scenario"
    );
    options.finish()?;
    let run = observe_boot(&request, BootMode::TimeoutProbe)?;
    print_json(&run)?;
    validate_timeout_probe(&run)
}

fn command_baseline(options: &mut Options) -> Result<()> {
    let boot = boot_request(options)?;
    let runs = options.optional_usize("--runs")?.unwrap_or(10);
    let output = options
        .optional_path("--output")
        .unwrap_or_else(|| PathBuf::from(DEFAULT_BASELINE));
    options.finish()?;
    print_json(&run_baseline(&BaselineRequest { boot, runs, output })?)
}

fn boot_request(options: &mut Options) -> Result<BootRequest> {
    let timeout_seconds = options.optional_u64("--timeout-secs")?.unwrap_or(15);
    ensure!(timeout_seconds > 0, "--timeout-secs must be positive");
    Ok(BootRequest {
        image: options
            .optional_path("--image")
            .unwrap_or_else(|| PathBuf::from(DEFAULT_IMAGE)),
        scenario: options.scenario()?,
        timeout: Duration::from_secs(timeout_seconds),
        qemu: options.optional_path("--qemu"),
        ovmf_cache: options
            .optional_path("--ovmf-cache")
            .unwrap_or_else(|| PathBuf::from(DEFAULT_OVMF_CACHE)),
    })
}

fn override_string(options: &mut Options, name: &str, destination: &mut String) -> Result<()> {
    if let Some(value) = options.optional_string(name)? {
        *destination = value;
    }
    Ok(())
}

fn override_features(
    options: &mut Options,
    name: &str,
    destination: &mut Vec<String>,
) -> Result<()> {
    if let Some(value) = options.optional_string(name)? {
        let features: Vec<String> = value
            .split(',')
            .map(str::trim)
            .filter(|feature| !feature.is_empty())
            .map(String::from)
            .collect();
        ensure!(
            !features.is_empty(),
            "{name} must contain at least one feature"
        );
        *destination = features;
    }
    Ok(())
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    let serialized =
        serde_json::to_string_pretty(value).context("failed to serialize command result")?;
    println!("{serialized}");
    Ok(())
}

struct Options {
    values: BTreeMap<String, OsString>,
}

impl Options {
    fn parse(arguments: impl Iterator<Item = OsString>) -> Result<Self> {
        let mut arguments = arguments;
        let mut values = BTreeMap::new();
        while let Some(name) = arguments.next() {
            let name = name
                .into_string()
                .map_err(|_| anyhow::anyhow!("option names must be valid UTF-8"))?;
            ensure!(name.starts_with("--"), "expected an option, found {name:?}");
            ensure!(name != "--help", "use `cargo xtask help` for usage");
            let value = arguments
                .next()
                .with_context(|| format!("option {name} requires a value"))?;
            ensure!(
                values.insert(name.clone(), value).is_none(),
                "option {name} was provided more than once"
            );
        }
        Ok(Self { values })
    }

    fn required_path(&mut self, name: &str) -> Result<PathBuf> {
        self.optional_path(name)
            .with_context(|| format!("required option {name} is missing"))
    }

    fn optional_path(&mut self, name: &str) -> Option<PathBuf> {
        self.values.remove(name).map(PathBuf::from)
    }

    fn optional_string(&mut self, name: &str) -> Result<Option<String>> {
        self.values
            .remove(name)
            .map(|value| {
                value
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("{name} must be valid UTF-8"))
            })
            .transpose()
    }

    fn optional_u64(&mut self, name: &str) -> Result<Option<u64>> {
        self.optional_string(name)?
            .map(|value| {
                value
                    .parse()
                    .with_context(|| format!("{name} must be an unsigned integer"))
            })
            .transpose()
    }

    fn optional_usize(&mut self, name: &str) -> Result<Option<usize>> {
        self.optional_string(name)?
            .map(|value| {
                value
                    .parse()
                    .with_context(|| format!("{name} must be a positive integer"))
            })
            .transpose()
    }

    fn scenario(&mut self) -> Result<BootScenario> {
        self.optional_string("--scenario")?
            .as_deref()
            .map_or(Ok(BootScenario::Normal), str::parse)
    }

    fn finish(&self) -> Result<()> {
        if let Some(name) = self.values.keys().next() {
            bail!("unsupported option {name}");
        }
        Ok(())
    }
}

fn print_usage() {
    println!(
        "PolytopeOS deterministic boot tooling\n\
\n\
Usage:\n\
  cargo xtask image --loader PATH --kernel PATH [--output PATH] [--scenario TOKEN]\n\
  cargo xtask inspect-kernel --kernel PATH --map PATH\n\
  cargo xtask repro-check [--workspace PATH] [--output PATH] [artifact overrides]\n\
  cargo xtask boot-test [--image PATH] [--scenario TOKEN] [--timeout-secs N]\n\
  cargo xtask timeout-probe [--image PATH] [--timeout-secs N]\n\
  cargo xtask baseline [--image PATH] [--runs N] [--output PATH]\n\
\n\
Scenario tokens: normal, bad-version, truncated, panic\n\
Firmware overrides: POLYTOPE_OVMF_CODE and POLYTOPE_OVMF_VARS\n\
Tool overrides: --cargo/POLYTOPE_CARGO and --qemu/POLYTOPE_QEMU\n\
Default image: {DEFAULT_IMAGE}\n\
Default baseline: {DEFAULT_BASELINE}"
    );
}

#[cfg(test)]
mod tests {
    use super::Options;
    use std::ffi::OsString;

    #[test]
    fn duplicate_and_unknown_options_are_rejected() {
        let duplicate = vec![
            OsString::from("--runs"),
            OsString::from("1"),
            OsString::from("--runs"),
            OsString::from("2"),
        ];
        assert!(Options::parse(duplicate.into_iter()).is_err());

        let unknown =
            Options::parse(vec![OsString::from("--mystery"), OsString::from("value")].into_iter())
                .unwrap();
        assert!(unknown.finish().is_err());
    }
}
