#![doc = "Host-side developer control plane for the `AxiomOS` workspace."]

use std::{env, fmt, fs, io, path::Path, process::Command, process::ExitCode};

const USAGE: &str = "Usage: axiomctl <doctor|help>";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CliCommand {
    Doctor,
    Help,
}

#[derive(Debug)]
enum DoctorError {
    Manifest(io::Error),
    NotWorkspace,
    ToolStart {
        tool: &'static str,
        source: io::Error,
    },
    ToolFailed {
        tool: &'static str,
    },
    ToolOutput {
        tool: &'static str,
    },
}

impl fmt::Display for DoctorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(error) => write!(formatter, "cannot read Cargo.toml: {error}"),
            Self::NotWorkspace => {
                formatter.write_str("Cargo.toml is not an AxiomOS workspace manifest")
            }
            Self::ToolStart { tool, source } => write!(formatter, "cannot run {tool}: {source}"),
            Self::ToolFailed { tool } => {
                write!(formatter, "{tool} --version returned a failure status")
            }
            Self::ToolOutput { tool } => {
                write!(formatter, "{tool} returned non-UTF-8 version output")
            }
        }
    }
}

fn parse_command(arguments: &[String]) -> Result<CliCommand, String> {
    match arguments {
        [] => Ok(CliCommand::Help),
        [command] if command == "help" => Ok(CliCommand::Help),
        [command] if command == "doctor" => Ok(CliCommand::Doctor),
        [command] => Err(format!("unknown command '{command}'")),
        _ => Err("expected exactly one command".to_owned()),
    }
}

fn tool_version(tool: &'static str) -> Result<String, DoctorError> {
    let output = Command::new(tool)
        .arg("--version")
        .output()
        .map_err(|source| DoctorError::ToolStart { tool, source })?;
    if !output.status.success() {
        return Err(DoctorError::ToolFailed { tool });
    }
    let version = String::from_utf8(output.stdout).map_err(|_| DoctorError::ToolOutput { tool })?;
    Ok(version.trim().to_owned())
}

fn doctor(workspace: &Path) -> Result<(), DoctorError> {
    let manifest =
        fs::read_to_string(workspace.join("Cargo.toml")).map_err(DoctorError::Manifest)?;
    if !manifest.contains("[workspace]") || !manifest.contains("axiomctl") {
        return Err(DoctorError::NotWorkspace);
    }

    let rustc = tool_version("rustc")?;
    let cargo = tool_version("cargo")?;
    println!("[ok] AxiomOS workspace manifest");
    println!("[ok] {rustc}");
    println!("[ok] {cargo}");
    println!("Foundation checks passed; boot tooling is introduced in Sprint 2.");
    Ok(())
}

fn main() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match parse_command(&arguments) {
        Ok(CliCommand::Help) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(CliCommand::Doctor) => match env::current_dir()
            .map_err(DoctorError::Manifest)
            .and_then(|directory| doctor(&directory))
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("doctor failed: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("error: {error}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CliCommand, USAGE, parse_command};

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn usage_names_the_binary() {
        assert!(USAGE.starts_with("Usage: axiomctl"));
    }

    #[test]
    fn parses_supported_commands_strictly() {
        assert_eq!(
            parse_command(&arguments(&["doctor"])),
            Ok(CliCommand::Doctor)
        );
        assert_eq!(parse_command(&[]), Ok(CliCommand::Help));
        assert!(parse_command(&arguments(&["doctor", "extra"])).is_err());
        assert!(parse_command(&arguments(&["unknown"])).is_err());
    }
}
