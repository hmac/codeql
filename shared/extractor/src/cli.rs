use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::{
    diagnostics::{self, DiagnosticLoggers, LogWriter},
    trap,
};

#[derive(Parser, Clone)]
#[command(author, version, about)]
pub struct CliExt {
    #[command(subcommand)]
    pub command: CommandExt,
}

pub enum Command {
    Extract(ExtractArgs),
    Generate(GenerateArgs),
    Autobuild,
}

#[derive(Subcommand, Clone)]
pub enum CommandExt {
    Extract(ExtractArgsExt),
    Generate(GenerateArgs),
    Autobuild,
}

/// The set of arguments provided to the extractor via the command line.
/// This excludes arguments that are derived from environment variables, as we must do custom error
/// handling for those.
#[derive(Args, Clone)]
pub struct ExtractArgsExt {
    /// Sets a custom source archive folder
    #[arg(long, value_name = "DIR")]
    source_archive_dir: PathBuf,
    /// Sets a custom trap folder
    #[arg(long, value_name = "DIR")]
    output_dir: PathBuf,
    /// A text file containing the paths of the files to extract
    #[arg(long, value_name = "FILE_LIST")]
    file_list: PathBuf,
}

/// This is the full set of arguments provided to the extractor, including those that are derived
/// from environment variables.
pub struct ExtractArgs {
    /// Sets a custom source archive folder
    pub source_archive_dir: PathBuf,
    /// Sets a custom trap folder
    pub output_dir: PathBuf,
    /// A text file containing the paths of the files to extract
    pub file_list: PathBuf,
    /// The number of threads to use for extraction
    pub codeql_threads: usize,
    /// The level of compression to use when writing TRAP
    pub codeql_trap_compression: trap::Compression,
    /// The diagnostics loggers handler
    pub diagnostics: DiagnosticLoggers,
    /// The logger for the main thread
    pub logger: LogWriter,
}

/**
 * Gets the number of threads the extractor should use, by reading the
 * CODEQL_THREADS environment variable and using it as described in the
 * extractor spec:
 *
 * "If the number is positive, it indicates the number of threads that should
 * be used. If the number is negative or zero, it should be added to the number
 * of cores available on the machine to determine how many threads to use
 * (minimum of 1). If unspecified, should be considered as set to -1."
 */
fn num_codeql_threads_from_env(logger: &mut LogWriter) -> usize {
    let threads_str = std::env::var("CODEQL_THREADS").unwrap_or_else(|_| "-1".to_owned());
    match threads_str.parse::<i32>() {
        Ok(num) if num <= 0 => {
            let reduction = -num as usize;
            std::cmp::max(1, num_cpus::get() - reduction)
        }
        Ok(num) => num as usize,

        Err(_) => {
            logger
                .message("configuration-error", "Configuration error")
                .text(&format!(
                    "Unable to parse CODEQL_THREADS value '{}'",
                    &threads_str
                ));
            1
        }
    }
}

fn trap_compression_from_env(logger: &mut LogWriter) -> trap::Compression {
    // CODEQL_RUBY_TRAP_COMPRESSION is a legacy environment variable that we still support for
    // backwards compatibility.
    let compression = trap::Compression::from_env("CODEQL_TRAP_COMPRESSION")
        .or_else(|_| trap::Compression::from_env("CODEQL_RUBY_TRAP_COMPRESSION"));
    match compression {
        Ok(x) => x,
        Err(e) => {
            logger.write(
                logger
                    .message("configuration-error", "Configuration error")
                    .text(&format!("{}; using gzip.", e))
                    .severity(diagnostics::Severity::Warning),
            );
            trap::Compression::Gzip
        }
    }
}

#[derive(Args, Clone)]
pub struct GenerateArgs {
    /// Path of the generated dbscheme file
    #[arg(long, value_name = "FILE")]
    pub dbscheme: PathBuf,
    /// Path of the generated QLL file
    #[arg(long, value_name = "FILE", default_value = "gzip")]
    pub library: PathBuf,
}

pub fn parse_cli(extractor_name: &str) -> Command {
    let cli = CliExt::parse();

    match cli.command {
        CommandExt::Extract(cli_args) => {
            let diagnostics = diagnostics::DiagnosticLoggers::new(extractor_name);
            let mut logger = diagnostics.logger();
            let num_threads = num_codeql_threads_from_env(&mut logger);
            let trap_compression = trap_compression_from_env(&mut logger);

            let args = ExtractArgs {
                source_archive_dir: cli_args.source_archive_dir,
                output_dir: cli_args.output_dir,
                file_list: cli_args.file_list,
                codeql_threads: num_threads,
                codeql_trap_compression: trap_compression,
                diagnostics,
                logger,
            };
            Command::Extract(args)
        }
        CommandExt::Generate(args) => Command::Generate(args),
        CommandExt::Autobuild => Command::Autobuild,
    }
}
