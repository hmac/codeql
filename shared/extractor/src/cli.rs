use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::trap;

#[derive(Parser, Clone)]
#[command(author, version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Clone)]
pub enum Command {
    Extract(ExtractArgs),
    Generate(GenerateArgs),
    Autobuild,
}

#[derive(Args, Clone)]
pub struct ExtractArgs {
    /// Sets a custom source archive folder
    #[arg(long, value_name = "DIR")]
    pub source_archive_dir: PathBuf,
    /// Sets a custom trap folder
    #[arg(long, value_name = "DIR")]
    pub output_dir: PathBuf,
    /// A text file containing the paths of the files to extract
    #[arg(long, value_name = "FILE_LIST")]
    pub file_list: PathBuf,
    /// The number of threads to use for extraction
    #[arg(long, env, value_parser = parse_codeql_threads)]
    pub codeql_threads: usize,
    /// The level of compression to use when writing TRAP
    #[arg(long, env, value_parser = parse_trap_compression)]
    pub codeql_trap_compression: trap::Compression,
}

/**
 * Parse the CODEQL_THREADS environment variable as described in the extractor spec:
 *
 * "If the number is positive, it indicates the number of threads that should
 * be used. If the number is negative or zero, it should be added to the number
 * of cores available on the machine to determine how many threads to use
 * (minimum of 1). If unspecified, should be considered as set to -1."
 */
fn parse_codeql_threads(s: &str) -> Result<usize, String> {
    match s.parse::<i32>() {
        Ok(num) if num <= 0 => {
            let reduction = -num as usize;
            Ok(std::cmp::max(1, num_cpus::get() - reduction))
        }
        Ok(num) => Ok(num as usize),

        Err(_) => {
            tracing::error!(
                "Unable to parse CODEQL_THREADS value '{}'; defaulting to 1 thread.",
                &s
            );
            Ok(1)
        }
    }
}

fn parse_trap_compression(s: &str) -> Result<trap::Compression, String> {
    match trap::Compression::from_string(s) {
        Some(compression) => Ok(compression),
        None => {
            // TODO: how do we log this?
            // main_thread_logger.write(
            //     main_thread_logger
            //         .message("configuration-error", "Configuration error")
            //         .text(&format!("{}; using gzip.", e))
            //         .status_page()
            //         .severity(diagnostics::Severity::Warning),
            // );
            Ok(trap::Compression::Gzip)
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

pub fn parse_cli() -> Cli {
    Cli::parse()
}
