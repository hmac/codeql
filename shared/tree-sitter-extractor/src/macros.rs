#[macro_export]

use serde::Deserialize;

macro_rules! make_cli {
  ($lang:ident, $yaml_file:expr) => {
        use std::io;
        use std::path::PathBuf;

        use clap::{Parser, Args};

        #[derive(Parser)]
        #[command(author, version, about)]
        enum Cli {
            Extract(ExtractorOptions),
            Generate(GeneratorOptions),
            Autobuild,
        }

        #[derive(Args)]
        pub struct ExtractorOptions {
            /// Sets a custom source achive folder
            #[arg(long)]
            source_archive_dir: PathBuf,

            /// Sets a custom trap folder
            #[arg(long)]
            output_dir: PathBuf,

            /// A text file containing the paths of the files to extract
            #[arg(long)]
            file_list: PathBuf,
        }

        #[derive(Args)]
        pub struct GeneratorOptions {
            /// Path of the generated dbscheme file
            #[arg(long)]
            dbscheme: PathBuf,

            /// Path of the generated QLL file
            #[arg(long)]
            library: PathBuf,
        }

        fn main() -> io::Result<()> {
            let cli = Cli::parse();

            match cli {
                Cli::Extract(options) => run_extractor(options),
                Cli::Generate(options) => run_generator(options),
                Cli::Autobuild => run_autobuilder(),
            }
        }

        fn run_extractor(opts: ExtractorOptions) -> io::Result<()> {
            Ok(())
        }
        fn run_generator(opts: GeneratorOptions) -> io::Result<()> {
            Ok(())
        }
        fn run_autobuilder() -> io::Result<()> {
            Ok(())
        }
    }
  }

