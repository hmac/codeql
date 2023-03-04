extern crate num_cpus;

use std::fs;
use std::io::BufRead;
use std::path::PathBuf;

use codeql_extractor::{extractor::Extractor, diagnostics, node_types, trap};

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
fn num_codeql_threads() -> usize {
    let threads_str = std::env::var("CODEQL_THREADS").unwrap_or_else(|_| "-1".to_owned());
    match threads_str.parse::<i32>() {
        Ok(num) if num <= 0 => {
            let reduction = -num as usize;
            std::cmp::max(1, num_cpus::get() - reduction)
        }
        Ok(num) => num as usize,

        Err(_) => {
            tracing::error!(
                "Unable to parse CODEQL_THREADS value '{}'; defaulting to 1 thread.",
                &threads_str
            );
            1
        }
    }
}

fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .without_time()
        .with_level(true)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let diagnostics = diagnostics::DiagnosticLoggers::new("ql");
    let mut main_thread_logger = diagnostics.logger();

    let num_threads = num_codeql_threads();
    tracing::info!(
        "Using {} {}",
        num_threads,
        if num_threads == 1 {
            "thread"
        } else {
            "threads"
        }
    );
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .unwrap();

    let matches = clap::App::new("QL extractor")
        .version("1.0")
        .author("GitHub")
        .about("CodeQL QL extractor")
        .args_from_usage(
            "--source-archive-dir=<DIR> 'Sets a custom source archive folder'
                    --output-dir=<DIR>         'Sets a custom trap folder'
                    --file-list=<FILE_LIST>    'A text files containing the paths of the files to extract'",
        )
        .get_matches();
    let src_archive_dir = matches
        .value_of("source-archive-dir")
        .expect("missing --source-archive-dir");
    let src_archive_dir = PathBuf::from(src_archive_dir);

    let trap_dir = matches
        .value_of("output-dir")
        .expect("missing --output-dir");
    let trap_dir = PathBuf::from(trap_dir);
    let trap_compression = match trap::Compression::from_env("CODEQL_RUBY_TRAP_COMPRESSION") {
        Ok(x) => x,
        Err(e) => {
            main_thread_logger.write(
                main_thread_logger
                    .message("configuration-error", "Configuration error")
                    .text(&format!("{}; using gzip.", e))
                    .status_page()
                    .severity(diagnostics::Severity::Warning),
            );
            trap::Compression::Gzip
        }
    };

    let file_list = matches.value_of("file-list").expect("missing --file-list");
    let file_list = fs::File::open(file_list)?;

    let language = tree_sitter_ql::language();
    let dbscheme = tree_sitter_ql_dbscheme::language();
    let yaml = tree_sitter_ql_yaml::language();
    let blame = tree_sitter_blame::language();
    let json = tree_sitter_json::language();
    let schema = node_types::read_node_types_str("ql", tree_sitter_ql::NODE_TYPES)?;
    let dbscheme_schema =
        node_types::read_node_types_str("dbscheme", tree_sitter_ql_dbscheme::NODE_TYPES)?;
    let yaml_schema = node_types::read_node_types_str("yaml", tree_sitter_ql_yaml::NODE_TYPES)?;
    let blame_schema = node_types::read_node_types_str("blame", tree_sitter_blame::NODE_TYPES)?;
    let json_schema = node_types::read_node_types_str("json", tree_sitter_json::NODE_TYPES)?;

    let lines: std::io::Result<Vec<String>> = std::io::BufReader::new(file_list).lines().collect();
    let lines = lines?;

    let mut extractor = Extractor::new(&src_archive_dir, &trap_dir, trap_compression, diagnostics);

    let lang_dbscheme = extractor.build_language("dbscheme", dbscheme, dbscheme_schema);
    let lang_yaml = extractor.build_language("yaml", yaml, yaml_schema);
    let lang_json = extractor.build_language("json", json, json_schema);
    let lang_blame = extractor.build_language("blame", blame, blame_schema);
    let lang_ql = extractor.build_language("ql", language, schema);

    extractor.register_language(lang_dbscheme);
    extractor.register_language(lang_yaml);
    extractor.register_language(lang_json);
    extractor.register_language(lang_blame);
    extractor.register_language(lang_ql);

    extractor.register_extension("dbscheme", "dbscheme");
    extractor.register_extension("yml", "yaml");
    extractor.register_extension("json", "json");
    extractor.register_extension("jsonl", "json");
    extractor.register_extension("jsonc", "json");
    extractor.register_extension("blame", "blame");
    extractor.register_extension("ql", "ql");
    extractor.register_extension("qll", "ql");

    extractor.run(lines)
}
