use std::fs;
use std::io::BufRead;
use std::path::PathBuf;

use codeql_extractor::{
    cli::{Command, ExtractArgs, GenerateArgs},
    extractor::Extractor,
    generator::{generate, language::Language},
    node_types,
};

fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .without_time()
        .with_level(true)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    match codeql_extractor::cli::parse_cli("ql") {
        Command::Extract(args) => run_extract(args),
        Command::Generate(args) => run_generate(args),
        Command::Autobuild => run_autobuild(),
    }
}

fn run_extract(args: ExtractArgs) -> std::io::Result<()> {
    let diagnostics = args.diagnostics;

    let file_list = fs::File::open(args.file_list)?;
    let lines: std::io::Result<Vec<String>> = std::io::BufReader::new(file_list).lines().collect();
    let lines = lines?;

    let mut extractor = Extractor::new(
        &args.source_archive_dir,
        &args.output_dir,
        args.codeql_trap_compression,
        diagnostics,
        args.codeql_threads,
    );

    let ql = extractor.register_language(
        "ql",
        tree_sitter_ql::language(),
        node_types::read_node_types_str("ql", tree_sitter_ql::NODE_TYPES)?,
    );
    let dbscheme = extractor.register_language(
        "dbscheme",
        tree_sitter_ql_dbscheme::language(),
        node_types::read_node_types_str("dbscheme", tree_sitter_ql_dbscheme::NODE_TYPES)?,
    );
    let yaml = extractor.register_language(
        "yaml",
        tree_sitter_ql_yaml::language(),
        node_types::read_node_types_str("yaml", tree_sitter_ql_yaml::NODE_TYPES)?,
    );
    let json = extractor.register_language(
        "json",
        tree_sitter_json::language(),
        node_types::read_node_types_str("json", tree_sitter_json::NODE_TYPES)?,
    );
    let blame = extractor.register_language(
        "blame",
        tree_sitter_blame::language(),
        node_types::read_node_types_str("blame", tree_sitter_blame::NODE_TYPES)?,
    );

    extractor.register_extension("ql", ql);
    extractor.register_extension("qll", ql);
    extractor.register_extension("dbscheme", dbscheme);
    extractor.register_extension("yml", yaml);
    extractor.register_extension("json", json);
    extractor.register_extension("jsonl", json);
    extractor.register_extension("jsonc", json);
    extractor.register_extension("blame", blame);

    extractor.run(lines)
}

fn run_generate(args: GenerateArgs) -> std::io::Result<()> {
    let languages = vec![
        Language {
            name: "QL".to_owned(),
            node_types: tree_sitter_ql::NODE_TYPES,
        },
        Language {
            name: "Dbscheme".to_owned(),
            node_types: tree_sitter_ql_dbscheme::NODE_TYPES,
        },
        Language {
            name: "Yaml".to_owned(),
            node_types: tree_sitter_ql_yaml::NODE_TYPES,
        },
        Language {
            name: "Blame".to_owned(),
            node_types: tree_sitter_blame::NODE_TYPES,
        },
        Language {
            name: "JSON".to_owned(),
            node_types: tree_sitter_json::NODE_TYPES,
        },
    ];

    generate(args.dbscheme, args.library, languages)
}

fn run_autobuild() -> std::io::Result<()> {
    use std::env;
    use std::process::Command;

    let dist = env::var("CODEQL_DIST").expect("CODEQL_DIST not set");
    let db = env::var("CODEQL_EXTRACTOR_QL_WIP_DATABASE")
        .expect("CODEQL_EXTRACTOR_QL_WIP_DATABASE not set");
    let codeql = if env::consts::OS == "windows" {
        "codeql.exe"
    } else {
        "codeql"
    };
    let codeql: PathBuf = [&dist, codeql].iter().collect();
    let mut cmd = Command::new(codeql);
    cmd.arg("database")
        .arg("index-files")
        .arg("--include-extension=.ql")
        .arg("--include-extension=.qll")
        .arg("--include-extension=.dbscheme")
        .arg("--include-extension=.json")
        .arg("--include-extension=.jsonc")
        .arg("--include-extension=.jsonl")
        .arg("--include=**/qlpack.yml")
        .arg("--include=deprecated.blame")
        .arg("--size-limit=5m")
        .arg("--language=ql")
        .arg("--working-dir=.")
        .arg(db);

    for line in env::var("LGTM_INDEX_FILTERS")
        .unwrap_or_default()
        .split('\n')
    {
        if let Some(stripped) = line.strip_prefix("include:") {
            cmd.arg("--also-match=".to_owned() + stripped);
        } else if let Some(stripped) = line.strip_prefix("exclude:") {
            cmd.arg("--exclude=".to_owned() + stripped);
        }
    }
    let exit = &cmd.spawn()?.wait()?;
    std::process::exit(exit.code().unwrap_or(1))
}
