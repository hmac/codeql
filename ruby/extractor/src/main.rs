#[macro_use]
extern crate lazy_static;

use std::borrow::Cow;
use std::fs;
use std::io::BufRead;
use tree_sitter::{Language, Parser, Range};

use codeql_extractor::{
    cli::{Command, ExtractArgs, GenerateArgs},
    diagnostics,
    extractor::{self, Extractor},
    generator::generate,
    node_types,
};

lazy_static! {
    static ref CP_NUMBER: regex::Regex = regex::Regex::new("cp([0-9]+)").unwrap();
}

fn encoding_from_name(encoding_name: &str) -> Option<&(dyn encoding::Encoding + Send + Sync)> {
    match encoding::label::encoding_from_whatwg_label(encoding_name) {
        s @ Some(_) => s,
        None => CP_NUMBER.captures(encoding_name).and_then(|cap| {
            encoding::label::encoding_from_windows_code_page(
                str::parse(cap.get(1).unwrap().as_str()).unwrap(),
            )
        }),
    }
}

fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .without_time()
        .with_level(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("ruby_extractor=warn")),
        )
        .init();

    match codeql_extractor::cli::parse_cli("ruby") {
        Command::Extract(args) => run_extract(args),
        Command::Generate(args) => run_generate(args),
        Command::Autobuild => run_autobuild(),
    }
}

fn run_extract(args: ExtractArgs) -> std::io::Result<()> {
    let diagnostics = args.diagnostics;

    let lang_ruby = tree_sitter_ruby::language();
    let lang_erb = tree_sitter_embedded_template::language();

    let schema_ruby = node_types::read_node_types_str("ruby", tree_sitter_ruby::NODE_TYPES)?;
    let schema_erb =
        node_types::read_node_types_str("erb", tree_sitter_embedded_template::NODE_TYPES)?;

    let file_list = fs::File::open(args.file_list)?;
    let lines: std::io::Result<Vec<String>> = std::io::BufReader::new(file_list).lines().collect();
    let lines = lines?;

    // Look up tree-sitter kind ids now, to avoid string comparisons when scanning ERB files.
    let erb_directive_id = lang_erb.id_for_node_kind("directive", true);
    let erb_output_directive_id = lang_erb.id_for_node_kind("output_directive", true);
    let erb_code_id = lang_erb.id_for_node_kind("code", true);

    let extractor = Extractor::new(
        &args.source_archive_dir,
        &args.output_dir,
        args.codeql_trap_compression,
        diagnostics,
        args.codeql_threads,
    );

    extractor.for_each(lines, |path, mut source, logger, trap_writer| {
        let mut code_ranges = vec![];
        let mut needs_conversion = false;

        if path.extension().map_or(false, |x| x == "erb") {
            tracing::info!("scanning: {}", path.display());
            extractor::extract(
                lang_erb,
                "erb",
                &schema_erb,
                logger,
                trap_writer,
                path,
                &source,
                &[],
            )?;
            let (ranges, line_breaks) = scan_erb(
                lang_erb,
                &source,
                erb_directive_id,
                erb_output_directive_id,
                erb_code_id,
            );
            for i in line_breaks {
                if i < source.len() {
                    source[i] = b'\n';
                }
            }
            code_ranges = ranges;
        } else if let Some(encoding_name) = scan_coding_comment(&source) {
            // If the input is already UTF-8 then there is no need to recode the source
            // If the declared encoding is 'binary' or 'ascii-8bit' then it is not clear how
            // to interpret characters. In this case it is probably best to leave the input
            // unchanged.
            if !encoding_name.eq_ignore_ascii_case("utf-8")
                && !encoding_name.eq_ignore_ascii_case("ascii-8bit")
                && !encoding_name.eq_ignore_ascii_case("binary")
            {
                if let Some(encoding) = encoding_from_name(&encoding_name) {
                    needs_conversion = encoding.whatwg_name().unwrap_or_default() != "utf-8";
                    if needs_conversion {
                        match encoding.decode(&source, encoding::types::DecoderTrap::Replace) {
                            Ok(str) => {
                                source = str.as_bytes().to_owned();
                            }
                            Err(msg) => {
                                needs_conversion = false;
                                logger.write(
                                    logger
                                        .message(
                                            "character-encoding-error",
                                            "Character encoding error",
                                        )
                                        .text(&format!(
                                            "{}: character decoding failure: {} ({})",
                                            &path.to_string_lossy(),
                                            msg,
                                            &encoding_name
                                        ))
                                        .status_page()
                                        .severity(diagnostics::Severity::Warning),
                                );
                            }
                        }
                    }
                } else {
                    logger.write(
                        logger
                            .message("character-encoding-error", "Character encoding error")
                            .text(&format!(
                                "{}: unknown character encoding: '{}'",
                                &path.to_string_lossy(),
                                &encoding_name
                            ))
                            .status_page()
                            .severity(diagnostics::Severity::Warning),
                    );
                }
            }
        }

        extractor::extract(
            lang_ruby,
            "ruby",
            &schema_ruby,
            logger,
            trap_writer,
            path,
            &source,
            &code_ranges,
        )?;

        Ok((source, needs_conversion))
    })
}

fn run_generate(args: GenerateArgs) -> std::io::Result<()> {
    use codeql_extractor::generator::language::Language;

    let languages = vec![
        Language {
            name: "Ruby".to_owned(),
            node_types: tree_sitter_ruby::NODE_TYPES,
        },
        Language {
            name: "Erb".to_owned(),
            node_types: tree_sitter_embedded_template::NODE_TYPES,
        },
    ];

    generate(args.dbscheme, args.library, languages)
}

fn run_autobuild() -> std::io::Result<()> {
    use std::env;
    use std::path::PathBuf;
    use std::process::Command;

    let dist = env::var("CODEQL_DIST").expect("CODEQL_DIST not set");
    let db = env::var("CODEQL_EXTRACTOR_RUBY_WIP_DATABASE")
        .expect("CODEQL_EXTRACTOR_RUBY_WIP_DATABASE not set");
    let codeql = if env::consts::OS == "windows" {
        "codeql.exe"
    } else {
        "codeql"
    };
    let codeql: PathBuf = [&dist, codeql].iter().collect();
    let mut cmd = Command::new(codeql);
    cmd.arg("database")
        .arg("index-files")
        .arg("--include-extension=.rb")
        .arg("--include-extension=.erb")
        .arg("--include-extension=.gemspec")
        .arg("--include=**/Gemfile")
        .arg("--exclude=**/.git")
        .arg("--size-limit=5m")
        .arg("--language=ruby")
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

fn scan_erb(
    erb: Language,
    source: &[u8],
    directive_id: u16,
    output_directive_id: u16,
    code_id: u16,
) -> (Vec<Range>, Vec<usize>) {
    let mut parser = Parser::new();
    parser.set_language(erb).unwrap();
    let tree = parser.parse(source, None).expect("Failed to parse file");
    let mut result = Vec::new();
    let mut line_breaks = vec![];

    for n in tree.root_node().children(&mut tree.walk()) {
        let kind_id = n.kind_id();
        if kind_id == directive_id || kind_id == output_directive_id {
            for c in n.children(&mut tree.walk()) {
                if c.kind_id() == code_id {
                    let mut range = c.range();
                    if range.end_byte < source.len() {
                        line_breaks.push(range.end_byte);
                        range.end_byte += 1;
                        range.end_point.column += 1;
                    }
                    result.push(range);
                }
            }
        }
    }
    if result.is_empty() {
        let root = tree.root_node();
        // Add an empty range at the end of the file
        result.push(Range {
            start_byte: root.end_byte(),
            end_byte: root.end_byte(),
            start_point: root.end_position(),
            end_point: root.end_position(),
        });
    }
    (result, line_breaks)
}

fn skip_space(content: &[u8], index: usize) -> usize {
    let mut index = index;
    while index < content.len() {
        let c = content[index] as char;
        // white space except \n
        let is_space = c == ' ' || ('\t'..='\r').contains(&c) && c != '\n';
        if !is_space {
            break;
        }
        index += 1;
    }
    index
}

fn scan_coding_comment(content: &[u8]) -> std::option::Option<Cow<str>> {
    let mut index = 0;
    // skip UTF-8 BOM marker if there is one
    if content.len() >= 3 && content[0] == 0xef && content[1] == 0xbb && content[2] == 0xbf {
        index += 3;
    }
    // skip #! line if there is one
    if index + 1 < content.len()
        && content[index] as char == '#'
        && content[index + 1] as char == '!'
    {
        index += 2;
        while index < content.len() && content[index] as char != '\n' {
            index += 1
        }
        index += 1
    }
    index = skip_space(content, index);

    if index >= content.len() || content[index] as char != '#' {
        return None;
    }
    index += 1;

    const CODING: [char; 12] = ['C', 'c', 'O', 'o', 'D', 'd', 'I', 'i', 'N', 'n', 'G', 'g'];
    let mut word_index = 0;
    while index < content.len() && word_index < CODING.len() && content[index] as char != '\n' {
        if content[index] as char == CODING[word_index]
            || content[index] as char == CODING[word_index + 1]
        {
            word_index += 2
        } else {
            word_index = 0;
        }
        index += 1;
    }
    if word_index < CODING.len() {
        return None;
    }
    index = skip_space(content, index);

    if index < content.len() && content[index] as char != ':' && content[index] as char != '=' {
        return None;
    }
    index += 1;
    index = skip_space(content, index);

    let start = index;
    while index < content.len() {
        let c = content[index] as char;
        if c == '-' || c == '_' || c.is_ascii_alphanumeric() {
            index += 1;
        } else {
            break;
        }
    }
    if index > start {
        return Some(String::from_utf8_lossy(&content[start..index]));
    }
    None
}

#[test]
fn test_scan_coding_comment() {
    let text = "# encoding: utf-8";
    let result = scan_coding_comment(text.as_bytes());
    assert_eq!(result, Some("utf-8".into()));

    let text = "#coding:utf-8";
    let result = scan_coding_comment(&text.as_bytes());
    assert_eq!(result, Some("utf-8".into()));

    let text = "# foo\n# encoding: utf-8";
    let result = scan_coding_comment(&text.as_bytes());
    assert_eq!(result, None);

    let text = "# encoding: latin1 encoding: utf-8";
    let result = scan_coding_comment(&text.as_bytes());
    assert_eq!(result, Some("latin1".into()));

    let text = "# encoding: nonsense";
    let result = scan_coding_comment(&text.as_bytes());
    assert_eq!(result, Some("nonsense".into()));

    let text = "# coding = utf-8";
    let result = scan_coding_comment(&text.as_bytes());
    assert_eq!(result, Some("utf-8".into()));

    let text = "# CODING = utf-8";
    let result = scan_coding_comment(&text.as_bytes());
    assert_eq!(result, Some("utf-8".into()));

    let text = "# CoDiNg = utf-8";
    let result = scan_coding_comment(&text.as_bytes());
    assert_eq!(result, Some("utf-8".into()));

    let text = "# blah blahblahcoding = utf-8";
    let result = scan_coding_comment(&text.as_bytes());
    assert_eq!(result, Some("utf-8".into()));

    // unicode BOM is ignored
    let text = "\u{FEFF}# encoding: utf-8";
    let result = scan_coding_comment(&text.as_bytes());
    assert_eq!(result, Some("utf-8".into()));

    let text = "\u{FEFF} # encoding: utf-8";
    let result = scan_coding_comment(&text.as_bytes());
    assert_eq!(result, Some("utf-8".into()));

    let text = "#! /usr/bin/env ruby\n # encoding: utf-8";
    let result = scan_coding_comment(&text.as_bytes());
    assert_eq!(result, Some("utf-8".into()));

    let text = "\u{FEFF}#! /usr/bin/env ruby\n # encoding: utf-8";
    let result = scan_coding_comment(&text.as_bytes());
    assert_eq!(result, Some("utf-8".into()));

    // A #! must be the first thing on a line, otherwise it's a normal comment
    let text = " #! /usr/bin/env ruby encoding = utf-8";
    let result = scan_coding_comment(&text.as_bytes());
    assert_eq!(result, Some("utf-8".into()));
    let text = " #! /usr/bin/env ruby \n # encoding = utf-8";
    let result = scan_coding_comment(&text.as_bytes());
    assert_eq!(result, None);
}
