use std::env;
use std::process::Command;
use std::path::PathBuf;

pub fn autobuild(language: &str, extensions: &[&str], include_globs: &[&str], exclude_globs: &[&str]) -> std::io::Result<()> {
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
        .arg("index-files");

    for ext in extensions {
        cmd.arg(format!("--include-extension=.{ext}"));
    }

    for glob in include_globs {
        cmd.arg(format!("--include={glob}"));
    }

    for glob in exclude_globs {
        cmd.arg(format!("--exclude={glob}"));
    }

    cmd
        .arg("--size-limit=5m")
        .arg(format!("--language={language}"))
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
