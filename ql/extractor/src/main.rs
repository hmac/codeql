

mod autobuilder;
mod extractor;
mod generator;

use codeql_extractor::make_cli;

make_cli!(ql, "../../codeql-extractor.yml");

