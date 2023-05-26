use proc_macro::{TokenStream, TokenTree};

pub mod autobuilder;
pub mod diagnostics;
pub mod extractor;
pub mod file_paths;
pub mod generator;
pub mod node_types;
pub mod options;
pub mod trap;
mod macros;

use serde::Deserialize;


#[derive(Deserialize)]
struct ExtractorConfig {
    name: String,
    display_name: String,
    file_types: Vec<FileTypeConfig>
}

#[derive(Deserialize)]
struct FileTypeConfig {
    name: String,
    display_name: String,
    extensions: Vec<String>
}


#[proc_macro]
pub fn load_yaml_config(input: TokenStream) -> TokenStream {
    match input.into_iter().next() {
        Some(TokenTree::Literal(s)) => {
            let file_source = std::fs::read_to_string(s.to_string()).unwrap();
            let config = 
        },
        _ => { panic!("Bad invocation of load_yaml_config"); }
    }
    TokenStream::new()
}