/*
Copyright 2026 Adobe. All rights reserved.
This file is licensed to you under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License. You may obtain a copy
of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
OF ANY KIND, either express or implied. See the License for the specific language
governing permissions and limitations in the License.
*/

//! Negative tests: invalid or non-existent paths, missing params, and bad CLI combinations.

mod common;

use c2pa_validate::{cli::*, validator::Validator};

fn default_cli_with_inputs(inputs: Vec<String>) -> Cli {
    Cli {
        inputs,
        output: None,
        format: OutputFormat::Json,
        profile: None,
        trust_mode: TrustMode::Default,
        trust_list: None,
        settings: None,
        strict: false,
        verbose: 0,
        rubric: None,
        rubric_dir: None,
        rubric_mode: RubricMode::Conformance,
        emit_crjson: false,
        crjson: false,
        rubric_strict: false,
    }
}

#[test]
fn empty_inputs_returns_error() {
    let cli = default_cli_with_inputs(vec![]);
    let validator = Validator::new(cli).expect("Validator::new (no custom trust)");
    let result = validator.run();

    assert!(result.is_err(), "empty inputs should yield an error");
    let err = result.unwrap_err();
    let err_str = format!("{:#}", err);
    assert!(
        err_str.contains("no input files matched"),
        "error should mention no input files matched: {}",
        err_str
    );
}

#[test]
fn glob_matching_nothing_returns_error() {
    // Pattern that looks like a glob but matches no files in testfiles
    let pattern = common::testfiles_dir().join("assets/nonexistent_*.jpg");
    let cli = default_cli_with_inputs(vec![pattern.display().to_string()]);
    let validator = Validator::new(cli).expect("Validator::new");
    let result = validator.run();

    assert!(
        result.is_err(),
        "glob matching no files should yield an error"
    );
    let err_str = format!("{:#}", result.unwrap_err());
    assert!(
        err_str.contains("did not match any files"),
        "error should mention pattern did not match: {}",
        err_str
    );
}

#[test]
fn non_existent_file_returns_error() {
    let path = common::testfiles_dir().join("assets/does_not_exist_12345.jpg");
    let cli = default_cli_with_inputs(vec![path.display().to_string()]);
    let validator = Validator::new(cli).expect("Validator::new");
    let result = validator.run();

    assert!(result.is_err(), "non-existent file should yield an error");
    let err_str = format!("{:#}", result.unwrap_err());
    assert!(
        err_str.contains("failed to validate")
            || err_str.contains("failed to resolve")
            || err_str.contains("No such file")
            || err_str.contains("not found"),
        "error should indicate missing/invalid file: {}",
        err_str
    );
}

#[test]
fn custom_trust_mode_without_trust_list_returns_error() {
    let path = common::testfile_asset_jpg();
    if !path.exists() {
        eprintln!("skip: testfile not found");
        return;
    }

    let cli = Cli {
        inputs: vec![path.display().to_string()],
        output: None,
        format: OutputFormat::Json,
        profile: None,
        trust_mode: TrustMode::Custom,
        trust_list: None,
        settings: None,
        strict: false,
        verbose: 0,
        rubric: None,
        rubric_dir: None,
        rubric_mode: RubricMode::Conformance,
        emit_crjson: false,
        crjson: false,
        rubric_strict: false,
    };

    let result = Validator::new(cli);

    assert!(
        result.is_err(),
        "--trust-mode custom without --trust-list should yield an error"
    );
    let err_str = format!("{:#}", result.unwrap_err());
    assert!(
        err_str.contains("custom") && err_str.contains("trust-list"),
        "error should mention custom trust list requirement: {}",
        err_str
    );
}

#[test]
fn run_with_cli_empty_inputs_exits_failure() {
    let cli = default_cli_with_inputs(vec![]);
    let code = c2pa_validate::run_with_cli(cli);
    assert_eq!(code, std::process::ExitCode::FAILURE);
}

#[test]
fn run_with_cli_nonexistent_path_exits_failure() {
    let cli = default_cli_with_inputs(vec!["/nonexistent/path/foo.jpg".to_string()]);
    let code = c2pa_validate::run_with_cli(cli);
    assert_eq!(code, std::process::ExitCode::FAILURE);
}
