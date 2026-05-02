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

//! Integration tests for report rendering (JSON/MD/HTML) and exit code.
//! Uses crJSON fixtures only (no network). Asset tests would use default trust list (network).

mod common;

use c2pa_validate::{cli::*, validator::Validator};
use std::fs;

fn cli_with_input_and_format(
    input: String,
    format: OutputFormat,
    output: Option<std::path::PathBuf>,
) -> Cli {
    Cli {
        inputs: vec![input],
        output,
        format,
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
        cert_profile: None,
        cert_schema: None,
        emit_cert_json: false,
    }
}

#[test]
fn valid_crjson_exit_code_success() {
    let path = common::testfile_crjson_valid();
    if !path.exists() {
        return;
    }
    let cli = cli_with_input_and_format(path.display().to_string(), OutputFormat::Json, None);
    let validator = Validator::new(cli).unwrap();
    let report = validator.run().unwrap();
    assert_eq!(report.exit_code(), std::process::ExitCode::SUCCESS);
}

#[test]
fn invalid_crjson_exit_code_failure() {
    let path = common::testfile_crjson_invalid_no_results();
    if !path.exists() {
        return;
    }
    let cli = cli_with_input_and_format(path.display().to_string(), OutputFormat::Json, None);
    let validator = Validator::new(cli).unwrap();
    let report = validator.run().unwrap();
    assert_eq!(report.exit_code(), std::process::ExitCode::FAILURE);
}

#[test]
fn report_render_markdown_contains_expected() {
    let path = common::testfile_crjson_valid();
    if !path.exists() {
        return;
    }
    let cli = cli_with_input_and_format(path.display().to_string(), OutputFormat::Markdown, None);
    let validator = Validator::new(cli).unwrap();
    let report = validator.run().unwrap();
    let md = report.render_markdown(false);
    assert!(md.contains("# C2PA Conformance Report"));
    assert!(md.contains("Report Generation Info"));
    assert!(md.contains("crJSON"));
}

#[test]
fn report_render_html_contains_expected() {
    let path = common::testfile_crjson_valid();
    if !path.exists() {
        return;
    }
    let cli = cli_with_input_and_format(path.display().to_string(), OutputFormat::Html, None);
    let validator = Validator::new(cli).unwrap();
    let report = validator.run().unwrap();
    let html = report.render_html(false);
    assert!(html.contains("<!doctype html>"));
    assert!(html.contains("C2PA Conformance Report"));
}

#[test]
fn full_run_writes_json_to_specified_output() {
    let path = common::testfile_crjson_valid();
    if !path.exists() {
        return;
    }
    let out = std::env::temp_dir().join("c2pa_validate_test_output.json");
    let _ = fs::remove_file(&out);

    let cli = Cli {
        inputs: vec![path.display().to_string()],
        output: Some(out.clone()),
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
        cert_profile: None,
        cert_schema: None,
        emit_cert_json: false,
    };
    let _code = c2pa_validate::run_with_cli(cli);
    assert!(out.exists(), "output file should be created");
    let content = fs::read_to_string(&out).unwrap();
    // Single crJSON input yields no Asset, so JSON output is null; otherwise we get crJSON object
    assert!(
        content.trim() == "null" || content.contains("crjson") || content.contains("schema"),
        "unexpected content: {}",
        &content[..content.len().min(200)]
    );
    let _ = fs::remove_file(&out);
}

/// With multiple assets and JSON format, the tool writes one .json file per asset into -o directory.
#[test]
fn multiple_assets_json_writes_one_file_per_asset_to_output_dir() {
    let pxl1 = common::testfile_asset_jpg();
    let pxl2 = common::testfile_asset_jpg_second();
    if !pxl1.exists() || !pxl2.exists() {
        eprintln!("skip: PXL testfiles not found");
        return;
    }

    let out_dir = std::env::temp_dir().join("c2pa_validate_multi_out");
    let _ = fs::remove_dir_all(&out_dir);
    fs::create_dir_all(&out_dir).unwrap();

    let cli = Cli {
        inputs: vec![pxl1.display().to_string(), pxl2.display().to_string()],
        output: Some(out_dir.clone()),
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
        cert_profile: None,
        cert_schema: None,
        emit_cert_json: false,
    };

    let code = c2pa_validate::run_with_cli(cli);
    assert_eq!(code, std::process::ExitCode::SUCCESS);

    let entries: Vec<_> = fs::read_dir(&out_dir)
        .unwrap()
        .map(|e| e.unwrap())
        .collect();
    assert_eq!(entries.len(), 2, "expected two JSON files in output dir");

    let names: Vec<String> = entries
        .iter()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let has_pxl1 = names
        .iter()
        .any(|n| n.starts_with("PXL_20260208") && n.ends_with(".json"));
    let has_pxl2 = names
        .iter()
        .any(|n| n.starts_with("PXL_20250818") && n.ends_with(".json"));
    assert!(
        has_pxl1,
        "output should include JSON for first PXL file, got: {:?}",
        names
    );
    assert!(
        has_pxl2,
        "output should include JSON for second PXL file, got: {:?}",
        names
    );

    for entry in entries {
        let path = entry.path();
        let content = fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("manifests") || content.contains("jsonGenerator"),
            "each output should be crJSON"
        );
    }

    let _ = fs::remove_dir_all(&out_dir);
}
