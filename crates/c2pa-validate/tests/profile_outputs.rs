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

mod common;

use std::fs;
use std::process::ExitCode;

use c2pa_validate::{cli::*, report::ReportItem, validator::Validator};
use serde_json::Value;

fn cli_with_profile(
    input: String,
    profile: std::path::PathBuf,
    format: OutputFormat,
    output: Option<std::path::PathBuf>,
) -> Cli {
    Cli {
        inputs: vec![input],
        output,
        format,
        profile: Some(profile),
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

fn expected_profile_output(
    input: &std::path::Path,
    profile: &std::path::Path,
) -> (Value, ExitCode) {
    let validator = Validator::new(cli_with_profile(
        input.display().to_string(),
        profile.to_path_buf(),
        OutputFormat::Json,
        None,
    ))
    .expect("Validator::new");
    let report = validator.run().expect("run");
    let expected_value = match report.results.first().expect("first result") {
        ReportItem::Asset(asset) => asset
            .profile_evaluation
            .clone()
            .expect("profile evaluation should be present"),
        ReportItem::CrJsonValidation(_) => panic!("expected asset result"),
    };
    (expected_value, report.exit_code())
}

#[test]
fn validator_attaches_profile_evaluation_to_asset_reports() {
    let asset = common::testfile_asset_jpg();
    let profile = common::testfile_profile_real_media();
    if !asset.exists() || !profile.exists() {
        eprintln!("skip: required profile fixture missing");
        return;
    }

    let validator = Validator::new(cli_with_profile(
        asset.display().to_string(),
        profile.clone(),
        OutputFormat::Json,
        None,
    ))
    .expect("Validator::new");
    let report = validator.run().expect("run");

    let expected_profile_path = profile.display().to_string();

    match report.results.first().expect("first result") {
        ReportItem::Asset(asset_report) => {
            assert_eq!(
                asset_report.profile_path.as_deref(),
                Some(expected_profile_path.as_str())
            );
            let profile_evaluation = asset_report
                .profile_evaluation
                .as_ref()
                .expect("profile evaluation should be populated");
            assert_eq!(
                profile_evaluation
                    .get("profile_metadata")
                    .and_then(Value::as_object)
                    .and_then(|metadata| metadata.get("name"))
                    .and_then(Value::as_str),
                Some("Real Media Profile")
            );
            assert!(
                profile_evaluation.get("statements").is_some(),
                "profile output should include statements"
            );
        }
        ReportItem::CrJsonValidation(_) => panic!("expected asset result"),
    }
}

#[test]
fn full_run_writes_profile_json_to_specified_output() {
    let asset = common::testfile_asset_jpg();
    let profile = common::testfile_profile_real_media();
    if !asset.exists() || !profile.exists() {
        eprintln!("skip: required profile fixture missing");
        return;
    }

    let (expected, expected_exit_code) = expected_profile_output(&asset, &profile);
    let out = std::env::temp_dir().join("c2pa_validate_profile_output.json");
    let _ = fs::remove_file(&out);

    let code = c2pa_validate::run_with_cli(cli_with_profile(
        asset.display().to_string(),
        profile,
        OutputFormat::Json,
        Some(out.clone()),
    ));
    assert_eq!(code, expected_exit_code);
    assert!(out.exists(), "output file should be created");

    let actual: Value = serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(actual, expected);

    let _ = fs::remove_file(&out);
}

#[test]
fn full_run_writes_profile_yaml_to_specified_output() {
    let asset = common::testfile_asset_png();
    let profile = common::testfile_profile_real_life_capture();
    if !asset.exists() || !profile.exists() {
        eprintln!("skip: required profile fixture missing");
        return;
    }

    let (expected, expected_exit_code) = expected_profile_output(&asset, &profile);
    let out = std::env::temp_dir().join("c2pa_validate_profile_output.yaml");
    let _ = fs::remove_file(&out);

    let code = c2pa_validate::run_with_cli(cli_with_profile(
        asset.display().to_string(),
        profile,
        OutputFormat::Yaml,
        Some(out.clone()),
    ));
    assert_eq!(code, expected_exit_code);
    assert!(out.exists(), "output file should be created");

    let actual: Value = serde_yaml::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(actual, expected);

    let _ = fs::remove_file(&out);
}
