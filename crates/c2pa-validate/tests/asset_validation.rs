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

//! Integration tests for C2PA asset validation using testfiles.
//! Requires network for default trust list (official C2PA trust list).

mod common;

use c2pa::validation_results::ValidationState;
use c2pa_validate::{cli::*, report::*, validator::Validator};
use std::path::Path;

fn cli_with_inputs(inputs: Vec<String>) -> Cli {
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
fn single_asset_jpg_produces_asset_report() {
    let path = common::testfile_asset_jpg();
    if !path.exists() {
        eprintln!("skip: testfile not found: {}", path.display());
        return;
    }

    let cli = cli_with_inputs(vec![path.display().to_string()]);
    let validator = Validator::new(cli).expect("Validator::new");
    let report = validator.run().expect("run");

    assert_eq!(report.results.len(), 1, "one result");
    let item = report.results.first().unwrap();
    match item {
        ReportItem::Asset(asset) => {
            assert_eq!(asset.input.input_type, InputType::Asset);
            assert!(
                asset.input.detected_format.contains("jpeg")
                    || asset.input.detected_format.contains("image"),
                "detected format should reflect JPEG: {}",
                asset.input.detected_format
            );
            assert!(
                asset.reader_json.is_some(),
                "reader crJSON should be present"
            );
            assert!(
                matches!(
                    asset.validation_state,
                    ValidationState::Trusted | ValidationState::Valid | ValidationState::Invalid
                ),
                "validation_state should be one of Trusted/Valid/Invalid: {:?}",
                asset.validation_state
            );
        }
        ReportItem::CrJsonValidation(_) => panic!("expected Asset result, got CrJsonValidation"),
    }
    assert_eq!(report.summary.total, 1);
}

#[test]
fn single_asset_png_produces_asset_report() {
    let path = common::testfile_asset_png();
    if !path.exists() {
        eprintln!("skip: testfile not found: {}", path.display());
        return;
    }

    let cli = cli_with_inputs(vec![path.display().to_string()]);
    let validator = Validator::new(cli).expect("Validator::new");
    let report = validator.run().expect("run");

    assert_eq!(report.results.len(), 1);
    match report.results.first().unwrap() {
        ReportItem::Asset(asset) => {
            assert_eq!(asset.input.input_type, InputType::Asset);
            assert!(asset.reader_json.is_some());
            assert!(
                asset.manifest_count >= 1,
                "PNG should have at least one manifest"
            );
        }
        ReportItem::CrJsonValidation(_) => panic!("expected Asset result"),
    }
    assert_eq!(report.summary.total, 1);
}

#[test]
fn two_assets_produce_two_results_and_correct_summary() {
    let jpg = common::testfile_asset_jpg();
    let png = common::testfile_asset_png();
    if !jpg.exists() || !png.exists() {
        eprintln!("skip: testfiles not found");
        return;
    }

    let cli = cli_with_inputs(vec![jpg.display().to_string(), png.display().to_string()]);
    let validator = Validator::new(cli).expect("Validator::new");
    let report = validator.run().expect("run");

    assert_eq!(report.results.len(), 2);
    assert_eq!(report.summary.total, 2);
    for item in &report.results {
        match item {
            ReportItem::Asset(a) => assert!(a.reader_json.is_some()),
            ReportItem::CrJsonValidation(_) => panic!("expected only Asset results"),
        }
    }
}

/// Glob pattern testfiles/assets/PXL*.jpg resolves to both PXL assets.
#[test]
fn glob_pattern_pxl_jpg_expands_to_two_assets() {
    let pattern = common::glob_pxl_jpg();
    if !common::testfile_asset_jpg().exists() || !common::testfile_asset_jpg_second().exists() {
        eprintln!("skip: PXL testfiles not found");
        return;
    }

    let cli = cli_with_inputs(vec![pattern]);
    let validator = Validator::new(cli).expect("Validator::new");
    let report = validator.run().expect("run");

    assert_eq!(
        report.results.len(),
        2,
        "glob PXL*.jpg should expand to 2 assets"
    );
    assert_eq!(report.summary.total, 2);
    for item in &report.results {
        match item {
            ReportItem::Asset(a) => {
                assert_eq!(a.input.input_type, InputType::Asset);
                assert!(a.reader_json.is_some());
            }
            ReportItem::CrJsonValidation(_) => panic!("expected only Asset results from glob"),
        }
    }
}

#[test]
fn sidecar_manifest_data_c2pa_produces_asset_report() {
    let path = common::testfile_manifest_data_c2pa();
    if !path.exists() {
        eprintln!("skip: testfile not found: {}", path.display());
        return;
    }

    let cli = cli_with_inputs(vec![path.display().to_string()]);
    let validator = Validator::new(cli).expect("Validator::new");
    let report = validator.run().expect("run");

    assert_eq!(report.results.len(), 1);
    match report.results.first().unwrap() {
        ReportItem::Asset(asset) => {
            assert_eq!(asset.input.input_type, InputType::SidecarManifest);
            assert!(asset.reader_json.is_some());
        }
        ReportItem::CrJsonValidation(_) => panic!("expected Asset result for .c2pa sidecar"),
    }
}

#[test]
fn sidecar_cloud_manifest_c2pa_produces_asset_report() {
    let path = common::testfile_cloud_manifest_c2pa();
    if !path.exists() {
        eprintln!("skip: testfile not found: {}", path.display());
        return;
    }

    let cli = cli_with_inputs(vec![path.display().to_string()]);
    let validator = Validator::new(cli).expect("Validator::new");
    let report = validator.run().expect("run");

    assert_eq!(report.results.len(), 1);
    match report.results.first().unwrap() {
        ReportItem::Asset(asset) => {
            assert_eq!(asset.input.input_type, InputType::SidecarManifest);
            assert!(asset.reader_json.is_some());
        }
        ReportItem::CrJsonValidation(_) => panic!("expected Asset result for .c2pa sidecar"),
    }
}

#[test]
fn asset_mp4_produces_asset_report() {
    let path = common::testfile_asset_mp4();
    if !path.exists() {
        eprintln!("skip: testfile not found: {}", path.display());
        return;
    }

    let cli = cli_with_inputs(vec![path.display().to_string()]);
    let validator = Validator::new(cli).expect("Validator::new");
    let report = validator.run().expect("run");

    assert_eq!(report.results.len(), 1);
    match report.results.first().unwrap() {
        ReportItem::Asset(asset) => {
            assert_eq!(asset.input.input_type, InputType::Asset);
            assert!(asset.reader_json.is_some());
        }
        ReportItem::CrJsonValidation(_) => panic!("expected Asset result"),
    }
}

#[test]
fn asset_pdf_produces_asset_report() {
    let path = common::testfile_asset_pdf();
    if !path.exists() {
        eprintln!("skip: testfile not found: {}", path.display());
        return;
    }

    let cli = cli_with_inputs(vec![path.display().to_string()]);
    let validator = Validator::new(cli).expect("Validator::new");
    let report = validator.run().expect("run");

    assert_eq!(report.results.len(), 1);
    match report.results.first().unwrap() {
        ReportItem::Asset(asset) => {
            assert_eq!(asset.input.input_type, InputType::Asset);
            assert!(asset.reader_json.is_some());
        }
        ReportItem::CrJsonValidation(_) => panic!("expected Asset result"),
    }
}

/// Getty image does not chain to the default C2PA trust list; validation is expected to fail.
#[test]
fn asset_getty_jpg_fails_validation_with_default_trust() {
    let path = common::testfile_asset_getty_jpg();
    if !path.exists() {
        eprintln!("skip: testfile not found: {}", path.display());
        return;
    }

    let cli = cli_with_inputs(vec![path.display().to_string()]);
    let validator = Validator::new(cli).expect("Validator::new");
    let result = validator.run();

    assert!(
        result.is_err(),
        "getty image should fail validation with default trust list (e.g. all trust scenarios failed)"
    );
    // Error may be "failed to validate <path>" with cause "all trust scenarios failed"
    let err_str = format!("{:#}", result.unwrap_err());
    assert!(
        err_str.contains("all trust scenarios failed")
            || err_str.contains("trust")
            || err_str.contains("failed to validate"),
        "error should indicate validation/trust failure: {}",
        err_str
    );
}

#[test]
fn report_item_input_path_returns_resolved_path() {
    let path = common::testfile_asset_jpg();
    if !path.exists() {
        return;
    }
    let path_str = path.display().to_string();
    let cli = cli_with_inputs(vec![path_str.clone()]);
    let validator = Validator::new(cli).unwrap();
    let report = validator.run().unwrap();
    let item = report.results.first().unwrap();
    let resolved = item.input_path();
    assert!(
        Path::new(resolved).exists(),
        "input_path should be resolvable: {}",
        resolved
    );
}
