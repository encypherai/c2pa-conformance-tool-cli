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

//! Integration tests for crJSON file validation (schema + schema_version + results).

mod common;

use c2pa_validate::{cli::*, report::*, validator::Validator};

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
        cert_profile: None,
        cert_schema: None,
        emit_cert_json: false,
    }
}

#[test]
fn valid_minimal_crjson_passes_validation() {
    let path = common::testfile_crjson_valid();
    if !path.exists() {
        eprintln!("skip: testfile not found: {}", path.display());
        return;
    }

    let cli = cli_with_inputs(vec![path.display().to_string()]);
    let validator = Validator::new(cli).expect("Validator::new");
    let report = validator.run().expect("run");

    assert_eq!(report.results.len(), 1);
    match report.results.first().unwrap() {
        ReportItem::CrJsonValidation(r) => {
            assert!(r.valid, "valid_minimal.json should pass: {:?}", r.messages);
            assert!(
                r.messages.iter().any(|m| m.contains("valid")),
                "messages: {:?}",
                r.messages
            );
        }
        ReportItem::Asset(_) => panic!("expected CrJsonValidation result"),
    }
}

/// JSON file without "schema": "crjson" is detected as Asset, not crJSON, so validation
/// fails when trying to read it as an asset (run returns Err).
#[test]
fn json_without_crjson_schema_treated_as_asset_and_fails() {
    let path = common::testfile_crjson_invalid_schema();
    if !path.exists() {
        eprintln!("skip: testfile not found: {}", path.display());
        return;
    }

    let cli = cli_with_inputs(vec![path.display().to_string()]);
    let validator = Validator::new(cli).expect("Validator::new");
    let result = validator.run();
    assert!(
        result.is_err(),
        "JSON without schema \"crjson\" is treated as Asset; reading it as asset should fail"
    );
}

/// crJSON with missing schema_version is still detected as crJSON and fails schema validation.
#[test]
fn invalid_schema_version_missing_fails_crjson_validation() {
    let path = common::testfile_crjson_invalid_schema_version();
    if !path.exists() {
        eprintln!("skip: testfile not found: {}", path.display());
        return;
    }

    let cli = cli_with_inputs(vec![path.display().to_string()]);
    let validator = Validator::new(cli).expect("Validator::new");
    let report = validator.run().expect("run");

    assert_eq!(report.results.len(), 1);
    match report.results.first().unwrap() {
        ReportItem::CrJsonValidation(r) => {
            assert!(!r.valid);
            assert!(
                r.messages.iter().any(|m| m.contains("schema_version")),
                "messages should mention schema_version: {:?}",
                r.messages
            );
        }
        ReportItem::Asset(_) => panic!("expected CrJsonValidation result"),
    }
}

#[test]
fn invalid_no_results_array_fails_validation() {
    let path = common::testfile_crjson_invalid_no_results();
    if !path.exists() {
        eprintln!("skip: testfile not found: {}", path.display());
        return;
    }

    let cli = cli_with_inputs(vec![path.display().to_string()]);
    let validator = Validator::new(cli).expect("Validator::new");
    let report = validator.run().expect("run");

    assert_eq!(report.results.len(), 1);
    match report.results.first().unwrap() {
        ReportItem::CrJsonValidation(r) => {
            assert!(!r.valid);
            assert!(
                r.messages.iter().any(|m| m.contains("results")),
                "messages should mention results: {:?}",
                r.messages
            );
        }
        ReportItem::Asset(_) => panic!("expected CrJsonValidation result"),
    }
}
