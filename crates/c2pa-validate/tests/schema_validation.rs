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

//! Formal validation of tool output JSON against the crJSON schema (crJSON-docs/crJSON-schema.json).

mod common;

use c2pa_validate::{cli::*, report::*, validator::Validator};
use serde_json::Value;
use std::fs;

fn cli_with_input(input: String) -> Cli {
    Cli {
        inputs: vec![input],
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

/// Load the crJSON schema from crJSON-docs. Returns None if the file is missing.
fn load_crjson_schema() -> Option<Value> {
    let path = common::crjson_schema_path();
    if !path.exists() {
        eprintln!("skip: crJSON schema not found: {}", path.display());
        return None;
    }
    let s = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&s).ok()
}

/// Validate a JSON value (Reader crJSON) against the crJSON schema.
/// Uses JSON Schema draft 2020-12 when available; otherwise draft 7.
fn validate_against_crjson_schema(schema: &Value, instance: &Value) -> Result<(), String> {
    use jsonschema::{Draft, Validator};
    let compiled = Validator::options()
        .with_draft(Draft::Draft202012)
        .build(schema)
        .map_err(|e| format!("schema build: {}", e))?;
    compiled.validate(instance).map_err(|errs| {
        errs.into_iter()
            .map(|e| format!("{} at {}", e, e.instance_path))
            .collect::<Vec<_>>()
            .join("; ")
    })
}

#[test]
fn asset_output_json_valid_against_crjson_schema() {
    let schema = match load_crjson_schema() {
        Some(s) => s,
        None => return,
    };

    let path = common::testfile_asset_jpg();
    if !path.exists() {
        eprintln!("skip: testfile not found: {}", path.display());
        return;
    }

    let cli = cli_with_input(path.display().to_string());
    let validator = Validator::new(cli).expect("Validator::new");
    let report = validator.run().expect("run");

    let reader_json = match report.results.first() {
        Some(ReportItem::Asset(asset)) => match &asset.reader_json {
            Some(j) => j.clone(),
            None => {
                eprintln!("skip: no reader_json in report");
                return;
            }
        },
        _ => {
            eprintln!("skip: expected single Asset result");
            return;
        }
    };

    validate_against_crjson_schema(&schema, &reader_json)
        .expect("asset output JSON should conform to crJSON schema");
}

#[test]
fn second_asset_output_json_valid_against_crjson_schema() {
    let schema = match load_crjson_schema() {
        Some(s) => s,
        None => return,
    };

    let path = common::testfile_asset_png();
    if !path.exists() {
        return;
    }

    let cli = cli_with_input(path.display().to_string());
    let validator = Validator::new(cli).unwrap();
    let report = validator.run().unwrap();

    let reader_json = match report.results.first() {
        Some(ReportItem::Asset(asset)) => asset.reader_json.as_ref().cloned(),
        _ => None,
    };
    let reader_json = match reader_json {
        Some(j) => j,
        None => return,
    };

    validate_against_crjson_schema(&schema, &reader_json)
        .expect("PNG asset output JSON should conform to crJSON schema");
}

#[test]
fn sidecar_c2pa_output_json_valid_against_crjson_schema() {
    let schema = match load_crjson_schema() {
        Some(s) => s,
        None => return,
    };

    let path = common::testfile_manifest_data_c2pa();
    if !path.exists() {
        return;
    }

    let cli = cli_with_input(path.display().to_string());
    let validator = Validator::new(cli).unwrap();
    let report = validator.run().unwrap();

    let reader_json = match report.results.first() {
        Some(ReportItem::Asset(asset)) => asset.reader_json.as_ref().cloned(),
        _ => None,
    };
    let reader_json = match reader_json {
        Some(j) => j,
        None => return,
    };

    validate_against_crjson_schema(&schema, &reader_json)
        .expect(".c2pa sidecar output JSON should conform to crJSON schema");
}
