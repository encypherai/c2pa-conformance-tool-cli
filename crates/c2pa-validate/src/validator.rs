/*
Copyright 2026 Adobe. All rights reserved.
This file is licensed to you under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License. You may obtain a copy
of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under
the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
OF ANY KIND, either express or implied. See the License for the specific language
governing permissions and limitations under the License.
*/

use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use c2pa::{
    format_from_path, settings::Settings, validation_results::ValidationState,
    Context as C2paContext, Manifest, Reader,
};
use glob::glob;
use profile_evaluator_rs::{
    evaluate, evaluate_rubric_conformance, evaluate_rubric_signals, load_profile, CompiledProfile,
};
use serde_json::Value;
use tracing::debug;

use crate::{
    cli::{Cli, RubricMode, TrustMode},
    report::{
        AssertionRecord, AssetReport, CrJsonReport, CrJsonValidationReport, IngredientRecord,
        InputDescriptor, InputType, ManifestRecord, ReportItem, SdkMetadata, SignatureRecord,
        StatusRecord, Summary, ToolMetadata, TrustAssessment,
    },
};

const OFFICIAL_TRUST_LIST_URL: &str =
    "https://raw.githubusercontent.com/c2pa-org/conformance-public/main/trust-list/C2PA-TRUST-LIST.pem";
const DEFAULT_ITL_URL: &str =
    "https://raw.githubusercontent.com/c2pa-org/conformance-public/main/trust-list/ITL.pem";

#[derive(Debug, Clone)]
pub struct Validator {
    cli: Cli,
    compiled_profile: Option<CompiledProfile>,
    rubric_profiles: Vec<(String, CompiledProfile)>,
}

#[derive(Debug, Clone)]
struct TrustScenario {
    label: String,
    source: String,
    settings: Settings,
}

impl Validator {
    pub fn new(cli: Cli) -> Result<Self> {
        if cli.trust_mode == TrustMode::Custom && cli.trust_list.is_none() {
            bail!("--trust-mode custom requires --trust-list FILE_OR_URL");
        }
        let compiled_profile = cli
            .profile
            .as_ref()
            .map(|path| {
                load_profile(path)
                    .with_context(|| format!("failed to load profile {}", path.display()))
            })
            .transpose()?;

        let rubric_profiles = load_rubric_profiles(&cli)?;

        Ok(Self {
            cli,
            compiled_profile,
            rubric_profiles,
        })
    }

    pub fn run(&self) -> Result<CrJsonReport> {
        let inputs = expand_inputs(&self.cli.inputs)?;
        if inputs.is_empty() {
            bail!("no input files matched");
        }

        let mut summary = Summary::default();
        let mut results = Vec::with_capacity(inputs.len());

        for input in inputs {
            let report = self
                .validate_input(&input)
                .with_context(|| format!("failed to validate {}", input.display()))?;

            match &report {
                ReportItem::Asset(asset) => {
                    summary.total += 1;
                    match asset.validation_state {
                        ValidationState::Trusted => summary.trusted += 1,
                        ValidationState::Valid => summary.valid += 1,
                        ValidationState::Invalid => summary.invalid += 1,
                    }
                    summary.warnings += asset.warnings.len();
                }
                ReportItem::CrJsonValidation(report) => {
                    summary.total += 1;
                    if !report.valid {
                        summary.errors += 1;
                    }
                }
            }

            results.push(report);
        }

        if self.cli.strict {
            summary.errors += results
                .iter()
                .filter_map(|item| match item {
                    ReportItem::Asset(asset) => Some(
                        asset.validation_state == ValidationState::Valid
                            && !asset.warnings.is_empty(),
                    ),
                    ReportItem::CrJsonValidation(_) => None,
                })
                .filter(|needs_error| *needs_error)
                .count();
        }

        Ok(CrJsonReport {
            schema: "crjson",
            schema_version: "0.1.0",
            tool: ToolMetadata {
                name: env!("CARGO_PKG_NAME"),
                version: env!("CARGO_PKG_VERSION"),
                c2pa_sdk: SdkMetadata {
                    name: c2pa::NAME,
                    version: c2pa::VERSION,
                    source: "vendor/c2pa-rs/sdk",
                },
            },
            generated_at: iso_now(),
            summary,
            results,
        })
    }

    fn validate_input(&self, path: &Path) -> Result<ReportItem> {
        // --crjson flag forces all inputs to be treated as crJSON.
        if self.cli.crjson {
            return self.validate_crjson(path);
        }

        match detect_input_type(path)? {
            InputType::CrJson => self.validate_crjson(path),
            InputType::Asset | InputType::SidecarManifest => {
                Ok(ReportItem::Asset(self.validate_asset(path)?))
            }
        }
    }

    fn validate_crjson(&self, path: &Path) -> Result<ReportItem> {
        let data = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let value: Value = serde_json::from_str(&data)
            .with_context(|| format!("failed to parse {}", path.display()))?;

        // If rubric evaluation is requested on crJSON input, run it.
        if !self.rubric_profiles.is_empty() {
            return self.evaluate_rubrics_on_crjson(path, &value);
        }

        // If a profile is requested on crJSON, evaluate it.
        if self.compiled_profile.is_some() {
            let profile_result = self.evaluate_profile(&value)?;
            return Ok(ReportItem::CrJsonValidation(CrJsonValidationReport {
                input: input_descriptor(path, InputType::CrJson)?,
                valid: true,
                messages: vec!["profile evaluated against crJSON".to_string()],
                rubric_results: vec![profile_result],
            }));
        }

        let mut messages = Vec::new();
        let mut valid = true;

        if value.get("schema").and_then(Value::as_str) != Some("crjson") {
            valid = false;
            messages.push("schema must equal 'crjson'".to_string());
        }

        if value
            .get("schema_version")
            .and_then(Value::as_str)
            .is_none()
        {
            valid = false;
            messages.push("schema_version is required".to_string());
        }

        if !value.get("results").is_some_and(Value::is_array) {
            valid = false;
            messages.push("results must be an array".to_string());
        }

        if messages.is_empty() {
            messages.push("crJSON structure is valid".to_string());
        }

        Ok(ReportItem::CrJsonValidation(CrJsonValidationReport {
            input: input_descriptor(path, InputType::CrJson)?,
            valid,
            messages,
            rubric_results: Vec::new(),
        }))
    }

    fn evaluate_rubrics_on_crjson(&self, path: &Path, crjson: &Value) -> Result<ReportItem> {
        // For crJSON inputs that wrap results (tool output format), extract
        // the inner crJSON from the first result's reader_json. For bare
        // crJSON (conformance golden format with manifests at top level),
        // use the value directly.
        let effective_crjson = if crjson.get("manifests").is_some() {
            crjson.clone()
        } else if let Some(results) = crjson.get("results").and_then(Value::as_array) {
            // Tool-output format: results[].reader_json contains the crJSON.
            results
                .iter()
                .find_map(|r| r.get("reader_json"))
                .cloned()
                .unwrap_or_else(|| crjson.clone())
        } else {
            crjson.clone()
        };

        let mut rubric_results = Vec::new();
        for (name, profile) in &self.rubric_profiles {
            let result = match self.cli.rubric_mode {
                RubricMode::Conformance => evaluate_rubric_conformance(profile, &effective_crjson)
                    .with_context(|| format!("rubric conformance evaluation failed for {name}"))?,
                RubricMode::Signals => evaluate_rubric_signals(profile, &effective_crjson)
                    .with_context(|| format!("rubric signals evaluation failed for {name}"))?,
            };
            rubric_results.push(result);
        }

        Ok(ReportItem::CrJsonValidation(CrJsonValidationReport {
            input: input_descriptor(path, InputType::CrJson)?,
            valid: true,
            messages: vec![format!(
                "evaluated {} rubric(s) against crJSON",
                rubric_results.len()
            )],
            rubric_results,
        }))
    }

    fn validate_asset(&self, path: &Path) -> Result<AssetReport> {
        let input_type = detect_input_type(path)?;
        let scenarios = self.build_trust_scenarios()?;

        let mut last_asset = None;
        let mut warnings = Vec::new();

        for scenario in scenarios {
            match self.read_asset(path, input_type, &scenario.settings) {
                Ok((reader, reader_json)) => {
                    let asset = self.build_asset_report(
                        path,
                        input_type,
                        scenario.label,
                        scenario.source,
                        reader,
                        reader_json,
                    )?;

                    if asset.validation_state == ValidationState::Trusted {
                        return Ok(asset);
                    }

                    last_asset = Some(asset);
                }
                Err(error) => {
                    debug!(
                        "validation with scenario {} failed: {error:#}",
                        scenario.label
                    );
                    warnings.push(format!(
                        "trust scenario '{}' could not complete: {error}",
                        scenario.label
                    ));
                }
            }
        }

        let mut asset = last_asset.ok_or_else(|| anyhow!("all trust scenarios failed"))?;
        asset.warnings.extend(warnings);
        Ok(asset)
    }

    fn read_asset(
        &self,
        path: &Path,
        input_type: InputType,
        settings: &Settings,
    ) -> Result<(Reader, Option<Value>)> {
        let context = C2paContext::new()
            .with_settings(settings.clone())
            .context("failed to build c2pa context")?;

        let reader = match input_type {
            InputType::Asset => Reader::from_context(context)
                .with_file(path)
                .with_context(|| format!("failed to read asset {}", path.display()))?,
            InputType::SidecarManifest => self.read_sidecar(path, context)?,
            InputType::CrJson => bail!("crjson is not handled by read_asset"),
        };

        let reader_json = Some(
            reader
                .to_crjson_value()
                .context("failed to render reader crJSON")?,
        );

        Ok((reader, reader_json))
    }

    fn read_sidecar(&self, path: &Path, context: C2paContext) -> Result<Reader> {
        let c2pa_data =
            fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        // Validate manifest only (signatures, structure); no asset to verify against.
        let settings = context.settings().clone();
        let settings = settings
            .with_value("verify.verify_after_reading", false)
            .context("failed to set verify_after_reading")?;
        let context = context
            .with_settings(settings)
            .context("failed to apply settings")?;
        let empty: Vec<u8> = Vec::new();
        Reader::from_context(context)
            .with_manifest_data_and_stream(
                &c2pa_data,
                "application/octet-stream",
                Cursor::new(empty),
            )
            .with_context(|| format!("failed to read sidecar manifest {}", path.display()))
    }

    fn build_asset_report(
        &self,
        path: &Path,
        input_type: InputType,
        scenario_label: String,
        scenario_source: String,
        reader: Reader,
        reader_json: Option<Value>,
    ) -> Result<AssetReport> {
        let validation_state = reader.validation_state();
        let mut manifests = reader
            .iter_manifests()
            .map(manifest_record)
            .collect::<Result<Vec<_>>>()?;
        let active_manifest_label = reader.active_label().map(ToOwned::to_owned);
        let ingredient_count = reader
            .iter_manifests()
            .map(|manifest| manifest.ingredients().len())
            .sum();
        let assertion_labels = reader
            .iter_manifests()
            .flat_map(|manifest| {
                manifest
                    .assertions()
                    .iter()
                    .map(|assertion| assertion.label().to_string())
            })
            .collect::<Vec<_>>();
        let mut statuses = collect_statuses(&reader);
        if statuses.is_empty() {
            if let Some(ref j) = reader_json {
                if let Some(first) = j
                    .get("manifests")
                    .and_then(Value::as_array)
                    .and_then(|a| a.first())
                {
                    statuses = statuses_from_manifest_validation_results(first);
                }
            }
        }

        if let Some(ref j) = reader_json {
            if let Some(manifests_json) = j.get("manifests").and_then(Value::as_array) {
                for (i, m) in manifests_json.iter().enumerate() {
                    if i < manifests.len() {
                        manifests[i].statuses = statuses_from_manifest_validation_results(m);
                        manifests[i].claim_version = claim_version_from_manifest_value(m);
                        if let Some(gen) = claim_generator_from_manifest_value(m) {
                            manifests[i].claim_generator = Some(gen);
                        }
                    }
                }
            }
        }

        let mut report = AssetReport {
            input: input_descriptor(path, input_type)?,
            validation_state,
            trust: TrustAssessment {
                mode: self.cli.trust_mode.to_string(),
                classification: trust_classification(validation_state).to_string(),
                source: Some(scenario_source),
                notes: trust_notes(&self.cli),
            },
            profile_path: self
                .cli
                .profile
                .as_ref()
                .map(|path| path.display().to_string()),
            profile_evaluation: if self.compiled_profile.is_some() {
                reader_json
                    .as_ref()
                    .map(|indicators| self.evaluate_profile(indicators))
                    .transpose()?
            } else {
                None
            },
            active_manifest_label,
            manifest_count: manifests.len(),
            ingredient_count,
            assertion_labels,
            statuses,
            manifests,
            reader_json,
            warnings: Vec::new(),
        };

        if validation_state != ValidationState::Trusted && scenario_label == "itl" {
            report
                .trust
                .notes
                .push("ITL was checked but the manifest did not chain to it".to_string());
        }

        Ok(report)
    }

    fn evaluate_profile(&self, indicators: &Value) -> Result<Value> {
        let Some(profile) = &self.compiled_profile else {
            bail!("profile evaluation requested but no profile was loaded");
        };

        evaluate(profile, indicators).context("failed to evaluate profile")
    }

    fn build_trust_scenarios(&self) -> Result<Vec<TrustScenario>> {
        let base = self.base_settings()?;
        let scenarios = match self.cli.trust_mode {
            TrustMode::Default => vec![self.with_trust_source(
                &base,
                "official",
                OFFICIAL_TRUST_LIST_URL.to_string(),
            )?],
            TrustMode::Itl => vec![
                self.with_trust_source(&base, "official", OFFICIAL_TRUST_LIST_URL.to_string())?,
                self.with_trust_source(&base, "itl", DEFAULT_ITL_URL.to_string())?,
            ],
            TrustMode::Custom => vec![self.with_custom_trust(&base)?],
        };

        Ok(scenarios)
    }

    fn base_settings(&self) -> Result<Settings> {
        let mut settings = Settings::new();
        if let Some(settings_path) = &self.cli.settings {
            settings = settings
                .with_file(settings_path)
                .with_context(|| format!("failed to load settings {}", settings_path.display()))?;
        }
        // Disable thumbnail generation; we don't use add_thumbnails, and leaving it enabled triggers a warning.
        settings = settings
            .with_value("builder.thumbnail.enabled", false)
            .context("failed to set builder.thumbnail.enabled")?;
        Ok(settings)
    }

    fn with_custom_trust(&self, base: &Settings) -> Result<TrustScenario> {
        let path = self
            .cli
            .trust_list
            .as_ref()
            .expect("trust_list required when trust_mode is Custom");
        let settings = base
            .clone()
            .with_value("verify.verify_trust", true)?
            .with_value("trust.trust_anchors", read_resource(path)?)?;

        Ok(TrustScenario {
            label: "custom".to_string(),
            source: "custom".to_string(),
            settings,
        })
    }

    fn with_trust_source(
        &self,
        base: &Settings,
        label: &str,
        resource: String,
    ) -> Result<TrustScenario> {
        let settings = base
            .clone()
            .with_value("verify.verify_trust", true)?
            .with_value("trust.trust_anchors", read_resource(&resource)?)?;

        Ok(TrustScenario {
            label: label.to_string(),
            source: label.to_string(),
            settings,
        })
    }
}

/// Loads rubric profiles from --rubric and/or --rubric-dir CLI flags.
fn load_rubric_profiles(cli: &Cli) -> Result<Vec<(String, CompiledProfile)>> {
    let mut profiles = Vec::new();

    if let Some(path) = &cli.rubric {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("rubric")
            .to_string();
        let profile = load_profile(path)
            .with_context(|| format!("failed to load rubric {}", path.display()))?;
        profiles.push((name, profile));
    }

    if let Some(dir) = &cli.rubric_dir {
        let pattern = dir.join("*.yml");
        let pattern_str = pattern
            .to_str()
            .ok_or_else(|| anyhow!("invalid rubric-dir path"))?;
        for entry in glob::glob(pattern_str)
            .with_context(|| format!("invalid rubric-dir pattern: {}", pattern_str))?
        {
            let path = entry.with_context(|| "invalid rubric glob match")?;
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("rubric")
                .to_string();
            let profile = load_profile(&path)
                .with_context(|| format!("failed to load rubric {}", path.display()))?;
            profiles.push((name, profile));
        }
    }

    Ok(profiles)
}

fn expand_inputs(inputs: &[String]) -> Result<Vec<PathBuf>> {
    let mut expanded = Vec::new();

    for input in inputs {
        if has_glob_pattern(input) {
            let mut matched = false;
            for path in glob(input).with_context(|| format!("invalid glob pattern '{input}'"))? {
                let path = path.with_context(|| format!("invalid match for pattern '{input}'"))?;
                expanded.push(path);
                matched = true;
            }
            if !matched {
                bail!("pattern '{input}' did not match any files");
            }
        } else {
            expanded.push(PathBuf::from(input));
        }
    }

    Ok(expanded)
}

fn has_glob_pattern(input: &str) -> bool {
    input.contains('*') || input.contains('?') || input.contains('[')
}

fn detect_input_type(path: &Path) -> Result<InputType> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("c2pa") => Ok(InputType::SidecarManifest),
        Some("json") => {
            let value = fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let json: Value = serde_json::from_str(&value)
                .with_context(|| format!("failed to parse {}", path.display()))?;
            if json.get("schema").and_then(Value::as_str) == Some("crjson") {
                Ok(InputType::CrJson)
            } else {
                Ok(InputType::Asset)
            }
        }
        _ => Ok(InputType::Asset),
    }
}

fn input_descriptor(path: &Path, input_type: InputType) -> Result<InputDescriptor> {
    let resolved = path
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", path.display()))?;

    Ok(InputDescriptor {
        original: path.display().to_string(),
        resolved_path: resolved.display().to_string(),
        detected_format: format_from_path(path)
            .unwrap_or_else(|| "application/octet-stream".to_string()),
        input_type,
    })
}

fn collect_statuses(reader: &Reader) -> Vec<StatusRecord> {
    reader
        .validation_status()
        .unwrap_or(&[])
        .iter()
        .map(|status| StatusRecord {
            code: status.code().to_string(),
            url: status.url().map(ToOwned::to_owned),
            explanation: status.explanation().map(ToOwned::to_owned),
            kind: format!("{:?}", status.kind()).to_lowercase(),
        })
        .collect()
}

fn manifest_record(manifest: &Manifest) -> Result<ManifestRecord> {
    Ok(ManifestRecord {
        label: manifest.label().map(ToOwned::to_owned),
        title: manifest.title().map(ToOwned::to_owned),
        format: manifest.format().map(ToOwned::to_owned),
        claim_version: None,
        claim_generator: manifest.claim_generator().map(ToOwned::to_owned),
        signature: manifest.signature_info().map(|signature| SignatureRecord {
            alg: signature
                .alg
                .as_ref()
                .map(|alg| format!("{alg:?}").to_lowercase()),
            issuer: signature.issuer.clone(),
            common_name: signature.common_name.clone(),
            serial_number: signature.cert_serial_number.clone(),
            time: signature.time.clone(),
            revoked: signature.revocation_status,
        }),
        ingredients: manifest
            .ingredients()
            .iter()
            .map(|ingredient| IngredientRecord {
                title: ingredient.title().map(ToOwned::to_owned),
                format: ingredient.format().map(ToOwned::to_owned),
                relationship: Some(format!("{:?}", ingredient.relationship())),
                active_manifest: ingredient.active_manifest().map(ToOwned::to_owned),
            })
            .collect(),
        assertions: manifest
            .assertions()
            .iter()
            .map(|assertion| AssertionRecord {
                label: assertion.label().to_string(),
                instance: assertion.instance(),
                kind: format!("{:?}", assertion.kind()).to_lowercase(),
            })
            .collect(),
        statuses: Vec::new(),
    })
}

/// Claim version from crJSON manifest keys (e.g. "claim.v2" -> "2", "claim" -> "1").
fn claim_version_from_manifest_value(manifest_value: &Value) -> Option<String> {
    let obj = manifest_value.as_object()?;
    if obj.contains_key("claim.v2") {
        return Some("2".to_string());
    }
    if obj.contains_key("claim") {
        return Some("1".to_string());
    }
    None
}

/// Claim generator string from crJSON manifest claim's claim_generator_info (name + version).
fn claim_generator_from_manifest_value(manifest_value: &Value) -> Option<String> {
    let claim = manifest_value
        .get("claim.v2")
        .or_else(|| manifest_value.get("claim"))?;
    let info = claim.get("claim_generator_info")?.as_object()?;
    let name = info.get("name").and_then(Value::as_str)?;
    let version = info.get("version").and_then(Value::as_str);
    let s = match version {
        Some(v) => format!("{} {}", name, v),
        None => name.to_string(),
    };
    Some(s)
}

/// Per-manifest validation results from crJSON manifest.validationResults (success/informational/failure).
fn statuses_from_manifest_validation_results(manifest_value: &Value) -> Vec<StatusRecord> {
    let mut out = Vec::new();
    let vr = match manifest_value.get("validationResults") {
        Some(v) => v,
        None => return out,
    };
    for (kind, arr) in [
        ("success", vr.get("success")),
        ("informational", vr.get("informational")),
        ("failure", vr.get("failure")),
    ] {
        let items = match arr.and_then(Value::as_array) {
            Some(a) => a,
            None => continue,
        };
        for item in items {
            let code = item
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let url = item
                .get("url")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let explanation = item
                .get("explanation")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            out.push(StatusRecord {
                code,
                url,
                explanation,
                kind: kind.to_string(),
            });
        }
    }
    out
}

fn trust_classification(state: ValidationState) -> &'static str {
    match state {
        ValidationState::Trusted => "trusted",
        ValidationState::Valid => "valid_untrusted",
        ValidationState::Invalid => "invalid",
    }
}

fn trust_notes(_cli: &Cli) -> Vec<String> {
    Vec::new()
}

fn read_resource(resource: &str) -> Result<String> {
    if resource.starts_with("http://") || resource.starts_with("https://") {
        reqwest::blocking::get(resource)
            .with_context(|| format!("failed to fetch {resource}"))?
            .error_for_status()
            .with_context(|| format!("request failed for {resource}"))?
            .text()
            .with_context(|| format!("failed to read body from {resource}"))
    } else {
        fs::read_to_string(resource).with_context(|| format!("failed to read {resource}"))
    }
}

fn iso_now() -> String {
    chrono::Utc::now().format("%B %-d, %Y").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_globs() {
        let inputs = expand_inputs(&["Cargo.toml".to_string()]).unwrap();
        assert_eq!(inputs.len(), 1);
    }

    #[test]
    fn detects_glob_patterns() {
        assert!(has_glob_pattern("*.jpg"));
        assert!(!has_glob_pattern("image.jpg"));
    }

    #[test]
    fn trust_classification_maps_state() {
        assert_eq!(trust_classification(ValidationState::Trusted), "trusted");
        assert_eq!(
            trust_classification(ValidationState::Valid),
            "valid_untrusted"
        );
        assert_eq!(trust_classification(ValidationState::Invalid), "invalid");
    }
}
